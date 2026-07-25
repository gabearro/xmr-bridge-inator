//! Authenticated-QUIC payloads for durable deposit consolidation signing.
//!
//! This module is transport- and server-independent. Every payload carries a complete attempt
//! binding, while every relay carries explicit authenticated sender and recipient identities.
//!
//! # Coordinator-free Byzantine lane
//!
//! Every FROSTLASS preprocess and signature share is retained with its signer's portable Ed25519
//! [`SignedEnvelope`]. The inner envelope is a broadcast (`to = None`) and commits to the scenario
//! QUIC network identity, round phase, complete attempt binding, sender, signing context, and exact
//! canonical FROSTLASS bytes. [`ByzantineConsolidationWireMessage`] wraps those statements in a
//! separately versioned, domain-tagged all-to-all relay protocol. The outer authenticated QUIC
//! relay is independent of the inner origin, so no coordinator can suppress an already-observed
//! contribution or candidate.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use monero_oxide::{ringct::RctPrunable, transaction::Transaction};
use monero_wallet::send::Eventuality;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, SeqAccess, Visitor},
};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    committee::{Committee, CommitteeError, MAX_COMMITTEE_MEMBERS, PartyId, SessionId},
    consolidation_consensus::{
        CONSOLIDATION_INTENT_APPLICATION, ConsolidationConsensusError, ConsolidationIntent,
        ConsolidationIntentCertificate, decode_consolidation_intent,
    },
    consolidation_roast::RoastViewPlan,
    deposit_consensus::{
        ConsensusBinding, ConsensusContext, ConsensusMessage, ConsensusMessageBody, ConsensusValue,
        ConsensusValueDigest, MAX_CONSENSUS_MESSAGE_BYTES, ViewChangeCertificate,
        decode_consensus_message,
    },
    deposit_consolidation::{
        AttemptBinding, ConsolidationError, ConsolidationId, OpaqueIntentBinding,
        SignedTransactionBinding, TransactionAuthorization, consolidation_input_set_binding,
        consolidation_signed_bytes_binding,
    },
    deposit_wallet::{
        DepositAddressDeriver, DepositWalletError, FamilyKeyImageBinding, SignedSweepTransaction,
        SweepId, WalletOutputId,
    },
    deposit_worker::{
        DepositWorkerError, DepositWorkerState, PreparedFrostlassSweep, PreparedSweepIntent,
    },
    identity::{Identity, IdentityError, SignedEnvelope},
    signing::{
        BoundPreprocessMessage, BoundSignatureShareMessage, CanonicalSignerSet,
        MAX_FROSTLASS_MESSAGE_BYTES, ProofVerifiedKeyImagePreview, SigningContext, SigningError,
    },
};

const ATTEMPT_WIRE_BINDING_VERSION: u16 = 1;
const CONTRIBUTION_BINDING_VERSION: u16 = 1;
const TERMINAL_ATTESTATION_BINDING_VERSION: u16 = 1;
const PREPROCESS_CONTRIBUTION_DOMAIN: &str =
    "threshold-monero/deposit-consolidation/preprocess-contribution/v1";
const SHARE_CONTRIBUTION_DOMAIN: &str =
    "threshold-monero/deposit-consolidation/share-contribution/v1";
// These stable, phase-distinct logical sequence tags prevent a future inner-envelope replay cache
// from treating preprocess and share statements by the same sender/session as one slot. The exact
// attempt remains committed inside the signed contribution binding.
const PREPROCESS_CONTRIBUTION_SEQUENCE: u64 = 0x544d_4350_5245_5031;
const SHARE_CONTRIBUTION_SEQUENCE: u64 = 0x544d_4353_4841_5231;
const KEY_IMAGE_BINDING_ATTESTATION_VERSION: u16 = 1;
const KEY_IMAGE_BINDING_CERTIFICATE_VERSION: u16 = 1;
const CONSOLIDATION_CONSENSUS_SLOT_VERSION: u16 = 2;
const CONSOLIDATION_CONSENSUS_SLOT_DOMAIN: &str =
    "threshold-monero/deposit-consolidation/consensus-slot/v1";
const CONSOLIDATION_CONSENSUS_GENESIS_SLOT_DOMAIN: &str =
    "threshold-monero/deposit-consolidation/consensus-genesis-slot/v1";
const CONSOLIDATION_CONSENSUS_SLOT_SESSION_DOMAIN: &str =
    "threshold-monero/deposit-consolidation/consensus-slot-session/v1";
const KEY_IMAGE_BINDING_ATTESTATION_DOMAIN: &str =
    "threshold-monero/deposit-consolidation/key-image-binding-attestation/v1";
const KEY_IMAGE_BINDING_ATTESTATION_SEQUENCE: u64 = 0x544d_434b_494d_4731;
const MAX_BYZANTINE_SWEEP_INPUTS: usize = 1_024;
const MAX_CONSENSUS_VALUE_ATTACHMENTS: usize = MAX_COMMITTEE_MEMBERS + 1;
const SIGNED_TRANSACTION_ATTESTATION_DOMAIN: &str =
    "threshold-monero/deposit-consolidation/signed-transaction-attestation/v1";
// A signer must never produce two different transaction values for one attempt. Keeping a stable
// logical sequence makes such an equivocation visible to any envelope replay/equivocation index.
const SIGNED_TRANSACTION_ATTESTATION_SEQUENCE: u64 = 0x544d_4354_5853_4731;
/// Matches the authenticated QUIC transport's hard request-body ceiling.
pub const MAX_CONSOLIDATION_WIRE_BYTES: usize = 8 * 1024 * 1024;

// Keeping a fixed magic in the body makes an operation-routing mistake fail closed before any
// semantic dispatch.
const BYZANTINE_CONSOLIDATION_WIRE_MAGIC: [u8; 16] = *b"tm-roast-wire-v2";
const BYZANTINE_CONSOLIDATION_WIRE_VERSION: u16 = 2;
const BYZANTINE_DELIVERY_ID_VERSION: u16 = 1;
const BYZANTINE_DELIVERY_DIGEST_DOMAIN: &str =
    "threshold-monero/consolidation-byzantine/delivery/v1";

/// Explicit authenticated relay route for a coordinator-free Byzantine delivery.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationWireRoute {
    pub from: PartyId,
    pub to: PartyId,
}

impl ConsolidationWireRoute {
    pub fn new(from: PartyId, to: PartyId) -> Result<Self, ConsolidationWireError> {
        let route = Self { from, to };
        route.validate()?;
        Ok(route)
    }

    fn validate(self) -> Result<(), ConsolidationWireError> {
        if self.from.0 == 0 || self.to.0 == 0 || self.from == self.to {
            return Err(ConsolidationWireError::InvalidRoute);
        }
        Ok(())
    }
}

macro_rules! wire_accessors {
    () => {
        #[must_use]
        pub const fn route(&self) -> ConsolidationWireRoute {
            self.route
        }

        #[must_use]
        pub const fn relay(&self) -> PartyId {
            self.route.from
        }

        #[must_use]
        pub const fn recipient(&self) -> PartyId {
            self.route.to
        }

        #[must_use]
        pub const fn binding(&self) -> &ConsolidationAttemptWireBinding {
            &self.binding
        }
    };
}

macro_rules! impl_redacted_round_debug {
    ($message:ty, $bytes_label:literal, $bytes_len:expr) => {
        impl fmt::Debug for $message {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($message))
                    .field("route", &self.route)
                    .field("family", &hex::encode(self.family))
                    .field("view", &self.view)
                    .field("binding", &self.binding)
                    .field($bytes_label, &$bytes_len(self))
                    .finish_non_exhaustive()
            }
        }
    };
}

/// Public binding repeated by every wire phase for one exact signing attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationAttemptWireBinding {
    version: u16,
    consolidation: ConsolidationId,
    authorization: [u8; 32],
    opaque_intent: OpaqueIntentBinding,
    attempt: AttemptBinding,
    leader: PartyId,
}

impl ConsolidationAttemptWireBinding {
    pub fn new(
        authorization: &TransactionAuthorization,
        attempt: &AttemptBinding,
        leader: PartyId,
    ) -> Result<Self, ConsolidationWireError> {
        authorization.validate()?;
        attempt.validate()?;
        if authorization.root_group_key() != attempt.root_group_key() {
            return Err(ConsolidationWireError::AuthorizationMismatch);
        }
        let binding = Self {
            version: ATTEMPT_WIRE_BINDING_VERSION,
            consolidation: authorization.id(),
            authorization: authorization.digest(),
            opaque_intent: authorization.opaque_intent(),
            attempt: attempt.clone(),
            leader,
        };
        binding.validate()?;
        Ok(binding)
    }

    #[must_use]
    pub const fn consolidation_id(&self) -> ConsolidationId {
        self.consolidation
    }

    #[must_use]
    pub const fn authorization_digest(&self) -> [u8; 32] {
        self.authorization
    }

    #[must_use]
    pub const fn opaque_intent(&self) -> OpaqueIntentBinding {
        self.opaque_intent
    }

    #[must_use]
    pub const fn attempt(&self) -> &AttemptBinding {
        &self.attempt
    }

    #[must_use]
    pub const fn leader(&self) -> PartyId {
        self.leader
    }

    /// Compare the wire binding with independently authenticated active-epoch state.
    pub fn validate_active(
        &self,
        committee: &Committee,
        expected_registry: [u8; 32],
        expected_activation: [u8; 32],
        expected_root_group_key: [u8; 32],
    ) -> Result<CanonicalSignerSet, ConsolidationWireError> {
        self.validate()?;
        committee.validate()?;
        if expected_registry == [0_u8; 32]
            || expected_activation == [0_u8; 32]
            || expected_root_group_key == [0_u8; 32]
            || self.attempt.epoch() != committee.epoch
            || self.attempt.committee_digest() != committee.digest()
            || self.attempt.registry_digest() != expected_registry
            || self.attempt.activation_digest() != expected_activation
            || self.attempt.root_group_key() != expected_root_group_key
            || self.attempt.threshold() != committee.threshold
        {
            return Err(ConsolidationWireError::ActiveEpochMismatch);
        }
        CanonicalSignerSet::new(committee, self.leader, self.attempt.signers().iter().copied())
            .map_err(ConsolidationWireError::Signing)
    }

    pub fn validate_authorization(
        &self,
        authorization: &TransactionAuthorization,
    ) -> Result<(), ConsolidationWireError> {
        authorization.validate()?;
        if self.consolidation != authorization.id()
            || self.authorization != authorization.digest()
            || self.opaque_intent != authorization.opaque_intent()
            || self.attempt.root_group_key() != authorization.root_group_key()
        {
            return Err(ConsolidationWireError::AuthorizationMismatch);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConsolidationWireError> {
        self.attempt.validate()?;
        if self.version != ATTEMPT_WIRE_BINDING_VERSION
            || self.consolidation.0 == [0_u8; 32]
            || self.authorization == [0_u8; 32]
            || self.opaque_intent.0 == [0_u8; 32]
            || self.leader.0 == 0
            || self.attempt.signers().binary_search(&self.leader).is_err()
        {
            return Err(ConsolidationWireError::InvalidAttemptBinding);
        }
        Ok(())
    }
}

/// Sensitive exact prepared-intent bytes with zeroization and redacted formatting.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
struct PreparedIntentBytes(Vec<u8>);

impl Drop for PreparedIntentBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for PreparedIntentBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedIntentBytes")
            .field("len", &self.0.len())
            .field(
                "binding",
                &hex::encode(OpaqueIntentBinding::from_prepared_sweep_bytes(&self.0).0),
            )
            .finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for PreparedIntentBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_capped_sensitive_bytes(deserializer).map(Self)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConsolidationContributionPhase {
    Preprocess,
    Share,
}

impl ConsolidationContributionPhase {
    const fn domain(self) -> &'static str {
        match self {
            Self::Preprocess => PREPROCESS_CONTRIBUTION_DOMAIN,
            Self::Share => SHARE_CONTRIBUTION_DOMAIN,
        }
    }

    const fn envelope_sequence(self) -> u64 {
        match self {
            Self::Preprocess => PREPROCESS_CONTRIBUTION_SEQUENCE,
            Self::Share => SHARE_CONTRIBUTION_SEQUENCE,
        }
    }
}

/// Complete public provenance binding for one portable consolidation round contribution.
///
/// The full [`ConsolidationAttemptWireBinding`] is intentionally embedded instead of only its
/// digest. A verifier can therefore compare every authorization, attempt, committee, session,
/// signer-set, and leader dimension before handing the raw contribution to a linear FROST state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationContributionBinding {
    version: u16,
    quic_network_id: [u8; 32],
    phase: ConsolidationContributionPhase,
    attempt: ConsolidationAttemptWireBinding,
    sender: PartyId,
    signing_context: [u8; 32],
}

impl ConsolidationContributionBinding {
    fn new(
        quic_network_id: [u8; 32],
        phase: ConsolidationContributionPhase,
        attempt: ConsolidationAttemptWireBinding,
        sender: PartyId,
        signing_context: [u8; 32],
    ) -> Result<Self, ConsolidationWireError> {
        let binding = Self {
            version: CONTRIBUTION_BINDING_VERSION,
            quic_network_id,
            phase,
            attempt,
            sender,
            signing_context,
        };
        binding.validate_for_phase(phase)?;
        Ok(binding)
    }

    #[must_use]
    pub const fn quic_network_id(&self) -> [u8; 32] {
        self.quic_network_id
    }

    #[must_use]
    pub const fn phase(&self) -> ConsolidationContributionPhase {
        self.phase
    }

    #[must_use]
    pub const fn attempt(&self) -> &ConsolidationAttemptWireBinding {
        &self.attempt
    }

    #[must_use]
    pub const fn sender(&self) -> PartyId {
        self.sender
    }

    #[must_use]
    pub const fn signing_context(&self) -> [u8; 32] {
        self.signing_context
    }

    fn validate_for_phase(
        &self,
        expected_phase: ConsolidationContributionPhase,
    ) -> Result<(), ConsolidationWireError> {
        self.attempt.validate()?;
        if self.version != CONTRIBUTION_BINDING_VERSION
            || self.quic_network_id == [0_u8; 32]
            || self.phase != expected_phase
            || self.sender.0 == 0
            || self.attempt.attempt.signers().binary_search(&self.sender).is_err()
            || self.signing_context != self.attempt.attempt.signing_context()
        {
            return Err(ConsolidationWireError::InvalidContributionBinding);
        }
        Ok(())
    }

    fn validate_committee(&self, committee: &Committee) -> Result<(), ConsolidationWireError> {
        committee.validate()?;
        if committee.epoch != self.attempt.attempt.epoch()
            || committee.digest() != self.attempt.attempt.committee_digest()
            || committee.threshold != self.attempt.attempt.threshold()
        {
            return Err(ConsolidationWireError::ActiveEpochMismatch);
        }
        CanonicalSignerSet::new(
            committee,
            self.attempt.leader,
            self.attempt.attempt.signers().iter().copied(),
        )?;
        committee.member(self.sender)?;
        Ok(())
    }
}

#[derive(Serialize)]
struct CanonicalContributionPayload<'a, T> {
    domain: &'a str,
    binding: &'a ConsolidationContributionBinding,
    contribution: &'a T,
}

#[derive(Deserialize)]
struct DecodedContributionPayload<T> {
    domain: String,
    binding: ConsolidationContributionBinding,
    contribution: T,
}

fn encode_contribution_payload<T: Serialize>(
    binding: &ConsolidationContributionBinding,
    contribution: &T,
) -> Result<Vec<u8>, ConsolidationWireError> {
    postcard::to_allocvec(&CanonicalContributionPayload {
        domain: binding.phase.domain(),
        binding,
        contribution,
    })
    .map_err(|_| ConsolidationWireError::Serialization)
}

fn decode_contribution_payload<T: for<'de> Deserialize<'de>>(
    payload: &[u8],
    expected_domain: &str,
) -> Result<(ConsolidationContributionBinding, T), ConsolidationWireError> {
    let (decoded, trailing) = postcard::take_from_bytes::<DecodedContributionPayload<T>>(payload)
        .map_err(|_| ConsolidationWireError::Serialization)?;
    if !trailing.is_empty() || decoded.domain != expected_domain {
        return Err(ConsolidationWireError::ContributionEnvelopeMismatch);
    }
    Ok((decoded.binding, decoded.contribution))
}

fn validate_contribution_envelope(
    binding: &ConsolidationContributionBinding,
    envelope: &SignedEnvelope,
    canonical_payload: &[u8],
) -> Result<(), ConsolidationWireError> {
    if envelope.committee != binding.attempt.attempt.committee_digest()
        || envelope.epoch != binding.attempt.attempt.epoch()
        || envelope.session != binding.attempt.attempt.session()
        || envelope.from != binding.sender
        || envelope.to.is_some()
        || envelope.sequence != binding.phase.envelope_sequence()
        || envelope.payload != canonical_payload
    {
        return Err(ConsolidationWireError::ContributionEnvelopeMismatch);
    }
    Ok(())
}

fn verify_contribution_envelope(
    binding: &ConsolidationContributionBinding,
    envelope: &SignedEnvelope,
    committee: &Committee,
    expected_quic_network_id: [u8; 32],
    expected_attempt: &ConsolidationAttemptWireBinding,
    expected_phase: ConsolidationContributionPhase,
    canonical_payload: &[u8],
) -> Result<(), ConsolidationWireError> {
    binding.validate_for_phase(expected_phase)?;
    if binding.quic_network_id != expected_quic_network_id {
        return Err(ConsolidationWireError::ContributionNetworkMismatch);
    }
    if &binding.attempt != expected_attempt {
        return Err(ConsolidationWireError::ExpectedAttemptMismatch);
    }
    binding.validate_committee(committee)?;
    validate_contribution_envelope(binding, envelope, canonical_payload)?;
    // `to = None` makes the envelope portable, so the local-party argument cannot restrict it.
    Identity::verify_envelope(committee, expected_attempt.leader, envelope)?;
    Ok(())
}

/// Portable, independently attributable FROSTLASS round-one contribution.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedPreprocessContribution {
    binding: ConsolidationContributionBinding,
    preprocess: BoundPreprocessMessage,
    envelope: SignedEnvelope,
}

impl Serialize for SignedPreprocessContribution {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // The typed fields are the canonical decode of this exact payload. Serializing only the
        // envelope avoids duplicating up to one MiB per signer in aggregate wire bodies.
        self.envelope.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignedPreprocessContribution {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = SignedEnvelope::deserialize(deserializer)?;
        let (binding, preprocess) = decode_contribution_payload::<BoundPreprocessMessage>(
            &envelope.payload,
            PREPROCESS_CONTRIBUTION_DOMAIN,
        )
        .map_err(D::Error::custom)?;
        Ok(Self { binding, preprocess, envelope })
    }
}

impl SignedPreprocessContribution {
    pub fn sign(
        identity: &Identity,
        committee: &Committee,
        quic_network_id: [u8; 32],
        attempt: ConsolidationAttemptWireBinding,
        preprocess: BoundPreprocessMessage,
    ) -> Result<Self, ConsolidationWireError> {
        let binding = ConsolidationContributionBinding::new(
            quic_network_id,
            ConsolidationContributionPhase::Preprocess,
            attempt,
            preprocess.sender(),
            preprocess.context().into_bytes(),
        )?;
        binding.validate_committee(committee)?;
        let payload = encode_contribution_payload(&binding, &preprocess)?;
        let envelope = identity.sign_envelope(
            committee,
            binding.attempt.attempt.session(),
            None,
            ConsolidationContributionPhase::Preprocess.envelope_sequence(),
            payload,
        )?;
        let signed = Self { binding, preprocess, envelope };
        signed.verify(committee, quic_network_id, signed.binding.attempt())?;
        Ok(signed)
    }

    #[must_use]
    pub const fn binding(&self) -> &ConsolidationContributionBinding {
        &self.binding
    }

    #[must_use]
    pub const fn sender(&self) -> PartyId {
        self.binding.sender
    }

    #[must_use]
    pub const fn preprocess(&self) -> &BoundPreprocessMessage {
        &self.preprocess
    }

    #[must_use]
    pub const fn envelope(&self) -> &SignedEnvelope {
        &self.envelope
    }

    pub fn verify(
        &self,
        committee: &Committee,
        expected_quic_network_id: [u8; 32],
        expected_attempt: &ConsolidationAttemptWireBinding,
    ) -> Result<(), ConsolidationWireError> {
        self.validate_structure()?;
        let payload = encode_contribution_payload(&self.binding, &self.preprocess)?;
        verify_contribution_envelope(
            &self.binding,
            &self.envelope,
            committee,
            expected_quic_network_id,
            expected_attempt,
            ConsolidationContributionPhase::Preprocess,
            &payload,
        )
    }

    fn validate_structure(&self) -> Result<(), ConsolidationWireError> {
        self.binding.validate_for_phase(ConsolidationContributionPhase::Preprocess)?;
        if self.preprocess.sender() != self.binding.sender
            || self.preprocess.context().into_bytes() != self.binding.signing_context
            || self.preprocess.message().as_bytes().is_empty()
            || self.preprocess.message().as_bytes().len() > MAX_FROSTLASS_MESSAGE_BYTES
        {
            return Err(ConsolidationWireError::InvalidPreprocess);
        }
        let payload = encode_contribution_payload(&self.binding, &self.preprocess)?;
        validate_contribution_envelope(&self.binding, &self.envelope, &payload)
    }
}

impl fmt::Debug for SignedPreprocessContribution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedPreprocessContribution")
            .field("binding", &self.binding)
            .field("preprocess_bytes", &self.preprocess.message().as_bytes().len())
            .finish_non_exhaustive()
    }
}

/// Portable, independently attributable FROSTLASS round-two contribution.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedShareContribution {
    binding: ConsolidationContributionBinding,
    share: BoundSignatureShareMessage,
    envelope: SignedEnvelope,
}

impl Serialize for SignedShareContribution {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.envelope.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignedShareContribution {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = SignedEnvelope::deserialize(deserializer)?;
        let (binding, share) = decode_contribution_payload::<BoundSignatureShareMessage>(
            &envelope.payload,
            SHARE_CONTRIBUTION_DOMAIN,
        )
        .map_err(D::Error::custom)?;
        Ok(Self { binding, share, envelope })
    }
}

impl SignedShareContribution {
    pub fn sign(
        identity: &Identity,
        committee: &Committee,
        quic_network_id: [u8; 32],
        attempt: ConsolidationAttemptWireBinding,
        share: BoundSignatureShareMessage,
    ) -> Result<Self, ConsolidationWireError> {
        let binding = ConsolidationContributionBinding::new(
            quic_network_id,
            ConsolidationContributionPhase::Share,
            attempt,
            share.sender(),
            share.context().into_bytes(),
        )?;
        binding.validate_committee(committee)?;
        let payload = encode_contribution_payload(&binding, &share)?;
        let envelope = identity.sign_envelope(
            committee,
            binding.attempt.attempt.session(),
            None,
            ConsolidationContributionPhase::Share.envelope_sequence(),
            payload,
        )?;
        let signed = Self { binding, share, envelope };
        signed.verify(committee, quic_network_id, signed.binding.attempt())?;
        Ok(signed)
    }

    #[must_use]
    pub const fn binding(&self) -> &ConsolidationContributionBinding {
        &self.binding
    }

    #[must_use]
    pub const fn sender(&self) -> PartyId {
        self.binding.sender
    }

    #[must_use]
    pub const fn share(&self) -> &BoundSignatureShareMessage {
        &self.share
    }

    #[must_use]
    pub const fn envelope(&self) -> &SignedEnvelope {
        &self.envelope
    }

    pub fn verify(
        &self,
        committee: &Committee,
        expected_quic_network_id: [u8; 32],
        expected_attempt: &ConsolidationAttemptWireBinding,
    ) -> Result<(), ConsolidationWireError> {
        self.validate_structure()?;
        let payload = encode_contribution_payload(&self.binding, &self.share)?;
        verify_contribution_envelope(
            &self.binding,
            &self.envelope,
            committee,
            expected_quic_network_id,
            expected_attempt,
            ConsolidationContributionPhase::Share,
            &payload,
        )
    }

    fn validate_structure(&self) -> Result<(), ConsolidationWireError> {
        self.binding.validate_for_phase(ConsolidationContributionPhase::Share)?;
        if self.share.sender() != self.binding.sender
            || self.share.context().into_bytes() != self.binding.signing_context
            || self.share.message().as_bytes().is_empty()
            || self.share.message().as_bytes().len() > MAX_FROSTLASS_MESSAGE_BYTES
        {
            return Err(ConsolidationWireError::InvalidShare);
        }
        let payload = encode_contribution_payload(&self.binding, &self.share)?;
        validate_contribution_envelope(&self.binding, &self.envelope, &payload)
    }
}

impl fmt::Debug for SignedShareContribution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedShareContribution")
            .field("binding", &self.binding)
            .field("share_bytes", &self.share.message().as_bytes().len())
            .finish_non_exhaustive()
    }
}

fn deserialize_capped_contribution_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ContributionVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for ContributionVisitor<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_COMMITTEE_MEMBERS} signer contributions")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|length| length > MAX_COMMITTEE_MEMBERS) {
                return Err(A::Error::custom("too many signer contributions"));
            }
            let mut contributions =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_COMMITTEE_MEMBERS));
            while let Some(contribution) = sequence.next_element()? {
                if contributions.len() == MAX_COMMITTEE_MEMBERS {
                    return Err(A::Error::custom("too many signer contributions"));
                }
                contributions.push(contribution);
            }
            Ok(contributions)
        }
    }

    deserializer.deserialize_seq(ContributionVisitor(std::marker::PhantomData))
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationSignedPayload {
    binding: SignedTransactionBinding,
    transaction: SignedSweepTransaction,
}

impl ConsolidationSignedPayload {
    pub fn new(
        attempt: &ConsolidationAttemptWireBinding,
        transaction: SignedSweepTransaction,
    ) -> Result<Self, ConsolidationWireError> {
        let bytes = transaction.as_bytes();
        let exact_bytes_len =
            u32::try_from(bytes.len()).map_err(|_| ConsolidationWireError::SignedTooLarge)?;
        let binding = SignedTransactionBinding {
            authorization: attempt.authorization,
            attempt: attempt.attempt.attempt(),
            attempt_binding: attempt.attempt.digest(),
            session: attempt.attempt.session(),
            signing_context: attempt.attempt.signing_context(),
            opaque_intent: attempt.opaque_intent,
            transaction: transaction.transaction_id(),
            exact_bytes: consolidation_signed_bytes_binding(bytes),
            exact_bytes_len,
        };
        let payload = Self { binding, transaction };
        payload.validate_for(attempt)?;
        Ok(payload)
    }

    #[must_use]
    pub const fn binding(&self) -> SignedTransactionBinding {
        self.binding
    }

    #[must_use]
    pub const fn transaction(&self) -> &SignedSweepTransaction {
        &self.transaction
    }

    fn validate_for(
        &self,
        attempt: &ConsolidationAttemptWireBinding,
    ) -> Result<(), ConsolidationWireError> {
        self.binding.validate()?;
        let canonical = SignedSweepTransaction::from_bytes(
            self.transaction.as_bytes().to_vec(),
            Some(self.transaction.transaction_id()),
        )?;
        if canonical != self.transaction
            || self.binding.authorization != attempt.authorization
            || self.binding.attempt != attempt.attempt.attempt()
            || self.binding.attempt_binding != attempt.attempt.digest()
            || self.binding.session != attempt.attempt.session()
            || self.binding.signing_context != attempt.attempt.signing_context()
            || self.binding.opaque_intent != attempt.opaque_intent
            || self.binding.transaction != self.transaction.transaction_id()
            || self.binding.exact_bytes
                != consolidation_signed_bytes_binding(self.transaction.as_bytes())
            || usize::try_from(self.binding.exact_bytes_len).ok()
                != Some(self.transaction.as_bytes().len())
        {
            return Err(ConsolidationWireError::SignedBindingMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ConsolidationSignedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsolidationSignedPayload")
            .field("binding", &self.binding)
            .field("transaction_bytes", &self.transaction.as_bytes().len())
            .finish_non_exhaustive()
    }
}

fn validate_terminal_committee(
    attempt: &ConsolidationAttemptWireBinding,
    committee: &Committee,
) -> Result<(), ConsolidationWireError> {
    attempt.validate()?;
    committee.validate()?;
    if committee.epoch != attempt.attempt.epoch()
        || committee.digest() != attempt.attempt.committee_digest()
        || committee.threshold != attempt.attempt.threshold()
    {
        return Err(ConsolidationWireError::ActiveEpochMismatch);
    }
    CanonicalSignerSet::new(committee, attempt.leader, attempt.attempt.signers().iter().copied())?;
    Ok(())
}

/// Public provenance binding for one exact signed transaction attestation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableSignedTransactionBinding {
    version: u16,
    quic_network_id: [u8; 32],
    attempt: ConsolidationAttemptWireBinding,
    origin: PartyId,
}

impl PortableSignedTransactionBinding {
    #[must_use]
    pub const fn quic_network_id(&self) -> [u8; 32] {
        self.quic_network_id
    }

    #[must_use]
    pub const fn attempt(&self) -> &ConsolidationAttemptWireBinding {
        &self.attempt
    }

    #[must_use]
    pub const fn origin(&self) -> PartyId {
        self.origin
    }

    fn validate(&self) -> Result<(), ConsolidationWireError> {
        self.attempt.validate()?;
        if self.version != TERMINAL_ATTESTATION_BINDING_VERSION
            || self.quic_network_id == [0_u8; 32]
            || self.origin.0 == 0
            || self.attempt.attempt.signers().binary_search(&self.origin).is_err()
        {
            return Err(ConsolidationWireError::InvalidTerminalAttestation);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct CanonicalSignedTransactionAttestationPayload<'a> {
    domain: &'a str,
    binding: &'a PortableSignedTransactionBinding,
    signed: &'a ConsolidationSignedPayload,
}

#[derive(Deserialize)]
struct DecodedSignedTransactionAttestationPayload {
    domain: String,
    binding: PortableSignedTransactionBinding,
    signed: ConsolidationSignedPayload,
}

/// A route-independent Ed25519 statement for one exact canonical Monero transaction.
///
/// Serialization stores only the signed envelope. The decoded typed transaction is a view over
/// that payload, so the potentially large transaction bytes occur exactly once on the wire.
#[derive(Clone, Eq, PartialEq)]
pub struct PortableSignedTransactionAttestation {
    binding: PortableSignedTransactionBinding,
    signed: ConsolidationSignedPayload,
    envelope: SignedEnvelope,
}

impl Serialize for PortableSignedTransactionAttestation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.envelope.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PortableSignedTransactionAttestation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = SignedEnvelope::deserialize(deserializer)?;
        let (decoded, trailing) = postcard::take_from_bytes::<
            DecodedSignedTransactionAttestationPayload,
        >(&envelope.payload)
        .map_err(D::Error::custom)?;
        if !trailing.is_empty() || decoded.domain != SIGNED_TRANSACTION_ATTESTATION_DOMAIN {
            return Err(D::Error::custom("invalid signed transaction attestation payload"));
        }
        let attestation = Self { binding: decoded.binding, signed: decoded.signed, envelope };
        attestation.validate_structure().map_err(D::Error::custom)?;
        Ok(attestation)
    }
}

impl PortableSignedTransactionAttestation {
    pub fn sign(
        identity: &Identity,
        committee: &Committee,
        quic_network_id: [u8; 32],
        attempt: ConsolidationAttemptWireBinding,
        transaction: SignedSweepTransaction,
    ) -> Result<Self, ConsolidationWireError> {
        validate_terminal_committee(&attempt, committee)?;
        let binding = PortableSignedTransactionBinding {
            version: TERMINAL_ATTESTATION_BINDING_VERSION,
            quic_network_id,
            attempt,
            origin: identity.party(),
        };
        binding.validate()?;
        committee.member(binding.origin)?;
        let signed = ConsolidationSignedPayload::new(&binding.attempt, transaction)?;
        let payload = postcard::to_allocvec(&CanonicalSignedTransactionAttestationPayload {
            domain: SIGNED_TRANSACTION_ATTESTATION_DOMAIN,
            binding: &binding,
            signed: &signed,
        })
        .map_err(|_| ConsolidationWireError::Serialization)?;
        let envelope = identity.sign_envelope(
            committee,
            binding.attempt.attempt.session(),
            None,
            SIGNED_TRANSACTION_ATTESTATION_SEQUENCE,
            payload,
        )?;
        let attestation = Self { binding, signed, envelope };
        attestation.verify(committee, quic_network_id, &attestation.binding.attempt)?;
        Ok(attestation)
    }

    #[must_use]
    pub const fn binding(&self) -> &PortableSignedTransactionBinding {
        &self.binding
    }

    #[must_use]
    pub const fn origin(&self) -> PartyId {
        self.binding.origin
    }

    #[must_use]
    pub const fn signed(&self) -> &ConsolidationSignedPayload {
        &self.signed
    }

    #[must_use]
    pub const fn envelope(&self) -> &SignedEnvelope {
        &self.envelope
    }

    /// Verify this broadcast statement independently of the peer that relayed it.
    pub fn verify(
        &self,
        committee: &Committee,
        expected_quic_network_id: [u8; 32],
        expected_attempt: &ConsolidationAttemptWireBinding,
    ) -> Result<(), ConsolidationWireError> {
        self.validate_structure()?;
        if self.binding.quic_network_id != expected_quic_network_id {
            return Err(ConsolidationWireError::TerminalNetworkMismatch);
        }
        if &self.binding.attempt != expected_attempt {
            return Err(ConsolidationWireError::ExpectedAttemptMismatch);
        }
        validate_terminal_committee(&self.binding.attempt, committee)?;
        committee.member(self.binding.origin)?;
        // `to = None` makes the verifier's local-party argument irrelevant. Use the origin to make
        // clear that verification authenticates `from`, not the current leader or relay.
        Identity::verify_envelope(committee, self.binding.origin, &self.envelope)?;
        Ok(())
    }

    pub fn verify_from(
        &self,
        committee: &Committee,
        expected_quic_network_id: [u8; 32],
        expected_attempt: &ConsolidationAttemptWireBinding,
        expected_origin: PartyId,
    ) -> Result<(), ConsolidationWireError> {
        self.verify(committee, expected_quic_network_id, expected_attempt)?;
        if self.origin() != expected_origin {
            return Err(ConsolidationWireError::TerminalOriginMismatch);
        }
        Ok(())
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, ConsolidationWireError> {
        postcard::to_allocvec(&CanonicalSignedTransactionAttestationPayload {
            domain: SIGNED_TRANSACTION_ATTESTATION_DOMAIN,
            binding: &self.binding,
            signed: &self.signed,
        })
        .map_err(|_| ConsolidationWireError::Serialization)
    }

    fn validate_structure(&self) -> Result<(), ConsolidationWireError> {
        self.binding.validate()?;
        self.signed.validate_for(&self.binding.attempt)?;
        let payload = self.canonical_payload()?;
        if self.envelope.committee != self.binding.attempt.attempt.committee_digest()
            || self.envelope.epoch != self.binding.attempt.attempt.epoch()
            || self.envelope.session != self.binding.attempt.attempt.session()
            || self.envelope.from != self.binding.origin
            || self.envelope.to.is_some()
            || self.envelope.sequence != SIGNED_TRANSACTION_ATTESTATION_SEQUENCE
            || self.envelope.payload != payload
        {
            return Err(ConsolidationWireError::TerminalEnvelopeMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for PortableSignedTransactionAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortableSignedTransactionAttestation")
            .field("binding", &self.binding)
            .field("signed_binding", &self.signed.binding())
            .field("transaction_bytes", &self.signed.transaction().as_bytes().len())
            .finish_non_exhaustive()
    }
}

// -----------------------------------------------------------------------------
// Coordinator-free Byzantine/ROAST wire protocol
// -----------------------------------------------------------------------------

/// Value-independent Byzantine-agreement slot for one wallet/epoch and ledger position.
///
/// The slot contains only state every honest party can reconstruct before seeing a proposal. In
/// particular it excludes the randomized prepared transaction, authorization, signer subset,
/// attempt/session, and eventual ROAST family. Competing valid proposal values therefore enter the
/// same consensus reducer instead of selecting disjoint instances.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationConsensusSlot {
    version: u16,
    binding: ConsensusBinding,
    committee: Committee,
    fault_bound: u16,
    family_anchor: [u8; 32],
    roast_view: u64,
    ledger_height: u64,
    ledger_sequence: u64,
    ledger_previous: [u8; 32],
}

impl ConsolidationConsensusSlot {
    /// Construct a slot from trusted registry and portable-ledger state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: ConsensusBinding,
        committee: &Committee,
        fault_bound: u16,
        roast_view: u64,
        ledger_height: u64,
        ledger_sequence: u64,
        ledger_previous: [u8; 32],
    ) -> Result<Self, ConsolidationWireError> {
        if roast_view != 0 {
            return Err(ConsolidationWireError::InvalidConsensusSlot);
        }
        Self::new_inner(
            binding,
            committee,
            fault_bound,
            [0; 32],
            roast_view,
            ledger_height,
            ledger_sequence,
            ledger_previous,
        )
    }

    /// Construct an exact successor while retaining the genesis-slot family anchor.
    #[allow(clippy::too_many_arguments)]
    pub fn new_successor(
        binding: ConsensusBinding,
        committee: &Committee,
        fault_bound: u16,
        family_anchor: [u8; 32],
        roast_view: u64,
        ledger_height: u64,
        ledger_sequence: u64,
        ledger_previous: [u8; 32],
    ) -> Result<Self, ConsolidationWireError> {
        if roast_view == 0 || family_anchor == [0; 32] {
            return Err(ConsolidationWireError::InvalidConsensusSlot);
        }
        Self::new_inner(
            binding,
            committee,
            fault_bound,
            family_anchor,
            roast_view,
            ledger_height,
            ledger_sequence,
            ledger_previous,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        binding: ConsensusBinding,
        committee: &Committee,
        fault_bound: u16,
        family_anchor: [u8; 32],
        roast_view: u64,
        ledger_height: u64,
        ledger_sequence: u64,
        ledger_previous: [u8; 32],
    ) -> Result<Self, ConsolidationWireError> {
        committee.validate_async_security_with_faults(fault_bound)?;
        let mut slot = Self {
            version: CONSOLIDATION_CONSENSUS_SLOT_VERSION,
            binding,
            committee: committee.clone(),
            fault_bound,
            family_anchor,
            roast_view,
            ledger_height,
            ledger_sequence,
            ledger_previous,
        };
        if roast_view == 0 {
            slot.family_anchor = slot.expected_genesis_anchor();
        }
        slot.validate()?;
        // Reconstructing the context also validates every otherwise-private ConsensusBinding
        // invariant and the signed-envelope sequence bound.
        slot.consensus_context()?;
        Ok(slot)
    }

    #[must_use]
    pub const fn binding(&self) -> &ConsensusBinding {
        &self.binding
    }

    #[must_use]
    pub fn committee_digest(&self) -> [u8; 32] {
        self.committee.digest()
    }

    #[must_use]
    pub const fn committee(&self) -> &Committee {
        &self.committee
    }

    #[must_use]
    pub const fn fault_bound(&self) -> u16 {
        self.fault_bound
    }

    /// Digest of the value-independent view-zero slot retained by every successor.
    #[must_use]
    pub const fn family_anchor(&self) -> [u8; 32] {
        self.family_anchor
    }

    #[must_use]
    pub const fn roast_view(&self) -> u64 {
        self.roast_view
    }

    #[must_use]
    pub const fn ledger_height(&self) -> u64 {
        self.ledger_height
    }

    #[must_use]
    pub const fn ledger_sequence(&self) -> u64 {
        self.ledger_sequence
    }

    #[must_use]
    pub const fn ledger_previous(&self) -> [u8; 32] {
        self.ledger_previous
    }

    /// Stable slot identifier used for reducer lookup and pre-decision delivery IDs.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        if self.roast_view == 0 {
            return self.family_anchor;
        }
        let bytes = postcard::to_allocvec(self).expect("bounded consensus slot serializes");
        let mut hasher = blake3::Hasher::new_derive_key(CONSOLIDATION_CONSENSUS_SLOT_DOMAIN);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }

    fn expected_genesis_anchor(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key(CONSOLIDATION_CONSENSUS_GENESIS_SLOT_DOMAIN);
        hasher.update(&self.version.to_le_bytes());
        let binding = postcard::to_allocvec(&self.binding).expect("consensus binding serializes");
        hasher.update(&(binding.len() as u64).to_le_bytes());
        hasher.update(&binding);
        hasher.update(&self.committee.digest());
        hasher.update(&self.fault_bound.to_le_bytes());
        hasher.update(&self.ledger_height.to_le_bytes());
        hasher.update(&self.ledger_sequence.to_le_bytes());
        hasher.update(&self.ledger_previous);
        *hasher.finalize().as_bytes()
    }

    /// Consensus session derived exclusively from the value-independent slot.
    #[must_use]
    pub fn session(&self) -> SessionId {
        let digest = self.digest();
        let mut hasher =
            blake3::Hasher::new_derive_key(CONSOLIDATION_CONSENSUS_SLOT_SESSION_DOMAIN);
        hasher.update(&digest);
        SessionId(*hasher.finalize().as_bytes())
    }

    /// Reconstruct the sole valid consensus context for this slot.
    pub fn consensus_context(&self) -> Result<ConsensusContext, ConsolidationWireError> {
        self.validate()?;
        self.committee.validate_async_security_with_faults(self.fault_bound)?;
        Ok(ConsensusContext::new(
            self.binding.clone(),
            self.session(),
            self.committee.clone(),
            self.fault_bound,
            self.ledger_height,
            self.ledger_sequence,
            self.ledger_previous,
        )?)
    }

    /// Compare a received context to the one reconstructed from this trusted slot.
    pub fn verify_context(&self, context: &ConsensusContext) -> Result<(), ConsolidationWireError> {
        if self.consensus_context()? != *context {
            return Err(ConsolidationWireError::InvalidConsensusSlot);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConsolidationWireError> {
        if self.version != CONSOLIDATION_CONSENSUS_SLOT_VERSION
            || self.binding.application.as_slice() != CONSOLIDATION_INTENT_APPLICATION
            || self.committee.digest() == [0; 32]
            || self.family_anchor == [0; 32]
            || (self.roast_view == 0 && self.family_anchor != self.expected_genesis_anchor())
            || self.ledger_sequence == 0
            || (self.ledger_height == 0) != (self.ledger_previous == [0; 32])
            || self.digest() == [0; 32]
            || self.session().0 == [0; 32]
        {
            return Err(ConsolidationWireError::InvalidConsensusSlot);
        }
        Ok(())
    }
}

/// Causal class of one durable Byzantine consolidation delivery.
///
/// The discriminant is part of the exact acknowledgement identifier. A preprocess ACK can never
/// retire a share, and an attestation ACK can never retire the transaction material it endorses.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ByzantineDeliveryKind {
    ConsensusMessage,
    ViewCertificate,
    CertifiedIntent,
    Preprocess,
    KeyImageBinding,
    Share,
    Candidate,
}

impl ByzantineDeliveryKind {
    /// Stable causal outbox order within one `(family, view)`.
    #[must_use]
    pub const fn causal_priority(self) -> u8 {
        match self {
            Self::ConsensusMessage => 0,
            Self::ViewCertificate => 1,
            Self::CertifiedIntent => 2,
            Self::Preprocess => 3,
            Self::KeyImageBinding => 4,
            Self::Share => 5,
            Self::Candidate => 6,
        }
    }
}

/// Exact identifier of one point-to-point delivery of an independently portable body.
///
/// `origin` authenticates the inner Ed25519 statement. `relay` authenticates the outer QUIC peer
/// that actually sent this copy. They intentionally differ when a third party repairs
/// availability. The complete identifier is returned by the recipient only after durable
/// readback; a sender must compare it byte-for-byte before retiring an outbox entry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ByzantineDeliveryId {
    version: u16,
    family: [u8; 32],
    view: u64,
    attempt: [u8; 32],
    session: SessionId,
    kind: ByzantineDeliveryKind,
    origin: PartyId,
    relay: PartyId,
    recipient: PartyId,
    payload: [u8; 32],
}

impl ByzantineDeliveryId {
    #[must_use]
    pub const fn family(&self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub const fn attempt_digest(&self) -> [u8; 32] {
        self.attempt
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub const fn kind(&self) -> ByzantineDeliveryKind {
        self.kind
    }

    #[must_use]
    pub const fn origin(&self) -> PartyId {
        self.origin
    }

    #[must_use]
    pub const fn relay(&self) -> PartyId {
        self.relay
    }

    #[must_use]
    pub const fn recipient(&self) -> PartyId {
        self.recipient
    }

    #[must_use]
    pub const fn payload_digest(&self) -> [u8; 32] {
        self.payload
    }

    /// Stable outbox/response key for this complete identifier.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self).expect("fixed delivery identifier serializes");
        let mut hasher = blake3::Hasher::new_derive_key(BYZANTINE_DELIVERY_DIGEST_DOMAIN);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }

    fn new(
        route: ConsolidationWireRoute,
        family: [u8; 32],
        view: u64,
        binding: &ConsolidationAttemptWireBinding,
        kind: ByzantineDeliveryKind,
        origin: PartyId,
        payload: [u8; 32],
    ) -> Result<Self, ConsolidationWireError> {
        Self::new_with_scope(
            route,
            family,
            view,
            binding.attempt.digest(),
            binding.attempt.session(),
            kind,
            origin,
            payload,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_scope(
        route: ConsolidationWireRoute,
        family: [u8; 32],
        view: u64,
        attempt: [u8; 32],
        session: SessionId,
        kind: ByzantineDeliveryKind,
        origin: PartyId,
        payload: [u8; 32],
    ) -> Result<Self, ConsolidationWireError> {
        let id = Self {
            version: BYZANTINE_DELIVERY_ID_VERSION,
            family,
            view,
            attempt,
            session,
            kind,
            origin,
            relay: route.from,
            recipient: route.to,
            payload,
        };
        id.validate()?;
        Ok(id)
    }

    fn validate(&self) -> Result<(), ConsolidationWireError> {
        if self.version != BYZANTINE_DELIVERY_ID_VERSION
            || self.family == [0; 32]
            || self.attempt == [0; 32]
            || self.session.0 == [0; 32]
            || self.origin.0 == 0
            || self.relay.0 == 0
            || self.recipient.0 == 0
            || self.relay == self.recipient
            || self.payload == [0; 32]
            || (matches!(
                self.kind,
                ByzantineDeliveryKind::CertifiedIntent | ByzantineDeliveryKind::ViewCertificate
            ) && self.origin != self.relay)
            || (!matches!(
                self.kind,
                ByzantineDeliveryKind::CertifiedIntent | ByzantineDeliveryKind::ViewCertificate
            ) && self.origin == self.recipient)
        {
            return Err(ConsolidationWireError::InvalidByzantineDelivery);
        }
        Ok(())
    }
}

fn validate_byzantine_view_binding(
    view: u64,
    binding: &ConsolidationAttemptWireBinding,
) -> Result<(), ConsolidationWireError> {
    binding.validate()?;
    if view.checked_add(1) != Some(binding.attempt.attempt()) {
        return Err(ConsolidationWireError::InvalidByzantineView);
    }
    Ok(())
}

fn validate_byzantine_committee_route(
    route: ConsolidationWireRoute,
    committee: &Committee,
) -> Result<(), ConsolidationWireError> {
    route.validate()?;
    committee.member(route.from)?;
    committee.member(route.to)?;
    Ok(())
}

fn byzantine_payload_digest<T: Serialize>(
    label: &'static [u8],
    value: &T,
) -> Result<[u8; 32], ConsolidationWireError> {
    let mut bytes =
        postcard::to_allocvec(value).map_err(|_| ConsolidationWireError::Serialization)?;
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/consolidation-byzantine/payload/v1");
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    let digest = *hasher.finalize().as_bytes();
    bytes.zeroize();
    Ok(digest)
}

fn validate_certified_prepared_intent(
    binding: &ConsolidationAttemptWireBinding,
    intent: &ConsolidationIntent,
    prepared_intent: &[u8],
) -> Result<(), ConsolidationWireError> {
    binding.validate_authorization(intent.authorization())?;
    if binding.attempt != *intent.attempt()
        || prepared_intent.is_empty()
        || prepared_intent.len() > MAX_CONSOLIDATION_WIRE_BYTES
    {
        return Err(ConsolidationWireError::InvalidCertifiedIntent);
    }
    let decoded = PreparedSweepIntent::decode(prepared_intent)?;
    let authorization = intent.authorization();
    let plan = decoded.plan();
    let input_count = usize::try_from(authorization.input_count())
        .map_err(|_| ConsolidationWireError::InvalidCertifiedIntent)?;
    if plan.wallet != authorization.wallet_id()
        || plan.id != authorization.sweep_id()
        || plan.epoch != binding.attempt.epoch()
        || plan.destination_binding != authorization.destination_policy()
        || plan.inputs.len() != input_count
        || plan.total_input_atomic_units != authorization.total_input_atomic_units()
        || consolidation_input_set_binding(&plan.inputs) != authorization.input_set()
        || decoded.fee_atomic_units() != authorization.fee_atomic_units()
        || OpaqueIntentBinding::from_prepared_sweep_bytes(prepared_intent)
            != authorization.opaque_intent()
    {
        return Err(ConsolidationWireError::InvalidCertifiedIntent);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_byzantine_prepared_with_worker(
    worker: &DepositWorkerState,
    deriver: &DepositAddressDeriver,
    committee: &Committee,
    expected_registry: [u8; 32],
    expected_activation: [u8; 32],
    authorization: &TransactionAuthorization,
    binding: &ConsolidationAttemptWireBinding,
    prepared_intent: &[u8],
    authenticated_minimum: Option<u64>,
) -> Result<PreparedFrostlassSweep, ConsolidationWireError> {
    binding.validate_authorization(authorization)?;
    let signer_set = binding.validate_active(
        committee,
        expected_registry,
        expected_activation,
        deriver.root_spend_key(),
    )?;
    let decoded = PreparedSweepIntent::decode(prepared_intent)?;
    let prepared = match worker.reconstruct_reserved_sweep(deriver, decoded.plan().id) {
        Ok(reserved) => {
            let mut reserved_bytes = reserved.prepared_intent().encode()?;
            let exact = reserved_bytes == prepared_intent;
            reserved_bytes.zeroize();
            if !exact {
                return Err(ConsolidationWireError::WorkerAuthorizationMismatch);
            }
            reserved
        }
        Err(DepositWorkerError::Wallet(DepositWalletError::UnknownSweep(id)))
            if id == decoded.plan().id =>
        {
            if let Some(minimum) = authenticated_minimum {
                worker.verify_prepared_sweep_intent_at_or_above(deriver, &decoded, minimum)?
            } else {
                worker.verify_prepared_sweep_intent(deriver, &decoded)?
            }
        }
        Err(error) => return Err(error.into()),
    };
    let plan = prepared.plan();
    let input_count = u32::try_from(plan.inputs.len())
        .map_err(|_| ConsolidationWireError::AuthorizationMismatch)?;
    let expected_authorization = TransactionAuthorization::new(
        plan.wallet,
        plan.id,
        OpaqueIntentBinding::from_prepared_sweep_bytes(prepared_intent),
        consolidation_input_set_binding(&plan.inputs),
        plan.destination_binding,
        deriver.root_spend_key(),
        input_count,
        plan.total_input_atomic_units,
        prepared.fee_atomic_units(),
        worker.config().maximum_fee_atomic_units,
    )?;
    let (worker_intent, signing_context) = worker.prepared_signing_binding(
        &prepared,
        committee,
        &signer_set,
        deriver.root_spend_key(),
        binding.attempt.session(),
    )?;
    if &expected_authorization != authorization
        || plan.epoch != binding.attempt.epoch()
        || worker_intent != binding.attempt.worker_intent_digest()
        || signing_context != binding.attempt.signing_context()
    {
        return Err(ConsolidationWireError::WorkerAuthorizationMismatch);
    }
    Ok(prepared)
}

fn validate_consensus_value_attachment(
    context: &ConsensusContext,
    slot: &ConsolidationConsensusSlot,
    value: &ConsensusValue,
    attachment: &ByzantineConsensusValueAttachment,
) -> Result<(), ConsolidationWireError> {
    if attachment.value != value.digest() {
        return Err(ConsolidationWireError::InvalidConsensusValueAttachments);
    }
    validate_byzantine_view_binding(slot.roast_view, &attachment.binding)?;
    let intent = decode_consolidation_intent(context, value)?;
    attachment.binding.validate_authorization(intent.authorization())?;
    if attachment.binding.attempt != *intent.attempt() {
        return Err(ConsolidationWireError::InvalidCertifiedIntent);
    }
    attachment.binding.validate_active(
        &slot.committee,
        slot.binding.registry,
        slot.binding.activation,
        intent.authorization().root_group_key(),
    )?;
    let plan =
        RoastViewPlan::derive(slot, &slot.committee, slot.fault_bound, intent.authorization())
            .map_err(|_| ConsolidationWireError::NonDeterministicRoastAttempt)?;
    if attachment.binding.leader != plan.relay_seed()
        || attachment.binding.attempt.attempt() != plan.attempt()
        || attachment.binding.attempt.signers() != plan.signers()
        || attachment.binding.attempt.session() != plan.signing_session()
    {
        return Err(ConsolidationWireError::NonDeterministicRoastAttempt);
    }
    validate_certified_prepared_intent(
        &attachment.binding,
        &intent,
        &attachment.prepared_intent.0,
    )?;
    Ok(())
}

fn decode_unverified_consensus_payload(
    envelope: &SignedEnvelope,
) -> Result<ConsensusMessage, ConsolidationWireError> {
    if envelope.payload.len() > MAX_CONSENSUS_MESSAGE_BYTES {
        return Err(ConsolidationWireError::MessageTooLarge {
            actual: envelope.payload.len(),
            maximum: MAX_CONSENSUS_MESSAGE_BYTES,
        });
    }
    let (message, trailing) = postcard::take_from_bytes::<ConsensusMessage>(&envelope.payload)
        .map_err(|_| ConsolidationWireError::Serialization)?;
    if !trailing.is_empty() {
        return Err(ConsolidationWireError::TrailingBytes(trailing.len()));
    }
    Ok(message)
}

fn insert_consensus_value(
    values: &mut BTreeMap<ConsensusValueDigest, ConsensusValue>,
    value: &ConsensusValue,
) -> Result<(), ConsolidationWireError> {
    value.validate()?;
    if let Some(existing) = values.insert(value.digest(), value.clone())
        && existing != *value
    {
        return Err(ConsolidationWireError::InvalidConsensusValueAttachments);
    }
    Ok(())
}

fn collect_prepare_value(
    values: &mut BTreeMap<ConsensusValueDigest, ConsensusValue>,
    certificate: Option<&crate::deposit_consensus::PrepareCertificate>,
) -> Result<(), ConsolidationWireError> {
    if let Some(certificate) = certificate {
        insert_consensus_value(values, certificate.value())?;
    }
    Ok(())
}

fn collect_view_certificate_values(
    context: &ConsensusContext,
    values: &mut BTreeMap<ConsensusValueDigest, ConsensusValue>,
    certificate: &ViewChangeCertificate,
) -> Result<(), ConsolidationWireError> {
    for witness in certificate.witnesses() {
        let message = decode_unverified_consensus_payload(witness)?;
        if message.context != context.digest() {
            return Err(ConsolidationWireError::InvalidConsensusValueAttachments);
        }
        let ConsensusMessageBody::ViewChange(change) = message.body else {
            return Err(ConsolidationWireError::InvalidConsensusValueAttachments);
        };
        collect_prepare_value(values, change.highest_prepared.as_ref())?;
    }
    Ok(())
}

fn collect_message_values(
    context: &ConsensusContext,
    values: &mut BTreeMap<ConsensusValueDigest, ConsensusValue>,
    body: &ConsensusMessageBody,
) -> Result<(), ConsolidationWireError> {
    match body {
        ConsensusMessageBody::Proposal(proposal) => {
            insert_consensus_value(values, &proposal.value)?;
            collect_prepare_value(values, proposal.proof_of_lock.as_ref())?;
            if let Some(certificate) = &proposal.view_change {
                collect_view_certificate_values(context, values, certificate)?;
            }
        }
        ConsensusMessageBody::ViewChange(change) => {
            collect_prepare_value(values, change.highest_prepared.as_ref())?;
        }
        ConsensusMessageBody::Prevote(_) | ConsensusMessageBody::Precommit(_) => {}
    }
    Ok(())
}

/// Canonically collect every unique full value reachable through a body and its nested proofs.
///
/// Services use this before constructing a relay to select the exact already-validated attachment
/// set; a missing or extra attachment makes the relay constructor fail closed.
pub fn referenced_consolidation_consensus_values(
    context: &ConsensusContext,
    body: &ByzantineConsensusBody,
) -> Result<Vec<ConsensusValue>, ConsolidationWireError> {
    let mut values = BTreeMap::new();
    match body {
        ByzantineConsensusBody::Message(envelope) => {
            let message = decode_unverified_consensus_payload(envelope)?;
            if message.context != context.digest() {
                return Err(ConsolidationWireError::InvalidConsensusValueAttachments);
            }
            collect_message_values(context, &mut values, &message.body)?;
        }
        ByzantineConsensusBody::ViewCertificate(certificate) => {
            collect_view_certificate_values(context, &mut values, certificate)?;
        }
    }
    if values.len() > MAX_CONSENSUS_VALUE_ATTACHMENTS {
        return Err(ConsolidationWireError::InvalidConsensusValueAttachments);
    }
    Ok(values.into_values().collect())
}

fn validate_consensus_value_attachments(
    context: &ConsensusContext,
    slot: &ConsolidationConsensusSlot,
    body: &ByzantineConsensusBody,
    attachments: &[ByzantineConsensusValueAttachment],
) -> Result<(), ConsolidationWireError> {
    let values = referenced_consolidation_consensus_values(context, body)?;
    if attachments.len() != values.len()
        || attachments.windows(2).any(|pair| pair[0].value >= pair[1].value)
    {
        return Err(ConsolidationWireError::InvalidConsensusValueAttachments);
    }
    for (value, attachment) in values.iter().zip(attachments) {
        validate_consensus_value_attachment(context, slot, value, attachment)?;
    }
    Ok(())
}

/// Portable consensus traffic needed to produce each ROAST view's intent certificate.
///
/// Allocation/handoff consensus lanes use a different application predicate and must not receive
/// these bodies. The fixed Byzantine wire magic plus a distinct transport operation prevents
/// accidental cross-lane decoding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ByzantineConsensusBody {
    Message(SignedEnvelope),
    ViewCertificate(ViewChangeCertificate),
}

/// Exact private material required to validate one consensus value before reducer admission.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ByzantineConsensusValueAttachment {
    value: ConsensusValueDigest,
    binding: ConsolidationAttemptWireBinding,
    prepared_intent: PreparedIntentBytes,
}

impl ByzantineConsensusValueAttachment {
    /// Bind one exact consensus value to the prepared bytes needed for independent validation.
    pub fn new(
        context: &ConsensusContext,
        slot: &ConsolidationConsensusSlot,
        value: &ConsensusValue,
        binding: ConsolidationAttemptWireBinding,
        prepared_intent: Vec<u8>,
    ) -> Result<Self, ConsolidationWireError> {
        let attachment = Self {
            value: value.digest(),
            binding,
            prepared_intent: PreparedIntentBytes(prepared_intent),
        };
        validate_consensus_value_attachment(context, slot, value, &attachment)?;
        Ok(attachment)
    }

    #[must_use]
    pub const fn value_digest(&self) -> ConsensusValueDigest {
        self.value
    }

    #[must_use]
    pub const fn binding(&self) -> &ConsolidationAttemptWireBinding {
        &self.binding
    }

    #[must_use]
    pub fn prepared_intent_bytes(&self) -> &[u8] {
        &self.prepared_intent.0
    }

    /// Digest of the exact canonical private proposal attachment.
    pub fn prepared_intent_digest(&self) -> Result<[u8; 32], ConsolidationWireError> {
        Ok(PreparedSweepIntent::decode(&self.prepared_intent.0)?.digest()?)
    }
}

impl fmt::Debug for ByzantineConsensusValueAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ByzantineConsensusValueAttachment")
            .field("value", &self.value)
            .field("binding", &self.binding)
            .field("prepared_intent_bytes", &self.prepared_intent.0.len())
            .finish_non_exhaustive()
    }
}

fn deserialize_consensus_value_attachments<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ByzantineConsensusValueAttachment>, D::Error> {
    struct AttachmentVisitor;

    impl<'de> Visitor<'de> for AttachmentVisitor {
        type Value = Vec<ByzantineConsensusValueAttachment>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_CONSENSUS_VALUE_ATTACHMENTS} value attachments")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|length| length > MAX_CONSENSUS_VALUE_ATTACHMENTS) {
                return Err(A::Error::custom("too many consensus value attachments"));
            }
            let mut attachments = Vec::with_capacity(
                sequence.size_hint().unwrap_or(0).min(MAX_CONSENSUS_VALUE_ATTACHMENTS),
            );
            while let Some(attachment) = sequence.next_element()? {
                if attachments.len() == MAX_CONSENSUS_VALUE_ATTACHMENTS {
                    return Err(A::Error::custom("too many consensus value attachments"));
                }
                attachments.push(attachment);
            }
            Ok(attachments)
        }
    }

    deserializer.deserialize_seq(AttachmentVisitor)
}

/// Coordinator-free relay for one signed consolidation-consensus message or portable view-change
/// certificate. `view` is the outer deterministic ROAST view; the inner BFT pacemaker view remains
/// authenticated in the envelope/certificate and may advance independently.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ByzantineConsensusRelay {
    route: ConsolidationWireRoute,
    slot: ConsolidationConsensusSlot,
    context: ConsensusContext,
    body: ByzantineConsensusBody,
    #[serde(deserialize_with = "deserialize_consensus_value_attachments")]
    attachments: Vec<ByzantineConsensusValueAttachment>,
}

impl ByzantineConsensusRelay {
    #[allow(clippy::too_many_arguments)]
    pub fn new_message(
        relay: PartyId,
        recipient: PartyId,
        slot: ConsolidationConsensusSlot,
        context: ConsensusContext,
        envelope: SignedEnvelope,
        mut attachments: Vec<ByzantineConsensusValueAttachment>,
    ) -> Result<Self, ConsolidationWireError> {
        attachments.sort_unstable_by_key(ByzantineConsensusValueAttachment::value_digest);
        let message = Self {
            route: ConsolidationWireRoute::new(relay, recipient)?,
            slot,
            context,
            body: ByzantineConsensusBody::Message(envelope),
            attachments,
        };
        message.verify_expected(&message.slot, &message.context)?;
        Ok(message)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_view_certificate(
        relay: PartyId,
        recipient: PartyId,
        slot: ConsolidationConsensusSlot,
        context: ConsensusContext,
        certificate: ViewChangeCertificate,
        mut attachments: Vec<ByzantineConsensusValueAttachment>,
    ) -> Result<Self, ConsolidationWireError> {
        attachments.sort_unstable_by_key(ByzantineConsensusValueAttachment::value_digest);
        let message = Self {
            route: ConsolidationWireRoute::new(relay, recipient)?,
            slot,
            context,
            body: ByzantineConsensusBody::ViewCertificate(certificate),
            attachments,
        };
        message.verify_expected(&message.slot, &message.context)?;
        Ok(message)
    }

    #[must_use]
    pub const fn route(&self) -> ConsolidationWireRoute {
        self.route
    }

    /// Pre-decision scope; this is the slot digest, not the value-derived ROAST family.
    #[must_use]
    pub fn family(&self) -> [u8; 32] {
        self.slot.digest()
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.slot.roast_view
    }

    #[must_use]
    pub const fn slot(&self) -> &ConsolidationConsensusSlot {
        &self.slot
    }

    #[must_use]
    pub fn attachments(&self) -> &[ByzantineConsensusValueAttachment] {
        &self.attachments
    }

    pub fn attachment(
        &self,
        value: ConsensusValueDigest,
    ) -> Option<&ByzantineConsensusValueAttachment> {
        self.attachments
            .binary_search_by_key(&value, ByzantineConsensusValueAttachment::value_digest)
            .ok()
            .map(|index| &self.attachments[index])
    }

    #[must_use]
    pub const fn context(&self) -> &ConsensusContext {
        &self.context
    }

    #[must_use]
    pub const fn body(&self) -> &ByzantineConsensusBody {
        &self.body
    }

    /// Canonically ordered unique full values which must be backend-validated before admission.
    pub fn referenced_values(&self) -> Result<Vec<ConsensusValue>, ConsolidationWireError> {
        referenced_consolidation_consensus_values(&self.context, &self.body)
    }

    #[must_use]
    pub const fn envelope(&self) -> Option<&SignedEnvelope> {
        match &self.body {
            ByzantineConsensusBody::Message(envelope) => Some(envelope),
            ByzantineConsensusBody::ViewCertificate(_) => None,
        }
    }

    #[must_use]
    pub const fn view_certificate(&self) -> Option<&ViewChangeCertificate> {
        match &self.body {
            ByzantineConsensusBody::Message(_) => None,
            ByzantineConsensusBody::ViewCertificate(certificate) => Some(certificate),
        }
    }

    pub fn verify_expected(
        &self,
        expected_slot: &ConsolidationConsensusSlot,
        expected_context: &ConsensusContext,
    ) -> Result<(), ConsolidationWireError> {
        self.validate_structure()?;
        if &self.slot != expected_slot || &self.context != expected_context {
            return Err(ConsolidationWireError::ExpectedByzantineDeliveryMismatch);
        }
        self.slot.verify_context(expected_context)?;
        validate_byzantine_committee_route(self.route, self.context.committee())?;
        match &self.body {
            ByzantineConsensusBody::Message(envelope) => {
                decode_consensus_message(&self.context, envelope)?;
            }
            ByzantineConsensusBody::ViewCertificate(certificate) => {
                certificate.verify(&self.context)?;
            }
        }
        validate_consensus_value_attachments(
            &self.context,
            &self.slot,
            &self.body,
            &self.attachments,
        )
    }

    /// Independently rebuild a proposed transaction before casting any consensus vote.
    ///
    /// This is mandatory for proposal ingress: public authorization fields and an opaque digest
    /// alone do not prove the daemon-selected rings, fee, worker intent, signer subset, or
    /// session-bound signing context. Non-proposal consensus bodies are rejected by this API.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_proposal_with_worker(
        &self,
        expected_slot: &ConsolidationConsensusSlot,
        expected_context: &ConsensusContext,
        worker: &DepositWorkerState,
        deriver: &DepositAddressDeriver,
        committee: &Committee,
        expected_registry: [u8; 32],
        expected_activation: [u8; 32],
    ) -> Result<PreparedFrostlassSweep, ConsolidationWireError> {
        self.verify_proposal_with_worker_at_sweep_floor(
            expected_slot,
            expected_context,
            worker,
            deriver,
            committee,
            expected_registry,
            expected_activation,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_proposal_with_worker_at_sweep_floor(
        &self,
        expected_slot: &ConsolidationConsensusSlot,
        expected_context: &ConsensusContext,
        worker: &DepositWorkerState,
        deriver: &DepositAddressDeriver,
        committee: &Committee,
        expected_registry: [u8; 32],
        expected_activation: [u8; 32],
        authenticated_minimum: Option<u64>,
    ) -> Result<PreparedFrostlassSweep, ConsolidationWireError> {
        self.verify_expected(expected_slot, expected_context)?;
        let ByzantineConsensusBody::Message(envelope) = &self.body else {
            return Err(ConsolidationWireError::InvalidCertifiedIntent);
        };
        let decoded = decode_consensus_message(&self.context, envelope)?;
        let ConsensusMessageBody::Proposal(proposal) = decoded.body else {
            return Err(ConsolidationWireError::InvalidCertifiedIntent);
        };
        let attachment = self
            .attachment(proposal.value.digest())
            .ok_or(ConsolidationWireError::InvalidCertifiedIntent)?;
        let intent = decode_consolidation_intent(&self.context, &proposal.value)?;
        let primary = verify_byzantine_prepared_with_worker(
            worker,
            deriver,
            committee,
            expected_registry,
            expected_activation,
            intent.authorization(),
            &attachment.binding,
            &attachment.prepared_intent.0,
            authenticated_minimum,
        )?;
        for value in self.referenced_values()? {
            if value.digest() == proposal.value.digest() {
                continue;
            }
            let attachment = self
                .attachment(value.digest())
                .ok_or(ConsolidationWireError::InvalidConsensusValueAttachments)?;
            let intent = decode_consolidation_intent(&self.context, &value)?;
            verify_byzantine_prepared_with_worker(
                worker,
                deriver,
                committee,
                expected_registry,
                expected_activation,
                intent.authorization(),
                &attachment.binding,
                &attachment.prepared_intent.0,
                authenticated_minimum,
            )?;
        }
        Ok(primary)
    }

    /// Reconstruct every unique value reachable through this message or nested lock/view proof.
    ///
    /// The caller must additionally await its Monero backend's full prepared-sweep validation for
    /// every returned value and durably persist that result before passing the body to the BA
    /// reducer. Synchronous worker validation alone is not voting authority.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_referenced_values_with_worker(
        &self,
        expected_slot: &ConsolidationConsensusSlot,
        expected_context: &ConsensusContext,
        worker: &DepositWorkerState,
        deriver: &DepositAddressDeriver,
        committee: &Committee,
        expected_registry: [u8; 32],
        expected_activation: [u8; 32],
        authenticated_minimum: Option<u64>,
    ) -> Result<Vec<PreparedFrostlassSweep>, ConsolidationWireError> {
        self.verify_expected(expected_slot, expected_context)?;
        let mut prepared = Vec::with_capacity(self.attachments.len());
        for value in self.referenced_values()? {
            let attachment = self
                .attachment(value.digest())
                .ok_or(ConsolidationWireError::InvalidConsensusValueAttachments)?;
            let intent = decode_consolidation_intent(&self.context, &value)?;
            prepared.push(verify_byzantine_prepared_with_worker(
                worker,
                deriver,
                committee,
                expected_registry,
                expected_activation,
                intent.authorization(),
                &attachment.binding,
                &attachment.prepared_intent.0,
                authenticated_minimum,
            )?);
        }
        Ok(prepared)
    }

    pub fn delivery_id(&self) -> Result<ByzantineDeliveryId, ConsolidationWireError> {
        let (kind, origin, label): (ByzantineDeliveryKind, PartyId, &'static [u8]) =
            match &self.body {
                ByzantineConsensusBody::Message(envelope) => {
                    (ByzantineDeliveryKind::ConsensusMessage, envelope.from, b"consensus-message")
                }
                ByzantineConsensusBody::ViewCertificate(_) => {
                    (ByzantineDeliveryKind::ViewCertificate, self.route.from, b"view-certificate")
                }
            };
        let payload = byzantine_payload_digest(
            label,
            &(&self.slot, &self.context, &self.body, &self.attachments),
        )?;
        ByzantineDeliveryId::new_with_scope(
            self.route,
            self.slot.digest(),
            self.slot.roast_view,
            self.slot.digest(),
            self.context.session(),
            kind,
            origin,
            payload,
        )
    }

    fn validate_structure(&self) -> Result<(), ConsolidationWireError> {
        self.route.validate()?;
        self.slot.verify_context(&self.context)?;
        match &self.body {
            ByzantineConsensusBody::Message(envelope) => {
                if envelope.committee != self.context.committee().digest()
                    || envelope.epoch != self.context.epoch()
                    || envelope.session != self.context.session()
                    || envelope.to.is_some()
                    || envelope.from.0 == 0
                    || self.context.committee().member(envelope.from).is_err()
                    || envelope.payload.is_empty()
                    || envelope.payload.len() > MAX_CONSENSUS_MESSAGE_BYTES
                    || self.route.to == envelope.from
                {
                    return Err(ConsolidationWireError::InvalidByzantineDelivery);
                }
                let decoded = decode_unverified_consensus_payload(envelope)?;
                if decoded.context != self.context.digest() {
                    return Err(ConsolidationWireError::InvalidByzantineView);
                }
            }
            ByzantineConsensusBody::ViewCertificate(_) => {}
        }
        validate_consensus_value_attachments(
            &self.context,
            &self.slot,
            &self.body,
            &self.attachments,
        )?;
        self.delivery_id()?.validate()
    }
}

impl fmt::Debug for ByzantineConsensusRelay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ByzantineConsensusRelay")
            .field("route", &self.route)
            .field("slot", &hex::encode(self.slot.digest()))
            .field("view", &self.slot.roast_view)
            .field("value_attachments", &self.attachments.len())
            .field("context", &self.context.digest())
            .field(
                "body",
                &match &self.body {
                    ByzantineConsensusBody::Message(envelope) => {
                        ("message", envelope.from, envelope.payload.len())
                    }
                    ByzantineConsensusBody::ViewCertificate(certificate) => {
                        ("view_certificate", self.route.from, certificate.witnesses().len())
                    }
                },
            )
            .finish_non_exhaustive()
    }
}

/// A BA-certified ROAST view plus the exact bounded transaction material needed before nonce
/// release. The attachment deliberately fails closed at the 8 MiB QUIC ceiling; larger worker
/// intents require a future content-addressed chunk protocol and are never silently truncated.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ByzantineCertifiedIntent {
    route: ConsolidationWireRoute,
    slot: ConsolidationConsensusSlot,
    family: [u8; 32],
    binding: ConsolidationAttemptWireBinding,
    certificate: ConsolidationIntentCertificate,
    prepared_intent: PreparedIntentBytes,
}

impl ByzantineCertifiedIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay: PartyId,
        recipient: PartyId,
        slot: ConsolidationConsensusSlot,
        family: [u8; 32],
        binding: ConsolidationAttemptWireBinding,
        certificate: ConsolidationIntentCertificate,
        prepared_intent: Vec<u8>,
    ) -> Result<Self, ConsolidationWireError> {
        certificate.verify()?;
        let message = Self {
            route: ConsolidationWireRoute::new(relay, recipient)?,
            slot,
            family,
            binding,
            certificate,
            prepared_intent: PreparedIntentBytes(prepared_intent),
        };
        message.validate_structure()?;
        validate_byzantine_committee_route(
            message.route,
            message.certificate.context().committee(),
        )?;
        Ok(message)
    }

    #[must_use]
    pub const fn route(&self) -> ConsolidationWireRoute {
        self.route
    }

    #[must_use]
    pub const fn family(&self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.slot.roast_view
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
    pub const fn certificate(&self) -> &ConsolidationIntentCertificate {
        &self.certificate
    }

    #[must_use]
    pub fn prepared_intent_bytes(&self) -> &[u8] {
        &self.prepared_intent.0
    }

    pub fn verify_expected(
        &self,
        expected_slot: &ConsolidationConsensusSlot,
        expected_family: [u8; 32],
        expected_binding: &ConsolidationAttemptWireBinding,
        expected_context: &ConsensusContext,
    ) -> Result<ConsolidationIntent, ConsolidationWireError> {
        self.validate_structure()?;
        if &self.slot != expected_slot
            || self.family != expected_family
            || &self.binding != expected_binding
            || self.certificate.context() != expected_context
        {
            return Err(ConsolidationWireError::ExpectedByzantineDeliveryMismatch);
        }
        let intent = self.certificate.verify_in_context(expected_context)?;
        validate_byzantine_committee_route(self.route, expected_context.committee())?;
        validate_certified_prepared_intent(&self.binding, &intent, &self.prepared_intent.0)?;
        Ok(intent)
    }

    /// Rebuild the certified attachment from local scanner state and recompute both private
    /// worker-intent and session-bound signing-context digests before any nonce authority exists.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_with_worker(
        &self,
        expected_slot: &ConsolidationConsensusSlot,
        expected_family: [u8; 32],
        expected_binding: &ConsolidationAttemptWireBinding,
        expected_context: &ConsensusContext,
        worker: &DepositWorkerState,
        deriver: &DepositAddressDeriver,
        committee: &Committee,
        expected_registry: [u8; 32],
        expected_activation: [u8; 32],
    ) -> Result<PreparedFrostlassSweep, ConsolidationWireError> {
        self.verify_with_worker_at_sweep_floor(
            expected_slot,
            expected_family,
            expected_binding,
            expected_context,
            worker,
            deriver,
            committee,
            expected_registry,
            expected_activation,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_with_worker_at_sweep_floor(
        &self,
        expected_slot: &ConsolidationConsensusSlot,
        expected_family: [u8; 32],
        expected_binding: &ConsolidationAttemptWireBinding,
        expected_context: &ConsensusContext,
        worker: &DepositWorkerState,
        deriver: &DepositAddressDeriver,
        committee: &Committee,
        expected_registry: [u8; 32],
        expected_activation: [u8; 32],
        authenticated_minimum: Option<u64>,
    ) -> Result<PreparedFrostlassSweep, ConsolidationWireError> {
        let intent = self.verify_expected(
            expected_slot,
            expected_family,
            expected_binding,
            expected_context,
        )?;
        verify_byzantine_prepared_with_worker(
            worker,
            deriver,
            committee,
            expected_registry,
            expected_activation,
            intent.authorization(),
            &self.binding,
            &self.prepared_intent.0,
            authenticated_minimum,
        )
    }

    pub fn delivery_id(&self) -> Result<ByzantineDeliveryId, ConsolidationWireError> {
        let payload = byzantine_payload_digest(
            b"certified-intent",
            &(&self.slot, &self.binding, &self.certificate, &self.prepared_intent),
        )?;
        ByzantineDeliveryId::new(
            self.route,
            self.family,
            self.slot.roast_view,
            &self.binding,
            ByzantineDeliveryKind::CertifiedIntent,
            self.route.from,
            payload,
        )
    }

    fn validate_structure(&self) -> Result<(), ConsolidationWireError> {
        self.route.validate()?;
        if self.family == [0; 32] {
            return Err(ConsolidationWireError::InvalidByzantineDelivery);
        }
        self.slot.verify_context(self.certificate.context())?;
        // Decode and validate the exact application value without doing quorum signature work.
        // The authenticated ingress reducer calls `verify_expected` only after slot admission.
        let attachment = ByzantineConsensusValueAttachment {
            value: self.certificate.certificate().value().digest(),
            binding: self.binding.clone(),
            prepared_intent: self.prepared_intent.clone(),
        };
        validate_consensus_value_attachment(
            self.certificate.context(),
            &self.slot,
            self.certificate.certificate().value(),
            &attachment,
        )?;
        self.delivery_id()?.validate()
    }
}

impl fmt::Debug for ByzantineCertifiedIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ByzantineCertifiedIntent")
            .field("route", &self.route)
            .field("slot", &hex::encode(self.slot.digest()))
            .field("family", &hex::encode(self.family))
            .field("view", &self.slot.roast_view)
            .field("binding", &self.binding)
            .field("prepared_intent", &self.prepared_intent)
            .finish_non_exhaustive()
    }
}

/// Coordinator-free outer relay for a portable round-one contribution.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ByzantinePreprocessRelay {
    route: ConsolidationWireRoute,
    family: [u8; 32],
    view: u64,
    binding: ConsolidationAttemptWireBinding,
    contribution: SignedPreprocessContribution,
}

impl ByzantinePreprocessRelay {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay: PartyId,
        recipient: PartyId,
        family: [u8; 32],
        view: u64,
        binding: ConsolidationAttemptWireBinding,
        contribution: SignedPreprocessContribution,
        committee: &Committee,
        quic_network_id: [u8; 32],
    ) -> Result<Self, ConsolidationWireError> {
        let message = Self {
            route: ConsolidationWireRoute::new(relay, recipient)?,
            family,
            view,
            binding,
            contribution,
        };
        message.verify_expected(committee, quic_network_id, family, view, &message.binding)?;
        Ok(message)
    }

    wire_accessors!();

    #[must_use]
    pub const fn family(&self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub const fn contribution(&self) -> &SignedPreprocessContribution {
        &self.contribution
    }

    pub fn verify_expected(
        &self,
        committee: &Committee,
        quic_network_id: [u8; 32],
        expected_family: [u8; 32],
        expected_view: u64,
        expected_binding: &ConsolidationAttemptWireBinding,
    ) -> Result<(), ConsolidationWireError> {
        self.validate_structure()?;
        if self.family != expected_family
            || self.view != expected_view
            || &self.binding != expected_binding
        {
            return Err(ConsolidationWireError::ExpectedByzantineDeliveryMismatch);
        }
        validate_byzantine_committee_route(self.route, committee)?;
        self.contribution.verify(committee, quic_network_id, expected_binding)
    }

    pub fn delivery_id(&self) -> Result<ByzantineDeliveryId, ConsolidationWireError> {
        let payload = byzantine_payload_digest(b"preprocess", self.contribution.envelope())?;
        ByzantineDeliveryId::new(
            self.route,
            self.family,
            self.view,
            &self.binding,
            ByzantineDeliveryKind::Preprocess,
            self.contribution.sender(),
            payload,
        )
    }

    fn validate_structure(&self) -> Result<(), ConsolidationWireError> {
        self.route.validate()?;
        validate_byzantine_view_binding(self.view, &self.binding)?;
        self.contribution.validate_structure()?;
        if self.family == [0; 32]
            || self.contribution.binding.attempt != self.binding
            || self.route.to == self.contribution.sender()
        {
            return Err(ConsolidationWireError::InvalidByzantineDelivery);
        }
        self.delivery_id()?.validate()
    }
}

impl_redacted_round_debug!(
    ByzantinePreprocessRelay,
    "preprocess_bytes",
    |message: &ByzantinePreprocessRelay| message.contribution.preprocess.message().as_bytes().len()
);

fn deserialize_bounded_key_image_inputs<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<WalletOutputId>, D::Error> {
    struct InputVisitor;

    impl<'de> Visitor<'de> for InputVisitor {
        type Value = Vec<WalletOutputId>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_BYZANTINE_SWEEP_INPUTS} sweep inputs")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|hint| hint > MAX_BYZANTINE_SWEEP_INPUTS) {
                return Err(A::Error::custom("too many key-image binding inputs"));
            }
            let mut values = Vec::with_capacity(
                sequence.size_hint().unwrap_or(0).min(MAX_BYZANTINE_SWEEP_INPUTS),
            );
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX_BYZANTINE_SWEEP_INPUTS {
                    return Err(A::Error::custom("too many key-image binding inputs"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(InputVisitor)
}

fn deserialize_bounded_key_images<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<[u8; 32]>, D::Error> {
    struct KeyImageVisitor;

    impl<'de> Visitor<'de> for KeyImageVisitor {
        type Value = Vec<[u8; 32]>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_BYZANTINE_SWEEP_INPUTS} key images")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|hint| hint > MAX_BYZANTINE_SWEEP_INPUTS) {
                return Err(A::Error::custom("too many key images"));
            }
            let mut values = Vec::with_capacity(
                sequence.size_hint().unwrap_or(0).min(MAX_BYZANTINE_SWEEP_INPUTS),
            );
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX_BYZANTINE_SWEEP_INPUTS {
                    return Err(A::Error::custom("too many key images"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(KeyImageVisitor)
}

fn proof_verified_unsigned_transaction_digest(
    transaction: &Transaction,
) -> Result<[u8; 32], ConsolidationWireError> {
    let mut unsigned = transaction.clone();
    let Transaction::V2 { proofs: Some(proofs), .. } = &mut unsigned else {
        return Err(ConsolidationWireError::InvalidKeyImageBinding);
    };
    let RctPrunable::Clsag { clsags, pseudo_outs, .. } = &mut proofs.prunable else {
        return Err(ConsolidationWireError::InvalidKeyImageBinding);
    };
    clsags.clear();
    pseudo_outs.clear();
    let mut bytes = unsigned.serialize();
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/deposit-sweep-unsigned-transaction/v1");
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(&bytes);
    let digest = *hasher.finalize().as_bytes();
    bytes.zeroize();
    Ok(digest)
}

/// Attempt-specific portable statement over a proof-verified preprocess set and worker family.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableFamilyKeyImageBinding {
    sweep: SweepId,
    #[serde(deserialize_with = "deserialize_bounded_key_image_inputs")]
    inputs: Vec<WalletOutputId>,
    #[serde(deserialize_with = "deserialize_bounded_key_images")]
    key_images: Vec<[u8; 32]>,
    family_digest: [u8; 32],
    unsigned_transaction_digest: [u8; 32],
    signing_context: SigningContext,
    preprocess_set_digest: [u8; 32],
}

impl PortableFamilyKeyImageBinding {
    #[cfg(test)]
    fn new_for_test(
        sweep: SweepId,
        inputs: Vec<WalletOutputId>,
        key_images: Vec<[u8; 32]>,
        family_digest: [u8; 32],
        unsigned_transaction_digest: [u8; 32],
        signing_context: SigningContext,
        preprocess_set_digest: [u8; 32],
    ) -> Result<Self, ConsolidationWireError> {
        let portable = Self {
            sweep,
            inputs,
            key_images,
            family_digest,
            unsigned_transaction_digest,
            signing_context,
            preprocess_set_digest,
        };
        portable.validate()?;
        Ok(portable)
    }

    fn from_verified_preview(
        attempt: &ConsolidationAttemptWireBinding,
        preview: &ProofVerifiedKeyImagePreview,
        binding: &FamilyKeyImageBinding,
    ) -> Result<Self, ConsolidationWireError> {
        let signing_context = preview.context();
        let key_images = preview.key_images().iter().map(|image| image.to_bytes()).collect();
        let portable = Self {
            sweep: binding.sweep(),
            inputs: binding.inputs().to_vec(),
            key_images,
            family_digest: binding.family_digest(),
            unsigned_transaction_digest: proof_verified_unsigned_transaction_digest(
                preview.unsigned_transaction(),
            )?,
            signing_context,
            preprocess_set_digest: preview.preprocess_set_digest(),
        };
        portable.validate()?;
        portable.verify_worker_binding(binding)?;
        if signing_context.into_bytes() != attempt.attempt.signing_context() {
            return Err(ConsolidationWireError::InvalidKeyImageBinding);
        }
        Ok(portable)
    }

    #[must_use]
    pub const fn sweep(&self) -> SweepId {
        self.sweep
    }

    #[must_use]
    pub fn inputs(&self) -> &[WalletOutputId] {
        &self.inputs
    }

    #[must_use]
    pub fn key_images(&self) -> &[[u8; 32]] {
        &self.key_images
    }

    #[must_use]
    pub const fn family_digest(&self) -> [u8; 32] {
        self.family_digest
    }

    #[must_use]
    pub const fn unsigned_transaction_digest(&self) -> [u8; 32] {
        self.unsigned_transaction_digest
    }

    #[must_use]
    pub const fn signing_context(&self) -> SigningContext {
        self.signing_context
    }

    #[must_use]
    pub const fn preprocess_set_digest(&self) -> [u8; 32] {
        self.preprocess_set_digest
    }

    /// Compare this statement to an API-unforgeable locally verified preprocess receipt.
    pub fn verify_proof_verified_preview(
        &self,
        attempt: &ConsolidationAttemptWireBinding,
        preview: &ProofVerifiedKeyImagePreview,
        worker_binding: &FamilyKeyImageBinding,
    ) -> Result<(), ConsolidationWireError> {
        let expected = Self::from_verified_preview(attempt, preview, worker_binding)?;
        if self != &expected {
            return Err(ConsolidationWireError::InvalidKeyImageBinding);
        }
        Ok(())
    }

    pub fn verify_worker_binding(
        &self,
        expected: &FamilyKeyImageBinding,
    ) -> Result<(), ConsolidationWireError> {
        self.validate()?;
        if self.sweep != expected.sweep()
            || self.inputs != expected.inputs()
            || self.key_images != expected.key_images()
            || self.family_digest != expected.family_digest()
            || self.unsigned_transaction_digest != expected.unsigned_transaction_digest()
        {
            return Err(ConsolidationWireError::InvalidKeyImageBinding);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConsolidationWireError> {
        if self.sweep.0 == [0; 32]
            || self.inputs.is_empty()
            || self.inputs.len() > MAX_BYZANTINE_SWEEP_INPUTS
            || self.key_images.len() != self.inputs.len()
            || self.inputs.windows(2).any(|window| window[0] >= window[1])
            || self.key_images.iter().any(|image| *image == [0; 32])
            || self.key_images.iter().copied().collect::<BTreeSet<_>>().len()
                != self.key_images.len()
            || self.family_digest == [0; 32]
            || self.unsigned_transaction_digest == [0; 32]
            || self.signing_context.into_bytes() == [0; 32]
            || self.preprocess_set_digest == [0; 32]
        {
            return Err(ConsolidationWireError::InvalidKeyImageBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableKeyImageBindingProvenance {
    version: u16,
    quic_network_id: [u8; 32],
    attempt: ConsolidationAttemptWireBinding,
    origin: PartyId,
}

impl PortableKeyImageBindingProvenance {
    #[must_use]
    pub const fn quic_network_id(&self) -> [u8; 32] {
        self.quic_network_id
    }

    #[must_use]
    pub const fn attempt(&self) -> &ConsolidationAttemptWireBinding {
        &self.attempt
    }

    #[must_use]
    pub const fn origin(&self) -> PartyId {
        self.origin
    }

    fn validate(&self) -> Result<(), ConsolidationWireError> {
        self.attempt.validate()?;
        if self.version != KEY_IMAGE_BINDING_ATTESTATION_VERSION
            || self.quic_network_id == [0; 32]
            || self.origin.0 == 0
            || self.attempt.attempt.signers().binary_search(&self.origin).is_err()
        {
            return Err(ConsolidationWireError::InvalidKeyImageBinding);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct CanonicalKeyImageBindingAttestationPayload<'a> {
    domain: &'a str,
    provenance: &'a PortableKeyImageBindingProvenance,
    value: &'a PortableFamilyKeyImageBinding,
}

#[derive(Deserialize)]
struct DecodedKeyImageBindingAttestationPayload {
    domain: String,
    provenance: PortableKeyImageBindingProvenance,
    value: PortableFamilyKeyImageBinding,
}

/// Route-independent attributable statement over the exact unsigned transaction/key-image family.
#[derive(Clone, Eq, PartialEq)]
pub struct PortableKeyImageBindingAttestation {
    provenance: PortableKeyImageBindingProvenance,
    value: PortableFamilyKeyImageBinding,
    envelope: SignedEnvelope,
}

impl Serialize for PortableKeyImageBindingAttestation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.envelope.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PortableKeyImageBindingAttestation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let envelope = SignedEnvelope::deserialize(deserializer)?;
        let (decoded, trailing) = postcard::take_from_bytes::<
            DecodedKeyImageBindingAttestationPayload,
        >(&envelope.payload)
        .map_err(D::Error::custom)?;
        if !trailing.is_empty() || decoded.domain != KEY_IMAGE_BINDING_ATTESTATION_DOMAIN {
            return Err(D::Error::custom("invalid key-image binding attestation payload"));
        }
        let attestation = Self { provenance: decoded.provenance, value: decoded.value, envelope };
        attestation.validate_structure().map_err(D::Error::custom)?;
        Ok(attestation)
    }
}

impl PortableKeyImageBindingAttestation {
    /// Sign only after comparing an API-unforgeable DLEq-verified preview with local worker state.
    pub fn sign(
        identity: &Identity,
        committee: &Committee,
        quic_network_id: [u8; 32],
        attempt: ConsolidationAttemptWireBinding,
        preview: &ProofVerifiedKeyImagePreview,
        worker_binding: &FamilyKeyImageBinding,
    ) -> Result<Self, ConsolidationWireError> {
        let value = PortableFamilyKeyImageBinding::from_verified_preview(
            &attempt,
            preview,
            worker_binding,
        )?;
        Self::sign_value(identity, committee, quic_network_id, attempt, value)
    }

    fn sign_value(
        identity: &Identity,
        committee: &Committee,
        quic_network_id: [u8; 32],
        attempt: ConsolidationAttemptWireBinding,
        value: PortableFamilyKeyImageBinding,
    ) -> Result<Self, ConsolidationWireError> {
        validate_terminal_committee(&attempt, committee)?;
        let provenance = PortableKeyImageBindingProvenance {
            version: KEY_IMAGE_BINDING_ATTESTATION_VERSION,
            quic_network_id,
            attempt,
            origin: identity.party(),
        };
        provenance.validate()?;
        committee.member(provenance.origin)?;
        value.validate()?;
        if value.signing_context.into_bytes() != provenance.attempt.attempt.signing_context() {
            return Err(ConsolidationWireError::InvalidKeyImageBinding);
        }
        let payload = postcard::to_allocvec(&CanonicalKeyImageBindingAttestationPayload {
            domain: KEY_IMAGE_BINDING_ATTESTATION_DOMAIN,
            provenance: &provenance,
            value: &value,
        })
        .map_err(|_| ConsolidationWireError::Serialization)?;
        if payload.len() > MAX_FROSTLASS_MESSAGE_BYTES {
            return Err(ConsolidationWireError::MessageTooLarge {
                actual: payload.len(),
                maximum: MAX_FROSTLASS_MESSAGE_BYTES,
            });
        }
        let envelope = identity.sign_envelope(
            committee,
            provenance.attempt.attempt.session(),
            None,
            KEY_IMAGE_BINDING_ATTESTATION_SEQUENCE,
            payload,
        )?;
        let attestation = Self { provenance, value, envelope };
        attestation.verify(committee, quic_network_id, &attestation.provenance.attempt)?;
        Ok(attestation)
    }

    #[must_use]
    pub const fn provenance(&self) -> &PortableKeyImageBindingProvenance {
        &self.provenance
    }

    #[must_use]
    pub const fn origin(&self) -> PartyId {
        self.provenance.origin
    }

    #[must_use]
    pub const fn value(&self) -> &PortableFamilyKeyImageBinding {
        &self.value
    }

    #[must_use]
    pub const fn envelope(&self) -> &SignedEnvelope {
        &self.envelope
    }

    pub fn verify(
        &self,
        committee: &Committee,
        expected_quic_network_id: [u8; 32],
        expected_attempt: &ConsolidationAttemptWireBinding,
    ) -> Result<(), ConsolidationWireError> {
        self.validate_structure()?;
        if self.provenance.quic_network_id != expected_quic_network_id {
            return Err(ConsolidationWireError::ContributionNetworkMismatch);
        }
        if &self.provenance.attempt != expected_attempt {
            return Err(ConsolidationWireError::ExpectedAttemptMismatch);
        }
        validate_terminal_committee(expected_attempt, committee)?;
        committee.member(self.origin())?;
        // `to = None` makes this an attributable portable broadcast, so verify against the
        // attested origin instead of suggesting that the attempt leader has special authority.
        Identity::verify_envelope(committee, self.origin(), &self.envelope)?;
        Ok(())
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, ConsolidationWireError> {
        postcard::to_allocvec(&CanonicalKeyImageBindingAttestationPayload {
            domain: KEY_IMAGE_BINDING_ATTESTATION_DOMAIN,
            provenance: &self.provenance,
            value: &self.value,
        })
        .map_err(|_| ConsolidationWireError::Serialization)
    }

    fn validate_structure(&self) -> Result<(), ConsolidationWireError> {
        self.provenance.validate()?;
        self.value.validate()?;
        let payload = self.canonical_payload()?;
        if payload.len() > MAX_FROSTLASS_MESSAGE_BYTES
            || self.envelope.committee != self.provenance.attempt.attempt.committee_digest()
            || self.envelope.epoch != self.provenance.attempt.attempt.epoch()
            || self.envelope.session != self.provenance.attempt.attempt.session()
            || self.envelope.from != self.provenance.origin
            || self.envelope.to.is_some()
            || self.envelope.sequence != KEY_IMAGE_BINDING_ATTESTATION_SEQUENCE
            || self.envelope.payload != payload
            || self.value.signing_context.into_bytes()
                != self.provenance.attempt.attempt.signing_context()
        {
            return Err(ConsolidationWireError::InvalidKeyImageBinding);
        }
        Ok(())
    }
}

impl fmt::Debug for PortableKeyImageBindingAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortableKeyImageBindingAttestation")
            .field("provenance", &self.provenance)
            .field("sweep", &self.value.sweep)
            .field("inputs", &self.value.inputs.len())
            .field("key_images", &self.value.key_images.len())
            .field("family_digest", &hex::encode(self.value.family_digest))
            .field("signing_context", &self.value.signing_context)
            .field("preprocess_set_digest", &hex::encode(self.value.preprocess_set_digest))
            .field(
                "unsigned_transaction_digest",
                &hex::encode(self.value.unsigned_transaction_digest),
            )
            .finish_non_exhaustive()
    }
}

fn deserialize_key_image_binding_attestations<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<PortableKeyImageBindingAttestation>, D::Error> {
    deserialize_capped_contribution_vec(deserializer)
}

/// Exact all-selected certificate over one proof-bearing preprocess set and transaction preview.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableKeyImageBindingCertificate {
    version: u16,
    fault_bound: u16,
    #[serde(deserialize_with = "deserialize_key_image_binding_attestations")]
    attestations: Vec<PortableKeyImageBindingAttestation>,
}

impl PortableKeyImageBindingCertificate {
    /// Build the sole canonical certificate from every signer selected for this ROAST view.
    pub fn from_attestations(
        committee: &Committee,
        fault_bound: u16,
        expected_quic_network_id: [u8; 32],
        expected_attempt: &ConsolidationAttemptWireBinding,
        mut attestations: Vec<PortableKeyImageBindingAttestation>,
    ) -> Result<Self, ConsolidationWireError> {
        attestations.sort_unstable_by_key(PortableKeyImageBindingAttestation::origin);
        let certificate =
            Self { version: KEY_IMAGE_BINDING_CERTIFICATE_VERSION, fault_bound, attestations };
        certificate.verify(committee, fault_bound, expected_quic_network_id, expected_attempt)?;
        Ok(certificate)
    }

    #[must_use]
    pub const fn fault_bound(&self) -> u16 {
        self.fault_bound
    }

    #[must_use]
    pub fn attestations(&self) -> &[PortableKeyImageBindingAttestation] {
        &self.attestations
    }

    #[must_use]
    pub fn authorizers(&self) -> Vec<PartyId> {
        self.attestations.iter().map(PortableKeyImageBindingAttestation::origin).collect()
    }

    #[must_use]
    pub fn value(&self) -> Option<&PortableFamilyKeyImageBinding> {
        self.attestations.first().map(PortableKeyImageBindingAttestation::value)
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self).expect("bounded key-image certificate serializes");
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/deposit-consolidation/key-image-certificate/v1",
        );
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }

    /// Verify exact selected origins, all signatures, and the complete attempt-specific value.
    pub fn verify<'a>(
        &'a self,
        committee: &Committee,
        expected_fault_bound: u16,
        expected_quic_network_id: [u8; 32],
        expected_attempt: &ConsolidationAttemptWireBinding,
    ) -> Result<&'a PortableFamilyKeyImageBinding, ConsolidationWireError> {
        committee.validate_async_security_with_faults(expected_fault_bound)?;
        validate_terminal_committee(expected_attempt, committee)?;
        let expected_origins = expected_attempt.attempt.signers();
        if self.version != KEY_IMAGE_BINDING_CERTIFICATE_VERSION
            || self.fault_bound != expected_fault_bound
            || expected_origins.len()
                != usize::from(
                    committee
                        .n()
                        .checked_sub(expected_fault_bound)
                        .ok_or(ConsolidationWireError::InvalidKeyImageBindingCertificate)?,
                )
            || self.attestations.len() != expected_origins.len()
            || self
                .attestations
                .iter()
                .zip(expected_origins)
                .any(|(attestation, expected)| attestation.origin() != *expected)
        {
            return Err(ConsolidationWireError::InvalidKeyImageBindingCertificate);
        }
        let first = self
            .attestations
            .first()
            .ok_or(ConsolidationWireError::InvalidKeyImageBindingCertificate)?;
        for attestation in &self.attestations {
            attestation.verify(committee, expected_quic_network_id, expected_attempt)?;
            if attestation.value() != first.value() {
                return Err(ConsolidationWireError::InvalidKeyImageBindingCertificate);
            }
        }
        Ok(first.value())
    }

    /// Parse only the bounded canonical storage shape; this does not authorize pinning or shares.
    pub fn decode_unverified(bytes: &[u8]) -> Result<Self, ConsolidationWireError> {
        if bytes.len() > MAX_CONSOLIDATION_WIRE_BYTES {
            return Err(ConsolidationWireError::MessageTooLarge {
                actual: bytes.len(),
                maximum: MAX_CONSOLIDATION_WIRE_BYTES,
            });
        }
        let (certificate, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| ConsolidationWireError::Serialization)?;
        if !trailing.is_empty() {
            return Err(ConsolidationWireError::InvalidKeyImageBinding);
        }
        certificate.validate_unverified_shape()?;
        if postcard::to_allocvec(&certificate).map_err(|_| ConsolidationWireError::Serialization)?
            != bytes
        {
            return Err(ConsolidationWireError::InvalidKeyImageBinding);
        }
        Ok(certificate)
    }

    fn validate_unverified_shape(&self) -> Result<(), ConsolidationWireError> {
        if self.version != KEY_IMAGE_BINDING_CERTIFICATE_VERSION
            || self.attestations.is_empty()
            || self.attestations.len() > MAX_COMMITTEE_MEMBERS
            || self.attestations.windows(2).any(|pair| pair[0].origin() >= pair[1].origin())
        {
            return Err(ConsolidationWireError::InvalidKeyImageBindingCertificate);
        }
        let first = self
            .attestations
            .first()
            .ok_or(ConsolidationWireError::InvalidKeyImageBindingCertificate)?;
        for attestation in &self.attestations {
            attestation.validate_structure()?;
            if attestation.value() != first.value() {
                return Err(ConsolidationWireError::InvalidKeyImageBindingCertificate);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for PortableKeyImageBindingCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortableKeyImageBindingCertificate")
            .field("version", &self.version)
            .field("fault_bound", &self.fault_bound)
            .field("attestations", &self.attestations.len())
            .field(
                "origins",
                &self.attestations.iter().map(|item| item.origin()).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// Coordinator-free all-to-all relay of one attributable key-image family statement.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ByzantineKeyImageBindingRelay {
    route: ConsolidationWireRoute,
    family: [u8; 32],
    view: u64,
    binding: ConsolidationAttemptWireBinding,
    attestation: PortableKeyImageBindingAttestation,
}

impl ByzantineKeyImageBindingRelay {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay: PartyId,
        recipient: PartyId,
        family: [u8; 32],
        view: u64,
        binding: ConsolidationAttemptWireBinding,
        attestation: PortableKeyImageBindingAttestation,
        committee: &Committee,
        quic_network_id: [u8; 32],
    ) -> Result<Self, ConsolidationWireError> {
        let message = Self {
            route: ConsolidationWireRoute::new(relay, recipient)?,
            family,
            view,
            binding,
            attestation,
        };
        message.verify_expected(committee, quic_network_id, family, view, &message.binding)?;
        Ok(message)
    }

    wire_accessors!();

    #[must_use]
    pub const fn family(&self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub const fn attestation(&self) -> &PortableKeyImageBindingAttestation {
        &self.attestation
    }

    pub fn verify_expected(
        &self,
        committee: &Committee,
        quic_network_id: [u8; 32],
        expected_family: [u8; 32],
        expected_view: u64,
        expected_binding: &ConsolidationAttemptWireBinding,
    ) -> Result<(), ConsolidationWireError> {
        self.validate_structure()?;
        if self.family != expected_family
            || self.view != expected_view
            || &self.binding != expected_binding
        {
            return Err(ConsolidationWireError::ExpectedByzantineDeliveryMismatch);
        }
        validate_byzantine_committee_route(self.route, committee)?;
        self.attestation.verify(committee, quic_network_id, expected_binding)
    }

    pub fn delivery_id(&self) -> Result<ByzantineDeliveryId, ConsolidationWireError> {
        let payload = byzantine_payload_digest(b"key-image-binding", self.attestation.envelope())?;
        ByzantineDeliveryId::new(
            self.route,
            self.family,
            self.view,
            &self.binding,
            ByzantineDeliveryKind::KeyImageBinding,
            self.attestation.origin(),
            payload,
        )
    }

    fn validate_structure(&self) -> Result<(), ConsolidationWireError> {
        self.route.validate()?;
        validate_byzantine_view_binding(self.view, &self.binding)?;
        self.attestation.validate_structure()?;
        if self.family == [0; 32]
            || self.attestation.provenance.attempt != self.binding
            || self.route.to == self.attestation.origin()
        {
            return Err(ConsolidationWireError::InvalidByzantineDelivery);
        }
        self.delivery_id()?.validate()
    }
}

impl fmt::Debug for ByzantineKeyImageBindingRelay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ByzantineKeyImageBindingRelay")
            .field("route", &self.route)
            .field("family", &hex::encode(self.family))
            .field("view", &self.view)
            .field("binding", &self.binding)
            .field("attestation", &self.attestation)
            .finish_non_exhaustive()
    }
}

/// Coordinator-free outer relay for a portable round-two signature share.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ByzantineShareRelay {
    route: ConsolidationWireRoute,
    family: [u8; 32],
    view: u64,
    binding: ConsolidationAttemptWireBinding,
    contribution: SignedShareContribution,
}

impl ByzantineShareRelay {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay: PartyId,
        recipient: PartyId,
        family: [u8; 32],
        view: u64,
        binding: ConsolidationAttemptWireBinding,
        contribution: SignedShareContribution,
        committee: &Committee,
        quic_network_id: [u8; 32],
    ) -> Result<Self, ConsolidationWireError> {
        let message = Self {
            route: ConsolidationWireRoute::new(relay, recipient)?,
            family,
            view,
            binding,
            contribution,
        };
        message.verify_expected(committee, quic_network_id, family, view, &message.binding)?;
        Ok(message)
    }

    wire_accessors!();

    #[must_use]
    pub const fn family(&self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub const fn contribution(&self) -> &SignedShareContribution {
        &self.contribution
    }

    pub fn verify_expected(
        &self,
        committee: &Committee,
        quic_network_id: [u8; 32],
        expected_family: [u8; 32],
        expected_view: u64,
        expected_binding: &ConsolidationAttemptWireBinding,
    ) -> Result<(), ConsolidationWireError> {
        self.validate_structure()?;
        if self.family != expected_family
            || self.view != expected_view
            || &self.binding != expected_binding
        {
            return Err(ConsolidationWireError::ExpectedByzantineDeliveryMismatch);
        }
        validate_byzantine_committee_route(self.route, committee)?;
        self.contribution.verify(committee, quic_network_id, expected_binding)
    }

    pub fn delivery_id(&self) -> Result<ByzantineDeliveryId, ConsolidationWireError> {
        let payload = byzantine_payload_digest(b"share", self.contribution.envelope())?;
        ByzantineDeliveryId::new(
            self.route,
            self.family,
            self.view,
            &self.binding,
            ByzantineDeliveryKind::Share,
            self.contribution.sender(),
            payload,
        )
    }

    fn validate_structure(&self) -> Result<(), ConsolidationWireError> {
        self.route.validate()?;
        validate_byzantine_view_binding(self.view, &self.binding)?;
        self.contribution.validate_structure()?;
        if self.family == [0; 32]
            || self.contribution.binding.attempt != self.binding
            || self.route.to == self.contribution.sender()
        {
            return Err(ConsolidationWireError::InvalidByzantineDelivery);
        }
        self.delivery_id()?.validate()
    }
}

impl_redacted_round_debug!(ByzantineShareRelay, "share_bytes", |message: &ByzantineShareRelay| {
    message.contribution.share.message().as_bytes().len()
});

/// Coordinator-free relay for one exact signed Monero transaction attestation.
///
/// Stateful reducers must retain at most one transaction value per `(family, view, origin)` and
/// treat a second txid as equivocation. This wrapper makes both values attributable; it does not
/// hide an equivocation by choosing one.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ByzantineCandidateRelay {
    route: ConsolidationWireRoute,
    family: [u8; 32],
    view: u64,
    binding: ConsolidationAttemptWireBinding,
    attestation: PortableSignedTransactionAttestation,
}

impl ByzantineCandidateRelay {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay: PartyId,
        recipient: PartyId,
        family: [u8; 32],
        view: u64,
        binding: ConsolidationAttemptWireBinding,
        attestation: PortableSignedTransactionAttestation,
        committee: &Committee,
        quic_network_id: [u8; 32],
    ) -> Result<Self, ConsolidationWireError> {
        let message = Self {
            route: ConsolidationWireRoute::new(relay, recipient)?,
            family,
            view,
            binding,
            attestation,
        };
        message.verify_expected(committee, quic_network_id, family, view, &message.binding)?;
        Ok(message)
    }

    wire_accessors!();

    #[must_use]
    pub const fn family(&self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub const fn attestation(&self) -> &PortableSignedTransactionAttestation {
        &self.attestation
    }

    pub fn verify_expected(
        &self,
        committee: &Committee,
        quic_network_id: [u8; 32],
        expected_family: [u8; 32],
        expected_view: u64,
        expected_binding: &ConsolidationAttemptWireBinding,
    ) -> Result<(), ConsolidationWireError> {
        self.validate_structure()?;
        if self.family != expected_family
            || self.view != expected_view
            || &self.binding != expected_binding
        {
            return Err(ConsolidationWireError::ExpectedByzantineDeliveryMismatch);
        }
        validate_byzantine_committee_route(self.route, committee)?;
        self.attestation.verify(committee, quic_network_id, expected_binding)
    }

    /// Verify the exact signed Monero transaction against the locally reconstructed signable
    /// transaction. Call this before persisting or endorsing an attestation; structural txid and
    /// FROST binding checks alone do not prove that an honest origin signed the prepared sweep.
    pub fn verify_transaction_for_prepared(
        &self,
        prepared: &PreparedFrostlassSweep,
    ) -> Result<(), ConsolidationWireError> {
        self.validate_structure()?;
        let transaction = self.attestation.signed().transaction().transaction()?;
        let eventuality = Eventuality::from(prepared.transaction().clone());
        let (pruned, _) = transaction.pruned_with_prunable();
        if !eventuality.matches(&pruned) {
            return Err(ConsolidationWireError::InvalidByzantineCandidate);
        }
        Ok(())
    }

    /// Authenticate the portable attestation and prove that its exact Monero transaction belongs
    /// to the expected locally reconstructed signing family in one fail-closed call.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_for_prepared(
        &self,
        committee: &Committee,
        quic_network_id: [u8; 32],
        expected_family: [u8; 32],
        expected_view: u64,
        expected_binding: &ConsolidationAttemptWireBinding,
        prepared: &PreparedFrostlassSweep,
    ) -> Result<(), ConsolidationWireError> {
        self.verify_expected(
            committee,
            quic_network_id,
            expected_family,
            expected_view,
            expected_binding,
        )?;
        self.verify_transaction_for_prepared(prepared)
    }

    /// Full honest-origin admission predicate: authenticate the attestation, bind it to the local
    /// signable transaction, then verify the exact prepared rings, every CLSAG, aggregate
    /// Bulletproof+, RingCT balance, fee, key images, and outputs against durable worker state.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_with_worker(
        &self,
        committee: &Committee,
        quic_network_id: [u8; 32],
        expected_family: [u8; 32],
        expected_view: u64,
        expected_binding: &ConsolidationAttemptWireBinding,
        prepared: &PreparedFrostlassSweep,
        worker: &DepositWorkerState,
    ) -> Result<(), ConsolidationWireError> {
        self.verify_for_prepared(
            committee,
            quic_network_id,
            expected_family,
            expected_view,
            expected_binding,
            prepared,
        )?;
        worker.validate_sweep_family_candidate(
            prepared.plan().id,
            self.attestation.signed().transaction(),
        )?;
        Ok(())
    }

    pub fn delivery_id(&self) -> Result<ByzantineDeliveryId, ConsolidationWireError> {
        let payload = byzantine_payload_digest(b"candidate", self.attestation.envelope())?;
        ByzantineDeliveryId::new(
            self.route,
            self.family,
            self.view,
            &self.binding,
            ByzantineDeliveryKind::Candidate,
            self.attestation.origin(),
            payload,
        )
    }

    fn validate_structure(&self) -> Result<(), ConsolidationWireError> {
        self.route.validate()?;
        validate_byzantine_view_binding(self.view, &self.binding)?;
        self.attestation.validate_structure()?;
        if self.family == [0; 32]
            || self.attestation.binding.attempt != self.binding
            || self.route.to == self.attestation.origin()
        {
            return Err(ConsolidationWireError::InvalidByzantineDelivery);
        }
        self.delivery_id()?.validate()
    }
}

impl fmt::Debug for ByzantineCandidateRelay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ByzantineCandidateRelay")
            .field("route", &self.route)
            .field("family", &hex::encode(self.family))
            .field("view", &self.view)
            .field("binding", &self.binding)
            .field("origin", &self.attestation.origin())
            .field("signed_binding", &self.attestation.signed().binding())
            .finish_non_exhaustive()
    }
}

/// Exact authenticated success response for a Byzantine consolidation delivery.
///
/// This is a response body, not a second durable reverse-outbox protocol. The receiver constructs
/// it only after persisting and reading back the original effect. The original relay verifies the
/// response's QUIC peer and exact identifier before atomically checkpointing the reducer ACK and
/// retiring its outbox body.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ByzantineRelayAck {
    route: ConsolidationWireRoute,
    acknowledged: ByzantineDeliveryId,
}

impl ByzantineRelayAck {
    pub fn new(
        acknowledging_recipient: PartyId,
        acknowledged: ByzantineDeliveryId,
    ) -> Result<Self, ConsolidationWireError> {
        acknowledged.validate()?;
        if acknowledging_recipient != acknowledged.recipient {
            return Err(ConsolidationWireError::InvalidByzantineAck);
        }
        let ack = Self {
            route: ConsolidationWireRoute::new(acknowledged.recipient, acknowledged.relay)?,
            acknowledged,
        };
        ack.validate_structure()?;
        Ok(ack)
    }

    #[must_use]
    pub const fn route(&self) -> ConsolidationWireRoute {
        self.route
    }

    #[must_use]
    pub const fn acknowledged(&self) -> ByzantineDeliveryId {
        self.acknowledged
    }

    #[must_use]
    pub fn relay_id(&self) -> [u8; 32] {
        self.acknowledged.digest()
    }

    pub fn verify_expected(
        &self,
        committee: &Committee,
        expected: ByzantineDeliveryId,
    ) -> Result<(), ConsolidationWireError> {
        self.validate_structure()?;
        validate_byzantine_committee_route(self.route, committee)?;
        if self.acknowledged != expected {
            return Err(ConsolidationWireError::ExpectedByzantineDeliveryMismatch);
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), ConsolidationWireError> {
        self.route.validate()?;
        self.acknowledged.validate()?;
        if self.route.from != self.acknowledged.recipient
            || self.route.to != self.acknowledged.relay
        {
            return Err(ConsolidationWireError::InvalidByzantineAck);
        }
        Ok(())
    }
}

/// Canonical coordinator-free consolidation request or exact success response body.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ByzantineConsolidationWireMessage {
    Consensus(ByzantineConsensusRelay),
    CertifiedIntent(ByzantineCertifiedIntent),
    Preprocess(ByzantinePreprocessRelay),
    KeyImageBinding(ByzantineKeyImageBindingRelay),
    Share(ByzantineShareRelay),
    Candidate(ByzantineCandidateRelay),
    Ack(ByzantineRelayAck),
}

#[derive(Serialize, Deserialize)]
struct VersionedByzantineConsolidationWireMessage {
    magic: [u8; 16],
    version: u16,
    message: ByzantineConsolidationWireMessage,
}

impl ByzantineConsolidationWireMessage {
    #[must_use]
    pub const fn route(&self) -> ConsolidationWireRoute {
        match self {
            Self::Consensus(message) => message.route,
            Self::CertifiedIntent(message) => message.route,
            Self::Preprocess(message) => message.route,
            Self::KeyImageBinding(message) => message.route,
            Self::Share(message) => message.route,
            Self::Candidate(message) => message.route,
            Self::Ack(message) => message.route,
        }
    }

    #[must_use]
    pub const fn expected_sender(&self) -> PartyId {
        self.route().from
    }

    #[must_use]
    pub const fn expected_recipient(&self) -> PartyId {
        self.route().to
    }

    #[must_use]
    pub fn family(&self) -> [u8; 32] {
        match self {
            Self::Consensus(message) => message.family(),
            Self::CertifiedIntent(message) => message.family,
            Self::Preprocess(message) => message.family,
            Self::KeyImageBinding(message) => message.family,
            Self::Share(message) => message.family,
            Self::Candidate(message) => message.family,
            Self::Ack(message) => message.acknowledged.family,
        }
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        match self {
            Self::Consensus(message) => message.slot.roast_view,
            Self::CertifiedIntent(message) => message.slot.roast_view,
            Self::Preprocess(message) => message.view,
            Self::KeyImageBinding(message) => message.view,
            Self::Share(message) => message.view,
            Self::Candidate(message) => message.view,
            Self::Ack(message) => message.acknowledged.view,
        }
    }

    pub fn delivery_id(&self) -> Result<ByzantineDeliveryId, ConsolidationWireError> {
        match self {
            Self::Consensus(message) => message.delivery_id(),
            Self::CertifiedIntent(message) => message.delivery_id(),
            Self::Preprocess(message) => message.delivery_id(),
            Self::KeyImageBinding(message) => message.delivery_id(),
            Self::Share(message) => message.delivery_id(),
            Self::Candidate(message) => message.delivery_id(),
            Self::Ack(message) => Ok(message.acknowledged),
        }
    }

    pub fn validate_authenticated_route(
        &self,
        authenticated_sender: PartyId,
        local_recipient: PartyId,
    ) -> Result<(), ConsolidationWireError> {
        if authenticated_sender != self.expected_sender()
            || local_recipient != self.expected_recipient()
        {
            return Err(ConsolidationWireError::AuthenticatedRouteMismatch);
        }
        Ok(())
    }

    pub fn validate_authenticated_route_in_committee(
        &self,
        authenticated_sender: PartyId,
        local_recipient: PartyId,
        committee: &Committee,
    ) -> Result<(), ConsolidationWireError> {
        self.validate_authenticated_route(authenticated_sender, local_recipient)?;
        validate_byzantine_committee_route(self.route(), committee)
    }

    /// Encode one canonical domain-tagged body under the shared 8 MiB QUIC ceiling.
    pub fn encode(&self) -> Result<Vec<u8>, ConsolidationWireError> {
        self.validate_structure()?;
        let envelope = VersionedByzantineConsolidationWireMessage {
            magic: BYZANTINE_CONSOLIDATION_WIRE_MAGIC,
            version: BYZANTINE_CONSOLIDATION_WIRE_VERSION,
            message: self.clone(),
        };
        let mut bytes =
            postcard::to_allocvec(&envelope).map_err(|_| ConsolidationWireError::Serialization)?;
        if bytes.len() > MAX_CONSOLIDATION_WIRE_BYTES {
            let actual = bytes.len();
            bytes.zeroize();
            return Err(ConsolidationWireError::MessageTooLarge {
                actual,
                maximum: MAX_CONSOLIDATION_WIRE_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Decode exactly one canonical Byzantine body. The byte ceiling is checked before Serde can
    /// allocate an attacker-declared vector; nested consensus witness vectors have their own
    /// committee-size visitor and round bodies remain constrained by their existing hard caps.
    pub fn decode(bytes: &[u8]) -> Result<Self, ConsolidationWireError> {
        if bytes.len() > MAX_CONSOLIDATION_WIRE_BYTES {
            return Err(ConsolidationWireError::MessageTooLarge {
                actual: bytes.len(),
                maximum: MAX_CONSOLIDATION_WIRE_BYTES,
            });
        }
        let (envelope, trailing) =
            postcard::take_from_bytes::<VersionedByzantineConsolidationWireMessage>(bytes)
                .map_err(|_| ConsolidationWireError::Serialization)?;
        if !trailing.is_empty() {
            return Err(ConsolidationWireError::TrailingBytes(trailing.len()));
        }
        if envelope.magic != BYZANTINE_CONSOLIDATION_WIRE_MAGIC
            || envelope.version != BYZANTINE_CONSOLIDATION_WIRE_VERSION
        {
            return Err(ConsolidationWireError::UnsupportedByzantineProtocol);
        }
        envelope.message.validate_structure()?;
        let mut canonical =
            postcard::to_allocvec(&envelope).map_err(|_| ConsolidationWireError::Serialization)?;
        let equal = canonical == bytes;
        canonical.zeroize();
        if !equal {
            return Err(ConsolidationWireError::NonCanonicalEncoding);
        }
        Ok(envelope.message)
    }

    fn validate_structure(&self) -> Result<(), ConsolidationWireError> {
        match self {
            Self::Consensus(message) => message.validate_structure(),
            Self::CertifiedIntent(message) => message.validate_structure(),
            Self::Preprocess(message) => message.validate_structure(),
            Self::KeyImageBinding(message) => message.validate_structure(),
            Self::Share(message) => message.validate_structure(),
            Self::Candidate(message) => message.validate_structure(),
            Self::Ack(message) => message.validate_structure(),
        }
    }
}

impl fmt::Debug for ByzantineConsolidationWireMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consensus(message) => formatter.debug_tuple("Consensus").field(message).finish(),
            Self::CertifiedIntent(message) => {
                formatter.debug_tuple("CertifiedIntent").field(message).finish()
            }
            Self::Preprocess(message) => {
                formatter.debug_tuple("Preprocess").field(message).finish()
            }
            Self::KeyImageBinding(message) => {
                formatter.debug_tuple("KeyImageBinding").field(message).finish()
            }
            Self::Share(message) => formatter.debug_tuple("Share").field(message).finish(),
            Self::Candidate(message) => formatter.debug_tuple("Candidate").field(message).finish(),
            Self::Ack(message) => formatter.debug_tuple("Ack").field(message).finish(),
        }
    }
}

fn deserialize_capped_sensitive_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    struct CappedVisitor;

    impl<'de> Visitor<'de> for CappedVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "prepared intent no larger than {MAX_CONSOLIDATION_WIRE_BYTES} bytes")
        }

        fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            if bytes.len() > MAX_CONSOLIDATION_WIRE_BYTES {
                return Err(E::custom("prepared intent exceeds consolidation wire bound"));
            }
            Ok(bytes.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            if bytes.len() > MAX_CONSOLIDATION_WIRE_BYTES {
                return Err(E::custom("prepared intent exceeds consolidation wire bound"));
            }
            Ok(bytes)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|hint| hint > MAX_CONSOLIDATION_WIRE_BYTES) {
                return Err(A::Error::custom("prepared intent exceeds consolidation wire bound"));
            }
            let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == MAX_CONSOLIDATION_WIRE_BYTES {
                    bytes.zeroize();
                    return Err(A::Error::custom(
                        "prepared intent exceeds consolidation wire bound",
                    ));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_byte_buf(CappedVisitor)
}

#[derive(Debug, Error)]
pub enum ConsolidationWireError {
    #[error("deposit consensus wire error: {0}")]
    Consensus(#[from] crate::deposit_consensus::ConsensusError),
    #[error("consolidation Byzantine agreement error: {0}")]
    ConsolidationConsensus(#[from] ConsolidationConsensusError),
    #[error("consolidation state error: {0}")]
    Consolidation(#[from] ConsolidationError),
    #[error("deposit worker rejected prepared intent: {0}")]
    Worker(#[from] DepositWorkerError),
    #[error("deposit wallet rejected signed transaction: {0}")]
    Wallet(#[from] DepositWalletError),
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("contribution identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("FROSTLASS binding error: {0}")]
    Signing(#[from] SigningError),
    #[error("invalid explicit consolidation wire route")]
    InvalidRoute,
    #[error("authenticated sender or intended local recipient does not match the payload")]
    AuthenticatedRouteMismatch,
    #[error("Byzantine consolidation wire protocol magic or version is unsupported")]
    UnsupportedByzantineProtocol,
    #[error("invalid or out-of-range Byzantine consolidation view binding")]
    InvalidByzantineView,
    #[error("consolidation consensus slot/context is not the trusted value-independent slot")]
    InvalidConsensusSlot,
    #[error("consensus value attachments are missing, extra, conflicting, or non-canonical")]
    InvalidConsensusValueAttachments,
    #[error("proposal attempt does not match the deterministic ROAST plan for its slot")]
    NonDeterministicRoastAttempt,
    #[error("invalid Byzantine consolidation delivery or acknowledgement identifier")]
    InvalidByzantineDelivery,
    #[error("Byzantine consolidation acknowledgement does not reverse the exact delivery route")]
    InvalidByzantineAck,
    #[error("Byzantine consolidation message does not match the expected durable family/view")]
    ExpectedByzantineDeliveryMismatch,
    #[error("certified consolidation intent or its exact prepared attachment is inconsistent")]
    InvalidCertifiedIntent,
    #[error("signed consolidation candidate does not satisfy the locally reconstructed intent")]
    InvalidByzantineCandidate,
    #[error("portable key-image/unsigned-transaction family binding is invalid or mismatched")]
    InvalidKeyImageBinding,
    #[error("key-image certificate is not the exact all-selected proof-bearing authorization")]
    InvalidKeyImageBindingCertificate,
    #[error("wire message does not match the exact durable local consolidation attempt")]
    ExpectedAttemptMismatch,
    #[error("wire route contains a party outside the fixed signer set")]
    RouteOutsideSignerSet,
    #[error("invalid consolidation attempt wire binding")]
    InvalidAttemptBinding,
    #[error("wire attempt does not match the transaction authorization")]
    AuthorizationMismatch,
    #[error("invalid or unbounded predecessor attempt history")]
    InvalidPredecessorHistory,
    #[error("wire attempt does not match independently authenticated active epoch state")]
    ActiveEpochMismatch,
    #[error("wire attempt does not match the independently persisted worker signing release")]
    WorkerAuthorizationMismatch,
    #[error("invalid signed contribution provenance binding")]
    InvalidContributionBinding,
    #[error("signed contribution belongs to another QUIC network identity")]
    ContributionNetworkMismatch,
    #[error("signed contribution envelope does not match its canonical typed body")]
    ContributionEnvelopeMismatch,
    #[error("invalid portable terminal attestation binding")]
    InvalidTerminalAttestation,
    #[error("portable terminal attestation belongs to another QUIC network identity")]
    TerminalNetworkMismatch,
    #[error("portable terminal envelope does not match its canonical typed body")]
    TerminalEnvelopeMismatch,
    #[error("portable terminal attestation has an unexpected origin")]
    TerminalOriginMismatch,
    #[error("wire message does not contain a portable terminal attestation")]
    MissingTerminalAttestation,
    #[error("request or response has the wrong leader route")]
    WrongLeader,
    #[error("invalid bound preprocess response")]
    InvalidPreprocess,
    #[error("commitment set is not exactly the fixed canonical signer set")]
    InvalidCommitmentSet,
    #[error("invalid bound signature-share response")]
    InvalidShare,
    #[error("share set is not exactly the fixed canonical signer set")]
    InvalidShareSet,
    #[error("signed transaction exceeds its bounded representation")]
    SignedTooLarge,
    #[error("signed transaction bytes/hash/context/intent binding mismatch")]
    SignedBindingMismatch,
    #[error("attempt status is internally inconsistent")]
    StatusMismatch,
    #[error("unsupported consolidation wire version {0}")]
    UnsupportedVersion(u16),
    #[error("consolidation wire serialization failed")]
    Serialization,
    #[error("consolidation wire encoding has {0} trailing bytes")]
    TrailingBytes(usize),
    #[error("non-canonical consolidation wire encoding")]
    NonCanonicalEncoding,
    #[error("consolidation wire message has {actual} bytes; maximum is {maximum}")]
    MessageTooLarge { actual: usize, maximum: usize },
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};
    use monero_oxide::transaction::{Input, Timelock, Transaction, TransactionPrefix};
    use monero_wallet::interface::FeeRate;
    use serde::Serialize;

    use super::*;
    use crate::{
        committee::Member,
        consolidation_consensus::ConsolidationIntent,
        deposit_consensus::{
            CommitCertificate, ConsensusBinding, ConsensusContext, ConsensusMessageBody,
            PrepareCertificate, Proposal, ViewChange, Vote, sign_consensus_message,
        },
        deposit_wallet::{ChainPoint, DepositWalletId, SweepId, WalletOutputId},
        deposit_worker::SweepPlan,
        signing::{PreprocessMessage, SignatureShareMessage},
    };

    const PREPARED_VERSION: u16 = 1;

    #[derive(Serialize)]
    struct PreparedIntentFixture {
        version: u16,
        plan: SweepPlan,
        outgoing_view_key: [u8; 32],
        decoy_inputs: Vec<Vec<u8>>,
        fee_rate: Vec<u8>,
        transaction_commitment: [u8; 32],
        fee_atomic_units: u64,
    }

    #[derive(Serialize)]
    struct BoundMessageFixture {
        context: [u8; 32],
        sender: PartyId,
        message: Vec<u8>,
    }

    #[derive(Serialize)]
    struct FamilyKeyImageBindingFixture {
        sweep: SweepId,
        inputs: Vec<WalletOutputId>,
        key_images: Vec<[u8; 32]>,
        family_digest: [u8; 32],
        unsigned_transaction_digest: [u8; 32],
    }

    struct Fixture {
        committee: Committee,
        identities: Vec<Identity>,
        quic_network_id: [u8; 32],
        registry: [u8; 32],
        activation: [u8; 32],
        prepared: PreparedSweepIntent,
        authorization: TransactionAuthorization,
        attempt: AttemptBinding,
        binding: ConsolidationAttemptWireBinding,
    }

    impl Fixture {
        fn identity(&self, party: PartyId) -> &Identity {
            self.identities
                .iter()
                .find(|identity| identity.party() == party)
                .expect("fixture identity")
        }
    }

    fn plan_digest(plan: &SweepPlan) -> [u8; 32] {
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

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0x58; 32];
        secret[1..9].copy_from_slice(&epoch.to_le_bytes());
        secret[9..11].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    fn fixture() -> Fixture {
        let identities = (1_u16..=3)
            .map(|party| {
                let party = PartyId(party);
                let signing_seed = [u8::try_from(party.0).unwrap(); 32];
                Identity::from_test_secrets(party, 7, &signing_seed, test_x25519_secret(party, 7))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let committee = Committee {
            epoch: 7,
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
        committee.validate().unwrap();
        let quic_network_id = [19; 32];
        let registry = [21; 32];
        let activation = [22; 32];
        let root_group_key = (ED25519_BASEPOINT_POINT * Scalar::from(42_u64)).compress().to_bytes();
        let mut plan = SweepPlan {
            id: SweepId([0; 32]),
            wallet: DepositWalletId([31; 32]),
            sequence: 4,
            epoch: committee.epoch,
            destination_binding: [32; 32],
            at_tip: ChainPoint { height: 90, hash: [33; 32] },
            inputs: vec![WalletOutputId { transaction: [34; 32], index_in_transaction: 2 }],
            total_input_atomic_units: 50_000,
        };
        plan.id = SweepId(plan_digest(&plan));
        let encoded = postcard::to_allocvec(&PreparedIntentFixture {
            version: PREPARED_VERSION,
            plan: plan.clone(),
            outgoing_view_key: [35; 32],
            decoy_inputs: vec![b"private-decoy-sentinel".to_vec()],
            fee_rate: FeeRate::new(1, 1).unwrap().serialize(),
            transaction_commitment: [36; 32],
            fee_atomic_units: 500,
        })
        .unwrap();
        let prepared = PreparedSweepIntent::decode(&encoded).unwrap();
        let authorization = TransactionAuthorization::new(
            plan.wallet,
            plan.id,
            OpaqueIntentBinding::from_prepared_sweep_bytes(&encoded),
            consolidation_input_set_binding(&plan.inputs),
            plan.destination_binding,
            root_group_key,
            1,
            plan.total_input_atomic_units,
            500,
            2_000,
        )
        .unwrap();
        let attempt = AttemptBinding::new(
            1,
            committee.epoch,
            registry,
            committee.digest(),
            activation,
            root_group_key,
            committee.threshold,
            vec![PartyId(1), PartyId(2), PartyId(3)],
            [37; 32],
            crate::SessionId([38; 32]),
            [39; 32],
        )
        .unwrap();
        let binding =
            ConsolidationAttemptWireBinding::new(&authorization, &attempt, PartyId(1)).unwrap();
        Fixture {
            committee,
            identities,
            quic_network_id,
            registry,
            activation,
            prepared,
            authorization,
            attempt,
            binding,
        }
    }

    fn later_attempt(base: &AttemptBinding, number: u64, seed: u8) -> AttemptBinding {
        AttemptBinding::new(
            number,
            base.epoch(),
            base.registry_digest(),
            base.committee_digest(),
            base.activation_digest(),
            base.root_group_key(),
            base.threshold(),
            base.signers().to_vec(),
            [seed; 32],
            crate::SessionId([seed.wrapping_add(1); 32]),
            [seed.wrapping_add(2); 32],
        )
        .unwrap()
    }

    fn preprocess(sender: PartyId, context: [u8; 32], byte: u8) -> BoundPreprocessMessage {
        let encoded =
            postcard::to_allocvec(&BoundMessageFixture { context, sender, message: vec![byte; 8] })
                .unwrap();
        let decoded: BoundPreprocessMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.message(), &PreprocessMessage::from_bytes(vec![byte; 8]));
        decoded
    }

    fn share(sender: PartyId, context: [u8; 32], byte: u8) -> BoundSignatureShareMessage {
        let encoded =
            postcard::to_allocvec(&BoundMessageFixture { context, sender, message: vec![byte; 8] })
                .unwrap();
        let decoded: BoundSignatureShareMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.message(), &SignatureShareMessage::from_bytes(vec![byte; 8]));
        decoded
    }

    fn signed_preprocess(
        fixture: &Fixture,
        sender: PartyId,
        byte: u8,
    ) -> SignedPreprocessContribution {
        SignedPreprocessContribution::sign(
            fixture.identity(sender),
            &fixture.committee,
            fixture.quic_network_id,
            fixture.binding.clone(),
            preprocess(sender, fixture.attempt.signing_context(), byte),
        )
        .unwrap()
    }

    fn signed_share(fixture: &Fixture, sender: PartyId, byte: u8) -> SignedShareContribution {
        SignedShareContribution::sign(
            fixture.identity(sender),
            &fixture.committee,
            fixture.quic_network_id,
            fixture.binding.clone(),
            share(sender, fixture.attempt.signing_context(), byte),
        )
        .unwrap()
    }

    fn signed_transaction() -> SignedSweepTransaction {
        let transaction = Transaction::V1 {
            prefix: TransactionPrefix {
                additional_timelock: Timelock::None,
                inputs: vec![Input::Gen(1)],
                outputs: vec![],
                extra: vec![1, 2, 3],
            },
            signatures: vec![],
        };
        SignedSweepTransaction::from_transaction(&transaction, None).unwrap()
    }

    fn family_key_image_binding(fixture: &Fixture) -> FamilyKeyImageBinding {
        let encoded = postcard::to_allocvec(&FamilyKeyImageBindingFixture {
            sweep: fixture.authorization.sweep_id(),
            inputs: fixture.prepared.plan().inputs.clone(),
            key_images: vec![[81; 32]],
            family_digest: [82; 32],
            unsigned_transaction_digest: [83; 32],
        })
        .unwrap();
        postcard::from_bytes(&encoded).unwrap()
    }

    fn consensus_slot(fixture: &Fixture) -> ConsolidationConsensusSlot {
        ConsolidationConsensusSlot::new(
            ConsensusBinding {
                domain: [61; 32],
                application: CONSOLIDATION_INTENT_APPLICATION.to_vec(),
                wallet: fixture.authorization.wallet_id().0,
                network: fixture.quic_network_id,
                registry: fixture.registry,
                activation: fixture.activation,
            },
            &fixture.committee,
            0,
            0,
            0,
            1,
            [0; 32],
        )
        .unwrap()
    }

    fn deterministic_consensus_attempt(
        fixture: &Fixture,
        slot: &ConsolidationConsensusSlot,
        authorization: &TransactionAuthorization,
        seed: u8,
    ) -> (AttemptBinding, ConsolidationAttemptWireBinding) {
        let plan =
            RoastViewPlan::derive(slot, &fixture.committee, slot.fault_bound(), authorization)
                .unwrap();
        let attempt = AttemptBinding::new(
            plan.attempt(),
            fixture.committee.epoch,
            fixture.registry,
            fixture.committee.digest(),
            fixture.activation,
            authorization.root_group_key(),
            fixture.committee.threshold,
            plan.signers().to_vec(),
            [seed; 32],
            plan.signing_session(),
            [seed.wrapping_add(1); 32],
        )
        .unwrap();
        let binding =
            ConsolidationAttemptWireBinding::new(authorization, &attempt, plan.relay_seed())
                .unwrap();
        (attempt, binding)
    }

    fn certified_intent(
        fixture: &Fixture,
    ) -> (
        ConsolidationConsensusSlot,
        ConsensusContext,
        ConsolidationAttemptWireBinding,
        ConsolidationIntentCertificate,
    ) {
        let slot = consensus_slot(fixture);
        let context = slot.consensus_context().unwrap();
        let (attempt, binding) =
            deterministic_consensus_attempt(fixture, &slot, &fixture.authorization, 37);
        let intent =
            ConsolidationIntent::new(&context, fixture.authorization.clone(), attempt).unwrap();
        let value = intent.to_consensus_value().unwrap();
        let witnesses = fixture
            .identities
            .iter()
            .map(|identity| {
                sign_consensus_message(
                    &context,
                    identity,
                    ConsensusMessageBody::Precommit(Vote { view: 0, value: value.digest() }),
                )
                .unwrap()
            })
            .collect();
        let commit = CommitCertificate::from_witnesses(&context, 0, value, witnesses).unwrap();
        let certificate = ConsolidationIntentCertificate::new(context.clone(), commit).unwrap();
        (slot, context, binding, certificate)
    }

    fn byzantine_round_trip(message: ByzantineConsolidationWireMessage) {
        let encoded = message.encode().unwrap();
        let decoded = ByzantineConsolidationWireMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    #[test]
    fn byzantine_wire_rejects_the_pre_hardened_protocol_version() {
        let fixture = fixture();
        let contribution = signed_preprocess(&fixture, PartyId(1), 0x41);
        let relay = ByzantinePreprocessRelay::new(
            PartyId(2),
            PartyId(3),
            [0x42; 32],
            0,
            fixture.binding.clone(),
            contribution,
            &fixture.committee,
            fixture.quic_network_id,
        )
        .unwrap();
        let message = ByzantineConsolidationWireMessage::Preprocess(relay);
        let stale = VersionedByzantineConsolidationWireMessage {
            magic: BYZANTINE_CONSOLIDATION_WIRE_MAGIC,
            version: 1,
            message,
        };
        let encoded = postcard::to_allocvec(&stale).unwrap();
        assert!(matches!(
            ByzantineConsolidationWireMessage::decode(&encoded),
            Err(ConsolidationWireError::UnsupportedByzantineProtocol)
        ));
    }

    #[test]
    fn byzantine_consensus_proposal_requires_exact_prepared_attachment_and_is_route_bound() {
        let fixture = fixture();
        let slot = consensus_slot(&fixture);
        let context = slot.consensus_context().unwrap();
        let (attempt, binding) =
            deterministic_consensus_attempt(&fixture, &slot, &fixture.authorization, 37);
        let intent =
            ConsolidationIntent::new(&context, fixture.authorization.clone(), attempt).unwrap();
        let value = intent.to_consensus_value().unwrap();
        let prepare_witnesses = fixture
            .identities
            .iter()
            .map(|identity| {
                sign_consensus_message(
                    &context,
                    identity,
                    ConsensusMessageBody::Prevote(Vote { view: 0, value: value.digest() }),
                )
                .unwrap()
            })
            .collect();
        let prepared_certificate =
            PrepareCertificate::from_witnesses(&context, 0, value.clone(), prepare_witnesses)
                .unwrap();
        let proposal = sign_consensus_message(
            &context,
            fixture.identity(context.leader(0)),
            ConsensusMessageBody::Proposal(Proposal {
                view: 0,
                value: value.clone(),
                proof_of_lock: None,
                view_change: None,
            }),
        )
        .unwrap();

        assert!(matches!(
            ByzantineConsensusRelay::new_message(
                PartyId(1),
                PartyId(2),
                slot.clone(),
                context.clone(),
                proposal.clone(),
                vec![],
            ),
            Err(ConsolidationWireError::InvalidConsensusValueAttachments)
        ));

        let attachment = ByzantineConsensusValueAttachment::new(
            &context,
            &slot,
            &value,
            binding.clone(),
            fixture.prepared.encode().unwrap(),
        )
        .unwrap();
        let relay = ByzantineConsensusRelay::new_message(
            PartyId(1),
            PartyId(2),
            slot.clone(),
            context.clone(),
            proposal,
            vec![attachment],
        )
        .unwrap();
        assert_eq!(relay.slot(), &slot);
        assert_eq!(relay.referenced_values().unwrap(), vec![value.clone()]);
        assert!(relay.attachment(value.digest()).is_some());
        let message = ByzantineConsolidationWireMessage::Consensus(relay.clone());
        message.validate_authenticated_route(PartyId(1), PartyId(2)).unwrap();
        assert!(matches!(
            message.validate_authenticated_route(PartyId(3), PartyId(2)),
            Err(ConsolidationWireError::AuthenticatedRouteMismatch)
        ));
        assert_eq!(message.delivery_id().unwrap().kind(), ByzantineDeliveryKind::ConsensusMessage);
        byzantine_round_trip(message);

        let witnesses = fixture
            .identities
            .iter()
            .map(|identity| {
                sign_consensus_message(
                    &context,
                    identity,
                    ConsensusMessageBody::ViewChange(ViewChange {
                        from_view: 0,
                        target_view: 1,
                        highest_prepared: Some(prepared_certificate.clone()),
                    }),
                )
                .unwrap()
            })
            .collect();
        let certificate = ViewChangeCertificate::from_witnesses(&context, 1, witnesses).unwrap();
        assert!(
            ByzantineConsensusRelay::new_view_certificate(
                PartyId(2),
                PartyId(3),
                slot.clone(),
                context.clone(),
                certificate.clone(),
                vec![],
            )
            .is_err()
        );
        let view_certificate = ByzantineConsensusRelay::new_view_certificate(
            PartyId(2),
            PartyId(3),
            slot.clone(),
            context.clone(),
            certificate,
            vec![
                ByzantineConsensusValueAttachment::new(
                    &context,
                    &slot,
                    &value,
                    binding.clone(),
                    fixture.prepared.encode().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(
            view_certificate.delivery_id().unwrap().kind(),
            ByzantineDeliveryKind::ViewCertificate
        );
        assert_eq!(view_certificate.attachments().len(), 1);
        byzantine_round_trip(ByzantineConsolidationWireMessage::Consensus(view_certificate));

        let mut prepared = fixture.prepared.encode().unwrap();
        prepared.push(0);
        assert!(
            ByzantineConsensusValueAttachment::new(&context, &slot, &value, binding, prepared,)
                .is_err()
        );

        let wrong_attempt = AttemptBinding::new(
            1,
            fixture.committee.epoch,
            fixture.registry,
            fixture.committee.digest(),
            fixture.activation,
            fixture.authorization.root_group_key(),
            fixture.committee.threshold,
            vec![PartyId(1), PartyId(2)],
            [93; 32],
            SessionId([94; 32]),
            [95; 32],
        )
        .unwrap();
        let wrong_value = ConsolidationIntent::new(
            &context,
            fixture.authorization.clone(),
            wrong_attempt.clone(),
        )
        .unwrap()
        .to_consensus_value()
        .unwrap();
        let wrong_binding = ConsolidationAttemptWireBinding::new(
            &fixture.authorization,
            &wrong_attempt,
            PartyId(1),
        )
        .unwrap();
        assert!(matches!(
            ByzantineConsensusValueAttachment::new(
                &context,
                &slot,
                &wrong_value,
                wrong_binding,
                fixture.prepared.encode().unwrap(),
            ),
            Err(ConsolidationWireError::NonDeterministicRoastAttempt)
        ));

        // Randomized proposal-specific bindings remain values inside this one slot/session.
        let (second_attempt, second_binding) =
            deterministic_consensus_attempt(&fixture, &slot, &fixture.authorization, 91);
        let second_value =
            ConsolidationIntent::new(&context, fixture.authorization.clone(), second_attempt)
                .unwrap()
                .to_consensus_value()
                .unwrap();
        assert_ne!(second_value.digest(), value.digest());
        let second = ByzantineConsensusRelay::new_message(
            PartyId(1),
            PartyId(2),
            slot.clone(),
            context.clone(),
            sign_consensus_message(
                &context,
                fixture.identity(context.leader(0)),
                ConsensusMessageBody::Proposal(Proposal {
                    view: 0,
                    value: second_value.clone(),
                    proof_of_lock: None,
                    view_change: None,
                }),
            )
            .unwrap(),
            vec![
                ByzantineConsensusValueAttachment::new(
                    &context,
                    &slot,
                    &second_value,
                    second_binding,
                    fixture.prepared.encode().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(second.slot().digest(), relay.slot().digest());
        assert_eq!(second.context().session(), relay.context().session());
        assert_ne!(
            second.delivery_id().unwrap().payload_digest(),
            relay.delivery_id().unwrap().payload_digest()
        );
    }

    #[test]
    fn byzantine_portable_relay_and_ack_bind_origin_relay_recipient_phase_and_payload() {
        let fixture = fixture();
        let family = [64; 32];
        // Party 2 repairs availability for party 1's independently signed contribution. The
        // existing binding's `leader` is party 1, but the outer route is deliberately 2 -> 3.
        let contribution = signed_preprocess(&fixture, PartyId(1), 71);
        let relay = ByzantinePreprocessRelay::new(
            PartyId(2),
            PartyId(3),
            family,
            0,
            fixture.binding.clone(),
            contribution,
            &fixture.committee,
            fixture.quic_network_id,
        )
        .unwrap();
        let id = relay.delivery_id().unwrap();
        assert_eq!(id.kind(), ByzantineDeliveryKind::Preprocess);
        assert_eq!(id.origin(), PartyId(1));
        assert_eq!(id.relay(), PartyId(2));
        assert_eq!(id.recipient(), PartyId(3));

        let ack = ByzantineRelayAck::new(PartyId(3), id).unwrap();
        assert_eq!(ack.route(), ConsolidationWireRoute::new(PartyId(3), PartyId(2)).unwrap());
        assert_eq!(ack.relay_id(), id.digest());
        ack.verify_expected(&fixture.committee, id).unwrap();
        // Exact response replay is structurally idempotent; durable outbox state decides whether
        // it changes anything after restart.
        ack.verify_expected(&fixture.committee, id).unwrap();
        let mut wrong = id;
        wrong.payload[0] ^= 1;
        assert!(matches!(
            ack.verify_expected(&fixture.committee, wrong),
            Err(ConsolidationWireError::ExpectedByzantineDeliveryMismatch)
        ));
        assert!(matches!(
            ByzantineRelayAck::new(PartyId(1), id),
            Err(ConsolidationWireError::InvalidByzantineAck)
        ));

        byzantine_round_trip(ByzantineConsolidationWireMessage::Preprocess(relay));
        byzantine_round_trip(ByzantineConsolidationWireMessage::Ack(ack));

        let worker_binding = family_key_image_binding(&fixture);
        let signing_context: SigningContext =
            postcard::from_bytes(&fixture.attempt.signing_context()).unwrap();
        let portable_key_image_binding = PortableFamilyKeyImageBinding::new_for_test(
            worker_binding.sweep(),
            worker_binding.inputs().to_vec(),
            worker_binding.key_images().to_vec(),
            worker_binding.family_digest(),
            worker_binding.unsigned_transaction_digest(),
            signing_context,
            [88; 32],
        )
        .unwrap();
        let key_image_attestation = PortableKeyImageBindingAttestation::sign_value(
            fixture.identity(PartyId(1)),
            &fixture.committee,
            fixture.quic_network_id,
            fixture.binding.clone(),
            portable_key_image_binding.clone(),
        )
        .unwrap();
        key_image_attestation.value().verify_worker_binding(&worker_binding).unwrap();
        assert!(
            PortableKeyImageBindingCertificate::from_attestations(
                &fixture.committee,
                0,
                fixture.quic_network_id,
                &fixture.binding,
                vec![key_image_attestation.clone()],
            )
            .is_err()
        );
        let mut all_attestations = vec![key_image_attestation.clone()];
        for party in [PartyId(2), PartyId(3)] {
            all_attestations.push(
                PortableKeyImageBindingAttestation::sign_value(
                    fixture.identity(party),
                    &fixture.committee,
                    fixture.quic_network_id,
                    fixture.binding.clone(),
                    portable_key_image_binding.clone(),
                )
                .unwrap(),
            );
        }
        let key_image_certificate = PortableKeyImageBindingCertificate::from_attestations(
            &fixture.committee,
            0,
            fixture.quic_network_id,
            &fixture.binding,
            all_attestations.clone(),
        )
        .unwrap();
        assert_eq!(key_image_certificate.authorizers(), fixture.attempt.signers().to_vec());
        assert_eq!(
            key_image_certificate
                .verify(&fixture.committee, 0, fixture.quic_network_id, &fixture.binding,)
                .unwrap(),
            &portable_key_image_binding
        );
        assert_ne!(key_image_certificate.digest(), [0; 32]);

        let split_preprocess = PortableFamilyKeyImageBinding::new_for_test(
            worker_binding.sweep(),
            worker_binding.inputs().to_vec(),
            worker_binding.key_images().to_vec(),
            worker_binding.family_digest(),
            worker_binding.unsigned_transaction_digest(),
            signing_context,
            [89; 32],
        )
        .unwrap();
        all_attestations[2] = PortableKeyImageBindingAttestation::sign_value(
            fixture.identity(PartyId(3)),
            &fixture.committee,
            fixture.quic_network_id,
            fixture.binding.clone(),
            split_preprocess,
        )
        .unwrap();
        assert!(
            PortableKeyImageBindingCertificate::from_attestations(
                &fixture.committee,
                0,
                fixture.quic_network_id,
                &fixture.binding,
                all_attestations,
            )
            .is_err()
        );
        let key_image_relay = ByzantineKeyImageBindingRelay::new(
            PartyId(2),
            PartyId(3),
            family,
            0,
            fixture.binding.clone(),
            key_image_attestation,
            &fixture.committee,
            fixture.quic_network_id,
        )
        .unwrap();
        let key_image_id = key_image_relay.delivery_id().unwrap();
        assert_eq!(key_image_id.kind(), ByzantineDeliveryKind::KeyImageBinding);
        assert!(
            ByzantineDeliveryKind::Preprocess.causal_priority()
                < ByzantineDeliveryKind::KeyImageBinding.causal_priority()
        );
        assert!(
            ByzantineDeliveryKind::KeyImageBinding.causal_priority()
                < ByzantineDeliveryKind::Share.causal_priority()
        );
        assert!(matches!(
            ack.verify_expected(&fixture.committee, key_image_id),
            Err(ConsolidationWireError::ExpectedByzantineDeliveryMismatch)
        ));
        byzantine_round_trip(ByzantineConsolidationWireMessage::KeyImageBinding(key_image_relay));

        let oversized_inputs = (0..=MAX_BYZANTINE_SWEEP_INPUTS)
            .map(|index| WalletOutputId {
                transaction: [84; 32],
                index_in_transaction: u64::try_from(index).unwrap(),
            })
            .collect::<Vec<_>>();
        let oversized_images = (0..=MAX_BYZANTINE_SWEEP_INPUTS)
            .map(|index| {
                let mut image = [85; 32];
                image[..8].copy_from_slice(&u64::try_from(index + 1).unwrap().to_le_bytes());
                image
            })
            .collect::<Vec<_>>();
        let oversized = PortableFamilyKeyImageBinding {
            sweep: fixture.authorization.sweep_id(),
            inputs: oversized_inputs,
            key_images: oversized_images,
            family_digest: [86; 32],
            unsigned_transaction_digest: [87; 32],
            signing_context,
            preprocess_set_digest: [88; 32],
        };
        assert!(matches!(
            oversized.validate(),
            Err(ConsolidationWireError::InvalidKeyImageBinding)
        ));
        let encoded = postcard::to_allocvec(&oversized).unwrap();
        assert!(postcard::from_bytes::<PortableFamilyKeyImageBinding>(&encoded).is_err());

        let share = ByzantineShareRelay::new(
            PartyId(2),
            PartyId(3),
            family,
            0,
            fixture.binding.clone(),
            signed_share(&fixture, PartyId(1), 72),
            &fixture.committee,
            fixture.quic_network_id,
        )
        .unwrap();
        let share_id = share.delivery_id().unwrap();
        assert_eq!(share_id.kind(), ByzantineDeliveryKind::Share);
        assert_ne!(share_id.digest(), id.digest());
        assert!(matches!(
            ack.verify_expected(&fixture.committee, share_id),
            Err(ConsolidationWireError::ExpectedByzantineDeliveryMismatch)
        ));
        byzantine_round_trip(ByzantineConsolidationWireMessage::Share(share));
    }

    #[test]
    fn byzantine_certified_intent_and_candidate_are_relayable_and_reject_foreign_payloads() {
        let fixture = fixture();
        let family = [65; 32];
        let (slot, context, binding, certificate) = certified_intent(&fixture);
        let certified = ByzantineCertifiedIntent::new(
            PartyId(2),
            PartyId(3),
            slot.clone(),
            family,
            binding.clone(),
            certificate,
            fixture.prepared.encode().unwrap(),
        )
        .unwrap();
        certified.verify_expected(&slot, family, &binding, &context).unwrap();
        let wrong_slot = ConsolidationConsensusSlot::new(
            slot.binding().clone(),
            slot.committee(),
            slot.fault_bound(),
            0,
            0,
            2,
            [0; 32],
        )
        .unwrap();
        let wrong_context = wrong_slot.consensus_context().unwrap();
        assert!(certified.verify_expected(&wrong_slot, family, &binding, &wrong_context).is_err());
        byzantine_round_trip(ByzantineConsolidationWireMessage::CertifiedIntent(certified));

        let attestation = PortableSignedTransactionAttestation::sign(
            fixture.identity(PartyId(1)),
            &fixture.committee,
            fixture.quic_network_id,
            fixture.binding.clone(),
            signed_transaction(),
        )
        .unwrap();
        let candidate = ByzantineCandidateRelay::new(
            PartyId(2),
            PartyId(3),
            family,
            0,
            fixture.binding.clone(),
            attestation,
            &fixture.committee,
            fixture.quic_network_id,
        )
        .unwrap();
        assert_eq!(candidate.delivery_id().unwrap().kind(), ByzantineDeliveryKind::Candidate);
        byzantine_round_trip(ByzantineConsolidationWireMessage::Candidate(candidate));

        let foreign_payload = postcard::to_allocvec(&fixture.authorization).unwrap();
        assert!(ByzantineConsolidationWireMessage::decode(&foreign_payload).is_err());
    }

    #[test]
    fn canonical_slot_session_matches_roast_across_bootstrap_and_successor_view() {
        let fixture = fixture();
        let (slot, context, _, certificate) = certified_intent(&fixture);
        assert_eq!(slot.session(), context.session());
        let intent = certificate.verify().unwrap();
        let roast = crate::consolidation_roast::ConsolidationRoast::new(
            PartyId(1),
            fixture.quic_network_id,
            slot.clone(),
            context,
            intent,
            certificate,
            1_000,
            100,
        )
        .unwrap();
        let successor = roast.expected_slot(1).unwrap();
        let successor_context = roast.expected_context(1).unwrap();
        let successor_plan = roast.expected_plan(1).unwrap();
        assert_eq!(successor.family_anchor(), slot.digest());
        assert_eq!(successor.session(), successor_context.session());
        assert_eq!(successor.session(), successor_plan.consensus_session());
    }

    #[test]
    fn signed_contributions_are_portable_deterministic_and_canonical() {
        let fixture = fixture();
        let first = signed_preprocess(&fixture, PartyId(1), 51);
        let duplicate = signed_preprocess(&fixture, PartyId(1), 51);
        assert_eq!(first, duplicate, "Ed25519 signing and canonical encoding are deterministic");
        assert_eq!(first.envelope().to, None);
        assert_eq!(first.envelope().sequence, PREPROCESS_CONTRIBUTION_SEQUENCE);
        assert_eq!(
            postcard::to_allocvec(&first).unwrap(),
            postcard::to_allocvec(first.envelope()).unwrap(),
            "wrapper wire encoding retains exactly one copy of the signed canonical payload"
        );
        first.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding).unwrap();
        // Exact duplicate delivery is idempotent at the authenticated-object boundary.
        duplicate.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding).unwrap();

        let leader_share = signed_share(&fixture, PartyId(1), 61);
        assert_eq!(leader_share.envelope().to, None);
        assert_eq!(leader_share.envelope().sequence, SHARE_CONTRIBUTION_SEQUENCE);
        assert_ne!(first.envelope().sequence, leader_share.envelope().sequence);
        leader_share.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding).unwrap();
    }

    #[test]
    fn signed_contribution_rejects_tamper_relabelling_and_cross_domain_replay() {
        let fixture = fixture();
        let signed = signed_preprocess(&fixture, PartyId(2), 91);

        let mut signature_tamper = signed.clone();
        signature_tamper.envelope.signature[0] ^= 1;
        assert!(matches!(
            signature_tamper.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding),
            Err(ConsolidationWireError::Identity(IdentityError::InvalidSignature))
        ));
        let data_only_decode: SignedPreprocessContribution =
            postcard::from_bytes(&postcard::to_allocvec(&signature_tamper).unwrap()).unwrap();
        assert!(matches!(
            data_only_decode.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding,),
            Err(ConsolidationWireError::Identity(IdentityError::InvalidSignature))
        ));

        let mut body_tamper = signed.clone();
        body_tamper.preprocess = preprocess(PartyId(2), fixture.attempt.signing_context(), 92);
        assert!(matches!(
            body_tamper.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding),
            Err(ConsolidationWireError::ContributionEnvelopeMismatch)
        ));

        let mut phase_relabel = signed.clone();
        phase_relabel.binding.phase = ConsolidationContributionPhase::Share;
        assert!(matches!(
            phase_relabel.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding),
            Err(ConsolidationWireError::InvalidContributionBinding)
        ));

        let mut sender_relabel = signed.clone();
        sender_relabel.binding.sender = PartyId(3);
        assert!(matches!(
            sender_relabel.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding),
            Err(ConsolidationWireError::InvalidPreprocess)
        ));

        let mut context_relabel = signed.clone();
        context_relabel.binding.signing_context[0] ^= 1;
        assert!(matches!(
            context_relabel.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding),
            Err(ConsolidationWireError::InvalidContributionBinding)
        ));

        let mut authorization_relabel = signed.clone();
        authorization_relabel.binding.attempt.authorization[0] ^= 1;
        assert!(matches!(
            authorization_relabel.verify(
                &fixture.committee,
                fixture.quic_network_id,
                &fixture.binding
            ),
            Err(ConsolidationWireError::ContributionEnvelopeMismatch)
        ));

        let mut leader_relabel = signed.clone();
        leader_relabel.binding.attempt.leader = PartyId(2);
        assert!(matches!(
            leader_relabel.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding),
            Err(ConsolidationWireError::ContributionEnvelopeMismatch)
        ));

        let mut sequence_relabel = signed.clone();
        sequence_relabel.envelope.sequence = SHARE_CONTRIBUTION_SEQUENCE;
        assert!(matches!(
            sequence_relabel.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding),
            Err(ConsolidationWireError::ContributionEnvelopeMismatch)
        ));

        let mut session_relabel = signed.clone();
        session_relabel.envelope.session = crate::SessionId([98; 32]);
        assert!(matches!(
            session_relabel.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding),
            Err(ConsolidationWireError::ContributionEnvelopeMismatch)
        ));

        assert!(matches!(
            signed.verify(&fixture.committee, [99; 32], &fixture.binding),
            Err(ConsolidationWireError::ContributionNetworkMismatch)
        ));
        let mut other_committee = fixture.committee.clone();
        other_committee.epoch += 1;
        assert!(matches!(
            signed.verify(&other_committee, fixture.quic_network_id, &fixture.binding),
            Err(ConsolidationWireError::ActiveEpochMismatch)
        ));

        let other_session_attempt = AttemptBinding::new(
            fixture.attempt.attempt(),
            fixture.attempt.epoch(),
            fixture.attempt.registry_digest(),
            fixture.attempt.committee_digest(),
            fixture.attempt.activation_digest(),
            fixture.attempt.root_group_key(),
            fixture.attempt.threshold(),
            fixture.attempt.signers().to_vec(),
            fixture.attempt.worker_intent_digest(),
            crate::SessionId([101; 32]),
            [102; 32],
        )
        .unwrap();
        let other_session = ConsolidationAttemptWireBinding::new(
            &fixture.authorization,
            &other_session_attempt,
            PartyId(1),
        )
        .unwrap();
        assert!(matches!(
            signed.verify(&fixture.committee, fixture.quic_network_id, &other_session),
            Err(ConsolidationWireError::ExpectedAttemptMismatch)
        ));

        let other_attempt = later_attempt(&fixture.attempt, 2, 103);
        let other_attempt = ConsolidationAttemptWireBinding::new(
            &fixture.authorization,
            &other_attempt,
            PartyId(1),
        )
        .unwrap();
        assert!(matches!(
            signed.verify(&fixture.committee, fixture.quic_network_id, &other_attempt),
            Err(ConsolidationWireError::ExpectedAttemptMismatch)
        ));

        let other_leader = ConsolidationAttemptWireBinding::new(
            &fixture.authorization,
            &fixture.attempt,
            PartyId(2),
        )
        .unwrap();
        assert!(matches!(
            signed.verify(&fixture.committee, fixture.quic_network_id, &other_leader),
            Err(ConsolidationWireError::ExpectedAttemptMismatch)
        ));

        let share = signed_share(&fixture, PartyId(2), 104);
        let mut phase_splice = share.clone();
        phase_splice.envelope = signed.envelope.clone();
        assert!(matches!(
            phase_splice.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding),
            Err(ConsolidationWireError::ContributionEnvelopeMismatch)
        ));
    }

    #[test]
    fn portable_terminal_attestations_are_canonical_and_fail_closed_on_tampering() {
        let fixture = fixture();
        let attestation = PortableSignedTransactionAttestation::sign(
            fixture.identity(PartyId(2)),
            &fixture.committee,
            fixture.quic_network_id,
            fixture.binding.clone(),
            signed_transaction(),
        )
        .unwrap();
        attestation.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding).unwrap();
        assert_eq!(attestation.origin(), PartyId(2));
        assert!(matches!(
            attestation.verify_from(
                &fixture.committee,
                fixture.quic_network_id,
                &fixture.binding,
                PartyId(3),
            ),
            Err(ConsolidationWireError::TerminalOriginMismatch)
        ));
        assert!(matches!(
            attestation.verify(&fixture.committee, [88; 32], &fixture.binding),
            Err(ConsolidationWireError::TerminalNetworkMismatch)
        ));

        let encoded = postcard::to_allocvec(&attestation).unwrap();
        let decoded: PortableSignedTransactionAttestation = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, attestation);

        let mut bad_signature = attestation.clone();
        bad_signature.envelope.signature[0] ^= 1;
        assert!(matches!(
            bad_signature.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding,),
            Err(ConsolidationWireError::Identity(IdentityError::InvalidSignature))
        ));

        let mut bad_payload = attestation.clone();
        bad_payload.envelope.payload[0] ^= 1;
        assert!(matches!(
            bad_payload.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding),
            Err(ConsolidationWireError::TerminalEnvelopeMismatch)
        ));

        let mut bad_session = attestation;
        bad_session.envelope.session = crate::SessionId([99; 32]);
        assert!(matches!(
            bad_session.verify(&fixture.committee, fixture.quic_network_id, &fixture.binding),
            Err(ConsolidationWireError::TerminalEnvelopeMismatch)
        ));
    }
}
