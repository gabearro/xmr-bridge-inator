//! Byzantine agreement values for consolidation intent selection and safe abandonment.
//!
//! Consolidation signing has two consensus boundaries which must remain outside the FROST nonce
//! machine:
//!
//! 1. an exact [`ConsolidationIntent`] is committed before any signing nonce is released; and
//! 2. an attempt may be abandoned only after `n-f` parties have signed an exact
//!    [`ShareUnexposedStatement`].
//!
//! Both boundaries use [`crate::deposit_consensus::DepositConsensus`] for ordering and portable
//! commit certificates. The application values below repeat every security-relevant context field
//! and compare it with a trusted local [`ConsensusContext`]. In particular, a context carried by a
//! peer is never a substitute for the locally reconstructed context.
//!
//! The local share boundary is symmetric: [`PendingShareExposure`] hides an exact outbound share
//! payload until the corresponding `ShareExposed` state is read back byte-for-byte. Conversely,
//! [`PendingShareUnexposed`] hides the unexposed attestation until `AbandonmentFenced` is read back.
//! A party which never received a signing start may take the latter branch directly from
//! `NonceUnreleased`, because it never obtained a nonce or share to expose.
//!
//! Byzantine witnesses may lie about exposure, so `n-f` signatures alone are not enough. The
//! validator intersects the witness set with the exact selected FROST signer set and requires
//! `unattested_selected + min(f, attested_selected) < threshold`. This is the worst-case number of
//! selected shares which could have escaped when up to `f` attesters lie. An unsafe signer-set
//! intersection fails closed. A durable `ThresholdExposed` safety phase is likewise deliberately
//! non-abandonable: local evidence that a complete signature may exist always wins over a remote
//! abandonment certificate.

use std::{collections::BTreeSet, fmt};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::{
    committee::{MAX_COMMITTEE_MEMBERS, PartyId, SessionId},
    deposit_consensus::{CommitCertificate, ConsensusContext, ConsensusError, ConsensusValue},
    deposit_consolidation::{
        AttemptBinding, ConsolidationError, ConsolidationId, TransactionAuthorization,
    },
    identity::{Identity, IdentityError, SignedEnvelope},
};

const INTENT_VERSION: u16 = 1;
const INTENT_CERTIFICATE_VERSION: u16 = 1;
const SHARE_UNEXPOSED_VERSION: u16 = 1;
const SHARE_UNEXPOSED_CERTIFICATE_VERSION: u16 = 1;
const ABANDONMENT_VERSION: u16 = 1;
const ABANDONMENT_CERTIFICATE_VERSION: u16 = 1;
const ATTEMPT_SAFETY_STATE_VERSION: u16 = 1;
const SHARE_UNEXPOSED_SEQUENCE: u64 = 1;
const MAX_SHARE_UNEXPOSED_MESSAGE_BYTES: usize = 4 * 1024;
/// Hard bound for one exact signed-share/outbox payload hidden behind durable readback.
pub const MAX_PENDING_SHARE_PAYLOAD_BYTES: usize = 64 * 1024;

/// Exact application tag required for the pre-nonce intent height.
pub const CONSOLIDATION_INTENT_APPLICATION: &[u8] = b"consolidation-intent/v1";
/// Exact application tag required for the immediately following abandonment height.
pub const CONSOLIDATION_ABANDONMENT_APPLICATION: &[u8] = b"consolidation-abandonment/v1";

/// A complete, field-by-field copy of the trusted consensus context binding.
///
/// The digest alone would cryptographically commit to these fields.  Repeating them makes
/// application validation explicit and prevents integrations from accidentally validating only a
/// subset (for example the wallet but not the network or activation certificate).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ExactContextBinding {
    context: [u8; 32],
    domain: [u8; 32],
    wallet: [u8; 32],
    network: [u8; 32],
    registry: [u8; 32],
    activation: [u8; 32],
    session: SessionId,
    epoch: u64,
    committee: [u8; 32],
    fault_bound: u16,
    threshold: u16,
    height: u64,
    sequence: u64,
    previous: [u8; 32],
}

impl ExactContextBinding {
    fn from_context(context: &ConsensusContext) -> Self {
        Self {
            context: context.digest(),
            domain: context.binding().domain,
            wallet: context.binding().wallet,
            network: context.binding().network,
            registry: context.binding().registry,
            activation: context.binding().activation,
            session: context.session(),
            epoch: context.epoch(),
            committee: context.committee().digest(),
            fault_bound: context.fault_bound(),
            threshold: context.committee().threshold,
            height: context.height(),
            sequence: context.sequence(),
            previous: context.previous(),
        }
    }

    fn validate_for(&self, context: &ConsensusContext) -> Result<(), ConsolidationConsensusError> {
        context.validate()?;
        if self != &Self::from_context(context) {
            return Err(ConsolidationConsensusError::WrongContext);
        }
        Ok(())
    }
}

/// Exact transaction and signing-attempt selection committed before nonce release.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationIntent {
    version: u16,
    context: ExactContextBinding,
    authorization: TransactionAuthorization,
    attempt: AttemptBinding,
}

impl ConsolidationIntent {
    /// Build an intent from a trusted local context and independently validated worker bindings.
    pub fn new(
        context: &ConsensusContext,
        authorization: TransactionAuthorization,
        attempt: AttemptBinding,
    ) -> Result<Self, ConsolidationConsensusError> {
        let intent = Self {
            version: INTENT_VERSION,
            context: ExactContextBinding::from_context(context),
            authorization,
            attempt,
        };
        intent.validate_for_context(context)?;
        Ok(intent)
    }

    /// Validate every application and epoch binding against a locally reconstructed context.
    pub fn validate_for_context(
        &self,
        context: &ConsensusContext,
    ) -> Result<(), ConsolidationConsensusError> {
        if self.version != INTENT_VERSION {
            return Err(ConsolidationConsensusError::UnsupportedVersion);
        }
        require_application(context, CONSOLIDATION_INTENT_APPLICATION)?;
        self.context.validate_for(context)?;
        self.authorization.validate()?;
        self.attempt.validate()?;

        if self.authorization.wallet_id().0 != context.binding().wallet
            || self.attempt.epoch() != context.epoch()
            || self.attempt.registry_digest() != context.binding().registry
            || self.attempt.committee_digest() != context.committee().digest()
            || self.attempt.activation_digest() != context.binding().activation
            || self.attempt.threshold() != context.committee().threshold
            || self.attempt.root_group_key() != self.authorization.root_group_key()
            || self.attempt.session() == context.session()
            || self
                .attempt
                .signers()
                .iter()
                .any(|party| context.committee().member(*party).is_err())
        {
            return Err(ConsolidationConsensusError::InvalidIntentBinding);
        }

        // This is redundant with ConsensusContext's asynchronous committee validation, but it is
        // kept at the abandonment boundary so a future context policy cannot weaken the safety
        // argument silently.
        if self.attempt.threshold() <= context.fault_bound() {
            return Err(ConsolidationConsensusError::UnsafeSigningThreshold);
        }
        let required_available = usize::from(self.attempt.threshold())
            .checked_add(usize::from(context.fault_bound()))
            .ok_or(ConsolidationConsensusError::InsufficientSignerAvailability)?;
        if self.attempt.signers().len() < required_available {
            return Err(ConsolidationConsensusError::InsufficientSignerAvailability);
        }
        Ok(())
    }

    /// Validate this value against an exact intent reconstructed from trusted worker state.
    pub fn validate_expected(
        &self,
        context: &ConsensusContext,
        expected: &Self,
    ) -> Result<(), ConsolidationConsensusError> {
        self.validate_for_context(context)?;
        expected.validate_for_context(context)?;
        if self != expected {
            return Err(ConsolidationConsensusError::WrongExpectedIntent);
        }
        Ok(())
    }

    /// Encode this exact intent as the bounded opaque value consumed by
    /// [`crate::deposit_consensus::DepositConsensus`].
    pub fn to_consensus_value(&self) -> Result<ConsensusValue, ConsolidationConsensusError> {
        let bytes =
            postcard::to_allocvec(self).map_err(|_| ConsolidationConsensusError::Serialization)?;
        Ok(ConsensusValue::new(bytes)?)
    }

    #[must_use]
    pub fn authorization(&self) -> &TransactionAuthorization {
        &self.authorization
    }

    #[must_use]
    pub fn attempt(&self) -> &AttemptBinding {
        &self.attempt
    }

    /// Stable application digest independent of a commit certificate's witness subset.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let encoded = postcard::to_allocvec(self).expect("validated intent serializes");
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/consolidation-intent/value/v1");
        hasher.update(&(encoded.len() as u64).to_le_bytes());
        hasher.update(&encoded);
        *hasher.finalize().as_bytes()
    }
}

/// Decode a canonical intent value and compare it with a trusted local context.
pub fn decode_consolidation_intent(
    context: &ConsensusContext,
    value: &ConsensusValue,
) -> Result<ConsolidationIntent, ConsolidationConsensusError> {
    value.validate()?;
    let intent = decode_exact::<ConsolidationIntent>(value.as_bytes())?;
    intent.validate_for_context(context)?;
    Ok(intent)
}

/// Application predicate suitable for every untrusted
/// [`crate::deposit_consensus::DepositConsensus`] ingress path.
#[must_use]
pub fn validate_consolidation_intent_value(
    context: &ConsensusContext,
    value: &ConsensusValue,
) -> bool {
    decode_consolidation_intent(context, value).is_ok()
}

/// Stateful application predicate which accepts only the exact locally reconstructed intent.
#[must_use]
pub fn validate_consolidation_intent_value_expected(
    context: &ConsensusContext,
    expected: &ConsolidationIntent,
    value: &ConsensusValue,
) -> bool {
    decode_consolidation_intent(context, value)
        .and_then(|intent| intent.validate_expected(context, expected))
        .is_ok()
}

/// Portable commit proof for one pre-nonce consolidation intent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationIntentCertificate {
    version: u16,
    context: ConsensusContext,
    certificate: CommitCertificate,
}

impl ConsolidationIntentCertificate {
    pub fn new(
        context: ConsensusContext,
        certificate: CommitCertificate,
    ) -> Result<Self, ConsolidationConsensusError> {
        let certified = Self { version: INTENT_CERTIFICATE_VERSION, context, certificate };
        certified.verify()?;
        Ok(certified)
    }

    /// Verify the embedded context, quorum certificate, and application value.
    pub fn verify(&self) -> Result<ConsolidationIntent, ConsolidationConsensusError> {
        if self.version != INTENT_CERTIFICATE_VERSION {
            return Err(ConsolidationConsensusError::UnsupportedVersion);
        }
        require_application(&self.context, CONSOLIDATION_INTENT_APPLICATION)?;
        self.certificate.verify(&self.context)?;
        decode_consolidation_intent(&self.context, self.certificate.value())
    }

    /// Verify against a context reconstructed from trusted local deployment state.
    pub fn verify_in_context(
        &self,
        expected: &ConsensusContext,
    ) -> Result<ConsolidationIntent, ConsolidationConsensusError> {
        if &self.context != expected {
            return Err(ConsolidationConsensusError::WrongContext);
        }
        self.verify()
    }

    /// Verify both the portable certificate and the exact intent expected by trusted local state.
    pub fn verify_expected(
        &self,
        expected_context: &ConsensusContext,
        expected_intent: &ConsolidationIntent,
    ) -> Result<ConsolidationIntent, ConsolidationConsensusError> {
        expected_intent.validate_for_context(expected_context)?;
        let certified = self.verify_in_context(expected_context)?;
        certified.validate_expected(expected_context, expected_intent)?;
        Ok(certified)
    }

    #[must_use]
    pub fn context(&self) -> &ConsensusContext {
        &self.context
    }

    #[must_use]
    pub fn certificate(&self) -> &CommitCertificate {
        &self.certificate
    }

    #[must_use]
    pub fn decision_digest(&self) -> [u8; 32] {
        self.certificate.digest()
    }
}

/// Collision-resistant key for one immutable FROST signing attempt.
///
/// The session is repeated next to the complete attempt digest so a reused signing session with a
/// different binding is detected as a collision rather than accepted as a new attempt.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct AttemptSafetyKey {
    session: SessionId,
    attempt: [u8; 32],
}

impl AttemptSafetyKey {
    pub fn from_attempt(attempt: &AttemptBinding) -> Result<Self, ConsolidationConsensusError> {
        attempt.validate()?;
        Ok(Self { session: attempt.session(), attempt: attempt.digest() })
    }

    /// Reconstruct a persisted key after validating its canonical non-zero components.
    pub fn from_parts(
        session: SessionId,
        attempt: [u8; 32],
    ) -> Result<Self, ConsolidationConsensusError> {
        if session.0 == [0; 32] || attempt == [0; 32] {
            return Err(ConsolidationConsensusError::InvalidSafetyKey);
        }
        Ok(Self { session, attempt })
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub const fn attempt_digest(&self) -> [u8; 32] {
        self.attempt
    }
}

/// Monotonic durable safety phase for one exact attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AttemptSafetyPhase {
    NonceUnreleased,
    NonceReleased,
    ShareExposed,
    ThresholdExposed,
    AbandonmentFenced,
    AbandonedCertified { decision: [u8; 32] },
}

impl AttemptSafetyPhase {
    /// Whether no further safety transition is possible for this attempt.
    ///
    /// Terminal state remains a permanent tombstone and must not be deleted or reused.
    #[must_use]
    pub const fn is_transition_terminal(self) -> bool {
        matches!(self, Self::ThresholdExposed | Self::AbandonedCertified { .. })
    }
}

/// Exact binding for an outbound signed-share/outbox payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SharePayloadBinding {
    digest: [u8; 32],
    length: u32,
}

impl SharePayloadBinding {
    fn from_payload(payload: &[u8]) -> Result<Self, ConsolidationConsensusError> {
        if payload.is_empty() || payload.len() > MAX_PENDING_SHARE_PAYLOAD_BYTES {
            return Err(ConsolidationConsensusError::InvalidSharePayload);
        }
        let length = u32::try_from(payload.len())
            .map_err(|_| ConsolidationConsensusError::InvalidSharePayload)?;
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/consolidation-share-payload/v1");
        hasher.update(&(payload.len() as u64).to_le_bytes());
        hasher.update(payload);
        Ok(Self { digest: *hasher.finalize().as_bytes(), length })
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub const fn length(&self) -> u32 {
        self.length
    }
}

/// Durable, exact-intent safety state from one party's perspective.
///
/// The two post-release branches are deliberately disjoint. Once a share crosses the transport
/// boundary this state can never produce an unexposed witness. Once the abandonment fence is
/// durable this state can never authorize a share send, including after restart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationAttemptSafety {
    version: u16,
    local_party: PartyId,
    key: AttemptSafetyKey,
    intent_context: [u8; 32],
    intent_decision: [u8; 32],
    intent: ConsolidationIntent,
    share_payload: Option<SharePayloadBinding>,
    phase: AttemptSafetyPhase,
    revision: u64,
    transition: [u8; 32],
}

impl ConsolidationAttemptSafety {
    /// Bind a new local safety record to one trusted intent and its portable commit proof.
    pub fn new(
        local_party: PartyId,
        expected_context: &ConsensusContext,
        expected_intent: ConsolidationIntent,
        intent_certificate: &ConsolidationIntentCertificate,
    ) -> Result<Self, ConsolidationConsensusError> {
        expected_context.committee().member(local_party).map_err(ConsensusError::from)?;
        intent_certificate.verify_expected(expected_context, &expected_intent)?;
        let key = AttemptSafetyKey::from_attempt(expected_intent.attempt())?;
        let mut state = Self {
            version: ATTEMPT_SAFETY_STATE_VERSION,
            local_party,
            key,
            intent_context: expected_context.digest(),
            intent_decision: intent_certificate.decision_digest(),
            intent: expected_intent,
            share_payload: None,
            phase: AttemptSafetyPhase::NonceUnreleased,
            revision: 0,
            transition: [0; 32],
        };
        state.transition = state.expected_transition_commitment()?;
        state.validate_expected(expected_context, &state.intent.clone(), intent_certificate)?;
        Ok(state)
    }

    #[must_use]
    pub const fn local_party(&self) -> PartyId {
        self.local_party
    }

    #[must_use]
    pub const fn key(&self) -> AttemptSafetyKey {
        self.key
    }

    #[must_use]
    pub const fn phase(&self) -> AttemptSafetyPhase {
        self.phase
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn is_transition_terminal(&self) -> bool {
        self.phase.is_transition_terminal()
    }

    #[must_use]
    pub const fn share_payload_binding(&self) -> Option<SharePayloadBinding> {
        self.share_payload
    }

    #[must_use]
    pub fn expected_intent(&self) -> &ConsolidationIntent {
        &self.intent
    }

    /// Canonically encode the complete state for authenticated durable storage.
    pub fn encode(&self) -> Result<Vec<u8>, ConsolidationConsensusError> {
        postcard::to_allocvec(self).map_err(|_| ConsolidationConsensusError::Serialization)
    }

    /// Restore only after comparing the embedded attempt with trusted intent/certificate state.
    pub fn restore(
        encoded: &[u8],
        expected_context: &ConsensusContext,
        expected_intent: &ConsolidationIntent,
        intent_certificate: &ConsolidationIntentCertificate,
    ) -> Result<Self, ConsolidationConsensusError> {
        let state = decode_exact::<Self>(encoded)?;
        state.validate_expected(expected_context, expected_intent, intent_certificate)?;
        Ok(state)
    }

    /// Revalidate a restored record against exact trusted state.
    pub fn validate_expected(
        &self,
        expected_context: &ConsensusContext,
        expected_intent: &ConsolidationIntent,
        intent_certificate: &ConsolidationIntentCertificate,
    ) -> Result<(), ConsolidationConsensusError> {
        if self.version != ATTEMPT_SAFETY_STATE_VERSION {
            return Err(ConsolidationConsensusError::UnsupportedVersion);
        }
        let expected_key = AttemptSafetyKey::from_attempt(expected_intent.attempt())?;
        if self.key.session == expected_key.session && self.key.attempt != expected_key.attempt {
            return Err(ConsolidationConsensusError::AttemptSessionCollision);
        }
        if self.key != expected_key || self.intent != *expected_intent {
            return Err(ConsolidationConsensusError::WrongExpectedIntent);
        }
        expected_context.committee().member(self.local_party).map_err(ConsensusError::from)?;
        intent_certificate.verify_expected(expected_context, expected_intent)?;
        if self.intent_context != expected_context.digest()
            || self.intent_decision != intent_certificate.decision_digest()
            || self.intent.attempt().session() != self.key.session
            || self.intent.attempt().digest() != self.key.attempt
            || self.intent.attempt().session() == expected_context.session()
            || !self.phase_revision_is_valid()
            || !self.phase_payload_is_valid()
            || self.transition != self.expected_transition_commitment()?
        {
            return Err(ConsolidationConsensusError::InvalidSafetyState);
        }
        Ok(())
    }

    /// Record that the exact nonce-bearing machine has been durably released.
    pub fn mark_nonce_released(
        &mut self,
        expected_context: &ConsensusContext,
        expected_intent: &ConsolidationIntent,
        intent_certificate: &ConsolidationIntentCertificate,
    ) -> Result<bool, ConsolidationConsensusError> {
        self.validate_expected(expected_context, expected_intent, intent_certificate)?;
        match self.phase {
            AttemptSafetyPhase::NonceUnreleased => {
                self.advance(AttemptSafetyPhase::NonceReleased)?;
                Ok(true)
            }
            AttemptSafetyPhase::NonceReleased => Ok(false),
            _ => Err(ConsolidationConsensusError::InvalidSafetyTransition),
        }
    }

    /// Hide an exact outbound share payload until `ShareExposed` is durably read back.
    ///
    /// The returned pending value exposes only the new state bytes. The payload and its
    /// non-cloneable capability become available only through exact canonical readback.
    pub fn prepare_share_exposure(
        &mut self,
        expected_context: &ConsensusContext,
        expected_intent: &ConsolidationIntent,
        intent_certificate: &ConsolidationIntentCertificate,
        payload: Vec<u8>,
    ) -> Result<PendingShareExposure, ConsolidationConsensusError> {
        self.validate_expected(expected_context, expected_intent, intent_certificate)?;
        let payload_binding = SharePayloadBinding::from_payload(&payload)?;
        let mut candidate = self.clone();
        match candidate.phase {
            AttemptSafetyPhase::NonceReleased => {
                candidate.share_payload = Some(payload_binding);
                candidate.advance(AttemptSafetyPhase::ShareExposed)?;
            }
            AttemptSafetyPhase::ShareExposed | AttemptSafetyPhase::ThresholdExposed
                if candidate.share_payload == Some(payload_binding) => {}
            AttemptSafetyPhase::ShareExposed | AttemptSafetyPhase::ThresholdExposed => {
                return Err(ConsolidationConsensusError::ConflictingSharePayload);
            }
            AttemptSafetyPhase::AbandonmentFenced
            | AttemptSafetyPhase::AbandonedCertified { .. } => {
                return Err(ConsolidationConsensusError::ShareExposureAfterFence);
            }
            AttemptSafetyPhase::NonceUnreleased => {
                return Err(ConsolidationConsensusError::NonceNotReleased);
            }
        }

        let state = candidate.encode()?;
        let state_commitment = safety_state_commitment(&state);
        let pending = PendingShareExposure {
            payload,
            payload_binding,
            key: candidate.key,
            local_party: candidate.local_party,
            intent_decision: candidate.intent_decision,
            revision: candidate.revision,
            state_commitment,
            state,
        };
        *self = candidate;
        Ok(pending)
    }

    /// Record durable local evidence that a complete threshold set may be available.
    ///
    /// This transition does not authorize an outbound local share. It may therefore be entered
    /// directly from `NonceReleased` with no local payload binding when threshold exposure was
    /// learned from authenticated remote evidence. It permanently closes abandonment.
    pub fn mark_threshold_exposed(
        &mut self,
        expected_context: &ConsensusContext,
        expected_intent: &ConsolidationIntent,
        intent_certificate: &ConsolidationIntentCertificate,
    ) -> Result<bool, ConsolidationConsensusError> {
        self.validate_expected(expected_context, expected_intent, intent_certificate)?;
        match self.phase {
            AttemptSafetyPhase::NonceReleased | AttemptSafetyPhase::ShareExposed => {
                self.advance(AttemptSafetyPhase::ThresholdExposed)?;
                Ok(true)
            }
            AttemptSafetyPhase::ThresholdExposed => Ok(false),
            AttemptSafetyPhase::AbandonmentFenced
            | AttemptSafetyPhase::AbandonedCertified { .. } => {
                Err(ConsolidationConsensusError::ShareExposureAfterFence)
            }
            AttemptSafetyPhase::NonceUnreleased => {
                Err(ConsolidationConsensusError::NonceNotReleased)
            }
        }
    }

    /// Fence the share path and prepare a witness which remains inaccessible until exact readback.
    ///
    /// The caller must durably store [`PendingShareUnexposed::state_to_persist`] and pass its exact
    /// readback to [`PendingShareUnexposed::release_after_persisted_state`] before transmitting the
    /// witness. Repeating this after restart from `AbandonmentFenced` is idempotent.
    pub fn prepare_share_unexposed(
        &mut self,
        expected_context: &ConsensusContext,
        expected_intent: &ConsolidationIntent,
        intent_certificate: &ConsolidationIntentCertificate,
        abandonment_context: &ConsensusContext,
        identity: &Identity,
    ) -> Result<PendingShareUnexposed, ConsolidationConsensusError> {
        self.validate_expected(expected_context, expected_intent, intent_certificate)?;
        validate_abandonment_transition(abandonment_context, intent_certificate)?;
        validate_session_separation(
            expected_context,
            abandonment_context,
            expected_intent,
            intent_certificate,
        )?;
        if identity.party() != self.local_party {
            return Err(ConsolidationConsensusError::WrongLocalParty);
        }
        abandonment_context.committee().member(identity.party()).map_err(ConsensusError::from)?;
        match self.phase {
            AttemptSafetyPhase::NonceUnreleased
            | AttemptSafetyPhase::NonceReleased
            | AttemptSafetyPhase::AbandonmentFenced => {}
            AttemptSafetyPhase::ShareExposed => {
                return Err(ConsolidationConsensusError::ShareAlreadyExposed);
            }
            AttemptSafetyPhase::ThresholdExposed => {
                return Err(ConsolidationConsensusError::AllSharesExposed);
            }
            AttemptSafetyPhase::AbandonedCertified { .. } => {
                return Err(ConsolidationConsensusError::AttemptAlreadyAbandoned);
            }
        }

        let witness = sign_share_unexposed_statement(
            abandonment_context,
            intent_certificate,
            expected_intent,
            identity,
        )?;
        let mut candidate = self.clone();
        if matches!(
            candidate.phase,
            AttemptSafetyPhase::NonceUnreleased | AttemptSafetyPhase::NonceReleased
        ) {
            candidate.advance(AttemptSafetyPhase::AbandonmentFenced)?;
        }
        let state = candidate.encode()?;
        let state_commitment = safety_state_commitment(&state);
        let pending = PendingShareUnexposed {
            witness,
            key: candidate.key,
            local_party: candidate.local_party,
            intent_decision: candidate.intent_decision,
            revision: candidate.revision,
            state_commitment,
            state,
        };
        *self = candidate;
        Ok(pending)
    }

    /// Apply an exact abandonment certificate on the permanently fenced branch.
    #[allow(clippy::too_many_arguments)]
    pub fn mark_abandoned_certified(
        &mut self,
        expected_context: &ConsensusContext,
        expected_intent: &ConsolidationIntent,
        intent_certificate: &ConsolidationIntentCertificate,
        abandonment_context: &ConsensusContext,
        abandonment_certificate: &ConsolidationAbandonmentCertificate,
        fence: &AbandonmentFenceCapability,
    ) -> Result<bool, ConsolidationConsensusError> {
        self.validate_expected(expected_context, expected_intent, intent_certificate)?;
        abandonment_certificate.verify_expected(
            abandonment_context,
            expected_context,
            expected_intent,
            intent_certificate,
        )?;
        let decision = abandonment_certificate.decision_digest();
        match self.phase {
            AttemptSafetyPhase::AbandonmentFenced => {
                fence.validate_for(self)?;
                self.advance(AttemptSafetyPhase::AbandonedCertified { decision })?;
                Ok(true)
            }
            AttemptSafetyPhase::AbandonedCertified { decision: existing }
                if existing == decision =>
            {
                Ok(false)
            }
            AttemptSafetyPhase::AbandonedCertified { .. } => {
                Err(ConsolidationConsensusError::ConflictingAbandonmentDecision)
            }
            AttemptSafetyPhase::ShareExposed | AttemptSafetyPhase::ThresholdExposed => {
                Err(ConsolidationConsensusError::ShareAlreadyExposed)
            }
            AttemptSafetyPhase::NonceUnreleased | AttemptSafetyPhase::NonceReleased => {
                Err(ConsolidationConsensusError::AbandonmentFenceRequired)
            }
        }
    }

    fn advance(&mut self, phase: AttemptSafetyPhase) -> Result<(), ConsolidationConsensusError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ConsolidationConsensusError::SafetyRevisionOverflow)?;
        self.phase = phase;
        self.transition = self.expected_transition_commitment()?;
        Ok(())
    }

    fn phase_revision_is_valid(&self) -> bool {
        match self.phase {
            AttemptSafetyPhase::NonceUnreleased => self.revision == 0,
            AttemptSafetyPhase::NonceReleased => self.revision == 1,
            AttemptSafetyPhase::ShareExposed => self.revision == 2,
            AttemptSafetyPhase::AbandonmentFenced => matches!(self.revision, 1 | 2),
            AttemptSafetyPhase::ThresholdExposed => matches!(self.revision, 2 | 3),
            AttemptSafetyPhase::AbandonedCertified { decision } => {
                matches!(self.revision, 2 | 3) && decision != [0; 32]
            }
        }
    }

    fn phase_payload_is_valid(&self) -> bool {
        match self.phase {
            AttemptSafetyPhase::NonceUnreleased
            | AttemptSafetyPhase::NonceReleased
            | AttemptSafetyPhase::AbandonmentFenced
            | AttemptSafetyPhase::AbandonedCertified { .. } => self.share_payload.is_none(),
            AttemptSafetyPhase::ShareExposed => self.share_payload.is_some(),
            AttemptSafetyPhase::ThresholdExposed => true,
        }
    }

    fn expected_transition_commitment(&self) -> Result<[u8; 32], ConsolidationConsensusError> {
        let semantic = postcard::to_allocvec(&(
            self.version,
            self.local_party,
            self.key,
            self.intent_context,
            self.intent_decision,
            &self.intent,
            self.share_payload,
            self.phase,
            self.revision,
        ))
        .map_err(|_| ConsolidationConsensusError::Serialization)?;
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/consolidation-safety-state/v1");
        hasher.update(&(semantic.len() as u64).to_le_bytes());
        hasher.update(&semantic);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// A signed witness hidden behind the exact fenced-state persistence boundary.
pub struct PendingShareUnexposed {
    witness: SignedEnvelope,
    key: AttemptSafetyKey,
    local_party: PartyId,
    intent_decision: [u8; 32],
    revision: u64,
    state_commitment: [u8; 32],
    state: Vec<u8>,
}

impl fmt::Debug for PendingShareUnexposed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingShareUnexposed")
            .field("key", &self.key)
            .field("local_party", &self.local_party)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl PendingShareUnexposed {
    /// Exact fenced state bytes which must replace the pre-fence durable record.
    #[must_use]
    pub fn state_to_persist(&self) -> &[u8] {
        &self.state
    }

    /// Reveal the signed witness only after canonical readback proves the exact fence is present.
    pub fn release_after_persisted_state(
        self,
        persisted: &[u8],
        expected_context: &ConsensusContext,
        expected_intent: &ConsolidationIntent,
        intent_certificate: &ConsolidationIntentCertificate,
    ) -> Result<FencedShareUnexposed, ConsolidationConsensusError> {
        let state = ConsolidationAttemptSafety::restore(
            persisted,
            expected_context,
            expected_intent,
            intent_certificate,
        )?;
        if state.phase != AttemptSafetyPhase::AbandonmentFenced
            || state.key != self.key
            || state.local_party != self.local_party
            || state.intent_decision != self.intent_decision
            || state.revision != self.revision
            || safety_state_commitment(persisted) != self.state_commitment
            || persisted != self.state
        {
            return Err(ConsolidationConsensusError::AbandonmentFenceNotPersisted);
        }
        Ok(FencedShareUnexposed {
            witness: self.witness,
            fence: AbandonmentFenceCapability {
                key: self.key,
                local_party: self.local_party,
                intent_decision: self.intent_decision,
                revision: self.revision,
                state_commitment: self.state_commitment,
            },
        })
    }
}

/// Witness plus the non-cloneable proof-of-readback capability for its irreversible fence.
#[derive(Debug)]
pub struct FencedShareUnexposed {
    witness: SignedEnvelope,
    fence: AbandonmentFenceCapability,
}

impl FencedShareUnexposed {
    #[must_use]
    pub fn witness(&self) -> &SignedEnvelope {
        &self.witness
    }

    #[must_use]
    pub fn into_parts(self) -> (SignedEnvelope, AbandonmentFenceCapability) {
        (self.witness, self.fence)
    }
}

/// Non-cloneable capability proving exact readback of an `AbandonmentFenced` state.
pub struct AbandonmentFenceCapability {
    key: AttemptSafetyKey,
    local_party: PartyId,
    intent_decision: [u8; 32],
    revision: u64,
    state_commitment: [u8; 32],
}

impl fmt::Debug for AbandonmentFenceCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AbandonmentFenceCapability")
            .field("key", &self.key)
            .field("local_party", &self.local_party)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl AbandonmentFenceCapability {
    fn validate_for(
        &self,
        state: &ConsolidationAttemptSafety,
    ) -> Result<(), ConsolidationConsensusError> {
        let encoded = state.encode()?;
        if state.phase != AttemptSafetyPhase::AbandonmentFenced
            || self.key != state.key
            || self.local_party != state.local_party
            || self.intent_decision != state.intent_decision
            || self.revision != state.revision
            || self.state_commitment != safety_state_commitment(&encoded)
        {
            return Err(ConsolidationConsensusError::InvalidFenceCapability);
        }
        Ok(())
    }
}

fn safety_state_commitment(encoded: &[u8]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/consolidation-safety-readback/v1");
    hasher.update(&(encoded.len() as u64).to_le_bytes());
    hasher.update(encoded);
    *hasher.finalize().as_bytes()
}

/// Exact outbound share hidden behind a `ShareExposed` persistence boundary.
pub struct PendingShareExposure {
    payload: Vec<u8>,
    payload_binding: SharePayloadBinding,
    key: AttemptSafetyKey,
    local_party: PartyId,
    intent_decision: [u8; 32],
    revision: u64,
    state_commitment: [u8; 32],
    state: Vec<u8>,
}

impl fmt::Debug for PendingShareExposure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingShareExposure")
            .field("payload_binding", &self.payload_binding)
            .field("key", &self.key)
            .field("local_party", &self.local_party)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl PendingShareExposure {
    /// Exact `ShareExposed` state bytes which must replace the pre-exposure durable record.
    #[must_use]
    pub fn state_to_persist(&self) -> &[u8] {
        &self.state
    }

    #[must_use]
    pub const fn payload_binding(&self) -> SharePayloadBinding {
        self.payload_binding
    }

    /// Reveal the outbound share only after exact canonical `ShareExposed` state readback.
    pub fn release_after_persisted_state(
        self,
        persisted: &[u8],
        expected_context: &ConsensusContext,
        expected_intent: &ConsolidationIntent,
        intent_certificate: &ConsolidationIntentCertificate,
    ) -> Result<PersistedShareExposure, ConsolidationConsensusError> {
        let state = ConsolidationAttemptSafety::restore(
            persisted,
            expected_context,
            expected_intent,
            intent_certificate,
        )?;
        if !matches!(
            state.phase,
            AttemptSafetyPhase::ShareExposed | AttemptSafetyPhase::ThresholdExposed
        ) || state.share_payload != Some(self.payload_binding)
            || state.key != self.key
            || state.local_party != self.local_party
            || state.intent_decision != self.intent_decision
            || state.revision != self.revision
            || safety_state_commitment(persisted) != self.state_commitment
            || persisted != self.state
        {
            return Err(ConsolidationConsensusError::ShareExposureNotPersisted);
        }
        Ok(PersistedShareExposure {
            payload: self.payload,
            capability: ShareExposureCapability {
                payload_binding: self.payload_binding,
                key: self.key,
                local_party: self.local_party,
                intent_decision: self.intent_decision,
                revision: self.revision,
                state_commitment: self.state_commitment,
            },
        })
    }
}

/// Share payload plus the non-cloneable capability proving its exposure state was read back.
#[derive(Debug)]
pub struct PersistedShareExposure {
    payload: Vec<u8>,
    capability: ShareExposureCapability,
}

impl PersistedShareExposure {
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, ShareExposureCapability) {
        (self.payload, self.capability)
    }
}

/// Non-cloneable persisted-readback authority for one exact share payload.
pub struct ShareExposureCapability {
    payload_binding: SharePayloadBinding,
    key: AttemptSafetyKey,
    local_party: PartyId,
    intent_decision: [u8; 32],
    revision: u64,
    state_commitment: [u8; 32],
}

impl fmt::Debug for ShareExposureCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShareExposureCapability")
            .field("payload_binding", &self.payload_binding)
            .field("key", &self.key)
            .field("local_party", &self.local_party)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl ShareExposureCapability {
    #[must_use]
    pub const fn payload_binding(&self) -> SharePayloadBinding {
        self.payload_binding
    }

    /// Recheck that this capability still names the exact persisted state and payload.
    pub fn validate_for(
        &self,
        state: &ConsolidationAttemptSafety,
        payload: &[u8],
    ) -> Result<(), ConsolidationConsensusError> {
        let encoded = state.encode()?;
        if SharePayloadBinding::from_payload(payload)? != self.payload_binding
            || !matches!(
                state.phase,
                AttemptSafetyPhase::ShareExposed | AttemptSafetyPhase::ThresholdExposed
            )
            || state.share_payload != Some(self.payload_binding)
            || self.key != state.key
            || self.local_party != state.local_party
            || self.intent_decision != state.intent_decision
            || self.revision != state.revision
            || self.state_commitment != safety_state_commitment(&encoded)
        {
            return Err(ConsolidationConsensusError::InvalidShareExposureCapability);
        }
        Ok(())
    }
}

/// Witness-subset-independent statement signed only after the local share path is durably fenced.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShareUnexposedStatement {
    version: u16,
    abandonment_context: ExactContextBinding,
    intent_context: [u8; 32],
    intent_decision: [u8; 32],
    intent: [u8; 32],
    authorization: ConsolidationId,
    attempt: AttemptSafetyKey,
}

impl ShareUnexposedStatement {
    fn expected(
        abandonment_context: &ConsensusContext,
        intent_certificate: &ConsolidationIntentCertificate,
        intent: &ConsolidationIntent,
    ) -> Result<Self, ConsolidationConsensusError> {
        validate_abandonment_transition(abandonment_context, intent_certificate)?;
        let certified = intent_certificate.verify()?;
        certified.validate_expected(intent_certificate.context(), intent)?;
        validate_session_separation(
            intent_certificate.context(),
            abandonment_context,
            intent,
            intent_certificate,
        )?;
        Ok(Self {
            version: SHARE_UNEXPOSED_VERSION,
            abandonment_context: ExactContextBinding::from_context(abandonment_context),
            intent_context: intent_certificate.context().digest(),
            intent_decision: intent_certificate.decision_digest(),
            intent: intent.digest(),
            authorization: intent.authorization().id(),
            attempt: AttemptSafetyKey::from_attempt(intent.attempt())?,
        })
    }

    fn validate_expected(
        &self,
        abandonment_context: &ConsensusContext,
        intent_certificate: &ConsolidationIntentCertificate,
        intent: &ConsolidationIntent,
    ) -> Result<(), ConsolidationConsensusError> {
        if self.version != SHARE_UNEXPOSED_VERSION
            || self != &Self::expected(abandonment_context, intent_certificate, intent)?
        {
            return Err(ConsolidationConsensusError::InvalidShareWitness);
        }
        Ok(())
    }
}

/// Canonical `n-f` proof that abandoning the selected signer set cannot hide a threshold
/// signature, even if every one of the at most `f` Byzantine attesters lies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShareUnexposedCertificate {
    version: u16,
    statement: ShareUnexposedStatement,
    #[serde(deserialize_with = "deserialize_share_unexposed_witnesses")]
    witnesses: Vec<SignedEnvelope>,
}

impl ShareUnexposedCertificate {
    /// Verify an already-canonical exact quorum.
    pub fn from_witnesses(
        abandonment_context: &ConsensusContext,
        intent_certificate: &ConsolidationIntentCertificate,
        witnesses: Vec<SignedEnvelope>,
    ) -> Result<Self, ConsolidationConsensusError> {
        let intent = intent_certificate.verify()?;
        let statement =
            ShareUnexposedStatement::expected(abandonment_context, intent_certificate, &intent)?;
        let certificate =
            Self { version: SHARE_UNEXPOSED_CERTIFICATE_VERSION, statement, witnesses };
        certificate.verify(abandonment_context, intent_certificate)?;
        Ok(certificate)
    }

    /// Deterministically choose the lexicographically first safe exact quorum from all available
    /// valid witnesses. Input ordering can never change the resulting BA value.
    pub fn from_available_witnesses(
        abandonment_context: &ConsensusContext,
        intent_certificate: &ConsolidationIntentCertificate,
        mut available: Vec<SignedEnvelope>,
    ) -> Result<Self, ConsolidationConsensusError> {
        if available.len() > usize::from(abandonment_context.committee().n()) {
            return Err(ConsolidationConsensusError::TooManyShareWitnesses);
        }
        let intent = intent_certificate.verify()?;
        let statement =
            ShareUnexposedStatement::expected(abandonment_context, intent_certificate, &intent)?;
        let payload = postcard::to_allocvec(&statement)
            .map_err(|_| ConsolidationConsensusError::Serialization)?;
        available.sort_unstable_by_key(|witness| witness.from);
        if available.windows(2).any(|pair| pair[0].from == pair[1].from) {
            return Err(ConsolidationConsensusError::NonCanonicalWitnesses);
        }
        for witness in &available {
            verify_share_unexposed_witness(abandonment_context, &payload, witness)?;
        }
        let quorum = abandonment_context.quorum();
        if available.len() < quorum {
            return Err(ConsolidationConsensusError::InsufficientShareWitnesses);
        }
        for indices in combination_indices(available.len(), quorum) {
            let witnesses =
                indices.into_iter().map(|index| available[index].clone()).collect::<Vec<_>>();
            if share_unexposed_intersection_is_safe(
                abandonment_context,
                intent.attempt(),
                &witnesses,
            ) {
                return Self::from_witnesses(abandonment_context, intent_certificate, witnesses);
            }
        }
        Err(ConsolidationConsensusError::UnsafeIntersection)
    }

    /// Verify signatures, canonical ordering, exact context/intent binding, and the signer-set
    /// intersection inequality.
    pub fn verify(
        &self,
        abandonment_context: &ConsensusContext,
        intent_certificate: &ConsolidationIntentCertificate,
    ) -> Result<ConsolidationIntent, ConsolidationConsensusError> {
        if self.version != SHARE_UNEXPOSED_CERTIFICATE_VERSION {
            return Err(ConsolidationConsensusError::UnsupportedVersion);
        }
        let intent = intent_certificate.verify()?;
        self.statement.validate_expected(abandonment_context, intent_certificate, &intent)?;
        let quorum = abandonment_context.quorum();
        if self.witnesses.len() != quorum {
            return Err(ConsolidationConsensusError::InsufficientShareWitnesses);
        }
        if self.witnesses.windows(2).any(|pair| pair[0].from >= pair[1].from) {
            return Err(ConsolidationConsensusError::NonCanonicalWitnesses);
        }
        let payload = postcard::to_allocvec(&self.statement)
            .map_err(|_| ConsolidationConsensusError::Serialization)?;
        for witness in &self.witnesses {
            verify_share_unexposed_witness(abandonment_context, &payload, witness)?;
        }
        if !share_unexposed_intersection_is_safe(
            abandonment_context,
            intent.attempt(),
            &self.witnesses,
        ) {
            return Err(ConsolidationConsensusError::UnsafeIntersection);
        }
        Ok(intent)
    }

    #[must_use]
    pub fn witnesses(&self) -> &[SignedEnvelope] {
        &self.witnesses
    }
}

/// Self-contained application value committed at the exact successor consensus height.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationAbandonment {
    version: u16,
    context: ExactContextBinding,
    intent_certificate: ConsolidationIntentCertificate,
    share_unexposed: ShareUnexposedCertificate,
}

impl ConsolidationAbandonment {
    pub fn new(
        abandonment_context: &ConsensusContext,
        intent_certificate: ConsolidationIntentCertificate,
        share_unexposed: ShareUnexposedCertificate,
    ) -> Result<Self, ConsolidationConsensusError> {
        validate_abandonment_transition(abandonment_context, &intent_certificate)?;
        share_unexposed.verify(abandonment_context, &intent_certificate)?;
        let value = Self {
            version: ABANDONMENT_VERSION,
            context: ExactContextBinding::from_context(abandonment_context),
            intent_certificate,
            share_unexposed,
        };
        value.validate(abandonment_context)?;
        Ok(value)
    }

    pub fn validate(
        &self,
        abandonment_context: &ConsensusContext,
    ) -> Result<ConsolidationIntent, ConsolidationConsensusError> {
        if self.version != ABANDONMENT_VERSION {
            return Err(ConsolidationConsensusError::UnsupportedVersion);
        }
        require_application(abandonment_context, CONSOLIDATION_ABANDONMENT_APPLICATION)?;
        self.context.validate_for(abandonment_context)?;
        validate_abandonment_transition(abandonment_context, &self.intent_certificate)?;
        self.share_unexposed.verify(abandonment_context, &self.intent_certificate)
    }

    pub fn validate_expected(
        &self,
        abandonment_context: &ConsensusContext,
        intent_context: &ConsensusContext,
        expected_intent: &ConsolidationIntent,
        expected_certificate: &ConsolidationIntentCertificate,
    ) -> Result<(), ConsolidationConsensusError> {
        expected_certificate.verify_expected(intent_context, expected_intent)?;
        let certified = self.validate(abandonment_context)?;
        certified.validate_expected(intent_context, expected_intent)?;
        if self.intent_certificate.context() != intent_context
            || self.intent_certificate.decision_digest() != expected_certificate.decision_digest()
        {
            return Err(ConsolidationConsensusError::WrongExpectedAbandonment);
        }
        Ok(())
    }

    pub fn to_consensus_value(&self) -> Result<ConsensusValue, ConsolidationConsensusError> {
        let bytes =
            postcard::to_allocvec(self).map_err(|_| ConsolidationConsensusError::Serialization)?;
        Ok(ConsensusValue::new(bytes)?)
    }

    #[must_use]
    pub fn intent_certificate(&self) -> &ConsolidationIntentCertificate {
        &self.intent_certificate
    }

    #[must_use]
    pub fn share_unexposed(&self) -> &ShareUnexposedCertificate {
        &self.share_unexposed
    }
}

/// Portable BA commit certificate for an exact safe-abandonment value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationAbandonmentCertificate {
    version: u16,
    context: ConsensusContext,
    certificate: CommitCertificate,
}

impl ConsolidationAbandonmentCertificate {
    pub fn new(
        context: ConsensusContext,
        certificate: CommitCertificate,
    ) -> Result<Self, ConsolidationConsensusError> {
        let result = Self { version: ABANDONMENT_CERTIFICATE_VERSION, context, certificate };
        result.verify()?;
        Ok(result)
    }

    pub fn verify(&self) -> Result<ConsolidationAbandonment, ConsolidationConsensusError> {
        if self.version != ABANDONMENT_CERTIFICATE_VERSION {
            return Err(ConsolidationConsensusError::UnsupportedVersion);
        }
        require_application(&self.context, CONSOLIDATION_ABANDONMENT_APPLICATION)?;
        self.certificate.verify(&self.context)?;
        decode_consolidation_abandonment(&self.context, self.certificate.value())
    }

    pub fn verify_expected(
        &self,
        abandonment_context: &ConsensusContext,
        intent_context: &ConsensusContext,
        expected_intent: &ConsolidationIntent,
        intent_certificate: &ConsolidationIntentCertificate,
    ) -> Result<ConsolidationAbandonment, ConsolidationConsensusError> {
        if &self.context != abandonment_context {
            return Err(ConsolidationConsensusError::WrongContext);
        }
        let abandonment = self.verify()?;
        abandonment.validate_expected(
            abandonment_context,
            intent_context,
            expected_intent,
            intent_certificate,
        )?;
        Ok(abandonment)
    }

    #[must_use]
    pub fn decision_digest(&self) -> [u8; 32] {
        self.certificate.digest()
    }
}

pub fn decode_consolidation_abandonment(
    context: &ConsensusContext,
    value: &ConsensusValue,
) -> Result<ConsolidationAbandonment, ConsolidationConsensusError> {
    value.validate()?;
    let abandonment = decode_exact::<ConsolidationAbandonment>(value.as_bytes())?;
    abandonment.validate(context)?;
    Ok(abandonment)
}

/// Stateful BA application predicate. The non-cloneable fence capability proves this exact local
/// state was read back after the share path became permanently closed.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn validate_consolidation_abandonment_value_for_safety_state(
    abandonment_context: &ConsensusContext,
    intent_context: &ConsensusContext,
    expected_intent: &ConsolidationIntent,
    intent_certificate: &ConsolidationIntentCertificate,
    safety: &ConsolidationAttemptSafety,
    fence: &AbandonmentFenceCapability,
    value: &ConsensusValue,
) -> bool {
    safety
        .validate_expected(intent_context, expected_intent, intent_certificate)
        .and_then(|()| fence.validate_for(safety))
        .and_then(|()| {
            decode_consolidation_abandonment(abandonment_context, value).and_then(|abandonment| {
                abandonment.validate_expected(
                    abandonment_context,
                    intent_context,
                    expected_intent,
                    intent_certificate,
                )
            })
        })
        .is_ok()
}

pub fn validate_abandonment_transition(
    abandonment_context: &ConsensusContext,
    intent_certificate: &ConsolidationIntentCertificate,
) -> Result<(), ConsolidationConsensusError> {
    require_application(abandonment_context, CONSOLIDATION_ABANDONMENT_APPLICATION)?;
    let intent_context = intent_certificate.context();
    require_application(intent_context, CONSOLIDATION_INTENT_APPLICATION)?;
    intent_certificate.verify()?;
    let left = abandonment_context.binding();
    let right = intent_context.binding();
    if left.domain != right.domain
        || left.wallet != right.wallet
        || left.network != right.network
        || left.registry != right.registry
        || left.activation != right.activation
        || abandonment_context.epoch() != intent_context.epoch()
        || abandonment_context.committee() != intent_context.committee()
        || abandonment_context.fault_bound() != intent_context.fault_bound()
        || abandonment_context.height()
            != intent_context
                .height()
                .checked_add(1)
                .ok_or(ConsolidationConsensusError::InvalidAbandonmentTransition)?
        || abandonment_context.sequence()
            != intent_context
                .sequence()
                .checked_add(1)
                .ok_or(ConsolidationConsensusError::InvalidAbandonmentTransition)?
        || abandonment_context.previous() != intent_certificate.decision_digest()
    {
        return Err(ConsolidationConsensusError::InvalidAbandonmentTransition);
    }
    Ok(())
}

fn validate_session_separation(
    intent_context: &ConsensusContext,
    abandonment_context: &ConsensusContext,
    intent: &ConsolidationIntent,
    intent_certificate: &ConsolidationIntentCertificate,
) -> Result<(), ConsolidationConsensusError> {
    intent_certificate.verify_expected(intent_context, intent)?;
    if abandonment_context.session() == intent_context.session()
        || abandonment_context.session() == intent.attempt().session()
        || intent_context.session() == intent.attempt().session()
    {
        return Err(ConsolidationConsensusError::ProtocolSessionCollision);
    }
    Ok(())
}

fn sign_share_unexposed_statement(
    abandonment_context: &ConsensusContext,
    intent_certificate: &ConsolidationIntentCertificate,
    intent: &ConsolidationIntent,
    identity: &Identity,
) -> Result<SignedEnvelope, ConsolidationConsensusError> {
    abandonment_context.committee().member(identity.party()).map_err(ConsensusError::from)?;
    let statement =
        ShareUnexposedStatement::expected(abandonment_context, intent_certificate, intent)?;
    let payload = postcard::to_allocvec(&statement)
        .map_err(|_| ConsolidationConsensusError::Serialization)?;
    if payload.len() > MAX_SHARE_UNEXPOSED_MESSAGE_BYTES {
        return Err(ConsolidationConsensusError::InvalidShareWitness);
    }
    Ok(identity.sign_envelope(
        abandonment_context.committee(),
        abandonment_context.session(),
        None,
        SHARE_UNEXPOSED_SEQUENCE,
        payload,
    )?)
}

fn verify_share_unexposed_witness(
    context: &ConsensusContext,
    expected_payload: &[u8],
    witness: &SignedEnvelope,
) -> Result<(), ConsolidationConsensusError> {
    if witness.to.is_some()
        || witness.session != context.session()
        || witness.sequence != SHARE_UNEXPOSED_SEQUENCE
        || witness.payload != expected_payload
        || witness.payload.len() > MAX_SHARE_UNEXPOSED_MESSAGE_BYTES
    {
        return Err(ConsolidationConsensusError::InvalidShareWitness);
    }
    Identity::verify_envelope(context.committee(), witness.from, witness)?;
    Ok(())
}

/// Verify one portable share-unexposed witness against the exact certified intent transition.
///
/// Hosts use this for bounded gossip admission before enough witnesses exist to assemble the
/// canonical safe-intersection certificate.
pub fn verify_share_unexposed_attestation(
    abandonment_context: &ConsensusContext,
    intent_certificate: &ConsolidationIntentCertificate,
    witness: &SignedEnvelope,
) -> Result<(), ConsolidationConsensusError> {
    let intent = intent_certificate.verify()?;
    let statement =
        ShareUnexposedStatement::expected(abandonment_context, intent_certificate, &intent)?;
    let payload = postcard::to_allocvec(&statement)
        .map_err(|_| ConsolidationConsensusError::Serialization)?;
    verify_share_unexposed_witness(abandonment_context, &payload, witness)
}

/// Sign an unexposed witness for a party which was never selected for this attempt and therefore
/// has no nonce/share safety record to fence.
pub fn sign_unselected_share_unexposed_attestation(
    abandonment_context: &ConsensusContext,
    intent_certificate: &ConsolidationIntentCertificate,
    identity: &Identity,
) -> Result<SignedEnvelope, ConsolidationConsensusError> {
    let intent = intent_certificate.verify()?;
    if intent.attempt().signers().binary_search(&identity.party()).is_ok() {
        return Err(ConsolidationConsensusError::AbandonmentFenceRequired);
    }
    sign_share_unexposed_statement(abandonment_context, intent_certificate, &intent, identity)
}

fn share_unexposed_intersection_is_safe(
    context: &ConsensusContext,
    attempt: &AttemptBinding,
    witnesses: &[SignedEnvelope],
) -> bool {
    let witness_parties = witnesses.iter().map(|witness| witness.from).collect::<BTreeSet<_>>();
    let selected = attempt.signers().iter().copied().collect::<BTreeSet<_>>();
    let attested_selected = selected.intersection(&witness_parties).count();
    let unattested_selected = selected.len().saturating_sub(attested_selected);
    let possible_exposed = unattested_selected
        .saturating_add(usize::from(context.fault_bound()).min(attested_selected));
    possible_exposed < usize::from(attempt.threshold())
}

fn combination_indices(length: usize, choose: usize) -> Vec<Vec<usize>> {
    fn visit(
        start: usize,
        length: usize,
        choose: usize,
        current: &mut Vec<usize>,
        output: &mut Vec<Vec<usize>>,
    ) {
        if current.len() == choose {
            output.push(current.clone());
            return;
        }
        let remaining = choose - current.len();
        for index in start..=length.saturating_sub(remaining) {
            current.push(index);
            visit(index + 1, length, choose, current, output);
            current.pop();
        }
    }
    if choose == 0 || choose > length {
        return Vec::new();
    }
    let mut output = Vec::new();
    visit(0, length, choose, &mut Vec::new(), &mut output);
    output
}

fn deserialize_share_unexposed_witnesses<'de, D>(
    deserializer: D,
) -> Result<Vec<SignedEnvelope>, D::Error>
where
    D: Deserializer<'de>,
{
    struct WitnessVisitor;

    impl<'de> Visitor<'de> for WitnessVisitor {
        type Value = Vec<SignedEnvelope>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded vector of share-unexposed witnesses")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut witnesses = Vec::new();
            while let Some(witness) = sequence.next_element()? {
                if witnesses.len() == MAX_COMMITTEE_MEMBERS {
                    return Err(A::Error::custom("too many share-unexposed witnesses"));
                }
                witnesses.push(witness);
            }
            Ok(witnesses)
        }
    }

    deserializer.deserialize_seq(WitnessVisitor)
}

fn require_application(
    context: &ConsensusContext,
    expected: &[u8],
) -> Result<(), ConsolidationConsensusError> {
    context.validate()?;
    if context.binding().application != expected {
        return Err(ConsolidationConsensusError::WrongApplication);
    }
    Ok(())
}

fn decode_exact<T>(bytes: &[u8]) -> Result<T, ConsolidationConsensusError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let (value, trailing) = postcard::take_from_bytes::<T>(bytes)
        .map_err(|_| ConsolidationConsensusError::Serialization)?;
    if !trailing.is_empty() {
        return Err(ConsolidationConsensusError::TrailingBytes);
    }
    let canonical =
        postcard::to_allocvec(&value).map_err(|_| ConsolidationConsensusError::Serialization)?;
    if canonical != bytes {
        return Err(ConsolidationConsensusError::NonCanonicalEncoding);
    }
    Ok(value)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConsolidationConsensusError {
    #[error("deposit consensus error: {0}")]
    Consensus(#[from] ConsensusError),
    #[error("consolidation binding error: {0}")]
    Consolidation(#[from] ConsolidationError),
    #[error("unsupported consolidation-consensus version")]
    UnsupportedVersion,
    #[error("consensus context uses the wrong consolidation application")]
    WrongApplication,
    #[error("application value differs from the trusted local consensus context")]
    WrongContext,
    #[error("consolidation intent does not match its wallet, committee, epoch, or activation")]
    InvalidIntentBinding,
    #[error("signing threshold does not exceed the Byzantine fault bound")]
    UnsafeSigningThreshold,
    #[error("intent signer availability is smaller than threshold plus the fault bound")]
    InsufficientSignerAvailability,
    #[error("certified intent differs from the exact intent reconstructed by trusted local state")]
    WrongExpectedIntent,
    #[error("one signing session is bound to a different attempt")]
    AttemptSessionCollision,
    #[error("durable consolidation safety state is malformed or inconsistent")]
    InvalidSafetyState,
    #[error("attempt safety key contains a zero session or digest")]
    InvalidSafetyKey,
    #[error("requested consolidation safety transition is not monotonic")]
    InvalidSafetyTransition,
    #[error("safety-state revision overflow")]
    SafetyRevisionOverflow,
    #[error("nonce release must be durable before this transition")]
    NonceNotReleased,
    #[error("outbound share payload is empty or exceeds its hard size bound")]
    InvalidSharePayload,
    #[error("a different outbound share payload is already bound to this attempt")]
    ConflictingSharePayload,
    #[error("the exact share-exposure state was not read back from durable storage")]
    ShareExposureNotPersisted,
    #[error("share-exposure capability does not match this exact state and payload")]
    InvalidShareExposureCapability,
    #[error("the local party does not match the durable attempt safety record")]
    WrongLocalParty,
    #[error("a share cannot be exposed after the abandonment fence")]
    ShareExposureAfterFence,
    #[error("the local share was already exposed")]
    ShareAlreadyExposed,
    #[error("local evidence says a complete threshold signature may already exist")]
    AllSharesExposed,
    #[error("the exact signing attempt is already terminally abandoned")]
    AttemptAlreadyAbandoned,
    #[error("a different abandonment decision is already durable")]
    ConflictingAbandonmentDecision,
    #[error("the abandonment transition requires a durable share fence")]
    AbandonmentFenceRequired,
    #[error("the exact abandonment-fenced state was not read back from durable storage")]
    AbandonmentFenceNotPersisted,
    #[error("abandonment fence capability does not match this exact durable state")]
    InvalidFenceCapability,
    #[error("the abandonment context is not the exact successor of the intent decision")]
    InvalidAbandonmentTransition,
    #[error("intent consensus, abandonment consensus, and signing sessions must be distinct")]
    ProtocolSessionCollision,
    #[error("a share-unexposed witness is malformed or bound to another attempt")]
    InvalidShareWitness,
    #[error("fewer than n-f distinct share-unexposed witnesses are available")]
    InsufficientShareWitnesses,
    #[error("more share-unexposed witnesses were supplied than committee members")]
    TooManyShareWitnesses,
    #[error("share-unexposed witnesses are duplicated or not canonically ordered")]
    NonCanonicalWitnesses,
    #[error("the witness/signer intersection cannot rule out a hidden threshold signature")]
    UnsafeIntersection,
    #[error("the abandonment value differs from exact locally reconstructed intent state")]
    WrongExpectedAbandonment,
    #[error("identity signature validation failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("canonical serialization failed")]
    Serialization,
    #[error("canonical value contains trailing bytes")]
    TrailingBytes,
    #[error("value uses a non-canonical encoding")]
    NonCanonicalEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        committee::{Committee, Member},
        deposit_consensus::{ConsensusBinding, ConsensusMessageBody, Vote, sign_consensus_message},
        deposit_consolidation::OpaqueIntentBinding,
        deposit_wallet::{DepositWalletId, SweepId},
    };

    struct Fixture {
        identities: Vec<Identity>,
        intent_context: ConsensusContext,
        intent_certificate: ConsolidationIntentCertificate,
        abandonment_context: ConsensusContext,
    }

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0xa1; 32];
        secret[2..10].copy_from_slice(&epoch.to_le_bytes());
        // X25519 clamps away the low three bits of byte zero, so placing the
        // small test party identifiers there aliases parties 1 through 4.
        // Keep the discriminator in bytes which survive clamping unchanged.
        secret[10..12].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    fn identities_and_committee() -> (Vec<Identity>, Committee) {
        let identities = (1_u16..=4)
            .map(|party| {
                let party = PartyId(party);
                let signing_seed = [u8::try_from(party.0).unwrap(); 32];
                Identity::from_test_secrets(party, 7, &signing_seed, test_x25519_secret(party, 7))
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
        (identities, committee)
    }

    fn context(
        committee: Committee,
        application: &[u8],
        session_byte: u8,
        height: u64,
        sequence: u64,
        previous: [u8; 32],
    ) -> ConsensusContext {
        ConsensusContext::new(
            ConsensusBinding {
                domain: [0x11; 32],
                application: application.to_vec(),
                wallet: [0x22; 32],
                network: [0x33; 32],
                registry: [0x44; 32],
                activation: [0x55; 32],
            },
            SessionId([session_byte; 32]),
            committee,
            1,
            height,
            sequence,
            previous,
        )
        .unwrap()
    }

    fn intent(context: &ConsensusContext) -> ConsolidationIntent {
        let authorization = TransactionAuthorization::new(
            DepositWalletId(context.binding().wallet),
            SweepId([0x61; 32]),
            OpaqueIntentBinding([0x62; 32]),
            [0x63; 32],
            [0x64; 32],
            [0x65; 32],
            2,
            50_000,
            1_000,
            2_000,
        )
        .unwrap();
        let attempt = AttemptBinding::new(
            1,
            context.epoch(),
            context.binding().registry,
            context.committee().digest(),
            context.binding().activation,
            authorization.root_group_key(),
            context.committee().threshold,
            context
                .committee()
                .members
                .iter()
                .take(
                    usize::from(context.committee().threshold) + usize::from(context.fault_bound()),
                )
                .map(|member| member.id)
                .collect(),
            [0x66; 32],
            SessionId([0x67; 32]),
            [0x68; 32],
        )
        .unwrap();
        ConsolidationIntent::new(context, authorization, attempt).unwrap()
    }

    fn commit_certificate(
        context: &ConsensusContext,
        identities: &[Identity],
        value: ConsensusValue,
    ) -> CommitCertificate {
        let witnesses = identities
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

    fn fixture() -> Fixture {
        let (identities, committee) = identities_and_committee();
        let intent_context =
            context(committee.clone(), CONSOLIDATION_INTENT_APPLICATION, 0x71, 0, 41, [0; 32]);
        let value = intent(&intent_context).to_consensus_value().unwrap();
        let commit = commit_certificate(&intent_context, &identities, value);
        let intent_certificate =
            ConsolidationIntentCertificate::new(intent_context.clone(), commit).unwrap();
        let abandonment_context = context(
            committee,
            CONSOLIDATION_ABANDONMENT_APPLICATION,
            0x72,
            1,
            42,
            intent_certificate.decision_digest(),
        );
        Fixture { identities, intent_context, intent_certificate, abandonment_context }
    }

    fn share_unexposed_witness(
        abandonment_context: &ConsensusContext,
        intent_certificate: &ConsolidationIntentCertificate,
        identity: &Identity,
    ) -> Result<SignedEnvelope, ConsolidationConsensusError> {
        validate_abandonment_transition(abandonment_context, intent_certificate)?;
        abandonment_context.committee().member(identity.party()).map_err(ConsensusError::from)?;
        let intent = intent_certificate.verify()?;
        sign_share_unexposed_statement(abandonment_context, intent_certificate, &intent, identity)
    }

    fn abandonment_value(fixture: &Fixture) -> ConsolidationAbandonment {
        let witnesses = fixture
            .identities
            .iter()
            .take(fixture.abandonment_context.quorum())
            .map(|identity| {
                share_unexposed_witness(
                    &fixture.abandonment_context,
                    &fixture.intent_certificate,
                    identity,
                )
                .unwrap()
            })
            .collect();
        let proof = ShareUnexposedCertificate::from_witnesses(
            &fixture.abandonment_context,
            &fixture.intent_certificate,
            witnesses,
        )
        .unwrap();
        ConsolidationAbandonment::new(
            &fixture.abandonment_context,
            fixture.intent_certificate.clone(),
            proof,
        )
        .unwrap()
    }

    fn alternate_intent(fixture: &Fixture, reuse_signing_session: bool) -> ConsolidationIntent {
        let expected = fixture.intent_certificate.verify().unwrap();
        let attempt = expected.attempt();
        let alternate = AttemptBinding::new(
            attempt.attempt(),
            attempt.epoch(),
            attempt.registry_digest(),
            attempt.committee_digest(),
            attempt.activation_digest(),
            attempt.root_group_key(),
            attempt.threshold(),
            attempt.signers().to_vec(),
            [0x91; 32],
            if reuse_signing_session { attempt.session() } else { SessionId([0x92; 32]) },
            [0x93; 32],
        )
        .unwrap();
        ConsolidationIntent::new(
            &fixture.intent_context,
            expected.authorization().clone(),
            alternate,
        )
        .unwrap()
    }

    fn released_safety(
        fixture: &Fixture,
        party: PartyId,
    ) -> (ConsolidationIntent, ConsolidationAttemptSafety) {
        let expected = fixture
            .intent_certificate
            .verify_expected(&fixture.intent_context, &fixture.intent_certificate.verify().unwrap())
            .unwrap();
        let mut state = ConsolidationAttemptSafety::new(
            party,
            &fixture.intent_context,
            expected.clone(),
            &fixture.intent_certificate,
        )
        .unwrap();
        assert!(
            state
                .mark_nonce_released(
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                )
                .unwrap()
        );
        (expected, state)
    }

    fn certified_abandonment(fixture: &Fixture) -> ConsolidationAbandonmentCertificate {
        let value = abandonment_value(fixture).to_consensus_value().unwrap();
        let commit = commit_certificate(&fixture.abandonment_context, &fixture.identities, value);
        ConsolidationAbandonmentCertificate::new(fixture.abandonment_context.clone(), commit)
            .unwrap()
    }

    #[test]
    fn fenced_witness_permanently_rejects_a_delayed_share_even_after_restart() {
        let fixture = fixture();
        let (expected, mut state) = released_safety(&fixture, PartyId(1));
        let pre_fence = state.encode().unwrap();
        let pending = state
            .prepare_share_unexposed(
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
                &fixture.abandonment_context,
                &fixture.identities[0],
            )
            .unwrap();
        assert_eq!(state.phase(), AttemptSafetyPhase::AbandonmentFenced);

        // A pre-fence readback cannot reveal the already-signed witness.
        assert_eq!(
            pending
                .release_after_persisted_state(
                    &pre_fence,
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                )
                .unwrap_err(),
            ConsolidationConsensusError::AbandonmentFenceNotPersisted,
        );

        // Re-preparing from the fenced state is deterministic and safe after a crash.
        let pending = state
            .prepare_share_unexposed(
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
                &fixture.abandonment_context,
                &fixture.identities[0],
            )
            .unwrap();
        let persisted = pending.state_to_persist().to_vec();
        let fenced = pending
            .release_after_persisted_state(
                &persisted,
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
            )
            .unwrap();
        assert_eq!(fenced.witness().from, PartyId(1));
        let (_, fence) = fenced.into_parts();
        assert_eq!(
            state
                .prepare_share_exposure(
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                    vec![0xa5; 64],
                )
                .unwrap_err(),
            ConsolidationConsensusError::ShareExposureAfterFence,
        );

        let mut restored = ConsolidationAttemptSafety::restore(
            &persisted,
            &fixture.intent_context,
            &expected,
            &fixture.intent_certificate,
        )
        .unwrap();
        assert_eq!(
            restored
                .prepare_share_exposure(
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                    vec![0xa5; 64],
                )
                .unwrap_err(),
            ConsolidationConsensusError::ShareExposureAfterFence,
        );

        let certificate = certified_abandonment(&fixture);
        assert!(
            state
                .mark_abandoned_certified(
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                    &fixture.abandonment_context,
                    &certificate,
                    &fence,
                )
                .unwrap()
        );
        assert!(matches!(state.phase(), AttemptSafetyPhase::AbandonedCertified { .. }));
        assert!(
            !state
                .mark_abandoned_certified(
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                    &fixture.abandonment_context,
                    &certificate,
                    &fence,
                )
                .unwrap()
        );
        assert_eq!(
            state
                .prepare_share_exposure(
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                    vec![0xa5; 64],
                )
                .unwrap_err(),
            ConsolidationConsensusError::ShareExposureAfterFence,
        );
    }

    #[test]
    fn party_without_a_start_can_fence_directly_from_nonce_unreleased() {
        let fixture = fixture();
        let expected = fixture.intent_certificate.verify().unwrap();
        let mut state = ConsolidationAttemptSafety::new(
            PartyId(4),
            &fixture.intent_context,
            expected.clone(),
            &fixture.intent_certificate,
        )
        .unwrap();
        assert_eq!(state.phase(), AttemptSafetyPhase::NonceUnreleased);
        let pending = state
            .prepare_share_unexposed(
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
                &fixture.abandonment_context,
                &fixture.identities[3],
            )
            .unwrap();
        assert_eq!(state.phase(), AttemptSafetyPhase::AbandonmentFenced);
        assert_eq!(state.revision(), 1);
        let persisted = pending.state_to_persist().to_vec();
        let (_, fence) = pending
            .release_after_persisted_state(
                &persisted,
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
            )
            .unwrap()
            .into_parts();
        let certificate = certified_abandonment(&fixture);
        assert!(
            state
                .mark_abandoned_certified(
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                    &fixture.abandonment_context,
                    &certificate,
                    &fence,
                )
                .unwrap()
        );
        assert_eq!(state.revision(), 2);
        assert!(state.is_transition_terminal());
    }

    #[test]
    fn outbound_share_is_hidden_until_exact_exposure_state_readback() {
        let fixture = fixture();
        let (expected, mut state) = released_safety(&fixture, PartyId(1));
        let pre_exposure = state.encode().unwrap();
        assert_eq!(
            state
                .prepare_share_exposure(
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                    Vec::new(),
                )
                .unwrap_err(),
            ConsolidationConsensusError::InvalidSharePayload,
        );
        assert_eq!(state.encode().unwrap(), pre_exposure);
        assert_eq!(
            state
                .prepare_share_exposure(
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                    vec![0; MAX_PENDING_SHARE_PAYLOAD_BYTES + 1],
                )
                .unwrap_err(),
            ConsolidationConsensusError::InvalidSharePayload,
        );
        assert_eq!(state.encode().unwrap(), pre_exposure);
        let payload = vec![0xb5; 96];
        let pending = state
            .prepare_share_exposure(
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
                payload.clone(),
            )
            .unwrap();
        assert_eq!(state.phase(), AttemptSafetyPhase::ShareExposed);
        assert_eq!(state.share_payload_binding(), Some(pending.payload_binding()));
        assert_eq!(
            pending
                .release_after_persisted_state(
                    &pre_exposure,
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                )
                .unwrap_err(),
            ConsolidationConsensusError::ShareExposureNotPersisted,
        );

        let pending = state
            .prepare_share_exposure(
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
                payload.clone(),
            )
            .unwrap();
        let persisted = pending.state_to_persist().to_vec();
        let released = pending
            .release_after_persisted_state(
                &persisted,
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
            )
            .unwrap();
        assert_eq!(released.payload(), payload);
        let (released_payload, capability) = released.into_parts();
        capability.validate_for(&state, &released_payload).unwrap();

        assert_eq!(
            state
                .prepare_share_exposure(
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                    vec![0xc5; 96],
                )
                .unwrap_err(),
            ConsolidationConsensusError::ConflictingSharePayload,
        );
        assert_eq!(
            state
                .prepare_share_unexposed(
                    &fixture.intent_context,
                    &expected,
                    &fixture.intent_certificate,
                    &fixture.abandonment_context,
                    &fixture.identities[0],
                )
                .unwrap_err(),
            ConsolidationConsensusError::ShareAlreadyExposed,
        );

        // A forged/bypassed ShareExposed state without the bound payload is invalid on restart.
        let mut bypass = state.clone();
        bypass.share_payload = None;
        bypass.transition = bypass.expected_transition_commitment().unwrap();
        let bypass = bypass.encode().unwrap();
        assert_eq!(
            ConsolidationAttemptSafety::restore(
                &bypass,
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
            )
            .unwrap_err(),
            ConsolidationConsensusError::InvalidSafetyState,
        );
    }

    #[test]
    fn restored_safety_state_requires_the_exact_trusted_intent() {
        let fixture = fixture();
        let (expected, state) = released_safety(&fixture, PartyId(2));
        let encoded = state.encode().unwrap();
        assert_eq!(
            ConsolidationAttemptSafety::restore(
                &encoded,
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
            )
            .unwrap(),
            state,
        );

        let wrong = alternate_intent(&fixture, false);
        assert_eq!(
            ConsolidationAttemptSafety::restore(
                &encoded,
                &fixture.intent_context,
                &wrong,
                &fixture.intent_certificate,
            )
            .unwrap_err(),
            ConsolidationConsensusError::WrongExpectedIntent,
        );
        assert_eq!(
            fixture
                .intent_certificate
                .verify_expected(&fixture.intent_context, &wrong)
                .unwrap_err(),
            ConsolidationConsensusError::WrongExpectedIntent,
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            ConsolidationAttemptSafety::restore(
                &trailing,
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
            )
            .unwrap_err(),
            ConsolidationConsensusError::TrailingBytes,
        );
    }

    #[test]
    fn reused_signing_session_with_another_attempt_is_a_collision() {
        let fixture = fixture();
        let (expected, state) = released_safety(&fixture, PartyId(1));
        let colliding = alternate_intent(&fixture, true);
        assert_eq!(colliding.attempt().session(), expected.attempt().session());
        assert_ne!(colliding.attempt().digest(), expected.attempt().digest());
        assert_eq!(
            state.validate_expected(
                &fixture.intent_context,
                &colliding,
                &fixture.intent_certificate,
            ),
            Err(ConsolidationConsensusError::AttemptSessionCollision),
        );

        let colliding_abandonment = context(
            fixture.abandonment_context.committee().clone(),
            CONSOLIDATION_ABANDONMENT_APPLICATION,
            0x67,
            1,
            42,
            fixture.intent_certificate.decision_digest(),
        );
        assert_eq!(
            sign_share_unexposed_statement(
                &colliding_abandonment,
                &fixture.intent_certificate,
                &expected,
                &fixture.identities[0],
            ),
            Err(ConsolidationConsensusError::ProtocolSessionCollision),
        );
    }

    #[test]
    fn intent_requires_threshold_plus_f_available_signers() {
        let fixture = fixture();
        let expected = fixture.intent_certificate.verify().unwrap();
        let attempt = expected.attempt();
        let insufficient = AttemptBinding::new(
            attempt.attempt(),
            attempt.epoch(),
            attempt.registry_digest(),
            attempt.committee_digest(),
            attempt.activation_digest(),
            attempt.root_group_key(),
            attempt.threshold(),
            attempt.signers()[..usize::from(attempt.threshold())].to_vec(),
            attempt.worker_intent_digest(),
            SessionId([0xa1; 32]),
            [0xa2; 32],
        )
        .unwrap();
        assert_eq!(
            ConsolidationIntent::new(
                &fixture.intent_context,
                expected.authorization().clone(),
                insufficient,
            ),
            Err(ConsolidationConsensusError::InsufficientSignerAvailability),
        );
    }

    #[test]
    fn witness_subset_selection_is_safe_canonical_and_deterministic() {
        let fixture = fixture();
        let expected = fixture.intent_certificate.verify().unwrap();
        let mut available = fixture
            .identities
            .iter()
            .map(|identity| {
                sign_share_unexposed_statement(
                    &fixture.abandonment_context,
                    &fixture.intent_certificate,
                    &expected,
                    identity,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let forward = ShareUnexposedCertificate::from_available_witnesses(
            &fixture.abandonment_context,
            &fixture.intent_certificate,
            available.clone(),
        )
        .unwrap();
        available.reverse();
        let reverse = ShareUnexposedCertificate::from_available_witnesses(
            &fixture.abandonment_context,
            &fixture.intent_certificate,
            available,
        )
        .unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(
            forward.witnesses().iter().map(|witness| witness.from).collect::<Vec<_>>(),
            vec![PartyId(1), PartyId(2), PartyId(3)],
        );
    }

    #[test]
    fn reducer_validator_requires_the_exact_fenced_attempt() {
        let fixture = fixture();
        let (expected, mut state) = released_safety(&fixture, PartyId(1));
        let value = abandonment_value(&fixture).to_consensus_value().unwrap();
        let pending = state
            .prepare_share_unexposed(
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
                &fixture.abandonment_context,
                &fixture.identities[0],
            )
            .unwrap();
        let persisted = pending.state_to_persist().to_vec();
        let (_, fence) = pending
            .release_after_persisted_state(
                &persisted,
                &fixture.intent_context,
                &expected,
                &fixture.intent_certificate,
            )
            .unwrap()
            .into_parts();
        assert!(validate_consolidation_abandonment_value_for_safety_state(
            &fixture.abandonment_context,
            &fixture.intent_context,
            &expected,
            &fixture.intent_certificate,
            &state,
            &fence,
            &value,
        ));
        let wrong = alternate_intent(&fixture, false);
        assert!(!validate_consolidation_abandonment_value_for_safety_state(
            &fixture.abandonment_context,
            &fixture.intent_context,
            &wrong,
            &fixture.intent_certificate,
            &state,
            &fence,
            &value,
        ));
    }
}
