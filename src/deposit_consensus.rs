//! Durable, transport- and clock-independent Byzantine consensus for deposit operations.
//!
//! Every vote and certificate is portable: safety decisions are made from canonical collections
//! of complete Ed25519 [`SignedEnvelope`] witnesses, never from unauthenticated signer IDs.  The
//! reducer never reads a clock.  A caller decides when to request a view change, atomically persists
//! the returned state and outbound envelopes, and then relays each portable envelope to peers.
//!
//! This is a single-height reducer.  Its immutable [`ConsensusContext`] binds the application,
//! wallet, Monero network, registry and activation, committee and fault assumption, height,
//! sequence, and predecessor digest.  Start another reducer for the next height only after
//! persisting the resulting [`CommitCertificate`].
//!
//! Serde restoration rechecks signatures and internal reachability, after which the caller must
//! invoke [`DepositConsensus::validate_application_values`]. Decode snapshots behind an outer byte
//! limit and protect their monotonic revision with the durable storage layer: no self-contained
//! state machine can distinguish a byte-for-byte valid rollback from the original old snapshot.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::{
    committee::{Committee, CommitteeError, MAX_COMMITTEE_MEMBERS, PartyId, SessionId},
    identity::{Identity, IdentityError, SignedEnvelope},
};

const CONSENSUS_VERSION: u16 = 1;
const CONSENSUS_STATE_VERSION: u16 = 1;
const VALUE_VERSION: u16 = 1;
const PREPARE_CERTIFICATE_VERSION: u16 = 1;
const COMMIT_CERTIFICATE_VERSION: u16 = 1;
const VIEW_CERTIFICATE_VERSION: u16 = 1;
const WIRE_SEQUENCE_VIEW_BITS: u32 = 22;
const WIRE_SEQUENCE_KIND_BITS: u32 = 2;
const WIRE_SEQUENCE_LOW_BITS: u32 = WIRE_SEQUENCE_VIEW_BITS + WIRE_SEQUENCE_KIND_BITS;

// Test-only counters make the replay property observable without changing the production state
// format or putting a mock signature implementation on a security-critical path. Thread-local
// storage keeps independently scheduled Rust tests isolated.
#[cfg(test)]
std::thread_local! {
    static TEST_VIEW_CERTIFICATE_VERIFICATIONS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
    static TEST_COMMIT_CERTIFICATE_VERIFICATIONS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
fn note_view_certificate_verification() {
    TEST_VIEW_CERTIFICATE_VERIFICATIONS.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
fn take_view_certificate_verifications() -> usize {
    TEST_VIEW_CERTIFICATE_VERIFICATIONS.with(|count| count.replace(0))
}

#[cfg(test)]
fn note_commit_certificate_verification() {
    TEST_COMMIT_CERTIFICATE_VERIFICATIONS.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
fn take_commit_certificate_verifications() -> usize {
    TEST_COMMIT_CERTIFICATE_VERIFICATIONS.with(|count| count.replace(0))
}

/// Hard bound for application-domain labels committed by a consensus context.
pub const MAX_CONSENSUS_APPLICATION_BYTES: usize = 64;
/// Hard bound for an opaque canonical application value.
pub const MAX_CONSENSUS_VALUE_BYTES: usize = 64 * 1024;
/// Hard bound for one signed consensus payload, including nested full-witness certificates.
pub const MAX_CONSENSUS_MESSAGE_BYTES: usize = 1024 * 1024;
/// Highest representable view.  This keeps signed-envelope sequence slots collision-free.
pub const MAX_CONSENSUS_VIEW: u64 = (1_u64 << WIRE_SEQUENCE_VIEW_BITS) - 1;
/// Diagnostic evidence does not affect safety and is retained under this fixed cap.
pub const MAX_CONSENSUS_EVIDENCE: usize = MAX_COMMITTEE_MEMBERS * 2;
/// A singleton `f=0` reducer can emit a view change, proposal, and both vote phases in one step.
pub const MAX_CONSENSUS_OUTBOUND_PER_STEP: usize = 4;

/// Application and chain bindings shared by every height in one deployment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsensusBinding {
    pub domain: [u8; 32],
    #[serde(
        serialize_with = "serialize_bounded_bytes",
        deserialize_with = "deserialize_application_bytes"
    )]
    pub application: Vec<u8>,
    pub wallet: [u8; 32],
    pub network: [u8; 32],
    pub registry: [u8; 32],
    pub activation: [u8; 32],
}

impl ConsensusBinding {
    fn validate(&self) -> Result<(), ConsensusError> {
        if self.domain == [0; 32]
            || self.wallet == [0; 32]
            || self.network == [0; 32]
            || self.registry == [0; 32]
            || self.activation == [0; 32]
        {
            return Err(ConsensusError::InvalidContext("security binding cannot be zero"));
        }
        if self.application.is_empty() || self.application.len() > MAX_CONSENSUS_APPLICATION_BYTES {
            return Err(ConsensusError::InvalidContext("application tag has an invalid length"));
        }
        Ok(())
    }
}

/// Immutable, fully domain-separated context for one consensus height and sequence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsensusContext {
    version: u16,
    binding: ConsensusBinding,
    session: SessionId,
    epoch: u64,
    committee: Committee,
    fault_bound: u16,
    height: u64,
    sequence: u64,
    previous: [u8; 32],
}

#[derive(Deserialize)]
struct UncheckedConsensusContext {
    version: u16,
    binding: ConsensusBinding,
    session: SessionId,
    epoch: u64,
    committee: Committee,
    fault_bound: u16,
    height: u64,
    sequence: u64,
    previous: [u8; 32],
}

impl<'de> Deserialize<'de> for ConsensusContext {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let unchecked = UncheckedConsensusContext::deserialize(deserializer)?;
        let context = Self {
            version: unchecked.version,
            binding: unchecked.binding,
            session: unchecked.session,
            epoch: unchecked.epoch,
            committee: unchecked.committee,
            fault_bound: unchecked.fault_bound,
            height: unchecked.height,
            sequence: unchecked.sequence,
            previous: unchecked.previous,
        };
        context.validate().map_err(D::Error::custom)?;
        Ok(context)
    }
}

impl ConsensusContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: ConsensusBinding,
        session: SessionId,
        committee: Committee,
        fault_bound: u16,
        height: u64,
        sequence: u64,
        previous: [u8; 32],
    ) -> Result<Self, ConsensusError> {
        let context = Self {
            version: CONSENSUS_VERSION,
            binding,
            session,
            epoch: committee.epoch,
            committee,
            fault_bound,
            height,
            sequence,
            previous,
        };
        context.validate()?;
        Ok(context)
    }

    pub fn validate(&self) -> Result<(), ConsensusError> {
        if self.version != CONSENSUS_VERSION {
            return Err(ConsensusError::UnsupportedVersion);
        }
        self.binding.validate()?;
        self.committee.validate_async_security_with_faults(self.fault_bound)?;
        if self.session.0 == [0; 32] {
            return Err(ConsensusError::InvalidContext("session cannot be zero"));
        }
        if self.epoch != self.committee.epoch {
            return Err(ConsensusError::InvalidContext("epoch differs from committee"));
        }
        if self.sequence > (u64::MAX >> WIRE_SEQUENCE_LOW_BITS) {
            return Err(ConsensusError::InvalidContext("sequence exceeds signed-slot range"));
        }
        if self.sequence == 0 {
            return Err(ConsensusError::InvalidContext("sequence cannot be zero"));
        }
        if self.height == 0 {
            if self.previous != [0; 32] {
                return Err(ConsensusError::InvalidContext(
                    "genesis height must have a zero predecessor",
                ));
            }
        } else if self.previous == [0; 32] {
            return Err(ConsensusError::InvalidContext(
                "non-genesis height must bind a predecessor",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn binding(&self) -> &ConsensusBinding {
        &self.binding
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    #[must_use]
    pub const fn fault_bound(&self) -> u16 {
        self.fault_bound
    }

    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn previous(&self) -> [u8; 32] {
        self.previous
    }

    #[must_use]
    pub fn quorum(&self) -> usize {
        usize::from(self.committee.n() - self.fault_bound)
    }

    /// Deterministically rotate leaders across ledger sequences and views.
    #[must_use]
    pub fn leader(&self, view: u64) -> PartyId {
        let n = u64::from(self.committee.n());
        let index = (((self.sequence - 1) % n) + (view % n)) % n;
        let one_based = u16::try_from(index + 1).expect("validated committee fits u16");
        self.committee
            .party_for_frost_index(one_based)
            .expect("derived leader index is in the committee")
    }

    /// Canonical commitment repeated by every signed message and certificate.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/deposit-consensus-context/v1");
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.binding.domain);
        hasher.update(&(self.binding.application.len() as u64).to_le_bytes());
        hasher.update(&self.binding.application);
        hasher.update(&self.binding.wallet);
        hasher.update(&self.binding.network);
        hasher.update(&self.binding.registry);
        hasher.update(&self.binding.activation);
        hasher.update(&self.session.0);
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.committee.digest());
        hasher.update(&self.fault_bound.to_le_bytes());
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&self.previous);
        *hasher.finalize().as_bytes()
    }
}

/// Digest of a canonical opaque value.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConsensusValueDigest(pub [u8; 32]);

/// Bounded opaque application bytes and their domain-separated digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsensusValue {
    version: u16,
    #[serde(
        serialize_with = "serialize_bounded_bytes",
        deserialize_with = "deserialize_value_bytes"
    )]
    bytes: Vec<u8>,
    digest: ConsensusValueDigest,
}

#[derive(Deserialize)]
struct UncheckedConsensusValue {
    version: u16,
    #[serde(deserialize_with = "deserialize_value_bytes")]
    bytes: Vec<u8>,
    digest: ConsensusValueDigest,
}

impl<'de> Deserialize<'de> for ConsensusValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let unchecked = UncheckedConsensusValue::deserialize(deserializer)?;
        let value =
            Self { version: unchecked.version, bytes: unchecked.bytes, digest: unchecked.digest };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

impl ConsensusValue {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ConsensusError> {
        if bytes.len() > MAX_CONSENSUS_VALUE_BYTES {
            return Err(ConsensusError::ValueTooLarge {
                actual: bytes.len(),
                maximum: MAX_CONSENSUS_VALUE_BYTES,
            });
        }
        let digest = value_digest(&bytes);
        Ok(Self { version: VALUE_VERSION, bytes, digest })
    }

    pub fn validate(&self) -> Result<(), ConsensusError> {
        if self.version != VALUE_VERSION {
            return Err(ConsensusError::UnsupportedVersion);
        }
        if self.bytes.len() > MAX_CONSENSUS_VALUE_BYTES {
            return Err(ConsensusError::ValueTooLarge {
                actual: self.bytes.len(),
                maximum: MAX_CONSENSUS_VALUE_BYTES,
            });
        }
        if self.digest != value_digest(&self.bytes) {
            return Err(ConsensusError::InvalidValueDigest);
        }
        Ok(())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn digest(&self) -> ConsensusValueDigest {
        self.digest
    }
}

fn value_digest(bytes: &[u8]) -> ConsensusValueDigest {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/deposit-consensus-value/v1");
    hasher.update(&VALUE_VERSION.to_le_bytes());
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    ConsensusValueDigest(*hasher.finalize().as_bytes())
}

fn serialize_bounded_bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(bytes)
}

fn deserialize_application_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    deserialize_bounded_bytes::<D, MAX_CONSENSUS_APPLICATION_BYTES>(deserializer)
}

fn deserialize_value_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    deserialize_bounded_bytes::<D, MAX_CONSENSUS_VALUE_BYTES>(deserializer)
}

fn deserialize_bounded_bytes<'de, D: Deserializer<'de>, const MAXIMUM: usize>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    struct BoundedBytesVisitor<const MAXIMUM: usize>;

    impl<'de, const MAXIMUM: usize> Visitor<'de> for BoundedBytesVisitor<MAXIMUM> {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAXIMUM} bytes")
        }

        fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
            if value.len() > MAXIMUM {
                return Err(E::invalid_length(value.len(), &self));
            }
            Ok(value.to_vec())
        }

        fn visit_borrowed_bytes<E: serde::de::Error>(
            self,
            value: &'de [u8],
        ) -> Result<Self::Value, E> {
            self.visit_bytes(value)
        }

        fn visit_byte_buf<E: serde::de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
            if value.len() > MAXIMUM {
                return Err(E::invalid_length(value.len(), &self));
            }
            Ok(value)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let hinted = sequence.size_hint().unwrap_or(0);
            if hinted > MAXIMUM {
                return Err(A::Error::invalid_length(hinted, &self));
            }
            let mut bytes = Vec::with_capacity(hinted.min(MAXIMUM));
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == MAXIMUM {
                    return Err(A::Error::invalid_length(MAXIMUM.saturating_add(1), &self));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_bytes(BoundedBytesVisitor::<MAXIMUM>)
}

fn deserialize_certificate_witnesses<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<SignedEnvelope>, D::Error> {
    struct WitnessVisitor;

    impl<'de> Visitor<'de> for WitnessVisitor {
        type Value = Vec<SignedEnvelope>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_COMMITTEE_MEMBERS} signed witnesses")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let hinted = sequence.size_hint().unwrap_or(0);
            if hinted > MAX_COMMITTEE_MEMBERS {
                return Err(A::Error::invalid_length(hinted, &self));
            }
            let mut witnesses = Vec::with_capacity(hinted.min(MAX_COMMITTEE_MEMBERS));
            while let Some(witness) = sequence.next_element()? {
                if witnesses.len() == MAX_COMMITTEE_MEMBERS {
                    return Err(A::Error::invalid_length(
                        MAX_COMMITTEE_MEMBERS.saturating_add(1),
                        &self,
                    ));
                }
                witnesses.push(witness);
            }
            Ok(witnesses)
        }
    }

    deserializer.deserialize_seq(WitnessVisitor)
}

/// Leader proposal for one view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub view: u64,
    pub value: ConsensusValue,
    /// The deterministically selected highest prepared certificate in `view_change`.
    pub proof_of_lock: Option<PrepareCertificate>,
    /// Required for every view after zero.
    pub view_change: Option<ViewChangeCertificate>,
}

/// A digest vote in one view.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Vote {
    pub view: u64,
    pub value: ConsensusValueDigest,
}

/// A request to advance exactly one view, carrying the sender's highest prepared certificate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ViewChange {
    pub from_view: u64,
    pub target_view: u64,
    pub highest_prepared: Option<PrepareCertificate>,
}

/// Canonical body authenticated inside a portable [`SignedEnvelope`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConsensusMessageBody {
    Proposal(Proposal),
    Prevote(Vote),
    Precommit(Vote),
    ViewChange(ViewChange),
}

impl ConsensusMessageBody {
    #[must_use]
    pub const fn view(&self) -> u64 {
        match self {
            Self::Proposal(proposal) => proposal.view,
            Self::Prevote(vote) | Self::Precommit(vote) => vote.view,
            Self::ViewChange(change) => change.target_view,
        }
    }

    const fn kind(&self) -> MessageKind {
        match self {
            Self::Proposal(_) => MessageKind::Proposal,
            Self::Prevote(_) => MessageKind::Prevote,
            Self::Precommit(_) => MessageKind::Precommit,
            Self::ViewChange(_) => MessageKind::ViewChange,
        }
    }
}

/// Versioned context-bound signed payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsensusMessage {
    pub version: u16,
    pub context: [u8; 32],
    pub body: ConsensusMessageBody,
}

impl ConsensusMessage {
    #[must_use]
    pub fn new(context: &ConsensusContext, body: ConsensusMessageBody) -> Self {
        Self { version: CONSENSUS_VERSION, context: context.digest(), body }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum EvidenceKind {
    Proposal,
    Prevote,
    Precommit,
    ViewChange,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub view: u64,
    pub offender: PartyId,
    pub kind: EvidenceKind,
    pub first: SignedEnvelope,
    pub conflicting: SignedEnvelope,
}

/// A canonical, exact `n-f` collection of signed PREVOTE witnesses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrepareCertificate {
    version: u16,
    context: [u8; 32],
    view: u64,
    value: ConsensusValue,
    #[serde(deserialize_with = "deserialize_certificate_witnesses")]
    witnesses: Vec<SignedEnvelope>,
}

impl PrepareCertificate {
    pub fn from_witnesses(
        context: &ConsensusContext,
        view: u64,
        value: ConsensusValue,
        mut witnesses: Vec<SignedEnvelope>,
    ) -> Result<Self, ConsensusError> {
        witnesses.sort_unstable_by_key(|witness| witness.from);
        let certificate = Self {
            version: PREPARE_CERTIFICATE_VERSION,
            context: context.digest(),
            view,
            value,
            witnesses,
        };
        certificate.verify(context)?;
        Ok(certificate)
    }

    pub fn verify(&self, context: &ConsensusContext) -> Result<(), ConsensusError> {
        if self.version != PREPARE_CERTIFICATE_VERSION {
            return Err(ConsensusError::InvalidCertificate("unsupported prepare certificate"));
        }
        self.verify_common(context)?;
        verify_vote_witnesses(
            context,
            self.view,
            self.value.digest(),
            MessageKind::Prevote,
            &self.witnesses,
        )
    }

    fn verify_common(&self, context: &ConsensusContext) -> Result<(), ConsensusError> {
        if self.context != context.digest() || self.view > MAX_CONSENSUS_VIEW {
            return Err(ConsensusError::InvalidCertificate("prepare context or view mismatch"));
        }
        self.value.validate()?;
        verify_canonical_witness_set(context, &self.witnesses)
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub fn value(&self) -> &ConsensusValue {
        &self.value
    }

    #[must_use]
    pub fn witnesses(&self) -> &[SignedEnvelope] {
        &self.witnesses
    }

    fn canonical_digest(&self) -> [u8; 32] {
        let encoded = postcard::to_allocvec(self).expect("certificate serialization is infallible");
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/prepare-certificate/v1");
        hasher.update(&encoded);
        *hasher.finalize().as_bytes()
    }
}

/// A canonical, exact `n-f` collection of signed PRECOMMIT witnesses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitCertificate {
    version: u16,
    context: [u8; 32],
    view: u64,
    value: ConsensusValue,
    #[serde(deserialize_with = "deserialize_certificate_witnesses")]
    witnesses: Vec<SignedEnvelope>,
}

impl CommitCertificate {
    pub fn from_witnesses(
        context: &ConsensusContext,
        view: u64,
        value: ConsensusValue,
        mut witnesses: Vec<SignedEnvelope>,
    ) -> Result<Self, ConsensusError> {
        witnesses.sort_unstable_by_key(|witness| witness.from);
        let certificate = Self {
            version: COMMIT_CERTIFICATE_VERSION,
            context: context.digest(),
            view,
            value,
            witnesses,
        };
        certificate.verify(context)?;
        Ok(certificate)
    }

    pub fn verify(&self, context: &ConsensusContext) -> Result<(), ConsensusError> {
        #[cfg(test)]
        note_commit_certificate_verification();
        if self.version != COMMIT_CERTIFICATE_VERSION
            || self.context != context.digest()
            || self.view > MAX_CONSENSUS_VIEW
        {
            return Err(ConsensusError::InvalidCertificate("invalid commit certificate header"));
        }
        self.value.validate()?;
        verify_canonical_witness_set(context, &self.witnesses)?;
        verify_vote_witnesses(
            context,
            self.view,
            self.value.digest(),
            MessageKind::Precommit,
            &self.witnesses,
        )
    }

    /// Return parties that directly double-signed conflicting commits in the same view.
    ///
    /// Two same-view certificates intersect in at least `n-2f > f` parties. Cross-view conflicts
    /// still violate consensus safety, but an honest signer may have followed a later apparently
    /// valid proof of lock, so this method returns [`ConsensusError::CrossViewConflict`] instead of
    /// falsely attributing direct equivocation.
    pub fn conflicting_signers(
        &self,
        other: &Self,
        context: &ConsensusContext,
    ) -> Result<Vec<PartyId>, ConsensusError> {
        self.verify(context)?;
        other.verify(context)?;
        if self.value.digest() == other.value.digest() {
            return Ok(Vec::new());
        }
        if self.view != other.view {
            return Err(ConsensusError::CrossViewConflict);
        }
        let left = self.witnesses.iter().map(|witness| witness.from).collect::<BTreeSet<_>>();
        let right = other.witnesses.iter().map(|witness| witness.from).collect::<BTreeSet<_>>();
        let intersection = left.intersection(&right).copied().collect::<Vec<_>>();
        if intersection.len() <= usize::from(context.fault_bound) {
            return Err(ConsensusError::ConflictingQuorums);
        }
        Ok(intersection)
    }

    /// Witness-subset-independent digest for the next height's `previous` binding.
    ///
    /// Different honest parties may first collect different canonical `n-f` subsets for the same
    /// decision.  Those certificates are interchangeable, so the chain digest commits to the
    /// context and decided value rather than one collector's witness subset.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/deposit-consensus-decision/v1");
        hasher.update(&COMMIT_CERTIFICATE_VERSION.to_le_bytes());
        hasher.update(&self.context);
        hasher.update(&self.value.digest().0);
        *hasher.finalize().as_bytes()
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub fn value(&self) -> &ConsensusValue {
        &self.value
    }

    #[must_use]
    pub fn witnesses(&self) -> &[SignedEnvelope] {
        &self.witnesses
    }
}

/// A canonical, exact `n-f` collection of signed view-change witnesses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ViewChangeCertificate {
    version: u16,
    context: [u8; 32],
    target_view: u64,
    #[serde(deserialize_with = "deserialize_certificate_witnesses")]
    witnesses: Vec<SignedEnvelope>,
}

impl ViewChangeCertificate {
    pub fn from_witnesses(
        context: &ConsensusContext,
        target_view: u64,
        mut witnesses: Vec<SignedEnvelope>,
    ) -> Result<Self, ConsensusError> {
        witnesses.sort_unstable_by_key(|witness| witness.from);
        let certificate = Self {
            version: VIEW_CERTIFICATE_VERSION,
            context: context.digest(),
            target_view,
            witnesses,
        };
        certificate.verify(context)?;
        Ok(certificate)
    }

    pub fn verify(&self, context: &ConsensusContext) -> Result<(), ConsensusError> {
        #[cfg(test)]
        note_view_certificate_verification();
        if self.version != VIEW_CERTIFICATE_VERSION
            || self.context != context.digest()
            || self.target_view == 0
            || self.target_view > MAX_CONSENSUS_VIEW
        {
            return Err(ConsensusError::InvalidCertificate(
                "invalid view-change certificate header",
            ));
        }
        verify_canonical_witness_set(context, &self.witnesses)?;
        for witness in &self.witnesses {
            let message = decode_signed_message(context, witness)?;
            let ConsensusMessageBody::ViewChange(change) = message.body else {
                return Err(ConsensusError::InvalidCertificate(
                    "view certificate contains a non-view-change witness",
                ));
            };
            validate_view_change(context, &change)?;
            if change.target_view != self.target_view {
                return Err(ConsensusError::InvalidCertificate(
                    "view-change witness targets another view",
                ));
            }
        }
        self.highest_prepared(context)?;
        Ok(())
    }

    /// Deterministically select the highest prepared certificate carried by the witnesses.
    /// Equal-view certificates must name one value; their canonical certificate digest breaks
    /// ties between different valid `n-f` witness subsets.
    pub fn highest_prepared(
        &self,
        context: &ConsensusContext,
    ) -> Result<Option<PrepareCertificate>, ConsensusError> {
        let mut highest: Option<PrepareCertificate> = None;
        for witness in &self.witnesses {
            let message = decode_signed_message(context, witness)?;
            let ConsensusMessageBody::ViewChange(change) = message.body else {
                return Err(ConsensusError::InvalidCertificate(
                    "view certificate contains a non-view-change witness",
                ));
            };
            let Some(candidate) = change.highest_prepared else {
                continue;
            };
            candidate.verify(context)?;
            if candidate.view >= self.target_view {
                return Err(ConsensusError::InvalidCertificate(
                    "prepared certificate does not precede target view",
                ));
            }
            match &highest {
                None => highest = Some(candidate),
                Some(current) if candidate.view > current.view => highest = Some(candidate),
                Some(current) if candidate.view == current.view => {
                    if candidate.value.digest() != current.value.digest() {
                        return Err(ConsensusError::ConflictingQuorums);
                    }
                    if candidate.canonical_digest() < current.canonical_digest() {
                        highest = Some(candidate);
                    }
                }
                Some(_) => {}
            }
        }
        Ok(highest)
    }

    #[must_use]
    pub const fn target_view(&self) -> u64 {
        self.target_view
    }

    #[must_use]
    pub fn witnesses(&self) -> &[SignedEnvelope] {
        &self.witnesses
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConsensusStep {
    /// Portable broadcasts.  The caller durably enqueues one delivery per peer.
    pub broadcast: Vec<SignedEnvelope>,
    /// Newly assembled or adopted portable view certificate to durably gossip to every peer.
    pub relay_view_certificate: Option<ViewChangeCertificate>,
    /// Newly assembled or adopted portable commit certificate to durably gossip to every peer.
    pub relay_commit_certificate: Option<CommitCertificate>,
    /// A newly learned terminal decision for the local application.
    pub commit: Option<CommitCertificate>,
    pub evidence: Vec<EquivocationEvidence>,
    pub entered_view: Option<u64>,
    pub duplicate: bool,
    pub changed: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsensusError {
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("unsupported consensus version")]
    UnsupportedVersion,
    #[error("invalid consensus context: {0}")]
    InvalidContext(&'static str),
    #[error("value has {actual} bytes; maximum is {maximum}")]
    ValueTooLarge { actual: usize, maximum: usize },
    #[error("opaque value digest does not match its canonical bytes")]
    InvalidValueDigest,
    #[error("message serialization failed")]
    Serialization,
    #[error("signed message has {actual} bytes; maximum is {maximum}")]
    MessageTooLarge { actual: usize, maximum: usize },
    #[error("signed message has trailing bytes")]
    TrailingMessageBytes,
    #[error("message belongs to another consensus context")]
    WrongContext,
    #[error("consensus messages must be portable broadcasts")]
    NonPortableEnvelope,
    #[error("signed envelope uses the wrong session or logical sequence")]
    WrongEnvelopeSlot,
    #[error("party {0} is not a consensus voter")]
    UnknownVoter(PartyId),
    #[error("identity does not belong to the local reducer party")]
    WrongLocalIdentity,
    #[error("proposal did not come from the deterministic view leader")]
    WrongLeader,
    #[error("invalid certificate: {0}")]
    InvalidCertificate(&'static str),
    #[error("application rejected the proposed value")]
    InvalidApplicationValue,
    #[error("consensus has already started")]
    AlreadyStarted,
    #[error("consensus has not started")]
    NotStarted,
    #[error("consensus height is already committed")]
    AlreadyCommitted,
    #[error("message is from stale view {message}; current view is {current}")]
    StaleView { message: u64, current: u64 },
    #[error("message is from unsupported future view {message}; current view is {current}")]
    FutureView { message: u64, current: u64 },
    #[error("maximum consensus view exhausted")]
    ViewExhausted,
    #[error("conflicting quorum certificates require more faults than configured")]
    ConflictingQuorums,
    #[error(
        "cross-view conflicting decisions violate safety but do not identify direct double-voters"
    )]
    CrossViewConflict,
    #[error("outbound transition exceeded its fixed resource bound")]
    OutboundLimit,
    #[error("invalid persisted consensus state: {0}")]
    InvalidPersistedState(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageKind {
    Proposal = 0,
    Prevote = 1,
    Precommit = 2,
    ViewChange = 3,
}

impl MessageKind {
    const fn evidence(self) -> EvidenceKind {
        match self {
            Self::Proposal => EvidenceKind::Proposal,
            Self::Prevote => EvidenceKind::Prevote,
            Self::Precommit => EvidenceKind::Precommit,
            Self::ViewChange => EvidenceKind::ViewChange,
        }
    }
}

/// Durable state for one party and one context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DepositConsensus {
    state_version: u16,
    context: ConsensusContext,
    local_party: PartyId,
    started: bool,
    view: u64,
    candidate: Option<ConsensusValue>,
    view_certificate: Option<ViewChangeCertificate>,
    proposal: Option<SignedEnvelope>,
    prevotes: BTreeMap<PartyId, SignedEnvelope>,
    precommits: BTreeMap<PartyId, SignedEnvelope>,
    next_view_changes: BTreeMap<PartyId, SignedEnvelope>,
    locked: Option<PrepareCertificate>,
    highest_prepared: Option<PrepareCertificate>,
    committed: Option<CommitCertificate>,
    evidence: VecDeque<EquivocationEvidence>,
}

#[derive(Deserialize)]
struct UncheckedDepositConsensus {
    state_version: u16,
    context: ConsensusContext,
    local_party: PartyId,
    started: bool,
    view: u64,
    candidate: Option<ConsensusValue>,
    view_certificate: Option<ViewChangeCertificate>,
    proposal: Option<SignedEnvelope>,
    prevotes: BTreeMap<PartyId, SignedEnvelope>,
    precommits: BTreeMap<PartyId, SignedEnvelope>,
    next_view_changes: BTreeMap<PartyId, SignedEnvelope>,
    locked: Option<PrepareCertificate>,
    highest_prepared: Option<PrepareCertificate>,
    committed: Option<CommitCertificate>,
    evidence: VecDeque<EquivocationEvidence>,
}

impl<'de> Deserialize<'de> for DepositConsensus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let unchecked = UncheckedDepositConsensus::deserialize(deserializer)?;
        let state = Self {
            state_version: unchecked.state_version,
            context: unchecked.context,
            local_party: unchecked.local_party,
            started: unchecked.started,
            view: unchecked.view,
            candidate: unchecked.candidate,
            view_certificate: unchecked.view_certificate,
            proposal: unchecked.proposal,
            prevotes: unchecked.prevotes,
            precommits: unchecked.precommits,
            next_view_changes: unchecked.next_view_changes,
            locked: unchecked.locked,
            highest_prepared: unchecked.highest_prepared,
            committed: unchecked.committed,
            evidence: unchecked.evidence,
        };
        state.validate_restored().map_err(D::Error::custom)?;
        Ok(state)
    }
}

impl DepositConsensus {
    pub fn new(context: ConsensusContext, local_party: PartyId) -> Result<Self, ConsensusError> {
        context.validate()?;
        context
            .committee
            .member(local_party)
            .map_err(|_| ConsensusError::UnknownVoter(local_party))?;
        Ok(Self {
            state_version: CONSENSUS_STATE_VERSION,
            context,
            local_party,
            started: false,
            view: 0,
            candidate: None,
            view_certificate: None,
            proposal: None,
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            next_view_changes: BTreeMap::new(),
            locked: None,
            highest_prepared: None,
            committed: None,
            evidence: VecDeque::new(),
        })
    }

    #[must_use]
    pub fn context(&self) -> &ConsensusContext {
        &self.context
    }

    #[must_use]
    pub const fn local_party(&self) -> PartyId {
        self.local_party
    }

    /// Whether this durable lane has accepted its local candidate and begun emitting consensus
    /// traffic. Hosts use this to enforce a persisted pre-proposal acceptance gate.
    #[must_use]
    pub const fn started(&self) -> bool {
        self.started
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub fn leader(&self) -> PartyId {
        self.context.leader(self.view)
    }

    #[must_use]
    pub fn locked(&self) -> Option<&PrepareCertificate> {
        self.locked.as_ref()
    }

    #[must_use]
    pub fn highest_prepared(&self) -> Option<&PrepareCertificate> {
        self.highest_prepared.as_ref()
    }

    #[must_use]
    pub fn commit(&self) -> Option<&CommitCertificate> {
        self.committed.as_ref()
    }

    #[must_use]
    pub fn evidence(&self) -> &VecDeque<EquivocationEvidence> {
        &self.evidence
    }

    /// Re-apply the application's semantic predicate after restoring a structurally and
    /// cryptographically validated snapshot. Serde cannot persist executable validation policy;
    /// callers must run this before resuming a reducer loaded from durable storage.
    pub fn validate_application_values<F>(
        &self,
        mut validate_value: F,
    ) -> Result<(), ConsensusError>
    where
        F: FnMut(&ConsensusValue) -> bool,
    {
        let mut seen = BTreeSet::new();
        let mut check = |value: &ConsensusValue| {
            if seen.insert(value.digest()) && !validate_value(value) {
                Err(ConsensusError::InvalidApplicationValue)
            } else {
                Ok(())
            }
        };
        if let Some(candidate) = &self.candidate {
            check(candidate)?;
        }
        if let Some(proposal) = self.current_proposal()? {
            check(&proposal.value)?;
            if let Some(proof) = &proposal.proof_of_lock {
                check(proof.value())?;
            }
            if let Some(certificate) = &proposal.view_change {
                visit_view_certificate_values(&self.context, certificate, &mut check)?;
            }
        }
        for certificate in [&self.locked, &self.highest_prepared].into_iter().flatten() {
            check(certificate.value())?;
        }
        if let Some(certificate) = &self.committed {
            check(certificate.value())?;
        }
        if let Some(certificate) = &self.view_certificate {
            visit_view_certificate_values(&self.context, certificate, &mut check)?;
        }
        for envelope in self.next_view_changes.values() {
            let message = decode_signed_message(&self.context, envelope)?;
            let ConsensusMessageBody::ViewChange(change) = message.body else {
                return Err(ConsensusError::InvalidPersistedState(
                    "stored view change has the wrong phase",
                ));
            };
            if let Some(prepared) = change.highest_prepared {
                check(prepared.value())?;
            }
        }
        Ok(())
    }

    /// Start this height with a locally valid candidate.  Only the current leader proposes it.
    pub fn start(
        &mut self,
        identity: &Identity,
        candidate: ConsensusValue,
    ) -> Result<ConsensusStep, ConsensusError> {
        if self.started {
            return Err(ConsensusError::AlreadyStarted);
        }
        self.ensure_identity(identity)?;
        candidate.validate()?;
        self.started = true;
        self.candidate = Some(candidate);
        let mut step = ConsensusStep { changed: true, ..ConsensusStep::default() };
        self.drive(identity, &mut step)?;
        self.check_outbound(&step)?;
        Ok(step)
    }

    /// Explicitly request the next view.  The reducer never invokes this from a clock.
    pub fn request_view_change(
        &mut self,
        identity: &Identity,
    ) -> Result<ConsensusStep, ConsensusError> {
        self.ensure_live()?;
        self.ensure_identity(identity)?;
        let target_view = self.view.checked_add(1).ok_or(ConsensusError::ViewExhausted)?;
        if target_view > MAX_CONSENSUS_VIEW {
            return Err(ConsensusError::ViewExhausted);
        }
        if self.next_view_changes.contains_key(&self.local_party) {
            return Ok(ConsensusStep { duplicate: true, ..ConsensusStep::default() });
        }
        let change = ViewChange {
            from_view: self.view,
            target_view,
            highest_prepared: self.highest_prepared.clone(),
        };
        let envelope = sign_consensus_message(
            &self.context,
            identity,
            ConsensusMessageBody::ViewChange(change),
        )?;
        self.next_view_changes.insert(self.local_party, envelope.clone());
        let mut step =
            ConsensusStep { broadcast: vec![envelope], changed: true, ..ConsensusStep::default() };
        self.maybe_enter_next_view(identity, &mut step)?;
        self.check_outbound(&step)?;
        Ok(step)
    }

    /// Authenticate and reduce a message after the caller has independently established that all
    /// canonical values are application-valid. Prefer [`Self::handle_with_value_validator`] at
    /// untrusted ingress.
    pub fn handle_structurally_valid(
        &mut self,
        identity: &Identity,
        envelope: SignedEnvelope,
    ) -> Result<ConsensusStep, ConsensusError> {
        self.handle_with_value_validator(identity, envelope, |_| true)
    }

    /// Authenticate and reduce a portable message with an application validity predicate.
    pub fn handle_with_value_validator<F>(
        &mut self,
        identity: &Identity,
        envelope: SignedEnvelope,
        mut validate_value: F,
    ) -> Result<ConsensusStep, ConsensusError>
    where
        F: FnMut(&ConsensusValue) -> bool,
    {
        self.ensure_live()?;
        self.ensure_identity(identity)?;
        let mut step = ConsensusStep::default();
        // `proposal` is private durable state and can only be installed after authenticating the
        // envelope, fully validating its nested certificates, and applying the application
        // predicate. Deserialization re-establishes the same structural/cryptographic invariant;
        // callers re-establish the application invariant with `validate_application_values`.
        // Therefore an exact byte-for-byte replay can skip that expensive work. Equality is
        // deliberately against the complete envelope: a different signature, payload, slot, or
        // sender still takes the normal path below, where proposal equivocation is detected.
        if self.proposal.as_ref() == Some(&envelope) {
            step.duplicate = true;
        } else {
            let message = decode_signed_message(&self.context, &envelope)?;
            let sender = envelope.from;
            match message.body {
                ConsensusMessageBody::Proposal(proposal) => {
                    self.handle_proposal(
                        sender,
                        envelope,
                        proposal,
                        &mut validate_value,
                        identity,
                        &mut step,
                    )?;
                }
                ConsensusMessageBody::Prevote(vote) => {
                    self.handle_vote(sender, envelope, vote, MessageKind::Prevote, &mut step)?;
                }
                ConsensusMessageBody::Precommit(vote) => {
                    self.handle_vote(sender, envelope, vote, MessageKind::Precommit, &mut step)?;
                }
                ConsensusMessageBody::ViewChange(change) => {
                    self.handle_view_change(
                        sender,
                        envelope,
                        change,
                        &mut validate_value,
                        identity,
                        &mut step,
                    )?;
                }
            }
        }
        if self.committed.is_none() {
            self.drive(identity, &mut step)?;
        }
        self.check_outbound(&step)?;
        Ok(step)
    }

    /// Trusted-ingress convenience wrapper for a structurally valid view certificate. Prefer
    /// [`Self::handle_view_certificate_with_validator`] at untrusted ingress.
    pub fn handle_view_certificate_structurally_valid(
        &mut self,
        identity: &Identity,
        certificate: ViewChangeCertificate,
    ) -> Result<ConsensusStep, ConsensusError> {
        self.handle_view_certificate_with_validator(identity, certificate, |_| true)
    }

    /// Adopt and re-gossip a portable view certificate after validating every application value
    /// carried by its signed view-change witnesses.
    pub fn handle_view_certificate_with_validator<F>(
        &mut self,
        identity: &Identity,
        certificate: ViewChangeCertificate,
        mut validate_value: F,
    ) -> Result<ConsensusStep, ConsensusError>
    where
        F: FnMut(&ConsensusValue) -> bool,
    {
        self.ensure_live()?;
        self.ensure_identity(identity)?;
        // Exact equality with the current durable certificate is a bounded replay check against
        // an object which was fully verified when installed (and again when restored). An
        // alternate witness subset or any changed nested envelope is not equal and must verify.
        if self.view_certificate.as_ref() == Some(&certificate) {
            return Ok(ConsensusStep { duplicate: true, ..ConsensusStep::default() });
        }
        certificate.verify(&self.context)?;
        if certificate.target_view <= self.view {
            return Err(ConsensusError::StaleView {
                message: certificate.target_view,
                current: self.view,
            });
        }
        validate_view_certificate_application_values(
            &self.context,
            &certificate,
            &mut validate_value,
        )?;
        let mut step = ConsensusStep::default();
        self.enter_view(certificate, identity, &mut step, true)?;
        self.check_outbound(&step)?;
        Ok(step)
    }

    /// Adopt a terminal certificate whose value the caller already established as
    /// application-valid. Prefer [`Self::handle_commit_certificate_with_validator`] at ingress.
    pub fn handle_commit_certificate_structurally_valid(
        &mut self,
        certificate: CommitCertificate,
    ) -> Result<ConsensusStep, ConsensusError> {
        self.handle_commit_certificate_with_validator(certificate, |_| true)
    }

    /// Adopt a portable terminal certificate after applying the local application predicate.
    pub fn handle_commit_certificate_with_validator<F>(
        &mut self,
        certificate: CommitCertificate,
        mut validate_value: F,
    ) -> Result<ConsensusStep, ConsensusError>
    where
        F: FnMut(&ConsensusValue) -> bool,
    {
        // Only the exact installed certificate takes this path. Equivalent decisions carrying a
        // different quorum subset still verify below, and conflicting decisions still execute
        // the quorum-intersection/equivocation checks.
        if self.committed.as_ref() == Some(&certificate) {
            return Ok(ConsensusStep { duplicate: true, ..ConsensusStep::default() });
        }
        certificate.verify(&self.context)?;
        if let Some(existing) = &self.committed {
            if existing.value.digest() == certificate.value.digest() {
                return Ok(ConsensusStep { duplicate: true, ..ConsensusStep::default() });
            }
            // This verifies both certificates and proves their intersection exceeds `f`.
            existing.conflicting_signers(&certificate, &self.context)?;
            return Err(ConsensusError::ConflictingQuorums);
        }
        if !validate_value(certificate.value()) {
            return Err(ConsensusError::InvalidApplicationValue);
        }
        // A terminal quorum is sufficient to initialize a lagging/restarted reducer that never
        // observed the request or proposal. Do not call `start`: doing so could emit a stale
        // view-zero proposal before the terminal certificate is installed.
        if !self.started {
            self.started = true;
            self.candidate = Some(certificate.value.clone());
        }
        self.committed = Some(certificate.clone());
        Ok(ConsensusStep {
            relay_commit_certificate: Some(certificate.clone()),
            commit: Some(certificate),
            changed: true,
            ..ConsensusStep::default()
        })
    }

    fn handle_proposal(
        &mut self,
        sender: PartyId,
        envelope: SignedEnvelope,
        proposal: Proposal,
        validate_value: &mut dyn FnMut(&ConsensusValue) -> bool,
        identity: &Identity,
        step: &mut ConsensusStep,
    ) -> Result<(), ConsensusError> {
        proposal.value.validate()?;
        let future_certificate = if proposal.view > self.view {
            let certificate = proposal.view_change.as_ref().ok_or(
                ConsensusError::InvalidCertificate("future proposal lacks view certificate"),
            )?;
            self.validate_proposal(&proposal, sender)?;
            Some(certificate.clone())
        } else {
            self.require_current(proposal.view)?;
            self.validate_proposal(&proposal, sender)?;
            None
        };

        if future_certificate.is_none()
            && let Some(existing) = &self.proposal
        {
            let existing_message = decode_signed_message(&self.context, existing)?;
            let ConsensusMessageBody::Proposal(existing_proposal) = existing_message.body else {
                return Err(ConsensusError::InvalidPersistedState("invalid proposal slot"));
            };
            if existing_proposal == proposal {
                step.duplicate = true;
                return Ok(());
            }
            self.record_evidence(
                EquivocationEvidence {
                    view: proposal.view,
                    offender: sender,
                    kind: EvidenceKind::Proposal,
                    first: existing.clone(),
                    conflicting: envelope,
                },
                step,
            );
            return Ok(());
        }
        validate_message_application_values(
            &self.context,
            &ConsensusMessageBody::Proposal(proposal.clone()),
            validate_value,
        )?;
        if let Some(certificate) = future_certificate {
            self.enter_view(certificate, identity, step, false)?;
        }

        if let Some(proof) = &proposal.proof_of_lock {
            self.update_highest_prepared(proof.clone())?;
        }
        self.proposal = Some(envelope);
        step.changed = true;
        Ok(())
    }

    fn validate_proposal(
        &self,
        proposal: &Proposal,
        sender: PartyId,
    ) -> Result<(), ConsensusError> {
        validate_proposal_structure(&self.context, proposal, sender)
    }

    fn handle_vote(
        &mut self,
        sender: PartyId,
        envelope: SignedEnvelope,
        vote: Vote,
        kind: MessageKind,
        step: &mut ConsensusStep,
    ) -> Result<(), ConsensusError> {
        self.require_current(vote.view)?;
        let target = match kind {
            MessageKind::Prevote => &mut self.prevotes,
            MessageKind::Precommit => &mut self.precommits,
            _ => unreachable!("only vote kinds reach handle_vote"),
        };
        if let Some(existing) = target.get(&sender) {
            let existing_message = decode_signed_message(&self.context, existing)?;
            let existing_vote = match (kind, existing_message.body) {
                (MessageKind::Prevote, ConsensusMessageBody::Prevote(vote))
                | (MessageKind::Precommit, ConsensusMessageBody::Precommit(vote)) => vote,
                _ => {
                    return Err(ConsensusError::InvalidPersistedState(
                        "stored vote has the wrong phase",
                    ));
                }
            };
            if existing_vote == vote {
                step.duplicate = true;
                return Ok(());
            }
            let evidence = EquivocationEvidence {
                view: vote.view,
                offender: sender,
                kind: kind.evidence(),
                first: existing.clone(),
                conflicting: envelope,
            };
            self.record_evidence(evidence, step);
            return Ok(());
        }
        target.insert(sender, envelope);
        step.changed = true;
        Ok(())
    }

    fn handle_view_change(
        &mut self,
        sender: PartyId,
        envelope: SignedEnvelope,
        change: ViewChange,
        validate_value: &mut dyn FnMut(&ConsensusValue) -> bool,
        identity: &Identity,
        step: &mut ConsensusStep,
    ) -> Result<(), ConsensusError> {
        let expected = self.view.checked_add(1).ok_or(ConsensusError::ViewExhausted)?;
        if change.target_view < expected {
            return Err(ConsensusError::StaleView {
                message: change.target_view,
                current: self.view,
            });
        }
        if change.target_view > expected {
            return Err(ConsensusError::FutureView {
                message: change.target_view,
                current: self.view,
            });
        }
        validate_view_change(&self.context, &change)?;
        if let Some(existing) = self.next_view_changes.get(&sender) {
            let existing_message = decode_signed_message(&self.context, existing)?;
            let ConsensusMessageBody::ViewChange(existing_change) = existing_message.body else {
                return Err(ConsensusError::InvalidPersistedState(
                    "stored view change has the wrong phase",
                ));
            };
            if existing_change == change {
                step.duplicate = true;
                return Ok(());
            }
            self.record_evidence(
                EquivocationEvidence {
                    view: change.target_view,
                    offender: sender,
                    kind: EvidenceKind::ViewChange,
                    first: existing.clone(),
                    conflicting: envelope,
                },
                step,
            );
            return Ok(());
        }
        validate_message_application_values(
            &self.context,
            &ConsensusMessageBody::ViewChange(change.clone()),
            validate_value,
        )?;
        self.next_view_changes.insert(sender, envelope);
        step.changed = true;
        self.maybe_enter_next_view(identity, step)
    }

    fn maybe_enter_next_view(
        &mut self,
        identity: &Identity,
        step: &mut ConsensusStep,
    ) -> Result<(), ConsensusError> {
        if self.next_view_changes.len() < self.context.quorum() {
            return Ok(());
        }
        let target = self.view.checked_add(1).ok_or(ConsensusError::ViewExhausted)?;
        let witnesses =
            self.next_view_changes.values().take(self.context.quorum()).cloned().collect();
        let certificate = ViewChangeCertificate::from_witnesses(&self.context, target, witnesses)?;
        self.enter_view(certificate, identity, step, true)
    }

    fn enter_view(
        &mut self,
        certificate: ViewChangeCertificate,
        identity: &Identity,
        step: &mut ConsensusStep,
        drive: bool,
    ) -> Result<(), ConsensusError> {
        certificate.verify(&self.context)?;
        if certificate.target_view <= self.view {
            return Err(ConsensusError::StaleView {
                message: certificate.target_view,
                current: self.view,
            });
        }
        if let Some(highest) = certificate.highest_prepared(&self.context)? {
            self.update_highest_prepared(highest)?;
        }
        self.view = certificate.target_view;
        self.view_certificate = Some(certificate.clone());
        self.proposal = None;
        self.prevotes.clear();
        self.precommits.clear();
        self.next_view_changes.clear();
        step.entered_view = Some(self.view);
        step.relay_view_certificate = Some(certificate);
        step.changed = true;
        if drive {
            self.drive(identity, step)?;
        }
        Ok(())
    }

    fn drive(
        &mut self,
        identity: &Identity,
        step: &mut ConsensusStep,
    ) -> Result<(), ConsensusError> {
        loop {
            let mut progressed = false;
            // A party that has asked to leave a view must not help prepare a new value there.
            // It may still recognize an already-formed commit certificate below.
            let local_changing_view = self.next_view_changes.contains_key(&self.local_party);
            if !local_changing_view && self.proposal.is_none() && self.leader() == self.local_party
            {
                // A replacement leader is constrained by the exact public view certificate. A
                // stronger private lock omitted from that certificate remains a local voting
                // restriction; it cannot be added to the proposal as an unsupported proof.
                let proof_of_lock = self
                    .view_certificate
                    .as_ref()
                    .map(|certificate| certificate.highest_prepared(&self.context))
                    .transpose()?
                    .flatten();
                let value = proof_of_lock
                    .as_ref()
                    .map(|certificate| certificate.value.clone())
                    .or_else(|| self.candidate.clone())
                    .ok_or(ConsensusError::InvalidPersistedState(
                        "started state lacks candidate",
                    ))?;
                let proposal = Proposal {
                    view: self.view,
                    value,
                    proof_of_lock,
                    view_change: self.view_certificate.clone(),
                };
                self.validate_proposal(&proposal, self.local_party)?;
                let envelope = sign_consensus_message(
                    &self.context,
                    identity,
                    ConsensusMessageBody::Proposal(proposal),
                )?;
                self.proposal = Some(envelope.clone());
                step.broadcast.push(envelope);
                step.changed = true;
                progressed = true;
            }

            if !local_changing_view
                && !self.prevotes.contains_key(&self.local_party)
                && let Some(proposal) = self.current_proposal()?
                && self.can_prevote(&proposal)
            {
                let vote = Vote { view: self.view, value: proposal.value.digest() };
                let envelope = sign_consensus_message(
                    &self.context,
                    identity,
                    ConsensusMessageBody::Prevote(vote),
                )?;
                self.prevotes.insert(self.local_party, envelope.clone());
                step.broadcast.push(envelope);
                step.changed = true;
                progressed = true;
            }

            if !local_changing_view
                && !self.precommits.contains_key(&self.local_party)
                && let Some((digest, witnesses)) =
                    quorum_votes(&self.context, &self.prevotes, MessageKind::Prevote)?
                && let Some(value) = self.value_for_digest(digest)?
            {
                let certificate =
                    PrepareCertificate::from_witnesses(&self.context, self.view, value, witnesses)?;
                self.update_highest_prepared(certificate.clone())?;
                self.locked = Some(certificate);
                let vote = Vote { view: self.view, value: digest };
                let envelope = sign_consensus_message(
                    &self.context,
                    identity,
                    ConsensusMessageBody::Precommit(vote),
                )?;
                self.precommits.insert(self.local_party, envelope.clone());
                step.broadcast.push(envelope);
                step.changed = true;
                progressed = true;
            }

            if self.committed.is_none()
                && let Some((digest, witnesses)) =
                    quorum_votes(&self.context, &self.precommits, MessageKind::Precommit)?
                && let Some(value) = self.value_for_digest(digest)?
            {
                let certificate =
                    CommitCertificate::from_witnesses(&self.context, self.view, value, witnesses)?;
                self.committed = Some(certificate.clone());
                step.relay_commit_certificate = Some(certificate.clone());
                step.commit = Some(certificate);
                step.changed = true;
                progressed = true;
            }

            if !progressed || self.committed.is_some() {
                return Ok(());
            }
        }
    }

    fn current_proposal(&self) -> Result<Option<Proposal>, ConsensusError> {
        let Some(envelope) = &self.proposal else {
            return Ok(None);
        };
        let message = decode_signed_message(&self.context, envelope)?;
        let ConsensusMessageBody::Proposal(proposal) = message.body else {
            return Err(ConsensusError::InvalidPersistedState("proposal slot is not a proposal"));
        };
        Ok(Some(proposal))
    }

    fn value_for_digest(
        &self,
        digest: ConsensusValueDigest,
    ) -> Result<Option<ConsensusValue>, ConsensusError> {
        if let Some(proposal) = self.current_proposal()?
            && proposal.value.digest() == digest
        {
            return Ok(Some(proposal.value));
        }
        for certificate in [&self.highest_prepared, &self.locked].into_iter().flatten() {
            if certificate.value.digest() == digest {
                return Ok(Some(certificate.value.clone()));
            }
        }
        Ok(None)
    }

    fn can_prevote(&self, proposal: &Proposal) -> bool {
        let Some(locked) = &self.locked else {
            return true;
        };
        if locked.value.digest() == proposal.value.digest() {
            return true;
        }
        proposal.proof_of_lock.as_ref().is_some_and(|proof| proof.view > locked.view)
    }

    fn update_highest_prepared(
        &mut self,
        candidate: PrepareCertificate,
    ) -> Result<(), ConsensusError> {
        candidate.verify(&self.context)?;
        match &self.highest_prepared {
            None => self.highest_prepared = Some(candidate),
            Some(current) if candidate.view > current.view => {
                self.highest_prepared = Some(candidate);
            }
            Some(current) if candidate.view == current.view => {
                if candidate.value.digest() != current.value.digest() {
                    return Err(ConsensusError::ConflictingQuorums);
                }
                if candidate.canonical_digest() < current.canonical_digest() {
                    self.highest_prepared = Some(candidate);
                }
            }
            Some(_) => {}
        }
        Ok(())
    }

    fn ensure_identity(&self, identity: &Identity) -> Result<(), ConsensusError> {
        if identity.party() != self.local_party {
            return Err(ConsensusError::WrongLocalIdentity);
        }
        let member = self.context.committee.member(self.local_party)?;
        if member.signing_key != identity.signing_public_key() {
            return Err(ConsensusError::WrongLocalIdentity);
        }
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), ConsensusError> {
        if !self.started {
            Err(ConsensusError::NotStarted)
        } else if self.committed.is_some() {
            Err(ConsensusError::AlreadyCommitted)
        } else {
            Ok(())
        }
    }

    fn require_current(&self, message_view: u64) -> Result<(), ConsensusError> {
        match message_view.cmp(&self.view) {
            std::cmp::Ordering::Less => {
                Err(ConsensusError::StaleView { message: message_view, current: self.view })
            }
            std::cmp::Ordering::Greater => {
                Err(ConsensusError::FutureView { message: message_view, current: self.view })
            }
            std::cmp::Ordering::Equal => Ok(()),
        }
    }

    fn record_evidence(&mut self, evidence: EquivocationEvidence, step: &mut ConsensusStep) {
        if self.evidence.iter().any(|existing| {
            existing.view == evidence.view
                && existing.offender == evidence.offender
                && existing.kind == evidence.kind
        }) {
            step.duplicate = true;
            return;
        }
        if self.evidence.len() == MAX_CONSENSUS_EVIDENCE {
            self.evidence.pop_front();
        }
        self.evidence.push_back(evidence.clone());
        step.evidence.push(evidence);
        step.changed = true;
    }

    fn check_outbound(&self, step: &ConsensusStep) -> Result<(), ConsensusError> {
        if step.broadcast.len() > MAX_CONSENSUS_OUTBOUND_PER_STEP {
            Err(ConsensusError::OutboundLimit)
        } else {
            Ok(())
        }
    }

    fn validate_restored(&self) -> Result<(), ConsensusError> {
        if self.state_version != CONSENSUS_STATE_VERSION {
            return Err(ConsensusError::InvalidPersistedState(
                "unsupported reducer snapshot version",
            ));
        }
        self.context.validate()?;
        self.context
            .committee
            .member(self.local_party)
            .map_err(|_| ConsensusError::UnknownVoter(self.local_party))?;
        if self.view > MAX_CONSENSUS_VIEW
            || self.prevotes.len() > usize::from(self.context.committee.n())
            || self.precommits.len() > usize::from(self.context.committee.n())
            || self.next_view_changes.len() > usize::from(self.context.committee.n())
            || self.evidence.len() > MAX_CONSENSUS_EVIDENCE
        {
            return Err(ConsensusError::InvalidPersistedState("resource bound exceeded"));
        }
        if self.started != self.candidate.is_some() {
            return Err(ConsensusError::InvalidPersistedState("candidate/start mismatch"));
        }
        if !self.started
            && (self.view != 0
                || self.view_certificate.is_some()
                || self.proposal.is_some()
                || !self.prevotes.is_empty()
                || !self.precommits.is_empty()
                || !self.next_view_changes.is_empty()
                || self.locked.is_some()
                || self.highest_prepared.is_some()
                || self.committed.is_some()
                || !self.evidence.is_empty())
        {
            return Err(ConsensusError::InvalidPersistedState(
                "unstarted reducer contains protocol state",
            ));
        }
        if let Some(candidate) = &self.candidate {
            candidate.validate()?;
        }
        match (&self.view_certificate, self.view) {
            (None, 0) => {}
            (Some(certificate), view) if view > 0 => {
                certificate.verify(&self.context)?;
                if certificate.target_view != view {
                    return Err(ConsensusError::InvalidPersistedState(
                        "view certificate targets another view",
                    ));
                }
            }
            _ => {
                return Err(ConsensusError::InvalidPersistedState(
                    "nonzero view lacks its certificate",
                ));
            }
        }
        if let Some(envelope) = &self.proposal {
            let message = decode_signed_message(&self.context, envelope)?;
            let ConsensusMessageBody::Proposal(proposal) = message.body else {
                return Err(ConsensusError::InvalidPersistedState("invalid proposal slot"));
            };
            if proposal.view != self.view {
                return Err(ConsensusError::InvalidPersistedState("proposal is from another view"));
            }
            self.validate_proposal(&proposal, envelope.from)?;
        }
        validate_vote_map(&self.context, self.view, MessageKind::Prevote, &self.prevotes)?;
        validate_vote_map(&self.context, self.view, MessageKind::Precommit, &self.precommits)?;
        if !self.next_view_changes.is_empty() {
            let next = self.view.checked_add(1).ok_or(ConsensusError::ViewExhausted)?;
            for (sender, envelope) in &self.next_view_changes {
                if *sender != envelope.from {
                    return Err(ConsensusError::InvalidPersistedState(
                        "view-change map key mismatch",
                    ));
                }
                let message = decode_signed_message(&self.context, envelope)?;
                let ConsensusMessageBody::ViewChange(change) = message.body else {
                    return Err(ConsensusError::InvalidPersistedState("invalid view-change slot"));
                };
                validate_view_change(&self.context, &change)?;
                if change.target_view != next {
                    return Err(ConsensusError::InvalidPersistedState(
                        "stored view change targets another view",
                    ));
                }
            }
        }
        if let Some(locked) = &self.locked {
            locked.verify(&self.context)?;
            if locked.view > self.view {
                return Err(ConsensusError::InvalidPersistedState("future lock"));
            }
        }
        if let Some(highest) = &self.highest_prepared {
            highest.verify(&self.context)?;
            if highest.view > self.view
                || self.locked.as_ref().is_some_and(|locked| {
                    locked.view > highest.view
                        || (locked.view == highest.view
                            && locked.value.digest() != highest.value.digest())
                })
            {
                return Err(ConsensusError::InvalidPersistedState("invalid highest prepare"));
            }
        } else if self.locked.is_some() {
            return Err(ConsensusError::InvalidPersistedState("lock lacks highest prepare"));
        }
        if let Some(view_certificate) = &self.view_certificate
            && let Some(view_highest) = view_certificate.highest_prepared(&self.context)?
        {
            let state_highest = self.highest_prepared.as_ref().ok_or(
                ConsensusError::InvalidPersistedState("view proof omitted from highest prepare"),
            )?;
            if state_highest.view < view_highest.view
                || (state_highest.view == view_highest.view
                    && state_highest.value.digest() != view_highest.value.digest())
            {
                return Err(ConsensusError::InvalidPersistedState(
                    "highest prepare contradicts current view proof",
                ));
            }
        }
        let local_precommit = self.precommits.get(&self.local_party);
        match (local_precommit, self.locked.as_ref()) {
            (Some(envelope), Some(locked)) => {
                let message = decode_signed_message(&self.context, envelope)?;
                let ConsensusMessageBody::Precommit(vote) = message.body else {
                    return Err(ConsensusError::InvalidPersistedState(
                        "local precommit slot has the wrong phase",
                    ));
                };
                if locked.view != self.view
                    || vote.view != self.view
                    || vote.value != locked.value.digest()
                {
                    return Err(ConsensusError::InvalidPersistedState(
                        "local precommit is not backed by its lock certificate",
                    ));
                }
            }
            (Some(_), None) => {
                return Err(ConsensusError::InvalidPersistedState(
                    "local precommit lacks a lock certificate",
                ));
            }
            (None, Some(locked)) if locked.view == self.view => {
                return Err(ConsensusError::InvalidPersistedState(
                    "current-view lock lacks the local precommit",
                ));
            }
            (None, Some(_) | None) => {}
        }
        if let Some(committed) = &self.committed {
            committed.verify(&self.context)?;
            if !self.started {
                return Err(ConsensusError::InvalidPersistedState("invalid committed state"));
            }
        }
        let mut evidence_slots = BTreeSet::new();
        for evidence in &self.evidence {
            if !evidence_slots.insert((evidence.view, evidence.offender, evidence.kind)) {
                return Err(ConsensusError::InvalidPersistedState(
                    "duplicate equivocation evidence slot",
                ));
            }
            validate_evidence(&self.context, evidence)?;
        }
        Ok(())
    }
}

/// Sign one canonical portable message.  Byzantine test harnesses and integration adapters can use
/// this helper without giving the reducer ownership of long-lived identity material.
pub fn sign_consensus_message(
    context: &ConsensusContext,
    identity: &Identity,
    body: ConsensusMessageBody,
) -> Result<SignedEnvelope, ConsensusError> {
    context.validate()?;
    context.committee.member(identity.party())?;
    validate_message_body(context, &body)?;
    let view = body.view();
    let kind = body.kind();
    let message = ConsensusMessage::new(context, body);
    let payload = postcard::to_allocvec(&message).map_err(|_| ConsensusError::Serialization)?;
    if payload.len() > MAX_CONSENSUS_MESSAGE_BYTES {
        return Err(ConsensusError::MessageTooLarge {
            actual: payload.len(),
            maximum: MAX_CONSENSUS_MESSAGE_BYTES,
        });
    }
    identity
        .sign_envelope(
            &context.committee,
            context.session,
            None,
            wire_sequence(context, view, kind)?,
            payload,
        )
        .map_err(ConsensusError::Identity)
}

/// Decode, authenticate, and slot-check one portable envelope.
///
/// Nested certificates are allocation-bounded but deliberately verified only after the reducer
/// authorizes the sender/view slot, preventing an authenticated non-leader from forcing repeated
/// quorum-signature work. Certificate `verify` methods remain available to standalone consumers.
pub fn decode_consensus_message(
    context: &ConsensusContext,
    envelope: &SignedEnvelope,
) -> Result<ConsensusMessage, ConsensusError> {
    decode_signed_message(context, envelope)
}

fn decode_signed_message(
    context: &ConsensusContext,
    envelope: &SignedEnvelope,
) -> Result<ConsensusMessage, ConsensusError> {
    if envelope.payload.len() > MAX_CONSENSUS_MESSAGE_BYTES {
        return Err(ConsensusError::MessageTooLarge {
            actual: envelope.payload.len(),
            maximum: MAX_CONSENSUS_MESSAGE_BYTES,
        });
    }
    let verifier = context
        .committee
        .members
        .iter()
        .map(|member| member.id)
        .min()
        .ok_or(ConsensusError::InvalidContext("empty committee"))?;
    Identity::verify_envelope(&context.committee, verifier, envelope)?;
    if envelope.to.is_some() {
        return Err(ConsensusError::NonPortableEnvelope);
    }
    let (message, trailing) = postcard::take_from_bytes::<ConsensusMessage>(&envelope.payload)
        .map_err(|_| ConsensusError::Serialization)?;
    if !trailing.is_empty() {
        return Err(ConsensusError::TrailingMessageBytes);
    }
    if message.version != CONSENSUS_VERSION || message.context != context.digest() {
        return Err(ConsensusError::WrongContext);
    }
    validate_message_body_shallow(&message.body)?;
    if envelope.session != context.session
        || envelope.sequence != wire_sequence(context, message.body.view(), message.body.kind())?
    {
        return Err(ConsensusError::WrongEnvelopeSlot);
    }
    Ok(message)
}

fn validate_message_body_shallow(body: &ConsensusMessageBody) -> Result<(), ConsensusError> {
    if body.view() > MAX_CONSENSUS_VIEW {
        return Err(ConsensusError::ViewExhausted);
    }
    match body {
        ConsensusMessageBody::Proposal(proposal) => proposal.value.validate(),
        ConsensusMessageBody::Prevote(vote) | ConsensusMessageBody::Precommit(vote) => {
            if vote.value.0 == [0; 32] { Err(ConsensusError::InvalidValueDigest) } else { Ok(()) }
        }
        ConsensusMessageBody::ViewChange(change) => {
            if change.target_view == 0
                || change.from_view.checked_add(1) != Some(change.target_view)
            {
                Err(ConsensusError::InvalidCertificate(
                    "view change must advance exactly one bounded view",
                ))
            } else {
                Ok(())
            }
        }
    }
}

fn validate_message_body(
    context: &ConsensusContext,
    body: &ConsensusMessageBody,
) -> Result<(), ConsensusError> {
    if body.view() > MAX_CONSENSUS_VIEW {
        return Err(ConsensusError::ViewExhausted);
    }
    match body {
        ConsensusMessageBody::Proposal(proposal) => {
            proposal.value.validate()?;
            if let Some(proof) = &proposal.proof_of_lock {
                proof.verify(context)?;
                if proof.view >= proposal.view {
                    return Err(ConsensusError::InvalidCertificate(
                        "proposal proof does not precede proposal",
                    ));
                }
            }
            if let Some(certificate) = &proposal.view_change {
                certificate.verify(context)?;
            }
        }
        ConsensusMessageBody::Prevote(vote) | ConsensusMessageBody::Precommit(vote) => {
            if vote.value.0 == [0; 32] {
                return Err(ConsensusError::InvalidValueDigest);
            }
        }
        ConsensusMessageBody::ViewChange(change) => validate_view_change(context, change)?,
    }
    Ok(())
}

fn validate_view_change(
    context: &ConsensusContext,
    change: &ViewChange,
) -> Result<(), ConsensusError> {
    if change.target_view == 0
        || change.target_view > MAX_CONSENSUS_VIEW
        || change.from_view.checked_add(1) != Some(change.target_view)
    {
        return Err(ConsensusError::InvalidCertificate(
            "view change must advance exactly one bounded view",
        ));
    }
    if let Some(prepared) = &change.highest_prepared {
        prepared.verify(context)?;
        if prepared.view >= change.target_view {
            return Err(ConsensusError::InvalidCertificate(
                "view change carries a non-prior prepare",
            ));
        }
    }
    Ok(())
}

fn verify_canonical_witness_set(
    context: &ConsensusContext,
    witnesses: &[SignedEnvelope],
) -> Result<(), ConsensusError> {
    if witnesses.len() != context.quorum() {
        return Err(ConsensusError::InvalidCertificate(
            "certificate must contain exactly n-f witnesses",
        ));
    }
    let mut previous = None;
    for witness in witnesses {
        context
            .committee
            .member(witness.from)
            .map_err(|_| ConsensusError::UnknownVoter(witness.from))?;
        if previous.is_some_and(|party| party >= witness.from) {
            return Err(ConsensusError::InvalidCertificate(
                "certificate witnesses are not strictly canonical",
            ));
        }
        previous = Some(witness.from);
    }
    Ok(())
}

fn verify_vote_witnesses(
    context: &ConsensusContext,
    view: u64,
    digest: ConsensusValueDigest,
    kind: MessageKind,
    witnesses: &[SignedEnvelope],
) -> Result<(), ConsensusError> {
    for witness in witnesses {
        let message = decode_signed_message(context, witness)?;
        let vote = match (kind, message.body) {
            (MessageKind::Prevote, ConsensusMessageBody::Prevote(vote))
            | (MessageKind::Precommit, ConsensusMessageBody::Precommit(vote)) => vote,
            _ => {
                return Err(ConsensusError::InvalidCertificate(
                    "certificate contains the wrong witness phase",
                ));
            }
        };
        if vote.view != view || vote.value != digest {
            return Err(ConsensusError::InvalidCertificate(
                "certificate witness votes for another value or view",
            ));
        }
    }
    Ok(())
}

fn validate_vote_map(
    context: &ConsensusContext,
    view: u64,
    kind: MessageKind,
    votes: &BTreeMap<PartyId, SignedEnvelope>,
) -> Result<(), ConsensusError> {
    for (sender, envelope) in votes {
        if *sender != envelope.from {
            return Err(ConsensusError::InvalidPersistedState("vote map key mismatch"));
        }
        let message = decode_signed_message(context, envelope)?;
        let vote = match (kind, message.body) {
            (MessageKind::Prevote, ConsensusMessageBody::Prevote(vote))
            | (MessageKind::Precommit, ConsensusMessageBody::Precommit(vote)) => vote,
            _ => return Err(ConsensusError::InvalidPersistedState("vote map phase mismatch")),
        };
        if vote.view != view {
            return Err(ConsensusError::InvalidPersistedState("vote map view mismatch"));
        }
    }
    Ok(())
}

fn quorum_votes(
    context: &ConsensusContext,
    votes: &BTreeMap<PartyId, SignedEnvelope>,
    kind: MessageKind,
) -> Result<Option<(ConsensusValueDigest, Vec<SignedEnvelope>)>, ConsensusError> {
    let mut grouped = BTreeMap::<ConsensusValueDigest, Vec<SignedEnvelope>>::new();
    for envelope in votes.values() {
        let message = decode_signed_message(context, envelope)?;
        let vote = match (kind, message.body) {
            (MessageKind::Prevote, ConsensusMessageBody::Prevote(vote))
            | (MessageKind::Precommit, ConsensusMessageBody::Precommit(vote)) => vote,
            _ => return Err(ConsensusError::InvalidPersistedState("vote map phase mismatch")),
        };
        grouped.entry(vote.value).or_default().push(envelope.clone());
    }
    let mut quorums = grouped
        .into_iter()
        .filter(|(_, witnesses)| witnesses.len() >= context.quorum())
        .map(|(digest, mut witnesses)| {
            witnesses.sort_unstable_by_key(|witness| witness.from);
            witnesses.truncate(context.quorum());
            (digest, witnesses)
        });
    let first = quorums.next();
    if quorums.next().is_some() {
        return Err(ConsensusError::ConflictingQuorums);
    }
    Ok(first)
}

fn validate_proposal_structure(
    context: &ConsensusContext,
    proposal: &Proposal,
    sender: PartyId,
) -> Result<(), ConsensusError> {
    if proposal.view > MAX_CONSENSUS_VIEW || sender != context.leader(proposal.view) {
        return Err(ConsensusError::WrongLeader);
    }
    proposal.value.validate()?;
    match proposal.view {
        0 => {
            if proposal.proof_of_lock.is_some() || proposal.view_change.is_some() {
                return Err(ConsensusError::InvalidCertificate(
                    "view zero proposal carries view-change proof",
                ));
            }
        }
        _ => {
            let certificate = proposal.view_change.as_ref().ok_or(
                ConsensusError::InvalidCertificate("higher-view proposal lacks certificate"),
            )?;
            certificate.verify(context)?;
            if certificate.target_view != proposal.view {
                return Err(ConsensusError::InvalidCertificate(
                    "proposal view differs from view certificate",
                ));
            }
            let highest = certificate.highest_prepared(context)?;
            if proposal.proof_of_lock != highest {
                return Err(ConsensusError::InvalidCertificate(
                    "proposal proof is not the canonical highest prepared certificate",
                ));
            }
            if highest.as_ref().is_some_and(|proof| proof.value.digest() != proposal.value.digest())
            {
                return Err(ConsensusError::InvalidCertificate(
                    "proposal abandons the highest prepared value",
                ));
            }
        }
    }
    Ok(())
}

fn validate_message_application_values(
    context: &ConsensusContext,
    body: &ConsensusMessageBody,
    validate_value: &mut dyn FnMut(&ConsensusValue) -> bool,
) -> Result<(), ConsensusError> {
    let mut seen = BTreeSet::new();
    let mut check = |value: &ConsensusValue| {
        if seen.insert(value.digest()) && !validate_value(value) {
            Err(ConsensusError::InvalidApplicationValue)
        } else {
            Ok(())
        }
    };
    match body {
        ConsensusMessageBody::Proposal(proposal) => {
            check(&proposal.value)?;
            if let Some(proof) = &proposal.proof_of_lock {
                check(proof.value())?;
            }
            if let Some(certificate) = &proposal.view_change {
                visit_view_certificate_values(context, certificate, &mut check)?;
            }
        }
        ConsensusMessageBody::ViewChange(change) => {
            if let Some(prepared) = &change.highest_prepared {
                check(prepared.value())?;
            }
        }
        ConsensusMessageBody::Prevote(_) | ConsensusMessageBody::Precommit(_) => {}
    }
    Ok(())
}

fn validate_view_certificate_application_values(
    context: &ConsensusContext,
    certificate: &ViewChangeCertificate,
    validate_value: &mut dyn FnMut(&ConsensusValue) -> bool,
) -> Result<(), ConsensusError> {
    let mut seen = BTreeSet::new();
    let mut check = |value: &ConsensusValue| {
        if seen.insert(value.digest()) && !validate_value(value) {
            Err(ConsensusError::InvalidApplicationValue)
        } else {
            Ok(())
        }
    };
    visit_view_certificate_values(context, certificate, &mut check)
}

fn visit_view_certificate_values(
    context: &ConsensusContext,
    certificate: &ViewChangeCertificate,
    check: &mut dyn FnMut(&ConsensusValue) -> Result<(), ConsensusError>,
) -> Result<(), ConsensusError> {
    for witness in certificate.witnesses() {
        let message = decode_signed_message(context, witness)?;
        let ConsensusMessageBody::ViewChange(change) = message.body else {
            return Err(ConsensusError::InvalidCertificate(
                "view certificate contains a non-view-change witness",
            ));
        };
        if let Some(prepared) = change.highest_prepared {
            check(prepared.value())?;
        }
    }
    Ok(())
}

fn validate_evidence(
    context: &ConsensusContext,
    evidence: &EquivocationEvidence,
) -> Result<(), ConsensusError> {
    let first = decode_signed_message(context, &evidence.first)?;
    let conflicting = decode_signed_message(context, &evidence.conflicting)?;
    if evidence.first.from != evidence.offender
        || evidence.conflicting.from != evidence.offender
        || evidence.first == evidence.conflicting
        || first.body == conflicting.body
        || first.body.kind().evidence() != evidence.kind
        || conflicting.body.kind().evidence() != evidence.kind
        || first.body.view() != evidence.view
        || conflicting.body.view() != evidence.view
    {
        return Err(ConsensusError::InvalidPersistedState("invalid equivocation evidence"));
    }
    if evidence.kind == EvidenceKind::Proposal && evidence.offender != context.leader(evidence.view)
    {
        return Err(ConsensusError::InvalidPersistedState(
            "proposal evidence does not name the view leader",
        ));
    }
    if evidence.kind == EvidenceKind::Proposal {
        let ConsensusMessageBody::Proposal(first_proposal) = &first.body else {
            return Err(ConsensusError::InvalidPersistedState(
                "proposal evidence has the wrong phase",
            ));
        };
        let ConsensusMessageBody::Proposal(conflicting_proposal) = &conflicting.body else {
            return Err(ConsensusError::InvalidPersistedState(
                "proposal evidence has the wrong phase",
            ));
        };
        validate_proposal_structure(context, first_proposal, evidence.offender)?;
        validate_proposal_structure(context, conflicting_proposal, evidence.offender)?;
    }
    if evidence.kind == EvidenceKind::ViewChange {
        let ConsensusMessageBody::ViewChange(first_change) = &first.body else {
            return Err(ConsensusError::InvalidPersistedState(
                "view-change evidence has the wrong phase",
            ));
        };
        let ConsensusMessageBody::ViewChange(conflicting_change) = &conflicting.body else {
            return Err(ConsensusError::InvalidPersistedState(
                "view-change evidence has the wrong phase",
            ));
        };
        validate_view_change(context, first_change)?;
        validate_view_change(context, conflicting_change)?;
    }
    Ok(())
}

fn wire_sequence(
    context: &ConsensusContext,
    view: u64,
    kind: MessageKind,
) -> Result<u64, ConsensusError> {
    if view > MAX_CONSENSUS_VIEW {
        return Err(ConsensusError::ViewExhausted);
    }
    Ok((context.sequence << WIRE_SEQUENCE_LOW_BITS)
        | (view << WIRE_SEQUENCE_KIND_BITS)
        | kind as u64)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::committee::Member;

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0x58; 32];
        secret[1..9].copy_from_slice(&epoch.to_le_bytes());
        secret[9..11].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    fn fixtures() -> (ConsensusContext, Vec<Identity>) {
        let identities = (1_u16..=4)
            .map(|party| {
                let party = PartyId(party);
                let signing_seed = [party.0 as u8; 32];
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
        let context = ConsensusContext::new(
            ConsensusBinding {
                domain: [1; 32],
                application: b"deposit-ledger".to_vec(),
                wallet: [2; 32],
                network: [3; 32],
                registry: [4; 32],
                activation: [5; 32],
            },
            SessionId([6; 32]),
            committee,
            1,
            0,
            1,
            [0; 32],
        )
        .unwrap();
        (context, identities)
    }

    fn value(byte: u8) -> ConsensusValue {
        ConsensusValue::new(vec![byte; 16]).unwrap()
    }

    fn vote_envelopes(
        context: &ConsensusContext,
        identities: &[Identity],
        kind: MessageKind,
        view: u64,
        value: &ConsensusValue,
        signers: &[usize],
    ) -> Vec<SignedEnvelope> {
        signers
            .iter()
            .map(|index| {
                let vote = Vote { view, value: value.digest() };
                let body = match kind {
                    MessageKind::Prevote => ConsensusMessageBody::Prevote(vote),
                    MessageKind::Precommit => ConsensusMessageBody::Precommit(vote),
                    _ => unreachable!(),
                };
                sign_consensus_message(context, &identities[*index], body).unwrap()
            })
            .collect()
    }

    #[test]
    fn honest_portable_broadcasts_commit_one_value() {
        let (context, identities) = fixtures();
        let candidate = value(42);
        let mut nodes = identities
            .iter()
            .map(|identity| DepositConsensus::new(context.clone(), identity.party()).unwrap())
            .collect::<Vec<_>>();
        let mut network = VecDeque::new();
        for (index, node) in nodes.iter_mut().enumerate() {
            network.extend(node.start(&identities[index], candidate.clone()).unwrap().broadcast);
        }

        let mut deliveries = 0;
        while let Some(envelope) = network.pop_front() {
            deliveries += 1;
            assert!(deliveries < 256, "consensus broadcast did not quiesce");
            for (index, node) in nodes.iter_mut().enumerate() {
                if node.local_party() == envelope.from || node.commit().is_some() {
                    continue;
                }
                let step =
                    node.handle_structurally_valid(&identities[index], envelope.clone()).unwrap();
                network.extend(step.broadcast);
            }
        }

        for node in &nodes {
            let commit = node.commit().expect("every honest node commits");
            commit.verify(&context).unwrap();
            assert_eq!(commit.value(), &candidate);
        }
    }

    #[test]
    fn equivocal_leader_is_retained_as_portable_evidence() {
        let (context, identities) = fixtures();
        let mut node = DepositConsensus::new(context.clone(), PartyId(2)).unwrap();
        node.start(&identities[1], value(9)).unwrap();
        assert_eq!(context.leader(0), PartyId(1));
        let first = sign_consensus_message(
            &context,
            &identities[0],
            ConsensusMessageBody::Proposal(Proposal {
                view: 0,
                value: value(1),
                proof_of_lock: None,
                view_change: None,
            }),
        )
        .unwrap();
        let conflicting = sign_consensus_message(
            &context,
            &identities[0],
            ConsensusMessageBody::Proposal(Proposal {
                view: 0,
                value: value(2),
                proof_of_lock: None,
                view_change: None,
            }),
        )
        .unwrap();
        node.handle_structurally_valid(&identities[1], first.clone()).unwrap();
        let step = node.handle_structurally_valid(&identities[1], conflicting.clone()).unwrap();
        assert_eq!(step.evidence.len(), 1);
        assert_eq!(step.evidence[0].first, first);
        assert_eq!(step.evidence[0].conflicting, conflicting);
        assert_eq!(node.evidence().len(), 1);

        let third = sign_consensus_message(
            &context,
            &identities[0],
            ConsensusMessageBody::Proposal(Proposal {
                view: 0,
                value: value(3),
                proof_of_lock: None,
                view_change: None,
            }),
        )
        .unwrap();
        let repeated = node.handle_structurally_valid(&identities[1], third).unwrap();
        assert!(repeated.duplicate);
        assert!(!repeated.changed);
        assert_eq!(node.evidence().len(), 1);
    }

    #[test]
    fn delayed_old_view_cannot_reopen_state() {
        let (context, identities) = fixtures();
        let mut node = DepositConsensus::new(context.clone(), PartyId(4)).unwrap();
        node.start(&identities[3], value(1)).unwrap();
        for identity in identities.iter().take(3) {
            let envelope = sign_consensus_message(
                &context,
                identity,
                ConsensusMessageBody::ViewChange(ViewChange {
                    from_view: 0,
                    target_view: 1,
                    highest_prepared: None,
                }),
            )
            .unwrap();
            node.handle_structurally_valid(&identities[3], envelope).unwrap();
        }
        assert_eq!(node.view(), 1);
        let old = sign_consensus_message(
            &context,
            &identities[0],
            ConsensusMessageBody::Proposal(Proposal {
                view: 0,
                value: value(1),
                proof_of_lock: None,
                view_change: None,
            }),
        )
        .unwrap();
        assert_eq!(
            node.handle_structurally_valid(&identities[3], old),
            Err(ConsensusError::StaleView { message: 0, current: 1 })
        );
    }

    #[test]
    fn portable_view_certificate_catches_up_a_lagging_party() {
        let (context, identities) = fixtures();
        let changes = identities
            .iter()
            .take(3)
            .map(|identity| {
                sign_consensus_message(
                    &context,
                    identity,
                    ConsensusMessageBody::ViewChange(ViewChange {
                        from_view: 1,
                        target_view: 2,
                        highest_prepared: None,
                    }),
                )
                .unwrap()
            })
            .collect();
        let certificate = ViewChangeCertificate::from_witnesses(&context, 2, changes).unwrap();
        let mut lagging = DepositConsensus::new(context.clone(), PartyId(4)).unwrap();
        lagging.start(&identities[3], value(1)).unwrap();

        let step = lagging
            .handle_view_certificate_structurally_valid(&identities[3], certificate.clone())
            .unwrap();
        assert_eq!(lagging.view(), 2);
        assert_eq!(step.entered_view, Some(2));
        assert_eq!(step.relay_view_certificate, Some(certificate));
    }

    #[test]
    fn requesting_view_change_stops_new_votes_in_abandoned_view() {
        let (context, identities) = fixtures();
        let candidate = value(11);
        let mut node = DepositConsensus::new(context.clone(), PartyId(2)).unwrap();
        node.start(&identities[1], candidate.clone()).unwrap();
        let proposal = sign_consensus_message(
            &context,
            &identities[0],
            ConsensusMessageBody::Proposal(Proposal {
                view: 0,
                value: candidate.clone(),
                proof_of_lock: None,
                view_change: None,
            }),
        )
        .unwrap();
        node.handle_structurally_valid(&identities[1], proposal).unwrap();
        node.request_view_change(&identities[1]).unwrap();

        for peer_vote in
            vote_envelopes(&context, &identities, MessageKind::Prevote, 0, &candidate, &[2, 3])
        {
            let step = node.handle_structurally_valid(&identities[1], peer_vote).unwrap();
            assert!(!step.broadcast.iter().any(|envelope| matches!(
                decode_consensus_message(&context, envelope).unwrap().body,
                ConsensusMessageBody::Precommit(_)
            )));
        }
        assert!(node.locked().is_none());
    }

    #[test]
    fn unauthorized_and_duplicate_proposals_do_not_reinvoke_application_policy() {
        let (context, identities) = fixtures();
        let candidate = value(12);
        let mut node = DepositConsensus::new(context.clone(), PartyId(3)).unwrap();
        node.start(&identities[2], candidate.clone()).unwrap();
        let unauthorized = sign_consensus_message(
            &context,
            &identities[1],
            ConsensusMessageBody::Proposal(Proposal {
                view: 0,
                value: candidate.clone(),
                proof_of_lock: None,
                view_change: None,
            }),
        )
        .unwrap();
        let mut calls = 0;
        assert_eq!(
            node.handle_with_value_validator(&identities[2], unauthorized, |_| {
                calls += 1;
                true
            }),
            Err(ConsensusError::WrongLeader)
        );
        assert_eq!(calls, 0);

        let proposal = sign_consensus_message(
            &context,
            &identities[0],
            ConsensusMessageBody::Proposal(Proposal {
                view: 0,
                value: candidate,
                proof_of_lock: None,
                view_change: None,
            }),
        )
        .unwrap();
        node.handle_with_value_validator(&identities[2], proposal.clone(), |_| {
            calls += 1;
            true
        })
        .unwrap();
        assert_eq!(calls, 1);
        let duplicate = node
            .handle_with_value_validator(&identities[2], proposal, |_| {
                calls += 1;
                true
            })
            .unwrap();
        assert!(duplicate.duplicate);
        assert_eq!(calls, 1);
    }

    #[test]
    fn exact_proposal_and_view_certificate_replays_skip_nested_verification_after_restart() {
        let (context, identities) = fixtures();
        let candidate = value(21);
        let changes = [0_usize, 1, 2]
            .into_iter()
            .map(|index| {
                sign_consensus_message(
                    &context,
                    &identities[index],
                    ConsensusMessageBody::ViewChange(ViewChange {
                        from_view: 0,
                        target_view: 1,
                        highest_prepared: None,
                    }),
                )
                .unwrap()
            })
            .collect();
        let certificate = ViewChangeCertificate::from_witnesses(&context, 1, changes).unwrap();
        let proposal = sign_consensus_message(
            &context,
            &identities[1],
            ConsensusMessageBody::Proposal(Proposal {
                view: 1,
                value: candidate.clone(),
                proof_of_lock: None,
                view_change: Some(certificate.clone()),
            }),
        )
        .unwrap();

        let mut node = DepositConsensus::new(context.clone(), PartyId(3)).unwrap();
        node.start(&identities[2], candidate).unwrap();
        node.handle_view_certificate_structurally_valid(&identities[2], certificate.clone())
            .unwrap();
        node.handle_structurally_valid(&identities[2], proposal.clone()).unwrap();

        // Snapshot restoration performs full structural and cryptographic verification. The
        // application then explicitly re-establishes its semantic invariant before ingress.
        let encoded = postcard::to_allocvec(&node).unwrap();
        let mut restored: DepositConsensus = postcard::from_bytes(&encoded).unwrap();
        let mut restored_values = 0;
        restored
            .validate_application_values(|_| {
                restored_values += 1;
                true
            })
            .unwrap();
        assert!(restored_values > 0);

        let _ = take_view_certificate_verifications();
        let mut replay_values = 0;
        let proposal_replay = restored
            .handle_with_value_validator(&identities[2], proposal, |_| {
                replay_values += 1;
                true
            })
            .unwrap();
        assert!(proposal_replay.duplicate);
        assert!(!proposal_replay.changed);
        assert_eq!(replay_values, 0);
        assert_eq!(take_view_certificate_verifications(), 0);

        let view_replay = restored
            .handle_view_certificate_with_validator(&identities[2], certificate.clone(), |_| {
                replay_values += 1;
                true
            })
            .unwrap();
        assert!(view_replay.duplicate);
        assert!(!view_replay.changed);
        assert_eq!(replay_values, 0);
        assert_eq!(take_view_certificate_verifications(), 0);

        // Another valid quorum subset is logically related but not an exact replay. It still
        // verifies before being rejected as stale.
        let alternate_changes = [0_usize, 1, 3]
            .into_iter()
            .map(|index| {
                sign_consensus_message(
                    &context,
                    &identities[index],
                    ConsensusMessageBody::ViewChange(ViewChange {
                        from_view: 0,
                        target_view: 1,
                        highest_prepared: None,
                    }),
                )
                .unwrap()
            })
            .collect();
        let alternate =
            ViewChangeCertificate::from_witnesses(&context, 1, alternate_changes).unwrap();
        let _ = take_view_certificate_verifications();
        assert_eq!(
            restored.handle_view_certificate_structurally_valid(&identities[2], alternate),
            Err(ConsensusError::StaleView { message: 1, current: 1 })
        );
        assert!(take_view_certificate_verifications() > 0);

        // A conflicting leader proposal is also non-equal, so its nested proof is verified and
        // the durable equivocation path remains active.
        let conflicting = sign_consensus_message(
            &context,
            &identities[1],
            ConsensusMessageBody::Proposal(Proposal {
                view: 1,
                value: value(22),
                proof_of_lock: None,
                view_change: Some(certificate),
            }),
        )
        .unwrap();
        let _ = take_view_certificate_verifications();
        let evidence = restored.handle_structurally_valid(&identities[2], conflicting).unwrap();
        assert_eq!(evidence.evidence.len(), 1);
        assert!(take_view_certificate_verifications() > 0);
    }

    #[test]
    fn exact_commit_certificate_replay_skips_verification_after_restart() {
        let (context, identities) = fixtures();
        let decided = value(23);
        let certificate = CommitCertificate::from_witnesses(
            &context,
            0,
            decided.clone(),
            vote_envelopes(&context, &identities, MessageKind::Precommit, 0, &decided, &[0, 1, 2]),
        )
        .unwrap();
        let mut node = DepositConsensus::new(context.clone(), PartyId(4)).unwrap();
        node.handle_commit_certificate_with_validator(certificate.clone(), |_| true).unwrap();

        let encoded = postcard::to_allocvec(&node).unwrap();
        let mut restored: DepositConsensus = postcard::from_bytes(&encoded).unwrap();
        restored.validate_application_values(|_| true).unwrap();

        let _ = take_commit_certificate_verifications();
        let mut replay_values = 0;
        let replay = restored
            .handle_commit_certificate_with_validator(certificate.clone(), |_| {
                replay_values += 1;
                true
            })
            .unwrap();
        assert!(replay.duplicate);
        assert!(!replay.changed);
        assert_eq!(replay_values, 0);
        assert_eq!(take_commit_certificate_verifications(), 0);

        // A different valid quorum subset for the same decision is not an exact replay and must
        // still pay the verification cost before it is classified as a duplicate decision.
        let alternate = CommitCertificate::from_witnesses(
            &context,
            0,
            decided.clone(),
            vote_envelopes(&context, &identities, MessageKind::Precommit, 0, &decided, &[1, 2, 3]),
        )
        .unwrap();
        let _ = take_commit_certificate_verifications();
        let alternate_step =
            restored.handle_commit_certificate_structurally_valid(alternate).unwrap();
        assert!(alternate_step.duplicate);
        assert!(take_commit_certificate_verifications() > 0);

        // A changed nested witness cannot use the fast path even though every header/value field
        // still matches the installed certificate.
        let mut forged = certificate;
        forged.witnesses[0].payload[0] ^= 1;
        let _ = take_commit_certificate_verifications();
        assert!(restored.handle_commit_certificate_structurally_valid(forged).is_err());
        assert!(take_commit_certificate_verifications() > 0);
    }

    #[test]
    fn certificates_reject_duplicate_outsider_and_forged_witnesses() {
        let (context, identities) = fixtures();
        let candidate_value = value(3);
        let valid = vote_envelopes(
            &context,
            &identities,
            MessageKind::Prevote,
            0,
            &candidate_value,
            &[0, 1, 2],
        );
        PrepareCertificate::from_witnesses(&context, 0, candidate_value.clone(), valid.clone())
            .unwrap();

        let duplicate = vec![valid[0].clone(), valid[0].clone(), valid[1].clone()];
        assert!(matches!(
            PrepareCertificate::from_witnesses(&context, 0, candidate_value.clone(), duplicate),
            Err(ConsensusError::InvalidCertificate(_))
        ));

        let mut outsider = valid.clone();
        outsider[2].from = PartyId(99);
        assert!(
            PrepareCertificate::from_witnesses(&context, 0, candidate_value.clone(), outsider)
                .is_err()
        );

        let mut forged = valid;
        forged[2].payload[0] ^= 1;
        assert!(PrepareCertificate::from_witnesses(&context, 0, candidate_value, forged).is_err());

        let oversized = PrepareCertificate {
            version: PREPARE_CERTIFICATE_VERSION,
            context: context.digest(),
            view: 0,
            value: ConsensusValue::new(vec![3; 16]).unwrap(),
            witnesses: vec![
                vote_envelopes(
                    &context,
                    &identities,
                    MessageKind::Prevote,
                    0,
                    &ConsensusValue::new(vec![3; 16]).unwrap(),
                    &[0],
                )[0]
                .clone();
                MAX_COMMITTEE_MEMBERS + 1
            ],
        };
        let encoded = postcard::to_allocvec(&oversized).unwrap();
        assert!(postcard::from_bytes::<PrepareCertificate>(&encoded).is_err());
    }

    #[test]
    fn conflicting_commits_expose_more_than_f_double_signers() {
        let (context, identities) = fixtures();
        let left_value = value(4);
        let right_value = value(5);
        let left = CommitCertificate::from_witnesses(
            &context,
            0,
            left_value.clone(),
            vote_envelopes(
                &context,
                &identities,
                MessageKind::Precommit,
                0,
                &left_value,
                &[0, 1, 2],
            ),
        )
        .unwrap();
        let right = CommitCertificate::from_witnesses(
            &context,
            0,
            right_value.clone(),
            vote_envelopes(
                &context,
                &identities,
                MessageKind::Precommit,
                0,
                &right_value,
                &[1, 2, 3],
            ),
        )
        .unwrap();
        let equivocators = left.conflicting_signers(&right, &context).unwrap();
        assert_eq!(equivocators, vec![PartyId(2), PartyId(3)]);
        assert!(equivocators.len() > usize::from(context.fault_bound()));

        let equivalent = CommitCertificate::from_witnesses(
            &context,
            0,
            left_value.clone(),
            vote_envelopes(
                &context,
                &identities,
                MessageKind::Precommit,
                0,
                &left_value,
                &[1, 2, 3],
            ),
        )
        .unwrap();
        assert_eq!(left.digest(), equivalent.digest());

        let later = CommitCertificate::from_witnesses(
            &context,
            1,
            right_value.clone(),
            vote_envelopes(
                &context,
                &identities,
                MessageKind::Precommit,
                1,
                &right_value,
                &[1, 2, 3],
            ),
        )
        .unwrap();
        assert_eq!(
            left.conflicting_signers(&later, &context),
            Err(ConsensusError::CrossViewConflict)
        );
    }

    #[test]
    fn portable_commit_certificate_terminates_selective_delivery() {
        let (context, identities) = fixtures();
        let decided = value(15);
        let certificate = CommitCertificate::from_witnesses(
            &context,
            3,
            decided.clone(),
            vote_envelopes(&context, &identities, MessageKind::Precommit, 3, &decided, &[0, 1, 2]),
        )
        .unwrap();
        let mut first = DepositConsensus::new(context.clone(), PartyId(3)).unwrap();
        let mut second = DepositConsensus::new(context.clone(), PartyId(4)).unwrap();
        first.start(&identities[2], value(99)).unwrap();
        assert!(!second.started);

        let learned =
            first.handle_commit_certificate_structurally_valid(certificate.clone()).unwrap();
        assert_eq!(learned.commit, Some(certificate.clone()));
        assert_eq!(learned.relay_commit_certificate, Some(certificate.clone()));
        let relayed = learned.relay_commit_certificate.unwrap();
        second.handle_commit_certificate_structurally_valid(relayed).unwrap();
        assert!(second.started);
        assert_eq!(first.commit().unwrap().value(), &decided);
        assert_eq!(second.commit().unwrap().value(), &decided);
    }

    #[test]
    fn view_change_leader_must_repropose_highest_lock() {
        let (context, identities) = fixtures();
        let locked_value = value(6);
        let prepare = PrepareCertificate::from_witnesses(
            &context,
            0,
            locked_value.clone(),
            vote_envelopes(
                &context,
                &identities,
                MessageKind::Prevote,
                0,
                &locked_value,
                &[0, 1, 2],
            ),
        )
        .unwrap();
        let changes = identities
            .iter()
            .take(3)
            .enumerate()
            .map(|(index, identity)| {
                sign_consensus_message(
                    &context,
                    identity,
                    ConsensusMessageBody::ViewChange(ViewChange {
                        from_view: 0,
                        target_view: 1,
                        highest_prepared: (index == 0).then(|| prepare.clone()),
                    }),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let certificate =
            ViewChangeCertificate::from_witnesses(&context, 1, changes.clone()).unwrap();
        assert_eq!(certificate.highest_prepared(&context).unwrap(), Some(prepare.clone()));

        // Height zero/view one rotates to party two, which must ignore its local candidate.
        let mut leader = DepositConsensus::new(context.clone(), PartyId(2)).unwrap();
        leader.start(&identities[1], value(99)).unwrap();
        let mut final_step = ConsensusStep::default();
        for change in changes {
            final_step = leader.handle_structurally_valid(&identities[1], change).unwrap();
        }
        assert_eq!(leader.view(), 1);
        let proposal_envelope = final_step
            .broadcast
            .iter()
            .find(|envelope| {
                matches!(
                    decode_consensus_message(&context, envelope).unwrap().body,
                    ConsensusMessageBody::Proposal(_)
                )
            })
            .unwrap();
        let message = decode_consensus_message(&context, proposal_envelope).unwrap();
        let ConsensusMessageBody::Proposal(proposal) = message.body else { unreachable!() };
        assert_eq!(proposal.value, locked_value);
        assert_eq!(proposal.proof_of_lock, Some(prepare));
        assert_eq!(proposal.view_change, Some(certificate));
    }

    #[test]
    fn restart_round_trip_revalidates_every_signed_record() {
        let (context, identities) = fixtures();
        let mut node = DepositConsensus::new(context.clone(), PartyId(2)).unwrap();
        node.start(&identities[1], value(8)).unwrap();
        let proposal = sign_consensus_message(
            &context,
            &identities[0],
            ConsensusMessageBody::Proposal(Proposal {
                view: 0,
                value: value(8),
                proof_of_lock: None,
                view_change: None,
            }),
        )
        .unwrap();
        node.handle_structurally_valid(&identities[1], proposal).unwrap();
        let peer_vote =
            vote_envelopes(&context, &identities, MessageKind::Prevote, 0, &value(8), &[2])
                .pop()
                .unwrap();
        node.handle_structurally_valid(&identities[1], peer_vote).unwrap();

        let encoded = postcard::to_allocvec(&node).unwrap();
        let restored: DepositConsensus = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(restored, node);
        assert_eq!(restored.view(), 0);
        assert!(restored.commit().is_none());
    }

    #[test]
    fn secure_ingress_validates_nested_view_certificate_values() {
        let (context, identities) = fixtures();
        let rejected = value(77);
        let prepare = PrepareCertificate::from_witnesses(
            &context,
            0,
            rejected.clone(),
            vote_envelopes(&context, &identities, MessageKind::Prevote, 0, &rejected, &[0, 1, 2]),
        )
        .unwrap();
        let changes = identities
            .iter()
            .take(3)
            .enumerate()
            .map(|(index, identity)| {
                sign_consensus_message(
                    &context,
                    identity,
                    ConsensusMessageBody::ViewChange(ViewChange {
                        from_view: 0,
                        target_view: 1,
                        highest_prepared: (index == 0).then(|| prepare.clone()),
                    }),
                )
                .unwrap()
            })
            .collect();
        let certificate = ViewChangeCertificate::from_witnesses(&context, 1, changes).unwrap();
        let mut node = DepositConsensus::new(context, PartyId(4)).unwrap();
        node.start(&identities[3], value(1)).unwrap();
        let result =
            node.handle_view_certificate_with_validator(&identities[3], certificate, |candidate| {
                candidate.digest() != rejected.digest()
            });
        assert_eq!(result, Err(ConsensusError::InvalidApplicationValue));
        assert_eq!(node.view(), 0);
    }

    #[test]
    fn persistence_and_fault_assumption_fail_closed() {
        let (context, identities) = fixtures();
        let mut weak_committee = context.committee.clone();
        weak_committee.threshold = 1;
        assert!(matches!(
            ConsensusContext::new(
                context.binding.clone(),
                context.session,
                weak_committee,
                1,
                0,
                0,
                [0; 32],
            ),
            Err(ConsensusError::Committee(CommitteeError::InvalidFaultBound))
        ));

        let mut state = DepositConsensus::new(context, PartyId(1)).unwrap();
        state.start(&identities[0], value(1)).unwrap();
        state.state_version = CONSENSUS_STATE_VERSION + 1;
        let encoded = postcard::to_allocvec(&state).unwrap();
        assert!(postcard::from_bytes::<DepositConsensus>(&encoded).is_err());
    }
}
