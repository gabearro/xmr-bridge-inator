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
    identity::{EnvelopeSigner, EnvelopeSignerScope, Identity, IdentityError, SignedEnvelope},
    receiver_key_accumulator::MAX_RECEIVER_KEY_BATCH_UPDATE_PROOF_BYTES,
};

const CONSENSUS_VERSION: u16 = 1;
const CONSENSUS_STATE_VERSION: u16 = 2;
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
/// Fixed non-proof allowance for a maximum-size receiver-key advertisement set and canonical
/// application framing. The dominant sparse proof is independently derived from committee size
/// and its fixed 256-bit tree depth.
const MAX_CONSENSUS_VALUE_FRAMING_BYTES: usize = 32 * 1024;
/// Hard bound for an opaque canonical application value. It is independent of epoch/history
/// length; increasing receiver-key history cannot grow this bound.
pub const MAX_CONSENSUS_VALUE_BYTES: usize =
    MAX_RECEIVER_KEY_BATCH_UPDATE_PROOF_BYTES + MAX_CONSENSUS_VALUE_FRAMING_BYTES;
/// Hard bound for one signed consensus payload, including nested full-witness certificates.
pub const MAX_CONSENSUS_MESSAGE_BYTES: usize = 1024 * 1024;
/// Highest representable view.  This keeps signed-envelope sequence slots collision-free.
pub const MAX_CONSENSUS_VIEW: u64 = (1_u64 << WIRE_SEQUENCE_VIEW_BITS) - 1;
/// Diagnostic evidence does not affect safety and is retained under this fixed cap.
pub const MAX_CONSENSUS_EVIDENCE: usize = MAX_COMMITTEE_MEMBERS * 2;
/// A singleton `f=0` reducer can emit a view change, proposal, and both vote phases in one step.
pub const MAX_CONSENSUS_OUTBOUND_PER_STEP: usize = 4;
/// A restricted reducer retains only exact application-value digests which the deposit service
/// authenticated before reduction. This matches the host's bounded competing-value pool while
/// keeping the generic consensus layer independent of deposit-ledger payload semantics.
pub(crate) const MAX_RESTRICTED_AUTHORIZED_VALUES: usize = 128;

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

fn deserialize_restricted_authorized_values<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeSet<ConsensusValueDigest>, D::Error> {
    struct AuthorizedValueVisitor;

    impl<'de> Visitor<'de> for AuthorizedValueVisitor {
        type Value = BTreeSet<ConsensusValueDigest>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_RESTRICTED_AUTHORIZED_VALUES} unique consensus-value digests"
            )
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let hinted = sequence.size_hint().unwrap_or(0);
            if hinted > MAX_RESTRICTED_AUTHORIZED_VALUES {
                return Err(A::Error::invalid_length(hinted, &self));
            }
            let mut values = BTreeSet::new();
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX_RESTRICTED_AUTHORIZED_VALUES {
                    return Err(A::Error::invalid_length(
                        MAX_RESTRICTED_AUTHORIZED_VALUES.saturating_add(1),
                        &self,
                    ));
                }
                if !values.insert(value) {
                    return Err(A::Error::custom(
                        "restricted authorization contains a duplicate value digest",
                    ));
                }
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(AuthorizedValueVisitor)
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

    /// Digest of the exact consensus context authenticated by every witness.
    ///
    /// Durable application snapshots use this to retire only the matching transport retry
    /// scope after a stronger terminal certificate has embedded this commit certificate.
    #[must_use]
    pub(crate) const fn context_digest(&self) -> [u8; 32] {
        self.context
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
    #[error("signer scope is not authorized for this consensus reducer")]
    UnauthorizedSignerScope,
    #[error("consensus value is not authorized by the handoff-only reducer")]
    UnauthorizedHandoffValue,
    #[error("invalid handoff-only consensus signing policy")]
    InvalidHandoffSigningPolicy,
    #[error("consensus value is not authorized by the recovery-and-fence-only reducer")]
    UnauthorizedRecoveryAndFenceValue,
    #[error("invalid recovery-and-fence-only consensus signing policy")]
    InvalidRecoveryAndFenceSigningPolicy,
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

/// Durable authorization boundary for the local envelope signer.
///
/// Public/generic reducers are always `FullOnly`. The deposit service may construct crate-private
/// transition variants only after authenticating exact values. Their allowlists are persisted
/// with the reducer so restart or a later view change cannot widen a stable signing capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum ConsensusSigningPolicy {
    FullOnly,
    RecoveryAndFenceOnly {
        context: [u8; 32],
        recovery_authority: [u8; 32],
        #[serde(deserialize_with = "deserialize_restricted_authorized_values")]
        recovery_values: BTreeSet<ConsensusValueDigest>,
        #[serde(deserialize_with = "deserialize_restricted_authorized_values")]
        fence_values: BTreeSet<ConsensusValueDigest>,
    },
    HandoffOnly {
        context: [u8; 32],
        #[serde(deserialize_with = "deserialize_restricted_authorized_values")]
        authorized_values: BTreeSet<ConsensusValueDigest>,
    },
}

impl ConsensusSigningPolicy {
    fn recovery_and_fence_only<R, F>(
        context: &ConsensusContext,
        recovery_authority: [u8; 32],
        recovery_values: R,
        fence_values: F,
    ) -> Result<Self, ConsensusError>
    where
        R: IntoIterator<Item = ConsensusValueDigest>,
        F: IntoIterator<Item = ConsensusValueDigest>,
    {
        let policy = Self::RecoveryAndFenceOnly {
            context: context.digest(),
            recovery_authority,
            recovery_values: recovery_values.into_iter().collect(),
            fence_values: fence_values.into_iter().collect(),
        };
        policy.validate(context)?;
        Ok(policy)
    }

    fn handoff_only<I>(
        context: &ConsensusContext,
        authorized_values: I,
    ) -> Result<Self, ConsensusError>
    where
        I: IntoIterator<Item = ConsensusValueDigest>,
    {
        let authorized_values = authorized_values.into_iter().collect::<BTreeSet<_>>();
        if authorized_values.is_empty()
            || authorized_values.len() > MAX_RESTRICTED_AUTHORIZED_VALUES
        {
            return Err(ConsensusError::InvalidHandoffSigningPolicy);
        }
        Ok(Self::HandoffOnly { context: context.digest(), authorized_values })
    }

    fn validate(&self, context: &ConsensusContext) -> Result<(), ConsensusError> {
        match self {
            Self::FullOnly => Ok(()),
            Self::RecoveryAndFenceOnly {
                context: bound_context,
                recovery_authority,
                recovery_values,
                fence_values,
            } if *bound_context == context.digest()
                && *recovery_authority != [0; 32]
                && (!recovery_values.is_empty() || !fence_values.is_empty())
                && recovery_values.len().saturating_add(fence_values.len())
                    <= MAX_RESTRICTED_AUTHORIZED_VALUES
                && recovery_values.is_disjoint(fence_values) =>
            {
                Ok(())
            }
            Self::RecoveryAndFenceOnly { .. } => {
                Err(ConsensusError::InvalidRecoveryAndFenceSigningPolicy)
            }
            Self::HandoffOnly { context: bound_context, authorized_values }
                if *bound_context == context.digest()
                    && !authorized_values.is_empty()
                    && authorized_values.len() <= MAX_RESTRICTED_AUTHORIZED_VALUES =>
            {
                Ok(())
            }
            Self::HandoffOnly { .. } => Err(ConsensusError::InvalidHandoffSigningPolicy),
        }
    }

    fn authorize_handoff_values<I>(&mut self, values: I) -> Result<(), ConsensusError>
    where
        I: IntoIterator<Item = ConsensusValueDigest>,
    {
        let Self::HandoffOnly { authorized_values, .. } = self else {
            return Err(ConsensusError::InvalidHandoffSigningPolicy);
        };
        let mut extended = authorized_values.clone();
        extended.extend(values);
        if extended.is_empty() || extended.len() > MAX_RESTRICTED_AUTHORIZED_VALUES {
            return Err(ConsensusError::InvalidHandoffSigningPolicy);
        }
        *authorized_values = extended;
        Ok(())
    }

    fn authorize_recovery_values<I>(&mut self, values: I) -> Result<(), ConsensusError>
    where
        I: IntoIterator<Item = ConsensusValueDigest>,
    {
        let Self::RecoveryAndFenceOnly { recovery_values, fence_values, .. } = self else {
            return Err(ConsensusError::InvalidRecoveryAndFenceSigningPolicy);
        };
        let mut extended = recovery_values.clone();
        extended.extend(values);
        if extended.is_empty() && fence_values.is_empty()
            || extended.len().saturating_add(fence_values.len()) > MAX_RESTRICTED_AUTHORIZED_VALUES
            || !extended.is_disjoint(fence_values)
        {
            return Err(ConsensusError::InvalidRecoveryAndFenceSigningPolicy);
        }
        *recovery_values = extended;
        Ok(())
    }

    fn authorize_fence_values<I>(&mut self, values: I) -> Result<(), ConsensusError>
    where
        I: IntoIterator<Item = ConsensusValueDigest>,
    {
        let Self::RecoveryAndFenceOnly { recovery_values, fence_values, .. } = self else {
            return Err(ConsensusError::InvalidRecoveryAndFenceSigningPolicy);
        };
        let mut extended = fence_values.clone();
        extended.extend(values);
        if recovery_values.is_empty() && extended.is_empty()
            || recovery_values.len().saturating_add(extended.len())
                > MAX_RESTRICTED_AUTHORIZED_VALUES
            || !recovery_values.is_disjoint(&extended)
        {
            return Err(ConsensusError::InvalidRecoveryAndFenceSigningPolicy);
        }
        *fence_values = extended;
        Ok(())
    }

    fn ensure_signer(&self, identity: &dyn EnvelopeSigner) -> Result<(), ConsensusError> {
        match (self, identity.scope()) {
            (Self::FullOnly, EnvelopeSignerScope::Full)
            | (Self::RecoveryAndFenceOnly { .. }, EnvelopeSignerScope::Full)
            | (Self::HandoffOnly { .. }, EnvelopeSignerScope::Full)
            | (Self::HandoffOnly { .. }, EnvelopeSignerScope::HandoffOnly) => Ok(()),
            (
                Self::RecoveryAndFenceOnly { recovery_authority, .. },
                EnvelopeSignerScope::RecoveryAndFenceOnly,
            ) if identity.recovery_authority() == Some(*recovery_authority) => Ok(()),
            (
                Self::FullOnly | Self::HandoffOnly { .. },
                EnvelopeSignerScope::RecoveryAndFenceOnly,
            )
            | (
                Self::FullOnly | Self::RecoveryAndFenceOnly { .. },
                EnvelopeSignerScope::HandoffOnly,
            )
            | (Self::RecoveryAndFenceOnly { .. }, EnvelopeSignerScope::RecoveryAndFenceOnly) => {
                Err(ConsensusError::UnauthorizedSignerScope)
            }
        }
    }

    fn ensure_value_digest(&self, digest: ConsensusValueDigest) -> Result<(), ConsensusError> {
        match self {
            Self::FullOnly => Ok(()),
            Self::RecoveryAndFenceOnly { recovery_values, fence_values, .. }
                if recovery_values.contains(&digest) || fence_values.contains(&digest) =>
            {
                Ok(())
            }
            Self::RecoveryAndFenceOnly { .. } => {
                Err(ConsensusError::UnauthorizedRecoveryAndFenceValue)
            }
            Self::HandoffOnly { authorized_values, .. } if authorized_values.contains(&digest) => {
                Ok(())
            }
            Self::HandoffOnly { .. } => Err(ConsensusError::UnauthorizedHandoffValue),
        }
    }

    fn ensure_value(&self, value: &ConsensusValue) -> Result<(), ConsensusError> {
        value.validate()?;
        self.ensure_value_digest(value.digest())
    }

    fn ensure_prepare_certificate(
        &self,
        certificate: &PrepareCertificate,
    ) -> Result<(), ConsensusError> {
        self.ensure_value(certificate.value())
    }

    fn ensure_message_body(
        &self,
        context: &ConsensusContext,
        body: &ConsensusMessageBody,
    ) -> Result<(), ConsensusError> {
        match body {
            ConsensusMessageBody::Proposal(proposal) => {
                self.ensure_value(&proposal.value)?;
                if let Some(proof) = &proposal.proof_of_lock {
                    self.ensure_prepare_certificate(proof)?;
                }
                if let Some(certificate) = &proposal.view_change {
                    self.ensure_view_certificate(context, certificate)?;
                }
            }
            ConsensusMessageBody::Prevote(vote) | ConsensusMessageBody::Precommit(vote) => {
                self.ensure_value_digest(vote.value)?;
            }
            ConsensusMessageBody::ViewChange(change) => {
                if let Some(prepared) = &change.highest_prepared {
                    self.ensure_prepare_certificate(prepared)?;
                }
            }
        }
        Ok(())
    }

    fn ensure_view_certificate(
        &self,
        context: &ConsensusContext,
        certificate: &ViewChangeCertificate,
    ) -> Result<(), ConsensusError> {
        visit_view_certificate_values(context, certificate, &mut |value| self.ensure_value(value))
    }

    fn ensure_commit_certificate(
        &self,
        certificate: &CommitCertificate,
    ) -> Result<(), ConsensusError> {
        self.ensure_value(certificate.value())
    }
}

/// Durable state for one party and one context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DepositConsensus {
    state_version: u16,
    context: ConsensusContext,
    local_party: PartyId,
    signing_policy: ConsensusSigningPolicy,
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
    signing_policy: ConsensusSigningPolicy,
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
            signing_policy: unchecked.signing_policy,
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
        Self::new_with_signing_policy(context, local_party, ConsensusSigningPolicy::FullOnly)
    }

    /// Construct a transition-bound reducer for exact recovery and Fence values.
    ///
    /// The caller must authenticate every recovery digest from a matching Prepare/Commit
    /// certificate and every Fence digest against the exact certified transition before invoking
    /// this constructor. The nonzero authority must match the recovery signer which later drives
    /// the reducer; a full identity remains able to make progress without carrying that token.
    pub(crate) fn new_recovery_and_fence_only<R, F>(
        context: ConsensusContext,
        local_party: PartyId,
        recovery_authority: [u8; 32],
        recovery_values: R,
        fence_values: F,
    ) -> Result<Self, ConsensusError>
    where
        R: IntoIterator<Item = ConsensusValueDigest>,
        F: IntoIterator<Item = ConsensusValueDigest>,
    {
        let signing_policy = ConsensusSigningPolicy::recovery_and_fence_only(
            &context,
            recovery_authority,
            recovery_values,
            fence_values,
        )?;
        Self::new_with_signing_policy(context, local_party, signing_policy)
    }

    /// Construct the only reducer which may consume a historical handoff-only signer.
    ///
    /// The caller must first authenticate every supplied digest as an exact handoff value. The
    /// allowlist is durable and applies even when a live full identity drives this reducer, so an
    /// old-epoch restart cannot turn a previously generic lane into a handoff signing oracle.
    pub(crate) fn new_handoff_only<I>(
        context: ConsensusContext,
        local_party: PartyId,
        authorized_values: I,
    ) -> Result<Self, ConsensusError>
    where
        I: IntoIterator<Item = ConsensusValueDigest>,
    {
        let signing_policy = ConsensusSigningPolicy::handoff_only(&context, authorized_values)?;
        Self::new_with_signing_policy(context, local_party, signing_policy)
    }

    fn new_with_signing_policy(
        context: ConsensusContext,
        local_party: PartyId,
        signing_policy: ConsensusSigningPolicy,
    ) -> Result<Self, ConsensusError> {
        context.validate()?;
        signing_policy.validate(&context)?;
        context
            .committee
            .member(local_party)
            .map_err(|_| ConsensusError::UnknownVoter(local_party))?;
        Ok(Self {
            state_version: CONSENSUS_STATE_VERSION,
            context,
            local_party,
            signing_policy,
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

    /// Extend a handoff reducer with values which the deposit service has already authenticated.
    ///
    /// This operation cannot convert a generic reducer into a handoff reducer and is monotonic.
    /// The service persists the expanded policy atomically with the reduction that first consumes
    /// any newly authorized value.
    pub(crate) fn authorize_handoff_value_digests<I>(
        &mut self,
        values: I,
    ) -> Result<(), ConsensusError>
    where
        I: IntoIterator<Item = ConsensusValueDigest>,
    {
        self.signing_policy.authorize_handoff_values(values)
    }

    /// Monotonically add exact quorum-certificate-backed recovery values.
    ///
    /// The service must persist the certificate provenance atomically with this expansion. This
    /// method cannot create or convert a generic, Fence-only, or final-handoff reducer.
    pub(crate) fn authorize_recovery_value_digests<I>(
        &mut self,
        values: I,
    ) -> Result<(), ConsensusError>
    where
        I: IntoIterator<Item = ConsensusValueDigest>,
    {
        self.signing_policy.authorize_recovery_values(values)
    }

    /// Monotonically add exact host-validated Fence values.
    ///
    /// Recovery and Fence classifications are deliberately disjoint. A final handoff value must
    /// use a separate `HandoffOnly` reducer and cannot be added through this method.
    pub(crate) fn authorize_fence_value_digests<I>(
        &mut self,
        values: I,
    ) -> Result<(), ConsensusError>
    where
        I: IntoIterator<Item = ConsensusValueDigest>,
    {
        self.signing_policy.authorize_fence_values(values)
    }

    #[must_use]
    pub(crate) fn is_handoff_only(&self) -> bool {
        matches!(&self.signing_policy, ConsensusSigningPolicy::HandoffOnly { .. })
    }

    #[must_use]
    pub(crate) fn is_recovery_and_fence_only(&self) -> bool {
        matches!(&self.signing_policy, ConsensusSigningPolicy::RecoveryAndFenceOnly { .. })
    }

    #[must_use]
    pub(crate) fn recovery_authority_digest(&self) -> Option<[u8; 32]> {
        match &self.signing_policy {
            ConsensusSigningPolicy::RecoveryAndFenceOnly { recovery_authority, .. } => {
                Some(*recovery_authority)
            }
            ConsensusSigningPolicy::FullOnly | ConsensusSigningPolicy::HandoffOnly { .. } => None,
        }
    }

    #[must_use]
    pub(crate) fn recovery_authorized_value_digests(
        &self,
    ) -> Option<&BTreeSet<ConsensusValueDigest>> {
        match &self.signing_policy {
            ConsensusSigningPolicy::RecoveryAndFenceOnly { recovery_values, .. } => {
                Some(recovery_values)
            }
            ConsensusSigningPolicy::FullOnly | ConsensusSigningPolicy::HandoffOnly { .. } => None,
        }
    }

    #[must_use]
    pub(crate) fn fence_authorized_value_digests(&self) -> Option<&BTreeSet<ConsensusValueDigest>> {
        match &self.signing_policy {
            ConsensusSigningPolicy::RecoveryAndFenceOnly { fence_values, .. } => Some(fence_values),
            ConsensusSigningPolicy::FullOnly | ConsensusSigningPolicy::HandoffOnly { .. } => None,
        }
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

    pub(crate) fn candidate(&self) -> Option<&ConsensusValue> {
        self.candidate.as_ref()
    }

    /// Replace only the fallback for a future proposal. Never rewrite an emitted proposal,
    /// vote, lock, or certificate; a view certificate's prepared value still takes precedence.
    pub(crate) fn replace_candidate(
        &mut self,
        identity: &dyn EnvelopeSigner,
        candidate: ConsensusValue,
    ) -> Result<(), ConsensusError> {
        self.ensure_live()?;
        self.ensure_identity(identity)?;
        self.signing_policy.ensure_value(&candidate)?;
        self.candidate = Some(candidate);
        Ok(())
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

    /// Exact values currently backed by a stored Prepare or Commit certificate.
    ///
    /// This deliberately omits the raw local candidate, proposal value, and individual votes.
    /// Service restore validation pairs the result with its separately persisted certificate
    /// provenance, ensuring a restricted allowlist cannot be reconstructed from unbacked traffic.
    pub(crate) fn certificate_backed_value_digests(
        &self,
    ) -> Result<BTreeSet<ConsensusValueDigest>, ConsensusError> {
        self.validate_signing_policy_state()?;
        let mut digests = BTreeSet::new();
        let mut insert = |value: &ConsensusValue| {
            digests.insert(value.digest());
            Ok(())
        };
        if let Some(proposal) = self.current_proposal()? {
            if let Some(proof) = &proposal.proof_of_lock {
                insert(proof.value())?;
            }
            if let Some(certificate) = &proposal.view_change {
                visit_view_certificate_values(&self.context, certificate, &mut insert)?;
            }
        }
        for certificate in [&self.locked, &self.highest_prepared].into_iter().flatten() {
            insert(certificate.value())?;
        }
        if let Some(certificate) = &self.committed {
            insert(certificate.value())?;
        }
        if let Some(certificate) = &self.view_certificate {
            visit_view_certificate_values(&self.context, certificate, &mut insert)?;
        }
        for envelope in self.next_view_changes.values() {
            let message = decode_signed_message(&self.context, envelope)?;
            let ConsensusMessageBody::ViewChange(change) = message.body else {
                return Err(ConsensusError::InvalidPersistedState(
                    "stored view change has the wrong phase",
                ));
            };
            if let Some(prepared) = change.highest_prepared {
                insert(prepared.value())?;
            }
        }
        Ok(digests)
    }

    /// Atomically narrow a restricted signing policy to values still referenced by live reducer
    /// state.
    ///
    /// Restricted allowlists are a signing-safety boundary, but monotonic growth across
    /// arbitrarily many pre-GST views would eventually turn their resource cap into a liveness
    /// failure. The keep-set covers every full application value plus digest-only current-view
    /// votes. Prepare/commit certificates, locks, the local candidate and view certificates are
    /// therefore preserved. Equivocation evidence is diagnostic rather than safety state; evidence
    /// which alone references a retired value is dropped before the allowlist is narrowed.
    ///
    /// The update is performed on a clone and installed only after the complete reducer and signing
    /// policy revalidate, so malformed state cannot be partially pruned.
    pub(crate) fn prune_restricted_authorized_value_digests(
        &mut self,
    ) -> Result<Option<BTreeSet<ConsensusValueDigest>>, ConsensusError> {
        if matches!(self.signing_policy, ConsensusSigningPolicy::FullOnly) {
            return Ok(None);
        }
        if !self.started {
            return Err(ConsensusError::InvalidPersistedState(
                "cannot prune an unstarted restricted reducer",
            ));
        }

        let mut candidate = self.clone();
        let mut reachable = BTreeSet::new();
        candidate.validate_application_values(|value| {
            reachable.insert(value.digest());
            true
        })?;
        for (expected_prevote, envelopes) in
            [(true, &candidate.prevotes), (false, &candidate.precommits)]
        {
            for envelope in envelopes.values() {
                let message = decode_signed_message(&candidate.context, envelope)?;
                match message.body {
                    ConsensusMessageBody::Prevote(vote) if expected_prevote => {
                        reachable.insert(vote.value);
                    }
                    ConsensusMessageBody::Precommit(vote) if !expected_prevote => {
                        reachable.insert(vote.value);
                    }
                    _ => {
                        return Err(ConsensusError::InvalidPersistedState(
                            "stored vote has the wrong phase",
                        ));
                    }
                }
            }
        }
        if reachable.is_empty() {
            return Err(ConsensusError::InvalidPersistedState(
                "started restricted reducer has no reachable value",
            ));
        }

        let mut retained_evidence = VecDeque::new();
        for evidence in &candidate.evidence {
            let mut referenced = BTreeSet::new();
            for envelope in [&evidence.first, &evidence.conflicting] {
                let message = decode_signed_message(&candidate.context, envelope)?;
                validate_message_application_values(
                    &candidate.context,
                    &message.body,
                    &mut |value| {
                        referenced.insert(value.digest());
                        true
                    },
                )?;
                match message.body {
                    ConsensusMessageBody::Prevote(vote) | ConsensusMessageBody::Precommit(vote) => {
                        referenced.insert(vote.value);
                    }
                    ConsensusMessageBody::Proposal(_) | ConsensusMessageBody::ViewChange(_) => {}
                }
            }
            if referenced.is_subset(&reachable) {
                retained_evidence.push_back(evidence.clone());
            }
        }
        candidate.evidence = retained_evidence;

        match &mut candidate.signing_policy {
            ConsensusSigningPolicy::RecoveryAndFenceOnly {
                recovery_values, fence_values, ..
            } => {
                recovery_values.retain(|digest| reachable.contains(digest));
                fence_values.retain(|digest| reachable.contains(digest));
                let authorized =
                    recovery_values.union(fence_values).copied().collect::<BTreeSet<_>>();
                if authorized != reachable {
                    return Err(ConsensusError::InvalidRecoveryAndFenceSigningPolicy);
                }
            }
            ConsensusSigningPolicy::HandoffOnly { authorized_values, .. } => {
                authorized_values.retain(|digest| reachable.contains(digest));
                if *authorized_values != reachable {
                    return Err(ConsensusError::InvalidHandoffSigningPolicy);
                }
            }
            ConsensusSigningPolicy::FullOnly => unreachable!("checked above"),
        }
        candidate.validate_signing_policy_state()?;
        *self = candidate;
        Ok(Some(reachable))
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
        self.validate_signing_policy_state()?;
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
        identity: &dyn EnvelopeSigner,
        candidate: ConsensusValue,
    ) -> Result<ConsensusStep, ConsensusError> {
        if self.started {
            return Err(ConsensusError::AlreadyStarted);
        }
        self.ensure_identity(identity)?;
        self.signing_policy.ensure_value(&candidate)?;
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
        identity: &dyn EnvelopeSigner,
    ) -> Result<ConsensusStep, ConsensusError> {
        self.ensure_live()?;
        self.ensure_identity(identity)?;
        let mut step = ConsensusStep::default();
        if !self.emit_local_view_change(identity, &mut step)? {
            return Ok(ConsensusStep { duplicate: true, ..ConsensusStep::default() });
        }
        self.maybe_enter_next_view(identity, &mut step)?;
        self.check_outbound(&step)?;
        Ok(step)
    }

    /// Authenticate and reduce a message after the caller has independently established that all
    /// canonical values are application-valid. Prefer [`Self::handle_with_value_validator`] at
    /// untrusted ingress.
    pub fn handle_structurally_valid(
        &mut self,
        identity: &dyn EnvelopeSigner,
        envelope: SignedEnvelope,
    ) -> Result<ConsensusStep, ConsensusError> {
        self.handle_with_value_validator(identity, envelope, |_| true)
    }

    /// Authenticate and reduce a portable message with an application validity predicate.
    pub fn handle_with_value_validator<F>(
        &mut self,
        identity: &dyn EnvelopeSigner,
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
            self.signing_policy.ensure_message_body(&self.context, &message.body)?;
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

    /// Fully authenticate and validate one portable message without applying its temporal state
    /// transition.
    ///
    /// A host may use this only after independently proving that the message is semantically
    /// dominated by durable state. In particular, stale traffic must cross the same leader,
    /// nested-certificate, signing-policy, and application-value checks as live traffic before the
    /// host acknowledges it. Keeping this validation stateless prevents malformed stale messages
    /// from reaching reducer paths whose first operation is a view comparison.
    pub(crate) fn validate_message_ingress_with_value_validator<F>(
        &self,
        envelope: &SignedEnvelope,
        mut validate_value: F,
    ) -> Result<(), ConsensusError>
    where
        F: FnMut(&ConsensusValue) -> bool,
    {
        self.ensure_live()?;
        let message = decode_signed_message(&self.context, envelope)?;
        self.signing_policy.ensure_message_body(&self.context, &message.body)?;
        match &message.body {
            ConsensusMessageBody::Proposal(proposal) => {
                validate_proposal_structure(&self.context, proposal, envelope.from)?;
            }
            ConsensusMessageBody::ViewChange(change) => {
                validate_view_change(&self.context, change)?;
            }
            ConsensusMessageBody::Prevote(_) | ConsensusMessageBody::Precommit(_) => {
                // `decode_signed_message` already applies the bounded-view and nonzero-digest
                // checks required by vote bodies.
            }
        }
        validate_message_application_values(&self.context, &message.body, &mut validate_value)
    }

    /// Fully validate a portable view certificate without applying it to the reducer.
    pub(crate) fn validate_view_certificate_ingress_with_value_validator<F>(
        &self,
        certificate: &ViewChangeCertificate,
        mut validate_value: F,
    ) -> Result<(), ConsensusError>
    where
        F: FnMut(&ConsensusValue) -> bool,
    {
        self.ensure_live()?;
        certificate.verify(&self.context)?;
        self.signing_policy.ensure_view_certificate(&self.context, certificate)?;
        validate_view_certificate_application_values(
            &self.context,
            certificate,
            &mut validate_value,
        )
    }

    /// Whether this is the exact certificate already authenticated in durable reducer state.
    ///
    /// This is deliberately only an equality relation. Alternate quorum subsets must still cross
    /// full ingress validation even when they target the already-installed view.
    pub(crate) fn is_exact_view_certificate_replay(
        &self,
        certificate: &ViewChangeCertificate,
    ) -> bool {
        self.view_certificate.as_ref() == Some(certificate)
    }

    /// Initialize an unstarted reducer from an authenticated, application-valid proposal without
    /// emitting a competing local proposal first.
    ///
    /// The ordinary [`Self::handle_with_value_validator`] path deliberately enforces the host's
    /// persisted pre-proposal acceptance gate. Applications whose proposal value is itself a
    /// complete acceptance proof may opt into this narrower bootstrap path. Non-proposal traffic
    /// still cannot start a reducer, and the trial state is installed only after the complete
    /// proposal (including any view certificate) has passed structural, signature, and
    /// application validation.
    pub fn handle_initial_proposal_with_value_validator<F>(
        &mut self,
        identity: &dyn EnvelopeSigner,
        envelope: SignedEnvelope,
        validate_value: F,
    ) -> Result<ConsensusStep, ConsensusError>
    where
        F: FnMut(&ConsensusValue) -> bool,
    {
        if self.started {
            return self.handle_with_value_validator(identity, envelope, validate_value);
        }
        self.ensure_identity(identity)?;
        let message = decode_signed_message(&self.context, &envelope)?;
        let ConsensusMessageBody::Proposal(proposal) = message.body else {
            return Err(ConsensusError::NotStarted);
        };
        self.signing_policy.ensure_message_body(
            &self.context,
            &ConsensusMessageBody::Proposal(proposal.clone()),
        )?;

        let mut trial = self.clone();
        trial.started = true;
        trial.candidate = Some(proposal.value);
        let step = trial.handle_with_value_validator(identity, envelope, validate_value)?;
        *self = trial;
        Ok(step)
    }

    /// Trusted-ingress convenience wrapper for a structurally valid view certificate. Prefer
    /// [`Self::handle_view_certificate_with_validator`] at untrusted ingress.
    pub fn handle_view_certificate_structurally_valid(
        &mut self,
        identity: &dyn EnvelopeSigner,
        certificate: ViewChangeCertificate,
    ) -> Result<ConsensusStep, ConsensusError> {
        self.handle_view_certificate_with_validator(identity, certificate, |_| true)
    }

    /// Adopt and re-gossip a portable view certificate after validating every application value
    /// carried by its signed view-change witnesses.
    pub fn handle_view_certificate_with_validator<F>(
        &mut self,
        identity: &dyn EnvelopeSigner,
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
        self.signing_policy.ensure_view_certificate(&self.context, &certificate)?;
        if certificate.target_view < self.view {
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
        // Different honest replicas may enter the same view from different valid `n-f` witness
        // subsets. Such a certificate is not an exact replay, so it must cross every expensive
        // cryptographic, signing-policy, and application-value check above. Once verified it is
        // semantically dominated by the already durable current-view certificate and can be
        // acknowledged as a duplicate without replacing that certificate.
        if certificate.target_view == self.view {
            return Ok(ConsensusStep { duplicate: true, ..ConsensusStep::default() });
        }
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
        self.signing_policy.ensure_commit_certificate(&certificate)?;
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
        identity: &dyn EnvelopeSigner,
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
        identity: &dyn EnvelopeSigner,
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

        // Once `f + 1` distinct parties request the next view, at least one requester is honest.
        // Join that request exactly once so asymmetric delivery cannot strand the committee below
        // `n - f`; `f` Byzantine requests alone remain unable to make an honest party leave.
        let amplification_threshold = usize::from(self.context.fault_bound()) + 1;
        if self.next_view_changes.len() >= amplification_threshold {
            self.emit_local_view_change(identity, step)?;
        }
        self.maybe_enter_next_view(identity, step)
    }

    fn emit_local_view_change(
        &mut self,
        identity: &dyn EnvelopeSigner,
        step: &mut ConsensusStep,
    ) -> Result<bool, ConsensusError> {
        let target_view = self.view.checked_add(1).ok_or(ConsensusError::ViewExhausted)?;
        if target_view > MAX_CONSENSUS_VIEW {
            return Err(ConsensusError::ViewExhausted);
        }
        if self.next_view_changes.contains_key(&self.local_party) {
            return Ok(false);
        }
        let change = ViewChange {
            from_view: self.view,
            target_view,
            highest_prepared: self.highest_prepared.clone(),
        };
        let envelope = self.sign_message(identity, ConsensusMessageBody::ViewChange(change))?;
        self.next_view_changes.insert(self.local_party, envelope.clone());
        step.broadcast.push(envelope);
        step.changed = true;
        Ok(true)
    }

    fn maybe_enter_next_view(
        &mut self,
        identity: &dyn EnvelopeSigner,
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
        identity: &dyn EnvelopeSigner,
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
        identity: &dyn EnvelopeSigner,
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
                let envelope =
                    self.sign_message(identity, ConsensusMessageBody::Proposal(proposal))?;
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
                let envelope = self.sign_message(identity, ConsensusMessageBody::Prevote(vote))?;
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
                let envelope =
                    self.sign_message(identity, ConsensusMessageBody::Precommit(vote))?;
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

    fn ensure_identity(&self, identity: &dyn EnvelopeSigner) -> Result<(), ConsensusError> {
        self.signing_policy.ensure_signer(identity)?;
        if identity.party() != self.local_party {
            return Err(ConsensusError::WrongLocalIdentity);
        }
        let member = self.context.committee.member(self.local_party)?;
        if member.signing_key != identity.signing_public_key() {
            return Err(ConsensusError::WrongLocalIdentity);
        }
        Ok(())
    }

    fn sign_message(
        &self,
        identity: &dyn EnvelopeSigner,
        body: ConsensusMessageBody,
    ) -> Result<SignedEnvelope, ConsensusError> {
        self.ensure_identity(identity)?;
        self.signing_policy.ensure_message_body(&self.context, &body)?;
        sign_consensus_message_unchecked(&self.context, identity, body)
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

    fn validate_signing_policy_state(&self) -> Result<(), ConsensusError> {
        self.signing_policy.validate(&self.context)?;
        if let Some(candidate) = &self.candidate {
            self.signing_policy.ensure_value(candidate)?;
        }
        if let Some(proposal) = &self.proposal {
            let message = decode_signed_message(&self.context, proposal)?;
            self.signing_policy.ensure_message_body(&self.context, &message.body)?;
        }
        for envelope in self.prevotes.values().chain(self.precommits.values()) {
            let message = decode_signed_message(&self.context, envelope)?;
            self.signing_policy.ensure_message_body(&self.context, &message.body)?;
        }
        for envelope in self.next_view_changes.values() {
            let message = decode_signed_message(&self.context, envelope)?;
            self.signing_policy.ensure_message_body(&self.context, &message.body)?;
        }
        for certificate in [&self.locked, &self.highest_prepared].into_iter().flatten() {
            self.signing_policy.ensure_prepare_certificate(certificate)?;
        }
        if let Some(certificate) = &self.committed {
            self.signing_policy.ensure_commit_certificate(certificate)?;
        }
        if let Some(certificate) = &self.view_certificate {
            self.signing_policy.ensure_view_certificate(&self.context, certificate)?;
        }
        for evidence in &self.evidence {
            for envelope in [&evidence.first, &evidence.conflicting] {
                let message = decode_signed_message(&self.context, envelope)?;
                self.signing_policy.ensure_message_body(&self.context, &message.body)?;
            }
        }
        Ok(())
    }

    fn validate_restored(&self) -> Result<(), ConsensusError> {
        if self.state_version != CONSENSUS_STATE_VERSION {
            return Err(ConsensusError::InvalidPersistedState(
                "unsupported reducer snapshot version",
            ));
        }
        self.context.validate()?;
        self.signing_policy.validate(&self.context)?;
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
            if self.next_view_changes.len() >= self.context.quorum() {
                return Err(ConsensusError::InvalidPersistedState("unapplied view-change quorum"));
            }
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
            let amplification_threshold = usize::from(self.context.fault_bound()) + 1;
            if self.next_view_changes.len() >= amplification_threshold
                && !self.next_view_changes.contains_key(&self.local_party)
            {
                return Err(ConsensusError::InvalidPersistedState(
                    "amplified view change lacks the local witness",
                ));
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
        self.validate_signing_policy_state()?;
        Ok(())
    }
}

/// Sign one canonical portable message.  Byzantine test harnesses and integration adapters can use
/// this helper without giving the reducer ownership of long-lived identity material.
pub fn sign_consensus_message(
    context: &ConsensusContext,
    identity: &dyn EnvelopeSigner,
    body: ConsensusMessageBody,
) -> Result<SignedEnvelope, ConsensusError> {
    if identity.scope() != EnvelopeSignerScope::Full {
        return Err(ConsensusError::UnauthorizedSignerScope);
    }
    sign_consensus_message_unchecked(context, identity, body)
}

fn sign_consensus_message_unchecked(
    context: &ConsensusContext,
    identity: &dyn EnvelopeSigner,
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
    use crate::{
        committee::Member,
        identity::{StableRecoverySigningIdentity, StableSigningIdentity},
    };

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0x58; 32];
        secret[1..9].copy_from_slice(&epoch.to_le_bytes());
        secret[9..11].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    fn fixtures_with_profile(
        member_count: u16,
        threshold: u16,
        fault_bound: u16,
    ) -> (ConsensusContext, Vec<Identity>) {
        let identities = (1_u16..=member_count)
            .map(|party| {
                let party = PartyId(party);
                let signing_seed = [party.0 as u8; 32];
                Identity::from_test_secrets(party, 7, &signing_seed, test_x25519_secret(party, 7))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let committee = Committee {
            epoch: 7,
            threshold,
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
            fault_bound,
            0,
            1,
            [0; 32],
        )
        .unwrap();
        (context, identities)
    }

    fn fixtures() -> (ConsensusContext, Vec<Identity>) {
        fixtures_with_profile(4, 2, 1)
    }

    fn value(byte: u8) -> ConsensusValue {
        ConsensusValue::new(vec![byte; 16]).unwrap()
    }

    fn stable_signer(context: &ConsensusContext, party: PartyId) -> StableSigningIdentity {
        StableSigningIdentity::for_committee(
            party,
            &[u8::try_from(party.0).unwrap(); 32],
            context.committee(),
        )
        .unwrap()
    }

    fn recovery_signer(
        context: &ConsensusContext,
        party: PartyId,
        authority: [u8; 32],
    ) -> StableRecoverySigningIdentity {
        StableRecoverySigningIdentity::for_certified_transition(
            party,
            &[u8::try_from(party.0).unwrap(); 32],
            context.committee(),
            authority,
        )
        .unwrap()
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

    fn sign_structurally_unchecked_for_test(
        context: &ConsensusContext,
        identity: &Identity,
        body: ConsensusMessageBody,
    ) -> SignedEnvelope {
        let view = body.view();
        let kind = body.kind();
        let payload = postcard::to_allocvec(&ConsensusMessage::new(context, body)).unwrap();
        identity
            .sign_envelope(
                context.committee(),
                context.session(),
                None,
                wire_sequence(context, view, kind).unwrap(),
                payload,
            )
            .unwrap()
    }

    #[test]
    fn generic_reducer_and_public_signing_helper_reject_handoff_only_scope() {
        let (context, identities) = fixtures();
        let leader = context.leader(0);
        let leader_index =
            identities.iter().position(|identity| identity.party() == leader).unwrap();
        let stable = stable_signer(&context, leader);
        let candidate = value(41);
        let body = ConsensusMessageBody::Proposal(Proposal {
            view: 0,
            value: candidate.clone(),
            proof_of_lock: None,
            view_change: None,
        });

        assert_eq!(
            sign_consensus_message(&context, &stable, body),
            Err(ConsensusError::UnauthorizedSignerScope)
        );

        let mut reducer = DepositConsensus::new(context, leader).unwrap();
        assert_eq!(
            reducer.authorize_handoff_value_digests([candidate.digest()]),
            Err(ConsensusError::InvalidHandoffSigningPolicy)
        );
        assert_eq!(reducer.start(&stable, candidate), Err(ConsensusError::UnauthorizedSignerScope));
        assert!(!reducer.started());
        assert!(reducer.start(&identities[leader_index], value(42)).is_ok());
    }

    #[test]
    fn recovery_and_fence_reducer_binds_authority_scope_and_value_classes() {
        let (context, identities) = fixtures();
        let leader = context.leader(0);
        let leader_index =
            identities.iter().position(|identity| identity.party() == leader).unwrap();
        let authority = [0x71; 32];
        let recovery = value(71);
        let fence = value(72);
        let unauthorized = value(73);
        let signer = recovery_signer(&context, leader, authority);
        let wrong_signer = recovery_signer(&context, leader, [0x72; 32]);
        let final_handoff_signer = stable_signer(&context, leader);

        assert_eq!(
            DepositConsensus::new_recovery_and_fence_only(
                context.clone(),
                leader,
                [0; 32],
                [recovery.digest()],
                [fence.digest()],
            ),
            Err(ConsensusError::InvalidRecoveryAndFenceSigningPolicy)
        );
        assert_eq!(
            DepositConsensus::new_recovery_and_fence_only(
                context.clone(),
                leader,
                authority,
                [],
                [],
            ),
            Err(ConsensusError::InvalidRecoveryAndFenceSigningPolicy)
        );

        let new_reducer = || {
            DepositConsensus::new_recovery_and_fence_only(
                context.clone(),
                leader,
                authority,
                [recovery.digest()],
                [fence.digest()],
            )
            .unwrap()
        };
        let mut wrong_authority = new_reducer();
        assert_eq!(
            wrong_authority.start(&wrong_signer, recovery.clone()),
            Err(ConsensusError::UnauthorizedSignerScope)
        );
        let mut wrong_scope = new_reducer();
        assert_eq!(
            wrong_scope.start(&final_handoff_signer, recovery.clone()),
            Err(ConsensusError::UnauthorizedSignerScope)
        );
        let mut unauthorized_value = new_reducer();
        assert_eq!(
            unauthorized_value.start(&signer, unauthorized.clone()),
            Err(ConsensusError::UnauthorizedRecoveryAndFenceValue)
        );

        let mut full_driven = new_reducer();
        assert!(full_driven.start(&identities[leader_index], fence.clone()).is_ok());
        let mut recovery_driven = new_reducer();
        assert!(recovery_driven.start(&signer, recovery.clone()).is_ok());

        let mut expanding = new_reducer();
        expanding.authorize_recovery_value_digests([unauthorized.digest()]).unwrap();
        assert_eq!(
            expanding.recovery_authorized_value_digests(),
            Some(&[recovery.digest(), unauthorized.digest()].into_iter().collect::<BTreeSet<_>>())
        );
        let baseline = expanding.clone();
        assert_eq!(
            expanding.authorize_fence_value_digests([recovery.digest()]),
            Err(ConsensusError::InvalidRecoveryAndFenceSigningPolicy)
        );
        assert_eq!(expanding, baseline);
        assert_eq!(expanding.recovery_authority_digest(), Some(authority));
        assert!(expanding.is_recovery_and_fence_only());
        assert!(!expanding.is_handoff_only());

        let mut handoff =
            DepositConsensus::new_handoff_only(context, leader, [recovery.digest()]).unwrap();
        assert_eq!(
            handoff.authorize_recovery_value_digests([unauthorized.digest()]),
            Err(ConsensusError::InvalidRecoveryAndFenceSigningPolicy)
        );
        assert_eq!(handoff.start(&signer, recovery), Err(ConsensusError::UnauthorizedSignerScope));
    }

    #[test]
    fn recovery_policy_and_certificate_backing_survive_restart() {
        let (context, identities) = fixtures();
        let local_index =
            identities.iter().position(|identity| identity.party() != context.leader(0)).unwrap();
        let local_party = identities[local_index].party();
        let authority = [0x81; 32];
        let recovery = value(81);
        let fence = value(82);
        let signer = recovery_signer(&context, local_party, authority);
        let mut reducer = DepositConsensus::new_recovery_and_fence_only(
            context.clone(),
            local_party,
            authority,
            [recovery.digest()],
            [fence.digest()],
        )
        .unwrap();
        reducer.start(&signer, recovery.clone()).unwrap();

        let prepare = PrepareCertificate::from_witnesses(
            &context,
            0,
            recovery.clone(),
            vote_envelopes(&context, &identities, MessageKind::Prevote, 0, &recovery, &[0, 1, 2]),
        )
        .unwrap();
        let sender_index =
            identities.iter().position(|identity| identity.party() != local_party).unwrap();
        let change = sign_consensus_message(
            &context,
            &identities[sender_index],
            ConsensusMessageBody::ViewChange(ViewChange {
                from_view: 0,
                target_view: 1,
                highest_prepared: Some(prepare),
            }),
        )
        .unwrap();
        reducer.handle_with_value_validator(&signer, change, |_| true).unwrap();
        assert_eq!(
            reducer.certificate_backed_value_digests().unwrap(),
            [recovery.digest()].into_iter().collect()
        );

        let bytes = postcard::to_allocvec(&reducer).unwrap();
        let restored: DepositConsensus = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.recovery_authority_digest(), Some(authority));
        assert_eq!(
            restored.recovery_authorized_value_digests(),
            Some(&[recovery.digest()].into_iter().collect())
        );
        assert_eq!(
            restored.fence_authorized_value_digests(),
            Some(&[fence.digest()].into_iter().collect())
        );
        assert_eq!(
            restored.certificate_backed_value_digests().unwrap(),
            [recovery.digest()].into_iter().collect()
        );
    }

    #[test]
    fn restricted_policy_gc_preserves_live_vote_and_candidate_across_restart() {
        let (context, identities) = fixtures();
        let local_party = context.leader(0);
        let authority = [0x83; 32];
        let candidate = value(83);
        let live_vote = value(84);
        let stale_evidence_only = value(85);
        let signer = recovery_signer(&context, local_party, authority);
        let mut reducer = DepositConsensus::new_recovery_and_fence_only(
            context.clone(),
            local_party,
            authority,
            [candidate.digest()],
            [live_vote.digest(), stale_evidence_only.digest()],
        )
        .unwrap();
        reducer.start(&signer, candidate.clone()).unwrap();

        let voter = identities.iter().find(|identity| identity.party() != local_party).unwrap();
        let live = sign_consensus_message(
            &context,
            voter,
            ConsensusMessageBody::Prevote(Vote { view: 0, value: live_vote.digest() }),
        )
        .unwrap();
        reducer.handle_with_value_validator(&signer, live, |_| true).unwrap();
        let conflicting = sign_consensus_message(
            &context,
            voter,
            ConsensusMessageBody::Prevote(Vote { view: 0, value: stale_evidence_only.digest() }),
        )
        .unwrap();
        reducer.handle_with_value_validator(&signer, conflicting, |_| true).unwrap();
        assert_eq!(reducer.evidence().len(), 1);

        let expected = BTreeSet::from([candidate.digest(), live_vote.digest()]);
        assert_eq!(
            reducer.prune_restricted_authorized_value_digests().unwrap(),
            Some(expected.clone()),
        );
        assert_eq!(
            reducer.recovery_authorized_value_digests(),
            Some(&BTreeSet::from([candidate.digest()])),
        );
        assert_eq!(
            reducer.fence_authorized_value_digests(),
            Some(&BTreeSet::from([live_vote.digest()])),
        );
        assert!(reducer.evidence().is_empty());
        reducer.validate_application_values(|value| expected.contains(&value.digest())).unwrap();

        let bytes = postcard::to_allocvec(&reducer).unwrap();
        let mut restored: DepositConsensus = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored, reducer);
        assert_eq!(restored.prune_restricted_authorized_value_digests().unwrap(), Some(expected),);
    }

    #[test]
    fn handoff_reducer_accepts_only_allowlisted_values_for_full_and_stable_signers() {
        let (context, identities) = fixtures();
        let leader = context.leader(0);
        let leader_index =
            identities.iter().position(|identity| identity.party() == leader).unwrap();
        let stable = stable_signer(&context, leader);
        let allowed = value(51);
        let unauthorized = value(52);

        let mut full_attempt =
            DepositConsensus::new_handoff_only(context.clone(), leader, [allowed.digest()])
                .unwrap();
        assert_eq!(
            full_attempt.start(&identities[leader_index], unauthorized.clone()),
            Err(ConsensusError::UnauthorizedHandoffValue)
        );
        assert!(!full_attempt.started());
        full_attempt.authorize_handoff_value_digests([unauthorized.digest()]).unwrap();
        assert!(full_attempt.start(&identities[leader_index], unauthorized.clone()).is_ok());

        let mut stable_attempt =
            DepositConsensus::new_handoff_only(context, leader, [allowed.digest()]).unwrap();
        assert_eq!(
            stable_attempt.start(&stable, unauthorized),
            Err(ConsensusError::UnauthorizedHandoffValue)
        );
        assert!(!stable_attempt.started());
        let step = stable_attempt.start(&stable, allowed).unwrap();
        assert!(!step.broadcast.is_empty());
    }

    #[test]
    fn handoff_policy_survives_restart_and_rejects_proposals_votes_and_view_proofs() {
        let (context, identities) = fixtures();
        let local_index =
            identities.iter().position(|identity| identity.party() != context.leader(0)).unwrap();
        let local_party = identities[local_index].party();
        let stable = stable_signer(&context, local_party);
        let allowed = value(61);
        let unauthorized = value(62);
        let mut reducer =
            DepositConsensus::new_handoff_only(context.clone(), local_party, [allowed.digest()])
                .unwrap();
        reducer.start(&stable, allowed).unwrap();
        let bytes = postcard::to_allocvec(&reducer).unwrap();
        let mut reducer: DepositConsensus = postcard::from_bytes(&bytes).unwrap();
        assert!(reducer.is_handoff_only());
        let baseline = reducer.clone();

        let leader_index =
            identities.iter().position(|identity| identity.party() == context.leader(0)).unwrap();
        let proposal = sign_consensus_message(
            &context,
            &identities[leader_index],
            ConsensusMessageBody::Proposal(Proposal {
                view: 0,
                value: unauthorized.clone(),
                proof_of_lock: None,
                view_change: None,
            }),
        )
        .unwrap();
        assert_eq!(
            reducer.handle_with_value_validator(&stable, proposal, |_| true),
            Err(ConsensusError::UnauthorizedHandoffValue)
        );
        assert_eq!(reducer, baseline);

        let vote = sign_consensus_message(
            &context,
            &identities[leader_index],
            ConsensusMessageBody::Prevote(Vote { view: 0, value: unauthorized.digest() }),
        )
        .unwrap();
        assert_eq!(
            reducer.handle_with_value_validator(&stable, vote, |_| true),
            Err(ConsensusError::UnauthorizedHandoffValue)
        );
        assert_eq!(reducer, baseline);

        let prepare = PrepareCertificate::from_witnesses(
            &context,
            0,
            unauthorized.clone(),
            vote_envelopes(
                &context,
                &identities,
                MessageKind::Prevote,
                0,
                &unauthorized,
                &[0, 1, 2],
            ),
        )
        .unwrap();
        let direct_view_change = sign_consensus_message(
            &context,
            &identities[leader_index],
            ConsensusMessageBody::ViewChange(ViewChange {
                from_view: 0,
                target_view: 1,
                highest_prepared: Some(prepare.clone()),
            }),
        )
        .unwrap();
        assert_eq!(
            reducer.handle_with_value_validator(&stable, direct_view_change, |_| true),
            Err(ConsensusError::UnauthorizedHandoffValue)
        );
        assert_eq!(reducer, baseline);

        let changes = identities
            .iter()
            .take(context.quorum())
            .map(|identity| {
                sign_consensus_message(
                    &context,
                    identity,
                    ConsensusMessageBody::ViewChange(ViewChange {
                        from_view: 0,
                        target_view: 1,
                        highest_prepared: Some(prepare.clone()),
                    }),
                )
                .unwrap()
            })
            .collect();
        let certificate = ViewChangeCertificate::from_witnesses(&context, 1, changes).unwrap();
        assert_eq!(
            reducer.handle_view_certificate_with_validator(&stable, certificate, |_| true),
            Err(ConsensusError::UnauthorizedHandoffValue)
        );
        assert_eq!(reducer, baseline);
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
        for identity in identities.iter().take(2) {
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
    fn stateless_ingress_fully_validates_dominated_nested_bodies_without_mutation() {
        let (context, identities) = fixtures();
        let candidate = value(71);
        let local = PartyId(4);
        let mut node = DepositConsensus::new(context.clone(), local).unwrap();
        node.start(&identities[3], candidate.clone()).unwrap();
        let certificate = |target_view: u64, highest_prepared: Option<PrepareCertificate>| {
            let witnesses = identities
                .iter()
                .take(context.quorum())
                .map(|identity| {
                    sign_consensus_message(
                        &context,
                        identity,
                        ConsensusMessageBody::ViewChange(ViewChange {
                            from_view: target_view - 1,
                            target_view,
                            highest_prepared: highest_prepared.clone(),
                        }),
                    )
                    .unwrap()
                })
                .collect();
            ViewChangeCertificate::from_witnesses(&context, target_view, witnesses).unwrap()
        };
        let view_one = certificate(1, None);
        for target_view in [1_u64, 2] {
            let entered = node
                .handle_view_certificate_structurally_valid(
                    &identities[3],
                    if target_view == 1 {
                        view_one.clone()
                    } else {
                        certificate(target_view, None)
                    },
                )
                .unwrap()
                .entered_view;
            assert_eq!(entered, Some(target_view));
        }
        assert_eq!(node.view(), 2);
        let baseline = node.clone();

        let leader = context.leader(1);
        let leader_identity =
            identities.iter().find(|identity| identity.party() == leader).unwrap();
        let valid_stale_proposal = sign_consensus_message(
            &context,
            leader_identity,
            ConsensusMessageBody::Proposal(Proposal {
                view: 1,
                value: candidate.clone(),
                proof_of_lock: None,
                view_change: Some(view_one),
            }),
        )
        .unwrap();
        assert_eq!(
            node.validate_message_ingress_with_value_validator(&valid_stale_proposal, |_| false),
            Err(ConsensusError::InvalidApplicationValue)
        );

        let wrong_leader = identities.iter().find(|identity| identity.party() != leader).unwrap();
        let wrong_leader_proposal = sign_consensus_message(
            &context,
            wrong_leader,
            ConsensusMessageBody::Proposal(Proposal {
                view: 1,
                value: candidate.clone(),
                proof_of_lock: None,
                view_change: Some(certificate(1, None)),
            }),
        )
        .unwrap();
        let mut wrong_leader_application_checks = 0;
        assert_eq!(
            node.validate_message_ingress_with_value_validator(&wrong_leader_proposal, |_| {
                wrong_leader_application_checks += 1;
                true
            },),
            Err(ConsensusError::WrongLeader)
        );
        assert_eq!(wrong_leader_application_checks, 0);

        let prepared_zero = PrepareCertificate::from_witnesses(
            &context,
            0,
            candidate.clone(),
            vote_envelopes(&context, &identities, MessageKind::Prevote, 0, &candidate, &[0, 1, 2]),
        )
        .unwrap();
        let valid_stale_change = sign_consensus_message(
            &context,
            &identities[0],
            ConsensusMessageBody::ViewChange(ViewChange {
                from_view: 0,
                target_view: 1,
                highest_prepared: Some(prepared_zero.clone()),
            }),
        )
        .unwrap();
        assert_eq!(
            node.validate_message_ingress_with_value_validator(&valid_stale_change, |_| false),
            Err(ConsensusError::InvalidApplicationValue)
        );

        let prepared_same_view = PrepareCertificate::from_witnesses(
            &context,
            1,
            candidate.clone(),
            vote_envelopes(&context, &identities, MessageKind::Prevote, 1, &candidate, &[0, 1, 2]),
        )
        .unwrap();
        let malformed_stale_change = sign_structurally_unchecked_for_test(
            &context,
            &identities[0],
            ConsensusMessageBody::ViewChange(ViewChange {
                from_view: 0,
                target_view: 1,
                highest_prepared: Some(prepared_same_view),
            }),
        );
        let mut malformed_application_checks = 0;
        assert_eq!(
            node.validate_message_ingress_with_value_validator(&malformed_stale_change, |_| {
                malformed_application_checks += 1;
                true
            },),
            Err(ConsensusError::InvalidCertificate("view change carries a non-prior prepare"))
        );
        assert_eq!(malformed_application_checks, 0);

        let alternate_stale_certificate = certificate(1, Some(prepared_zero));
        assert_eq!(
            node.validate_view_certificate_ingress_with_value_validator(
                &alternate_stale_certificate,
                |_| false,
            ),
            Err(ConsensusError::InvalidApplicationValue)
        );
        assert_eq!(node, baseline);
    }

    #[test]
    fn f_plus_one_view_changes_amplify_once_and_survive_restart() {
        let (context, identities) = fixtures_with_profile(5, 3, 1);
        let local_index = 4;
        let local_party = identities[local_index].party();
        let mut node = DepositConsensus::new(context.clone(), local_party).unwrap();
        node.start(&identities[local_index], value(10)).unwrap();
        let change = |index: usize| {
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
        };
        let first = change(0);
        let second = change(1);
        let third = change(2);

        let below_threshold =
            node.handle_structurally_valid(&identities[local_index], first.clone()).unwrap();
        assert!(below_threshold.changed);
        assert!(below_threshold.broadcast.is_empty());
        assert_eq!(node.view(), 0);
        assert_eq!(node.next_view_changes.len(), usize::from(context.fault_bound()));
        assert!(!node.next_view_changes.contains_key(&local_party));

        let before_duplicate = node.clone();
        let duplicate = node.handle_structurally_valid(&identities[local_index], first).unwrap();
        assert!(duplicate.duplicate);
        assert!(!duplicate.changed);
        assert!(duplicate.broadcast.is_empty());
        assert_eq!(node, before_duplicate);

        let encoded = postcard::to_allocvec(&node).unwrap();
        let mut node: DepositConsensus = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(node, before_duplicate);

        let amplified =
            node.handle_structurally_valid(&identities[local_index], second.clone()).unwrap();
        assert!(amplified.changed);
        assert!(!amplified.duplicate);
        assert_eq!(amplified.broadcast.len(), 1);
        assert_eq!(node.view(), 0);
        assert_eq!(node.next_view_changes.len(), 3);
        let local_change = node.next_view_changes.get(&local_party).unwrap();
        assert_eq!(amplified.broadcast, vec![local_change.clone()]);
        let message = decode_consensus_message(&context, local_change).unwrap();
        assert_eq!(
            message.body,
            ConsensusMessageBody::ViewChange(ViewChange {
                from_view: 0,
                target_view: 1,
                highest_prepared: None,
            })
        );

        let mut invalid_snapshot = node.clone();
        invalid_snapshot.next_view_changes.remove(&local_party);
        let encoded = postcard::to_allocvec(&invalid_snapshot).unwrap();
        assert!(postcard::from_bytes::<DepositConsensus>(&encoded).is_err());

        let mut unapplied_quorum = node.clone();
        unapplied_quorum.next_view_changes.insert(third.from, third.clone());
        let encoded = postcard::to_allocvec(&unapplied_quorum).unwrap();
        assert!(postcard::from_bytes::<DepositConsensus>(&encoded).is_err());

        let encoded = postcard::to_allocvec(&node).unwrap();
        let mut restored: DepositConsensus = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(restored, node);
        let before_duplicate = restored.clone();
        let duplicate =
            restored.handle_structurally_valid(&identities[local_index], second).unwrap();
        assert!(duplicate.duplicate);
        assert!(!duplicate.changed);
        assert!(duplicate.broadcast.is_empty());
        assert_eq!(restored, before_duplicate);

        let entered = restored.handle_structurally_valid(&identities[local_index], third).unwrap();
        assert_eq!(entered.entered_view, Some(1));
        assert!(entered.relay_view_certificate.is_some());
        assert_eq!(restored.view(), 1);
        assert!(restored.next_view_changes.is_empty());
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
    fn explicit_initial_proposal_bootstrap_preserves_the_default_acceptance_gate() {
        let (context, identities) = fixtures();
        let candidate = value(13);
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

        let mut ordinary = DepositConsensus::new(context.clone(), PartyId(3)).unwrap();
        assert_eq!(
            ordinary.handle_with_value_validator(&identities[2], proposal.clone(), |_| true),
            Err(ConsensusError::NotStarted)
        );
        assert!(!ordinary.started());

        let mut rejected = DepositConsensus::new(context.clone(), PartyId(3)).unwrap();
        assert_eq!(
            rejected.handle_initial_proposal_with_value_validator(
                &identities[2],
                proposal.clone(),
                |_| false,
            ),
            Err(ConsensusError::InvalidApplicationValue)
        );
        assert!(!rejected.started());

        let mut bootstrapped = DepositConsensus::new(context, PartyId(3)).unwrap();
        let step = bootstrapped
            .handle_initial_proposal_with_value_validator(&identities[2], proposal, |value| {
                value == &candidate
            })
            .unwrap();
        assert!(bootstrapped.started());
        assert!(step.changed);
        assert!(step.broadcast.iter().any(|envelope| matches!(
            decode_consensus_message(bootstrapped.context(), envelope).unwrap().body,
            ConsensusMessageBody::Prevote(_)
        )));
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
        node.start(&identities[2], candidate.clone()).unwrap();
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

        // Another valid quorum subset is logically related but not an exact replay. It must cross
        // full certificate and nested application validation before it can be treated as a
        // semantic duplicate of the already installed current-view authority.
        let alternate_prepare = PrepareCertificate::from_witnesses(
            &context,
            0,
            candidate.clone(),
            vote_envelopes(&context, &identities, MessageKind::Prevote, 0, &candidate, &[0, 1, 2]),
        )
        .unwrap();
        let alternate_changes = [0_usize, 1, 3]
            .into_iter()
            .enumerate()
            .map(|(position, index)| {
                sign_consensus_message(
                    &context,
                    &identities[index],
                    ConsensusMessageBody::ViewChange(ViewChange {
                        from_view: 0,
                        target_view: 1,
                        highest_prepared: (position == 0).then(|| alternate_prepare.clone()),
                    }),
                )
                .unwrap()
            })
            .collect();
        let alternate =
            ViewChangeCertificate::from_witnesses(&context, 1, alternate_changes).unwrap();
        let _ = take_view_certificate_verifications();
        let mut alternate_values = 0;
        let semantic_replay = restored
            .handle_view_certificate_with_validator(&identities[2], alternate, |value| {
                alternate_values += 1;
                value == &candidate
            })
            .unwrap();
        assert!(semantic_replay.duplicate);
        assert!(!semantic_replay.changed);
        assert_eq!(alternate_values, 1);
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
        leader.replace_candidate(&identities[1], value(100)).unwrap();
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
    fn replacing_fallback_preserves_signed_state_and_waits_for_a_new_view() {
        let (context, identities) = fixtures();
        let mut leader = DepositConsensus::new(context.clone(), PartyId(1)).unwrap();
        leader.start(&identities[0], value(8)).unwrap();
        let proposal = leader.proposal.clone();
        let votes = leader.prevotes.clone();
        leader.replace_candidate(&identities[0], value(9)).unwrap();
        assert_eq!(leader.proposal, proposal);
        assert_eq!(leader.prevotes, votes);
        let restarted: DepositConsensus =
            postcard::from_bytes(&postcard::to_allocvec(&leader).unwrap()).unwrap();
        assert_eq!(restarted.candidate(), Some(&value(9)));
        assert_eq!(restarted.proposal, proposal);

        let mut next = DepositConsensus::new(context.clone(), PartyId(2)).unwrap();
        next.start(&identities[1], value(8)).unwrap();
        next.replace_candidate(&identities[1], value(9)).unwrap();
        let changes = identities
            .iter()
            .take(3)
            .map(|identity| {
                sign_consensus_message(
                    &context,
                    identity,
                    ConsensusMessageBody::ViewChange(ViewChange {
                        from_view: 0,
                        target_view: 1,
                        highest_prepared: None,
                    }),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let certificate = ViewChangeCertificate::from_witnesses(&context, 1, changes).unwrap();
        let step = next
            .handle_view_certificate_with_validator(&identities[1], certificate, |_| true)
            .unwrap();
        assert!(step.broadcast.iter().any(|envelope| {
            matches!(decode_consensus_message(&context, envelope).unwrap().body,
                ConsensusMessageBody::Proposal(proposal) if proposal.value == value(9))
        }));
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
