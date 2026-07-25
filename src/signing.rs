//! One-party wrapper around monero-oxide's FROSTLASS transaction signer.
//!
//! The underlying implementation creates one threshold CLSAG for every input. It deliberately
//! does not accept an application message: the Monero transaction signature hash is calculated
//! only after the parties' key-image shares and pseudo-output masks have been combined.
//!
//! [`AwaitingCommitments`], [`AwaitingAuthorization`], and [`AwaitingShares`] are linear,
//! in-memory states. None is serializable or cloneable. In particular, dropping either of the
//! first two states aborts the attempt and burns its nonce material. The authorization state
//! exposes the exact unsigned Monero transaction without calculating a signature share, allowing
//! the application to certify its transaction family before share release. The caller must
//! authenticate messages, bind them to a unique protocol session, and durably record that a
//! preprocess has been spent before sending it. monero-oxide intentionally does not support
//! caching/restoring transaction preprocesses.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    io::{Cursor, Write},
};

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar, traits::Identity};
use frost::{
    FrostError, Participant, ThresholdKeys,
    curve::{Ciphersuite, Ed25519, Group},
    dkg::Interpolation,
    sign::{PreprocessMachine, SignMachine, SignatureMachine, Writable},
};
use monero_oxide::{ed25519::CompressedPoint, transaction::Transaction};
use monero_wallet::send::{
    SendError, SignableTransaction, TransactionBoundSignMachine, TransactionSignMachine,
    TransactionSignatureMachine,
};
use rand_core::{CryptoRng, RngCore};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::committee::{Committee, CommitteeError, PartyId, SessionId};

type FrostScalar = <Ed25519 as Ciphersuite>::F;
type FrostPoint = <Ed25519 as Ciphersuite>::G;

/// Hard ceiling for one serialized FROSTLASS round message.
///
/// A valid `SignableTransaction` is limited to less than 150 KiB by monero-wallet. Even at the
/// maximum possible input density its fixed-size FROSTLASS data remains comfortably below this
/// ceiling. The state machine additionally requires every peer message to have exactly the same
/// length as its locally generated message.
pub const MAX_FROSTLASS_MESSAGE_BYTES: usize = 1024 * 1024;

/// Exact number of bytes in one input's current FROSTLASS round-one encoding.
///
/// The vendored `TransactionSignMachine::read_preprocess` reads, in order, four FROST nonce
/// commitment points, one CLSAG key-image-share point, two Chaum-Pedersen proof points, and one
/// proof scalar. Every field is a canonical 32-byte Ed25519 encoding.
pub const FROSTLASS_PREPROCESS_BYTES_PER_INPUT: usize = 8 * 32;

/// Exact round-one byte length for an authorized input count, if it fits the wire ceiling.
#[must_use]
pub fn expected_frostlass_preprocess_bytes(input_count: u32) -> Option<usize> {
    let input_count = usize::try_from(input_count).ok()?;
    let bytes = input_count.checked_mul(FROSTLASS_PREPROCESS_BYTES_PER_INPUT)?;
    (input_count != 0 && bytes <= MAX_FROSTLASS_MESSAGE_BYTES).then_some(bytes)
}

/// Raw FROSTLASS round-one bytes.
///
/// The bytes are specific to one `SignableTransaction` and one invocation of `start`. They must
/// be carried inside the application's authenticated, session-bound envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PreprocessMessage(Vec<u8>);

impl<'de> Deserialize<'de> for PreprocessMessage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_capped_bytes(deserializer, "a FROSTLASS preprocess").map(PreprocessMessage)
    }
}

impl PreprocessMessage {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for PreprocessMessage {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Parse the complete fixed-shape FROSTLASS preprocess before durable network retention.
///
/// `monero-wallet` exposes its canonical parser only through the live, non-serializable
/// `TransactionSignMachine`. The durable ingress reducer nevertheless knows the exact authorized
/// input count. This parser mirrors the vendored reader's structural rules without attempting the
/// transaction- and verification-share-bound Chaum-Pedersen equations; those remain enforced by
/// [`AwaitingCommitments::bind_transaction_bound`] before any signature share is released.
///
/// In particular, the four FROST nonce commitments are canonical prime-subgroup, non-identity
/// points, while the key-image share and proof points are canonical torsion-free Edwards points.
/// The proof response must be a canonical scalar and no trailing bytes are permitted.
pub fn validate_frostlass_preprocess_shape(
    party: PartyId,
    message: &PreprocessMessage,
    input_count: u32,
) -> Result<usize, SigningError> {
    let expected =
        expected_frostlass_preprocess_bytes(input_count).ok_or(SigningError::MessageTooLarge {
            party,
            kind: SigningMessageKind::Preprocess,
            maximum: MAX_FROSTLASS_MESSAGE_BYTES,
            actual: usize::try_from(input_count)
                .ok()
                .and_then(|count| count.checked_mul(FROSTLASS_PREPROCESS_BYTES_PER_INPUT))
                .unwrap_or(usize::MAX),
        })?;
    if message.as_bytes().len() != expected {
        return Err(SigningError::WrongMessageLength {
            party,
            kind: SigningMessageKind::Preprocess,
            expected,
            actual: message.as_bytes().len(),
        });
    }

    for input in message.as_bytes().chunks_exact(FROSTLASS_PREPROCESS_BYTES_PER_INPUT) {
        // The first four fields are read through modular-frost's `Curve::read_G`, which adds an
        // identity rejection to the ciphersuite's canonical prime-subgroup point decoder.
        for field in 0..7 {
            let offset = field * 32;
            let encoding: [u8; 32] =
                input[offset..offset + 32].try_into().expect("fixed-size preprocess chunk");
            let point = CompressedEdwardsY(encoding)
                .decompress()
                .filter(|point| point.is_torsion_free() && point.compress().to_bytes() == encoding)
                .ok_or_else(|| SigningError::MalformedMessage {
                    party,
                    kind: SigningMessageKind::Preprocess,
                    source: std::io::Error::other("invalid or non-canonical Ed25519 point"),
                })?;
            if field < 4
                && point == <curve25519_dalek::edwards::EdwardsPoint as Identity>::identity()
            {
                return Err(SigningError::MalformedMessage {
                    party,
                    kind: SigningMessageKind::Preprocess,
                    source: std::io::Error::other("identity FROST nonce commitment"),
                });
            }
        }

        let response: [u8; 32] =
            input[7 * 32..8 * 32].try_into().expect("fixed-size preprocess chunk");
        if Option::<Scalar>::from(Scalar::from_canonical_bytes(response)).is_none() {
            return Err(SigningError::MalformedMessage {
                party,
                kind: SigningMessageKind::Preprocess,
                source: std::io::Error::other("non-canonical key-image proof scalar"),
            });
        }
    }
    Ok(expected)
}

/// Raw FROSTLASS round-two signature-share bytes.
///
/// Like [`PreprocessMessage`], this has no authentication of its own and belongs inside the
/// application's signed protocol envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SignatureShareMessage(Vec<u8>);

impl<'de> Deserialize<'de> for SignatureShareMessage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_capped_bytes(deserializer, "a FROSTLASS signature share")
            .map(SignatureShareMessage)
    }
}

impl SignatureShareMessage {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for SignatureShareMessage {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A preprocess explicitly committed to the complete application transcript.
///
/// Its context includes the session ID produced by [`FrostlassSigner::start_in_session`]. The
/// containing transport must still authenticate the sender; the context prevents an authenticated
/// message from being replayed into a different session or transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoundPreprocessMessage {
    context: SigningContext,
    sender: PartyId,
    message: PreprocessMessage,
}

impl BoundPreprocessMessage {
    pub fn context(&self) -> SigningContext {
        self.context
    }

    pub fn sender(&self) -> PartyId {
        self.sender
    }

    pub fn message(&self) -> &PreprocessMessage {
        &self.message
    }

    pub fn into_message(self) -> PreprocessMessage {
        self.message
    }
}

/// A signature share explicitly committed to the complete application transcript.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoundSignatureShareMessage {
    context: SigningContext,
    sender: PartyId,
    message: SignatureShareMessage,
}

impl BoundSignatureShareMessage {
    pub fn context(&self) -> SigningContext {
        self.context
    }

    pub fn sender(&self) -> PartyId {
        self.sender
    }

    pub fn message(&self) -> &SignatureShareMessage {
        &self.message
    }

    pub fn into_message(self) -> SignatureShareMessage {
        self.message
    }
}

/// A canonical, immutable signing subset for one transaction attempt.
///
/// Party IDs are sorted before being translated to the committee's epoch-local FROST indices.
/// The set must contain the local party and at least the committee threshold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalSignerSet {
    parties: Vec<PartyId>,
    participants: BTreeMap<PartyId, Participant>,
}

/// Commitment to the committee, wallet group key, fixed signer set, and complete transaction
/// intent used by a FROSTLASS attempt.
///
/// All parties must compare this value before publishing their preprocess. It does not replace a
/// unique session ID or an explicit configured Monero network/genesis binding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SigningContext([u8; 32]);

impl SigningContext {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl CanonicalSignerSet {
    pub fn new(
        committee: &Committee,
        local_party: PartyId,
        signers: impl IntoIterator<Item = PartyId>,
    ) -> Result<Self, SigningError> {
        committee.validate()?;
        committee.member(local_party)?;

        let mut parties = signers.into_iter().collect::<Vec<_>>();
        parties.sort_unstable();

        if let Some(duplicate) =
            parties.windows(2).find_map(|pair| (pair[0] == pair[1]).then_some(pair[0]))
        {
            return Err(SigningError::DuplicateSigner(duplicate));
        }
        if parties.len() < usize::from(committee.threshold) {
            return Err(SigningError::NotEnoughSigners {
                threshold: committee.threshold,
                provided: parties.len(),
            });
        }
        if parties.len() > committee.members.len() {
            return Err(SigningError::TooManySigners {
                committee: committee.members.len(),
                provided: parties.len(),
            });
        }
        if parties.binary_search(&local_party).is_err() {
            return Err(SigningError::LocalSignerMissing(local_party));
        }

        let mut participants = BTreeMap::new();
        for party in &parties {
            committee.member(*party)?;
            let index = committee.frost_index(*party)?;
            let participant = Participant::new(index)
                .expect("committee FROST indices are non-zero by construction");
            participants.insert(*party, participant);
        }

        Ok(Self { parties, participants })
    }

    pub fn parties(&self) -> &[PartyId] {
        &self.parties
    }

    pub fn participant(&self, party: PartyId) -> Option<Participant> {
        self.participants.get(&party).copied()
    }

    pub fn contains(&self, party: PartyId) -> bool {
        self.participants.contains_key(&party)
    }

    pub fn party_for_participant(&self, participant: Participant) -> Option<PartyId> {
        self.participants
            .iter()
            .find_map(|(party, candidate)| (*candidate == participant).then_some(*party))
    }

    fn peers(&self, local_party: PartyId) -> impl Iterator<Item = PartyId> + '_ {
        self.parties.iter().copied().filter(move |party| *party != local_party)
    }
}

/// The kind of FROSTLASS payload being parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningMessageKind {
    Preprocess,
    SignatureShare,
}

impl fmt::Display for SigningMessageKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preprocess => formatter.write_str("preprocess"),
            Self::SignatureShare => formatter.write_str("signature share"),
        }
    }
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error(
        "threshold-key parameters do not match the committee/local party: expected {expected_t}-of-{expected_n} as participant {expected_i}, got {actual_t}-of-{actual_n} as participant {actual_i}"
    )]
    KeyParameters {
        expected_t: u16,
        expected_n: u16,
        expected_i: Participant,
        actual_t: u16,
        actual_n: u16,
        actual_i: Participant,
    },
    #[error("threshold keys have an application scalar or offset already applied")]
    TweakedThresholdKeys,
    #[error("threshold keys do not use Shamir/Lagrange interpolation")]
    UnsupportedInterpolation,
    #[error("threshold group key is the identity")]
    IdentityGroupKey,
    #[error("threshold group key does not match the expected wallet spend key")]
    WrongGroupKey,
    #[error("local secret share does not match its public verification share")]
    LocalShareMismatch,
    #[error("public verification share {participant} is inconsistent with the sharing polynomial")]
    InconsistentVerificationShare { participant: Participant },
    #[error("signer {0} appears more than once")]
    DuplicateSigner(PartyId),
    #[error("local party {0} is absent from the signing set")]
    LocalSignerMissing(PartyId),
    #[error("not enough signers: threshold {threshold}, provided {provided}")]
    NotEnoughSigners { threshold: u16, provided: usize },
    #[error("too many signers: committee size {committee}, provided {provided}")]
    TooManySigners { committee: usize, provided: usize },
    #[error("unexpected {kind} from party {party}")]
    UnexpectedMessage { party: PartyId, kind: SigningMessageKind },
    #[error("duplicate {kind} from party {party}")]
    DuplicateMessage { party: PartyId, kind: SigningMessageKind },
    #[error("missing {kind} from party {party}")]
    MissingMessage { party: PartyId, kind: SigningMessageKind },
    #[error("malformed {kind} from party {party}: {source}")]
    MalformedMessage {
        party: PartyId,
        kind: SigningMessageKind,
        #[source]
        source: std::io::Error,
    },
    #[error("{kind} from party {party} has {trailing} trailing bytes")]
    TrailingBytes { party: PartyId, kind: SigningMessageKind, trailing: usize },
    #[error("{kind} from party {party} has length {actual}, expected exactly {expected} bytes")]
    WrongMessageLength { party: PartyId, kind: SigningMessageKind, expected: usize, actual: usize },
    #[error("{kind} from party {party} is {actual} bytes, exceeding the {maximum}-byte limit")]
    MessageTooLarge { party: PartyId, kind: SigningMessageKind, maximum: usize, actual: usize },
    #[error("{kind} from party {party} is bound to another signing context")]
    WrongMessageContext { party: PartyId, kind: SigningMessageKind },
    #[error("{kind} was attributed to party {party}, but its bound sender is {bound_sender}")]
    WrongMessageSender { party: PartyId, bound_sender: PartyId, kind: SigningMessageKind },
    #[error("party {party} supplied a cryptographically invalid preprocess")]
    InvalidPreprocess { party: PartyId },
    #[error("party {party} supplied a cryptographically invalid signature share")]
    InvalidSignatureShare { party: PartyId },
    #[error("Monero transaction construction rejected the threshold keys: {0}")]
    Monero(#[from] SendError),
    #[error("FROSTLASS signing failed: {0}")]
    Frost(#[from] FrostError),
}

/// Namespace for starting a one-party FROSTLASS signing state machine.
pub struct FrostlassSigner;

impl FrostlassSigner {
    /// Start a signing attempt whose wire messages are bound to a unique session.
    ///
    /// A session must be durably tombstoned before this method's preprocess is published; retrying
    /// after a crash requires a fresh session and fresh nonce material.
    #[allow(clippy::too_many_arguments)]
    pub fn start_in_session<R: RngCore + CryptoRng>(
        transaction: SignableTransaction,
        keys: ThresholdKeys<Ed25519>,
        committee: &Committee,
        local_party: PartyId,
        signers: impl IntoIterator<Item = PartyId>,
        expected_group_key: [u8; 32],
        session: SessionId,
        rng: &mut R,
    ) -> Result<(AwaitingCommitments, BoundPreprocessMessage), SigningError> {
        validate_threshold_keys(&keys, committee, local_party, expected_group_key)?;
        let signers = CanonicalSignerSet::new(committee, local_party, signers)?;
        let context = signing_context_in_session(
            &transaction,
            committee,
            &signers,
            expected_group_key,
            session,
        );
        let (state, message) =
            Self::start_with_context(transaction, keys, local_party, signers, context, rng)?;
        Ok((state, BoundPreprocessMessage { context, sender: local_party, message }))
    }

    fn start_with_context<R: RngCore + CryptoRng>(
        transaction: SignableTransaction,
        keys: ThresholdKeys<Ed25519>,
        local_party: PartyId,
        signers: CanonicalSignerSet,
        context: SigningContext,
        rng: &mut R,
    ) -> Result<(AwaitingCommitments, PreprocessMessage), SigningError> {
        let machine = transaction.multisig_with_context(keys, context.into_bytes())?;
        let (machine, preprocess) = machine.preprocess(rng);
        let preprocess = PreprocessMessage(preprocess.serialize());
        ensure_message_maximum(
            local_party,
            SigningMessageKind::Preprocess,
            preprocess.as_bytes().len(),
        )?;
        let expected_preprocess_bytes = preprocess.as_bytes().len();

        Ok((
            AwaitingCommitments {
                local_party,
                signers,
                context,
                expected_preprocess_bytes,
                machine,
            },
            preprocess,
        ))
    }
}

/// A transaction-bound state waiting for every other fixed signer's preprocess.
///
/// Calling the binding transition consumes this state even if parsing or proof verification
/// fails. The caller should collect the complete peer set before calling it; an error aborts this
/// signing attempt. There is intentionally no bind-and-release shortcut: applications must
/// inspect and authorize the proof-verified transaction before producing a signature share.
pub struct AwaitingCommitments {
    local_party: PartyId,
    signers: CanonicalSignerSet,
    context: SigningContext,
    expected_preprocess_bytes: usize,
    machine: TransactionSignMachine,
}

impl fmt::Debug for AwaitingCommitments {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwaitingCommitments")
            .field("local_party", &self.local_party)
            .field("signers", &self.signers)
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl AwaitingCommitments {
    pub fn local_party(&self) -> PartyId {
        self.local_party
    }

    pub fn signers(&self) -> &CanonicalSignerSet {
        &self.signers
    }

    pub fn context(&self) -> SigningContext {
        self.context
    }

    /// Validate the session binding and fix the exact unsigned transaction before share release.
    pub fn bind_transaction_bound(
        self,
        messages: impl IntoIterator<Item = (PartyId, BoundPreprocessMessage)>,
    ) -> Result<AwaitingAuthorization, SigningError> {
        let messages = collect_exact_messages(
            &self.signers,
            self.local_party,
            messages,
            SigningMessageKind::Preprocess,
        )?;
        let mut raw = BTreeMap::new();
        for (party, bound) in messages {
            if bound.sender != party {
                return Err(SigningError::WrongMessageSender {
                    party,
                    bound_sender: bound.sender,
                    kind: SigningMessageKind::Preprocess,
                });
            }
            if bound.context != self.context {
                return Err(SigningError::WrongMessageContext {
                    party,
                    kind: SigningMessageKind::Preprocess,
                });
            }
            raw.insert(party, bound.message);
        }
        self.bind_collected(raw)
    }

    fn bind_collected(
        self,
        messages: BTreeMap<PartyId, PreprocessMessage>,
    ) -> Result<AwaitingAuthorization, SigningError> {
        let mut preprocesses = HashMap::with_capacity(messages.len());
        for (party, message) in messages {
            ensure_exact_message_length(
                party,
                SigningMessageKind::Preprocess,
                self.expected_preprocess_bytes,
                message.as_bytes().len(),
            )?;
            let participant = self
                .signers
                .participant(party)
                .expect("messages were restricted to the validated signing set");
            let parsed =
                parse_exact(party, SigningMessageKind::Preprocess, message.as_bytes(), |reader| {
                    self.machine.read_preprocess(reader)
                })?;
            preprocesses.insert(participant, parsed);
        }

        let machine = self
            .machine
            .bind(preprocesses)
            .map_err(|error| map_frost_error(error, &self.signers))?;
        let preview = ProofVerifiedKeyImagePreview {
            context: self.context,
            key_images: machine.key_images().to_vec(),
            unsigned_transaction: machine.transaction().clone(),
            preprocess_set_digest: machine.preprocess_set_digest(),
        };
        Ok(AwaitingAuthorization {
            local_party: self.local_party,
            signers: self.signers,
            context: self.context,
            machine,
            preview,
        })
    }
}

/// Proof that a bound unsigned transaction was derived from a fully verified round-one set.
///
/// This value has no public constructor or deserializer. It can only be obtained from a successful
/// [`AwaitingCommitments::bind_transaction_bound`] transition, after every participant's
/// session/input-bound Chaum-Pedersen key-image-share proof has verified.
#[derive(Clone)]
pub struct ProofVerifiedKeyImagePreview {
    context: SigningContext,
    key_images: Vec<CompressedPoint>,
    unsigned_transaction: Transaction,
    preprocess_set_digest: [u8; 32],
}

impl fmt::Debug for ProofVerifiedKeyImagePreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofVerifiedKeyImagePreview")
            .field("context", &self.context)
            .field("key_image_quantity", &self.key_images.len())
            .field("preprocess_set_digest", &hex::encode(self.preprocess_set_digest))
            .finish_non_exhaustive()
    }
}

impl ProofVerifiedKeyImagePreview {
    pub const fn context(&self) -> SigningContext {
        self.context
    }

    /// Aggregate key images in the prepared transaction's original input order.
    pub fn key_images(&self) -> &[CompressedPoint] {
        &self.key_images
    }

    /// The exact unsigned Monero transaction fixed by the verified preprocess set.
    pub const fn unsigned_transaction(&self) -> &Transaction {
        &self.unsigned_transaction
    }

    /// Digest of the participant-sorted canonical proof-bearing preprocess bytes and context.
    pub const fn preprocess_set_digest(&self) -> [u8; 32] {
        self.preprocess_set_digest
    }
}

/// A transaction-bound state waiting for application consensus before signature-share release.
///
/// The exact preprocess set is held inside the vendored monero-wallet state machine. It cannot be
/// replaced between [`Self::unsigned_transaction`] and [`Self::release_bound_signature_share`].
pub struct AwaitingAuthorization {
    local_party: PartyId,
    signers: CanonicalSignerSet,
    context: SigningContext,
    machine: TransactionBoundSignMachine,
    preview: ProofVerifiedKeyImagePreview,
}

impl fmt::Debug for AwaitingAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwaitingAuthorization")
            .field("local_party", &self.local_party)
            .field("signers", &self.signers)
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl AwaitingAuthorization {
    pub fn local_party(&self) -> PartyId {
        self.local_party
    }

    pub fn signers(&self) -> &CanonicalSignerSet {
        &self.signers
    }

    pub fn context(&self) -> SigningContext {
        self.context
    }

    /// Aggregate key images in the prepared transaction's original input order.
    pub fn key_images(&self) -> &[CompressedPoint] {
        self.preview.key_images()
    }

    /// The exact unsigned transaction fixed by this signing attempt's aggregate key images.
    pub fn unsigned_transaction(&self) -> &Transaction {
        self.preview.unsigned_transaction()
    }

    /// An API-unforgeable receipt for the verified key-image/unsigned-transaction preview.
    pub const fn proof_verified_preview(&self) -> &ProofVerifiedKeyImagePreview {
        &self.preview
    }

    /// Consume the authorization state and calculate this party's signature share.
    ///
    /// Production callers must invoke this only after durably verifying the Byzantine agreement
    /// certificate for the transaction-family and key-image binding.
    fn release_signature_share(
        self,
    ) -> Result<(AwaitingShares, SignatureShareMessage), SigningError> {
        // TransactionSignMachine constructs Monero's signature hash internally. Passing an
        // application message is unsupported; the vendored bound state retains the exact
        // preprocess set validated before authorization.
        let (machine, share) = self
            .machine
            .release_signature_share()
            .map_err(|error| map_frost_error(error, &self.signers))?;
        let share = SignatureShareMessage(share.serialize());
        ensure_message_maximum(
            self.local_party,
            SigningMessageKind::SignatureShare,
            share.as_bytes().len(),
        )?;
        let expected_share_bytes = share.as_bytes().len();
        Ok((
            AwaitingShares {
                local_party: self.local_party,
                signers: self.signers,
                context: self.context,
                expected_share_bytes,
                machine,
            },
            share,
        ))
    }

    /// Release a share carrying the same session and transaction context as the bound state.
    pub fn release_bound_signature_share(
        self,
    ) -> Result<(AwaitingShares, BoundSignatureShareMessage), SigningError> {
        let context = self.context;
        let sender = self.local_party;
        let (state, message) = self.release_signature_share()?;
        Ok((state, BoundSignatureShareMessage { context, sender, message }))
    }
}

/// A state waiting for every other fixed signer's signature share.
///
/// As with round one, completion consumes the state and any error aborts the attempt.
pub struct AwaitingShares {
    local_party: PartyId,
    signers: CanonicalSignerSet,
    context: SigningContext,
    expected_share_bytes: usize,
    machine: TransactionSignatureMachine,
}

impl fmt::Debug for AwaitingShares {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwaitingShares")
            .field("local_party", &self.local_party)
            .field("signers", &self.signers)
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl AwaitingShares {
    pub fn local_party(&self) -> PartyId {
        self.local_party
    }

    pub fn signers(&self) -> &CanonicalSignerSet {
        &self.signers
    }

    pub fn context(&self) -> SigningContext {
        self.context
    }

    /// Validate session/intent binding, verify every share, and return the signed transaction.
    pub fn complete_bound(
        self,
        messages: impl IntoIterator<Item = (PartyId, BoundSignatureShareMessage)>,
    ) -> Result<Transaction, SigningError> {
        let messages = collect_exact_messages(
            &self.signers,
            self.local_party,
            messages,
            SigningMessageKind::SignatureShare,
        )?;
        let mut raw = BTreeMap::new();
        for (party, bound) in messages {
            if bound.sender != party {
                return Err(SigningError::WrongMessageSender {
                    party,
                    bound_sender: bound.sender,
                    kind: SigningMessageKind::SignatureShare,
                });
            }
            if bound.context != self.context {
                return Err(SigningError::WrongMessageContext {
                    party,
                    kind: SigningMessageKind::SignatureShare,
                });
            }
            raw.insert(party, bound.message);
        }
        self.complete_collected(raw)
    }

    fn complete_collected(
        self,
        messages: BTreeMap<PartyId, SignatureShareMessage>,
    ) -> Result<Transaction, SigningError> {
        let mut shares = HashMap::with_capacity(messages.len());
        for (party, message) in messages {
            ensure_exact_message_length(
                party,
                SigningMessageKind::SignatureShare,
                self.expected_share_bytes,
                message.as_bytes().len(),
            )?;
            let participant = self
                .signers
                .participant(party)
                .expect("messages were restricted to the validated signing set");
            let parsed = parse_exact(
                party,
                SigningMessageKind::SignatureShare,
                message.as_bytes(),
                |reader| self.machine.read_share(reader),
            )?;
            shares.insert(participant, parsed);
        }

        self.machine.complete(shares).map_err(|error| map_frost_error(error, &self.signers))
    }
}

/// Return the wallet's untweaked, compressed threshold group key.
pub fn threshold_group_key(keys: &ThresholdKeys<Ed25519>) -> [u8; 32] {
    keys.original_group_key().0.compress().to_bytes()
}

/// Compute a signing-intent commitment bound to one globally unique protocol session.
pub fn signing_context_in_session(
    transaction: &SignableTransaction,
    committee: &Committee,
    signers: &CanonicalSignerSet,
    expected_group_key: [u8; 32],
    session: SessionId,
) -> SigningContext {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/frostlass-context/v2/session-bound");
    hasher.update(&session.0);
    hasher.update(&committee.digest());
    hasher.update(&expected_group_key);
    hasher.update(
        &u32::try_from(signers.parties.len())
            .expect("a committee cannot contain more than u16::MAX parties")
            .to_le_bytes(),
    );
    for party in &signers.parties {
        hasher.update(&party.0.to_le_bytes());
    }
    transaction
        .write(&mut Blake3Writer(&mut hasher))
        .expect("writing to a BLAKE3 hasher cannot fail");
    SigningContext(*hasher.finalize().as_bytes())
}

/// Validate all threshold-key material available to one party before any signing nonce is made.
///
/// Besides checking committee parameters and the local secret/public pair, this verifies that all
/// public shares are evaluations of one polynomial of degree at most `threshold - 1`. This catches
/// malformed key files which `ThresholdKeys::new` can represent but which cannot safely form a
/// consistent signing view.
pub fn validate_threshold_keys(
    keys: &ThresholdKeys<Ed25519>,
    committee: &Committee,
    local_party: PartyId,
    expected_group_key: [u8; 32],
) -> Result<(), SigningError> {
    committee.validate()?;
    committee.member(local_party)?;

    let expected_i = Participant::new(committee.frost_index(local_party)?)
        .expect("committee FROST indices are non-zero by construction");
    let params = keys.params();
    if params.t() != committee.threshold || params.n() != committee.n() || params.i() != expected_i
    {
        return Err(SigningError::KeyParameters {
            expected_t: committee.threshold,
            expected_n: committee.n(),
            expected_i,
            actual_t: params.t(),
            actual_n: params.n(),
            actual_i: params.i(),
        });
    }

    if keys.current_scalar() != FrostScalar::ONE || keys.current_offset() != FrostScalar::ZERO {
        return Err(SigningError::TweakedThresholdKeys);
    }
    if !matches!(keys.interpolation(), Interpolation::Lagrange) {
        return Err(SigningError::UnsupportedInterpolation);
    }

    let group_key = keys.original_group_key();
    if bool::from(group_key.is_identity()) {
        return Err(SigningError::IdentityGroupKey);
    }
    if threshold_group_key(keys) != expected_group_key {
        return Err(SigningError::WrongGroupKey);
    }

    let local_public = <Ed25519 as Ciphersuite>::generator() * **keys.original_secret_share();
    if local_public != keys.original_verification_share(params.i()) {
        return Err(SigningError::LocalShareMismatch);
    }

    for participant in params.all_participant_indexes() {
        if evaluate_verification_polynomial(keys, participant)
            != keys.original_verification_share(participant)
        {
            return Err(SigningError::InconsistentVerificationShare { participant });
        }
    }

    Ok(())
}

fn evaluate_verification_polynomial(keys: &ThresholdKeys<Ed25519>, at: Participant) -> FrostPoint {
    let threshold = keys.params().t();
    let x = FrostScalar::from(u64::from(u16::from(at)));
    let mut value = FrostPoint::identity();

    for i_raw in 1..=threshold {
        let i = Participant::new(i_raw).expect("threshold indices are non-zero");
        let i_scalar = FrostScalar::from(u64::from(i_raw));
        let mut numerator = FrostScalar::ONE;
        let mut denominator = FrostScalar::ONE;

        for j_raw in 1..=threshold {
            if i_raw == j_raw {
                continue;
            }
            let j_scalar = FrostScalar::from(u64::from(j_raw));
            numerator *= x - j_scalar;
            denominator *= i_scalar - j_scalar;
        }

        // All interpolation nodes are distinct u16 values in a field much larger than u16::MAX.
        let coefficient = numerator * denominator.invert();
        value += keys.original_verification_share(i) * coefficient;
    }

    value
}

fn collect_exact_messages<M>(
    signers: &CanonicalSignerSet,
    local_party: PartyId,
    messages: impl IntoIterator<Item = (PartyId, M)>,
    kind: SigningMessageKind,
) -> Result<BTreeMap<PartyId, M>, SigningError> {
    let expected = signers.peers(local_party).collect::<BTreeSet<_>>();
    let mut collected = BTreeMap::new();

    for (party, message) in messages {
        if !expected.contains(&party) {
            return Err(SigningError::UnexpectedMessage { party, kind });
        }
        if collected.insert(party, message).is_some() {
            return Err(SigningError::DuplicateMessage { party, kind });
        }
    }

    for party in expected {
        if !collected.contains_key(&party) {
            return Err(SigningError::MissingMessage { party, kind });
        }
    }

    Ok(collected)
}

fn parse_exact<T>(
    party: PartyId,
    kind: SigningMessageKind,
    bytes: &[u8],
    parse: impl FnOnce(&mut Cursor<&[u8]>) -> std::io::Result<T>,
) -> Result<T, SigningError> {
    let mut reader = Cursor::new(bytes);
    let value = parse(&mut reader).map_err(|source| SigningError::MalformedMessage {
        party,
        kind,
        source,
    })?;
    let consumed = usize::try_from(reader.position())
        .expect("a cursor over a slice cannot consume more than usize::MAX bytes");
    if consumed != bytes.len() {
        return Err(SigningError::TrailingBytes { party, kind, trailing: bytes.len() - consumed });
    }
    Ok(value)
}

fn ensure_message_maximum(
    party: PartyId,
    kind: SigningMessageKind,
    actual: usize,
) -> Result<(), SigningError> {
    if actual > MAX_FROSTLASS_MESSAGE_BYTES {
        return Err(SigningError::MessageTooLarge {
            party,
            kind,
            maximum: MAX_FROSTLASS_MESSAGE_BYTES,
            actual,
        });
    }
    Ok(())
}

fn ensure_exact_message_length(
    party: PartyId,
    kind: SigningMessageKind,
    expected: usize,
    actual: usize,
) -> Result<(), SigningError> {
    ensure_message_maximum(party, kind, actual)?;
    if actual != expected {
        return Err(SigningError::WrongMessageLength { party, kind, expected, actual });
    }
    Ok(())
}

fn map_frost_error(error: FrostError, signers: &CanonicalSignerSet) -> SigningError {
    match error {
        FrostError::InvalidPreprocess(participant) => signers
            .party_for_participant(participant)
            .map_or(SigningError::Frost(error), |party| SigningError::InvalidPreprocess { party }),
        FrostError::InvalidShare(participant) => {
            signers.party_for_participant(participant).map_or(SigningError::Frost(error), |party| {
                SigningError::InvalidSignatureShare { party }
            })
        }
        _ => SigningError::Frost(error),
    }
}

fn deserialize_capped_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
    description: &'static str,
) -> Result<Vec<u8>, D::Error> {
    struct CappedBytesVisitor(&'static str);

    impl<'de> Visitor<'de> for CappedBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{} no longer than {MAX_FROSTLASS_MESSAGE_BYTES} bytes", self.0)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let hint = sequence.size_hint().unwrap_or(0);
            if hint > MAX_FROSTLASS_MESSAGE_BYTES {
                return Err(A::Error::custom(format_args!(
                    "{} is {hint} bytes, exceeding the {MAX_FROSTLASS_MESSAGE_BYTES}-byte limit",
                    self.0
                )));
            }
            let mut bytes = Vec::with_capacity(hint);
            while let Some(byte) = sequence.next_element::<u8>()? {
                if bytes.len() == MAX_FROSTLASS_MESSAGE_BYTES {
                    return Err(A::Error::custom(format_args!(
                        "{} exceeds the {MAX_FROSTLASS_MESSAGE_BYTES}-byte limit",
                        self.0
                    )));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_seq(CappedBytesVisitor(description))
}

struct Blake3Writer<'a>(&'a mut blake3::Hasher);

impl Write for Blake3Writer<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
