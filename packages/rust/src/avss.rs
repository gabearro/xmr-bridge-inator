//! CKLS-style asynchronous verifiable secret sharing over Edwards25519.
//!
//! This module implements one AVSS dealer instance from the point of view of one receiving
//! party. It uses a Feldman commitment matrix instead of the Pedersen matrix in CKLS. That is a
//! deliberate specialization for uniformly random DKG/wallet scalars: integrity follows from the
//! discrete-log assumption, while privacy is computational rather than unconditional.
//!
//! `DealerSend`, `Echo`, and `Ready` contain private polynomial evaluations. Every
//! [`PrivateAvssMessage`] must therefore be authenticated and encrypted to its named recipient by
//! the transport. Echo/Ready messages carry the full matrix and its digest. Together with the
//! transport signature and the rule that an honest party emits at most one Echo and one Ready,
//! this supplies the value binding used by the Bracha-style CKLS message pattern.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::{EdwardsPoint, Scalar, traits::Identity};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    committee::{Committee, CommitteeError, MAX_COMMITTEE_MEMBERS, PartyId, SessionId},
    keys::{
        DealerOutput, KeyError, PointBytes, PolynomialCommitment, ScalarBytes, scalar_for_party,
    },
    storage::MAX_SESSION_STATE_BYTES,
};

/// Domain separator for the canonical commitment-matrix digest.
const MATRIX_DIGEST_DOMAIN: &str = "threshold-monero/ckls-feldman-matrix/v1";

/// Maximum eligible dealers retained in one durable AVSS transition.
///
/// Like [`MAX_COMMITTEE_MEMBERS`], this is an engineering resource bound rather than a
/// cryptographic limit.
pub const MAX_AVSS_DEALERS: usize = MAX_COMMITTEE_MEMBERS;

/// Authenticated QUIC's request-body ceiling. AVSS reserves 64 KiB for the transition, signed
/// envelope, ciphertext metadata, and canonical container overhead around its plaintext message.
pub const MAX_AVSS_WIRE_BODY_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_AVSS_WIRE_PLAINTEXT_BYTES: usize = MAX_AVSS_WIRE_BODY_BYTES - 64 * 1024;

/// Conservative checked resource estimate for an accepted AVSS transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvssResourceBounds {
    /// Upper bound for one canonical plaintext [`AvssMessage`].
    pub maximum_wire_message_bytes: usize,
    /// Conservative upper estimate for the complete durable multi-dealer session.
    pub maximum_persisted_session_bytes: usize,
}

/// Security and routing parameters for one per-dealer AVSS instance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AvssConfig {
    pub session: SessionId,
    /// The dealer may be outside `receivers` during an old-to-new committee transition.
    pub dealer: PartyId,
    pub receivers: Committee,
    /// Configured Byzantine bound. This is deliberately not inferred from `n`.
    pub fault_bound: u16,
}

/// Compact identifier repeated inside every private payload.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct AvssInstanceId {
    pub session: SessionId,
    pub dealer: PartyId,
    pub receiver_committee: [u8; 32],
    pub receiver_epoch: u64,
    pub threshold: u16,
    pub fault_bound: u16,
}

/// Digest of a canonical Feldman commitment matrix.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommitmentDigest(pub [u8; 32]);

/// Row-major coefficient commitments, where `(x_degree, y_degree)` commits to
/// `F[x_degree, y_degree]`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitmentMatrix {
    threshold: u16,
    coefficients: Vec<PointBytes>,
}

/// The two univariate polynomials privately sent by the dealer to one receiver.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DealerPolynomials {
    /// Coefficients of `F(receiver, y)` in increasing powers of `y`.
    pub row: Vec<ScalarBytes>,
    /// Coefficients of `F(x, receiver)` in increasing powers of `x`.
    pub column: Vec<ScalarBytes>,
}

/// The two overlap values sent privately from one receiver to another.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CrossValues {
    /// `F(sender, recipient)`.
    pub sender_recipient: ScalarBytes,
    /// `F(recipient, sender)`.
    pub recipient_sender: ScalarBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AvssPayload {
    DealerSend(DealerPolynomials),
    Echo(CrossValues),
    Ready(CrossValues),
}

/// Self-describing wire payload. The outer transport must additionally bind sender and recipient.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AvssMessage {
    pub instance: AvssInstanceId,
    pub commitment_digest: CommitmentDigest,
    pub commitment: CommitmentMatrix,
    pub payload: AvssPayload,
}

/// An AVSS payload that must be encrypted independently for `recipient`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateAvssMessage {
    pub recipient: PartyId,
    pub message: AvssMessage,
}

/// A completed local AVSS output and the authenticated Ready senders that justified completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AvssOutput {
    pub instance: AvssInstanceId,
    pub recipient: PartyId,
    /// `F(recipient, 0)`.
    pub share: ScalarBytes,
    /// Commitments `F[a, 0] * G`, used by `keys.rs` to verify and aggregate the sharing.
    pub x_axis_commitment: PolynomialCommitment,
    pub commitment_digest: CommitmentDigest,
    pub ready_senders: BTreeSet<PartyId>,
}

impl AvssOutput {
    #[must_use]
    pub fn dealer_output(&self) -> DealerOutput {
        DealerOutput {
            dealer: self.instance.dealer,
            share: self.share.clone(),
            commitment: self.x_axis_commitment.clone(),
        }
    }
}

/// Effects produced by accepting one authenticated inbound message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AvssStep {
    pub outbound: Vec<PrivateAvssMessage>,
    /// Set only on the transition that first completes the instance.
    pub completed: Option<AvssOutput>,
    pub duplicate: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvssMessageKind {
    DealerSend,
    Echo,
    Ready,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AvssError {
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("key/curve encoding error: {0}")]
    Key(#[from] KeyError),
    #[error("AVSS dealer identifier must be non-zero")]
    ZeroDealer,
    #[error("invalid asynchronous fault bound: n={n}, f={fault_bound}; require n >= 3f + 1")]
    InvalidFaultBound { n: u16, fault_bound: u16 },
    #[error(
        "invalid AVSS threshold: n={n}, f={fault_bound}, k={threshold}; require f < k <= n - 2f"
    )]
    InvalidThreshold { n: u16, fault_bound: u16, threshold: u16 },
    #[error("local party {0} is not an AVSS receiver")]
    UnknownLocalParty(PartyId),
    #[error("message belongs to another AVSS instance")]
    WrongInstance,
    #[error("DealerSend came from {actual}, expected dealer {expected}")]
    WrongDealer { expected: PartyId, actual: PartyId },
    #[error("Echo/Ready sender {0} is not in the receiver committee")]
    UnknownSender(PartyId),
    #[error("commitment matrix has the wrong dimensions")]
    WrongMatrixDimensions,
    #[error("commitment matrix digest does not match its contents")]
    WrongCommitmentDigest,
    #[error("two different matrices produced the same digest")]
    CommitmentDigestCollision,
    #[error("dealer polynomial has the wrong number of coefficients")]
    WrongPolynomialLength,
    #[error("dealer row/column is not consistent with the commitment matrix")]
    InvalidDealerPolynomials,
    #[error("Echo/Ready overlap values are not consistent with the commitment matrix")]
    InvalidCrossValues,
    #[error("dealer equivocated between commitment matrices")]
    DealerEquivocation,
    #[error("sender {sender} equivocated in {kind:?}")]
    SenderEquivocation { sender: PartyId, kind: AvssMessageKind },
    #[error("valid Ready certificates conflict, violating the AVSS agreement invariant")]
    ConflictingReadyCertificate,
    #[error("not enough points to interpolate a threshold polynomial")]
    InsufficientPoints,
    #[error("interpolation produced a polynomial inconsistent with the commitment matrix")]
    InvalidRecoveredPolynomials,
    #[error("persisted AVSS state violates an invariant: {0}")]
    InvalidPersistedState(&'static str),
    #[error("AVSS transition has {dealers} dealers; maximum is {maximum}")]
    TooManyDealers { dealers: usize, maximum: usize },
    #[error("AVSS resource-bound arithmetic overflowed")]
    ResourceBoundOverflow,
    #[error("AVSS plaintext message needs at most {actual} bytes; maximum is {maximum}")]
    MessageResourceBound { actual: usize, maximum: usize },
    #[error("AVSS durable session needs at most {actual} bytes; maximum is {maximum}")]
    SessionResourceBound { actual: usize, maximum: usize },
}

/// Preflight all allocation-driving AVSS dimensions with checked arithmetic.
///
/// The persisted estimate covers all dealer receiver machines, the maximum distinct commitment
/// candidates permitted by the one-Echo/one-Ready sender indexes, AVSS retry/outbox wire copies,
/// and a separate conservative allowance for QUAL and fixed run metadata. The server still checks
/// the exact canonical encoded run immediately before every durable write; this preflight keeps
/// reaching that final fence from requiring an attacker-controlled large allocation.
pub fn preflight_avss_resources(
    receivers: &Committee,
    dealer_count: usize,
) -> Result<AvssResourceBounds, AvssError> {
    receivers.validate()?;
    if dealer_count == 0 || dealer_count > MAX_AVSS_DEALERS {
        return Err(AvssError::TooManyDealers { dealers: dealer_count, maximum: MAX_AVSS_DEALERS });
    }

    let n = receivers.members.len();
    let threshold = usize::from(receivers.threshold);
    let matrix = checked_add(64, checked_mul(32, checked_mul(threshold, threshold)?)?)?;
    let dealer_polynomials = checked_add(64, checked_mul(64, threshold)?)?;
    let maximum_wire_message_bytes = checked_add(512, checked_add(matrix, dealer_polynomials)?)?;
    if maximum_wire_message_bytes > MAX_AVSS_WIRE_PLAINTEXT_BYTES {
        return Err(AvssError::MessageResourceBound {
            actual: maximum_wire_message_bytes,
            maximum: MAX_AVSS_WIRE_PLAINTEXT_BYTES,
        });
    }

    // A sender can bind at most one Echo digest and one Ready digest. Including the dealer's
    // candidate therefore admits no more than `2n + 1` distinct matrices per receiver machine.
    let candidates_per_receiver = checked_add(checked_mul(2, n)?, 1)?;
    let candidate = checked_add(
        256,
        checked_add(
            matrix,
            checked_add(checked_mul(2, dealer_polynomials)?, checked_mul(128, n)?)?,
        )?,
    )?;
    let receiver_state = checked_add(
        checked_mul(candidates_per_receiver, candidate)?,
        checked_add(checked_mul(512, n)?, 4 * 1024)?,
    )?;
    let all_receiver_states = checked_mul(dealer_count, receiver_state)?;

    // At most one local Echo and Ready fan-out is retained per dealer. The response cache can
    // retain the same two fan-outs, plus one dealer-send fan-out for a local dealer.
    let retained_avss_wires =
        checked_add(checked_mul(4, checked_mul(dealer_count, n)?)?, checked_mul(2, n)?)?;
    let sealed_wire_allowance = checked_add(maximum_wire_message_bytes, 256)?;
    let retained_wire_bytes = checked_mul(retained_avss_wires, sealed_wire_allowance)?;

    // QUAL's current-round maps/witnesses are O(n^2), delivery and signed-wire caches retain at
    // most one value per sender and semantic kind, and diagnostic evidence is committee-bounded.
    // Two MiB conservatively covers those signed envelopes and response/outbox copies at n <= 10.
    let qual_and_witness_bytes =
        checked_add(checked_mul(4 * 1024, checked_mul(n, n)?)?, 2 * 1024 * 1024)?;
    let fixed_run_bytes = 512 * 1024;
    let maximum_persisted_session_bytes = checked_add(
        checked_add(all_receiver_states, retained_wire_bytes)?,
        checked_add(qual_and_witness_bytes, fixed_run_bytes)?,
    )?;
    if maximum_persisted_session_bytes > MAX_SESSION_STATE_BYTES {
        return Err(AvssError::SessionResourceBound {
            actual: maximum_persisted_session_bytes,
            maximum: MAX_SESSION_STATE_BYTES,
        });
    }

    Ok(AvssResourceBounds { maximum_wire_message_bytes, maximum_persisted_session_bytes })
}

fn checked_add(left: usize, right: usize) -> Result<usize, AvssError> {
    left.checked_add(right).ok_or(AvssError::ResourceBoundOverflow)
}

fn checked_mul(left: usize, right: usize) -> Result<usize, AvssError> {
    left.checked_mul(right).ok_or(AvssError::ResourceBoundOverflow)
}

/// Secret bivariate dealer polynomial. Coefficients are row-major `(x_degree, y_degree)`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct BivariatePolynomial {
    threshold: u16,
    coefficients: Vec<Scalar>,
}

impl std::fmt::Debug for BivariatePolynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BivariatePolynomial")
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}

/// Dealer-side helper. Persist this object's random coefficients before sending its messages.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct AvssDealer {
    #[zeroize(skip)]
    config: AvssConfig,
    polynomial: BivariatePolynomial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Candidate {
    commitment: CommitmentMatrix,
    dealer_polynomials: Option<DealerPolynomials>,
    recovered_polynomials: Option<DealerPolynomials>,
    echoes: BTreeMap<PartyId, CrossValues>,
    readies: BTreeMap<PartyId, CrossValues>,
}

impl Candidate {
    fn new(commitment: CommitmentMatrix) -> Self {
        Self {
            commitment,
            dealer_polynomials: None,
            recovered_polynomials: None,
            echoes: BTreeMap::new(),
            readies: BTreeMap::new(),
        }
    }
}

/// Durable receiver-side state for one AVSS dealer instance.
///
/// This value contains private polynomial evaluations. Serialized state must be authenticated and
/// encrypted at rest. Deserialization revalidates protocol invariants before returning a value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AvssParty {
    config: AvssConfig,
    local_party: PartyId,
    candidates: BTreeMap<CommitmentDigest, Candidate>,
    dealer_digest: Option<CommitmentDigest>,
    echo_digest_by_sender: BTreeMap<PartyId, CommitmentDigest>,
    ready_digest_by_sender: BTreeMap<PartyId, CommitmentDigest>,
    echoed_for: Option<CommitmentDigest>,
    ready_for: Option<CommitmentDigest>,
    output: Option<AvssOutput>,
}

#[derive(Deserialize)]
struct UncheckedAvssParty {
    config: AvssConfig,
    local_party: PartyId,
    candidates: BTreeMap<CommitmentDigest, Candidate>,
    dealer_digest: Option<CommitmentDigest>,
    echo_digest_by_sender: BTreeMap<PartyId, CommitmentDigest>,
    ready_digest_by_sender: BTreeMap<PartyId, CommitmentDigest>,
    echoed_for: Option<CommitmentDigest>,
    ready_for: Option<CommitmentDigest>,
    output: Option<AvssOutput>,
}

impl<'de> Deserialize<'de> for AvssParty {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let unchecked = UncheckedAvssParty::deserialize(deserializer)?;
        let party = Self {
            config: unchecked.config,
            local_party: unchecked.local_party,
            candidates: unchecked.candidates,
            dealer_digest: unchecked.dealer_digest,
            echo_digest_by_sender: unchecked.echo_digest_by_sender,
            ready_digest_by_sender: unchecked.ready_digest_by_sender,
            echoed_for: unchecked.echoed_for,
            ready_for: unchecked.ready_for,
            output: unchecked.output,
        };
        party.validate_restored().map_err(D::Error::custom)?;
        Ok(party)
    }
}

impl AvssConfig {
    /// Validate the CKLS resilience and committee constraints.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid committee, zero dealer, or parameters outside
    /// `n >= 3f + 1` and `f < k <= n - 2f`.
    pub fn validate(&self) -> Result<(), AvssError> {
        self.receivers.validate()?;
        preflight_avss_resources(&self.receivers, 1)?;
        if self.dealer.0 == 0 {
            return Err(AvssError::ZeroDealer);
        }
        let n = self.receivers.n();
        let f = self.fault_bound;
        let k = self.receivers.threshold;
        if u32::from(n) < 3 * u32::from(f) + 1 {
            return Err(AvssError::InvalidFaultBound { n, fault_bound: f });
        }
        if k <= f || u32::from(k) + 2 * u32::from(f) > u32::from(n) {
            return Err(AvssError::InvalidThreshold { n, fault_bound: f, threshold: k });
        }
        Ok(())
    }

    #[must_use]
    pub fn instance_id(&self) -> AvssInstanceId {
        AvssInstanceId {
            session: self.session,
            dealer: self.dealer,
            receiver_committee: self.receivers.digest(),
            receiver_epoch: self.receivers.epoch,
            threshold: self.receivers.threshold,
            fault_bound: self.fault_bound,
        }
    }

    #[must_use]
    pub fn echo_threshold(&self) -> usize {
        let n = usize::from(self.receivers.n());
        let f = usize::from(self.fault_bound);
        usize::from(self.receivers.threshold).max((n + f + 2) / 2)
    }

    #[must_use]
    pub fn ready_relay_threshold(&self) -> usize {
        usize::from(self.receivers.threshold)
    }

    #[must_use]
    pub fn completion_threshold(&self) -> usize {
        usize::from(self.receivers.threshold + self.fault_bound)
    }
}

impl CommitmentMatrix {
    fn new(threshold: u16, coefficients: Vec<PointBytes>) -> Result<Self, AvssError> {
        let matrix = Self { threshold, coefficients };
        matrix.validate_for_threshold(threshold)?;
        Ok(matrix)
    }

    #[must_use]
    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    #[must_use]
    pub fn coefficients(&self) -> &[PointBytes] {
        &self.coefficients
    }

    #[must_use]
    pub fn coefficient(&self, x_degree: usize, y_degree: usize) -> Option<PointBytes> {
        let k = usize::from(self.threshold);
        if x_degree >= k || y_degree >= k {
            return None;
        }
        self.coefficients.get(x_degree * k + y_degree).copied()
    }

    /// Validate the matrix dimensions and every encoded prime-order point.
    ///
    /// # Errors
    ///
    /// Returns an error on a dimension mismatch or invalid point encoding.
    pub fn validate_for_threshold(&self, threshold: u16) -> Result<(), AvssError> {
        let k = usize::from(threshold);
        if self.threshold != threshold || self.coefficients.len() != k * k {
            return Err(AvssError::WrongMatrixDimensions);
        }
        for coefficient in &self.coefficients {
            coefficient.parse()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> CommitmentDigest {
        let mut hasher = blake3::Hasher::new_derive_key(MATRIX_DIGEST_DOMAIN);
        hasher.update(&self.threshold.to_le_bytes());
        for coefficient in &self.coefficients {
            hasher.update(&coefficient.0);
        }
        CommitmentDigest(*hasher.finalize().as_bytes())
    }

    /// Extract commitments to the induced sharing polynomial `F(x, 0)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the matrix is malformed.
    pub fn x_axis_commitment(&self) -> Result<PolynomialCommitment, AvssError> {
        self.validate_for_threshold(self.threshold)?;
        let coefficients = (0..usize::from(self.threshold))
            .map(|x_degree| self.coefficient(x_degree, 0).ok_or(AvssError::WrongMatrixDimensions))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PolynomialCommitment { coefficients })
    }

    fn evaluate(&self, x: Scalar, y: Scalar) -> Result<EdwardsPoint, AvssError> {
        let k = usize::from(self.threshold);
        let mut x_power = Scalar::ONE;
        let mut result = EdwardsPoint::identity();
        for x_degree in 0..k {
            let mut y_power = Scalar::ONE;
            for y_degree in 0..k {
                let point = self
                    .coefficient(x_degree, y_degree)
                    .ok_or(AvssError::WrongMatrixDimensions)?
                    .parse()?;
                result += point * (x_power * y_power);
                y_power *= y;
            }
            x_power *= x;
        }
        Ok(result)
    }

    fn verify_polynomials(
        &self,
        receiver: Scalar,
        polynomials: &DealerPolynomials,
    ) -> Result<bool, AvssError> {
        let k = usize::from(self.threshold);
        if polynomials.row.len() != k || polynomials.column.len() != k {
            return Err(AvssError::WrongPolynomialLength);
        }

        let row = parse_polynomial(&polynomials.row)?;
        let column = parse_polynomial(&polynomials.column)?;
        for y_degree in 0..k {
            let mut expected = EdwardsPoint::identity();
            let mut x_power = Scalar::ONE;
            for x_degree in 0..k {
                expected += self
                    .coefficient(x_degree, y_degree)
                    .ok_or(AvssError::WrongMatrixDimensions)?
                    .parse()?
                    * x_power;
                x_power *= receiver;
            }
            if EdwardsPoint::mul_base(&row[y_degree]) != expected {
                return Ok(false);
            }

            let mut expected = EdwardsPoint::identity();
            let mut y_power = Scalar::ONE;
            for inner_y_degree in 0..k {
                expected += self
                    .coefficient(y_degree, inner_y_degree)
                    .ok_or(AvssError::WrongMatrixDimensions)?
                    .parse()?
                    * y_power;
                y_power *= receiver;
            }
            if EdwardsPoint::mul_base(&column[y_degree]) != expected {
                return Ok(false);
            }
        }
        // This equality is redundant given binding commitments, but catches orientation mistakes.
        Ok(evaluate_scalar_polynomial(&row, receiver)
            == evaluate_scalar_polynomial(&column, receiver))
    }

    fn verify_cross(
        &self,
        sender: Scalar,
        recipient: Scalar,
        values: &CrossValues,
    ) -> Result<bool, AvssError> {
        let sender_recipient = values.sender_recipient.parse()?;
        let recipient_sender = values.recipient_sender.parse()?;
        Ok(EdwardsPoint::mul_base(&sender_recipient) == self.evaluate(sender, recipient)?
            && EdwardsPoint::mul_base(&recipient_sender) == self.evaluate(recipient, sender)?)
    }
}

impl BivariatePolynomial {
    fn random_with_constant<R: RngCore + CryptoRng>(
        threshold: u16,
        constant: Scalar,
        rng: &mut R,
    ) -> Result<Self, AvssError> {
        if threshold == 0 {
            return Err(AvssError::WrongMatrixDimensions);
        }
        let k = usize::from(threshold);
        let mut coefficients = (0..k * k).map(|_| Scalar::random(&mut *rng)).collect::<Vec<_>>();
        coefficients[0] = constant;
        // Keep the induced x-axis sharing at its configured degree for honest dealers.
        if threshold > 1 {
            let highest_x_axis = (k - 1) * k;
            while coefficients[highest_x_axis] == Scalar::ZERO {
                coefficients[highest_x_axis] = Scalar::random(&mut *rng);
            }
        }
        Ok(Self { threshold, coefficients })
    }

    fn coefficient(&self, x_degree: usize, y_degree: usize) -> Scalar {
        self.coefficients[x_degree * usize::from(self.threshold) + y_degree]
    }

    fn commitment(&self) -> Result<CommitmentMatrix, AvssError> {
        CommitmentMatrix::new(
            self.threshold,
            self.coefficients
                .iter()
                .map(|coefficient| PointBytes::from(EdwardsPoint::mul_base(coefficient)))
                .collect(),
        )
    }

    fn polynomials_for(&self, receiver: Scalar) -> DealerPolynomials {
        let k = usize::from(self.threshold);
        let row = (0..k)
            .map(|y_degree| {
                let mut power = Scalar::ONE;
                let mut coefficient = Scalar::ZERO;
                for x_degree in 0..k {
                    coefficient += self.coefficient(x_degree, y_degree) * power;
                    power *= receiver;
                }
                ScalarBytes::from(coefficient)
            })
            .collect();
        let column = (0..k)
            .map(|x_degree| {
                let mut power = Scalar::ONE;
                let mut coefficient = Scalar::ZERO;
                for y_degree in 0..k {
                    coefficient += self.coefficient(x_degree, y_degree) * power;
                    power *= receiver;
                }
                ScalarBytes::from(coefficient)
            })
            .collect();
        DealerPolynomials { row, column }
    }
}

impl AvssDealer {
    /// Construct a dealer with a caller-specified constant, used for resharing and deterministic
    /// tests. For DKG, pass a fresh uniformly random scalar.
    ///
    /// # Errors
    ///
    /// Returns an error if the AVSS configuration is invalid.
    pub fn random_with_constant<R: RngCore + CryptoRng>(
        config: AvssConfig,
        constant: Scalar,
        rng: &mut R,
    ) -> Result<Self, AvssError> {
        config.validate()?;
        let polynomial =
            BivariatePolynomial::random_with_constant(config.receivers.threshold, constant, rng)?;
        Ok(Self { config, polynomial })
    }

    /// Construct a dealer whose constant is sampled uniformly at random.
    ///
    /// # Errors
    ///
    /// Returns an error if the AVSS configuration is invalid.
    pub fn random<R: RngCore + CryptoRng>(
        config: AvssConfig,
        rng: &mut R,
    ) -> Result<Self, AvssError> {
        // Validate all allocation-driving dimensions before touching cryptographic randomness.
        config.validate()?;
        let constant = Scalar::random(&mut *rng);
        Self::random_with_constant(config, constant, rng)
    }

    /// Construct a same-committee proactive-refresh contribution.
    ///
    /// The constant is fixed to zero and publicly verifiable in the output's x-axis Feldman
    /// commitment. Callers must add a consensus-selected set of these contributions to the
    /// already authenticated source share; they are not a standalone DKG result.
    pub fn random_zero_constant<R: RngCore + CryptoRng>(
        config: AvssConfig,
        rng: &mut R,
    ) -> Result<Self, AvssError> {
        config.validate()?;
        Self::random_with_constant(config, Scalar::ZERO, rng)
    }

    #[must_use]
    pub fn instance_id(&self) -> AvssInstanceId {
        self.config.instance_id()
    }

    /// Build the initial, independently encrypted `DealerSend` payload for every receiver.
    ///
    /// # Errors
    ///
    /// Returns an error if a receiver coordinate or commitment cannot be constructed.
    pub fn private_messages(&self) -> Result<Vec<PrivateAvssMessage>, AvssError> {
        let commitment = self.polynomial.commitment()?;
        let commitment_digest = commitment.digest();
        self.config
            .receivers
            .members
            .iter()
            .map(|member| {
                let receiver = scalar_for_party(&self.config.receivers, member.id)?;
                Ok(PrivateAvssMessage {
                    recipient: member.id,
                    message: AvssMessage {
                        instance: self.config.instance_id(),
                        commitment_digest,
                        commitment: commitment.clone(),
                        payload: AvssPayload::DealerSend(self.polynomial.polynomials_for(receiver)),
                    },
                })
            })
            .collect()
    }
}

impl AvssParty {
    /// Initialize durable local state for one receiver and one dealer instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or `local_party` is not a receiver.
    pub fn new(config: AvssConfig, local_party: PartyId) -> Result<Self, AvssError> {
        config.validate()?;
        config
            .receivers
            .member(local_party)
            .map_err(|_| AvssError::UnknownLocalParty(local_party))?;
        Ok(Self {
            config,
            local_party,
            candidates: BTreeMap::new(),
            dealer_digest: None,
            echo_digest_by_sender: BTreeMap::new(),
            ready_digest_by_sender: BTreeMap::new(),
            echoed_for: None,
            ready_for: None,
            output: None,
        })
    }

    #[must_use]
    pub fn config(&self) -> &AvssConfig {
        &self.config
    }

    #[must_use]
    pub fn local_party(&self) -> PartyId {
        self.local_party
    }

    #[must_use]
    pub fn output(&self) -> Option<&AvssOutput> {
        self.output.as_ref()
    }

    #[must_use]
    pub fn echoed_for(&self) -> Option<CommitmentDigest> {
        self.echoed_for
    }

    #[must_use]
    pub fn ready_for(&self) -> Option<CommitmentDigest> {
        self.ready_for
    }

    /// Accept one already-authenticated message. The caller must atomically persist this state and
    /// the returned private outbox before transmitting any returned message.
    ///
    /// # Errors
    ///
    /// Returns an error without counting malformed, cross-instance, unauthenticated-role, or
    /// equivocating input.
    pub fn handle(&mut self, sender: PartyId, message: AvssMessage) -> Result<AvssStep, AvssError> {
        self.validate_message_common(sender, &message)?;

        match message.payload {
            AvssPayload::DealerSend(polynomials) => self.handle_dealer_send(
                sender,
                message.commitment_digest,
                message.commitment,
                &polynomials,
            ),
            AvssPayload::Echo(values) => self.handle_cross(
                sender,
                message.commitment_digest,
                message.commitment,
                values,
                AvssMessageKind::Echo,
            ),
            AvssPayload::Ready(values) => self.handle_cross(
                sender,
                message.commitment_digest,
                message.commitment,
                values,
                AvssMessageKind::Ready,
            ),
        }
    }

    /// Validate every state-independent property of one already-authenticated inbound message.
    ///
    /// Terminal transport retries use this before returning a no-op, when the mutable reducer that
    /// would ordinarily perform these checks has already been compacted or destroyed.
    pub fn validate_message(
        &self,
        sender: PartyId,
        message: &AvssMessage,
    ) -> Result<(), AvssError> {
        self.validate_message_common(sender, message)?;
        let local_x = scalar_for_party(&self.config.receivers, self.local_party)?;
        match &message.payload {
            AvssPayload::DealerSend(polynomials) => {
                if !message.commitment.verify_polynomials(local_x, polynomials)? {
                    return Err(AvssError::InvalidDealerPolynomials);
                }
            }
            AvssPayload::Echo(values) | AvssPayload::Ready(values) => {
                let sender_x = scalar_for_party(&self.config.receivers, sender)?;
                if !message.commitment.verify_cross(sender_x, local_x, values)? {
                    return Err(AvssError::InvalidCrossValues);
                }
            }
        }
        Ok(())
    }

    fn validate_message_common(
        &self,
        sender: PartyId,
        message: &AvssMessage,
    ) -> Result<(), AvssError> {
        self.validate_message_header(message)?;
        self.validate_sender_role(sender, &message.payload)?;
        message.commitment.validate_for_threshold(self.config.receivers.threshold)?;
        if message.commitment.digest() != message.commitment_digest {
            return Err(AvssError::WrongCommitmentDigest);
        }
        Ok(())
    }

    fn validate_message_header(&self, message: &AvssMessage) -> Result<(), AvssError> {
        if message.instance != self.config.instance_id() {
            return Err(AvssError::WrongInstance);
        }
        Ok(())
    }

    fn validate_sender_role(
        &self,
        sender: PartyId,
        payload: &AvssPayload,
    ) -> Result<(), AvssError> {
        match payload {
            AvssPayload::DealerSend(_) if sender != self.config.dealer => {
                Err(AvssError::WrongDealer { expected: self.config.dealer, actual: sender })
            }
            AvssPayload::Echo(_) | AvssPayload::Ready(_) => self
                .config
                .receivers
                .member(sender)
                .map(|_| ())
                .map_err(|_| AvssError::UnknownSender(sender)),
            AvssPayload::DealerSend(_) => Ok(()),
        }
    }

    fn handle_dealer_send(
        &mut self,
        sender: PartyId,
        digest: CommitmentDigest,
        commitment: CommitmentMatrix,
        polynomials: &DealerPolynomials,
    ) -> Result<AvssStep, AvssError> {
        if sender != self.config.dealer {
            return Err(AvssError::WrongDealer { expected: self.config.dealer, actual: sender });
        }
        let local_x = scalar_for_party(&self.config.receivers, self.local_party)?;
        if !commitment.verify_polynomials(local_x, polynomials)? {
            return Err(AvssError::InvalidDealerPolynomials);
        }

        if let Some(previous) = self.dealer_digest
            && previous != digest
        {
            return Err(AvssError::DealerEquivocation);
        }
        self.ensure_candidate(digest, commitment)?;
        let candidate =
            self.candidates.get_mut(&digest).expect("ensure_candidate inserted the candidate");
        if let Some(previous) = &candidate.dealer_polynomials {
            if previous == polynomials {
                return Ok(AvssStep { duplicate: true, ..AvssStep::default() });
            }
            return Err(AvssError::DealerEquivocation);
        }
        candidate.dealer_polynomials = Some(polynomials.clone());
        self.dealer_digest = Some(digest);

        if self.echoed_for.is_some() {
            return Ok(AvssStep::default());
        }
        self.echoed_for = Some(digest);
        let outbound = self.messages_for_polynomials(digest, polynomials, AvssMessageKind::Echo)?;
        Ok(AvssStep { outbound, completed: None, duplicate: false })
    }

    fn handle_cross(
        &mut self,
        sender: PartyId,
        digest: CommitmentDigest,
        commitment: CommitmentMatrix,
        values: CrossValues,
        kind: AvssMessageKind,
    ) -> Result<AvssStep, AvssError> {
        self.config.receivers.member(sender).map_err(|_| AvssError::UnknownSender(sender))?;
        let sender_x = scalar_for_party(&self.config.receivers, sender)?;
        let local_x = scalar_for_party(&self.config.receivers, self.local_party)?;
        if !commitment.verify_cross(sender_x, local_x, &values)? {
            return Err(AvssError::InvalidCrossValues);
        }

        let digest_by_sender = match kind {
            AvssMessageKind::Echo => &self.echo_digest_by_sender,
            AvssMessageKind::Ready => &self.ready_digest_by_sender,
            AvssMessageKind::DealerSend => unreachable!("DealerSend is handled separately"),
        };
        if digest_by_sender.get(&sender).is_some_and(|previous| *previous != digest) {
            return Err(AvssError::SenderEquivocation { sender, kind });
        }

        self.ensure_candidate(digest, commitment)?;
        let candidate =
            self.candidates.get_mut(&digest).expect("ensure_candidate inserted the candidate");
        let values_by_sender = match kind {
            AvssMessageKind::Echo => &mut candidate.echoes,
            AvssMessageKind::Ready => &mut candidate.readies,
            AvssMessageKind::DealerSend => unreachable!("DealerSend is handled separately"),
        };
        if let Some(previous) = values_by_sender.get(&sender) {
            if previous == &values {
                return Ok(AvssStep { duplicate: true, ..AvssStep::default() });
            }
            return Err(AvssError::SenderEquivocation { sender, kind });
        }
        values_by_sender.insert(sender, values);
        match kind {
            AvssMessageKind::Echo => {
                self.echo_digest_by_sender.insert(sender, digest);
            }
            AvssMessageKind::Ready => {
                self.ready_digest_by_sender.insert(sender, digest);
            }
            AvssMessageKind::DealerSend => unreachable!("DealerSend is handled separately"),
        }

        self.advance(digest)
    }

    fn ensure_candidate(
        &mut self,
        digest: CommitmentDigest,
        commitment: CommitmentMatrix,
    ) -> Result<(), AvssError> {
        if let Some(existing) = self.candidates.get(&digest) {
            if existing.commitment != commitment {
                return Err(AvssError::CommitmentDigestCollision);
            }
            return Ok(());
        }
        self.candidates.insert(digest, Candidate::new(commitment));
        Ok(())
    }

    fn advance(&mut self, digest: CommitmentDigest) -> Result<AvssStep, AvssError> {
        let (echoes, readies) = {
            let candidate = self.candidates.get(&digest).expect("candidate exists");
            (candidate.echoes.len(), candidate.readies.len())
        };
        let should_ready = self.ready_for.is_none()
            && (echoes >= self.config.echo_threshold()
                || readies >= self.config.ready_relay_threshold());
        let mut outbound = Vec::new();
        if should_ready {
            let source = if echoes >= self.config.echo_threshold() {
                AvssMessageKind::Echo
            } else {
                AvssMessageKind::Ready
            };
            let recovered = self.recover_polynomials(digest, source)?;
            self.candidates.get_mut(&digest).expect("candidate exists").recovered_polynomials =
                Some(recovered.clone());
            self.ready_for = Some(digest);
            outbound = self.messages_for_polynomials(digest, &recovered, AvssMessageKind::Ready)?;
        }

        let ready_count = self.candidates.get(&digest).expect("candidate exists").readies.len();
        let mut completed = None;
        if ready_count >= self.config.completion_threshold() {
            if self.ready_for != Some(digest)
                || self.output.as_ref().is_some_and(|output| output.commitment_digest != digest)
            {
                return Err(AvssError::ConflictingReadyCertificate);
            }
            if self.output.is_none() {
                let candidate = self.candidates.get(&digest).expect("candidate exists");
                let recovered = candidate
                    .recovered_polynomials
                    .as_ref()
                    .ok_or(AvssError::InsufficientPoints)?;
                let share = recovered.row.first().ok_or(AvssError::WrongPolynomialLength)?.clone();
                let output = AvssOutput {
                    instance: self.config.instance_id(),
                    recipient: self.local_party,
                    share,
                    x_axis_commitment: candidate.commitment.x_axis_commitment()?,
                    commitment_digest: digest,
                    ready_senders: candidate.readies.keys().copied().collect(),
                };
                self.output = Some(output.clone());
                completed = Some(output);
            }
        }
        Ok(AvssStep { outbound, completed, duplicate: false })
    }

    fn recover_polynomials(
        &self,
        digest: CommitmentDigest,
        source: AvssMessageKind,
    ) -> Result<DealerPolynomials, AvssError> {
        let candidate = self.candidates.get(&digest).expect("candidate exists");
        let values = match source {
            AvssMessageKind::Echo => &candidate.echoes,
            AvssMessageKind::Ready => &candidate.readies,
            AvssMessageKind::DealerSend => unreachable!("recovery uses Echo or Ready"),
        };
        let k = usize::from(self.config.receivers.threshold);
        if values.len() < k {
            return Err(AvssError::InsufficientPoints);
        }
        let points = values
            .iter()
            .take(k)
            .map(|(sender, values)| {
                Ok((
                    scalar_for_party(&self.config.receivers, *sender)?,
                    values.sender_recipient.parse()?,
                    values.recipient_sender.parse()?,
                ))
            })
            .collect::<Result<Vec<_>, AvssError>>()?;
        // sender_recipient = F(sender, local) is a point on the local column F(x, local).
        let column_points = points.iter().map(|(x, value, _)| (*x, *value)).collect::<Vec<_>>();
        // recipient_sender = F(local, sender) is a point on the local row F(local, y).
        let row_points = points.iter().map(|(x, _, value)| (*x, *value)).collect::<Vec<_>>();
        let recovered = DealerPolynomials {
            row: interpolate_coefficients(&row_points, k)?
                .into_iter()
                .map(ScalarBytes::from)
                .collect(),
            column: interpolate_coefficients(&column_points, k)?
                .into_iter()
                .map(ScalarBytes::from)
                .collect(),
        };
        let local_x = scalar_for_party(&self.config.receivers, self.local_party)?;
        if !candidate.commitment.verify_polynomials(local_x, &recovered)? {
            return Err(AvssError::InvalidRecoveredPolynomials);
        }
        Ok(recovered)
    }

    fn messages_for_polynomials(
        &self,
        digest: CommitmentDigest,
        polynomials: &DealerPolynomials,
        kind: AvssMessageKind,
    ) -> Result<Vec<PrivateAvssMessage>, AvssError> {
        let candidate = self.candidates.get(&digest).expect("candidate exists");
        let row = parse_polynomial(&polynomials.row)?;
        let column = parse_polynomial(&polynomials.column)?;
        self.config
            .receivers
            .members
            .iter()
            .map(|member| {
                let recipient = scalar_for_party(&self.config.receivers, member.id)?;
                let values = CrossValues {
                    sender_recipient: ScalarBytes::from(evaluate_scalar_polynomial(
                        &row, recipient,
                    )),
                    recipient_sender: ScalarBytes::from(evaluate_scalar_polynomial(
                        &column, recipient,
                    )),
                };
                let payload = match kind {
                    AvssMessageKind::Echo => AvssPayload::Echo(values),
                    AvssMessageKind::Ready => AvssPayload::Ready(values),
                    AvssMessageKind::DealerSend => {
                        unreachable!("dealer messages are constructed by AvssDealer")
                    }
                };
                Ok(PrivateAvssMessage {
                    recipient: member.id,
                    message: AvssMessage {
                        instance: self.config.instance_id(),
                        commitment_digest: digest,
                        commitment: candidate.commitment.clone(),
                        payload,
                    },
                })
            })
            .collect()
    }

    #[allow(clippy::too_many_lines)]
    fn validate_restored(&self) -> Result<(), AvssError> {
        self.config.validate()?;
        self.config
            .receivers
            .member(self.local_party)
            .map_err(|_| AvssError::UnknownLocalParty(self.local_party))?;
        let local_x = scalar_for_party(&self.config.receivers, self.local_party)?;
        let mut echoes = BTreeMap::new();
        let mut readies = BTreeMap::new();
        let mut dealer_candidates = BTreeSet::new();
        let mut recovered_candidates = BTreeSet::new();

        for (digest, candidate) in &self.candidates {
            candidate.commitment.validate_for_threshold(self.config.receivers.threshold)?;
            if candidate.commitment.digest() != *digest {
                return Err(AvssError::InvalidPersistedState("candidate digest differs"));
            }
            if let Some(polynomials) = &candidate.dealer_polynomials {
                if !candidate.commitment.verify_polynomials(local_x, polynomials)? {
                    return Err(AvssError::InvalidPersistedState("invalid dealer polynomials"));
                }
                dealer_candidates.insert(*digest);
            }
            if let Some(polynomials) = &candidate.recovered_polynomials {
                if !candidate.commitment.verify_polynomials(local_x, polynomials)? {
                    return Err(AvssError::InvalidPersistedState("invalid recovered polynomials"));
                }
                recovered_candidates.insert(*digest);
            }
            for (sender, values) in &candidate.echoes {
                self.validate_restored_cross(
                    *sender,
                    *digest,
                    values,
                    &candidate.commitment,
                    &mut echoes,
                )?;
            }
            for (sender, values) in &candidate.readies {
                self.validate_restored_cross(
                    *sender,
                    *digest,
                    values,
                    &candidate.commitment,
                    &mut readies,
                )?;
            }
        }

        if echoes != self.echo_digest_by_sender || readies != self.ready_digest_by_sender {
            return Err(AvssError::InvalidPersistedState("sender digest indexes differ"));
        }
        match self.dealer_digest {
            Some(digest) if dealer_candidates == BTreeSet::from([digest]) => {}
            None if dealer_candidates.is_empty() => {}
            _ => return Err(AvssError::InvalidPersistedState("dealer lock differs")),
        }
        match self.echoed_for {
            Some(digest) if dealer_candidates.contains(&digest) => {}
            None => {}
            _ => return Err(AvssError::InvalidPersistedState("Echo lock is invalid")),
        }
        match self.ready_for {
            Some(digest) => {
                if recovered_candidates != BTreeSet::from([digest]) {
                    return Err(AvssError::InvalidPersistedState("Ready recovery lock differs"));
                }
                let candidate = self
                    .candidates
                    .get(&digest)
                    .ok_or(AvssError::InvalidPersistedState("Ready candidate is missing"))?;
                if candidate.echoes.len() < self.config.echo_threshold()
                    && candidate.readies.len() < self.config.ready_relay_threshold()
                {
                    return Err(AvssError::InvalidPersistedState("Ready threshold not reached"));
                }
            }
            None if recovered_candidates.is_empty() => {}
            None => return Err(AvssError::InvalidPersistedState("orphan recovered polynomial")),
        }

        if let Some(output) = &self.output {
            if output.instance != self.config.instance_id()
                || output.recipient != self.local_party
                || self.ready_for != Some(output.commitment_digest)
            {
                return Err(AvssError::InvalidPersistedState("output context differs"));
            }
            let candidate = self
                .candidates
                .get(&output.commitment_digest)
                .ok_or(AvssError::InvalidPersistedState("output candidate is missing"))?;
            let recovered = candidate
                .recovered_polynomials
                .as_ref()
                .ok_or(AvssError::InvalidPersistedState("output recovery is missing"))?;
            if recovered.row.first() != Some(&output.share)
                || candidate.commitment.x_axis_commitment()? != output.x_axis_commitment
                || output.ready_senders.len() < self.config.completion_threshold()
                || !output.ready_senders.iter().all(|sender| candidate.readies.contains_key(sender))
            {
                return Err(AvssError::InvalidPersistedState("output certificate differs"));
            }
        } else if self
            .candidates
            .values()
            .any(|candidate| candidate.readies.len() >= self.config.completion_threshold())
        {
            return Err(AvssError::InvalidPersistedState("completed output is missing"));
        }
        Ok(())
    }

    fn validate_restored_cross(
        &self,
        sender: PartyId,
        digest: CommitmentDigest,
        values: &CrossValues,
        commitment: &CommitmentMatrix,
        index: &mut BTreeMap<PartyId, CommitmentDigest>,
    ) -> Result<(), AvssError> {
        self.config
            .receivers
            .member(sender)
            .map_err(|_| AvssError::InvalidPersistedState("unknown cross-value sender"))?;
        if index.insert(sender, digest).is_some() {
            return Err(AvssError::InvalidPersistedState("sender occurs in two candidates"));
        }
        let sender_x = scalar_for_party(&self.config.receivers, sender)?;
        let local_x = scalar_for_party(&self.config.receivers, self.local_party)?;
        if !commitment.verify_cross(sender_x, local_x, values)? {
            return Err(AvssError::InvalidPersistedState("invalid cross value"));
        }
        Ok(())
    }
}

fn parse_polynomial(bytes: &[ScalarBytes]) -> Result<Vec<Scalar>, AvssError> {
    bytes.iter().map(|coefficient| Ok(coefficient.parse()?)).collect()
}

fn evaluate_scalar_polynomial(coefficients: &[Scalar], x: Scalar) -> Scalar {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::ZERO, |accumulator, coefficient| accumulator * x + coefficient)
}

fn interpolate_coefficients(
    points: &[(Scalar, Scalar)],
    threshold: usize,
) -> Result<Vec<Scalar>, AvssError> {
    if points.len() < threshold || threshold == 0 {
        return Err(AvssError::InsufficientPoints);
    }
    let points = &points[..threshold];
    let mut result = vec![Scalar::ZERO; threshold];
    for (index, (x_i, y_i)) in points.iter().enumerate() {
        let mut basis = vec![Scalar::ONE];
        let mut denominator = Scalar::ONE;
        for (other_index, (x_j, _)) in points.iter().enumerate() {
            if index == other_index {
                continue;
            }
            denominator *= *x_i - *x_j;
            let mut next = vec![Scalar::ZERO; basis.len() + 1];
            for (degree, coefficient) in basis.iter().enumerate() {
                next[degree] -= coefficient * x_j;
                next[degree + 1] += coefficient;
            }
            basis = next;
        }
        let scale = *y_i * denominator.invert();
        for (degree, coefficient) in basis.iter().enumerate() {
            result[degree] += coefficient * scale;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    use crate::committee::{MAX_COMMITTEE_THRESHOLD, Member};
    use curve25519_dalek::traits::IsIdentity;
    use rand_core::Error as RandError;

    fn committee(members: u16, threshold: u16) -> Committee {
        Committee {
            epoch: 0,
            threshold,
            members: (1..=members)
                .map(|id| Member {
                    id: PartyId(id),
                    signing_key: [u8::try_from(id).unwrap(); 32],
                    encryption_key: [u8::try_from(id + 32).unwrap(); 32],
                })
                .collect(),
        }
    }

    #[derive(Default)]
    struct CountingRng {
        calls: usize,
    }

    impl RngCore for CountingRng {
        fn next_u32(&mut self) -> u32 {
            self.calls += 1;
            1
        }

        fn next_u64(&mut self) -> u64 {
            self.calls += 1;
            1
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            self.calls += 1;
            destination.fill(1);
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl CryptoRng for CountingRng {}

    #[test]
    fn maximum_resource_preflight_bounds_the_canonical_message_and_session() {
        let receivers = committee(MAX_COMMITTEE_THRESHOLD, MAX_COMMITTEE_THRESHOLD);
        let bounds = preflight_avss_resources(&receivers, MAX_AVSS_DEALERS).unwrap();
        let threshold = usize::from(receivers.threshold);
        let message = AvssMessage {
            instance: AvssConfig {
                session: SessionId([1; 32]),
                dealer: PartyId(1),
                receivers,
                fault_bound: 0,
            }
            .instance_id(),
            commitment_digest: CommitmentDigest([2; 32]),
            commitment: CommitmentMatrix {
                threshold: MAX_COMMITTEE_THRESHOLD,
                coefficients: vec![PointBytes([3; 32]); threshold * threshold],
            },
            payload: AvssPayload::DealerSend(DealerPolynomials {
                row: vec![ScalarBytes([4; 32]); threshold],
                column: vec![ScalarBytes([5; 32]); threshold],
            }),
        };
        let canonical = postcard::to_allocvec(&message).unwrap();
        assert!(canonical.len() <= bounds.maximum_wire_message_bytes);
        assert!(bounds.maximum_wire_message_bytes < MAX_AVSS_WIRE_BODY_BYTES);
        assert!(bounds.maximum_persisted_session_bytes <= MAX_SESSION_STATE_BYTES);
    }

    #[test]
    fn oversized_committee_is_rejected_before_rng_or_polynomial_allocation() {
        let config = AvssConfig {
            session: SessionId([1; 32]),
            dealer: PartyId(1),
            receivers: committee(MAX_COMMITTEE_THRESHOLD + 1, MAX_COMMITTEE_THRESHOLD),
            fault_bound: 0,
        };
        let mut rng = CountingRng::default();
        assert!(matches!(
            AvssDealer::random(config, &mut rng),
            Err(AvssError::Committee(CommitteeError::TooManyMembers {
                members,
                maximum: MAX_COMMITTEE_MEMBERS,
            })) if members == MAX_COMMITTEE_MEMBERS + 1
        ));
        assert_eq!(rng.calls, 0, "invalid dimensions must not touch cryptographic randomness");
    }

    #[test]
    fn zero_constant_refresh_dealer_commits_to_identity_and_full_degree() {
        let receivers = committee(4, 2);
        let config = AvssConfig {
            session: SessionId([9; 32]),
            dealer: PartyId(1),
            receivers,
            fault_bound: 1,
        };
        let dealer = AvssDealer::random_zero_constant(config, &mut CountingRng::default()).unwrap();
        let messages = dealer.private_messages().unwrap();
        assert_eq!(messages.len(), 4);
        let commitment = messages[0].message.commitment.x_axis_commitment().unwrap();
        assert!(commitment.has_zero_constant().unwrap());
        assert!(
            !commitment.coefficients[1].parse().unwrap().is_identity(),
            "an honest refresh contribution must retain the configured degree"
        );
        assert!(messages.iter().all(|message| {
            message.message.commitment_digest == messages[0].message.commitment_digest
                && message.message.commitment == messages[0].message.commitment
        }));
    }
}
