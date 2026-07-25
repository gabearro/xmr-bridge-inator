use std::collections::{BTreeMap, BTreeSet, HashMap};

use curve25519_dalek::{
    EdwardsPoint, Scalar,
    edwards::CompressedEdwardsY,
    traits::{Identity, IsIdentity},
};
use dkg::{Interpolation, Participant, ThresholdKeys, ThresholdParams};
use frost::curve::{Ciphersuite, Ed25519};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::committee::{Committee, CommitteeError, PartyId};

/// A canonical scalar on the wire. Parsing is always canonical; reductions are never accepted.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct ScalarBytes(pub [u8; 32]);

impl ScalarBytes {
    pub fn parse(&self) -> Result<Scalar, KeyError> {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(self.0)).ok_or(KeyError::InvalidScalar)
    }
}

impl std::fmt::Debug for ScalarBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScalarBytes(REDACTED)")
    }
}

impl From<Scalar> for ScalarBytes {
    fn from(value: Scalar) -> Self {
        Self(value.to_bytes())
    }
}

/// A compressed, prime-order Edwards25519 point on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PointBytes(pub [u8; 32]);

impl PointBytes {
    pub fn parse(self) -> Result<EdwardsPoint, KeyError> {
        let point = CompressedEdwardsY(self.0).decompress().ok_or(KeyError::InvalidPoint)?;
        // `CompressedEdwardsY::decompress` is intentionally more permissive than the protocol
        // wire format. Re-encoding prevents accepting alternate encodings of the same point.
        if point.compress().to_bytes() != self.0 {
            return Err(KeyError::InvalidPoint);
        }
        if !point.is_torsion_free() {
            return Err(KeyError::NonPrimeOrderPoint);
        }
        Ok(point)
    }
}

impl From<EdwardsPoint> for PointBytes {
    fn from(value: EdwardsPoint) -> Self {
        Self(value.compress().to_bytes())
    }
}

/// Feldman commitments to a univariate Shamir polynomial.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolynomialCommitment {
    /// `coefficients[j] = a_j * G`.
    pub coefficients: Vec<PointBytes>,
}

/// Secret polynomial held only while dealing one AVSS instance.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretPolynomial {
    coefficients: Vec<Scalar>,
}

impl std::fmt::Debug for SecretPolynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretPolynomial")
            .field("degree", &self.coefficients.len().saturating_sub(1))
            .finish_non_exhaustive()
    }
}

/// One verified dealer output for a target committee member.
///
/// This bare value is not replay-safe by itself. Its authenticated AVSS envelope/certificate must
/// bind the key id, old/new committee digests, epochs, selected dealer set, dealer, recipient and
/// dense recipient index, AVSS session id, and commitment digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DealerOutput {
    #[zeroize(skip)]
    pub dealer: PartyId,
    pub share: ScalarBytes,
    #[zeroize(skip)]
    pub commitment: PolynomialCommitment,
}

/// Durable secret share and public verification data for one epoch.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EpochShare {
    #[zeroize(skip)]
    pub key_id: [u8; 32],
    #[zeroize(skip)]
    pub committee: Committee,
    #[zeroize(skip)]
    pub local_party: PartyId,
    secret_share: Scalar,
    #[zeroize(skip)]
    verification_shares: BTreeMap<PartyId, PointBytes>,
    #[zeroize(skip)]
    group_key: PointBytes,
}

impl std::fmt::Debug for EpochShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochShare")
            .field("key_id", &hex::encode(self.key_id))
            .field("epoch", &self.committee.epoch)
            .field("local_party", &self.local_party)
            .field("group_key", &hex::encode(self.group_key.0))
            .finish_non_exhaustive()
    }
}

/// Public key metadata shared with both existing and newly joining epoch members.
///
/// This is sufficient to verify a resharing dealer's Lagrange-weighted constant commitment. It
/// intentionally contains no old-epoch secret share, so a party joining only the new committee
/// can validate and aggregate its AVSS outputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochPublic {
    pub key_id: [u8; 32],
    pub committee: Committee,
    pub verification_shares: BTreeMap<PartyId, PointBytes>,
    pub group_key: PointBytes,
}

impl EpochPublic {
    pub fn group_key(&self) -> Result<EdwardsPoint, KeyError> {
        self.group_key.parse()
    }

    pub fn group_key_bytes(&self) -> [u8; 32] {
        self.group_key.0
    }

    pub fn verification_share(&self, party: PartyId) -> Result<EdwardsPoint, KeyError> {
        self.verification_shares
            .get(&party)
            .ok_or(KeyError::Committee(CommitteeError::UnknownParty(party)))?
            .parse()
    }

    /// Validate the complete public Shamir polynomial before using it for resharing.
    pub fn validate(&self) -> Result<(), KeyError> {
        self.committee.validate()?;
        let expected_parties =
            self.committee.members.iter().map(|member| member.id).collect::<BTreeSet<_>>();
        let supplied_parties = self.verification_shares.keys().copied().collect::<BTreeSet<_>>();
        if supplied_parties != expected_parties {
            return Err(KeyError::InconsistentVerificationShares);
        }

        let group_key = self.group_key()?;
        if group_key.is_identity() {
            return Err(KeyError::IdentityGroupKey);
        }

        // Rebuild the polynomial in the exact dense, one-based coordinate system which
        // `ThresholdKeys` uses. Stable PartyIds are deliberately not Shamir coordinates.
        let ordered = (1..=self.committee.n())
            .map(|index| {
                let party = self.committee.party_for_frost_index(index)?;
                let verification_share = self.verification_share(party)?;
                if verification_share.is_identity() {
                    return Err(KeyError::IdentityVerificationShare(party));
                }
                Ok((Scalar::from(u64::from(index)), verification_share))
            })
            .collect::<Result<Vec<_>, KeyError>>()?;
        let basis = &ordered[..usize::from(self.committee.threshold)];
        if interpolate_points(Scalar::ZERO, basis)? != group_key {
            return Err(KeyError::GroupKeyMismatch);
        }
        if self.committee.threshold > 1 && highest_coefficient(basis)?.is_identity() {
            return Err(KeyError::DegenerateSharingPolynomial);
        }
        for (x, expected) in &ordered {
            if interpolate_points(*x, basis)? != *expected {
                return Err(KeyError::InconsistentVerificationShares);
            }
        }
        Ok(())
    }

    /// Canonical public digest which every new member must confirm before activating an epoch.
    ///
    /// Equality proves the parties installed the same committee, group key, and verification
    /// polynomial. The AVSS layer must additionally bind this acknowledgement to its certified
    /// dealer/commitment transcript.
    pub fn activation_digest(&self) -> Result<[u8; 32], KeyError> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/key-epoch-activation/v1");
        hasher.update(&self.key_id);
        hasher.update(&self.committee.digest());
        hasher.update(&self.group_key.0);
        for index in 1..=self.committee.n() {
            let party = self.committee.party_for_frost_index(index)?;
            hasher.update(&index.to_le_bytes());
            hasher.update(&party.0.to_le_bytes());
            hasher.update(&self.verification_shares[&party].0);
        }
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Explicit serialization format for encrypted-at-rest persistence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EpochShareMaterial {
    #[zeroize(skip)]
    pub key_id: [u8; 32],
    #[zeroize(skip)]
    pub committee: Committee,
    #[zeroize(skip)]
    pub local_party: PartyId,
    pub secret_share: ScalarBytes,
    #[zeroize(skip)]
    pub verification_shares: BTreeMap<PartyId, PointBytes>,
    #[zeroize(skip)]
    pub group_key: PointBytes,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum KeyError {
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("invalid canonical scalar")]
    InvalidScalar,
    #[error("invalid compressed Edwards25519 point")]
    InvalidPoint,
    #[error("point is not in the prime-order subgroup")]
    NonPrimeOrderPoint,
    #[error("polynomial degree does not match threshold")]
    WrongDegree,
    #[error("a zero group/spend key is forbidden")]
    IdentityGroupKey,
    #[error("dealer {0} is duplicated")]
    DuplicateDealer(PartyId),
    #[error("dealer {0} is not eligible")]
    IneligibleDealer(PartyId),
    #[error("dealer set is not in canonical ascending party-id order")]
    NonCanonicalDealerSet,
    #[error("DKG dealer set must contain at least n-f ({minimum}) dealers, found {actual}")]
    InsufficientDkgDealers { minimum: u16, actual: usize },
    #[error("dealer set must contain exactly the old threshold ({expected}), found {actual}")]
    WrongReshareDealerCount { expected: u16, actual: usize },
    #[error("dealer set is empty")]
    EmptyDealerSet,
    #[error("dealer {0} is missing from the certified dealer set")]
    MissingDealer(PartyId),
    #[error("share from dealer {0} does not match its commitment")]
    InvalidDealerShare(PartyId),
    #[error("reshare dealer {0}'s constant commitment is not bound to its old verification share")]
    UnboundReshareDealer(PartyId),
    #[error("local secret share does not match its verification point")]
    LocalShareMismatch,
    #[error("verification share for party {0} is the identity")]
    IdentityVerificationShare(PartyId),
    #[error("verification shares do not lie on one degree-(threshold-1) polynomial")]
    InconsistentVerificationShares,
    #[error("the sharing polynomial has degree below threshold-1")]
    DegenerateSharingPolynomial,
    #[error("verification shares interpolate to a different group key")]
    GroupKeyMismatch,
    #[error("epoch transition must be the immediate successor of {old}, found {new}")]
    InvalidEpochTransition { old: u64, new: u64 },
    #[error("the final epoch cannot be reshared")]
    EpochExhausted,
    #[error("resharing changed the group key")]
    ReshareChangedGroupKey,
    #[error("zero-share refresh requires the same parties, signing identities, and threshold")]
    RefreshCommitteeChanged,
    #[error("proactive zero-share refresh requires threshold at least two")]
    RefreshThresholdTooSmall,
    #[error("zero-share refresh source belongs to party {source_party}, not local party {local}")]
    RefreshSourcePartyMismatch { source_party: PartyId, local: PartyId },
    #[error("zero-share refresh dealer set must contain exactly n-f ({expected}), found {actual}")]
    WrongRefreshDealerCount { expected: u16, actual: usize },
    #[error("zero-share refresh dealer {0} committed to a nonzero constant")]
    NonZeroRefreshConstant(PartyId),
    #[error("threshold-key conversion failed")]
    ThresholdKeyConversion,
}

impl SecretPolynomial {
    pub fn random<R: RngCore + CryptoRng>(threshold: u16, rng: &mut R) -> Result<Self, KeyError> {
        if threshold == 0 {
            return Err(KeyError::WrongDegree);
        }
        let mut coefficients =
            (0..threshold).map(|_| Scalar::random(&mut *rng)).collect::<Vec<_>>();
        // A zero highest coefficient silently lowers the effective threshold. It is negligible
        // for an honest RNG, so rejection sampling is preferable to importing weaker material.
        if threshold > 1 {
            let highest = coefficients.last_mut().expect("threshold is non-zero");
            while *highest == Scalar::ZERO {
                *highest = Scalar::random(&mut *rng);
            }
        }
        Ok(Self { coefficients })
    }

    pub fn random_with_constant<R: RngCore + CryptoRng>(
        threshold: u16,
        constant: Scalar,
        rng: &mut R,
    ) -> Result<Self, KeyError> {
        let mut polynomial = Self::random(threshold, rng)?;
        polynomial.coefficients[0] = constant;
        Ok(polynomial)
    }

    /// Sample a full-degree polynomial whose constant is exactly zero.
    ///
    /// These polynomials are additive proactive-refresh contributions. They must be added to an
    /// already authenticated sharing; aggregating them alone intentionally produces the identity
    /// group key.
    pub fn random_zero_constant<R: RngCore + CryptoRng>(
        threshold: u16,
        rng: &mut R,
    ) -> Result<Self, KeyError> {
        Self::random_with_constant(threshold, Scalar::ZERO, rng)
    }

    pub fn threshold(&self) -> u16 {
        u16::try_from(self.coefficients.len()).expect("polynomial exceeds u16")
    }

    pub fn constant(&self) -> Scalar {
        self.coefficients[0]
    }

    pub fn evaluate(&self, x: Scalar) -> Scalar {
        self.coefficients
            .iter()
            .rev()
            .fold(Scalar::ZERO, |accumulator, coefficient| accumulator * x + coefficient)
    }

    pub fn commitment(&self) -> PolynomialCommitment {
        PolynomialCommitment {
            coefficients: self
                .coefficients
                .iter()
                .map(|coefficient| {
                    PointBytes(EdwardsPoint::mul_base(coefficient).compress().to_bytes())
                })
                .collect(),
        }
    }
}

impl PolynomialCommitment {
    pub fn validate_for_threshold(&self, threshold: u16) -> Result<(), KeyError> {
        if self.coefficients.len() != usize::from(threshold) {
            return Err(KeyError::WrongDegree);
        }
        for coefficient in &self.coefficients {
            coefficient.parse()?;
        }
        Ok(())
    }

    pub fn evaluate(&self, x: Scalar) -> Result<EdwardsPoint, KeyError> {
        self.coefficients.iter().rev().try_fold(EdwardsPoint::identity(), |accumulator, point| {
            Ok((accumulator * x) + point.parse()?)
        })
    }

    pub fn constant(&self) -> Result<EdwardsPoint, KeyError> {
        self.coefficients.first().ok_or(KeyError::WrongDegree)?.parse()
    }

    pub fn has_zero_constant(&self) -> Result<bool, KeyError> {
        Ok(self.constant()?.is_identity())
    }

    pub fn verify_share(&self, x: Scalar, share: Scalar) -> Result<bool, KeyError> {
        Ok(EdwardsPoint::mul_base(&share) == self.evaluate(x)?)
    }
}

impl EpochShare {
    pub fn from_material(material: EpochShareMaterial) -> Result<Self, KeyError> {
        let secret_share = material.secret_share.parse()?;
        let share = Self {
            key_id: material.key_id,
            committee: material.committee.clone(),
            local_party: material.local_party,
            secret_share,
            verification_shares: material.verification_shares.clone(),
            group_key: material.group_key,
        };
        share.validate()?;
        Ok(share)
    }

    pub fn material(&self) -> EpochShareMaterial {
        EpochShareMaterial {
            key_id: self.key_id,
            committee: self.committee.clone(),
            local_party: self.local_party,
            secret_share: self.secret_share.into(),
            verification_shares: self.verification_shares.clone(),
            group_key: self.group_key,
        }
    }

    pub fn secret_share(&self) -> Scalar {
        self.secret_share
    }

    pub fn public(&self) -> EpochPublic {
        EpochPublic {
            key_id: self.key_id,
            committee: self.committee.clone(),
            verification_shares: self.verification_shares.clone(),
            group_key: self.group_key,
        }
    }

    pub fn group_key(&self) -> Result<EdwardsPoint, KeyError> {
        self.group_key.parse()
    }

    pub fn group_key_bytes(&self) -> [u8; 32] {
        self.group_key.0
    }

    pub fn activation_digest(&self) -> Result<[u8; 32], KeyError> {
        self.validate()?;
        self.public().activation_digest()
    }

    pub fn verification_share(&self, party: PartyId) -> Result<EdwardsPoint, KeyError> {
        self.verification_shares
            .get(&party)
            .ok_or(KeyError::Committee(CommitteeError::UnknownParty(party)))?
            .parse()
    }

    /// Recheck all invariants before crossing into the FROSTLASS implementation.
    pub fn validate(&self) -> Result<(), KeyError> {
        self.public().validate()?;
        self.committee.member(self.local_party)?;
        let local = self.verification_share(self.local_party)?;
        if EdwardsPoint::mul_base(&self.secret_share) != local {
            return Err(KeyError::LocalShareMismatch);
        }
        Ok(())
    }

    pub fn to_threshold_keys(&self) -> Result<ThresholdKeys<Ed25519>, KeyError> {
        self.validate()?;
        let local_index = self.committee.frost_index(self.local_party)?;
        let params = ThresholdParams::new(
            self.committee.threshold,
            self.committee.n(),
            Participant::new(local_index).ok_or(KeyError::ThresholdKeyConversion)?,
        )
        .map_err(|_| KeyError::ThresholdKeyConversion)?;

        let verification_shares: HashMap<Participant, <Ed25519 as Ciphersuite>::G> = self
            .committee
            .members
            .iter()
            .map(|member| {
                let index = self.committee.frost_index(member.id)?;
                let participant =
                    Participant::new(index).ok_or(KeyError::ThresholdKeyConversion)?;
                let point = self.verification_share(member.id)?;
                let encoded = point.compress().to_bytes();
                let mut reader = encoded.as_slice();
                let point = <Ed25519 as Ciphersuite>::read_G(&mut reader)
                    .map_err(|_| KeyError::ThresholdKeyConversion)?;
                Ok((participant, point))
            })
            .collect::<Result<HashMap<_, _>, KeyError>>()?;

        ThresholdKeys::new(
            params,
            Interpolation::Lagrange,
            Zeroizing::new(self.secret_share),
            verification_shares,
        )
        .map_err(|_| KeyError::ThresholdKeyConversion)
    }
}

/// Aggregate a common, certified dealer set into a fresh DKG result.
pub fn aggregate_dkg(
    key_id: [u8; 32],
    committee: Committee,
    local_party: PartyId,
    outputs: Vec<DealerOutput>,
) -> Result<EpochShare, KeyError> {
    committee.validate()?;
    if outputs.is_empty() {
        return Err(KeyError::EmptyDealerSet);
    }
    let eligible = committee.members.iter().map(|member| member.id).collect::<BTreeSet<_>>();
    aggregate_outputs(key_id, committee, local_party, &eligible, outputs, None)
}

/// Aggregate a consensus-selected subset of completed DKG dealer instances.
///
/// `selected_dealers` must be the canonical, strictly ascending set agreed by the protocol's
/// common-subset layer. The key layer requires at least `n - f` dealers for the committee's
/// explicitly configured asynchronous fault bound and requires `outputs` to contain that exact
/// set. Every output must already have a valid AVSS certificate bound to the same selection
/// transcript. The fault bound is deliberately not inferred from `n`: deployments may configure a
/// smaller `f`, and their larger `n-f` agreement quorum remains security-critical here.
pub fn aggregate_dkg_subset(
    key_id: [u8; 32],
    committee: Committee,
    local_party: PartyId,
    fault_bound: u16,
    selected_dealers: &[PartyId],
    outputs: Vec<DealerOutput>,
) -> Result<EpochShare, KeyError> {
    committee.validate_async_security_with_faults(fault_bound)?;
    committee.member(local_party)?;
    let selected = validate_canonical_dkg_dealers(&committee, fault_bound, selected_dealers)?;
    aggregate_outputs(key_id, committee, local_party, &selected, outputs, None)
}

/// Aggregate exactly `old.threshold` link-valid old dealers into a new sharing of the same key.
///
/// Each dealer output must already be certified by its AVSS instance. Its constant commitment is
/// checked against `lambda_i * old_verification_share_i`, which prevents a new key from being
/// substituted during a committee transition.
pub fn aggregate_reshare(
    old: &EpochShare,
    new_committee: Committee,
    local_party: PartyId,
    selected_old_dealers: &[PartyId],
    outputs: Vec<DealerOutput>,
) -> Result<EpochShare, KeyError> {
    old.validate()?;
    aggregate_reshare_from_public(
        &old.public(),
        new_committee,
        local_party,
        selected_old_dealers,
        outputs,
    )
}

/// Aggregate a resharing as a newly joining member using only validated old public metadata.
pub fn aggregate_reshare_from_public(
    old: &EpochPublic,
    new_committee: Committee,
    local_party: PartyId,
    selected_old_dealers: &[PartyId],
    outputs: Vec<DealerOutput>,
) -> Result<EpochShare, KeyError> {
    old.validate()?;
    validate_reshare_transition(old, &new_committee, local_party)?;
    let selected = validate_reshare_dealers(old, selected_old_dealers)?;

    let result =
        aggregate_outputs(old.key_id, new_committee, local_party, &selected, outputs, Some(old))?;
    if result.group_key_bytes() != old.group_key_bytes() {
        return Err(KeyError::ReshareChangedGroupKey);
    }
    Ok(result)
}

/// Aggregate raw-share proactive resharing outputs using an old local share.
///
/// Unlike [`aggregate_reshare`], every dealer polynomial has the unweighted constant `p(x_i)`.
/// This lets every old member complete AVSS before a common exact-threshold subset is selected.
/// The recipient validates the raw commitment, applies the subset's Lagrange coefficient to the
/// share and every commitment coefficient, and then runs the same strict weighted aggregation.
pub fn aggregate_proactive_reshare(
    old: &EpochShare,
    new_committee: Committee,
    local_party: PartyId,
    selected_old_dealers: &[PartyId],
    outputs: Vec<DealerOutput>,
) -> Result<EpochShare, KeyError> {
    old.validate()?;
    aggregate_proactive_reshare_from_public(
        &old.public(),
        new_committee,
        local_party,
        selected_old_dealers,
        outputs,
    )
}

/// Aggregate raw-share proactive resharing outputs using only old public metadata.
pub fn aggregate_proactive_reshare_from_public(
    old: &EpochPublic,
    new_committee: Committee,
    local_party: PartyId,
    selected_old_dealers: &[PartyId],
    outputs: Vec<DealerOutput>,
) -> Result<EpochShare, KeyError> {
    old.validate()?;
    validate_reshare_transition(old, &new_committee, local_party)?;
    let selected = validate_canonical_reshare_dealers(old, selected_old_dealers)?;
    let weighted_outputs = weight_proactive_outputs(
        old,
        &new_committee,
        local_party,
        selected_old_dealers,
        &selected,
        outputs,
    )?;

    let result = aggregate_outputs(
        old.key_id,
        new_committee,
        local_party,
        &selected,
        weighted_outputs,
        Some(old),
    )?;
    if result.group_key_bytes() != old.group_key_bytes() {
        return Err(KeyError::ReshareChangedGroupKey);
    }
    Ok(result)
}

/// Add an agreed set of zero-constant AVSS contributions to the local source share.
///
/// This is the proactive refresh operation for a committee whose stable party identifiers,
/// signing identities, and threshold are unchanged. It is deliberately distinct from
/// [`aggregate_proactive_reshare`], which redistributes Lagrange-weighted old shares across a
/// changed committee or threshold.
///
/// `selected_refresh_dealers` is the exact canonical `n-f` set decided by refresh QUAL. Requiring
/// `n-f` means at least `n-2f` contributions are honest under the configured fault assumption,
/// while up to `f` silent or invalid dealers cannot block progress.
pub fn aggregate_zero_share_refresh(
    old: &EpochShare,
    new_committee: Committee,
    local_party: PartyId,
    fault_bound: u16,
    selected_refresh_dealers: &[PartyId],
    outputs: Vec<DealerOutput>,
) -> Result<EpochShare, KeyError> {
    old.validate()?;
    validate_zero_share_refresh_transition(
        &old.public(),
        &new_committee,
        local_party,
        fault_bound,
    )?;
    if old.local_party != local_party {
        return Err(KeyError::RefreshSourcePartyMismatch {
            source_party: old.local_party,
            local: local_party,
        });
    }

    let expected = new_committee.n().saturating_sub(fault_bound);
    if selected_refresh_dealers.len() != usize::from(expected) {
        return Err(KeyError::WrongRefreshDealerCount {
            expected,
            actual: selected_refresh_dealers.len(),
        });
    }
    let selected = validate_canonical_dealer_subset(&old.committee, selected_refresh_dealers)?;
    let local_x = scalar_for_party(&new_committee, local_party)?;
    let mut seen = BTreeSet::new();
    let mut refreshed_secret = old.secret_share;
    let mut contribution_commitments =
        vec![EdwardsPoint::identity(); usize::from(new_committee.threshold)];

    for output in outputs {
        if !selected.contains(&output.dealer) {
            return Err(KeyError::IneligibleDealer(output.dealer));
        }
        if !seen.insert(output.dealer) {
            return Err(KeyError::DuplicateDealer(output.dealer));
        }
        output.commitment.validate_for_threshold(new_committee.threshold)?;
        if !output.commitment.has_zero_constant()? {
            return Err(KeyError::NonZeroRefreshConstant(output.dealer));
        }
        let dealer_share = output.share.parse()?;
        if !output.commitment.verify_share(local_x, dealer_share)? {
            return Err(KeyError::InvalidDealerShare(output.dealer));
        }
        refreshed_secret += dealer_share;
        for (aggregate, coefficient) in
            contribution_commitments.iter_mut().zip(&output.commitment.coefficients)
        {
            *aggregate += coefficient.parse()?;
        }
    }
    if seen != selected {
        let missing = selected
            .difference(&seen)
            .next()
            .copied()
            .expect("an unequal subset with no ineligible entries must omit a selected dealer");
        return Err(KeyError::MissingDealer(missing));
    }
    if !contribution_commitments[0].is_identity() {
        // Every independently verified contribution was zero-constant. Reaching this branch would
        // require an internal arithmetic or representation error.
        return Err(KeyError::ReshareChangedGroupKey);
    }

    let contribution = PolynomialCommitment {
        coefficients: contribution_commitments.into_iter().map(PointBytes::from).collect(),
    };
    let verification_shares = new_committee
        .members
        .iter()
        .map(|member| {
            let x = scalar_for_party(&new_committee, member.id)?;
            Ok((
                member.id,
                PointBytes::from(old.verification_share(member.id)? + contribution.evaluate(x)?),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, KeyError>>()?;
    let result = EpochShare {
        key_id: old.key_id,
        committee: new_committee,
        local_party,
        secret_share: refreshed_secret,
        verification_shares,
        group_key: old.group_key,
    };
    result.validate()?;
    if result.group_key_bytes() != old.group_key_bytes() {
        return Err(KeyError::ReshareChangedGroupKey);
    }
    Ok(result)
}

fn aggregate_outputs(
    key_id: [u8; 32],
    committee: Committee,
    local_party: PartyId,
    eligible: &BTreeSet<PartyId>,
    outputs: Vec<DealerOutput>,
    old: Option<&EpochPublic>,
) -> Result<EpochShare, KeyError> {
    let local_x = scalar_for_party(&committee, local_party)?;
    let mut seen = BTreeSet::new();
    let mut share = Scalar::ZERO;
    let mut aggregate_commitments =
        vec![EdwardsPoint::identity(); usize::from(committee.threshold)];

    for output in outputs {
        if !eligible.contains(&output.dealer) {
            return Err(KeyError::IneligibleDealer(output.dealer));
        }
        if !seen.insert(output.dealer) {
            return Err(KeyError::DuplicateDealer(output.dealer));
        }
        output.commitment.validate_for_threshold(committee.threshold)?;
        let dealer_share = output.share.parse()?;
        if !output.commitment.verify_share(local_x, dealer_share)? {
            return Err(KeyError::InvalidDealerShare(output.dealer));
        }

        if let Some(old) = old {
            let selected = eligible.iter().copied().collect::<Vec<_>>();
            let lambda = lagrange_for_party_at_zero(&old.committee, output.dealer, &selected)?;
            if output.commitment.constant()? != old.verification_share(output.dealer)? * lambda {
                return Err(KeyError::UnboundReshareDealer(output.dealer));
            }
        }

        share += dealer_share;
        for (aggregate, coefficient) in
            aggregate_commitments.iter_mut().zip(&output.commitment.coefficients)
        {
            *aggregate += coefficient.parse()?;
        }
    }
    if seen != *eligible {
        let missing =
            eligible.difference(&seen).next().copied().expect(
                "an unequal subset with no ineligible entries must omit an eligible dealer",
            );
        return Err(KeyError::MissingDealer(missing));
    }

    let aggregate = PolynomialCommitment {
        coefficients: aggregate_commitments.into_iter().map(PointBytes::from).collect(),
    };
    let verification_shares = committee
        .members
        .iter()
        .map(|member| {
            Ok((
                member.id,
                PointBytes::from(aggregate.evaluate(scalar_for_party(&committee, member.id)?)?),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, KeyError>>()?;
    let result = EpochShare {
        key_id,
        committee,
        local_party,
        secret_share: share,
        verification_shares,
        group_key: PointBytes::from(aggregate.constant()?),
    };
    result.validate()?;
    Ok(result)
}

pub fn make_dkg_output(
    dealer: PartyId,
    polynomial: &SecretPolynomial,
    target_committee: &Committee,
    recipient: PartyId,
) -> Result<DealerOutput, KeyError> {
    if polynomial.threshold() != target_committee.threshold {
        return Err(KeyError::WrongDegree);
    }
    target_committee.member(recipient)?;
    Ok(DealerOutput {
        dealer,
        share: polynomial.evaluate(scalar_for_party(target_committee, recipient)?).into(),
        commitment: polynomial.commitment(),
    })
}

pub fn make_reshare_polynomial<R: RngCore + CryptoRng>(
    old: &EpochShare,
    dealer: PartyId,
    selected_old_dealers: &[PartyId],
    new_threshold: u16,
    rng: &mut R,
) -> Result<SecretPolynomial, KeyError> {
    old.validate()?;
    if dealer != old.local_party {
        return Err(KeyError::IneligibleDealer(dealer));
    }
    let selected = validate_reshare_dealers(&old.public(), selected_old_dealers)?;
    if !selected.contains(&dealer) {
        return Err(KeyError::IneligibleDealer(dealer));
    }
    let lambda = lagrange_for_party_at_zero(&old.committee, dealer, selected_old_dealers)?;
    SecretPolynomial::random_with_constant(new_threshold, lambda * old.secret_share, rng)
}

/// Create a proactive resharing polynomial whose constant is the dealer's raw old share.
///
/// All old members may deal these polynomials before the eventual exact-threshold subset is
/// known. Recipients must use [`aggregate_proactive_reshare`] or
/// [`aggregate_proactive_reshare_from_public`] so the complete polynomial is weighted only after
/// the common subset is fixed.
pub fn make_proactive_reshare_polynomial<R: RngCore + CryptoRng>(
    old: &EpochShare,
    dealer: PartyId,
    new_threshold: u16,
    rng: &mut R,
) -> Result<SecretPolynomial, KeyError> {
    old.validate()?;
    if dealer != old.local_party {
        return Err(KeyError::IneligibleDealer(dealer));
    }
    SecretPolynomial::random_with_constant(new_threshold, old.secret_share, rng)
}

/// Create one independently randomized, zero-constant contribution for a same-committee refresh.
pub fn make_zero_share_refresh_polynomial<R: RngCore + CryptoRng>(
    old: &EpochShare,
    dealer: PartyId,
    new_committee: &Committee,
    fault_bound: u16,
    rng: &mut R,
) -> Result<SecretPolynomial, KeyError> {
    old.validate()?;
    if dealer != old.local_party {
        return Err(KeyError::IneligibleDealer(dealer));
    }
    validate_zero_share_refresh_transition(&old.public(), new_committee, dealer, fault_bound)?;
    SecretPolynomial::random_zero_constant(new_committee.threshold, rng)
}

fn validate_reshare_transition(
    old: &EpochPublic,
    new_committee: &Committee,
    local_party: PartyId,
) -> Result<(), KeyError> {
    new_committee.validate()?;
    new_committee.member(local_party)?;
    let expected_epoch = old.committee.epoch.checked_add(1).ok_or(KeyError::EpochExhausted)?;
    if new_committee.epoch != expected_epoch {
        return Err(KeyError::InvalidEpochTransition {
            old: old.committee.epoch,
            new: new_committee.epoch,
        });
    }
    Ok(())
}

fn validate_zero_share_refresh_transition(
    old: &EpochPublic,
    new_committee: &Committee,
    local_party: PartyId,
    fault_bound: u16,
) -> Result<(), KeyError> {
    validate_reshare_transition(old, new_committee, local_party)?;
    if old.committee.threshold < 2 || new_committee.threshold < 2 {
        // A threshold-one sharing has no non-constant coefficient. Its only zero-constant
        // polynomial is identically zero, so accepting it would call a no-op a proactive refresh
        // and leave the old scalar valid forever.
        return Err(KeyError::RefreshThresholdTooSmall);
    }
    old.committee.validate_async_security_with_faults(fault_bound)?;
    new_committee.validate_async_security_with_faults(fault_bound)?;
    if old.committee.threshold != new_committee.threshold
        || old.committee.n() != new_committee.n()
        || old.committee.members.iter().any(|old_member| {
            new_committee
                .member(old_member.id)
                .map_or(true, |new_member| new_member.signing_key != old_member.signing_key)
        })
    {
        return Err(KeyError::RefreshCommitteeChanged);
    }
    Ok(())
}

fn validate_canonical_dkg_dealers(
    committee: &Committee,
    fault_bound: u16,
    selected_dealers: &[PartyId],
) -> Result<BTreeSet<PartyId>, KeyError> {
    let selected = validate_canonical_dealer_subset(committee, selected_dealers)?;
    let minimum = committee.n().saturating_sub(fault_bound);
    if selected.len() < usize::from(minimum) {
        return Err(KeyError::InsufficientDkgDealers { minimum, actual: selected.len() });
    }
    Ok(selected)
}

fn validate_canonical_reshare_dealers(
    old: &EpochPublic,
    selected_old_dealers: &[PartyId],
) -> Result<BTreeSet<PartyId>, KeyError> {
    if selected_old_dealers.len() != usize::from(old.committee.threshold) {
        return Err(KeyError::WrongReshareDealerCount {
            expected: old.committee.threshold,
            actual: selected_old_dealers.len(),
        });
    }
    validate_canonical_dealer_subset(&old.committee, selected_old_dealers)
}

fn validate_canonical_dealer_subset(
    committee: &Committee,
    selected_dealers: &[PartyId],
) -> Result<BTreeSet<PartyId>, KeyError> {
    if selected_dealers.is_empty() {
        return Err(KeyError::EmptyDealerSet);
    }

    let mut selected = BTreeSet::new();
    let mut previous = None;
    for dealer in selected_dealers {
        if committee.member(*dealer).is_err() {
            return Err(KeyError::IneligibleDealer(*dealer));
        }
        if let Some(previous) = previous {
            if *dealer == previous {
                return Err(KeyError::DuplicateDealer(*dealer));
            }
            if *dealer < previous {
                return Err(KeyError::NonCanonicalDealerSet);
            }
        }
        selected.insert(*dealer);
        previous = Some(*dealer);
    }
    Ok(selected)
}

fn weight_proactive_outputs(
    old: &EpochPublic,
    new_committee: &Committee,
    local_party: PartyId,
    selected_old_dealers: &[PartyId],
    selected: &BTreeSet<PartyId>,
    outputs: Vec<DealerOutput>,
) -> Result<Vec<DealerOutput>, KeyError> {
    let local_x = scalar_for_party(new_committee, local_party)?;
    let mut seen = BTreeSet::new();
    let mut weighted = Vec::with_capacity(outputs.len());

    for mut output in outputs {
        if !selected.contains(&output.dealer) {
            return Err(KeyError::IneligibleDealer(output.dealer));
        }
        if !seen.insert(output.dealer) {
            return Err(KeyError::DuplicateDealer(output.dealer));
        }
        output.commitment.validate_for_threshold(new_committee.threshold)?;
        let dealer_share = output.share.parse()?;
        if !output.commitment.verify_share(local_x, dealer_share)? {
            return Err(KeyError::InvalidDealerShare(output.dealer));
        }
        if output.commitment.constant()? != old.verification_share(output.dealer)? {
            return Err(KeyError::UnboundReshareDealer(output.dealer));
        }

        let lambda =
            lagrange_for_party_at_zero(&old.committee, output.dealer, selected_old_dealers)?;
        output.share = ScalarBytes::from(lambda * dealer_share);
        for coefficient in &mut output.commitment.coefficients {
            *coefficient = PointBytes::from(coefficient.parse()? * lambda);
        }
        weighted.push(output);
    }

    if seen != *selected {
        let missing = selected
            .difference(&seen)
            .next()
            .copied()
            .expect("an unequal subset with no ineligible entries must omit a selected dealer");
        return Err(KeyError::MissingDealer(missing));
    }
    Ok(weighted)
}

fn validate_reshare_dealers(
    old: &EpochPublic,
    selected_old_dealers: &[PartyId],
) -> Result<BTreeSet<PartyId>, KeyError> {
    if selected_old_dealers.len() != usize::from(old.committee.threshold) {
        return Err(KeyError::WrongReshareDealerCount {
            expected: old.committee.threshold,
            actual: selected_old_dealers.len(),
        });
    }

    validate_canonical_dealer_subset(&old.committee, selected_old_dealers)
}

pub fn scalar_for_party(committee: &Committee, party: PartyId) -> Result<Scalar, KeyError> {
    Ok(Scalar::from(u64::from(committee.frost_index(party)?)))
}

pub fn lagrange_for_party_at_zero(
    committee: &Committee,
    party: PartyId,
    included: &[PartyId],
) -> Result<Scalar, KeyError> {
    committee.validate()?;
    if !included.contains(&party) {
        return Err(KeyError::IneligibleDealer(party));
    }
    let x_i = scalar_for_party(committee, party)?;
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    let mut seen = BTreeSet::new();
    for member in included {
        if !seen.insert(*member) {
            return Err(KeyError::DuplicateDealer(*member));
        }
        if *member == party {
            continue;
        }
        let x_j = scalar_for_party(committee, *member)?;
        numerator *= -x_j;
        denominator *= x_i - x_j;
    }
    Ok(numerator * denominator.invert())
}

fn interpolate_points(
    target: Scalar,
    points: &[(Scalar, EdwardsPoint)],
) -> Result<EdwardsPoint, KeyError> {
    if points.is_empty() {
        return Err(KeyError::EmptyDealerSet);
    }
    let mut result = EdwardsPoint::identity();
    for (index, (x_i, point)) in points.iter().enumerate() {
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (other_index, (x_j, _)) in points.iter().enumerate() {
            if index == other_index {
                continue;
            }
            numerator *= target - x_j;
            denominator *= x_i - x_j;
        }
        if denominator == Scalar::ZERO {
            return Err(KeyError::InconsistentVerificationShares);
        }
        result += point * (numerator * denominator.invert());
    }
    Ok(result)
}

/// Recover the highest-degree coefficient of the unique polynomial through `points`.
fn highest_coefficient(points: &[(Scalar, EdwardsPoint)]) -> Result<EdwardsPoint, KeyError> {
    if points.is_empty() {
        return Err(KeyError::EmptyDealerSet);
    }

    let mut result = EdwardsPoint::identity();
    for (index, (x_i, point)) in points.iter().enumerate() {
        let mut denominator = Scalar::ONE;
        for (other_index, (x_j, _)) in points.iter().enumerate() {
            if index != other_index {
                denominator *= x_i - x_j;
            }
        }
        if denominator == Scalar::ZERO {
            return Err(KeyError::InconsistentVerificationShares);
        }
        result += point * denominator.invert();
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};

    use super::*;
    use crate::{committee::Member, identity::Identity};

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0xa3; 32];
        secret[2..10].copy_from_slice(&epoch.to_le_bytes());
        // X25519 clears the low three bits of byte zero. Small party identifiers encoded there
        // therefore collapse to the same private scalar (and public encryption key). Keep the
        // per-party discriminator in bytes which survive clamping unchanged.
        secret[10..12].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    fn committee(epoch: u64, threshold: u16, ids: &[u16]) -> Committee {
        Committee {
            epoch,
            threshold,
            members: ids
                .iter()
                .map(|id| {
                    let party = PartyId(*id);
                    let signing_seed = [u8::try_from(*id).unwrap(); 32];
                    let identity = Identity::from_test_secrets(
                        party,
                        epoch,
                        &signing_seed,
                        test_x25519_secret(party, epoch),
                    )
                    .unwrap();
                    Member {
                        id: party,
                        signing_key: identity.signing_public_key(),
                        encryption_key: identity.encryption_public_key(),
                    }
                })
                .collect(),
        }
    }

    fn dkg_all(committee: &Committee) -> BTreeMap<PartyId, EpochShare> {
        let polynomials = committee
            .members
            .iter()
            .map(|member| {
                (member.id, SecretPolynomial::random(committee.threshold, &mut OsRng).unwrap())
            })
            .collect::<BTreeMap<_, _>>();
        committee
            .members
            .iter()
            .map(|recipient| {
                let outputs = polynomials
                    .iter()
                    .map(|(dealer, polynomial)| {
                        make_dkg_output(*dealer, polynomial, committee, recipient.id).unwrap()
                    })
                    .collect();
                (
                    recipient.id,
                    aggregate_dkg([7; 32], committee.clone(), recipient.id, outputs).unwrap(),
                )
            })
            .collect()
    }

    fn deterministic_rng(domain: u8, epoch: u64, party: PartyId) -> ChaCha20Rng {
        let mut seed = [0_u8; 32];
        seed[0] = domain;
        seed[1..9].copy_from_slice(&epoch.to_le_bytes());
        seed[9..11].copy_from_slice(&party.0.to_le_bytes());
        ChaCha20Rng::from_seed(seed)
    }

    fn deterministic_dkg_all(committee: &Committee, domain: u8) -> BTreeMap<PartyId, EpochShare> {
        let polynomials = committee
            .members
            .iter()
            .map(|member| {
                let mut rng = deterministic_rng(domain, committee.epoch, member.id);
                (member.id, SecretPolynomial::random(committee.threshold, &mut rng).unwrap())
            })
            .collect::<BTreeMap<_, _>>();

        committee
            .members
            .iter()
            .map(|recipient| {
                let outputs = polynomials
                    .iter()
                    .map(|(dealer, polynomial)| {
                        make_dkg_output(*dealer, polynomial, committee, recipient.id).unwrap()
                    })
                    .collect();
                (
                    recipient.id,
                    aggregate_dkg([domain; 32], committee.clone(), recipient.id, outputs).unwrap(),
                )
            })
            .collect()
    }

    fn deterministic_zero_refresh_all(
        old: &BTreeMap<PartyId, EpochShare>,
        new_committee: &Committee,
        fault_bound: u16,
        selected_dealers: &[PartyId],
        domain: u8,
    ) -> BTreeMap<PartyId, EpochShare> {
        let polynomials = selected_dealers
            .iter()
            .copied()
            .map(|dealer| {
                let mut rng = deterministic_rng(domain, new_committee.epoch, dealer);
                (
                    dealer,
                    make_zero_share_refresh_polynomial(
                        &old[&dealer],
                        dealer,
                        new_committee,
                        fault_bound,
                        &mut rng,
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        new_committee
            .members
            .iter()
            .map(|recipient| {
                let outputs = selected_dealers
                    .iter()
                    .map(|dealer| {
                        make_dkg_output(*dealer, &polynomials[dealer], new_committee, recipient.id)
                            .unwrap()
                    })
                    .collect();
                (
                    recipient.id,
                    aggregate_zero_share_refresh(
                        &old[&recipient.id],
                        new_committee.clone(),
                        recipient.id,
                        fault_bound,
                        selected_dealers,
                        outputs,
                    )
                    .unwrap(),
                )
            })
            .collect()
    }

    fn threshold_subsets(parties: &[PartyId], threshold: usize) -> Vec<Vec<PartyId>> {
        assert!(parties.len() < usize::BITS as usize);
        (0_usize..(1_usize << parties.len()))
            .filter(|mask| mask.count_ones() as usize == threshold)
            .map(|mask| {
                parties
                    .iter()
                    .copied()
                    .enumerate()
                    .filter_map(|(index, party)| {
                        ((mask & (1_usize << index)) != 0).then_some(party)
                    })
                    .collect()
            })
            .collect()
    }

    fn reconstruct_at_zero(committee: &Committee, samples: &[(PartyId, Scalar)]) -> Scalar {
        let parties = samples.iter().map(|(party, _)| *party).collect::<Vec<_>>();
        samples
            .iter()
            .map(|(party, share)| {
                *share * lagrange_for_party_at_zero(committee, *party, &parties).unwrap()
            })
            .sum()
    }

    #[test]
    fn dkg_outputs_valid_frost_keys() {
        let committee = committee(0, 3, &[1, 2, 3, 4, 5]);
        let shares = dkg_all(&committee);
        let group = shares[&PartyId(1)].group_key_bytes();
        for share in shares.values() {
            share.validate().unwrap();
            assert_eq!(share.group_key_bytes(), group);
            assert_eq!(
                share.to_threshold_keys().unwrap().group_key().0.compress().to_bytes(),
                group
            );
        }
    }

    #[test]
    fn reshare_expands_and_shrinks_without_changing_key() {
        let old_committee = committee(0, 3, &[1, 2, 3, 4, 5]);
        let old = dkg_all(&old_committee);
        let group = old[&PartyId(1)].group_key_bytes();

        let expanded = committee(1, 4, &[1, 2, 3, 4, 5, 6, 7]);
        let selected = vec![PartyId(1), PartyId(3), PartyId(5)];
        let polynomials = selected
            .iter()
            .map(|dealer| {
                (
                    *dealer,
                    make_reshare_polynomial(
                        &old[dealer],
                        *dealer,
                        &selected,
                        expanded.threshold,
                        &mut OsRng,
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let expanded_shares = expanded
            .members
            .iter()
            .map(|recipient| {
                let outputs = polynomials
                    .iter()
                    .map(|(dealer, polynomial)| {
                        make_dkg_output(*dealer, polynomial, &expanded, recipient.id).unwrap()
                    })
                    .collect();
                (
                    recipient.id,
                    aggregate_reshare(
                        &old[&selected[0]],
                        expanded.clone(),
                        recipient.id,
                        &selected,
                        outputs,
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert!(expanded_shares.values().all(|share| share.group_key_bytes() == group));

        let shrunk = committee(2, 2, &[2, 4, 6]);
        let selected_expanded = vec![PartyId(1), PartyId(2), PartyId(5), PartyId(7)];
        let polynomials = selected_expanded
            .iter()
            .map(|dealer| {
                (
                    *dealer,
                    make_reshare_polynomial(
                        &expanded_shares[dealer],
                        *dealer,
                        &selected_expanded,
                        shrunk.threshold,
                        &mut OsRng,
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for recipient in &shrunk.members {
            let outputs = polynomials
                .iter()
                .map(|(dealer, polynomial)| {
                    make_dkg_output(*dealer, polynomial, &shrunk, recipient.id).unwrap()
                })
                .collect();
            let share = aggregate_reshare(
                &expanded_shares[&selected_expanded[0]],
                shrunk.clone(),
                recipient.id,
                &selected_expanded,
                outputs,
            )
            .unwrap();
            assert_eq!(share.group_key_bytes(), group);
            share.to_threshold_keys().unwrap();
        }
    }

    #[test]
    fn proactive_refresh_preserves_constant_and_isolates_all_epoch_share_mixes() {
        let initial_committee = committee(40, 3, &[1, 2, 3, 4, 5]);
        let initial = deterministic_dkg_all(&initial_committee, 191);
        let selected_dealers = [PartyId(1), PartyId(2), PartyId(3), PartyId(4)];

        let first_committee = committee(41, 3, &[1, 2, 3, 4, 5]);
        let first =
            deterministic_zero_refresh_all(&initial, &first_committee, 1, &selected_dealers, 192);
        let second_committee = committee(42, 3, &[1, 2, 3, 4, 5]);
        let second =
            deterministic_zero_refresh_all(&first, &second_committee, 1, &selected_dealers, 193);

        let parties = initial_committee.members.iter().map(|member| member.id).collect::<Vec<_>>();
        let subsets = threshold_subsets(&parties, usize::from(initial_committee.threshold));
        let reference_samples = subsets[0]
            .iter()
            .map(|party| (*party, initial[party].secret_share()))
            .collect::<Vec<_>>();
        let constant = reconstruct_at_zero(&initial_committee, &reference_samples);
        let group_key = initial.values().next().unwrap().group_key().unwrap();
        assert_eq!(EdwardsPoint::mul_base(&constant), group_key);

        // Every valid current-epoch threshold subset reconstructs the same scalar constant, and
        // every installed share exposes the unchanged public group key.
        for epoch in [&initial, &first, &second] {
            for share in epoch.values() {
                assert_eq!(share.group_key().unwrap(), group_key);
            }
            for subset in &subsets {
                let samples = subset
                    .iter()
                    .map(|party| (*party, epoch[party].secret_share()))
                    .collect::<Vec<_>>();
                assert_eq!(reconstruct_at_zero(&epoch[&subset[0]].committee, &samples), constant);
            }
        }

        // The transcript is actually refreshed rather than merely carrying the old polynomial
        // forward. These checks also make a future accidental deterministic-RNG collision clear.
        assert_ne!(
            initial.values().next().unwrap().public().verification_shares,
            first.values().next().unwrap().public().verification_shares,
        );
        assert_ne!(
            first.values().next().unwrap().public().verification_shares,
            second.values().next().unwrap().public().verification_shares,
        );

        // Exhaust every threshold subset and every assignment containing at least one share from
        // each epoch. This deterministic vector covers initial/first, first/second, and stale
        // initial/current mixing: C(5, 3) * (2^3 - 2) * 3 = 180 mixed reconstructions.
        let epoch_pairs = [
            ("initial/first", &initial, &first),
            ("first/second", &first, &second),
            ("initial/second", &initial, &second),
        ];
        let mut mixed_reconstructions = 0_usize;
        for (label, older, newer) in epoch_pairs {
            for subset in &subsets {
                let all_newer_mask = (1_usize << subset.len()) - 1;
                for newer_mask in 1_usize..all_newer_mask {
                    let samples = subset
                        .iter()
                        .copied()
                        .enumerate()
                        .map(|(index, party)| {
                            let share = if (newer_mask & (1_usize << index)) == 0 {
                                older[&party].secret_share()
                            } else {
                                newer[&party].secret_share()
                            };
                            (party, share)
                        })
                        .collect::<Vec<_>>();
                    let mixed = reconstruct_at_zero(&newer[&subset[0]].committee, &samples);
                    assert_ne!(
                        mixed, constant,
                        "{label} subset {subset:?} with newer mask {newer_mask:#b} reconstructed \
                         the group secret"
                    );
                    mixed_reconstructions += 1;
                }
            }
        }
        assert_eq!(mixed_reconstructions, 180);
    }

    #[test]
    fn threshold_one_cannot_claim_a_proactive_zero_refresh() {
        let initial_committee = committee(50, 1, &[1]);
        let initial = deterministic_dkg_all(&initial_committee, 201);
        let target = committee(51, 1, &[1]);
        let error = make_zero_share_refresh_polynomial(
            &initial[&PartyId(1)],
            PartyId(1),
            &target,
            0,
            &mut ChaCha20Rng::from_seed([202; 32]),
        )
        .unwrap_err();
        assert_eq!(error, KeyError::RefreshThresholdTooSmall);
    }

    #[test]
    fn changed_threshold_requires_old_threshold_dealers() {
        let old_committee = committee(0, 3, &[1, 2, 3, 4]);
        let old = dkg_all(&old_committee);
        let new_committee = committee(1, 2, &[1, 2, 3]);
        let error = aggregate_reshare(
            &old[&PartyId(1)],
            new_committee,
            PartyId(1),
            &[PartyId(1), PartyId(2)],
            vec![],
        )
        .unwrap_err();
        assert_eq!(error, KeyError::WrongReshareDealerCount { expected: 3, actual: 2 });
    }
}
