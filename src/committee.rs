use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const COMMITTEE_DIGEST_VERSION: u16 = 2;

/// Engineering resource cap for one threshold committee.
///
/// This is not a protocol-theory limit. A durable AVSS run retains one receiver machine per
/// dealer plus bounded encrypted fan-out/retry material, whose worst-case growth is quartic when
/// the dealer count and threshold both track `n`. Ten keeps that complete run comfortably below
/// the 8 MiB protocol-session snapshot ceiling while preserving the deployment's 3/5, 4/7, and
/// 2/3 quorum profiles.
pub const MAX_COMMITTEE_MEMBERS: usize = 10;

/// Matching resource cap for a threshold (`degree + 1`).
pub const MAX_COMMITTEE_THRESHOLD: u16 = MAX_COMMITTEE_MEMBERS as u16;

/// Stable, application-level party identifier.
///
/// FROST participant indices are derived from the sorted committee and are deliberately scoped to
/// an epoch. A party may therefore move to a different FROST index after resharing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PartyId(pub u16);

impl PartyId {
    pub fn new(value: u16) -> Result<Self, CommitteeError> {
        if value == 0 {
            return Err(CommitteeError::ZeroPartyId);
        }
        Ok(Self(value))
    }
}

impl std::fmt::Display for PartyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Globally unique protocol session identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    pub fn derive(domain: &[u8], material: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/session-id/v1");
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        hasher.update(&(material.len() as u64).to_le_bytes());
        hasher.update(material);
        Self(*hasher.finalize().as_bytes())
    }

    pub fn random(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> Self {
        let mut bytes = [0_u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Security-relevant public information for one committee member.
///
/// Network routes and transport certificates deliberately live outside this type. Changing a
/// hostname, UDP port, or TLS certificate must not change an epoch's cryptographic identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Member {
    pub id: PartyId,
    /// Ed25519 verification key.
    pub signing_key: [u8; 32],
    /// X25519 static public key used to protect point-to-point shares.
    pub encryption_key: [u8; 32],
}

/// Ordered committee configuration for one sharing epoch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Committee {
    pub epoch: u64,
    /// Number of shares required to sign/reconstruct; this is `degree + 1`.
    pub threshold: u16,
    pub members: Vec<Member>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CommitteeError {
    #[error("party identifiers are non-zero")]
    ZeroPartyId,
    #[error("committee cannot be empty")]
    Empty,
    #[error("committee has {members} members; maximum is {maximum}")]
    TooManyMembers { members: usize, maximum: usize },
    #[error("threshold {threshold} exceeds the resource maximum {maximum}")]
    ThresholdTooLarge { threshold: u16, maximum: u16 },
    #[error("threshold {threshold} is not in 1..={members}")]
    InvalidThreshold { threshold: u16, members: usize },
    #[error("duplicate party identifier {0}")]
    DuplicateParty(PartyId),
    #[error("duplicate signing key")]
    DuplicateSigningKey,
    #[error("duplicate encryption key")]
    DuplicateEncryptionKey,
    #[error("party {0} is not in the committee")]
    UnknownParty(PartyId),
    #[error("asynchronous Byzantine operation requires n >= 3f + 1")]
    InvalidFaultBound,
}

impl Committee {
    pub fn validate(&self) -> Result<(), CommitteeError> {
        if self.members.is_empty() {
            return Err(CommitteeError::Empty);
        }
        if self.members.len() > MAX_COMMITTEE_MEMBERS {
            return Err(CommitteeError::TooManyMembers {
                members: self.members.len(),
                maximum: MAX_COMMITTEE_MEMBERS,
            });
        }
        if self.threshold > MAX_COMMITTEE_THRESHOLD {
            return Err(CommitteeError::ThresholdTooLarge {
                threshold: self.threshold,
                maximum: MAX_COMMITTEE_THRESHOLD,
            });
        }
        if self.threshold == 0 || usize::from(self.threshold) > self.members.len() {
            return Err(CommitteeError::InvalidThreshold {
                threshold: self.threshold,
                members: self.members.len(),
            });
        }

        let mut ids = BTreeSet::new();
        let mut signing_keys = BTreeSet::new();
        let mut encryption_keys = BTreeSet::new();
        for member in &self.members {
            if member.id.0 == 0 {
                return Err(CommitteeError::ZeroPartyId);
            }
            if !ids.insert(member.id) {
                return Err(CommitteeError::DuplicateParty(member.id));
            }
            if !signing_keys.insert(member.signing_key) {
                return Err(CommitteeError::DuplicateSigningKey);
            }
            if !encryption_keys.insert(member.encryption_key) {
                return Err(CommitteeError::DuplicateEncryptionKey);
            }
        }
        Ok(())
    }

    pub fn canonicalized(mut self) -> Result<Self, CommitteeError> {
        self.validate()?;
        self.members.sort_by_key(|member| member.id);
        Ok(self)
    }

    pub fn n(&self) -> u16 {
        u16::try_from(self.members.len()).expect("validated committee exceeds u16")
    }

    /// Maximum Byzantine faults tolerated by Bracha reliable broadcast.
    pub fn fault_bound(&self) -> u16 {
        self.n().saturating_sub(1) / 3
    }

    /// Validate CKLS AVSS bounds at the committee's maximum asynchronous fault tolerance.
    ///
    /// Deployments may deliberately configure a smaller `f` to support a higher signing
    /// threshold; use [`Self::validate_async_security_with_faults`] for that case.
    pub fn validate_async_security(&self) -> Result<(), CommitteeError> {
        self.validate_async_security_with_faults(self.fault_bound())
    }

    /// Validate an explicit asynchronous Byzantine fault assumption.
    ///
    /// The Feldman/CKLS AVSS implementation requires `n >= 3f + 1` and
    /// `f < threshold <= n - 2f`. The fault bound is not inferred from `n`: doing so would make
    /// the first inequality tautological and would incorrectly reject useful higher-threshold
    /// configurations which intentionally assume a smaller `f`.
    pub fn validate_async_security_with_faults(&self, faults: u16) -> Result<(), CommitteeError> {
        self.validate()?;
        if self.n() < faults.saturating_mul(3).saturating_add(1)
            || self.threshold <= faults
            || self.threshold > self.n().saturating_sub(faults.saturating_mul(2))
        {
            return Err(CommitteeError::InvalidFaultBound);
        }
        Ok(())
    }

    pub fn member(&self, id: PartyId) -> Result<&Member, CommitteeError> {
        self.members.iter().find(|member| member.id == id).ok_or(CommitteeError::UnknownParty(id))
    }

    /// Convert a stable party ID to the contiguous, one-based index required by FROST.
    pub fn frost_index(&self, id: PartyId) -> Result<u16, CommitteeError> {
        let mut ids = self.members.iter().map(|member| member.id).collect::<Vec<_>>();
        ids.sort_unstable();
        ids.iter()
            .position(|candidate| *candidate == id)
            .map(|index| u16::try_from(index + 1).expect("committee index exceeds u16"))
            .ok_or(CommitteeError::UnknownParty(id))
    }

    pub fn party_for_frost_index(&self, index: u16) -> Result<PartyId, CommitteeError> {
        let mut ids = self.members.iter().map(|member| member.id).collect::<Vec<_>>();
        ids.sort_unstable();
        index
            .checked_sub(1)
            .and_then(|zero_based| ids.get(usize::from(zero_based)).copied())
            .ok_or(CommitteeError::UnknownParty(PartyId(index)))
    }

    pub fn by_id(&self) -> BTreeMap<PartyId, &Member> {
        self.members.iter().map(|member| (member.id, member)).collect()
    }

    /// Versioned canonical commitment to every security-relevant field in this committee.
    ///
    /// This encoding is intentionally explicit instead of serializing [`Committee`] directly.
    /// Adding deployment metadata to a Rust struct must never silently redefine an active epoch.
    pub fn digest(&self) -> [u8; 32] {
        let canonical = self.clone().canonicalized().expect("digesting invalid committee");
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/committee-digest/v2");
        hasher.update(&COMMITTEE_DIGEST_VERSION.to_le_bytes());
        hasher.update(&canonical.epoch.to_le_bytes());
        hasher.update(&canonical.threshold.to_le_bytes());
        hasher.update(&canonical.n().to_le_bytes());
        for member in canonical.members {
            hasher.update(&member.id.0.to_le_bytes());
            hasher.update(&member.signing_key);
            hasher.update(&member.encryption_key);
        }
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: u16) -> Member {
        Member {
            id: PartyId(id),
            signing_key: [u8::try_from(id).unwrap(); 32],
            encryption_key: [u8::try_from(id + 10).unwrap(); 32],
        }
    }

    #[test]
    fn frost_indices_are_canonical() {
        let committee =
            Committee { epoch: 3, threshold: 2, members: vec![member(9), member(2), member(7)] };
        committee.validate().unwrap();
        assert_eq!(committee.frost_index(PartyId(2)).unwrap(), 1);
        assert_eq!(committee.frost_index(PartyId(7)).unwrap(), 2);
        assert_eq!(committee.frost_index(PartyId(9)).unwrap(), 3);
    }

    #[test]
    fn committee_digest_ignores_input_order() {
        let left = Committee { epoch: 1, threshold: 2, members: vec![member(1), member(2)] };
        let right = Committee { epoch: 1, threshold: 2, members: vec![member(2), member(1)] };
        assert_eq!(left.digest(), right.digest());
    }

    #[test]
    fn committee_digest_commits_to_each_security_field() {
        let original = Committee { epoch: 1, threshold: 2, members: vec![member(1), member(2)] };
        let mut changed_epoch = original.clone();
        changed_epoch.epoch += 1;
        let mut changed_threshold = original.clone();
        changed_threshold.threshold = 1;
        let mut changed_signing_key = original.clone();
        changed_signing_key.members[0].signing_key[0] ^= 1;
        let mut changed_encryption_key = original.clone();
        changed_encryption_key.members[0].encryption_key[0] ^= 1;

        for changed in
            [changed_epoch, changed_threshold, changed_signing_key, changed_encryption_key]
        {
            assert_ne!(original.digest(), changed.digest());
        }
    }

    #[test]
    fn resource_boundary_accepts_maximum_committee_and_threshold() {
        let maximum = Committee {
            epoch: 0,
            threshold: MAX_COMMITTEE_THRESHOLD,
            members: (1..=MAX_COMMITTEE_THRESHOLD).map(member).collect(),
        };
        maximum.validate().unwrap();
        assert_eq!(maximum.n(), MAX_COMMITTEE_THRESHOLD);
    }

    #[test]
    fn resource_cap_preserves_required_quorum_profiles() {
        for (members, threshold, faults) in [(5, 3, 1), (7, 4, 1), (3, 2, 0)] {
            Committee { epoch: 0, threshold, members: (1..=members).map(member).collect() }
                .validate_async_security_with_faults(faults)
                .unwrap();
        }
    }

    #[test]
    fn oversized_committee_fails_before_infallible_index_conversions() {
        let oversized = Committee {
            epoch: 0,
            threshold: 1,
            members: (1..=MAX_COMMITTEE_THRESHOLD + 1).map(member).collect(),
        };
        assert!(matches!(
            oversized.validate(),
            Err(CommitteeError::TooManyMembers { members, maximum })
                if members == MAX_COMMITTEE_MEMBERS + 1
                    && maximum == MAX_COMMITTEE_MEMBERS
        ));
    }

    #[test]
    fn oversized_threshold_fails_at_the_resource_boundary() {
        let oversized = Committee {
            epoch: 0,
            threshold: MAX_COMMITTEE_THRESHOLD + 1,
            members: (1..=MAX_COMMITTEE_THRESHOLD).map(member).collect(),
        };
        assert_eq!(
            oversized.validate(),
            Err(CommitteeError::ThresholdTooLarge {
                threshold: MAX_COMMITTEE_THRESHOLD + 1,
                maximum: MAX_COMMITTEE_THRESHOLD,
            })
        );
    }
}
