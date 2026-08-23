//! Bounded, transport-agnostic Tendermint-style agreement on an AVSS QUAL set.
//!
//! The caller authenticates `sender` before calling [`QualConsensus::handle`]. A proposal or
//! round-change may carry a portable [`ProofOfLockCertificate`]. That certificate deliberately
//! contains no signatures: the transport must retain and authenticate the named PREVOTE witnesses,
//! then call [`QualConsensus::handle_with_proof_of_lock_verifier`]. A [`QualNewRound`] certificate
//! is authenticated by first delivering each constituent [`QualRoundChange`] through `handle`;
//! the reducer enters the new round only when its durable, sender-indexed records exactly match all
//! `n-f` certificate witnesses.
//!
//! AVSS delivery is a separate validity predicate: a party only votes for values whose
//! dealer/digest pairs it has locally certified with [`QualConsensus::certify`]. State and emitted
//! messages are metadata-only and serializable. Persist a successful transition before
//! broadcasting its messages.
//!
//! A timeout requests a later round by broadcasting a round-change; it does not phase-shift the
//! active voting round. Seeing valid future traffic from `f+1` distinct authenticated senders makes
//! a lagging party relay a round-change for the highest justified target. The target leader enters
//! and broadcasts a new-round only after collecting an exact `n-f` certificate. Future proposals,
//! votes, and new-round messages use a fixed number of per-sender slots, while only the latest
//! round-change per sender is retained, so memory is independent of the numeric round.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use crate::{
    avss::CommitmentDigest,
    committee::{Committee, CommitteeError, MAX_COMMITTEE_MEMBERS, PartyId, SessionId},
};

const QUAL_VERSION: u16 = 4;
const MAX_COMMITTEE_SIZE: usize = MAX_COMMITTEE_MEMBERS;
const FUTURE_MESSAGE_KINDS: usize = 4;
const MAX_FUTURE_MESSAGES: usize = MAX_COMMITTEE_MEMBERS * FUTURE_MESSAGE_KINDS;
// Keep one successor available even after accepting the largest legal wire round.
const MAX_QUAL_ROUND: u64 = u64::MAX - 1;
// Evidence is diagnostic and never participates in a safety decision. Retaining eight conflicts
// per possible sender is ample for operator attribution while keeping a live AVSS session's
// canonical snapshot strictly resource-bounded.
const MAX_EVIDENCE: usize = MAX_COMMITTEE_MEMBERS * 8;

type VoteQuorum = (Option<QualValueDigest>, BTreeSet<PartyId>);

/// The dealer-selection policy agreed by this consensus instance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QualMode {
    /// Select at least `n - f` target-committee DKG dealers.
    Dkg,
    /// Select exactly `n - f` zero-constant dealers from the unchanged current committee.
    Refresh,
    /// Select exactly `old_threshold` dealers from the bound old-dealer candidate set.
    Reshare { old_threshold: u16, eligible_dealers: Vec<PartyId> },
}

/// Immutable consensus context. Its digest is repeated in every message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QualConfig {
    version: u16,
    session: SessionId,
    epoch: u64,
    transition: [u8; 32],
    committee: Committee,
    fault_bound: u16,
    mode: QualMode,
}

impl QualConfig {
    pub fn dkg(
        session: SessionId,
        transition: [u8; 32],
        committee: Committee,
        fault_bound: u16,
    ) -> Result<Self, QualError> {
        let config = Self {
            version: QUAL_VERSION,
            session,
            epoch: committee.epoch,
            transition,
            committee,
            fault_bound,
            mode: QualMode::Dkg,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn reshare(
        session: SessionId,
        transition: [u8; 32],
        committee: Committee,
        fault_bound: u16,
        old_threshold: u16,
        mut eligible_dealers: Vec<PartyId>,
    ) -> Result<Self, QualError> {
        if eligible_dealers.len() > MAX_COMMITTEE_SIZE {
            return Err(QualError::InvalidConfig("old dealer set exceeds hard size limit"));
        }
        eligible_dealers.sort_unstable();
        let config = Self {
            version: QUAL_VERSION,
            session,
            epoch: committee.epoch,
            transition,
            committee,
            fault_bound,
            mode: QualMode::Reshare { old_threshold, eligible_dealers },
        };
        config.validate()?;
        Ok(config)
    }

    pub fn refresh(
        session: SessionId,
        transition: [u8; 32],
        committee: Committee,
        fault_bound: u16,
    ) -> Result<Self, QualError> {
        let config = Self {
            version: QUAL_VERSION,
            session,
            epoch: committee.epoch,
            transition,
            committee,
            fault_bound,
            mode: QualMode::Refresh,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), QualError> {
        if self.version != QUAL_VERSION {
            return Err(QualError::UnsupportedVersion);
        }
        self.committee.validate()?;
        if self.committee.members.len() > MAX_COMMITTEE_SIZE {
            return Err(QualError::InvalidConfig("committee exceeds hard size limit"));
        }
        if self.epoch != self.committee.epoch {
            return Err(QualError::InvalidConfig("epoch differs from committee"));
        }
        let n = usize::from(self.committee.n());
        let f = usize::from(self.fault_bound);
        if n < (3 * f).saturating_add(1) {
            return Err(QualError::InvalidConfig("require n >= 3f + 1"));
        }
        if let QualMode::Reshare { old_threshold, eligible_dealers } = &self.mode {
            if *old_threshold == 0 || usize::from(*old_threshold) > eligible_dealers.len() {
                return Err(QualError::InvalidConfig("invalid old threshold"));
            }
            if eligible_dealers.len() > MAX_COMMITTEE_SIZE {
                return Err(QualError::InvalidConfig("old dealer set exceeds hard size limit"));
            }
            let mut previous = None;
            for dealer in eligible_dealers {
                if dealer.0 == 0 || previous.is_some_and(|value| value >= *dealer) {
                    return Err(QualError::InvalidConfig(
                        "old dealer set must be sorted, unique, and non-zero",
                    ));
                }
                previous = Some(*dealer);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    #[must_use]
    pub fn fault_bound(&self) -> u16 {
        self.fault_bound
    }

    #[must_use]
    pub fn mode(&self) -> &QualMode {
        &self.mode
    }

    #[must_use]
    pub fn quorum(&self) -> usize {
        usize::from(self.committee.n() - self.fault_bound)
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/qual-context/v4");
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.session.0);
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.transition);
        hasher.update(&self.committee.digest());
        hasher.update(&self.fault_bound.to_le_bytes());
        match &self.mode {
            QualMode::Dkg => {
                hasher.update(&[0]);
            }
            QualMode::Refresh => {
                hasher.update(&[1]);
            }
            QualMode::Reshare { old_threshold, eligible_dealers } => {
                hasher.update(&[2]);
                hasher.update(&old_threshold.to_le_bytes());
                for dealer in eligible_dealers {
                    hasher.update(&dealer.0.to_le_bytes());
                }
            }
        }
        *hasher.finalize().as_bytes()
    }

    fn eligible(&self, dealer: PartyId) -> bool {
        match &self.mode {
            QualMode::Dkg | QualMode::Refresh => self.committee.member(dealer).is_ok(),
            QualMode::Reshare { eligible_dealers, .. } => {
                eligible_dealers.binary_search(&dealer).is_ok()
            }
        }
    }
}

/// One AVSS dealer instance admitted to a proposed QUAL value.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct QualEntry {
    pub dealer: PartyId,
    pub commitment: CommitmentDigest,
}

/// Canonical, context-bound application value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QualValue {
    pub session: SessionId,
    pub epoch: u64,
    pub committee: [u8; 32],
    pub context: [u8; 32],
    pub entries: Vec<QualEntry>,
}

/// Canonical digest of a [`QualValue`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct QualValueDigest(pub [u8; 32]);

impl QualValue {
    pub fn new(config: &QualConfig, mut entries: Vec<QualEntry>) -> Result<Self, QualError> {
        if entries.len() > MAX_COMMITTEE_SIZE {
            return Err(QualError::InvalidValue("QUAL exceeds hard dealer limit"));
        }
        entries.sort_unstable_by_key(|entry| entry.dealer);
        let value = Self {
            session: config.session,
            epoch: config.epoch,
            committee: config.committee.digest(),
            context: config.digest(),
            entries,
        };
        value.validate(config)?;
        Ok(value)
    }

    pub fn validate(&self, config: &QualConfig) -> Result<(), QualError> {
        if self.entries.len() > MAX_COMMITTEE_SIZE {
            return Err(QualError::InvalidValue("QUAL exceeds hard dealer limit"));
        }
        if self.session != config.session
            || self.epoch != config.epoch
            || self.committee != config.committee.digest()
            || self.context != config.digest()
        {
            return Err(QualError::WrongContext);
        }
        let mut previous = None;
        for entry in &self.entries {
            if !config.eligible(entry.dealer)
                || previous.is_some_and(|dealer| dealer >= entry.dealer)
            {
                return Err(QualError::InvalidValue(
                    "entries must be eligible, sorted, and unique",
                ));
            }
            previous = Some(entry.dealer);
        }
        match &config.mode {
            QualMode::Dkg => {
                if self.entries.len() < config.quorum()
                    || self.entries.len() > usize::from(config.committee.n())
                {
                    return Err(QualError::InvalidValue(
                        "DKG QUAL must contain n-f through n dealers",
                    ));
                }
            }
            QualMode::Refresh => {
                if self.entries.len() != config.quorum() {
                    return Err(QualError::InvalidValue(
                        "refresh QUAL must contain exactly n-f dealers",
                    ));
                }
            }
            QualMode::Reshare { old_threshold, .. } => {
                if self.entries.len() != usize::from(*old_threshold) {
                    return Err(QualError::InvalidValue(
                        "reshare QUAL must contain exactly the old threshold",
                    ));
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> QualValueDigest {
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/qual-value/v2");
        hasher.update(&self.session.0);
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.committee);
        hasher.update(&self.context);
        hasher.update(&(self.entries.len() as u64).to_le_bytes());
        for entry in &self.entries {
            hasher.update(&entry.dealer.0.to_le_bytes());
            hasher.update(&entry.commitment.0);
        }
        QualValueDigest(*hasher.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QualProposal {
    pub round: u64,
    pub value: QualValue,
    /// A portable claim that exactly `n-f` named parties PREVOTEd this value in a prior round.
    ///
    /// This metadata is not independently authenticated. A receiver must verify retained signed
    /// PREVOTE witnesses and use [`QualConsensus::handle_with_proof_of_lock_verifier`].
    pub proof_of_lock: Option<ProofOfLockCertificate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum VotePhase {
    Prevote,
    Precommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QualVote {
    pub round: u64,
    pub phase: VotePhase,
    /// `None` is Tendermint NIL.
    pub value: Option<QualValueDigest>,
}

/// Canonical metadata for a portable proof of lock (POL).
///
/// The voter list has exactly `n-f` entries in strictly increasing order. The type intentionally
/// carries no signatures. [`Self::validate_structure`] checks its context, round/value binding, and
/// canonical voter set, but the caller must authenticate one signed PREVOTE witness per voter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProofOfLockCertificate {
    pub round: u64,
    pub value: QualValue,
    pub voters: Vec<PartyId>,
}

impl ProofOfLockCertificate {
    /// Validate all deterministic POL invariants except authentication of the named votes.
    pub fn validate_structure(
        &self,
        config: &QualConfig,
        proposal_round: u64,
        proposal_value: &QualValue,
    ) -> Result<(), QualError> {
        self.value.validate(config)?;
        if self.round >= proposal_round {
            return Err(QualError::InvalidProofOfLock("POL round must precede its proposal round"));
        }
        if self.value != *proposal_value {
            return Err(QualError::InvalidProofOfLock("POL value differs from its proposal value"));
        }
        if self.voters.len() != config.quorum() {
            return Err(QualError::InvalidProofOfLock(
                "POL must name exactly the configured quorum",
            ));
        }
        let mut previous = None;
        for voter in &self.voters {
            if config.committee.member(*voter).is_err() {
                return Err(QualError::InvalidProofOfLock(
                    "POL contains a voter outside the committee",
                ));
            }
            if previous.is_some_and(|prior| prior >= *voter) {
                return Err(QualError::InvalidProofOfLock(
                    "POL voters must be strictly sorted and unique",
                ));
            }
            previous = Some(*voter);
        }
        Ok(())
    }

    /// The exact QUAL vote body every authenticated POL witness must contain.
    #[must_use]
    pub fn expected_prevote(&self) -> QualVote {
        QualVote { round: self.round, phase: VotePhase::Prevote, value: Some(self.value.digest()) }
    }

    fn validate_for_round_change(
        &self,
        config: &QualConfig,
        target_round: u64,
    ) -> Result<(), QualError> {
        self.validate_structure(config, target_round, &self.value)
    }
}

/// One authenticated party's request to leave the active round.
///
/// `round` is the requested target, not the sender's current voting round. Honest senders increase
/// it monotonically and attach their highest known authenticated PREVOTE quorum.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QualRoundChange {
    pub round: u64,
    pub proof_of_lock: Option<ProofOfLockCertificate>,
}

impl QualRoundChange {
    fn validate_structure(&self, config: &QualConfig) -> Result<(), QualError> {
        if self.round == 0 || self.round > MAX_QUAL_ROUND {
            return Err(QualError::InvalidRoundChange("target round must be in 1..=u64::MAX-1"));
        }
        if let Some(proof) = &self.proof_of_lock {
            proof.validate_for_round_change(config, self.round)?;
        }
        Ok(())
    }
}

/// One canonical member of a new-round certificate.
///
/// The transport authenticates `change` as a message from `voter` before the reducer stores it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoundChangeWitness {
    pub voter: PartyId,
    pub change: QualRoundChange,
}

/// Exact `n-f` authenticated requests for one target round.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoundChangeCertificate {
    pub round: u64,
    pub witnesses: Vec<RoundChangeWitness>,
}

impl RoundChangeCertificate {
    pub fn validate_structure(&self, config: &QualConfig) -> Result<(), QualError> {
        if self.round == 0 || self.round > MAX_QUAL_ROUND {
            return Err(QualError::InvalidNewRound("certificate round must be in 1..=u64::MAX-1"));
        }
        if self.witnesses.len() != config.quorum() {
            return Err(QualError::InvalidNewRound(
                "round-change certificate must contain exactly n-f witnesses",
            ));
        }
        let mut previous = None;
        for witness in &self.witnesses {
            if config.committee.member(witness.voter).is_err() {
                return Err(QualError::InvalidNewRound(
                    "round-change certificate contains an unknown voter",
                ));
            }
            if previous.is_some_and(|prior| prior >= witness.voter) {
                return Err(QualError::InvalidNewRound(
                    "round-change witnesses must be strictly sorted and unique",
                ));
            }
            if witness.change.round != self.round {
                return Err(QualError::InvalidNewRound(
                    "round-change witness targets another round",
                ));
            }
            witness.change.validate_structure(config)?;
            previous = Some(witness.voter);
        }
        let _ = self.highest_proof_of_lock()?;
        Ok(())
    }

    /// Deterministically select the highest certified value carried by this certificate.
    ///
    /// Two different values with PREVOTE quorums in the same round violate quorum intersection and
    /// are rejected. Multiple canonical voter subsets for the same value are resolved by the
    /// lexicographically smallest voter vector.
    pub fn highest_proof_of_lock(&self) -> Result<Option<ProofOfLockCertificate>, QualError> {
        let mut highest: Option<&ProofOfLockCertificate> = None;
        for proof in
            self.witnesses.iter().filter_map(|witness| witness.change.proof_of_lock.as_ref())
        {
            let Some(current) = highest else {
                highest = Some(proof);
                continue;
            };
            if proof.round > current.round {
                highest = Some(proof);
            } else if proof.round == current.round {
                if proof.value.digest() != current.value.digest() {
                    return Err(QualError::ConflictingQuorums);
                }
                if proof.voters < current.voters {
                    highest = Some(proof);
                }
            }
        }
        Ok(highest.cloned())
    }
}

/// Leader-authenticated entry certificate and proposal for one voting round.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QualNewRound {
    pub round: u64,
    pub certificate: RoundChangeCertificate,
    pub proposal: QualProposal,
}

impl QualNewRound {
    fn validate_structure(&self, config: &QualConfig) -> Result<(), QualError> {
        if self.round != self.certificate.round || self.round != self.proposal.round {
            return Err(QualError::InvalidNewRound(
                "new-round, certificate, and proposal rounds differ",
            ));
        }
        self.certificate.validate_structure(config)?;
        self.proposal.value.validate(config)?;
        let highest = self.certificate.highest_proof_of_lock()?;
        match (&highest, &self.proposal.proof_of_lock) {
            (None, None) => {}
            (Some(expected), Some(actual))
                if expected == actual && self.proposal.value == expected.value => {}
            (None, Some(_)) => {
                return Err(QualError::InvalidNewRound(
                    "proposal proof is absent from its round-change certificate",
                ));
            }
            (Some(_), None) => {
                return Err(QualError::InvalidNewRound(
                    "proposal omitted the certificate's highest proof of lock",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(QualError::InvalidNewRound(
                    "proposal does not carry the certificate's highest proof of lock",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QualMessageBody {
    Proposal(QualProposal),
    Vote(QualVote),
    RoundChange(QualRoundChange),
    NewRound(QualNewRound),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QualMessage {
    pub context: [u8; 32],
    pub body: QualMessageBody,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum EquivocationKind {
    Proposal,
    Prevote,
    Precommit,
    RoundChange,
    NewRound,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub round: u64,
    pub sender: PartyId,
    pub kind: EquivocationKind,
    pub first: QualMessage,
    pub conflicting: QualMessage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub round: u64,
    pub value: QualValue,
    pub voters: BTreeSet<PartyId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QualDecision {
    pub certificate: QuorumCertificate,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QualStep {
    /// Each message is a broadcast to every target-committee member. The local vote is already
    /// counted; receiving the looped-back message is an idempotent duplicate.
    pub broadcast: Vec<QualMessage>,
    pub decision: Option<QualDecision>,
    pub evidence: Vec<EquivocationEvidence>,
    /// Set only when an authenticated `n-f` certificate changed the active voting round.
    pub entered_round: Option<u64>,
    /// Set when this step emitted a new local round-change request.
    pub requested_round: Option<u64>,
    pub duplicate: bool,
    pub changed: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum QualError {
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("unsupported QUAL version")]
    UnsupportedVersion,
    #[error("invalid QUAL configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("invalid QUAL value: {0}")]
    InvalidValue(&'static str),
    #[error("message/value belongs to another consensus context")]
    WrongContext,
    #[error("party {0} is not a consensus voter")]
    UnknownVoter(PartyId),
    #[error("proposal did not come from the round leader")]
    WrongLeader,
    #[error("invalid proof of lock: {0}")]
    InvalidProofOfLock(&'static str),
    #[error("invalid round-change: {0}")]
    InvalidRoundChange(&'static str),
    #[error("invalid new-round certificate: {0}")]
    InvalidNewRound(&'static str),
    #[error("portable proof of lock requires authenticated signed PREVOTE witnesses")]
    ProofOfLockAuthenticationRequired,
    #[error("dealer {0} has not locally completed the named AVSS instance")]
    UncertifiedDealer(PartyId),
    #[error("local AVSS certification equivocated for dealer {0}")]
    ConflictingCertification(PartyId),
    #[error("consensus has already started")]
    AlreadyStarted,
    #[error("consensus has not started")]
    NotStarted,
    #[error("consensus has already decided")]
    AlreadyDecided,
    #[error("round number exhausted")]
    RoundExhausted,
    #[error("state contains conflicting quorums; Byzantine assumption was exceeded")]
    ConflictingQuorums,
    #[error("invalid persisted QUAL state: {0}")]
    InvalidPersistedState(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ProposalRecord {
    sender: PartyId,
    proposal: QualProposal,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
enum FutureMessageKind {
    Proposal,
    Prevote,
    Precommit,
    NewRound,
}

type FutureMessageKey = (PartyId, FutureMessageKind);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct BufferedFutureMessage {
    message: QualMessage,
    /// True only when the message's optional proposal POL was authenticated before buffering.
    proof_of_lock_authenticated: bool,
}

/// Durable metadata state for one consensus height/transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QualConsensus {
    config: QualConfig,
    local_party: PartyId,
    started: bool,
    round: u64,
    certified: BTreeMap<PartyId, CommitmentDigest>,
    proposal: Option<ProposalRecord>,
    prevotes: BTreeMap<PartyId, Option<QualValueDigest>>,
    precommits: BTreeMap<PartyId, Option<QualValueDigest>>,
    locked: Option<QuorumCertificate>,
    valid: Option<QuorumCertificate>,
    decided: Option<QualDecision>,
    evidence: VecDeque<EquivocationEvidence>,
    /// Latest monotonically increasing authenticated round-change from each sender.
    round_changes: BTreeMap<PartyId, QualRoundChange>,
    /// At most one future message per sender and semantic kind.
    future_messages: BTreeMap<FutureMessageKey, BufferedFutureMessage>,
    /// Present for every active round after round zero.
    new_round: Option<QualNewRound>,
}

#[derive(Deserialize)]
struct UncheckedQualConsensus {
    config: QualConfig,
    local_party: PartyId,
    started: bool,
    round: u64,
    certified: BTreeMap<PartyId, CommitmentDigest>,
    proposal: Option<ProposalRecord>,
    prevotes: BTreeMap<PartyId, Option<QualValueDigest>>,
    precommits: BTreeMap<PartyId, Option<QualValueDigest>>,
    locked: Option<QuorumCertificate>,
    valid: Option<QuorumCertificate>,
    decided: Option<QualDecision>,
    evidence: VecDeque<EquivocationEvidence>,
    round_changes: BTreeMap<PartyId, QualRoundChange>,
    future_messages: BTreeMap<FutureMessageKey, BufferedFutureMessage>,
    new_round: Option<QualNewRound>,
}

impl<'de> Deserialize<'de> for QualConsensus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = UncheckedQualConsensus::deserialize(deserializer)?;
        let state = Self {
            config: value.config,
            local_party: value.local_party,
            started: value.started,
            round: value.round,
            certified: value.certified,
            proposal: value.proposal,
            prevotes: value.prevotes,
            precommits: value.precommits,
            locked: value.locked,
            valid: value.valid,
            decided: value.decided,
            evidence: value.evidence,
            round_changes: value.round_changes,
            future_messages: value.future_messages,
            new_round: value.new_round,
        };
        state.validate_restored().map_err(D::Error::custom)?;
        Ok(state)
    }
}

impl QualConsensus {
    pub fn new(config: QualConfig, local_party: PartyId) -> Result<Self, QualError> {
        config.validate()?;
        config.committee.member(local_party).map_err(|_| QualError::UnknownVoter(local_party))?;
        Ok(Self {
            config,
            local_party,
            started: false,
            round: 0,
            certified: BTreeMap::new(),
            proposal: None,
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            locked: None,
            valid: None,
            decided: None,
            evidence: VecDeque::new(),
            round_changes: BTreeMap::new(),
            future_messages: BTreeMap::new(),
            new_round: None,
        })
    }

    #[must_use]
    pub fn config(&self) -> &QualConfig {
        &self.config
    }

    #[must_use]
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Highest round this party has requested, or the active round when no request is outstanding.
    #[must_use]
    pub fn requested_round(&self) -> u64 {
        self.round_changes
            .get(&self.local_party)
            .map_or(self.round, |change| change.round.max(self.round))
    }

    /// Number of bounded future proposal/vote/new-round slots currently occupied.
    #[must_use]
    pub fn buffered_future_messages(&self) -> usize {
        self.future_messages.len()
    }

    #[must_use]
    pub fn leader(&self) -> PartyId {
        self.leader_for_round(self.round)
    }

    #[must_use]
    pub fn decision(&self) -> Option<&QualDecision> {
        self.decided.as_ref()
    }

    #[must_use]
    pub fn evidence(&self) -> &VecDeque<EquivocationEvidence> {
        &self.evidence
    }

    #[must_use]
    pub fn locked(&self) -> Option<&QuorumCertificate> {
        self.locked.as_ref()
    }

    /// Highest authenticated PREVOTE quorum known to this reducer.
    ///
    /// A durable transport can use this to retain exactly the signed witnesses needed to reproduce
    /// the next leader's portable proof of lock.
    #[must_use]
    pub fn valid(&self) -> Option<&QuorumCertificate> {
        self.valid.as_ref()
    }

    /// Record local completion/certification of one AVSS dealer instance.
    pub fn certify(&mut self, entry: QualEntry) -> Result<QualStep, QualError> {
        if !self.config.eligible(entry.dealer) {
            return Err(QualError::InvalidValue("ineligible certified dealer"));
        }
        if let Some(previous) = self.certified.get(&entry.dealer) {
            if *previous == entry.commitment {
                return Ok(QualStep { duplicate: true, ..QualStep::default() });
            }
            return Err(QualError::ConflictingCertification(entry.dealer));
        }
        self.certified.insert(entry.dealer, entry.commitment);
        let mut step = QualStep { changed: true, ..QualStep::default() };
        if self.started && self.decided.is_none() {
            self.drive(&mut step)?;
        }
        Ok(step)
    }

    pub fn start(&mut self) -> Result<QualStep, QualError> {
        if self.started {
            return Err(QualError::AlreadyStarted);
        }
        self.started = true;
        let mut step = QualStep { changed: true, ..QualStep::default() };
        self.drive(&mut step)?;
        Ok(step)
    }

    /// Expire the current request window and broadcast a monotonically higher round-change.
    ///
    /// This does not change [`Self::round`]. The active voting round changes only after an
    /// authenticated `n-f` [`RoundChangeCertificate`] is delivered by the target-round leader.
    pub fn advance_round(&mut self) -> Result<QualStep, QualError> {
        self.ensure_live()?;
        let target = self.requested_round().checked_add(1).ok_or(QualError::RoundExhausted)?;
        if target > MAX_QUAL_ROUND {
            return Err(QualError::RoundExhausted);
        }
        let mut step = QualStep::default();
        self.request_round(target, &mut step)?;
        self.drive(&mut step)?;
        Ok(step)
    }

    /// Handle a message that does not depend on a portable proof of lock.
    ///
    /// Proposals and round-changes carrying a POL are rejected with
    /// [`QualError::ProofOfLockAuthenticationRequired`] so voter IDs can never be mistaken for
    /// authenticated votes.
    pub fn handle(&mut self, sender: PartyId, message: QualMessage) -> Result<QualStep, QualError> {
        self.handle_inner(sender, message, &mut |_| false)
    }

    /// Handle a proposal or round-change while authenticating its portable proof of lock.
    ///
    /// `verify_signed_witnesses` is called only after structural validation. It **must** return true
    /// only after verifying one unique signed envelope for every canonical voter in the POL. Every
    /// envelope must bind the same QUAL context/session, POL round, [`VotePhase::Prevote`], and value
    /// returned by [`ProofOfLockCertificate::expected_prevote`]. Transport/TLS sender hints are not
    /// vote authentication. A proposal imports its POL as the highest valid value after its round
    /// is entered. A future round-change retains the authenticated proof inside its bounded
    /// sender-indexed record; the new-round certificate imports the highest proof atomically with
    /// round entry. Neither path downgrades a newer lock, and relocking happens only after a
    /// current-round PREVOTE quorum.
    pub fn handle_with_proof_of_lock_verifier<F>(
        &mut self,
        sender: PartyId,
        message: QualMessage,
        mut verify_signed_witnesses: F,
    ) -> Result<QualStep, QualError>
    where
        F: FnMut(&ProofOfLockCertificate) -> bool,
    {
        self.handle_inner(sender, message, &mut verify_signed_witnesses)
    }

    fn handle_inner(
        &mut self,
        sender: PartyId,
        message: QualMessage,
        verify_signed_witnesses: &mut dyn FnMut(&ProofOfLockCertificate) -> bool,
    ) -> Result<QualStep, QualError> {
        if !self.started {
            return Err(QualError::NotStarted);
        }
        self.config.committee.member(sender).map_err(|_| QualError::UnknownVoter(sender))?;
        if message.context != self.config.digest() {
            return Err(QualError::WrongContext);
        }
        if let Some(decision) = &self.decided {
            return Ok(QualStep {
                decision: Some(decision.clone()),
                duplicate: true,
                ..QualStep::default()
            });
        }
        let mut step = QualStep::default();
        match &message.body {
            QualMessageBody::Proposal(proposal) => {
                self.route_proposal(
                    sender,
                    proposal.clone(),
                    message,
                    false,
                    verify_signed_witnesses,
                    &mut step,
                )?;
            }
            QualMessageBody::Vote(vote) => {
                self.route_vote(sender, *vote, message, &mut step)?;
            }
            QualMessageBody::RoundChange(change) => {
                self.handle_round_change(
                    sender,
                    change.clone(),
                    message,
                    verify_signed_witnesses,
                    &mut step,
                )?;
            }
            QualMessageBody::NewRound(new_round) => {
                self.handle_new_round(sender, new_round.clone(), message, &mut step)?;
            }
        }
        if self.decided.is_none() {
            self.drive(&mut step)?;
        }
        Ok(step)
    }

    fn ensure_live(&self) -> Result<(), QualError> {
        if !self.started {
            Err(QualError::NotStarted)
        } else if self.decided.is_some() {
            Err(QualError::AlreadyDecided)
        } else {
            Ok(())
        }
    }

    fn route_proposal(
        &mut self,
        sender: PartyId,
        proposal: QualProposal,
        message: QualMessage,
        proof_already_authenticated: bool,
        verify_signed_witnesses: &mut dyn FnMut(&ProofOfLockCertificate) -> bool,
        step: &mut QualStep,
    ) -> Result<(), QualError> {
        if proposal.round > MAX_QUAL_ROUND {
            return Err(QualError::RoundExhausted);
        }
        if sender != self.leader_for_round(proposal.round) {
            return Err(QualError::WrongLeader);
        }
        proposal.value.validate(&self.config)?;
        self.ensure_locally_certified(&proposal.value)?;
        if let Some(proof) = &proposal.proof_of_lock {
            proof.validate_structure(&self.config, proposal.round, &proposal.value)?;
        }
        if proposal.round < self.round {
            step.duplicate = true;
            return Ok(());
        }
        if let Some(proof) = &proposal.proof_of_lock
            && !proof_already_authenticated
            && !verify_signed_witnesses(proof)
        {
            return Err(QualError::ProofOfLockAuthenticationRequired);
        }
        if let Some(proof) = &proposal.proof_of_lock {
            self.ensure_proof_compatible(proof)?;
        }
        if proposal.round > self.round {
            return self.buffer_future_message(
                sender,
                FutureMessageKind::Proposal,
                message,
                proposal.proof_of_lock.is_some(),
                step,
            );
        }
        self.handle_current_proposal(sender, proposal, message, step)
    }

    fn handle_current_proposal(
        &mut self,
        sender: PartyId,
        proposal: QualProposal,
        message: QualMessage,
        step: &mut QualStep,
    ) -> Result<(), QualError> {
        if let Some(existing) = &self.proposal {
            let first = QualMessage {
                context: self.config.digest(),
                body: QualMessageBody::Proposal(existing.proposal.clone()),
            };
            if existing.sender == sender && first == message {
                step.duplicate = true;
                return Ok(());
            }
            self.record_evidence(
                EquivocationEvidence {
                    round: proposal.round,
                    sender,
                    kind: EquivocationKind::Proposal,
                    first,
                    conflicting: message,
                },
                step,
            );
            return Ok(());
        }
        if let Some(proof) = &proposal.proof_of_lock {
            self.import_verified_proof_of_lock(proof, step)?;
        }
        self.proposal = Some(ProposalRecord { sender, proposal });
        step.changed = true;
        Ok(())
    }

    fn route_vote(
        &mut self,
        sender: PartyId,
        vote: QualVote,
        message: QualMessage,
        step: &mut QualStep,
    ) -> Result<(), QualError> {
        if vote.round > MAX_QUAL_ROUND {
            return Err(QualError::RoundExhausted);
        }
        if vote.round < self.round {
            step.duplicate = true;
            return Ok(());
        }
        if vote.round > self.round {
            let kind = match vote.phase {
                VotePhase::Prevote => FutureMessageKind::Prevote,
                VotePhase::Precommit => FutureMessageKind::Precommit,
            };
            return self.buffer_future_message(sender, kind, message, false, step);
        }
        self.handle_current_vote(sender, vote, message, step)
    }

    fn handle_current_vote(
        &mut self,
        sender: PartyId,
        vote: QualVote,
        message: QualMessage,
        step: &mut QualStep,
    ) -> Result<(), QualError> {
        let target = match vote.phase {
            VotePhase::Prevote => &mut self.prevotes,
            VotePhase::Precommit => &mut self.precommits,
        };
        if let Some(previous) = target.get(&sender) {
            if *previous == vote.value {
                step.duplicate = true;
                return Ok(());
            }
            let first_vote = QualVote { value: *previous, ..vote };
            self.record_evidence(
                EquivocationEvidence {
                    round: vote.round,
                    sender,
                    kind: match vote.phase {
                        VotePhase::Prevote => EquivocationKind::Prevote,
                        VotePhase::Precommit => EquivocationKind::Precommit,
                    },
                    first: QualMessage {
                        context: self.config.digest(),
                        body: QualMessageBody::Vote(first_vote),
                    },
                    conflicting: message,
                },
                step,
            );
            return Ok(());
        }
        target.insert(sender, vote.value);
        step.changed = true;
        Ok(())
    }

    fn handle_round_change(
        &mut self,
        sender: PartyId,
        change: QualRoundChange,
        message: QualMessage,
        verify_signed_witnesses: &mut dyn FnMut(&ProofOfLockCertificate) -> bool,
        step: &mut QualStep,
    ) -> Result<(), QualError> {
        change.validate_structure(&self.config)?;
        if change.round <= self.round {
            step.duplicate = true;
            return Ok(());
        }
        if let Some(previous) = self.round_changes.get(&sender) {
            if *previous == change {
                step.duplicate = true;
                return Ok(());
            }
            if previous.round > change.round {
                step.duplicate = true;
                return Ok(());
            }
            if previous.round == change.round {
                let first = QualMessage {
                    context: self.config.digest(),
                    body: QualMessageBody::RoundChange(previous.clone()),
                };
                self.record_evidence(
                    EquivocationEvidence {
                        round: change.round,
                        sender,
                        kind: EquivocationKind::RoundChange,
                        first,
                        conflicting: message,
                    },
                    step,
                );
                return Ok(());
            }
        }
        if let Some(proof) = &change.proof_of_lock {
            self.ensure_locally_certified(&proof.value)?;
            if !verify_signed_witnesses(proof) {
                return Err(QualError::ProofOfLockAuthenticationRequired);
            }
            self.ensure_proof_compatible(proof)?;
        }
        self.round_changes.insert(sender, change);
        step.changed = true;
        Ok(())
    }

    fn handle_new_round(
        &mut self,
        sender: PartyId,
        new_round: QualNewRound,
        message: QualMessage,
        step: &mut QualStep,
    ) -> Result<(), QualError> {
        new_round.validate_structure(&self.config)?;
        if sender != self.leader_for_round(new_round.round) {
            return Err(QualError::WrongLeader);
        }
        self.ensure_locally_certified(&new_round.proposal.value)?;
        if new_round.round < self.round {
            step.duplicate = true;
            return Ok(());
        }
        if new_round.round == self.round {
            if self.new_round.as_ref() == Some(&new_round) {
                step.duplicate = true;
                return Ok(());
            }
            if let Some(first) = self.new_round.clone() {
                self.record_evidence(
                    EquivocationEvidence {
                        round: new_round.round,
                        sender,
                        kind: EquivocationKind::NewRound,
                        first: QualMessage {
                            context: self.config.digest(),
                            body: QualMessageBody::NewRound(first),
                        },
                        conflicting: message,
                    },
                    step,
                );
                return Ok(());
            }
            return Err(QualError::InvalidNewRound(
                "round zero cannot be entered by a new-round certificate",
            ));
        }
        if self.round_change_certificate_is_authenticated(&new_round.certificate) {
            self.enter_new_round(sender, new_round, step)?;
            return Ok(());
        }
        self.buffer_future_message(sender, FutureMessageKind::NewRound, message, false, step)
    }

    fn buffer_future_message(
        &mut self,
        sender: PartyId,
        kind: FutureMessageKind,
        message: QualMessage,
        proof_of_lock_authenticated: bool,
        step: &mut QualStep,
    ) -> Result<(), QualError> {
        let incoming_round = Self::message_round(&message);
        debug_assert!(incoming_round > self.round);
        let key = (sender, kind);
        if let Some(existing) = self.future_messages.get(&key) {
            let existing_round = Self::message_round(&existing.message);
            if existing.message == message {
                step.duplicate = true;
                return Ok(());
            }
            if existing_round > incoming_round {
                step.duplicate = true;
                return Ok(());
            }
            if existing_round == incoming_round {
                let evidence_kind = match kind {
                    FutureMessageKind::Proposal => EquivocationKind::Proposal,
                    FutureMessageKind::Prevote => EquivocationKind::Prevote,
                    FutureMessageKind::Precommit => EquivocationKind::Precommit,
                    FutureMessageKind::NewRound => EquivocationKind::NewRound,
                };
                self.record_evidence(
                    EquivocationEvidence {
                        round: incoming_round,
                        sender,
                        kind: evidence_kind,
                        first: existing.message.clone(),
                        conflicting: message,
                    },
                    step,
                );
                return Ok(());
            }
        }
        let maximum = usize::from(self.config.committee.n()) * FUTURE_MESSAGE_KINDS;
        if !self.future_messages.contains_key(&key) && self.future_messages.len() >= maximum {
            return Err(QualError::InvalidPersistedState(
                "future-message buffer exceeds hard bound",
            ));
        }
        self.future_messages
            .insert(key, BufferedFutureMessage { message, proof_of_lock_authenticated });
        if self.future_messages.len() > MAX_FUTURE_MESSAGES {
            return Err(QualError::InvalidPersistedState(
                "future-message buffer exceeds hard bound",
            ));
        }
        step.changed = true;
        Ok(())
    }

    fn request_round(&mut self, target: u64, step: &mut QualStep) -> Result<(), QualError> {
        if target <= self.requested_round() || target <= self.round || target > MAX_QUAL_ROUND {
            return Err(QualError::InvalidRoundChange(
                "local round-change target must increase monotonically",
            ));
        }
        let change = QualRoundChange {
            round: target,
            proof_of_lock: self.valid.as_ref().map(|valid| self.proof_from_quorum(valid)),
        };
        change.validate_structure(&self.config)?;
        self.round_changes.insert(self.local_party, change.clone());
        step.broadcast.push(QualMessage {
            context: self.config.digest(),
            body: QualMessageBody::RoundChange(change),
        });
        step.requested_round = Some(target);
        step.changed = true;
        Ok(())
    }

    fn proof_from_quorum(&self, certificate: &QuorumCertificate) -> ProofOfLockCertificate {
        let voters =
            certificate.voters.iter().copied().take(self.config.quorum()).collect::<Vec<_>>();
        ProofOfLockCertificate {
            round: certificate.round,
            value: certificate.value.clone(),
            voters,
        }
    }

    fn round_change_certificate_is_authenticated(
        &self,
        certificate: &RoundChangeCertificate,
    ) -> bool {
        certificate
            .witnesses
            .iter()
            .all(|witness| self.round_changes.get(&witness.voter) == Some(&witness.change))
    }

    fn future_evidence_target(&self) -> Option<u64> {
        let mut by_sender = BTreeMap::<PartyId, u64>::new();
        for (sender, change) in &self.round_changes {
            if change.round > self.round {
                by_sender.insert(*sender, change.round);
            }
        }
        for ((sender, _), buffered) in &self.future_messages {
            let round = Self::message_round(&buffered.message);
            if round > self.round {
                by_sender
                    .entry(*sender)
                    .and_modify(|known| *known = (*known).max(round))
                    .or_insert(round);
            }
        }
        let needed = usize::from(self.config.fault_bound) + 1;
        if by_sender.len() < needed {
            return None;
        }
        let mut rounds = by_sender.into_values().collect::<Vec<_>>();
        rounds.sort_unstable_by(|left, right| right.cmp(left));
        rounds.get(needed - 1).copied()
    }

    fn catch_up_from_future_evidence(&mut self, step: &mut QualStep) -> Result<bool, QualError> {
        let Some(target) = self.future_evidence_target() else {
            return Ok(false);
        };
        if target <= self.requested_round() {
            return Ok(false);
        }
        self.request_round(target, step)?;
        Ok(true)
    }

    fn canonical_round_change_certificate(
        &self,
        target: u64,
    ) -> Result<Option<RoundChangeCertificate>, QualError> {
        let exact = self
            .round_changes
            .iter()
            .filter(|(_, change)| change.round == target)
            .map(|(voter, change)| RoundChangeWitness { voter: *voter, change: change.clone() })
            .collect::<Vec<_>>();
        if exact.len() < self.config.quorum() {
            return Ok(None);
        }

        let mut highest: Option<&ProofOfLockCertificate> = None;
        for proof in exact.iter().filter_map(|witness| witness.change.proof_of_lock.as_ref()) {
            let Some(current) = highest else {
                highest = Some(proof);
                continue;
            };
            if proof.round > current.round {
                highest = Some(proof);
            } else if proof.round == current.round {
                if proof.value.digest() != current.value.digest() {
                    return Err(QualError::ConflictingQuorums);
                }
                if proof.voters < current.voters {
                    highest = Some(proof);
                }
            }
        }
        let mandatory = highest.and_then(|proof| {
            exact
                .iter()
                .find(|witness| witness.change.proof_of_lock.as_ref() == Some(proof))
                .map(|witness| witness.voter)
        });
        let mut selected = exact.iter().take(self.config.quorum()).cloned().collect::<Vec<_>>();
        if let Some(mandatory) = mandatory
            && !selected.iter().any(|witness| witness.voter == mandatory)
        {
            selected.pop();
            selected.push(
                exact
                    .iter()
                    .find(|witness| witness.voter == mandatory)
                    .expect("mandatory voter came from the exact set")
                    .clone(),
            );
            selected.sort_unstable_by_key(|witness| witness.voter);
        }
        let certificate = RoundChangeCertificate { round: target, witnesses: selected };
        certificate.validate_structure(&self.config)?;
        Ok(Some(certificate))
    }

    fn try_emit_new_round(&mut self, step: &mut QualStep) -> Result<bool, QualError> {
        let mut targets = self
            .round_changes
            .values()
            .map(|change| change.round)
            .filter(|target| {
                *target > self.round && self.leader_for_round(*target) == self.local_party
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .rev();
        for target in &mut targets {
            let Some(certificate) = self.canonical_round_change_certificate(target)? else {
                continue;
            };
            let proof_of_lock = certificate.highest_proof_of_lock()?;
            let value = if let Some(proof) = &proof_of_lock {
                self.ensure_locally_certified(&proof.value)?;
                proof.value.clone()
            } else {
                let Some(value) = self.fresh_proposal_value()? else {
                    return Ok(false);
                };
                value
            };
            let new_round = QualNewRound {
                round: target,
                certificate,
                proposal: QualProposal { round: target, value, proof_of_lock },
            };
            new_round.validate_structure(&self.config)?;
            self.enter_new_round(self.local_party, new_round.clone(), step)?;
            step.broadcast.push(QualMessage {
                context: self.config.digest(),
                body: QualMessageBody::NewRound(new_round),
            });
            return Ok(true);
        }
        Ok(false)
    }

    fn try_enter_buffered_new_round(&mut self, step: &mut QualStep) -> Result<bool, QualError> {
        let candidate = self
            .future_messages
            .iter()
            .filter_map(|(key, buffered)| {
                let QualMessageBody::NewRound(new_round) = &buffered.message.body else {
                    return None;
                };
                (new_round.round > self.round
                    && self.round_change_certificate_is_authenticated(&new_round.certificate))
                .then_some((*key, new_round.clone()))
            })
            .max_by_key(|(_, new_round)| new_round.round);
        let Some(((sender, _), new_round)) = candidate else {
            return Ok(false);
        };
        self.future_messages.remove(&(sender, FutureMessageKind::NewRound));
        self.enter_new_round(sender, new_round, step)?;
        Ok(true)
    }

    fn enter_new_round(
        &mut self,
        sender: PartyId,
        new_round: QualNewRound,
        step: &mut QualStep,
    ) -> Result<(), QualError> {
        new_round.validate_structure(&self.config)?;
        if sender != self.leader_for_round(new_round.round)
            || new_round.round <= self.round
            || !self.round_change_certificate_is_authenticated(&new_round.certificate)
        {
            return Err(QualError::InvalidNewRound(
                "new-round lacks an authenticated leader certificate",
            ));
        }
        self.ensure_locally_certified(&new_round.proposal.value)?;
        let highest = new_round.certificate.highest_proof_of_lock()?;
        self.round = new_round.round;
        self.proposal = None;
        self.prevotes.clear();
        self.precommits.clear();
        if let Some(proof) = &highest {
            self.import_verified_proof_of_lock(proof, step)?;
        }
        self.proposal = Some(ProposalRecord { sender, proposal: new_round.proposal.clone() });
        self.new_round = Some(new_round);
        self.round_changes.retain(|_, change| change.round > self.round);
        step.entered_round = Some(self.round);
        step.changed = true;
        Ok(())
    }

    fn replay_buffered_current_messages(&mut self, step: &mut QualStep) -> Result<bool, QualError> {
        let ready = self
            .future_messages
            .iter()
            .filter(|(_, buffered)| Self::message_round(&buffered.message) <= self.round)
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        if ready.is_empty() {
            return Ok(false);
        }
        for key in ready {
            let buffered = self
                .future_messages
                .remove(&key)
                .expect("ready key came from the future-message map");
            let message_round = Self::message_round(&buffered.message);
            if message_round < self.round {
                step.changed = true;
                continue;
            }
            let sender = key.0;
            let message = buffered.message;
            match message.body.clone() {
                QualMessageBody::Proposal(proposal) => self.route_proposal(
                    sender,
                    proposal,
                    message,
                    buffered.proof_of_lock_authenticated,
                    &mut |_| false,
                    step,
                )?,
                QualMessageBody::Vote(vote) => {
                    self.route_vote(sender, vote, message, step)?;
                }
                QualMessageBody::NewRound(new_round) => {
                    self.handle_new_round(sender, new_round, message, step)?;
                }
                QualMessageBody::RoundChange(_) => {
                    return Err(QualError::InvalidPersistedState(
                        "round-change appeared in the future-message buffer",
                    ));
                }
            }
        }
        Ok(true)
    }

    fn message_round(message: &QualMessage) -> u64 {
        match &message.body {
            QualMessageBody::Proposal(proposal) => proposal.round,
            QualMessageBody::Vote(vote) => vote.round,
            QualMessageBody::RoundChange(change) => change.round,
            QualMessageBody::NewRound(new_round) => new_round.round,
        }
    }

    fn drive(&mut self, step: &mut QualStep) -> Result<(), QualError> {
        loop {
            let mut progressed = false;
            if self.catch_up_from_future_evidence(step)? {
                progressed = true;
            }
            if self.try_enter_buffered_new_round(step)? {
                continue;
            }
            if self.try_emit_new_round(step)? {
                continue;
            }
            if self.replay_buffered_current_messages(step)? {
                progressed = true;
            }
            if self.proposal.is_none()
                && self.round == 0
                && self.leader() == self.local_party
                && let Some(value) = self.fresh_proposal_value()?
            {
                let proposal = QualProposal { round: self.round, value, proof_of_lock: None };
                self.proposal =
                    Some(ProposalRecord { sender: self.local_party, proposal: proposal.clone() });
                step.broadcast.push(QualMessage {
                    context: self.config.digest(),
                    body: QualMessageBody::Proposal(proposal),
                });
                step.changed = true;
                progressed = true;
            }

            if !self.prevotes.contains_key(&self.local_party)
                && let Some(proposal) = self.proposal.as_ref().map(|record| record.proposal.clone())
                && self.can_prevote(&proposal)
            {
                self.emit_vote(VotePhase::Prevote, Some(proposal.value.digest()), step);
                progressed = true;
            }

            if let Some((value_digest, voters)) = self.quorum_for(&self.prevotes)? {
                match value_digest {
                    Some(digest) => {
                        if let Some(value) = self.proposal_value_for_digest(digest) {
                            let certificate =
                                QuorumCertificate { round: self.round, value, voters };
                            if self.valid.as_ref().is_none_or(|valid| valid.round < self.round) {
                                self.valid = Some(certificate.clone());
                                step.changed = true;
                            }
                            if !self.precommits.contains_key(&self.local_party) {
                                self.locked = Some(certificate);
                                self.emit_vote(VotePhase::Precommit, Some(digest), step);
                                progressed = true;
                            }
                        }
                    }
                    None if !self.precommits.contains_key(&self.local_party) => {
                        self.emit_vote(VotePhase::Precommit, None, step);
                        progressed = true;
                    }
                    None => {}
                }
            }

            if self.decided.is_none()
                && let Some((Some(digest), voters)) = self.quorum_for(&self.precommits)?
                && let Some(value) = self.proposal_value_for_digest(digest)
            {
                let decision = QualDecision {
                    certificate: QuorumCertificate { round: self.round, value, voters },
                };
                self.decided = Some(decision.clone());
                step.decision = Some(decision);
                step.changed = true;
                return Ok(());
            }

            if !progressed {
                return Ok(());
            }
        }
    }

    fn fresh_proposal_value(&self) -> Result<Option<QualValue>, QualError> {
        let needed = match &self.config.mode {
            QualMode::Dkg | QualMode::Refresh => self.config.quorum(),
            QualMode::Reshare { old_threshold, .. } => usize::from(*old_threshold),
        };
        if self.certified.len() < needed {
            return Ok(None);
        }
        let entries = self
            .certified
            .iter()
            .take(needed)
            .map(|(dealer, commitment)| QualEntry { dealer: *dealer, commitment: *commitment })
            .collect();
        Ok(Some(QualValue::new(&self.config, entries)?))
    }

    fn can_prevote(&self, proposal: &QualProposal) -> bool {
        let digest = proposal.value.digest();
        if self.locked.as_ref().is_some_and(|locked| locked.value.digest() == digest) {
            return true;
        }
        match &proposal.proof_of_lock {
            None => self.locked.is_none(),
            Some(proof) => self.locked.as_ref().is_none_or(|locked| locked.round <= proof.round),
        }
    }

    fn import_verified_proof_of_lock(
        &mut self,
        proof: &ProofOfLockCertificate,
        step: &mut QualStep,
    ) -> Result<(), QualError> {
        self.ensure_proof_compatible(proof)?;
        if self.valid.as_ref().is_none_or(|valid| valid.round < proof.round) {
            self.valid = Some(QuorumCertificate {
                round: proof.round,
                value: proof.value.clone(),
                voters: proof.voters.iter().copied().collect(),
            });
            step.changed = true;
        }
        Ok(())
    }

    fn ensure_proof_compatible(&self, proof: &ProofOfLockCertificate) -> Result<(), QualError> {
        let digest = proof.value.digest();
        for existing in [&self.valid, &self.locked].into_iter().flatten() {
            if existing.round == proof.round && existing.value.digest() != digest {
                return Err(QualError::ConflictingQuorums);
            }
        }
        Ok(())
    }

    fn emit_vote(&mut self, phase: VotePhase, value: Option<QualValueDigest>, step: &mut QualStep) {
        let vote = QualVote { round: self.round, phase, value };
        match phase {
            VotePhase::Prevote => {
                self.prevotes.insert(self.local_party, value);
            }
            VotePhase::Precommit => {
                self.precommits.insert(self.local_party, value);
            }
        }
        step.broadcast
            .push(QualMessage { context: self.config.digest(), body: QualMessageBody::Vote(vote) });
        step.changed = true;
    }

    fn quorum_for(
        &self,
        votes: &BTreeMap<PartyId, Option<QualValueDigest>>,
    ) -> Result<Option<VoteQuorum>, QualError> {
        let mut grouped = BTreeMap::<Option<QualValueDigest>, BTreeSet<PartyId>>::new();
        for (sender, value) in votes {
            grouped.entry(*value).or_default().insert(*sender);
        }
        let quorums = grouped
            .into_iter()
            .filter(|(_, voters)| voters.len() >= self.config.quorum())
            .collect::<Vec<_>>();
        match quorums.as_slice() {
            [] => Ok(None),
            [quorum] => Ok(Some(quorum.clone())),
            _ => Err(QualError::ConflictingQuorums),
        }
    }

    fn proposal_value_for_digest(&self, digest: QualValueDigest) -> Option<QualValue> {
        self.proposal
            .as_ref()
            .map(|record| &record.proposal.value)
            .filter(|value| value.digest() == digest)
            .cloned()
            .or_else(|| {
                self.valid
                    .as_ref()
                    .map(|valid| &valid.value)
                    .filter(|value| value.digest() == digest)
                    .cloned()
            })
            .or_else(|| {
                self.locked
                    .as_ref()
                    .map(|locked| &locked.value)
                    .filter(|value| value.digest() == digest)
                    .cloned()
            })
    }

    fn ensure_locally_certified(&self, value: &QualValue) -> Result<(), QualError> {
        value.validate(&self.config)?;
        for entry in &value.entries {
            if self.certified.get(&entry.dealer) != Some(&entry.commitment) {
                return Err(QualError::UncertifiedDealer(entry.dealer));
            }
        }
        Ok(())
    }

    fn leader_for_round(&self, round: u64) -> PartyId {
        let zero_based = round % u64::from(self.config.committee.n());
        let index = u16::try_from(zero_based + 1).expect("committee size is bounded by u16");
        self.config.committee.party_for_frost_index(index).expect("index is in committee")
    }

    fn record_evidence(&mut self, evidence: EquivocationEvidence, step: &mut QualStep) {
        if self.evidence.len() < MAX_EVIDENCE {
            self.evidence.push_back(evidence.clone());
        }
        step.evidence.push(evidence);
        step.changed = true;
    }

    fn validate_certificate(&self, certificate: &QuorumCertificate) -> Result<(), QualError> {
        certificate.value.validate(&self.config)?;
        self.ensure_locally_certified(&certificate.value)?;
        if certificate.voters.len() < self.config.quorum()
            || certificate.voters.len() > usize::from(self.config.committee.n())
            || !certificate.voters.iter().all(|voter| self.config.committee.member(*voter).is_ok())
        {
            return Err(QualError::InvalidPersistedState("invalid quorum certificate voters"));
        }
        Ok(())
    }

    fn validate_restored(&self) -> Result<(), QualError> {
        self.config.validate()?;
        self.config
            .committee
            .member(self.local_party)
            .map_err(|_| QualError::InvalidPersistedState("local party is not a voter"))?;
        if self.round > MAX_QUAL_ROUND
            || self.certified.len() > MAX_COMMITTEE_SIZE
            || self.evidence.len() > MAX_EVIDENCE
            || self.prevotes.len() > usize::from(self.config.committee.n())
            || self.precommits.len() > usize::from(self.config.committee.n())
            || self.round_changes.len() > usize::from(self.config.committee.n())
            || self.future_messages.len()
                > usize::from(self.config.committee.n()) * FUTURE_MESSAGE_KINDS
        {
            return Err(QualError::InvalidPersistedState("collection exceeds hard bound"));
        }
        for (dealer, digest) in &self.certified {
            if !self.config.eligible(*dealer) {
                return Err(QualError::InvalidPersistedState("ineligible certification"));
            }
            let _ = digest;
        }
        for votes in [&self.prevotes, &self.precommits] {
            if !votes.keys().all(|sender| self.config.committee.member(*sender).is_ok()) {
                return Err(QualError::InvalidPersistedState("vote from unknown sender"));
            }
        }
        for (sender, change) in &self.round_changes {
            if self.config.committee.member(*sender).is_err() || change.round <= self.round {
                return Err(QualError::InvalidPersistedState(
                    "invalid retained round-change routing",
                ));
            }
            change
                .validate_structure(&self.config)
                .map_err(|_| QualError::InvalidPersistedState("invalid retained round-change"))?;
            if let Some(proof) = &change.proof_of_lock {
                self.ensure_locally_certified(&proof.value)?;
            }
        }
        for ((sender, kind), buffered) in &self.future_messages {
            if self.config.committee.member(*sender).is_err()
                || buffered.message.context != self.config.digest()
                || Self::message_round(&buffered.message) <= self.round
            {
                return Err(QualError::InvalidPersistedState("invalid future-message routing"));
            }
            match (&buffered.message.body, kind) {
                (QualMessageBody::Proposal(proposal), FutureMessageKind::Proposal) => {
                    if *sender != self.leader_for_round(proposal.round) {
                        return Err(QualError::InvalidPersistedState(
                            "future proposal came from the wrong leader",
                        ));
                    }
                    proposal.value.validate(&self.config)?;
                    self.ensure_locally_certified(&proposal.value)?;
                    match &proposal.proof_of_lock {
                        Some(proof) => {
                            proof
                                .validate_structure(&self.config, proposal.round, &proposal.value)
                                .map_err(|_| {
                                    QualError::InvalidPersistedState(
                                        "invalid buffered proposal proof of lock",
                                    )
                                })?;
                            if !buffered.proof_of_lock_authenticated {
                                return Err(QualError::InvalidPersistedState(
                                    "buffered proposal proof was not authenticated",
                                ));
                            }
                        }
                        None if buffered.proof_of_lock_authenticated => {
                            return Err(QualError::InvalidPersistedState(
                                "buffered proposal has a spurious proof-authentication flag",
                            ));
                        }
                        None => {}
                    }
                }
                (
                    QualMessageBody::Vote(QualVote { phase: VotePhase::Prevote, .. }),
                    FutureMessageKind::Prevote,
                )
                | (
                    QualMessageBody::Vote(QualVote { phase: VotePhase::Precommit, .. }),
                    FutureMessageKind::Precommit,
                ) if !buffered.proof_of_lock_authenticated => {}
                (QualMessageBody::NewRound(new_round), FutureMessageKind::NewRound)
                    if !buffered.proof_of_lock_authenticated =>
                {
                    if *sender != self.leader_for_round(new_round.round) {
                        return Err(QualError::InvalidPersistedState(
                            "future new-round came from the wrong leader",
                        ));
                    }
                    new_round.validate_structure(&self.config).map_err(|_| {
                        QualError::InvalidPersistedState("invalid buffered new-round")
                    })?;
                    self.ensure_locally_certified(&new_round.proposal.value)?;
                }
                _ => {
                    return Err(QualError::InvalidPersistedState(
                        "future-message key differs from its body",
                    ));
                }
            }
        }
        if let Some(record) = &self.proposal {
            if record.sender != self.leader() || record.proposal.round != self.round {
                return Err(QualError::InvalidPersistedState("proposal routing differs"));
            }
            record.proposal.value.validate(&self.config)?;
            self.ensure_locally_certified(&record.proposal.value)?;
            if let Some(proof) = &record.proposal.proof_of_lock {
                proof
                    .validate_structure(&self.config, self.round, &record.proposal.value)
                    .map_err(|_| {
                        QualError::InvalidPersistedState("invalid proposal proof of lock")
                    })?;
                let imported = self.valid.as_ref().is_some_and(|valid| {
                    valid.round > proof.round
                        || (valid.round == proof.round && valid.value == proof.value)
                });
                if !imported {
                    return Err(QualError::InvalidPersistedState(
                        "proposal proof of lock was not imported as valid",
                    ));
                }
            }
        }
        match (&self.new_round, self.round) {
            (None, 0) => {}
            (Some(new_round), round) if round > 0 => {
                new_round
                    .validate_structure(&self.config)
                    .map_err(|_| QualError::InvalidPersistedState("invalid active new-round"))?;
                if new_round.round != round
                    || self.proposal.as_ref().is_none_or(|record| {
                        record.sender != self.leader_for_round(round)
                            || record.proposal != new_round.proposal
                    })
                {
                    return Err(QualError::InvalidPersistedState(
                        "active proposal differs from its new-round certificate",
                    ));
                }
                let highest = new_round.certificate.highest_proof_of_lock()?;
                if let Some(proof) = highest {
                    let imported = self.valid.as_ref().is_some_and(|valid| {
                        valid.round > proof.round
                            || (valid.round == proof.round && valid.value == proof.value)
                    });
                    if !imported {
                        return Err(QualError::InvalidPersistedState(
                            "active new-round proof was not imported as valid",
                        ));
                    }
                }
            }
            _ => {
                return Err(QualError::InvalidPersistedState(
                    "nonzero round lacks a new-round certificate",
                ));
            }
        }
        if let Some(locked) = &self.locked {
            self.validate_certificate(locked)?;
            if locked.round > self.round {
                return Err(QualError::InvalidPersistedState("future lock"));
            }
        }
        if let Some(valid) = &self.valid {
            self.validate_certificate(valid)?;
            if valid.round > self.round {
                return Err(QualError::InvalidPersistedState("future valid value"));
            }
        }
        if let (Some(locked), Some(valid)) = (&self.locked, &self.valid)
            && locked.round > valid.round
        {
            return Err(QualError::InvalidPersistedState("lock is newer than valid value"));
        }
        if let Some(decided) = &self.decided {
            self.validate_certificate(&decided.certificate)?;
            if decided.certificate.round > self.round {
                return Err(QualError::InvalidPersistedState("future decision"));
            }
        }
        for evidence in &self.evidence {
            self.validate_evidence(evidence)?;
        }
        if !self.started
            && (self.proposal.is_some()
                || !self.prevotes.is_empty()
                || !self.precommits.is_empty()
                || self.locked.is_some()
                || self.valid.is_some()
                || self.decided.is_some()
                || !self.round_changes.is_empty()
                || !self.future_messages.is_empty()
                || self.new_round.is_some())
        {
            return Err(QualError::InvalidPersistedState(
                "unstarted state contains consensus data",
            ));
        }
        Ok(())
    }

    fn validate_evidence(&self, evidence: &EquivocationEvidence) -> Result<(), QualError> {
        if self.config.committee.member(evidence.sender).is_err()
            || evidence.first.context != self.config.digest()
            || evidence.conflicting.context != self.config.digest()
            || evidence.first == evidence.conflicting
        {
            return Err(QualError::InvalidPersistedState("malformed equivocation evidence"));
        }
        match (&evidence.first.body, &evidence.conflicting.body, evidence.kind) {
            (
                QualMessageBody::Proposal(first),
                QualMessageBody::Proposal(second),
                EquivocationKind::Proposal,
            ) if evidence.sender == self.leader_for_round(evidence.round)
                && first.round == evidence.round
                && second.round == evidence.round =>
            {
                first.value.validate(&self.config)?;
                second.value.validate(&self.config)?;
                if let Some(proof) = &first.proof_of_lock {
                    proof.validate_structure(&self.config, first.round, &first.value).map_err(
                        |_| {
                            QualError::InvalidPersistedState(
                                "malformed first proposal proof of lock",
                            )
                        },
                    )?;
                }
                if let Some(proof) = &second.proof_of_lock {
                    proof.validate_structure(&self.config, second.round, &second.value).map_err(
                        |_| {
                            QualError::InvalidPersistedState(
                                "malformed conflicting proposal proof of lock",
                            )
                        },
                    )?;
                }
            }
            (
                QualMessageBody::Vote(first),
                QualMessageBody::Vote(second),
                EquivocationKind::Prevote,
            ) if first.round == evidence.round
                && second.round == evidence.round
                && first.phase == VotePhase::Prevote
                && second.phase == VotePhase::Prevote => {}
            (
                QualMessageBody::Vote(first),
                QualMessageBody::Vote(second),
                EquivocationKind::Precommit,
            ) if first.round == evidence.round
                && second.round == evidence.round
                && first.phase == VotePhase::Precommit
                && second.phase == VotePhase::Precommit => {}
            (
                QualMessageBody::RoundChange(first),
                QualMessageBody::RoundChange(second),
                EquivocationKind::RoundChange,
            ) if first.round == evidence.round && second.round == evidence.round => {
                first.validate_structure(&self.config).map_err(|_| {
                    QualError::InvalidPersistedState("malformed first round-change")
                })?;
                second.validate_structure(&self.config).map_err(|_| {
                    QualError::InvalidPersistedState("malformed conflicting round-change")
                })?;
            }
            (
                QualMessageBody::NewRound(first),
                QualMessageBody::NewRound(second),
                EquivocationKind::NewRound,
            ) if evidence.sender == self.leader_for_round(evidence.round)
                && first.round == evidence.round
                && second.round == evidence.round =>
            {
                first
                    .validate_structure(&self.config)
                    .map_err(|_| QualError::InvalidPersistedState("malformed first new-round"))?;
                second.validate_structure(&self.config).map_err(|_| {
                    QualError::InvalidPersistedState("malformed conflicting new-round")
                })?;
            }
            _ => return Err(QualError::InvalidPersistedState("evidence kind or round differs")),
        }
        Ok(())
    }
}
