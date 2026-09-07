//! Persistent Byzantine orchestration for one consolidation authorization family.
//!
//! FROSTLASS freezes its signer set for both rounds.  Consequently, rotating only a coordinator
//! cannot provide liveness: one silent member of that fixed set stalls the attempt.  This reducer
//! uses the ROAST liveness pattern instead.  A Byzantine-agreement certificate fixes one immutable
//! transaction authorization, while successive views deterministically enumerate `n-f` signer
//! subsets.  Every view has fresh consensus and signing sessions, and portable round
//! contributions are relayed all-to-all.  Since at most `f` parties are faulty, one of the
//! `C(n, f)` subsets is entirely honest; `MAX_COMMITTEE_MEMBERS == 10` keeps each deterministic
//! cycle bounded. After one cycle, the same subsets repeat with monotonically fresh attempts and
//! sessions so a long asynchronous period cannot permanently remove an honest subset.
//!
//! The absolute view counter is not bounded by the in-memory history window. Full round bodies are
//! retained only for a bounded live window, followed by a bounded exact-replay window containing
//! certified intent cores and contribution digests. Older views are folded into an authenticated
//! prefix boundary. Compaction never makes an attempt reusable: the absolute view/attempt high-water
//! remains monotonic and the worker/coordinator retain their independent nonce-burn high-waters.
//!
//! A later view does **not** claim that an earlier view can no longer finish.  Doing so would be
//! unsafe when a Byzantine party withholds an "unexposed" statement.  Multiple views may therefore
//! produce different, valid Monero transaction encodings.  They all bind the same prepared intent,
//! inputs, outputs, rings and fee, spend the same key images, and are mutually exclusive on chain.
//! The chain-confirmation layer must accept and gossip every independently validated candidate and
//! settle the family by confirmed inclusion, not by coordinator preference.
//!
//! Terminal completion and abandonment bind an authenticated prefix of every certified absolute
//! attempt.  The prefix is a witness-independent Merkle-mountain-range commitment: honest parties
//! may retain different relay/candidate witnesses without deriving different terminal values, and
//! cold storage can later prove an evicted winning attempt in logarithmic time.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::{
    committee::{Committee, MAX_COMMITTEE_MEMBERS, PartyId, SessionId},
    consolidation_consensus::{
        AttemptSafetyPhase, CONSOLIDATION_INTENT_APPLICATION, ConsolidationAttemptSafety,
        ConsolidationConsensusError, ConsolidationIntent, ConsolidationIntentCertificate,
        PendingShareExposure, PendingShareUnexposed,
    },
    deposit_consensus::{ConsensusBinding, ConsensusContext, ConsensusError},
    deposit_consolidation::{
        ConsolidationError, ConsolidationId, SignedTransactionBinding, TransactionAuthorization,
    },
    deposit_consolidation_wire::{
        ConsolidationAttemptWireBinding, ConsolidationConsensusSlot, ConsolidationWireError,
        MAX_CONSOLIDATION_WIRE_BYTES, PortableFamilyKeyImageBinding,
        PortableKeyImageBindingAttestation, PortableKeyImageBindingCertificate,
        PortableSignedTransactionAttestation, SignedPreprocessContribution,
        SignedShareContribution,
    },
    deposit_wallet::derive_sweep_signing_session,
    identity::Identity,
    signing::{expected_frostlass_preprocess_bytes, validate_frostlass_preprocess_shape},
};

const ROAST_STATE_VERSION: u16 = 8;
const ROAST_VIEW_PLAN_VERSION: u16 = 2;
const ROAST_RELAY_VERSION: u16 = 1;
const MAX_ROAST_PREFIX_PEAKS: usize = u64::BITS as usize;

/// Maximum number of live views whose exact round bodies remain available for progress.
pub const MAX_HOT_ROAST_VIEWS: usize = 8;

/// Maximum number of superseded views retained as exact digest replay tombstones.
pub const MAX_ROAST_REPLAY_TOMBSTONES: usize = 64;

/// Hard ceiling checked before decoding an attacker-controlled persisted reducer.
pub const MAX_ROAST_STATE_BYTES: usize = 48 * 1024 * 1024;

/// Maximum canonical binding/envelope overhead around exact raw FROSTLASS preprocess bytes.
///
/// The inner contribution is content-addressed once in the reducer. Recipient-specific outer
/// relay copies are pruned when a successor view is certified, so this allowance need cover only
/// the portable signed contribution itself rather than an all-to-all fanout.
const MAX_SIGNED_PREPROCESS_OVERHEAD_BYTES: usize = 16 * 1024;

/// One hot view may consume at most half of its equal share of the reducer resource ceiling with
/// round-one bodies. The other half remains available for certified intent, key-image, share, and
/// candidate evidence. Committee-derived limits below can make the effective budget smaller.
const MAX_PREPROCESS_RETAINED_BYTES_PER_VIEW: usize =
    MAX_ROAST_STATE_BYTES / MAX_HOT_ROAST_VIEWS / 2;

/// Deterministic cyclic lexicographic `n-f` subset for one absolute view.
///
/// The subset schedule repeats, but the caller binds the absolute view to a monotonically fresh
/// attempt/session. Repeating a signer set therefore never reuses nonce authority.
pub fn deterministic_roast_signers(
    committee: &Committee,
    fault_bound: u16,
    view: u64,
) -> Result<Vec<PartyId>, ConsolidationRoastError> {
    committee.validate_async_security_with_faults(fault_bound)?;
    let mut parties = committee.members.iter().map(|member| member.id).collect::<Vec<_>>();
    parties.sort_unstable();
    let combinations = combinations(&parties, usize::from(committee.n() - fault_bound));
    if combinations.is_empty() {
        return Err(ConsolidationRoastError::ViewExhausted);
    }
    let cycle =
        u64::try_from(combinations.len()).map_err(|_| ConsolidationRoastError::ViewExhausted)?;
    let index =
        usize::try_from(view % cycle).map_err(|_| ConsolidationRoastError::ViewExhausted)?;
    Ok(combinations[index].clone())
}

/// Round contribution kind used by the durable all-to-all relay index.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum RoastContributionPhase {
    Preprocess,
    KeyImageBinding,
    Share,
    Candidate,
}

/// Deterministic coordinator-free plan for one fresh-session signing view.
///
/// `relay_seed` is retained under the familiar coordinator name on the existing wire binding, but
/// it has no authority: any party may relay any portable contribution or completed transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastViewPlan {
    version: u16,
    view: u64,
    attempt: u64,
    relay_seed: PartyId,
    signers: Vec<PartyId>,
    signing_session: SessionId,
    consensus_session: SessionId,
}

impl RoastViewPlan {
    /// Derive the exact `n-f` subset and fresh sessions for `view`.
    pub fn derive(
        slot: &ConsolidationConsensusSlot,
        committee: &Committee,
        fault_bound: u16,
        authorization: &TransactionAuthorization,
    ) -> Result<Self, ConsolidationRoastError> {
        committee.validate_async_security_with_faults(fault_bound)?;
        authorization.validate()?;
        let binding = slot.binding();
        let view = slot.roast_view();
        if binding.application.as_slice() != CONSOLIDATION_INTENT_APPLICATION
            || binding.wallet != authorization.wallet_id().0
            || slot.committee_digest() != committee.digest()
            || slot.fault_bound() != fault_bound
            || binding.registry == [0; 32]
            || binding.activation == [0; 32]
            || binding.network == [0; 32]
            || binding.domain == [0; 32]
        {
            return Err(ConsolidationRoastError::WrongFamily);
        }

        let attempt = view.checked_add(1).ok_or(ConsolidationRoastError::ViewExhausted)?;
        let view_index =
            usize::try_from(view).map_err(|_| ConsolidationRoastError::ViewExhausted)?;
        let signers = deterministic_roast_signers(committee, fault_bound, view)?;
        // The relay seed is deliberately inside the selected subset.  The all-honest subset thus
        // necessarily has an honest seed, without taking the Cartesian product of subsets/leaders.
        let relay_seed = signers[view_index % signers.len()];
        // The encrypted worker's monotonic family counter and the coordinator-free view must name
        // the same sole session. This deterministic wallet/sweep/attempt binding survives exact
        // history compaction without permitting an old session to re-enter a later view.
        let signing_session = derive_sweep_signing_session(
            authorization.wallet_id(),
            authorization.sweep_id(),
            attempt,
        )
        .ok_or(ConsolidationRoastError::WrongFamily)?;
        // Consensus chooses the randomized prepared value *inside* one shared deterministic
        // sweep slot.  Deriving this session from `authorization` would put two independently
        // prepared (and therefore normally different) proposals into disjoint consensus lanes,
        // allowing honest parties to vote in both.  The immutable binding, committee, sweep-slot
        // anchor and outer ROAST view are sufficient to name the lane. The post-certificate
        // signing session is instead derived from the monotonic wallet/sweep attempt family, so
        // two competing values at one view cannot acquire two nonce namespaces.
        let consensus_session = slot.session();
        if signing_session == consensus_session {
            return Err(ConsolidationRoastError::SessionCollision);
        }
        Ok(Self {
            version: ROAST_VIEW_PLAN_VERSION,
            view,
            attempt,
            relay_seed,
            signers,
            signing_session,
            consensus_session,
        })
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }

    #[must_use]
    pub const fn relay_seed(&self) -> PartyId {
        self.relay_seed
    }

    #[must_use]
    pub fn signers(&self) -> &[PartyId] {
        &self.signers
    }

    #[must_use]
    pub const fn signing_session(&self) -> SessionId {
        self.signing_session
    }

    #[must_use]
    pub const fn consensus_session(&self) -> SessionId {
        self.consensus_session
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self).expect("validated view plan serializes");
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/consolidation-roast/view-plan/v1");
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }
}

/// Exact durable relay acknowledgement.  An ACK for one digest cannot retire another view,
/// contribution, origin or recipient.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RoastRelayId {
    version: u16,
    family: [u8; 32],
    view: u64,
    attempt: [u8; 32],
    session: SessionId,
    phase: RoastContributionPhase,
    origin: PartyId,
    recipient: PartyId,
    contribution: [u8; 32],
}

impl RoastRelayId {
    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub const fn phase(&self) -> RoastContributionPhase {
        self.phase
    }

    #[must_use]
    pub const fn origin(&self) -> PartyId {
        self.origin
    }

    #[must_use]
    pub const fn recipient(&self) -> PartyId {
        self.recipient
    }

    #[must_use]
    pub const fn contribution_digest(&self) -> [u8; 32] {
        self.contribution
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self).expect("relay identifier serializes");
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/consolidation-roast/relay/v1");
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CandidateArchive {
    signed: SignedTransactionBinding,
    origins: BTreeMap<PartyId, ArchivedContribution>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ArchivedContribution {
    digest: [u8; 32],
    /// Exact canonical portable body. Superseded round bodies are compacted to authenticated
    /// digest tombstones when the successor certificate is committed.
    body: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RoastViewRecord {
    slot: ConsolidationConsensusSlot,
    plan: RoastViewPlan,
    context: ConsensusContext,
    intent: ConsolidationIntent,
    intent_certificate: ConsolidationIntentCertificate,
    preprocesses: BTreeMap<PartyId, ArchivedContribution>,
    key_image_bindings: BTreeMap<PartyId, ArchivedContribution>,
    key_image_certificate: Option<PortableKeyImageBindingCertificate>,
    local_safety: Option<ConsolidationAttemptSafety>,
    shares: BTreeMap<PartyId, ArchivedContribution>,
    relay_acks: BTreeSet<RoastRelayId>,
    candidates: BTreeMap<[u8; 32], CandidateArchive>,
}

/// Exact certified view core retained after round bodies cease to be live.
///
/// The core is sufficient to authenticate a byte-identical late retry without allowing any new
/// contribution to enter a superseded view. Contribution bodies and recipient ACK matrices are
/// deliberately absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RoastViewReplayTombstone {
    slot: ConsolidationConsensusSlot,
    plan: RoastViewPlan,
    context: ConsensusContext,
    intent: ConsolidationIntent,
    intent_certificate: ConsolidationIntentCertificate,
    preprocesses: BTreeMap<PartyId, [u8; 32]>,
    key_image_bindings: BTreeMap<PartyId, [u8; 32]>,
    key_image_certificate: Option<[u8; 32]>,
    shares: BTreeMap<PartyId, [u8; 32]>,
    /// At most one candidate per origin is accepted by the live reducer.
    candidates: BTreeMap<PartyId, ([u8; 32], [u8; 32])>,
    digest: [u8; 32],
}

impl RoastViewReplayTombstone {
    fn from_record(record: RoastViewRecord) -> Result<Self, ConsolidationRoastError> {
        let candidates = record
            .candidates
            .iter()
            .flat_map(|(transaction, candidate)| {
                candidate
                    .origins
                    .iter()
                    .map(move |(origin, archive)| (*origin, (*transaction, archive.digest)))
            })
            .collect::<BTreeMap<_, _>>();
        let mut tombstone = Self {
            slot: record.slot,
            plan: record.plan,
            context: record.context,
            intent: record.intent,
            intent_certificate: record.intent_certificate,
            preprocesses: contribution_digests(record.preprocesses),
            key_image_bindings: contribution_digests(record.key_image_bindings),
            key_image_certificate: record
                .key_image_certificate
                .as_ref()
                .map(PortableKeyImageBindingCertificate::digest),
            shares: contribution_digests(record.shares),
            candidates,
            digest: [0; 32],
        };
        tombstone.digest = tombstone.expected_digest()?;
        Ok(tombstone)
    }

    fn expected_digest(&self) -> Result<[u8; 32], ConsolidationRoastError> {
        let mut canonical = self.clone();
        canonical.digest = [0; 32];
        let bytes = postcard::to_allocvec(&canonical)
            .map_err(|_| ConsolidationRoastError::Serialization)?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/consolidation-roast/replay-tombstone/v1",
        );
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    fn certified_attempt_leaf(&self) -> Result<[u8; 32], ConsolidationRoastError> {
        certified_roast_attempt_leaf(
            deterministic_roast_family_digest(
                self.slot.binding(),
                self.slot.committee(),
                self.slot.fault_bound(),
                self.intent.authorization(),
                self.slot.family_anchor(),
            ),
            self.slot.family_anchor(),
            &self.slot,
            &self.context,
            &self.intent,
            &self.intent_certificate,
        )
    }
}

/// One peak in the append-only Merkle-mountain-range commitment to certified attempts.
///
/// The fields are intentionally private. A frontier can only acquire peaks by verifying and
/// appending a complete certified attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastAttemptPrefixPeak {
    height: u8,
    digest: [u8; 32],
}

impl RoastAttemptPrefixPeak {
    #[must_use]
    pub const fn height(self) -> u8 {
        self.height
    }

    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

/// Append-only MMR frontier for one contiguous certified-attempt prefix.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastAttemptPrefixFrontier {
    leaf_count: u64,
    peaks: Vec<RoastAttemptPrefixPeak>,
}

impl RoastAttemptPrefixFrontier {
    #[must_use]
    pub const fn empty() -> Self {
        Self { leaf_count: 0, peaks: Vec::new() }
    }

    pub(crate) fn from_peaks(
        leaf_count: u64,
        peaks: Vec<RoastAttemptPrefixPeak>,
    ) -> Result<Self, ConsolidationRoastError> {
        if peaks.len() > MAX_ROAST_PREFIX_PEAKS {
            return Err(ConsolidationRoastError::InvalidAttemptPrefix);
        }
        let frontier = Self { leaf_count, peaks };
        frontier.validate()?;
        Ok(frontier)
    }

    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    #[must_use]
    pub fn peaks(&self) -> &[RoastAttemptPrefixPeak] {
        &self.peaks
    }

    /// Verify and append the exact next certified absolute attempt.
    #[allow(clippy::too_many_arguments)]
    pub fn append_certified_attempt(
        &mut self,
        family: [u8; 32],
        family_anchor: [u8; 32],
        slot: &ConsolidationConsensusSlot,
        context: &ConsensusContext,
        intent: &ConsolidationIntent,
        certificate: &ConsolidationIntentCertificate,
    ) -> Result<(), ConsolidationRoastError> {
        if slot.roast_view() != self.leaf_count {
            return Err(ConsolidationRoastError::InvalidViewChain);
        }
        let leaf = certified_roast_attempt_leaf(
            family,
            family_anchor,
            slot,
            context,
            intent,
            certificate,
        )?;
        self.append_verified_leaf(leaf)
    }

    pub(crate) fn append_verified_leaf(
        &mut self,
        leaf: [u8; 32],
    ) -> Result<(), ConsolidationRoastError> {
        self.validate()?;
        if leaf == [0; 32] || self.leaf_count == u64::MAX {
            return Err(ConsolidationRoastError::InvalidAttemptPrefix);
        }
        let mut height = 0_u8;
        let mut digest = leaf;
        let previous_count = self.leaf_count;
        while previous_count & (1_u64 << u32::from(height)) != 0 {
            let left = self.peaks.pop().ok_or(ConsolidationRoastError::InvalidAttemptPrefix)?;
            if left.height != height {
                return Err(ConsolidationRoastError::InvalidAttemptPrefix);
            }
            height = height.checked_add(1).ok_or(ConsolidationRoastError::InvalidAttemptPrefix)?;
            digest = roast_attempt_prefix_parent(height, left.digest, digest);
        }
        self.peaks.push(RoastAttemptPrefixPeak { height, digest });
        self.leaf_count =
            self.leaf_count.checked_add(1).ok_or(ConsolidationRoastError::ViewExhausted)?;
        self.validate()
    }

    /// Bag the ordered MMR peaks into the constant-size value committed by terminal BA.
    pub fn root(&self) -> Result<[u8; 32], ConsolidationRoastError> {
        self.validate()?;
        if self.leaf_count == 0 {
            return Err(ConsolidationRoastError::InvalidAttemptPrefix);
        }
        Ok(roast_attempt_prefix_root(self.leaf_count, &self.peaks))
    }

    fn validate(&self) -> Result<(), ConsolidationRoastError> {
        if self.peaks.len() > MAX_ROAST_PREFIX_PEAKS
            || usize::try_from(self.leaf_count.count_ones())
                .map_err(|_| ConsolidationRoastError::InvalidAttemptPrefix)?
                != self.peaks.len()
            || self.peaks.iter().any(|peak| peak.digest == [0; 32])
        {
            return Err(ConsolidationRoastError::InvalidAttemptPrefix);
        }
        let expected = (0..u64::BITS)
            .rev()
            .filter(|height| self.leaf_count & (1_u64 << height) != 0)
            .map(|height| u8::try_from(height).expect("u64 height fits u8"));
        if self.peaks.iter().map(|peak| peak.height).ne(expected) {
            return Err(ConsolidationRoastError::InvalidAttemptPrefix);
        }
        Ok(())
    }
}

/// Witness-independent semantic leaf for one BA-certified ROAST attempt.
///
/// Commit-certificate witnesses and locally observed relay/candidate maps are deliberately
/// excluded. `decision_digest()` already binds the context and value independently of which
/// canonical quorum subset a collector retained.
#[allow(clippy::too_many_arguments)]
pub fn certified_roast_attempt_leaf(
    family: [u8; 32],
    family_anchor: [u8; 32],
    slot: &ConsolidationConsensusSlot,
    context: &ConsensusContext,
    intent: &ConsolidationIntent,
    certificate: &ConsolidationIntentCertificate,
) -> Result<[u8; 32], ConsolidationRoastError> {
    if family == [0; 32]
        || family_anchor == [0; 32]
        || slot.family_anchor() != family_anchor
        || slot.roast_view().checked_add(1) != Some(intent.attempt().attempt())
    {
        return Err(ConsolidationRoastError::InvalidAttemptPrefix);
    }
    slot.verify_context(context)?;
    certificate.verify_expected(context, intent)?;
    let plan =
        RoastViewPlan::derive(slot, slot.committee(), slot.fault_bound(), intent.authorization())?;
    validate_intent_for_plan(context, intent, intent.authorization(), &plan)?;
    if deterministic_roast_family_digest(
        slot.binding(),
        slot.committee(),
        slot.fault_bound(),
        intent.authorization(),
        family_anchor,
    ) != family
    {
        return Err(ConsolidationRoastError::WrongFamily);
    }
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/consolidation-roast/attempt-leaf/v1");
    hasher.update(&family);
    hasher.update(&family_anchor);
    hasher.update(&slot.roast_view().to_le_bytes());
    hasher.update(&intent.attempt().attempt().to_le_bytes());
    hasher.update(&slot.digest());
    hasher.update(&context.digest());
    hasher.update(&plan.digest());
    hasher.update(&intent.digest());
    hasher.update(&certificate.decision_digest());
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn roast_attempt_prefix_parent(height: u8, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/consolidation-roast/mmr-parent/v1");
    hasher.update(&[height]);
    hasher.update(&left);
    hasher.update(&right);
    *hasher.finalize().as_bytes()
}

pub(crate) fn roast_attempt_prefix_root(
    leaf_count: u64,
    peaks: &[RoastAttemptPrefixPeak],
) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/consolidation-roast/mmr-root/v1");
    hasher.update(&leaf_count.to_le_bytes());
    hasher.update(&(peaks.len() as u64).to_le_bytes());
    for peak in peaks {
        hasher.update(&[peak.height]);
        hasher.update(&peak.digest);
    }
    *hasher.finalize().as_bytes()
}

/// Constant-size commitment to every view older than the exact replay window.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RoastCompactedPrefix {
    through_view: u64,
    ledger_height: u64,
    ledger_sequence: u64,
    decision: [u8; 32],
    frontier: RoastAttemptPrefixFrontier,
}

impl RoastCompactedPrefix {
    fn extend(
        previous: Option<Self>,
        view: u64,
        tombstone: &RoastViewReplayTombstone,
    ) -> Result<Self, ConsolidationRoastError> {
        if previous.as_ref().is_some_and(|prefix| prefix.through_view.checked_add(1) != Some(view))
        {
            return Err(ConsolidationRoastError::InvalidViewChain);
        }
        let mut frontier = previous
            .as_ref()
            .map_or_else(RoastAttemptPrefixFrontier::empty, |prefix| prefix.frontier.clone());
        if frontier.leaf_count() != view {
            return Err(ConsolidationRoastError::InvalidViewChain);
        }
        frontier.append_verified_leaf(tombstone.certified_attempt_leaf()?)?;
        Ok(Self {
            through_view: view,
            ledger_height: tombstone.context.height(),
            ledger_sequence: tombstone.context.sequence(),
            decision: tombstone.intent_certificate.decision_digest(),
            frontier,
        })
    }
}

fn contribution_digests(
    archive: BTreeMap<PartyId, ArchivedContribution>,
) -> BTreeMap<PartyId, [u8; 32]> {
    archive.into_iter().map(|(party, contribution)| (party, contribution.digest)).collect()
}

fn compact_live_views(state: &mut ConsolidationRoast) -> Result<(), ConsolidationRoastError> {
    let live = std::mem::take(&mut state.views);
    for (view, record) in live {
        let tombstone = RoastViewReplayTombstone::from_record(record)?;
        if state.replay_tombstones.insert(view, tombstone).is_some() {
            return Err(ConsolidationRoastError::InvalidState);
        }
    }
    while state.replay_tombstones.len() > MAX_ROAST_REPLAY_TOMBSTONES {
        let oldest = *state
            .replay_tombstones
            .first_key_value()
            .map(|(view, _)| view)
            .ok_or(ConsolidationRoastError::InvalidState)?;
        let tombstone =
            state.replay_tombstones.remove(&oldest).ok_or(ConsolidationRoastError::InvalidState)?;
        state.compacted_prefix =
            Some(RoastCompactedPrefix::extend(state.compacted_prefix.clone(), oldest, &tombstone)?);
    }
    Ok(())
}

/// Permanently retained, independently verifiable bootstrap certificate for public status and
/// family reconstruction after view zero leaves both bounded retention windows.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RoastBootstrapEvidence {
    slot: ConsolidationConsensusSlot,
    context: ConsensusContext,
    intent: ConsolidationIntent,
    certificate: ConsolidationIntentCertificate,
}

/// Certificate-linked public evidence for the latest durable ROAST view.
///
/// Counters are deliberately accompanied by the exact certificate/attempt/evidence digests from
/// which they were derived. Callers must never synthesize these fields from an uncertified local
/// coordinator view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastPublicEvidence {
    pub bootstrap_ba_view: u64,
    pub bootstrap_ba_proposer: PartyId,
    pub bootstrap_prepared_intent_digest: [u8; 32],
    pub bootstrap_certificate_digest: [u8; 32],
    pub bootstrap_certificate_signers: Vec<PartyId>,
    pub view: u64,
    pub relay_seed: PartyId,
    pub signers: Vec<PartyId>,
    pub view_count: u16,
    pub candidate_count: u16,
    pub endorsed_candidate_count: u16,
    pub intent_certificate_digest: [u8; 32],
    pub intent_certificate_signers: Vec<PartyId>,
    pub attempt_binding_digest: [u8; 32],
    pub endorsed_witness_count: u16,
    pub endorsed_evidence_digest: [u8; 32],
    pub key_image_binding_digest: [u8; 32],
    pub key_image_unsigned_transaction_digest: [u8; 32],
    pub key_image_preprocess_set_digest: [u8; 32],
    pub key_image_authorizers: Vec<PartyId>,
    pub key_image_authorization_quorum: u16,
}

/// Complete certificate-bearing hot attempt material which must enter cold storage before the
/// reducer retires its full key-image certificate and round bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoastAttemptArchiveMaterial {
    pub slot: ConsolidationConsensusSlot,
    pub context: ConsensusContext,
    pub intent: ConsolidationIntent,
    pub intent_certificate: ConsolidationIntentCertificate,
    pub wire_binding: ConsolidationAttemptWireBinding,
    pub key_image_certificate: Option<PortableKeyImageBindingCertificate>,
}

/// Constant-size ordered commitment to the complete certified attempt prefix closed by a terminal
/// abandonment. An evicted attempt proves membership with its original n-f intent certificate;
/// this seal binds the exact family anchor and absolute high-water selected by the abandonment BA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastAttemptPrefixSeal {
    family: [u8; 32],
    family_anchor: [u8; 32],
    closed_through_view: u64,
    closed_through_attempt: u64,
    accumulator: [u8; 32],
}

impl RoastAttemptPrefixSeal {
    /// Close a non-empty frontier whose leaves were all independently verified certified attempts.
    pub fn from_frontier(
        family: [u8; 32],
        family_anchor: [u8; 32],
        frontier: &RoastAttemptPrefixFrontier,
    ) -> Result<Self, ConsolidationRoastError> {
        if family == [0; 32] || family_anchor == [0; 32] || frontier.leaf_count() == 0 {
            return Err(ConsolidationRoastError::InvalidAttemptPrefix);
        }
        let closed_through_attempt = frontier.leaf_count();
        let closed_through_view = closed_through_attempt
            .checked_sub(1)
            .ok_or(ConsolidationRoastError::InvalidAttemptPrefix)?;
        Ok(Self {
            family,
            family_anchor,
            closed_through_view,
            closed_through_attempt,
            accumulator: frontier.root()?,
        })
    }

    /// Verify that this seal is exactly the root and high-water of `frontier`.
    pub fn verify_frontier(
        self,
        frontier: &RoastAttemptPrefixFrontier,
    ) -> Result<(), ConsolidationRoastError> {
        if self.closed_through_attempt != frontier.leaf_count()
            || self.closed_through_view.checked_add(1) != Some(self.closed_through_attempt)
            || self.accumulator != frontier.root()?
        {
            return Err(ConsolidationRoastError::InvalidAttemptPrefix);
        }
        Ok(())
    }

    #[must_use]
    pub const fn family(self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn family_anchor(self) -> [u8; 32] {
        self.family_anchor
    }

    #[must_use]
    pub const fn closed_through_view(self) -> u64 {
        self.closed_through_view
    }

    #[must_use]
    pub const fn closed_through_attempt(self) -> u64 {
        self.closed_through_attempt
    }

    #[must_use]
    pub const fn accumulator(self) -> [u8; 32] {
        self.accumulator
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RoastCompletionSeal {
    statement: [u8; 32],
    evidence: [u8; 32],
    completed_view: u64,
    /// Entire certified absolute attempt prefix closed by the sequence-scoped completion BA. The
    /// winning transaction may come from an older view, but every later released nonce remains
    /// permanently burned.
    prefix: RoastAttemptPrefixSeal,
    public: RoastPublicEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RoastAbandonmentSeal {
    statement: [u8; 32],
    evidence: [u8; 32],
    abandoned_view: u64,
    prefix: RoastAttemptPrefixSeal,
    public: RoastPublicEvidence,
}

/// Persistent orchestration state from one party's perspective.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationRoast {
    version: u16,
    local_party: PartyId,
    committee: Committee,
    fault_bound: u16,
    binding: ConsensusBinding,
    quic_network_id: [u8; 32],
    authorization: TransactionAuthorization,
    /// Digest of the value-independent genesis slot. This is the immutable family anchor.
    family_anchor: [u8; 32],
    family: [u8; 32],
    bootstrap: RoastBootstrapEvidence,
    compacted_prefix: Option<RoastCompactedPrefix>,
    replay_tombstones: BTreeMap<u64, RoastViewReplayTombstone>,
    views: BTreeMap<u64, RoastViewRecord>,
    completion_seal: Option<RoastCompletionSeal>,
    abandonment_seal: Option<RoastAbandonmentSeal>,
    /// First view not yet certified. This absolute high-water never follows retained map length.
    next_view: u64,
    outer_deadline_view: u64,
    outer_deadline_unix_ms: u64,
    outer_base_timeout_ms: u64,
    revision: u64,
    transition: [u8; 32],
}

impl ConsolidationRoast {
    /// Create a family only from an exact locally reconstructed, BA-certified first intent.
    pub fn new(
        local_party: PartyId,
        quic_network_id: [u8; 32],
        expected_slot: ConsolidationConsensusSlot,
        expected_context: ConsensusContext,
        expected_intent: ConsolidationIntent,
        intent_certificate: ConsolidationIntentCertificate,
        now_ms: u64,
        outer_base_timeout_ms: u64,
    ) -> Result<Self, ConsolidationRoastError> {
        expected_context.committee().member(local_party)?;
        if quic_network_id == [0; 32]
            || quic_network_id != expected_slot.binding().network
            || quic_network_id != expected_context.binding().network
        {
            return Err(ConsolidationRoastError::WrongNetwork);
        }
        expected_slot.verify_context(&expected_context)?;
        if expected_slot.roast_view() != 0 {
            return Err(ConsolidationRoastError::InvalidViewChain);
        }
        intent_certificate.verify_expected(&expected_context, &expected_intent)?;
        let authorization = expected_intent.authorization().clone();
        let committee = expected_context.committee().clone();
        let fault_bound = expected_context.fault_bound();
        let binding = expected_context.binding().clone();
        let family_anchor = expected_slot.digest();
        let family = deterministic_roast_family_digest(
            &binding,
            &committee,
            fault_bound,
            &authorization,
            family_anchor,
        );
        let plan = RoastViewPlan::derive(&expected_slot, &committee, fault_bound, &authorization)?;
        validate_intent_for_plan(&expected_context, &expected_intent, &authorization, &plan)?;
        let bootstrap = RoastBootstrapEvidence {
            slot: expected_slot.clone(),
            context: expected_context.clone(),
            intent: expected_intent.clone(),
            certificate: intent_certificate.clone(),
        };
        let local_safety = plan
            .signers
            .binary_search(&local_party)
            .is_ok()
            .then(|| {
                ConsolidationAttemptSafety::new(
                    local_party,
                    &expected_context,
                    expected_intent.clone(),
                    &intent_certificate,
                )
            })
            .transpose()?;
        let mut views = BTreeMap::new();
        views.insert(
            0,
            RoastViewRecord {
                slot: expected_slot,
                plan,
                context: expected_context,
                intent: expected_intent,
                intent_certificate,
                preprocesses: BTreeMap::new(),
                key_image_bindings: BTreeMap::new(),
                key_image_certificate: None,
                local_safety,
                shares: BTreeMap::new(),
                relay_acks: BTreeSet::new(),
                candidates: BTreeMap::new(),
            },
        );
        let mut state = Self {
            version: ROAST_STATE_VERSION,
            local_party,
            committee,
            fault_bound,
            binding,
            quic_network_id,
            authorization,
            family_anchor,
            family,
            bootstrap,
            compacted_prefix: None,
            replay_tombstones: BTreeMap::new(),
            views,
            completion_seal: None,
            abandonment_seal: None,
            next_view: 1,
            outer_deadline_view: 0,
            outer_deadline_unix_ms: roast_outer_deadline(now_ms, outer_base_timeout_ms, 0)?,
            outer_base_timeout_ms,
            revision: 0,
            transition: [0; 32],
        };
        state.transition = state.expected_transition()?;
        state.validate()?;
        Ok(state)
    }

    #[must_use]
    pub const fn family_digest(&self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn authorization_id(&self) -> ConsolidationId {
        self.authorization.id()
    }

    #[must_use]
    pub const fn authorization(&self) -> &TransactionAuthorization {
        &self.authorization
    }

    #[must_use]
    pub const fn wallet_id(&self) -> crate::deposit_wallet::DepositWalletId {
        self.authorization.wallet_id()
    }

    #[must_use]
    pub const fn sweep_id(&self) -> crate::deposit_wallet::SweepId {
        self.authorization.sweep_id()
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
    pub const fn local_party(&self) -> PartyId {
        self.local_party
    }

    #[must_use]
    pub const fn quic_network_id(&self) -> [u8; 32] {
        self.quic_network_id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Absolute first uncertified view. Retention compaction never changes this high-water.
    #[must_use]
    pub const fn next_view(&self) -> u64 {
        self.next_view
    }

    /// Number of full live view records currently retained.
    #[must_use]
    pub fn hot_view_count(&self) -> usize {
        self.views.len()
    }

    /// Highest view folded beyond the exact replay window.
    #[must_use]
    pub fn compacted_through(&self) -> Option<u64> {
        self.compacted_prefix.as_ref().map(|prefix| prefix.through_view)
    }

    /// Whether this family has folded the view beyond exact replay/progress retention.
    #[must_use]
    pub fn is_fully_compacted_view(&self, view: u64) -> bool {
        self.compacted_prefix.as_ref().is_some_and(|prefix| view <= prefix.through_view)
    }

    /// Match the immutable coordinates of a locally-created consensus slot from this family.
    #[must_use]
    pub fn owns_slot_family(&self, slot: &ConsolidationConsensusSlot) -> bool {
        slot.binding() == &self.binding
            && slot.committee() == &self.committee
            && slot.fault_bound() == self.fault_bound
            && slot.family_anchor() == self.family_anchor
    }

    #[must_use]
    pub fn is_completion_sealed(&self) -> bool {
        self.completion_seal.is_some()
    }

    #[must_use]
    pub fn is_abandonment_sealed(&self) -> bool {
        self.abandonment_seal.is_some()
    }

    #[must_use]
    pub fn is_terminal_sealed(&self) -> bool {
        self.completion_seal.is_some() || self.abandonment_seal.is_some()
    }

    #[must_use]
    pub fn completion_seal_matches(&self, statement: [u8; 32], evidence: [u8; 32]) -> bool {
        self.completion_seal
            .as_ref()
            .is_some_and(|seal| seal.statement == statement && seal.evidence == evidence)
    }

    #[must_use]
    pub fn abandonment_seal_matches(&self, statement: [u8; 32], evidence: [u8; 32]) -> bool {
        self.abandonment_seal
            .as_ref()
            .is_some_and(|seal| seal.statement == statement && seal.evidence == evidence)
    }

    /// Constant-size ordered commitment through the absolute latest certified attempt.
    pub fn attempt_prefix_seal(&self) -> Result<RoastAttemptPrefixSeal, ConsolidationRoastError> {
        self.validate()?;
        self.expected_attempt_prefix_seal()
    }

    fn expected_attempt_prefix_seal(
        &self,
    ) -> Result<RoastAttemptPrefixSeal, ConsolidationRoastError> {
        let mut prefix = self.compacted_prefix.clone();
        for (view, tombstone) in &self.replay_tombstones {
            prefix = Some(RoastCompactedPrefix::extend(prefix, *view, tombstone)?);
        }
        for (view, record) in &self.views {
            let tombstone = RoastViewReplayTombstone::from_record(record.clone())?;
            prefix = Some(RoastCompactedPrefix::extend(prefix, *view, &tombstone)?);
        }
        let prefix = prefix.ok_or(ConsolidationRoastError::InvalidState)?;
        let closed_through_attempt =
            prefix.through_view.checked_add(1).ok_or(ConsolidationRoastError::ViewExhausted)?;
        let accumulator = prefix.frontier.root()?;
        if closed_through_attempt != self.next_view || accumulator == [0; 32] {
            return Err(ConsolidationRoastError::InvalidState);
        }
        RoastAttemptPrefixSeal::from_frontier(self.family, self.family_anchor, &prefix.frontier)
    }

    #[must_use]
    pub const fn outer_deadline_unix_ms(&self) -> u64 {
        self.outer_deadline_unix_ms
    }

    /// Replace every live round body and ACK matrix with exact digest replay tombstones after the
    /// sequence-scoped BA has selected a self-contained completion. The caller stores this reducer
    /// in the same snapshot transaction which prunes all family transport effects.
    pub fn seal_completion(
        &mut self,
        completed_view: u64,
        expected_prefix: RoastAttemptPrefixSeal,
        statement: [u8; 32],
        evidence: [u8; 32],
    ) -> Result<bool, ConsolidationRoastError> {
        self.validate()?;
        if statement == [0; 32] || evidence == [0; 32] {
            return Err(ConsolidationRoastError::InvalidCompletionSeal);
        }
        if self.attempt_prefix_seal()? != expected_prefix
            || completed_view > expected_prefix.closed_through_view
        {
            return Err(ConsolidationRoastError::InvalidCompletionSeal);
        }
        if self.abandonment_seal.is_some() {
            return Err(ConsolidationRoastError::InvalidCompletionSeal);
        }
        if let Some(seal) = &self.completion_seal {
            return if seal.statement == statement
                && seal.evidence == evidence
                && seal.completed_view == completed_view
                && seal.prefix == expected_prefix
            {
                Ok(false)
            } else {
                Err(ConsolidationRoastError::InvalidCompletionSeal)
            };
        }
        let required = usize::from(self.fault_bound).saturating_add(1);
        self.views
            .get(&completed_view)
            .filter(|record| {
                record.candidates.values().any(|candidate| candidate.origins.len() >= required)
            })
            .ok_or(ConsolidationRoastError::InvalidCompletionSeal)?;
        let public = self.public_evidence()?;
        self.transact(move |next| {
            compact_live_views(next)?;
            next.completion_seal = Some(RoastCompletionSeal {
                statement,
                evidence,
                completed_view,
                prefix: expected_prefix,
                public,
            });
            Ok((true, true))
        })
    }

    /// Permanently burn an unsigned attempt lineage after the global ledger BA selects an exact,
    /// finality-backed input-reorg abandonment. This never releases any nonce, key image, signing
    /// session, or input for a replacement transaction.
    pub fn seal_abandonment(
        &mut self,
        abandoned_view: u64,
        expected_prefix: RoastAttemptPrefixSeal,
        statement: [u8; 32],
        evidence: [u8; 32],
    ) -> Result<bool, ConsolidationRoastError> {
        self.validate()?;
        if statement == [0; 32] || evidence == [0; 32] {
            return Err(ConsolidationRoastError::InvalidAbandonmentSeal);
        }
        if self.attempt_prefix_seal()? != expected_prefix {
            return Err(ConsolidationRoastError::InvalidAbandonmentSeal);
        }
        if self.completion_seal.is_some() {
            return Err(ConsolidationRoastError::InvalidAbandonmentSeal);
        }
        if let Some(seal) = &self.abandonment_seal {
            return if seal.statement == statement
                && seal.evidence == evidence
                && seal.abandoned_view == abandoned_view
                && seal.prefix == expected_prefix
            {
                Ok(false)
            } else {
                Err(ConsolidationRoastError::InvalidAbandonmentSeal)
            };
        }
        if abandoned_view >= self.next_view || self.plan(abandoned_view).is_none() {
            return Err(ConsolidationRoastError::InvalidAbandonmentSeal);
        }
        let public = self.public_evidence()?;
        self.transact(move |next| {
            compact_live_views(next)?;
            next.abandonment_seal = Some(RoastAbandonmentSeal {
                statement,
                evidence,
                abandoned_view,
                prefix: expected_prefix,
                public,
            });
            Ok((true, true))
        })
    }

    /// Return public status material derived exclusively from the verified durable certificate
    /// chain and portable candidate evidence.
    pub fn public_evidence(&self) -> Result<RoastPublicEvidence, ConsolidationRoastError> {
        self.validate()?;
        if let Some(seal) = &self.completion_seal {
            return Ok(seal.public.clone());
        }
        if let Some(seal) = &self.abandonment_seal {
            return Ok(seal.public.clone());
        }
        let bootstrap_ba_view = self.bootstrap.certificate.certificate().view();
        let bootstrap_prepared_intent_digest =
            self.bootstrap.intent.authorization().opaque_intent().0;
        let (latest_view, latest_record) =
            self.views.last_key_value().ok_or(ConsolidationRoastError::InvalidState)?;
        let required = usize::from(self.fault_bound).saturating_add(1);
        let candidate_count = self.views.values().try_fold(0_usize, |total, record| {
            total.checked_add(record.candidates.len()).ok_or(ConsolidationRoastError::InvalidState)
        })?;
        let endorsed = self
            .views
            .iter()
            .flat_map(|(candidate_view, candidate_record)| {
                candidate_record
                    .candidates
                    .iter()
                    .filter(move |(_, candidate)| candidate.origins.len() >= required)
                    .map(move |(transaction, candidate)| (*candidate_view, *transaction, candidate))
            })
            .collect::<Vec<_>>();
        let (endorsed_witness_count, endorsed_evidence_digest) = endorsed
            .first()
            .map(|(candidate_view, transaction, candidate)| {
                (
                    u16::try_from(candidate.origins.len()).unwrap_or(u16::MAX),
                    candidate_evidence_digest(*candidate_view, *transaction, candidate),
                )
            })
            .unwrap_or((0, [0; 32]));
        // Once a candidate is endorsed every attempt-specific public field must describe the
        // view which actually produced that candidate.  A later silent view remains useful
        // forensic history, but mixing its intent/session digest with an older winner makes an
        // otherwise valid portable completion appear inconsistent after restart.
        let (view, record) = endorsed
            .first()
            .and_then(|(candidate_view, _, _)| {
                self.views.get(candidate_view).map(|record| (candidate_view, record))
            })
            .unwrap_or((latest_view, latest_record));
        // An endorsed transaction may finish in an older still-live view after a successor was
        // certified. Bind public key-image evidence to that candidate's view, never blindly to
        // the newest view. Before endorsement, the newest complete pre-share certificate is the
        // useful operational signal.
        let key_image_record = endorsed
            .first()
            .and_then(|(candidate_view, _, _)| self.views.get(candidate_view))
            .or_else(|| {
                self.views
                    .values()
                    .rev()
                    .find(|candidate| candidate.key_image_certificate.is_some())
            });
        let key_image_certificate =
            key_image_record.and_then(|candidate| candidate.key_image_certificate.as_ref());
        let key_image_value = key_image_certificate.and_then(|certificate| certificate.value());
        Ok(RoastPublicEvidence {
            bootstrap_ba_view,
            bootstrap_ba_proposer: self.bootstrap.context.leader(bootstrap_ba_view),
            bootstrap_prepared_intent_digest,
            bootstrap_certificate_digest: self.bootstrap.certificate.decision_digest(),
            bootstrap_certificate_signers: self
                .bootstrap
                .certificate
                .certificate()
                .witnesses()
                .iter()
                .map(|witness| witness.from)
                .collect(),
            view: *view,
            relay_seed: record.plan.relay_seed,
            signers: record.plan.signers.clone(),
            view_count: u16::try_from(self.next_view).unwrap_or(u16::MAX),
            candidate_count: u16::try_from(candidate_count).unwrap_or(u16::MAX),
            endorsed_candidate_count: u16::try_from(endorsed.len()).unwrap_or(u16::MAX),
            intent_certificate_digest: record.intent_certificate.decision_digest(),
            intent_certificate_signers: record
                .intent_certificate
                .certificate()
                .witnesses()
                .iter()
                .map(|witness| witness.from)
                .collect(),
            attempt_binding_digest: record.intent.attempt().digest(),
            endorsed_witness_count,
            endorsed_evidence_digest,
            key_image_binding_digest: key_image_certificate
                .map(PortableKeyImageBindingCertificate::digest)
                .unwrap_or([0; 32]),
            key_image_unsigned_transaction_digest: key_image_value
                .map(PortableFamilyKeyImageBinding::unsigned_transaction_digest)
                .unwrap_or([0; 32]),
            key_image_preprocess_set_digest: key_image_value
                .map(PortableFamilyKeyImageBinding::preprocess_set_digest)
                .unwrap_or([0; 32]),
            key_image_authorizers: key_image_certificate
                .map(PortableKeyImageBindingCertificate::authorizers)
                .unwrap_or_default(),
            key_image_authorization_quorum: key_image_certificate
                .map(|certificate| {
                    u16::try_from(certificate.attestations().len()).unwrap_or(u16::MAX)
                })
                .unwrap_or(0),
        })
    }

    pub fn plan(&self, view: u64) -> Option<&RoastViewPlan> {
        self.views
            .get(&view)
            .map(|record| &record.plan)
            .or_else(|| self.replay_tombstones.get(&view).map(|record| &record.plan))
    }

    /// Exact all-selected key-image certificate for a still-live attempt. Terminal abandonment
    /// persists this certificate in the global ledger statement before compacting round bodies.
    #[must_use]
    pub fn key_image_certificate(&self, view: u64) -> Option<&PortableKeyImageBindingCertificate> {
        self.views.get(&view).and_then(|record| record.key_image_certificate.as_ref())
    }

    /// Locate a retained exact attempt without scanning the absolute compacted prefix.
    #[must_use]
    pub fn view_for_signing_session(&self, session: SessionId) -> Option<u64> {
        self.replay_tombstones
            .iter()
            .map(|(view, record)| (*view, &record.plan))
            .chain(self.views.iter().map(|(view, record)| (*view, &record.plan)))
            .find_map(|(view, plan)| (plan.signing_session == session).then_some(view))
    }

    pub fn complete_preprocesses(
        &self,
        view: u64,
    ) -> Result<Option<Vec<SignedPreprocessContribution>>, ConsolidationRoastError> {
        self.validate()?;
        let record = self.views.get(&view).ok_or(ConsolidationRoastError::UnknownView(view))?;
        if record.preprocesses.len() != record.plan.signers.len() {
            return Ok(None);
        }
        record
            .plan
            .signers
            .iter()
            .map(|signer| {
                let body = record
                    .preprocesses
                    .get(signer)
                    .and_then(|archive| archive.body.as_deref())
                    .ok_or(ConsolidationRoastError::ContributionBodyRetired(*signer))?;
                decode_canonical(body)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    pub fn complete_shares(
        &self,
        view: u64,
    ) -> Result<Option<Vec<SignedShareContribution>>, ConsolidationRoastError> {
        self.validate()?;
        let record = self.views.get(&view).ok_or(ConsolidationRoastError::UnknownView(view))?;
        if record.key_image_certificate.is_none()
            || record.shares.len() != record.plan.signers.len()
        {
            return Ok(None);
        }
        record
            .plan
            .signers
            .iter()
            .map(|signer| {
                let body = record
                    .shares
                    .get(signer)
                    .and_then(|archive| archive.body.as_deref())
                    .ok_or(ConsolidationRoastError::ContributionBodyRetired(*signer))?;
                decode_canonical(body)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    /// Reconstruct an already certified slot or the single deterministic successor slot. The
    /// exact wire slot is the sole source of the consensus session.
    pub fn expected_slot(
        &self,
        view: u64,
    ) -> Result<ConsolidationConsensusSlot, ConsolidationRoastError> {
        if let Some(record) = self.views.get(&view) {
            return Ok(record.slot.clone());
        }
        if let Some(record) = self.replay_tombstones.get(&view) {
            return Ok(record.slot.clone());
        }
        if view == self.next_view && self.is_terminal_sealed() {
            return Err(ConsolidationRoastError::TerminalSealed);
        }
        if view != self.next_view {
            if self.compacted_prefix.as_ref().is_some_and(|prefix| view <= prefix.through_view) {
                return Err(ConsolidationRoastError::CompactedView(view));
            }
            return Err(ConsolidationRoastError::UnknownView(view));
        }
        let (previous_height, previous_sequence, previous_decision) =
            self.latest_chain_boundary().ok_or(ConsolidationRoastError::InvalidState)?;
        Ok(ConsolidationConsensusSlot::new_successor(
            self.binding.clone(),
            self.committee(),
            self.fault_bound,
            self.family_anchor,
            view,
            previous_height.checked_add(1).ok_or(ConsolidationRoastError::ViewExhausted)?,
            previous_sequence.checked_add(1).ok_or(ConsolidationRoastError::ViewExhausted)?,
            previous_decision,
        )?)
    }

    pub fn expected_plan(&self, view: u64) -> Result<RoastViewPlan, ConsolidationRoastError> {
        let slot = self.expected_slot(view)?;
        RoastViewPlan::derive(&slot, &self.committee, self.fault_bound, &self.authorization)
    }

    /// Reconstruct an already certified context or the single deterministic successor context.
    pub fn expected_context(&self, view: u64) -> Result<ConsensusContext, ConsolidationRoastError> {
        let slot = self.expected_slot(view)?;
        Ok(slot.consensus_context()?)
    }

    /// Construct the exact local nonce/share safety record only after the view's intent
    /// certificate has been verified. Parties outside the selected subset never receive a nonce
    /// authority for this view.
    pub fn new_local_attempt_safety(
        &self,
        view: u64,
    ) -> Result<ConsolidationAttemptSafety, ConsolidationRoastError> {
        self.validate()?;
        let record = self.views.get(&view).ok_or(ConsolidationRoastError::UnknownView(view))?;
        if record.plan.signers.binary_search(&self.local_party).is_err() {
            return Err(ConsolidationRoastError::LocalPartyNotSelected);
        }
        Ok(ConsolidationAttemptSafety::new(
            self.local_party,
            &record.context,
            record.intent.clone(),
            &record.intent_certificate,
        )?)
    }

    /// Exact trusted values needed to validate a persisted local safety record.
    pub fn certified_intent(
        &self,
        view: u64,
    ) -> Option<(&ConsensusContext, &ConsolidationIntent, &ConsolidationIntentCertificate)> {
        self.views
            .get(&view)
            .map(|record| (&record.context, &record.intent, &record.intent_certificate))
            .or_else(|| {
                self.replay_tombstones
                    .get(&view)
                    .map(|record| (&record.context, &record.intent, &record.intent_certificate))
            })
    }

    fn hot_attempt_archive_material(
        &self,
        view: u64,
        record: &RoastViewRecord,
    ) -> Result<RoastAttemptArchiveMaterial, ConsolidationRoastError> {
        Ok(RoastAttemptArchiveMaterial {
            slot: record.slot.clone(),
            context: record.context.clone(),
            intent: record.intent.clone(),
            intent_certificate: record.intent_certificate.clone(),
            wire_binding: self.wire_binding(view)?,
            key_image_certificate: record.key_image_certificate.clone(),
        })
    }

    /// Clone every full hot attempt proof in absolute-view order for terminal cold staging.
    ///
    /// Replay tombstones are intentionally excluded: their complete key-image certificates may
    /// already have been retired, so they must have been archived before entering that window.
    pub fn hot_attempt_archive_materials(
        &self,
    ) -> Result<Vec<RoastAttemptArchiveMaterial>, ConsolidationRoastError> {
        self.validate()?;
        self.views
            .iter()
            .map(|(view, record)| self.hot_attempt_archive_material(*view, record))
            .collect()
    }

    /// Return the sole hot attempt which certifying the next view will demote into the immutable
    /// replay-tombstone window.
    ///
    /// Superseded hot views remain live and may still acquire a key-image certificate or an
    /// endorsed candidate. Freezing any of them earlier would make a later valid contribution
    /// conflict with the immutable `(family, view)` archive entry. At the bounded hot-window
    /// boundary, `append_certified_view` demotes exactly the oldest view and rejects every new
    /// contribution to that tombstone, so that is the first safe time to archive it.
    pub fn attempts_requiring_archive_before_successor(
        &self,
    ) -> Result<Vec<RoastAttemptArchiveMaterial>, ConsolidationRoastError> {
        self.validate()?;
        if self.views.len() < MAX_HOT_ROAST_VIEWS {
            return Ok(Vec::new());
        }
        let (&view, record) =
            self.views.first_key_value().ok_or(ConsolidationRoastError::InvalidState)?;
        Ok(vec![self.hot_attempt_archive_material(view, record)?])
    }

    /// Append the next BA-certified view.  No claim is made about prior views being unable to
    /// finish; their portable contributions and candidates remain live and relayable.
    pub fn append_certified_view(
        &mut self,
        expected_context: ConsensusContext,
        expected_intent: ConsolidationIntent,
        intent_certificate: ConsolidationIntentCertificate,
        now_ms: u64,
    ) -> Result<u64, ConsolidationRoastError> {
        self.validate()?;
        if self.is_terminal_sealed() {
            return Err(ConsolidationRoastError::TerminalSealed);
        }
        if self.has_endorsed_candidate() {
            return Err(ConsolidationRoastError::CandidateAlreadyAvailable);
        }
        let view = self.next_view;
        let slot = self.expected_slot(view)?;
        slot.verify_context(&expected_context)?;
        let plan = self.expected_plan(view)?;
        intent_certificate.verify_expected(&expected_context, &expected_intent)?;
        validate_intent_for_plan(&expected_context, &expected_intent, &self.authorization, &plan)?;
        self.validate_successor_context(&expected_context)?;
        if self
            .views
            .values()
            .map(|record| &record.plan)
            .chain(self.replay_tombstones.values().map(|record| &record.plan))
            .any(|record| {
                record.signing_session == plan.signing_session
                    || record.consensus_session == plan.consensus_session
            })
        {
            return Err(ConsolidationRoastError::SessionCollision);
        }
        let local_safety = plan
            .signers
            .binary_search(&self.local_party)
            .is_ok()
            .then(|| {
                ConsolidationAttemptSafety::new(
                    self.local_party,
                    &expected_context,
                    expected_intent.clone(),
                    &intent_certificate,
                )
            })
            .transpose()?;
        self.transact(move |next| {
            let mut retire = Vec::new();
            for (old_view, record) in &next.views {
                for (phase, archive) in [
                    (RoastContributionPhase::Preprocess, &record.preprocesses),
                    (RoastContributionPhase::KeyImageBinding, &record.key_image_bindings),
                    (RoastContributionPhase::Share, &record.shares),
                ] {
                    for (origin, contribution) in archive {
                        if contribution.body.is_some()
                            && (phase != RoastContributionPhase::KeyImageBinding
                                || record.key_image_certificate.is_some())
                            && contribution_fully_acked(
                                next,
                                record,
                                phase,
                                *origin,
                                contribution.digest,
                            )
                        {
                            retire.push((*old_view, phase, *origin));
                        }
                    }
                }
            }
            for (old_view, phase, origin) in retire {
                let record = next
                    .views
                    .get_mut(&old_view)
                    .ok_or(ConsolidationRoastError::UnknownView(old_view))?;
                let contribution = match phase {
                    RoastContributionPhase::Preprocess => record.preprocesses.get_mut(&origin),
                    RoastContributionPhase::KeyImageBinding => {
                        record.key_image_bindings.get_mut(&origin)
                    }
                    RoastContributionPhase::Share => record.shares.get_mut(&origin),
                    RoastContributionPhase::Candidate => None,
                }
                .ok_or(ConsolidationRoastError::MissingContribution(origin))?;
                contribution.body = None;
            }
            next.views.insert(
                view,
                RoastViewRecord {
                    slot,
                    plan,
                    context: expected_context,
                    intent: expected_intent,
                    intent_certificate,
                    preprocesses: BTreeMap::new(),
                    key_image_bindings: BTreeMap::new(),
                    key_image_certificate: None,
                    local_safety,
                    shares: BTreeMap::new(),
                    relay_acks: BTreeSet::new(),
                    candidates: BTreeMap::new(),
                },
            );
            next.next_view = view.checked_add(1).ok_or(ConsolidationRoastError::ViewExhausted)?;
            next.compact_retained_history()?;
            next.outer_deadline_view = view;
            next.outer_deadline_unix_ms =
                roast_outer_deadline(now_ms, next.outer_base_timeout_ms, view)?;
            Ok((view, true))
        })
    }

    /// Exact wire binding for portable contributions.  `leader()` is only a deterministic relay
    /// seed; contribution signatures use broadcast envelopes and may be forwarded by any party.
    pub fn wire_binding(
        &self,
        view: u64,
    ) -> Result<ConsolidationAttemptWireBinding, ConsolidationRoastError> {
        let (intent, relay_seed) = if let Some(record) = self.views.get(&view) {
            (&record.intent, record.plan.relay_seed)
        } else if let Some(record) = self.replay_tombstones.get(&view) {
            (&record.intent, record.plan.relay_seed)
        } else if self.compacted_prefix.as_ref().is_some_and(|prefix| view <= prefix.through_view) {
            return Err(ConsolidationRoastError::CompactedView(view));
        } else {
            return Err(ConsolidationRoastError::UnknownView(view));
        };
        Ok(ConsolidationAttemptWireBinding::new(&self.authorization, intent.attempt(), relay_seed)?)
    }

    /// Verify and archive a portable preprocess before exposing it to a FROST machine.
    pub fn observe_preprocess(
        &mut self,
        view: u64,
        contribution: &SignedPreprocessContribution,
    ) -> Result<bool, ConsolidationRoastError> {
        let binding = self.wire_binding(view)?;
        contribution.verify(&self.committee, self.quic_network_id, &binding)?;
        validate_frostlass_preprocess_shape(
            contribution.sender(),
            contribution.preprocess().message(),
            self.authorization.input_count(),
        )
        .map_err(ConsolidationWireError::from)?;
        let body = canonical_body(contribution)?;
        let digest = envelope_digest(contribution.envelope())?;
        self.observe_contribution(
            view,
            RoastContributionPhase::Preprocess,
            contribution.sender(),
            digest,
            body,
        )
    }

    /// Verify and archive one proof-bearing key-image statement. A certificate exists only when
    /// every signer selected for this exact view attests the same complete value. Statements for
    /// different values remain attributable evidence but can never unlock signature shares.
    pub fn observe_key_image_binding(
        &mut self,
        view: u64,
        attestation: &PortableKeyImageBindingAttestation,
    ) -> Result<bool, ConsolidationRoastError> {
        self.validate()?;
        let binding = self.wire_binding(view)?;
        attestation.verify(&self.committee, self.quic_network_id, &binding)?;
        let origin = attestation.origin();
        let body = canonical_body(attestation)?;
        let digest = envelope_digest(attestation.envelope())?;
        if let Some(record) = self.replay_tombstones.get(&view) {
            return match record.key_image_bindings.get(&origin) {
                Some(existing) if *existing == digest => Ok(false),
                Some(_) => Err(ConsolidationRoastError::ContributionEquivocation(origin)),
                None => Err(ConsolidationRoastError::SupersededView(view)),
            };
        }
        let record = self.views.get(&view).ok_or(ConsolidationRoastError::UnknownView(view))?;
        if record.plan.signers.binary_search(&origin).is_err() {
            return Err(ConsolidationRoastError::UnexpectedContributor(origin));
        }
        match record.key_image_bindings.get(&origin) {
            Some(existing) if existing.digest == digest => {
                if existing.body.as_deref().is_some_and(|known| known != body) {
                    return Err(ConsolidationRoastError::ContributionEquivocation(origin));
                }
                return Ok(false);
            }
            Some(_) => return Err(ConsolidationRoastError::ContributionEquivocation(origin)),
            None => {}
        }
        self.transact(move |next| {
            next.views
                .get_mut(&view)
                .ok_or(ConsolidationRoastError::UnknownView(view))?
                .key_image_bindings
                .insert(origin, ArchivedContribution { digest, body: Some(body) });
            let certificate = derive_key_image_certificate(next, view)?;
            next.views
                .get_mut(&view)
                .ok_or(ConsolidationRoastError::UnknownView(view))?
                .key_image_certificate = certificate;
            Ok((true, true))
        })
    }

    /// Exact all-selected certificate for a view, if every selected signer attested one value.
    pub fn key_image_binding_certificate(
        &self,
        view: u64,
    ) -> Result<Option<&PortableKeyImageBindingCertificate>, ConsolidationRoastError> {
        self.validate()?;
        Ok(self
            .views
            .get(&view)
            .ok_or(ConsolidationRoastError::UnknownView(view))?
            .key_image_certificate
            .as_ref())
    }

    #[must_use]
    pub fn local_safety_phase(&self, view: u64) -> Option<AttemptSafetyPhase> {
        self.views
            .get(&view)
            .and_then(|record| record.local_safety.as_ref())
            .map(ConsolidationAttemptSafety::phase)
    }

    /// Cross the nonce-release fence in the same authenticated snapshot as the worker and
    /// coordinator release. Parties outside this view's subset have no local safety record.
    pub fn mark_local_nonce_released(
        &mut self,
        view: u64,
    ) -> Result<bool, ConsolidationRoastError> {
        self.validate()?;
        if self
            .views
            .get(&view)
            .ok_or(ConsolidationRoastError::UnknownView(view))?
            .plan
            .signers
            .binary_search(&self.local_party)
            .is_err()
        {
            return Err(ConsolidationRoastError::LocalPartyNotSelected);
        }
        self.transact(|next| {
            let record =
                next.views.get_mut(&view).ok_or(ConsolidationRoastError::UnknownView(view))?;
            let changed = record
                .local_safety
                .as_mut()
                .ok_or(ConsolidationRoastError::InvalidState)?
                .mark_nonce_released(&record.context, &record.intent, &record.intent_certificate)?;
            Ok((changed, changed))
        })
    }

    /// Stage an exact local share behind the durable ShareExposed boundary.
    pub fn prepare_local_share_exposure(
        &mut self,
        view: u64,
        payload: Vec<u8>,
    ) -> Result<PendingShareExposure, ConsolidationRoastError> {
        self.validate()?;
        let mut successor = self.clone();
        let record =
            successor.views.get_mut(&view).ok_or(ConsolidationRoastError::UnknownView(view))?;
        let pending = record
            .local_safety
            .as_mut()
            .ok_or(ConsolidationRoastError::LocalPartyNotSelected)?
            .prepare_share_exposure(
                &record.context,
                &record.intent,
                &record.intent_certificate,
                payload,
            )?;
        successor.advance()?;
        *self = successor;
        Ok(pending)
    }

    /// Irreversibly fence this party's share path and stage its unexposed witness behind durable
    /// ROAST readback. Parties outside the selected signer set have no share to fence and return
    /// `LocalPartyNotSelected`.
    pub fn prepare_local_share_unexposed(
        &mut self,
        view: u64,
        abandonment_context: &ConsensusContext,
        identity: &Identity,
    ) -> Result<PendingShareUnexposed, ConsolidationRoastError> {
        self.validate()?;
        let mut successor = self.clone();
        let record =
            successor.views.get_mut(&view).ok_or(ConsolidationRoastError::UnknownView(view))?;
        let prior_revision = record
            .local_safety
            .as_ref()
            .ok_or(ConsolidationRoastError::LocalPartyNotSelected)?
            .revision();
        let pending = record
            .local_safety
            .as_mut()
            .ok_or(ConsolidationRoastError::LocalPartyNotSelected)?
            .prepare_share_unexposed(
                &record.context,
                &record.intent,
                &record.intent_certificate,
                abandonment_context,
                identity,
            )?;
        if record.local_safety.as_ref().is_some_and(|safety| safety.revision() != prior_revision) {
            successor.advance()?;
        }
        *self = successor;
        Ok(pending)
    }

    pub fn local_safety_bytes(
        &self,
        view: u64,
    ) -> Result<Option<Vec<u8>>, ConsolidationRoastError> {
        self.validate()?;
        self.views
            .get(&view)
            .ok_or(ConsolidationRoastError::UnknownView(view))?
            .local_safety
            .as_ref()
            .map(ConsolidationAttemptSafety::encode)
            .transpose()
            .map_err(Into::into)
    }

    /// Verify and archive a portable signature share for all-to-all availability.
    pub fn observe_share(
        &mut self,
        view: u64,
        contribution: &SignedShareContribution,
    ) -> Result<bool, ConsolidationRoastError> {
        self.validate()?;
        let has_key_image_certificate = self
            .views
            .get(&view)
            .and_then(|record| record.key_image_certificate.as_ref())
            .is_some()
            || self
                .replay_tombstones
                .get(&view)
                .is_some_and(|record| record.key_image_certificate.is_some());
        if !has_key_image_certificate {
            return if self
                .compacted_prefix
                .as_ref()
                .is_some_and(|prefix| view <= prefix.through_view)
            {
                Err(ConsolidationRoastError::CompactedView(view))
            } else if self.views.contains_key(&view) || self.replay_tombstones.contains_key(&view) {
                Err(ConsolidationRoastError::MissingKeyImageCertificate(view))
            } else {
                Err(ConsolidationRoastError::UnknownView(view))
            };
        }
        let binding = self.wire_binding(view)?;
        contribution.verify(&self.committee, self.quic_network_id, &binding)?;
        let body = canonical_body(contribution)?;
        let digest = envelope_digest(contribution.envelope())?;
        self.observe_contribution(
            view,
            RoastContributionPhase::Share,
            contribution.sender(),
            digest,
            body,
        )
    }

    fn observe_contribution(
        &mut self,
        view: u64,
        phase: RoastContributionPhase,
        sender: PartyId,
        digest: [u8; 32],
        body: Vec<u8>,
    ) -> Result<bool, ConsolidationRoastError> {
        self.validate()?;
        if phase == RoastContributionPhase::Candidate
            || digest == [0; 32]
            || body.is_empty()
            || body.len() > MAX_CONSOLIDATION_WIRE_BYTES
        {
            return Err(ConsolidationRoastError::InvalidContribution);
        }
        if let Some(record) = self.replay_tombstones.get(&view) {
            let known = match phase {
                RoastContributionPhase::Preprocess => record.preprocesses.get(&sender),
                RoastContributionPhase::KeyImageBinding => record.key_image_bindings.get(&sender),
                RoastContributionPhase::Share => record.shares.get(&sender),
                RoastContributionPhase::Candidate => None,
            };
            return match known {
                Some(existing) if *existing == digest => Ok(false),
                Some(_) => Err(ConsolidationRoastError::ContributionEquivocation(sender)),
                None => Err(ConsolidationRoastError::SupersededView(view)),
            };
        }
        let record = self.views.get(&view).ok_or(ConsolidationRoastError::UnknownView(view))?;
        if record.plan.signers.binary_search(&sender).is_err() {
            return Err(ConsolidationRoastError::UnexpectedContributor(sender));
        }
        let archive = match phase {
            RoastContributionPhase::Preprocess => &record.preprocesses,
            RoastContributionPhase::KeyImageBinding => &record.key_image_bindings,
            RoastContributionPhase::Share => &record.shares,
            RoastContributionPhase::Candidate => {
                return Err(ConsolidationRoastError::InvalidContribution);
            }
        };
        match archive.get(&sender) {
            Some(existing) if existing.digest == digest => {
                if existing.body.as_deref().is_some_and(|known| known != body) {
                    return Err(ConsolidationRoastError::ContributionEquivocation(sender));
                }
                return Ok(false);
            }
            Some(_) => return Err(ConsolidationRoastError::ContributionEquivocation(sender)),
            None => {}
        }
        if phase == RoastContributionPhase::Preprocess {
            let per_contribution = maximum_signed_preprocess_body_bytes(self)?;
            let retained = retained_preprocess_body_bytes(record)?;
            let actual = retained.checked_add(body.len()).ok_or(
                ConsolidationRoastError::PreprocessRetentionBudgetExceeded {
                    view,
                    actual: usize::MAX,
                    maximum: preprocess_retained_byte_budget(self, record)?,
                },
            )?;
            let maximum = preprocess_retained_byte_budget(self, record)?;
            if body.len() > per_contribution || actual > maximum {
                return Err(ConsolidationRoastError::PreprocessRetentionBudgetExceeded {
                    view,
                    actual,
                    maximum,
                });
            }
        }
        self.transact(move |next| {
            let record =
                next.views.get_mut(&view).ok_or(ConsolidationRoastError::UnknownView(view))?;
            let archive = match phase {
                RoastContributionPhase::Preprocess => &mut record.preprocesses,
                RoastContributionPhase::KeyImageBinding => &mut record.key_image_bindings,
                RoastContributionPhase::Share => &mut record.shares,
                RoastContributionPhase::Candidate => {
                    return Err(ConsolidationRoastError::InvalidContribution);
                }
            };
            archive.insert(sender, ArchivedContribution { digest, body: Some(body) });
            Ok((true, true))
        })
    }

    /// Return every peer to which this party has not durably relayed the exact contribution.
    pub fn pending_relays(
        &self,
        view: u64,
        phase: RoastContributionPhase,
        origin: PartyId,
    ) -> Result<Vec<RoastRelayId>, ConsolidationRoastError> {
        self.validate()?;
        if self.replay_tombstones.contains_key(&view) {
            return Ok(Vec::new());
        }
        // A certified successor fixes a fresh attempt and makes incomplete round-one/two traffic
        // from this attempt irrelevant for liveness. Keep its sole canonical body/digest in the
        // reducer until ACK or ordinary hot-history compaction (no false ACK), but do not recreate
        // recipient-specific relay copies. A completed candidate remains relayable because it may
        // already be the transaction observed on chain.
        if phase != RoastContributionPhase::Candidate
            && view.checked_add(1).is_some_and(|successor| successor < self.next_view)
        {
            return Ok(Vec::new());
        }
        let record = self.views.get(&view).ok_or(ConsolidationRoastError::UnknownView(view))?;
        let contribution = contribution_archive(record, phase, origin)?;
        if contribution.body.is_none() {
            return Ok(Vec::new());
        }
        let digest = contribution.digest;
        let attempt = record.intent.attempt();
        let mut peers = self.committee.members.iter().map(|member| member.id).collect::<Vec<_>>();
        peers.sort_unstable();
        Ok(peers
            .into_iter()
            .filter(|recipient| *recipient != self.local_party && *recipient != origin)
            .map(|recipient| RoastRelayId {
                version: ROAST_RELAY_VERSION,
                family: self.family,
                view,
                attempt: attempt.digest(),
                session: attempt.session(),
                phase,
                origin,
                recipient,
                contribution: digest,
            })
            .filter(|relay| !record.relay_acks.contains(relay))
            .collect())
    }

    /// Exact canonical portable body for one pending relay. Digest-only superseded tombstones are
    /// intentionally not relayable.
    pub fn relay_body(&self, relay: &RoastRelayId) -> Result<&[u8], ConsolidationRoastError> {
        self.validate()?;
        self.validate_relay(relay)?;
        if self.replay_tombstones.contains_key(&relay.view) {
            return Err(ConsolidationRoastError::ContributionBodyRetired(relay.origin));
        }
        let record =
            self.views.get(&relay.view).ok_or(ConsolidationRoastError::UnknownView(relay.view))?;
        contribution_archive(record, relay.phase, relay.origin)?
            .body
            .as_deref()
            .ok_or(ConsolidationRoastError::ContributionBodyRetired(relay.origin))
    }

    /// Durably retire only the exact relay entry acknowledged by its authenticated recipient.
    pub fn acknowledge_relay(
        &mut self,
        authenticated_recipient: PartyId,
        relay: RoastRelayId,
    ) -> Result<bool, ConsolidationRoastError> {
        self.validate()?;
        if authenticated_recipient != relay.recipient {
            return Err(ConsolidationRoastError::InvalidRelay);
        }
        self.validate_relay(&relay)?;
        if self.replay_tombstones.contains_key(&relay.view) {
            return Ok(false);
        }
        let record =
            self.views.get(&relay.view).ok_or(ConsolidationRoastError::UnknownView(relay.view))?;
        if record.relay_acks.contains(&relay) {
            return Ok(false);
        }
        self.transact(move |next| {
            next.views
                .get_mut(&relay.view)
                .ok_or(ConsolidationRoastError::UnknownView(relay.view))?
                .relay_acks
                .insert(relay);
            Ok((true, true))
        })
    }

    /// Verify and retain a route-independent completed transaction attestation.
    ///
    /// A single Byzantine attestation does not stop view rotation.  A candidate becomes endorsed
    /// only after `f+1` distinct selected signers attest byte-identically, guaranteeing at least
    /// one honest party independently completed and validated it.
    pub fn observe_candidate(
        &mut self,
        view: u64,
        attestation: &PortableSignedTransactionAttestation,
    ) -> Result<bool, ConsolidationRoastError> {
        self.validate()?;
        let has_key_image_certificate = self
            .views
            .get(&view)
            .and_then(|record| record.key_image_certificate.as_ref())
            .is_some()
            || self
                .replay_tombstones
                .get(&view)
                .is_some_and(|record| record.key_image_certificate.is_some());
        if !has_key_image_certificate {
            return if self
                .compacted_prefix
                .as_ref()
                .is_some_and(|prefix| view <= prefix.through_view)
            {
                Err(ConsolidationRoastError::CompactedView(view))
            } else if self.views.contains_key(&view) || self.replay_tombstones.contains_key(&view) {
                Err(ConsolidationRoastError::MissingKeyImageCertificate(view))
            } else {
                Err(ConsolidationRoastError::UnknownView(view))
            };
        }
        let binding = self.wire_binding(view)?;
        attestation.verify(&self.committee, self.quic_network_id, &binding)?;
        let origin = attestation.origin();
        let signed = attestation.signed().binding();
        let transaction = signed.transaction();
        let body = canonical_body(attestation)?;
        let digest = envelope_digest(attestation.envelope())?;
        if let Some(record) = self.replay_tombstones.get(&view) {
            return match record.candidates.get(&origin) {
                Some((known_transaction, known_digest))
                    if *known_transaction == transaction && *known_digest == digest =>
                {
                    Ok(false)
                }
                Some(_) => Err(ConsolidationRoastError::CandidateOriginEquivocation(origin)),
                None => Err(ConsolidationRoastError::SupersededView(view)),
            };
        }
        let record = self.views.get(&view).ok_or(ConsolidationRoastError::UnknownView(view))?;
        for (known_transaction, candidate) in &record.candidates {
            if let Some(existing) = candidate.origins.get(&origin) {
                if *known_transaction == transaction && candidate.signed == signed {
                    return if existing.digest == digest
                        && existing.body.as_deref() == Some(body.as_slice())
                    {
                        Ok(false)
                    } else {
                        Err(ConsolidationRoastError::ContributionEquivocation(origin))
                    };
                }
                return Err(ConsolidationRoastError::CandidateOriginEquivocation(origin));
            }
        }
        if record.candidates.get(&transaction).is_some_and(|candidate| candidate.signed != signed) {
            return Err(ConsolidationRoastError::CandidateEquivocation);
        }
        self.transact(move |next| {
            let candidate = next
                .views
                .get_mut(&view)
                .ok_or(ConsolidationRoastError::UnknownView(view))?
                .candidates
                .entry(transaction)
                .or_insert_with(|| CandidateArchive { signed, origins: BTreeMap::new() });
            candidate.origins.insert(origin, ArchivedContribution { digest, body: Some(body) });
            Ok((true, true))
        })
    }

    /// Endorsed candidates in deterministic `(view, txid)` order.  All must remain available for
    /// broadcast/rebroadcast until one reaches the configured confirmation depth.
    pub fn endorsed_candidates(&self) -> Vec<(u64, SignedTransactionBinding)> {
        let required = usize::from(self.fault_bound).saturating_add(1);
        self.views
            .iter()
            .flat_map(|(view, record)| {
                record
                    .candidates
                    .values()
                    .filter(move |candidate| candidate.origins.len() >= required)
                    .map(move |candidate| (*view, candidate.signed))
            })
            .collect()
    }

    /// One exact portable full-body witness for each endorsed candidate, in `(view, txid)` order.
    pub fn endorsed_candidate_attestations(
        &self,
    ) -> Result<Vec<(u64, PortableSignedTransactionAttestation)>, ConsolidationRoastError> {
        self.validate()?;
        let required = usize::from(self.fault_bound).saturating_add(1);
        self.views
            .iter()
            .flat_map(|(view, record)| {
                record
                    .candidates
                    .values()
                    .filter(move |candidate| candidate.origins.len() >= required)
                    .map(move |candidate| (*view, candidate))
            })
            .map(|(view, candidate)| {
                let body = candidate
                    .origins
                    .first_key_value()
                    .and_then(|(_, archive)| archive.body.as_deref())
                    .ok_or(ConsolidationRoastError::InvalidState)?;
                Ok((view, decode_canonical(body)?))
            })
            .collect()
    }

    /// Canonical self-contained completion witnesses in `(view, txid)` order.
    ///
    /// A main-ledger BA voter must not depend on having received candidate gossip first.  Keep
    /// exactly the smallest attributable `f + 1` endorsement set (ordered by origin) together
    /// with the all-selected key-image certificate for the producing view.  At least one of those
    /// endorsements is honest, while the key-image certificate proves every selected signer
    /// authorized the same proof-verified preprocess family before any share was released.
    pub fn endorsed_candidate_completion_evidence(
        &self,
    ) -> Result<
        Vec<(u64, PortableKeyImageBindingCertificate, Vec<PortableSignedTransactionAttestation>)>,
        ConsolidationRoastError,
    > {
        self.validate()?;
        let required = usize::from(self.fault_bound).saturating_add(1);
        self.views
            .iter()
            .flat_map(|(view, record)| {
                record
                    .candidates
                    .values()
                    .filter(move |candidate| candidate.origins.len() >= required)
                    .map(move |candidate| (*view, record, candidate))
            })
            .map(|(view, record, candidate)| {
                let certificate = record
                    .key_image_certificate
                    .clone()
                    .ok_or(ConsolidationRoastError::InvalidState)?;
                let attestations = candidate
                    .origins
                    .iter()
                    .take(required)
                    .map(|(_, archive)| {
                        archive
                            .body
                            .as_deref()
                            .ok_or(ConsolidationRoastError::InvalidState)
                            .and_then(decode_canonical)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((view, certificate, attestations))
            })
            .collect()
    }

    #[must_use]
    pub fn has_endorsed_candidate(&self) -> bool {
        !self.endorsed_candidates().is_empty()
    }

    /// Canonical authenticated-storage representation.
    pub fn encode(&self) -> Result<Vec<u8>, ConsolidationRoastError> {
        self.validate()?;
        let bytes =
            postcard::to_allocvec(self).map_err(|_| ConsolidationRoastError::Serialization)?;
        if bytes.len() > MAX_ROAST_STATE_BYTES {
            return Err(ConsolidationRoastError::StateTooLarge {
                actual: bytes.len(),
                maximum: MAX_ROAST_STATE_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Restore and compare every trusted deployment/family dimension.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        bytes: &[u8],
        expected_local_party: PartyId,
        expected_quic_network_id: [u8; 32],
        expected_committee: &Committee,
        expected_fault_bound: u16,
        expected_authorization: &TransactionAuthorization,
        expected_genesis_slot: &ConsolidationConsensusSlot,
        expected_genesis_context: &ConsensusContext,
        expected_intents: &[ConsolidationIntent],
    ) -> Result<Self, ConsolidationRoastError> {
        let state = Self::decode_authenticated_snapshot(bytes)?;
        if state.local_party != expected_local_party
            || state.quic_network_id != expected_quic_network_id
            || &state.committee != expected_committee
            || state.fault_bound != expected_fault_bound
            || &state.authorization != expected_authorization
            || state.binding != *expected_genesis_context.binding()
            || state.family_anchor != expected_genesis_slot.digest()
        {
            return Err(ConsolidationRoastError::WrongFamily);
        }
        if &state.bootstrap.slot != expected_genesis_slot
            || &state.bootstrap.context != expected_genesis_context
            || expected_intents.len()
                != state.replay_tombstones.len().saturating_add(state.views.len())
            || state
                .replay_tombstones
                .values()
                .map(|record| &record.intent)
                .chain(state.views.values().map(|record| &record.intent))
                .zip(expected_intents)
                .any(|(record, expected)| record != expected)
        {
            return Err(ConsolidationRoastError::WrongExpectedIntentChain);
        }
        Ok(state)
    }

    /// Decode a reducer from an already authenticated local snapshot. New ingress must use
    /// [`Self::new`] or [`Self::restore`] with independently reconstructed worker intents; this
    /// narrower helper exists so the enclosing encrypted snapshot can re-open its own previously
    /// validated reducer without treating the network as a trust source.
    pub fn decode_authenticated_snapshot(bytes: &[u8]) -> Result<Self, ConsolidationRoastError> {
        if bytes.len() > MAX_ROAST_STATE_BYTES {
            return Err(ConsolidationRoastError::StateTooLarge {
                actual: bytes.len(),
                maximum: MAX_ROAST_STATE_BYTES,
            });
        }
        let (state, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| ConsolidationRoastError::Serialization)?;
        if !trailing.is_empty() {
            return Err(ConsolidationRoastError::TrailingBytes(trailing.len()));
        }
        if postcard::to_allocvec(&state).map_err(|_| ConsolidationRoastError::Serialization)?
            != bytes
        {
            return Err(ConsolidationRoastError::NonCanonicalEncoding);
        }
        state.validate()?;
        Ok(state)
    }

    fn latest_chain_boundary(&self) -> Option<(u64, u64, [u8; 32])> {
        self.views
            .last_key_value()
            .map(|(_, record)| {
                (
                    record.context.height(),
                    record.context.sequence(),
                    record.intent_certificate.decision_digest(),
                )
            })
            .or_else(|| {
                self.replay_tombstones.last_key_value().map(|(_, record)| {
                    (
                        record.context.height(),
                        record.context.sequence(),
                        record.intent_certificate.decision_digest(),
                    )
                })
            })
            .or_else(|| {
                self.compacted_prefix
                    .as_ref()
                    .map(|prefix| (prefix.ledger_height, prefix.ledger_sequence, prefix.decision))
            })
    }

    /// Move only superseded records across the bounded full-body and exact-replay windows.
    fn compact_retained_history(&mut self) -> Result<(), ConsolidationRoastError> {
        while self.views.len() > MAX_HOT_ROAST_VIEWS {
            let oldest = *self
                .views
                .first_key_value()
                .map(|(view, _)| view)
                .ok_or(ConsolidationRoastError::InvalidState)?;
            let record = self.views.remove(&oldest).ok_or(ConsolidationRoastError::InvalidState)?;
            if record.candidates.values().any(|candidate| {
                candidate.origins.len() >= usize::from(self.fault_bound).saturating_add(1)
            }) {
                return Err(ConsolidationRoastError::CandidateAlreadyAvailable);
            }
            let tombstone = RoastViewReplayTombstone::from_record(record)?;
            if self.replay_tombstones.insert(oldest, tombstone).is_some() {
                return Err(ConsolidationRoastError::InvalidState);
            }
        }
        while self.replay_tombstones.len() > MAX_ROAST_REPLAY_TOMBSTONES {
            let oldest = *self
                .replay_tombstones
                .first_key_value()
                .map(|(view, _)| view)
                .ok_or(ConsolidationRoastError::InvalidState)?;
            let tombstone = self
                .replay_tombstones
                .remove(&oldest)
                .ok_or(ConsolidationRoastError::InvalidState)?;
            self.compacted_prefix = Some(RoastCompactedPrefix::extend(
                self.compacted_prefix.clone(),
                oldest,
                &tombstone,
            )?);
        }
        Ok(())
    }

    fn validate_successor_context(
        &self,
        context: &ConsensusContext,
    ) -> Result<(), ConsolidationRoastError> {
        let (_, previous) =
            self.views.last_key_value().ok_or(ConsolidationRoastError::InvalidState)?;
        let previous_height = previous.context.height();
        let previous_sequence = previous.context.sequence();
        let previous_decision = previous.intent_certificate.decision_digest();
        if context.binding() != &self.binding
            || context.committee() != &self.committee
            || context.fault_bound() != self.fault_bound
            || context.height()
                != previous_height.checked_add(1).ok_or(ConsolidationRoastError::ViewExhausted)?
            || context.sequence()
                != previous_sequence.checked_add(1).ok_or(ConsolidationRoastError::ViewExhausted)?
            || context.previous() != previous_decision
        {
            return Err(ConsolidationRoastError::InvalidViewChain);
        }
        Ok(())
    }

    fn validate_relay(&self, relay: &RoastRelayId) -> Result<(), ConsolidationRoastError> {
        let (attempt, contribution) = if let Some(record) = self.views.get(&relay.view) {
            (record.intent.attempt(), contribution_digest(record, relay.phase, relay.origin)?)
        } else if let Some(record) = self.replay_tombstones.get(&relay.view) {
            let contribution = match relay.phase {
                RoastContributionPhase::Preprocess => record.preprocesses.get(&relay.origin),
                RoastContributionPhase::KeyImageBinding => {
                    record.key_image_bindings.get(&relay.origin)
                }
                RoastContributionPhase::Share => record.shares.get(&relay.origin),
                RoastContributionPhase::Candidate => {
                    record.candidates.get(&relay.origin).map(|(_, digest)| digest)
                }
            }
            .copied()
            .ok_or(ConsolidationRoastError::MissingContribution(relay.origin))?;
            (record.intent.attempt(), contribution)
        } else if self
            .compacted_prefix
            .as_ref()
            .is_some_and(|prefix| relay.view <= prefix.through_view)
        {
            return Err(ConsolidationRoastError::CompactedView(relay.view));
        } else {
            return Err(ConsolidationRoastError::UnknownView(relay.view));
        };
        if relay.version != ROAST_RELAY_VERSION
            || relay.family != self.family
            || relay.attempt != attempt.digest()
            || relay.session != attempt.session()
            || relay.recipient == self.local_party
            || relay.recipient == relay.origin
            || self.committee.member(relay.recipient).is_err()
            || contribution != relay.contribution
        {
            return Err(ConsolidationRoastError::InvalidRelay);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConsolidationRoastError> {
        let terminal_seals = usize::from(self.completion_seal.is_some())
            .saturating_add(usize::from(self.abandonment_seal.is_some()));
        if self.version != ROAST_STATE_VERSION
            || self.quic_network_id == [0; 32]
            || self.quic_network_id != self.binding.network
            || terminal_seals > 1
            || (self.views.is_empty() != (terminal_seals == 1))
            || self.views.len() > MAX_HOT_ROAST_VIEWS
            || self.replay_tombstones.len() > MAX_ROAST_REPLAY_TOMBSTONES
            || self.next_view == 0
            || self.outer_base_timeout_ms == 0
            || self.outer_deadline_unix_ms == 0
            || self.outer_deadline_view.checked_add(1) != Some(self.next_view)
        {
            return Err(ConsolidationRoastError::InvalidState);
        }
        self.committee.validate_async_security_with_faults(self.fault_bound)?;
        self.committee.member(self.local_party)?;
        self.authorization.validate()?;
        let bootstrap_plan = RoastViewPlan::derive(
            &self.bootstrap.slot,
            &self.committee,
            self.fault_bound,
            &self.authorization,
        )?;
        validate_view_core(
            self,
            0,
            &self.bootstrap.slot,
            &bootstrap_plan,
            &self.bootstrap.context,
            &self.bootstrap.intent,
            &self.bootstrap.certificate,
        )?;
        if self.binding.application.as_slice() != CONSOLIDATION_INTENT_APPLICATION
            || self.binding.wallet != self.authorization.wallet_id().0
            || self.bootstrap.slot.roast_view() != 0
            || self.family_anchor != self.bootstrap.slot.digest()
            || self.family
                != deterministic_roast_family_digest(
                    &self.binding,
                    &self.committee,
                    self.fault_bound,
                    &self.authorization,
                    self.family_anchor,
                )
        {
            return Err(ConsolidationRoastError::WrongFamily);
        }
        if let Some(seal) = &self.completion_seal {
            let required = usize::from(self.fault_bound).saturating_add(1);
            let endorsed = self.replay_tombstones.get(&seal.completed_view).is_some_and(|record| {
                let mut counts = BTreeMap::<[u8; 32], usize>::new();
                for (transaction, _) in record.candidates.values() {
                    *counts.entry(*transaction).or_default() += 1;
                }
                counts.into_values().any(|count| count >= required)
            });
            if seal.statement == [0; 32]
                || seal.evidence == [0; 32]
                || seal.completed_view >= self.next_view
                || seal.public.view != seal.completed_view
                || seal.prefix.family != self.family
                || seal.prefix.family_anchor != self.family_anchor
                || seal.prefix.closed_through_attempt != self.next_view
                || seal.prefix.closed_through_view.checked_add(1)
                    != Some(seal.prefix.closed_through_attempt)
                || seal.prefix.accumulator == [0; 32]
                || !endorsed
            {
                return Err(ConsolidationRoastError::InvalidCompletionSeal);
            }
        }
        if let Some(seal) = &self.abandonment_seal {
            if seal.statement == [0; 32]
                || seal.evidence == [0; 32]
                || seal.abandoned_view >= self.next_view
                || seal.abandoned_view != seal.prefix.closed_through_view
                || seal.prefix.closed_through_attempt != self.next_view
                || seal.prefix.family != self.family
                || seal.prefix.family_anchor != self.family_anchor
                || seal.prefix.accumulator == [0; 32]
                || seal.public.view >= self.next_view
                || !self.replay_tombstones.contains_key(&seal.abandoned_view)
            {
                return Err(ConsolidationRoastError::InvalidAbandonmentSeal);
            }
        }

        let mut expected_view = self.compacted_prefix.as_ref().map_or(Ok(0), |prefix| {
            if prefix.frontier.root().is_err()
                || prefix.decision == [0; 32]
                || prefix.through_view >= self.next_view
                || prefix.frontier.leaf_count() != prefix.through_view.saturating_add(1)
            {
                return Err(ConsolidationRoastError::InvalidState);
            }
            prefix.through_view.checked_add(1).ok_or(ConsolidationRoastError::InvalidState)
        })?;
        let mut previous = self
            .compacted_prefix
            .as_ref()
            .map(|prefix| (prefix.ledger_height, prefix.ledger_sequence, prefix.decision));
        let mut signing_sessions = BTreeSet::new();
        let mut consensus_sessions = BTreeSet::new();
        for (view, record) in &self.replay_tombstones {
            if *view != expected_view || record.digest != record.expected_digest()? {
                return Err(ConsolidationRoastError::InvalidState);
            }
            validate_view_core(
                self,
                *view,
                &record.slot,
                &record.plan,
                &record.context,
                &record.intent,
                &record.intent_certificate,
            )?;
            validate_view_link(*view, &record.slot, &record.context, previous)?;
            validate_replay_tombstone(self, record)?;
            if !signing_sessions.insert(record.plan.signing_session)
                || !consensus_sessions.insert(record.plan.consensus_session)
                || signing_sessions.contains(&record.plan.consensus_session)
                || consensus_sessions.contains(&record.plan.signing_session)
            {
                return Err(ConsolidationRoastError::SessionCollision);
            }
            if *view == 0
                && (record.slot != self.bootstrap.slot
                    || record.context != self.bootstrap.context
                    || record.intent != self.bootstrap.intent
                    || record.intent_certificate != self.bootstrap.certificate)
            {
                return Err(ConsolidationRoastError::InvalidState);
            }
            previous = Some((
                record.context.height(),
                record.context.sequence(),
                record.intent_certificate.decision_digest(),
            ));
            expected_view =
                expected_view.checked_add(1).ok_or(ConsolidationRoastError::InvalidState)?;
        }
        for (view, record) in &self.views {
            if *view != expected_view {
                return Err(ConsolidationRoastError::InvalidState);
            }
            validate_view_core(
                self,
                *view,
                &record.slot,
                &record.plan,
                &record.context,
                &record.intent,
                &record.intent_certificate,
            )?;
            validate_view_link(*view, &record.slot, &record.context, previous)?;
            if !signing_sessions.insert(record.plan.signing_session)
                || !consensus_sessions.insert(record.plan.consensus_session)
                || signing_sessions.contains(&record.plan.consensus_session)
                || consensus_sessions.contains(&record.plan.signing_session)
            {
                return Err(ConsolidationRoastError::SessionCollision);
            }
            if *view == 0
                && (record.slot != self.bootstrap.slot
                    || record.context != self.bootstrap.context
                    || record.intent != self.bootstrap.intent
                    || record.intent_certificate != self.bootstrap.certificate)
            {
                return Err(ConsolidationRoastError::InvalidState);
            }
            validate_record(self, record)?;
            previous = Some((
                record.context.height(),
                record.context.sequence(),
                record.intent_certificate.decision_digest(),
            ));
            expected_view =
                expected_view.checked_add(1).ok_or(ConsolidationRoastError::InvalidState)?;
        }
        if expected_view != self.next_view {
            return Err(ConsolidationRoastError::InvalidState);
        }
        if let Some(seal) = &self.abandonment_seal
            && seal.prefix != self.expected_attempt_prefix_seal()?
        {
            return Err(ConsolidationRoastError::InvalidAbandonmentSeal);
        }
        if let Some(seal) = &self.completion_seal
            && seal.prefix != self.expected_attempt_prefix_seal()?
        {
            return Err(ConsolidationRoastError::InvalidCompletionSeal);
        }
        if self.transition != self.expected_transition()? {
            return Err(ConsolidationRoastError::InvalidState);
        }
        Ok(())
    }

    fn advance(&mut self) -> Result<(), ConsolidationRoastError> {
        self.revision =
            self.revision.checked_add(1).ok_or(ConsolidationRoastError::RevisionExhausted)?;
        self.transition = self.expected_transition()?;
        self.validate()
    }

    /// Apply one reducer mutation to a clone and publish it only after the successor transition
    /// hash and all semantic invariants validate.  Any error leaves `self` byte-identical.
    fn transact<T, F>(&mut self, mutation: F) -> Result<T, ConsolidationRoastError>
    where
        F: FnOnce(&mut Self) -> Result<(T, bool), ConsolidationRoastError>,
    {
        self.validate()?;
        let mut successor = self.clone();
        let (output, changed) = mutation(&mut successor)?;
        if changed {
            successor.advance()?;
            *self = successor;
        }
        Ok(output)
    }

    fn expected_transition(&self) -> Result<[u8; 32], ConsolidationRoastError> {
        let mut canonical = self.clone();
        canonical.transition = [0; 32];
        let bytes = postcard::to_allocvec(&canonical)
            .map_err(|_| ConsolidationRoastError::Serialization)?;
        if bytes.len() > MAX_ROAST_STATE_BYTES {
            return Err(ConsolidationRoastError::StateTooLarge {
                actual: bytes.len(),
                maximum: MAX_ROAST_STATE_BYTES,
            });
        }
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/consolidation-roast/state/v1");
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_view_core(
    state: &ConsolidationRoast,
    view: u64,
    slot: &ConsolidationConsensusSlot,
    plan: &RoastViewPlan,
    context: &ConsensusContext,
    intent: &ConsolidationIntent,
    certificate: &ConsolidationIntentCertificate,
) -> Result<(), ConsolidationRoastError> {
    slot.verify_context(context)?;
    if slot.roast_view() != view
        || slot.binding() != &state.binding
        || slot.committee_digest() != state.committee.digest()
        || slot.fault_bound() != state.fault_bound
        || slot.family_anchor() != state.family_anchor
        || *plan
            != RoastViewPlan::derive(
                slot,
                &state.committee,
                state.fault_bound,
                &state.authorization,
            )?
    {
        return Err(ConsolidationRoastError::InvalidViewPlan);
    }
    validate_intent_for_plan(context, intent, &state.authorization, plan)?;
    certificate.verify_expected(context, intent)?;
    Ok(())
}

fn validate_view_link(
    view: u64,
    slot: &ConsolidationConsensusSlot,
    context: &ConsensusContext,
    previous: Option<(u64, u64, [u8; 32])>,
) -> Result<(), ConsolidationRoastError> {
    let Some((height, sequence, decision)) = previous else {
        return if view == 0 { Ok(()) } else { Err(ConsolidationRoastError::InvalidViewChain) };
    };
    if slot.ledger_height() != height.checked_add(1).ok_or(ConsolidationRoastError::InvalidState)?
        || slot.ledger_sequence()
            != sequence.checked_add(1).ok_or(ConsolidationRoastError::InvalidState)?
        || slot.ledger_previous() != decision
        || context.height() != height.checked_add(1).ok_or(ConsolidationRoastError::InvalidState)?
        || context.sequence()
            != sequence.checked_add(1).ok_or(ConsolidationRoastError::InvalidState)?
        || context.previous() != decision
    {
        return Err(ConsolidationRoastError::InvalidViewChain);
    }
    Ok(())
}

fn validate_replay_tombstone(
    state: &ConsolidationRoast,
    record: &RoastViewReplayTombstone,
) -> Result<(), ConsolidationRoastError> {
    let selected = &record.plan.signers;
    let invalid_archive = |archive: &BTreeMap<PartyId, [u8; 32]>| {
        archive.len() > selected.len()
            || archive
                .iter()
                .any(|(party, digest)| *digest == [0; 32] || selected.binary_search(party).is_err())
    };
    if invalid_archive(&record.preprocesses)
        || invalid_archive(&record.key_image_bindings)
        || invalid_archive(&record.shares)
        || record.key_image_certificate == Some([0; 32])
        || ((!record.shares.is_empty() || !record.candidates.is_empty())
            && record.key_image_certificate.is_none())
        || record.candidates.len() > selected.len()
        || record.candidates.iter().any(|(origin, (transaction, digest))| {
            selected.binary_search(origin).is_err() || *transaction == [0; 32] || *digest == [0; 32]
        })
    {
        return Err(ConsolidationRoastError::InvalidState);
    }
    // A selected local signer may have exposed a share before compaction. Its permanent nonce burn
    // lives in the worker/coordinator high-water; this tombstone authenticates the exact replay but
    // deliberately cannot re-open the local safety machine.
    if record.intent.authorization() != &state.authorization {
        return Err(ConsolidationRoastError::WrongFamily);
    }
    Ok(())
}

fn validate_record(
    state: &ConsolidationRoast,
    record: &RoastViewRecord,
) -> Result<(), ConsolidationRoastError> {
    let local_selected = record.plan.signers.binary_search(&state.local_party).is_ok();
    match (&record.local_safety, local_selected) {
        (Some(safety), true) => {
            safety.validate_expected(&record.context, &record.intent, &record.intent_certificate)?
        }
        (None, false) => {}
        _ => return Err(ConsolidationRoastError::InvalidState),
    }
    let local_share_visible = record.shares.contains_key(&state.local_party)
        || record
            .candidates
            .values()
            .any(|candidate| candidate.origins.contains_key(&state.local_party));
    if local_share_visible
        && !record.local_safety.as_ref().is_some_and(|safety| {
            matches!(
                safety.phase(),
                AttemptSafetyPhase::ShareExposed | AttemptSafetyPhase::ThresholdExposed
            )
        })
    {
        return Err(ConsolidationRoastError::InvalidState);
    }
    if retained_preprocess_body_bytes(record)? > preprocess_retained_byte_budget(state, record)? {
        return Err(ConsolidationRoastError::InvalidState);
    }
    for (phase, archive) in [
        (RoastContributionPhase::Preprocess, &record.preprocesses),
        (RoastContributionPhase::KeyImageBinding, &record.key_image_bindings),
        (RoastContributionPhase::Share, &record.shares),
    ] {
        if archive.len() > record.plan.signers.len()
            || archive.iter().any(|(party, contribution)| {
                contribution.digest == [0; 32]
                    || record.plan.signers.binary_search(party).is_err()
                    || (contribution.body.is_none()
                        && !contribution_fully_acked(
                            state,
                            record,
                            phase,
                            *party,
                            contribution.digest,
                        ))
            })
        {
            return Err(ConsolidationRoastError::InvalidState);
        }
        for (origin, contribution) in archive {
            if let Some(body) = &contribution.body {
                validate_contribution_body(
                    state,
                    record,
                    phase,
                    *origin,
                    contribution.digest,
                    body,
                )?;
            }
        }
    }
    for relay in &record.relay_acks {
        state.validate_relay(relay)?;
    }
    let expected_key_image_certificate = derive_key_image_certificate(state, record.plan.view)?;
    if record.key_image_certificate != expected_key_image_certificate
        || ((!record.shares.is_empty() || !record.candidates.is_empty())
            && record.key_image_certificate.is_none())
    {
        return Err(ConsolidationRoastError::InvalidState);
    }
    let mut candidate_origins = BTreeSet::new();
    for (transaction, candidate) in &record.candidates {
        candidate.signed.validate()?;
        if *transaction != candidate.signed.transaction()
            || candidate.signed.authorization_digest() != state.authorization.digest()
            || candidate.signed.attempt() != record.intent.attempt().attempt()
            || candidate.signed.attempt_binding_digest() != record.intent.attempt().digest()
            || candidate.signed.session() != record.intent.attempt().session()
            || candidate.signed.signing_context() != record.intent.attempt().signing_context()
            || candidate.signed.opaque_intent() != state.authorization.opaque_intent()
            || candidate.origins.is_empty()
            || candidate.origins.len() > record.plan.signers.len()
            || candidate.origins.iter().any(|(origin, contribution)| {
                contribution.digest == [0; 32]
                    || contribution.body.is_none()
                    || record.plan.signers.binary_search(origin).is_err()
                    || !candidate_origins.insert(*origin)
            })
        {
            return Err(ConsolidationRoastError::InvalidState);
        }
        for (origin, contribution) in &candidate.origins {
            let body = contribution.body.as_deref().ok_or(ConsolidationRoastError::InvalidState)?;
            let attestation = decode_canonical::<PortableSignedTransactionAttestation>(body)?;
            attestation.verify(
                &state.committee,
                state.quic_network_id,
                &state.wire_binding(record.plan.view)?,
            )?;
            if attestation.origin() != *origin
                || attestation.signed().binding() != candidate.signed
                || envelope_digest(attestation.envelope())? != contribution.digest
            {
                return Err(ConsolidationRoastError::InvalidState);
            }
        }
    }
    Ok(())
}

fn derive_key_image_certificate(
    state: &ConsolidationRoast,
    view: u64,
) -> Result<Option<PortableKeyImageBindingCertificate>, ConsolidationRoastError> {
    let record = state.views.get(&view).ok_or(ConsolidationRoastError::UnknownView(view))?;
    if record.key_image_bindings.len() < record.plan.signers.len() {
        return Ok(None);
    }
    if record.key_image_bindings.len() != record.plan.signers.len() {
        return Err(ConsolidationRoastError::InvalidState);
    }
    let retained = record.key_image_certificate.as_ref();
    let mut attestations = Vec::with_capacity(record.plan.signers.len());
    for signer in &record.plan.signers {
        let archive = record
            .key_image_bindings
            .get(signer)
            .ok_or(ConsolidationRoastError::MissingContribution(*signer))?;
        let attestation = if let Some(body) = &archive.body {
            decode_canonical::<PortableKeyImageBindingAttestation>(body)?
        } else {
            retained
                .and_then(|certificate| {
                    certificate
                        .attestations()
                        .iter()
                        .find(|attestation| attestation.origin() == *signer)
                })
                .cloned()
                .ok_or(ConsolidationRoastError::InvalidState)?
        };
        attestation.verify(&state.committee, state.quic_network_id, &state.wire_binding(view)?)?;
        if attestation.origin() != *signer
            || envelope_digest(attestation.envelope())? != archive.digest
        {
            return Err(ConsolidationRoastError::InvalidState);
        }
        attestations.push(attestation);
    }
    let Some(first) = attestations.first() else {
        return Ok(None);
    };
    if attestations.iter().any(|attestation| attestation.value() != first.value()) {
        // Preserve every attributable statement. A split value is evidence, never a quorum.
        return Ok(None);
    }
    Ok(Some(PortableKeyImageBindingCertificate::from_attestations(
        &state.committee,
        state.fault_bound,
        state.quic_network_id,
        &state.wire_binding(view)?,
        attestations,
    )?))
}

fn validate_contribution_body(
    state: &ConsolidationRoast,
    record: &RoastViewRecord,
    phase: RoastContributionPhase,
    origin: PartyId,
    expected_digest: [u8; 32],
    body: &[u8],
) -> Result<(), ConsolidationRoastError> {
    let binding = state.wire_binding(record.plan.view)?;
    match phase {
        RoastContributionPhase::Preprocess => {
            let contribution = decode_canonical::<SignedPreprocessContribution>(body)?;
            contribution.verify(&state.committee, state.quic_network_id, &binding)?;
            validate_frostlass_preprocess_shape(
                contribution.sender(),
                contribution.preprocess().message(),
                state.authorization.input_count(),
            )
            .map_err(ConsolidationWireError::from)?;
            if body.len() > maximum_signed_preprocess_body_bytes(state)? {
                return Err(ConsolidationRoastError::InvalidState);
            }
            if contribution.sender() != origin
                || envelope_digest(contribution.envelope())? != expected_digest
            {
                return Err(ConsolidationRoastError::InvalidState);
            }
        }
        RoastContributionPhase::Share => {
            let contribution = decode_canonical::<SignedShareContribution>(body)?;
            contribution.verify(&state.committee, state.quic_network_id, &binding)?;
            if contribution.sender() != origin
                || envelope_digest(contribution.envelope())? != expected_digest
            {
                return Err(ConsolidationRoastError::InvalidState);
            }
        }
        RoastContributionPhase::KeyImageBinding => {
            let attestation = decode_canonical::<PortableKeyImageBindingAttestation>(body)?;
            attestation.verify(&state.committee, state.quic_network_id, &binding)?;
            if attestation.origin() != origin
                || envelope_digest(attestation.envelope())? != expected_digest
            {
                return Err(ConsolidationRoastError::InvalidState);
            }
        }
        RoastContributionPhase::Candidate => {
            return Err(ConsolidationRoastError::InvalidContribution);
        }
    }
    Ok(())
}

fn validate_intent_for_plan(
    context: &ConsensusContext,
    intent: &ConsolidationIntent,
    authorization: &TransactionAuthorization,
    plan: &RoastViewPlan,
) -> Result<(), ConsolidationRoastError> {
    intent.validate_expected(context, intent)?;
    let attempt = intent.attempt();
    if plan.version != ROAST_VIEW_PLAN_VERSION
        || intent.authorization() != authorization
        || context.session() != plan.consensus_session
        || attempt.attempt() != plan.attempt
        || attempt.session() != plan.signing_session
        || attempt.signers() != plan.signers
        || attempt.epoch() != context.epoch()
        || attempt.registry_digest() != context.binding().registry
        || attempt.activation_digest() != context.binding().activation
        || attempt.committee_digest() != context.committee().digest()
        || attempt.threshold() != context.committee().threshold
        || attempt.root_group_key() != authorization.root_group_key()
        || plan.signers.binary_search(&plan.relay_seed).is_err()
    {
        return Err(ConsolidationRoastError::InvalidViewPlan);
    }
    Ok(())
}

fn contribution_digest(
    record: &RoastViewRecord,
    phase: RoastContributionPhase,
    origin: PartyId,
) -> Result<[u8; 32], ConsolidationRoastError> {
    Ok(contribution_archive(record, phase, origin)?.digest)
}

fn contribution_archive(
    record: &RoastViewRecord,
    phase: RoastContributionPhase,
    origin: PartyId,
) -> Result<&ArchivedContribution, ConsolidationRoastError> {
    match phase {
        RoastContributionPhase::Preprocess => record.preprocesses.get(&origin),
        RoastContributionPhase::KeyImageBinding => record.key_image_bindings.get(&origin),
        RoastContributionPhase::Share => record.shares.get(&origin),
        RoastContributionPhase::Candidate => {
            record.candidates.values().find_map(|candidate| candidate.origins.get(&origin))
        }
    }
    .ok_or(ConsolidationRoastError::MissingContribution(origin))
}

fn maximum_signed_preprocess_body_bytes(
    state: &ConsolidationRoast,
) -> Result<usize, ConsolidationRoastError> {
    expected_frostlass_preprocess_bytes(state.authorization.input_count())
        .and_then(|bytes| bytes.checked_add(MAX_SIGNED_PREPROCESS_OVERHEAD_BYTES))
        .ok_or(ConsolidationRoastError::InvalidContribution)
}

fn preprocess_retained_byte_budget(
    state: &ConsolidationRoast,
    record: &RoastViewRecord,
) -> Result<usize, ConsolidationRoastError> {
    let committee_budget = maximum_signed_preprocess_body_bytes(state)?
        .checked_mul(record.plan.signers.len())
        .ok_or(ConsolidationRoastError::InvalidContribution)?;
    Ok(committee_budget.min(MAX_PREPROCESS_RETAINED_BYTES_PER_VIEW))
}

fn retained_preprocess_body_bytes(
    record: &RoastViewRecord,
) -> Result<usize, ConsolidationRoastError> {
    record
        .preprocesses
        .values()
        .filter_map(|contribution| contribution.body.as_ref().map(Vec::len))
        .try_fold(0_usize, |total, bytes| {
            total.checked_add(bytes).ok_or(ConsolidationRoastError::InvalidState)
        })
}

fn contribution_fully_acked(
    state: &ConsolidationRoast,
    record: &RoastViewRecord,
    phase: RoastContributionPhase,
    origin: PartyId,
    digest: [u8; 32],
) -> bool {
    let attempt = record.intent.attempt();
    state
        .committee
        .members
        .iter()
        .map(|member| member.id)
        .filter(|recipient| *recipient != state.local_party && *recipient != origin)
        .all(|recipient| {
            record.relay_acks.contains(&RoastRelayId {
                version: ROAST_RELAY_VERSION,
                family: state.family,
                view: record.plan.view,
                attempt: attempt.digest(),
                session: attempt.session(),
                phase,
                origin,
                recipient,
                contribution: digest,
            })
        })
}

fn family_material(
    binding: &ConsensusBinding,
    committee: &Committee,
    fault_bound: u16,
    authorization: &TransactionAuthorization,
    chain_anchor: [u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 * 8);
    bytes.extend_from_slice(&binding.domain);
    bytes.extend_from_slice(&(binding.application.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&binding.application);
    bytes.extend_from_slice(&binding.wallet);
    bytes.extend_from_slice(&binding.network);
    bytes.extend_from_slice(&binding.registry);
    bytes.extend_from_slice(&binding.activation);
    bytes.extend_from_slice(&committee.digest());
    bytes.extend_from_slice(&fault_bound.to_le_bytes());
    bytes.extend_from_slice(&authorization.digest());
    bytes.extend_from_slice(&chain_anchor);
    bytes
}

/// Derive the immutable post-certificate signing family. Unlike the bootstrap slot, the family
/// intentionally commits to the BA-selected authorization.
#[must_use]
pub fn deterministic_roast_family_digest(
    binding: &ConsensusBinding,
    committee: &Committee,
    fault_bound: u16,
    authorization: &TransactionAuthorization,
    chain_anchor: [u8; 32],
) -> [u8; 32] {
    let material = family_material(binding, committee, fault_bound, authorization, chain_anchor);
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/consolidation-roast/family/v1");
    hasher.update(&(material.len() as u64).to_le_bytes());
    hasher.update(&material);
    *hasher.finalize().as_bytes()
}

fn candidate_evidence_digest(
    view: u64,
    transaction: [u8; 32],
    candidate: &CandidateArchive,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(
        "threshold-monero/consolidation-roast/candidate-evidence/v1",
    );
    hasher.update(&view.to_le_bytes());
    hasher.update(&transaction);
    let signed = postcard::to_allocvec(&candidate.signed)
        .expect("validated signed transaction binding serializes");
    hasher.update(&(signed.len() as u64).to_le_bytes());
    hasher.update(&signed);
    hasher.update(&(candidate.origins.len() as u64).to_le_bytes());
    for (origin, digest) in &candidate.origins {
        hasher.update(&origin.0.to_le_bytes());
        hasher.update(&digest.digest);
    }
    *hasher.finalize().as_bytes()
}

fn roast_outer_deadline(
    now_ms: u64,
    base_timeout_ms: u64,
    view: u64,
) -> Result<u64, ConsolidationRoastError> {
    if now_ms == 0 || base_timeout_ms == 0 {
        return Err(ConsolidationRoastError::InvalidDeadline);
    }
    let shift = u32::try_from(view.min(6)).map_err(|_| ConsolidationRoastError::InvalidDeadline)?;
    now_ms
        .checked_add(
            base_timeout_ms
                .checked_mul(1_u64 << shift)
                .ok_or(ConsolidationRoastError::InvalidDeadline)?,
        )
        .ok_or(ConsolidationRoastError::InvalidDeadline)
}

fn combinations(parties: &[PartyId], choose: usize) -> Vec<Vec<PartyId>> {
    fn visit(
        parties: &[PartyId],
        choose: usize,
        start: usize,
        current: &mut Vec<PartyId>,
        output: &mut Vec<Vec<PartyId>>,
    ) {
        if current.len() == choose {
            output.push(current.clone());
            return;
        }
        let remaining = choose - current.len();
        let Some(last_start) = parties.len().checked_sub(remaining) else {
            return;
        };
        for index in start..=last_start {
            current.push(parties[index]);
            visit(parties, choose, index + 1, current, output);
            current.pop();
        }
    }

    if choose == 0 || choose > parties.len() || parties.len() > MAX_COMMITTEE_MEMBERS {
        return Vec::new();
    }
    let mut output = Vec::new();
    visit(parties, choose, 0, &mut Vec::with_capacity(choose), &mut output);
    output
}

fn envelope_digest(
    envelope: &crate::identity::SignedEnvelope,
) -> Result<[u8; 32], ConsolidationRoastError> {
    let bytes =
        postcard::to_allocvec(envelope).map_err(|_| ConsolidationRoastError::Serialization)?;
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/consolidation-roast/contribution/v1");
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn canonical_body<T: Serialize>(value: &T) -> Result<Vec<u8>, ConsolidationRoastError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| ConsolidationRoastError::Serialization)?;
    if bytes.is_empty() || bytes.len() > MAX_CONSOLIDATION_WIRE_BYTES {
        return Err(ConsolidationRoastError::InvalidContribution);
    }
    Ok(bytes)
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, ConsolidationRoastError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_CONSOLIDATION_WIRE_BYTES {
        return Err(ConsolidationRoastError::InvalidContribution);
    }
    let (decoded, trailing) = postcard::take_from_bytes::<T>(bytes)
        .map_err(|_| ConsolidationRoastError::Serialization)?;
    if !trailing.is_empty() || canonical_body(&decoded)? != bytes {
        return Err(ConsolidationRoastError::NonCanonicalEncoding);
    }
    Ok(decoded)
}

#[derive(Debug, Error)]
pub enum ConsolidationRoastError {
    #[error("committee error: {0}")]
    Committee(#[from] crate::committee::CommitteeError),
    #[error("deposit consensus error: {0}")]
    Consensus(#[from] ConsensusError),
    #[error("consolidation consensus error: {0}")]
    ConsolidationConsensus(#[from] ConsolidationConsensusError),
    #[error("consolidation state error: {0}")]
    Consolidation(#[from] ConsolidationError),
    #[error("consolidation wire error: {0}")]
    Wire(#[from] ConsolidationWireError),
    #[error("the reducer belongs to another authorization, committee, epoch or network")]
    WrongFamily,
    #[error("the persisted certified intents do not match local reconstruction")]
    WrongExpectedIntentChain,
    #[error("the QUIC network binding is zero or mismatched")]
    WrongNetwork,
    #[error("the deterministic ROAST view budget is exhausted")]
    ViewExhausted,
    #[error("ROAST view {0} is not certified locally")]
    UnknownView(u64),
    #[error("ROAST view {0} is older than the exact replay window")]
    CompactedView(u64),
    #[error("ROAST view {0} has been superseded and no longer accepts round contributions")]
    SupersededView(u64),
    #[error("the certified intent does not match the deterministic view plan")]
    InvalidViewPlan,
    #[error("the certified view does not extend the preceding decision")]
    InvalidViewChain,
    #[error("a consensus or signing session was reused across views or domains")]
    SessionCollision,
    #[error("an endorsed transaction candidate is already available")]
    CandidateAlreadyAvailable,
    #[error("the ROAST family is terminally sealed")]
    TerminalSealed,
    #[error("the terminal completion seal is missing or inconsistent")]
    InvalidCompletionSeal,
    #[error("the terminal abandonment seal is missing or inconsistent")]
    InvalidAbandonmentSeal,
    #[error("the certified-attempt prefix commitment is malformed or inconsistent")]
    InvalidAttemptPrefix,
    #[error("the local party is outside this view's signer subset")]
    LocalPartyNotSelected,
    #[error("ROAST view {0} has no exact all-selected key-image certificate")]
    MissingKeyImageCertificate(u64),
    #[error("the contribution digest or provenance is invalid")]
    InvalidContribution,
    #[error(
        "ROAST view {view} would retain {actual} preprocess bytes; its committee/resource budget is {maximum}"
    )]
    PreprocessRetentionBudgetExceeded { view: u64, actual: usize, maximum: usize },
    #[error("party {0} is outside this view's signer set")]
    UnexpectedContributor(PartyId),
    #[error("party {0} equivocated within one contribution slot")]
    ContributionEquivocation(PartyId),
    #[error("the completed transaction binding equivocated")]
    CandidateEquivocation,
    #[error("party {0} attested two transaction candidates in one view")]
    CandidateOriginEquivocation(PartyId),
    #[error("contribution from party {0} has not been observed")]
    MissingContribution(PartyId),
    #[error("the exact contribution body from party {0} was retired after successor certification")]
    ContributionBodyRetired(PartyId),
    #[error("the durable all-to-all relay acknowledgement is not exact")]
    InvalidRelay,
    #[error("durable ROAST revision exhausted")]
    RevisionExhausted,
    #[error("the durable ROAST outer-view deadline is invalid")]
    InvalidDeadline,
    #[error("durable ROAST state is malformed")]
    InvalidState,
    #[error("canonical ROAST serialization failed")]
    Serialization,
    #[error("ROAST encoding has {0} trailing bytes")]
    TrailingBytes(usize),
    #[error("ROAST encoding is non-canonical")]
    NonCanonicalEncoding,
    #[error("ROAST encoding is {actual} bytes, exceeding the {maximum}-byte limit")]
    StateTooLarge { actual: usize, maximum: usize },
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};

    use super::*;
    use crate::{
        committee::Member,
        consolidation_consensus::AttemptSafetyPhase,
        deposit_consensus::{
            CommitCertificate, ConsensusMessageBody, ConsensusValue, Vote, sign_consensus_message,
        },
        deposit_consolidation::{AttemptBinding, OpaqueIntentBinding},
        deposit_wallet::{DepositWalletId, SweepId},
        identity::Identity,
        signing::{
            BoundPreprocessMessage, MAX_FROSTLASS_MESSAGE_BYTES, PreprocessMessage, SigningError,
        },
    };

    #[derive(Serialize)]
    struct BoundPreprocessFixture {
        context: [u8; 32],
        sender: PartyId,
        message: Vec<u8>,
    }

    struct Fixture {
        identities: Vec<Identity>,
        authorization: TransactionAuthorization,
        reducer: ConsolidationRoast,
    }

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0xa2; 32];
        // Keep the identity discriminator away from X25519's clamped low byte.
        secret[1..9].copy_from_slice(&epoch.to_le_bytes());
        secret[9..11].copy_from_slice(&party.0.to_le_bytes());
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

    fn authorization() -> TransactionAuthorization {
        TransactionAuthorization::new(
            DepositWalletId([0x22; 32]),
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
        .unwrap()
    }

    fn binding(application: &[u8]) -> ConsensusBinding {
        ConsensusBinding {
            domain: [0x11; 32],
            application: application.to_vec(),
            wallet: [0x22; 32],
            network: [0x33; 32],
            registry: [0x44; 32],
            activation: [0x55; 32],
        }
    }

    fn intent_for_plan(
        context: &ConsensusContext,
        authorization: &TransactionAuthorization,
        plan: &RoastViewPlan,
    ) -> ConsolidationIntent {
        let attempt = AttemptBinding::new(
            plan.attempt(),
            context.epoch(),
            context.binding().registry,
            context.committee().digest(),
            context.binding().activation,
            authorization.root_group_key(),
            context.committee().threshold,
            plan.signers().to_vec(),
            [u8::try_from(0x66_u64 + plan.view()).unwrap(); 32],
            plan.signing_session(),
            [u8::try_from(0x80_u64 + plan.view()).unwrap(); 32],
        )
        .unwrap();
        ConsolidationIntent::new(context, authorization.clone(), attempt).unwrap()
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

    fn certify_intent(
        context: &ConsensusContext,
        identities: &[Identity],
        intent: &ConsolidationIntent,
    ) -> ConsolidationIntentCertificate {
        let value = intent.to_consensus_value().unwrap();
        ConsolidationIntentCertificate::new(
            context.clone(),
            commit_certificate(context, identities, value),
        )
        .unwrap()
    }

    fn fixture(local_party: PartyId) -> Fixture {
        let (identities, committee) = identities_and_committee();
        let authorization = authorization();
        let intent_binding = binding(CONSOLIDATION_INTENT_APPLICATION);
        let network = intent_binding.network;
        let slot =
            ConsolidationConsensusSlot::new(intent_binding, &committee, 1, 0, 0, 41, [0; 32])
                .unwrap();
        let plan = RoastViewPlan::derive(&slot, &committee, 1, &authorization).unwrap();
        let context = slot.consensus_context().unwrap();
        let intent = intent_for_plan(&context, &authorization, &plan);
        let certificate = certify_intent(&context, &identities, &intent);
        let reducer = ConsolidationRoast::new(
            local_party,
            network,
            slot,
            context,
            intent,
            certificate,
            1_000,
            100,
        )
        .unwrap();
        Fixture { identities, authorization, reducer }
    }

    #[test]
    fn constructor_and_authenticated_decode_reject_a_mismatched_quic_network() {
        let (identities, committee) = identities_and_committee();
        let authorization = authorization();
        let intent_binding = binding(CONSOLIDATION_INTENT_APPLICATION);
        let slot = ConsolidationConsensusSlot::new(
            intent_binding.clone(),
            &committee,
            1,
            0,
            0,
            41,
            [0; 32],
        )
        .unwrap();
        let plan = RoastViewPlan::derive(&slot, &committee, 1, &authorization).unwrap();
        let context = slot.consensus_context().unwrap();
        let intent = intent_for_plan(&context, &authorization, &plan);
        let certificate = certify_intent(&context, &identities, &intent);

        assert!(matches!(
            ConsolidationRoast::new(
                PartyId(1),
                [0x99; 32],
                slot,
                context,
                intent,
                certificate,
                1_000,
                100,
            ),
            Err(ConsolidationRoastError::WrongNetwork)
        ));

        let mut wrong_network = fixture(PartyId(1));
        wrong_network.reducer.quic_network_id = [0x99; 32];
        let bytes = postcard::to_allocvec(&wrong_network.reducer).unwrap();
        assert!(matches!(
            ConsolidationRoast::decode_authenticated_snapshot(&bytes),
            Err(ConsolidationRoastError::InvalidState)
        ));

        let mut stale = fixture(PartyId(1)).reducer;
        stale.version = 7;
        let bytes = postcard::to_allocvec(&stale).unwrap();
        assert!(matches!(
            ConsolidationRoast::decode_authenticated_snapshot(&bytes),
            Err(ConsolidationRoastError::InvalidState)
        ));
    }

    #[test]
    fn randomized_prepared_values_share_one_bootstrap_consensus_slot() {
        let (_, committee) = identities_and_committee();
        let first = authorization();
        let second = TransactionAuthorization::new(
            first.wallet_id(),
            first.sweep_id(),
            OpaqueIntentBinding([0x72; 32]),
            first.input_set(),
            first.destination_policy(),
            first.root_group_key(),
            first.input_count(),
            first.total_input_atomic_units(),
            first.fee_atomic_units(),
            first.maximum_fee_atomic_units(),
        )
        .unwrap();
        let binding = binding(CONSOLIDATION_INTENT_APPLICATION);
        let slot = ConsolidationConsensusSlot::new(
            binding.clone(),
            &committee,
            1,
            0,
            1,
            1,
            first.sweep_id().0,
        )
        .unwrap();
        let anchor = slot.digest();
        let first_plan = RoastViewPlan::derive(&slot, &committee, 1, &first).unwrap();
        let second_plan = RoastViewPlan::derive(&slot, &committee, 1, &second).unwrap();

        assert_eq!(first_plan.consensus_session(), second_plan.consensus_session());
        // Competing prepared values in one ROAST view share the sole monotonic signing namespace.
        // BA selects the authorization before nonce release, so a randomized proposal cannot mint
        // a second nonce namespace for the same wallet/sweep/attempt.
        assert_eq!(first_plan.signing_session(), second_plan.signing_session());
        assert_ne!(
            deterministic_roast_family_digest(&binding, &committee, 1, &first, anchor),
            deterministic_roast_family_digest(&binding, &committee, 1, &second, anchor),
        );
        assert_eq!(first_plan.consensus_session(), slot.session(),);
    }

    fn append_next(fixture: &mut Fixture) {
        let view = fixture.reducer.next_view();
        let plan = fixture.reducer.expected_plan(view).unwrap();
        let context = fixture.reducer.expected_context(view).unwrap();
        let intent = intent_for_plan(&context, &fixture.authorization, &plan);
        let certificate = certify_intent(&context, &fixture.identities, &intent);
        assert_eq!(
            fixture
                .reducer
                .append_certified_view(context, intent, certificate, 1_000 + view * 100)
                .unwrap(),
            view
        );
    }

    #[test]
    fn successor_archives_only_the_view_crossing_into_the_replay_window() {
        let mut fixture = fixture(PartyId(1));
        assert!(fixture.reducer.attempts_requiring_archive_before_successor().unwrap().is_empty());

        while fixture.reducer.views.len() < MAX_HOT_ROAST_VIEWS {
            append_next(&mut fixture);
            if fixture.reducer.views.len() < MAX_HOT_ROAST_VIEWS {
                assert!(
                    fixture
                        .reducer
                        .attempts_requiring_archive_before_successor()
                        .unwrap()
                        .is_empty()
                );
            }
        }

        let hot = fixture.reducer.hot_attempt_archive_materials().unwrap();
        let evicted = fixture.reducer.attempts_requiring_archive_before_successor().unwrap();
        assert_eq!(hot.len(), MAX_HOT_ROAST_VIEWS);
        assert_eq!(evicted, vec![hot[0].clone()]);
        assert_eq!(evicted[0].slot.roast_view(), 0);
        assert_ne!(evicted[0].slot.roast_view(), hot.last().unwrap().slot.roast_view());

        append_next(&mut fixture);
        let tombstone = fixture.reducer.replay_tombstones.get(&0).unwrap();
        assert_eq!(tombstone.slot, evicted[0].slot);
        assert_eq!(tombstone.context, evicted[0].context);
        assert_eq!(tombstone.intent, evicted[0].intent);
        assert_eq!(tombstone.intent_certificate, evicted[0].intent_certificate);
        assert_eq!(
            tombstone.key_image_certificate,
            evicted[0]
                .key_image_certificate
                .as_ref()
                .map(PortableKeyImageBindingCertificate::digest)
        );

        let next_eviction = fixture.reducer.attempts_requiring_archive_before_successor().unwrap();
        assert_eq!(next_eviction.len(), 1);
        assert_eq!(next_eviction[0].slot.roast_view(), 1);
        assert_eq!(
            fixture.reducer.views.last_key_value().unwrap().0,
            &u64::try_from(MAX_HOT_ROAST_VIEWS).unwrap()
        );
    }

    fn structurally_valid_preprocess(input_count: u32, discriminator: u8) -> Vec<u8> {
        let input_count = usize::try_from(input_count).unwrap();
        let mut bytes =
            Vec::with_capacity(input_count * crate::signing::FROSTLASS_PREPROCESS_BYTES_PER_INPUT);
        for input in 0..input_count {
            for field in 0..7 {
                let scalar = Scalar::from(
                    u64::from(discriminator)
                        .saturating_add(u64::try_from(input).unwrap())
                        .saturating_add(u64::try_from(field).unwrap())
                        .saturating_add(1),
                );
                bytes.extend_from_slice(&(ED25519_BASEPOINT_POINT * scalar).compress().to_bytes());
            }
            bytes.extend_from_slice(
                &Scalar::from(
                    u64::from(discriminator)
                        .saturating_add(u64::try_from(input).unwrap())
                        .saturating_add(1),
                )
                .to_bytes(),
            );
        }
        bytes
    }

    fn signed_preprocess_bytes(
        fixture: &Fixture,
        view: u64,
        sender: PartyId,
        message: Vec<u8>,
    ) -> SignedPreprocessContribution {
        let plan = fixture.reducer.plan(view).unwrap();
        let encoded = postcard::to_allocvec(&BoundPreprocessFixture {
            context: fixture.reducer.views.get(&view).unwrap().intent.attempt().signing_context(),
            sender,
            message: message.clone(),
        })
        .unwrap();
        let bound: BoundPreprocessMessage = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(bound.message(), &PreprocessMessage::from_bytes(message));
        SignedPreprocessContribution::sign(
            fixture.identities.iter().find(|identity| identity.party() == sender).unwrap(),
            &fixture.reducer.committee,
            fixture.reducer.quic_network_id,
            fixture.reducer.wire_binding(plan.view()).unwrap(),
            bound,
        )
        .unwrap()
    }

    fn signed_preprocess(
        fixture: &Fixture,
        sender: PartyId,
        byte: u8,
    ) -> SignedPreprocessContribution {
        signed_preprocess_bytes(
            fixture,
            0,
            sender,
            structurally_valid_preprocess(fixture.authorization.input_count(), byte),
        )
    }

    #[test]
    fn deterministic_n_minus_f_views_cover_the_all_honest_subset_and_restore() {
        let mut fixture = fixture(PartyId(1));
        assert_eq!(
            fixture.reducer.plan(0).unwrap().signers(),
            &[PartyId(1), PartyId(2), PartyId(3)]
        );
        append_next(&mut fixture);
        append_next(&mut fixture);
        append_next(&mut fixture);
        let subsets = fixture
            .reducer
            .views
            .values()
            .map(|record| record.plan.signers.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            subsets,
            vec![
                vec![PartyId(1), PartyId(2), PartyId(3)],
                vec![PartyId(1), PartyId(2), PartyId(4)],
                vec![PartyId(1), PartyId(3), PartyId(4)],
                vec![PartyId(2), PartyId(3), PartyId(4)],
            ]
        );
        let sessions = fixture
            .reducer
            .views
            .values()
            .flat_map(|record| [record.plan.signing_session, record.plan.consensus_session])
            .collect::<BTreeSet<_>>();
        assert_eq!(sessions.len(), 8);
        let genesis_slot = fixture.reducer.views.get(&0).unwrap().slot.clone();
        let genesis_context = fixture.reducer.views.get(&0).unwrap().context.clone();
        let expected_intents =
            fixture.reducer.views.values().map(|record| record.intent.clone()).collect::<Vec<_>>();
        let encoded = fixture.reducer.encode().unwrap();
        let network = fixture.reducer.quic_network_id();
        let restored = ConsolidationRoast::restore(
            &encoded,
            PartyId(1),
            network,
            &fixture.reducer.committee,
            1,
            &fixture.authorization,
            &genesis_slot,
            &genesis_context,
            &expected_intents,
        )
        .unwrap();
        assert_eq!(restored, fixture.reducer);
    }

    #[test]
    fn no_local_nonce_safety_record_exists_before_certification_or_outside_subset() {
        let fixture_unselected = fixture(PartyId(4));
        assert!(matches!(
            fixture_unselected.reducer.new_local_attempt_safety(0),
            Err(ConsolidationRoastError::LocalPartyNotSelected)
        ));
        assert!(matches!(
            fixture_unselected.reducer.new_local_attempt_safety(1),
            Err(ConsolidationRoastError::UnknownView(1))
        ));

        let fixture = fixture(PartyId(2));
        let safety = fixture.reducer.new_local_attempt_safety(0).unwrap();
        assert_eq!(safety.phase(), AttemptSafetyPhase::NonceUnreleased);
        assert_eq!(safety.key().session(), fixture.reducer.plan(0).unwrap().signing_session());
    }

    #[test]
    fn all_to_all_relay_ack_is_exact_and_contribution_equivocation_is_rejected() {
        let mut fixture = fixture(PartyId(1));
        let first = signed_preprocess(&fixture, PartyId(2), 0xa1);
        let conflicting = signed_preprocess(&fixture, PartyId(2), 0xa2);
        assert!(fixture.reducer.observe_preprocess(0, &first).unwrap());
        assert!(!fixture.reducer.observe_preprocess(0, &first).unwrap());
        assert!(matches!(
            fixture.reducer.observe_preprocess(0, &conflicting),
            Err(ConsolidationRoastError::ContributionEquivocation(PartyId(2)))
        ));
        let pending = fixture
            .reducer
            .pending_relays(0, RoastContributionPhase::Preprocess, PartyId(2))
            .unwrap();
        assert_eq!(
            pending.iter().map(RoastRelayId::recipient).collect::<Vec<_>>(),
            vec![PartyId(3), PartyId(4)]
        );
        assert!(fixture.reducer.acknowledge_relay(pending[0].recipient(), pending[0]).unwrap());
        assert!(!fixture.reducer.acknowledge_relay(pending[0].recipient(), pending[0]).unwrap());
        assert!(matches!(
            fixture.reducer.acknowledge_relay(PartyId(3), pending[1]),
            Err(ConsolidationRoastError::InvalidRelay)
        ));
        let mut wrong = pending[1];
        wrong.contribution = [0xff; 32];
        assert!(matches!(
            fixture.reducer.acknowledge_relay(wrong.recipient(), wrong),
            Err(ConsolidationRoastError::InvalidRelay)
        ));
    }

    #[test]
    fn maximum_schedule_cycles_subsets_with_fresh_absolute_attempts() {
        let identities = (1_u16..=10)
            .map(|party| {
                let party = PartyId(party);
                let signing_seed = [u8::try_from(party.0).unwrap(); 32];
                Identity::from_test_secrets(party, 7, &signing_seed, test_x25519_secret(party, 7))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let committee = Committee {
            epoch: 7,
            threshold: 4,
            members: identities
                .iter()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        };
        committee.validate_async_security_with_faults(3).unwrap();
        let all = (0_u64..120)
            .map(|view| deterministic_roast_signers(&committee, 3, view).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(all.len(), 120);
        assert_eq!(
            deterministic_roast_signers(&committee, 3, 119).unwrap(),
            (4_u16..=10).map(PartyId).collect::<Vec<_>>()
        );
        assert_eq!(
            deterministic_roast_signers(&committee, 3, 120).unwrap(),
            deterministic_roast_signers(&committee, 3, 0).unwrap()
        );
        assert_eq!(
            deterministic_roast_signers(&committee, 3, 239).unwrap(),
            deterministic_roast_signers(&committee, 3, 119).unwrap()
        );
        let wallet = DepositWalletId([0x42; 32]);
        let sweep = SweepId([0x24; 32]);
        assert_ne!(
            derive_sweep_signing_session(wallet, sweep, 1),
            derive_sweep_signing_session(wallet, sweep, 121)
        );
    }

    fn maximum_committee_fixture(local_party: PartyId) -> Fixture {
        let identities = (1_u16..=10)
            .map(|party| {
                let party = PartyId(party);
                let signing_seed = [u8::try_from(party.0).unwrap(); 32];
                Identity::from_test_secrets(party, 7, &signing_seed, test_x25519_secret(party, 7))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let committee = Committee {
            epoch: 7,
            threshold: 4,
            members: identities
                .iter()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        };
        committee.validate_async_security_with_faults(3).unwrap();
        let authorization = authorization();
        let intent_binding = binding(CONSOLIDATION_INTENT_APPLICATION);
        let network = intent_binding.network;
        let slot =
            ConsolidationConsensusSlot::new(intent_binding, &committee, 3, 0, 0, 41, [0; 32])
                .unwrap();
        let plan = RoastViewPlan::derive(&slot, &committee, 3, &authorization).unwrap();
        let context = slot.consensus_context().unwrap();
        let intent = intent_for_plan(&context, &authorization, &plan);
        let certificate = certify_intent(&context, &identities, &intent);
        let reducer = ConsolidationRoast::new(
            local_party,
            network,
            slot,
            context,
            intent,
            certificate,
            1_000,
            100,
        )
        .unwrap();
        Fixture { identities, authorization, reducer }
    }

    #[test]
    fn n10_signed_preprocess_amplification_is_bounded_and_reaches_the_honest_subset() {
        let mut fixture = maximum_committee_fixture(PartyId(10));
        let original = fixture.reducer.encode().unwrap();

        // Three authenticated Byzantine origins may sign arbitrary one-MiB bodies, but the
        // authorization fixes two inputs and therefore exactly 512 canonical preprocess bytes.
        // Reject each before a reducer revision or relay matrix can be retained.
        for sender in [PartyId(1), PartyId(2), PartyId(3)] {
            let malicious = signed_preprocess_bytes(
                &fixture,
                0,
                sender,
                vec![0x41; MAX_FROSTLASS_MESSAGE_BYTES],
            );
            assert!(matches!(
                fixture.reducer.observe_preprocess(0, &malicious),
                Err(ConsolidationRoastError::Wire(ConsolidationWireError::Signing(
                    SigningError::WrongMessageLength {
                        expected: 512,
                        actual: MAX_FROSTLASS_MESSAGE_BYTES,
                        ..
                    }
                )))
            ));
            assert_eq!(fixture.reducer.encode().unwrap(), original);
        }

        // Exact-shape bodies from the same f origins remain bounded even if every recipient
        // withholds its ACK. There are eight relay destinations per origin at n=10.
        for (sender, discriminator) in [(PartyId(1), 0x51), (PartyId(2), 0x52), (PartyId(3), 0x53)]
        {
            let contribution = signed_preprocess_bytes(
                &fixture,
                0,
                sender,
                structurally_valid_preprocess(fixture.authorization.input_count(), discriminator),
            );
            assert!(fixture.reducer.observe_preprocess(0, &contribution).unwrap());
            assert_eq!(
                fixture
                    .reducer
                    .pending_relays(0, RoastContributionPhase::Preprocess, sender)
                    .unwrap()
                    .len(),
                8
            );
        }
        let first_view = fixture.reducer.views.get(&0).unwrap();
        assert!(
            retained_preprocess_body_bytes(first_view).unwrap()
                <= preprocess_retained_byte_budget(&fixture.reducer, first_view).unwrap()
        );
        assert!(
            preprocess_retained_byte_budget(&fixture.reducer, first_view).unwrap()
                <= MAX_PREPROCESS_RETAINED_BYTES_PER_VIEW
        );

        // Certification of view one drops recipient-specific predecessor retries, but does not
        // forge ACKs or erase the reducer's sole exact evidence body.
        append_next(&mut fixture);
        for sender in [PartyId(1), PartyId(2), PartyId(3)] {
            assert!(
                fixture
                    .reducer
                    .pending_relays(0, RoastContributionPhase::Preprocess, sender)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                fixture
                    .reducer
                    .views
                    .get(&0)
                    .unwrap()
                    .preprocesses
                    .get(&sender)
                    .unwrap()
                    .body
                    .is_some()
            );
        }

        // The 120 deterministic 7-of-10 subsets end with the all-honest complement of the three
        // faulty origins. With predecessor amplification bounded, that view can retain all seven
        // honest preprocesses and expose the complete set to the live FROSTLASS machine.
        while fixture.reducer.next_view() <= 119 {
            append_next(&mut fixture);
        }
        assert_eq!(
            fixture.reducer.plan(119).unwrap().signers(),
            &(4_u16..=10).map(PartyId).collect::<Vec<_>>()
        );
        for (sender, discriminator) in (4_u16..=10).map(PartyId).zip(0x64_u8..) {
            let contribution = signed_preprocess_bytes(
                &fixture,
                119,
                sender,
                structurally_valid_preprocess(fixture.authorization.input_count(), discriminator),
            );
            assert!(fixture.reducer.observe_preprocess(119, &contribution).unwrap());
        }
        assert_eq!(fixture.reducer.complete_preprocesses(119).unwrap().unwrap().len(), 7);
        assert!(fixture.reducer.encode().unwrap().len() <= MAX_ROAST_STATE_BYTES);
    }

    #[test]
    fn failed_mutation_is_error_atomic() {
        let mut fixture = fixture(PartyId(1));
        let contribution = signed_preprocess(&fixture, PartyId(2), 0xa1);
        fixture.reducer.revision = u64::MAX;
        fixture.reducer.transition = fixture.reducer.expected_transition().unwrap();
        let before = fixture.reducer.encode().unwrap();
        assert!(matches!(
            fixture.reducer.observe_preprocess(0, &contribution),
            Err(ConsolidationRoastError::RevisionExhausted)
        ));
        assert_eq!(fixture.reducer.encode().unwrap(), before);
    }
}
