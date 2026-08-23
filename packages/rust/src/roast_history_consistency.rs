//! Bounded consistency proofs for witness-independent ROAST archive history.
//!
//! Archive artifacts may contain different, equally valid quorum-signature witness subsets. Those
//! bytes are deliberately excluded here. A semantic state commits only to canonical index roots
//! and counters. Each history leaf binds one exact semantic state transition, and dyadic parent
//! summaries carry both generation and state boundaries. This makes a fork splice fail even when
//! two branches later happen to have equal counters or index roots.
//!
//! A consistency proof is meaningful only when both endpoint roots and endpoint semantic states
//! are authenticated by the committee. This module verifies append-only consistency between those
//! endpoints in bounded work; endpoint certification and persistent anti-double-sign sequencing
//! belong to the archive/service layer.

use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::deposit_wallet::DepositWalletId;

/// Maximum number of peaks in a `u64`-sized dyadic frontier.
pub const MAX_ROAST_ARCHIVE_HISTORY_PEAKS: usize = u64::BITS as usize;

/// Resource ceiling for the dyadic summaries appended by one consistency proof.
///
/// Any interval in a `u64` generation space has a canonical aligned decomposition with at most
/// twice the bit width, so this does not constrain representable history.
pub const MAX_ROAST_ARCHIVE_HISTORY_SUFFIX_SUMMARIES: usize = 2 * MAX_ROAST_ARCHIVE_HISTORY_PEAKS;

const SEMANTIC_STATE_DOMAIN: &str = "threshold-monero/roast-archive-history/semantic-state/v1";
const HISTORY_LEAF_DOMAIN: &str = "threshold-monero/roast-archive-history/leaf/v1";
const HISTORY_PARENT_DOMAIN: &str = "threshold-monero/roast-archive-history/parent/v1";
const HISTORY_ROOT_DOMAIN: &str = "threshold-monero/roast-archive-history/root/v1";

/// Failure while constructing or verifying a bounded ROAST archive history proof.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RoastArchiveHistoryError {
    #[error("the ROAST archive semantic state is malformed")]
    InvalidSemanticState,
    #[error("the ROAST archive transition regresses or mutates incompatible counters")]
    InvalidSemanticTransition,
    #[error("the ROAST archive history summary is malformed")]
    InvalidSummary,
    #[error("ROAST archive history summaries are not generation-contiguous")]
    NonContiguousHistory,
    #[error("ROAST archive history summaries disagree at a semantic-state boundary")]
    StateBoundaryMismatch,
    #[error("the ROAST archive history frontier is malformed")]
    InvalidFrontier,
    #[error("the ROAST archive history proof exceeds its resource bound")]
    ProofTooLarge,
    #[error("the ROAST archive history proof is not in canonical dyadic form")]
    NonCanonicalProof,
    #[error("the ROAST archive history endpoints belong to different wallet or network domains")]
    WrongHistoryDomain,
    #[error("the source endpoint does not match the consistency proof")]
    SourceEndpointMismatch,
    #[error("the target endpoint does not match the consistency proof")]
    TargetEndpointMismatch,
    #[error("the source history root does not match the consistency proof")]
    SourceRootMismatch,
    #[error("the target history root does not match the consistency proof")]
    TargetRootMismatch,
    #[error("the ROAST archive generation counter is exhausted")]
    GenerationExhausted,
}

/// Witness-independent semantic state at one archive generation.
///
/// `view_root`, `transaction_root`, and `family_root` must be roots over canonical semantic
/// statements. They must not be content hashes of encrypted artifacts or encodings containing a
/// selectable quorum-signature witness set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RoastArchiveSemanticState {
    wallet: DepositWalletId,
    network: [u8; 32],
    generation: u64,
    attempt_count: u64,
    transaction_count: u64,
    family_count: u64,
    view_root: [u8; 32],
    transaction_root: Option<[u8; 32]>,
    family_root: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoastArchiveSemanticStateRepr {
    wallet: DepositWalletId,
    network: [u8; 32],
    generation: u64,
    attempt_count: u64,
    transaction_count: u64,
    family_count: u64,
    view_root: [u8; 32],
    transaction_root: Option<[u8; 32]>,
    family_root: [u8; 32],
}

impl RoastArchiveSemanticState {
    /// Construct one validated semantic archive state.
    ///
    /// # Errors
    ///
    /// Returns [`RoastArchiveHistoryError::InvalidSemanticState`] for zero domains or roots,
    /// inconsistent counters, or an absent/present transaction root inconsistent with its count.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet: DepositWalletId,
        network: [u8; 32],
        generation: u64,
        attempt_count: u64,
        transaction_count: u64,
        family_count: u64,
        view_root: [u8; 32],
        transaction_root: Option<[u8; 32]>,
        family_root: [u8; 32],
    ) -> Result<Self, RoastArchiveHistoryError> {
        let state = Self {
            wallet,
            network,
            generation,
            attempt_count,
            transaction_count,
            family_count,
            view_root,
            transaction_root,
            family_root,
        };
        state.validate()?;
        Ok(state)
    }

    /// Validate the state shape independently of any predecessor.
    ///
    /// # Errors
    ///
    /// Returns [`RoastArchiveHistoryError::InvalidSemanticState`] if the state cannot represent a
    /// current-format archive endpoint.
    pub fn validate(self) -> Result<(), RoastArchiveHistoryError> {
        if self.wallet.0 == [0; 32]
            || self.network == [0; 32]
            || self.view_root == [0; 32]
            || self.family_root == [0; 32]
            || self.transaction_root == Some([0; 32])
            || (self.transaction_count == 0) != self.transaction_root.is_none()
            || (self.generation == 0) != (self.attempt_count == 0)
            || (self.attempt_count == 0 && self.transaction_count != 0)
            || (self.attempt_count == 0) != (self.family_count == 0)
            || self.family_count > self.attempt_count
        {
            return Err(RoastArchiveHistoryError::InvalidSemanticState);
        }
        Ok(())
    }

    #[must_use]
    pub const fn wallet_id(self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn network_id(self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn attempt_count(self) -> u64 {
        self.attempt_count
    }

    #[must_use]
    pub const fn transaction_count(self) -> u64 {
        self.transaction_count
    }

    #[must_use]
    pub const fn family_count(self) -> u64 {
        self.family_count
    }

    #[must_use]
    pub const fn view_root(self) -> [u8; 32] {
        self.view_root
    }

    #[must_use]
    pub const fn transaction_root(self) -> Option<[u8; 32]> {
        self.transaction_root
    }

    #[must_use]
    pub const fn family_root(self) -> [u8; 32] {
        self.family_root
    }

    /// Stable digest signed alongside a certified history endpoint.
    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(SEMANTIC_STATE_DOMAIN);
        hasher.update(&self.wallet.0);
        hasher.update(&self.network);
        hasher.update(&self.generation.to_le_bytes());
        hasher.update(&self.attempt_count.to_le_bytes());
        hasher.update(&self.transaction_count.to_le_bytes());
        hasher.update(&self.family_count.to_le_bytes());
        hasher.update(&self.view_root);
        hash_optional_digest(&mut hasher, self.transaction_root);
        hasher.update(&self.family_root);
        *hasher.finalize().as_bytes()
    }

    fn validate_successor(self, successor: Self) -> Result<(), RoastArchiveHistoryError> {
        self.validate()?;
        successor.validate()?;
        if self.wallet != successor.wallet || self.network != successor.network {
            return Err(RoastArchiveHistoryError::WrongHistoryDomain);
        }
        if self.generation.checked_add(1) != Some(successor.generation) {
            return Err(if self.generation == u64::MAX {
                RoastArchiveHistoryError::GenerationExhausted
            } else {
                RoastArchiveHistoryError::InvalidSemanticTransition
            });
        }

        let attempt_delta = successor
            .attempt_count
            .checked_sub(self.attempt_count)
            .ok_or(RoastArchiveHistoryError::InvalidSemanticTransition)?;
        let transaction_delta = successor
            .transaction_count
            .checked_sub(self.transaction_count)
            .ok_or(RoastArchiveHistoryError::InvalidSemanticTransition)?;
        let family_delta = successor
            .family_count
            .checked_sub(self.family_count)
            .ok_or(RoastArchiveHistoryError::InvalidSemanticTransition)?;

        // A current-format archive generation is either one batch of new attempts or one
        // transaction mapping. It is never both and never a semantic no-op.
        if (attempt_delta == 0) == (transaction_delta == 0) {
            return Err(RoastArchiveHistoryError::InvalidSemanticTransition);
        }
        if attempt_delta != 0 {
            if transaction_delta != 0
                || family_delta > attempt_delta
                || successor.view_root == self.view_root
                || successor.family_root == self.family_root
                || successor.transaction_root != self.transaction_root
            {
                return Err(RoastArchiveHistoryError::InvalidSemanticTransition);
            }
        } else if transaction_delta != 1
            || family_delta != 0
            || successor.view_root != self.view_root
            || successor.family_root != self.family_root
            || successor.transaction_root == self.transaction_root
        {
            return Err(RoastArchiveHistoryError::InvalidSemanticTransition);
        }
        Ok(())
    }
}

impl TryFrom<RoastArchiveSemanticStateRepr> for RoastArchiveSemanticState {
    type Error = RoastArchiveHistoryError;

    fn try_from(value: RoastArchiveSemanticStateRepr) -> Result<Self, Self::Error> {
        Self::new(
            value.wallet,
            value.network,
            value.generation,
            value.attempt_count,
            value.transaction_count,
            value.family_count,
            value.view_root,
            value.transaction_root,
            value.family_root,
        )
    }
}

impl<'de> Deserialize<'de> for RoastArchiveSemanticState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(RoastArchiveSemanticStateRepr::deserialize(deserializer)?)
            .map_err(D::Error::custom)
    }
}

/// One authenticated, perfect dyadic subtree of semantic archive transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RoastArchiveHistorySummary {
    start_generation: u64,
    end_generation: u64,
    start_state: [u8; 32],
    end_state: [u8; 32],
    height: u8,
    digest: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoastArchiveHistorySummaryRepr {
    start_generation: u64,
    end_generation: u64,
    start_state: [u8; 32],
    end_state: [u8; 32],
    height: u8,
    digest: [u8; 32],
}

impl RoastArchiveHistorySummary {
    /// Create the generation-`g` leaf binding state `g - 1` to state `g`.
    ///
    /// # Errors
    ///
    /// Returns an error unless `current` is one valid current-format semantic successor of
    /// `previous`.
    pub fn leaf(
        previous: RoastArchiveSemanticState,
        current: RoastArchiveSemanticState,
    ) -> Result<Self, RoastArchiveHistoryError> {
        previous.validate_successor(current)?;
        let mut summary = Self {
            start_generation: previous.generation,
            end_generation: current.generation,
            start_state: previous.digest(),
            end_state: current.digest(),
            height: 0,
            digest: [0; 32],
        };
        summary.digest = history_leaf_digest(previous.wallet, previous.network, summary);
        summary.validate_shape()?;
        Ok(summary)
    }

    /// Merge adjacent, equal-height summaries into their unique dyadic parent.
    ///
    /// # Errors
    ///
    /// Returns an error for different heights, a non-aligned or non-contiguous generation range,
    /// or a semantic-state boundary mismatch.
    pub fn merge(
        wallet: DepositWalletId,
        network: [u8; 32],
        left: Self,
        right: Self,
    ) -> Result<Self, RoastArchiveHistoryError> {
        validate_history_domain(wallet, network)?;
        left.validate_commitment_for_domain(wallet, network)?;
        right.validate_commitment_for_domain(wallet, network)?;
        if left.height != right.height {
            return Err(RoastArchiveHistoryError::InvalidSummary);
        }
        if left.end_generation != right.start_generation {
            return Err(RoastArchiveHistoryError::NonContiguousHistory);
        }
        if left.end_state != right.start_state {
            return Err(RoastArchiveHistoryError::StateBoundaryMismatch);
        }
        let height =
            left.height.checked_add(1).ok_or(RoastArchiveHistoryError::GenerationExhausted)?;
        let width = summary_width(height)?;
        if left.start_generation % width != 0 {
            return Err(RoastArchiveHistoryError::InvalidSummary);
        }
        let mut parent = Self {
            start_generation: left.start_generation,
            end_generation: right.end_generation,
            start_state: left.start_state,
            end_state: right.end_state,
            height,
            digest: [0; 32],
        };
        parent.digest = history_parent_digest(wallet, network, parent, left, right);
        parent.validate_shape()?;
        Ok(parent)
    }

    #[must_use]
    pub const fn start_generation(self) -> u64 {
        self.start_generation
    }

    #[must_use]
    pub const fn end_generation(self) -> u64 {
        self.end_generation
    }

    #[must_use]
    pub const fn start_state(self) -> [u8; 32] {
        self.start_state
    }

    #[must_use]
    pub const fn end_state(self) -> [u8; 32] {
        self.end_state
    }

    #[must_use]
    pub const fn height(self) -> u8 {
        self.height
    }

    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    fn validate_shape(self) -> Result<(), RoastArchiveHistoryError> {
        let width = summary_width(self.height)?;
        if self.start_state == [0; 32]
            || self.end_state == [0; 32]
            || self.digest == [0; 32]
            || self.start_generation % width != 0
            || self.start_generation.checked_add(width) != Some(self.end_generation)
        {
            return Err(RoastArchiveHistoryError::InvalidSummary);
        }
        Ok(())
    }

    fn validate_commitment_for_domain(
        self,
        wallet: DepositWalletId,
        network: [u8; 32],
    ) -> Result<(), RoastArchiveHistoryError> {
        validate_history_domain(wallet, network)?;
        self.validate_shape()?;
        if self.height == 0 && self.digest != history_leaf_digest(wallet, network, self) {
            return Err(RoastArchiveHistoryError::InvalidSummary);
        }
        Ok(())
    }

    fn hash_fields(self, hasher: &mut blake3::Hasher) {
        hasher.update(&self.start_generation.to_le_bytes());
        hasher.update(&self.end_generation.to_le_bytes());
        hasher.update(&self.start_state);
        hasher.update(&self.end_state);
        hasher.update(&[self.height]);
        hasher.update(&self.digest);
    }
}

impl TryFrom<RoastArchiveHistorySummaryRepr> for RoastArchiveHistorySummary {
    type Error = RoastArchiveHistoryError;

    fn try_from(value: RoastArchiveHistorySummaryRepr) -> Result<Self, Self::Error> {
        let summary = Self {
            start_generation: value.start_generation,
            end_generation: value.end_generation,
            start_state: value.start_state,
            end_state: value.end_state,
            height: value.height,
            digest: value.digest,
        };
        summary.validate_shape()?;
        Ok(summary)
    }
}

impl<'de> Deserialize<'de> for RoastArchiveHistorySummary {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(RoastArchiveHistorySummaryRepr::deserialize(deserializer)?)
            .map_err(D::Error::custom)
    }
}

/// Canonical MMR frontier for one wallet/network semantic archive history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RoastArchiveHistoryFrontier {
    wallet: DepositWalletId,
    network: [u8; 32],
    leaf_count: u64,
    peaks: Vec<RoastArchiveHistorySummary>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoastArchiveHistoryFrontierRepr {
    wallet: DepositWalletId,
    network: [u8; 32],
    leaf_count: u64,
    #[serde(deserialize_with = "deserialize_history_peaks")]
    peaks: Vec<RoastArchiveHistorySummary>,
}

impl RoastArchiveHistoryFrontier {
    /// Construct the canonical empty frontier for a wallet/network domain.
    ///
    /// # Errors
    ///
    /// Returns [`RoastArchiveHistoryError::InvalidFrontier`] for a zero wallet or network domain.
    pub fn empty(
        wallet: DepositWalletId,
        network: [u8; 32],
    ) -> Result<Self, RoastArchiveHistoryError> {
        validate_history_domain(wallet, network)?;
        Ok(Self { wallet, network, leaf_count: 0, peaks: Vec::new() })
    }

    /// Reconstruct and validate a frontier from transmitted or persisted peak summaries.
    ///
    /// # Errors
    ///
    /// Returns an error unless the peaks are the unique ordered dyadic decomposition of
    /// `[0, leaf_count)` with matching semantic-state boundaries.
    pub fn from_peaks(
        wallet: DepositWalletId,
        network: [u8; 32],
        leaf_count: u64,
        peaks: Vec<RoastArchiveHistorySummary>,
    ) -> Result<Self, RoastArchiveHistoryError> {
        let frontier = Self { wallet, network, leaf_count, peaks };
        frontier.validate()?;
        Ok(frontier)
    }

    /// Append one locally validated semantic transition.
    ///
    /// # Errors
    ///
    /// Returns an error if `previous` is not the exact current endpoint, `current` is not its
    /// successor, or the frontier is malformed.
    pub fn append_transition(
        &mut self,
        previous: RoastArchiveSemanticState,
        current: RoastArchiveSemanticState,
    ) -> Result<RoastArchiveHistorySummary, RoastArchiveHistoryError> {
        self.validate()?;
        self.validate_domain(previous)?;
        self.validate_domain(current)?;
        if previous.generation != self.leaf_count {
            return Err(RoastArchiveHistoryError::SourceEndpointMismatch);
        }
        if let Some(end_state) = self.end_state() {
            if end_state != previous.digest() {
                return Err(RoastArchiveHistoryError::SourceEndpointMismatch);
            }
        }
        let leaf = RoastArchiveHistorySummary::leaf(previous, current)?;
        self.append_summary(leaf)?;
        Ok(leaf)
    }

    /// Append one authenticated dyadic suffix summary.
    ///
    /// This operation checks its generation and semantic-state boundaries. A non-leaf summary is
    /// a Merkle proof element: its internal digest is authenticated only when the resulting root
    /// is compared with a committee-certified target via
    /// [`RoastArchiveHistoryConsistencyProof::verify`].
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, misaligned, non-contiguous, or boundary-incompatible input.
    pub fn append_summary(
        &mut self,
        summary: RoastArchiveHistorySummary,
    ) -> Result<(), RoastArchiveHistoryError> {
        let mut staged = self.clone();
        staged.append_summary_in_place(summary)?;
        *self = staged;
        Ok(())
    }

    fn append_summary_in_place(
        &mut self,
        mut summary: RoastArchiveHistorySummary,
    ) -> Result<(), RoastArchiveHistoryError> {
        self.validate()?;
        summary.validate_commitment_for_domain(self.wallet, self.network)?;
        if summary.start_generation != self.leaf_count {
            return Err(RoastArchiveHistoryError::NonContiguousHistory);
        }
        if let Some(end_state) = self.end_state() {
            if end_state != summary.start_state {
                return Err(RoastArchiveHistoryError::StateBoundaryMismatch);
            }
        }
        let appended_width = summary_width(summary.height)?;
        let previous_count = self.leaf_count;
        let new_count = previous_count
            .checked_add(appended_width)
            .ok_or(RoastArchiveHistoryError::GenerationExhausted)?;

        while previous_count & summary_width(summary.height)? != 0 {
            let left = self.peaks.pop().ok_or(RoastArchiveHistoryError::InvalidFrontier)?;
            summary = RoastArchiveHistorySummary::merge(self.wallet, self.network, left, summary)?;
        }
        self.peaks.push(summary);
        self.leaf_count = new_count;
        self.validate()
    }

    /// Validate the canonical frontier shape.
    ///
    /// # Errors
    ///
    /// Returns an error for resource overflow, non-canonical peaks, gaps, or state-boundary
    /// disagreement.
    pub fn validate(&self) -> Result<(), RoastArchiveHistoryError> {
        validate_history_domain(self.wallet, self.network)
            .map_err(|_| RoastArchiveHistoryError::InvalidFrontier)?;
        if self.peaks.len() > MAX_ROAST_ARCHIVE_HISTORY_PEAKS
            || usize::try_from(self.leaf_count.count_ones())
                .map_err(|_| RoastArchiveHistoryError::InvalidFrontier)?
                != self.peaks.len()
        {
            return Err(RoastArchiveHistoryError::InvalidFrontier);
        }

        let expected_heights = (0..u64::BITS)
            .rev()
            .filter(|height| self.leaf_count & (1_u64 << height) != 0)
            .map(|height| u8::try_from(height).expect("u64 history height fits u8"));
        if self.peaks.iter().map(|peak| peak.height).ne(expected_heights) {
            return Err(RoastArchiveHistoryError::InvalidFrontier);
        }

        let mut generation = 0_u64;
        let mut state = None;
        for peak in &self.peaks {
            peak.validate_commitment_for_domain(self.wallet, self.network)?;
            if peak.start_generation != generation {
                return Err(RoastArchiveHistoryError::NonContiguousHistory);
            }
            if state.is_some_and(|previous| previous != peak.start_state) {
                return Err(RoastArchiveHistoryError::StateBoundaryMismatch);
            }
            generation = peak.end_generation;
            state = Some(peak.end_state);
        }
        if generation != self.leaf_count {
            return Err(RoastArchiveHistoryError::InvalidFrontier);
        }
        Ok(())
    }

    /// Require this frontier to be the exact history endpoint for `state`.
    ///
    /// # Errors
    ///
    /// Returns an error if the wallet, network, generation, or final semantic-state digest differs.
    pub fn validate_endpoint(
        &self,
        state: RoastArchiveSemanticState,
    ) -> Result<(), RoastArchiveHistoryError> {
        self.validate()?;
        state.validate()?;
        self.validate_domain(state)?;
        if state.generation != self.leaf_count
            || self.end_state().is_some_and(|end| end != state.digest())
        {
            return Err(RoastArchiveHistoryError::TargetEndpointMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn network_id(&self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    #[must_use]
    pub fn peaks(&self) -> &[RoastArchiveHistorySummary] {
        &self.peaks
    }

    #[must_use]
    pub fn start_state(&self) -> Option<[u8; 32]> {
        self.peaks.first().map(|peak| peak.start_state)
    }

    #[must_use]
    pub fn end_state(&self) -> Option<[u8; 32]> {
        self.peaks.last().map(|peak| peak.end_state)
    }

    /// Stable root committed by a certified archive endpoint.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(HISTORY_ROOT_DOMAIN);
        hasher.update(&self.wallet.0);
        hasher.update(&self.network);
        hasher.update(&self.leaf_count.to_le_bytes());
        hasher.update(
            &u64::try_from(self.peaks.len())
                .expect("bounded history peaks length fits u64")
                .to_le_bytes(),
        );
        for peak in &self.peaks {
            peak.hash_fields(&mut hasher);
        }
        *hasher.finalize().as_bytes()
    }

    fn validate_domain(
        &self,
        state: RoastArchiveSemanticState,
    ) -> Result<(), RoastArchiveHistoryError> {
        if self.wallet != state.wallet || self.network != state.network {
            return Err(RoastArchiveHistoryError::WrongHistoryDomain);
        }
        Ok(())
    }
}

impl TryFrom<RoastArchiveHistoryFrontierRepr> for RoastArchiveHistoryFrontier {
    type Error = RoastArchiveHistoryError;

    fn try_from(value: RoastArchiveHistoryFrontierRepr) -> Result<Self, Self::Error> {
        Self::from_peaks(value.wallet, value.network, value.leaf_count, value.peaks)
    }
}

impl<'de> Deserialize<'de> for RoastArchiveHistoryFrontier {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(RoastArchiveHistoryFrontierRepr::deserialize(deserializer)?)
            .map_err(D::Error::custom)
    }
}

/// Compact append-only proof from one certified archive endpoint to another.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RoastArchiveHistoryConsistencyProof {
    source_leaf_count: u64,
    source_peaks: Vec<RoastArchiveHistorySummary>,
    suffix: Vec<RoastArchiveHistorySummary>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoastArchiveHistoryConsistencyProofRepr {
    source_leaf_count: u64,
    #[serde(deserialize_with = "deserialize_history_peaks")]
    source_peaks: Vec<RoastArchiveHistorySummary>,
    #[serde(deserialize_with = "deserialize_history_suffix")]
    suffix: Vec<RoastArchiveHistorySummary>,
}

impl RoastArchiveHistoryConsistencyProof {
    /// Build a canonical compact proof from a source frontier and contiguous suffix summaries.
    ///
    /// The input may contain individual leaves or already-merged summaries. Mergeable adjacent
    /// summaries are canonicalized before the proof is returned.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or discontinuous input, a semantic-state boundary mismatch,
    /// or a proof exceeding the fixed `u64` resource ceiling.
    pub fn new(
        source: &RoastArchiveHistoryFrontier,
        source_state: RoastArchiveSemanticState,
        suffix: &[RoastArchiveHistorySummary],
    ) -> Result<Self, RoastArchiveHistoryError> {
        source.validate()?;
        source
            .validate_endpoint(source_state)
            .map_err(|_| RoastArchiveHistoryError::SourceEndpointMismatch)?;
        let suffix = canonicalize_suffix(
            source.wallet,
            source.network,
            source.leaf_count,
            Some(source_state.digest()),
            suffix,
        )?;
        let proof = Self {
            source_leaf_count: source.leaf_count,
            source_peaks: source.peaks.clone(),
            suffix,
        };
        proof.validate_resource_shape()?;
        Ok(proof)
    }

    /// Verify exact append-only consistency between two authenticated semantic endpoints.
    ///
    /// The endpoint certification layer must authenticate all four supplied values. This method
    /// then proves that the target history consists of the exact source history followed by the
    /// proof suffix.
    ///
    /// # Errors
    ///
    /// Returns an error for a domain or endpoint mismatch, a malformed/non-canonical proof, or a
    /// source/target root mismatch.
    pub fn verify(
        &self,
        source_state: RoastArchiveSemanticState,
        source_root: [u8; 32],
        target_state: RoastArchiveSemanticState,
        target_root: [u8; 32],
    ) -> Result<VerifiedRoastArchiveHistoryConsistency, RoastArchiveHistoryError> {
        self.validate_resource_shape()?;
        source_state.validate()?;
        target_state.validate()?;
        if source_state.wallet != target_state.wallet
            || source_state.network != target_state.network
        {
            return Err(RoastArchiveHistoryError::WrongHistoryDomain);
        }
        if source_state.generation != self.source_leaf_count {
            return Err(RoastArchiveHistoryError::SourceEndpointMismatch);
        }

        let source = RoastArchiveHistoryFrontier::from_peaks(
            source_state.wallet,
            source_state.network,
            self.source_leaf_count,
            self.source_peaks.clone(),
        )?;
        source
            .validate_endpoint(source_state)
            .map_err(|_| RoastArchiveHistoryError::SourceEndpointMismatch)?;
        if source.root() != source_root {
            return Err(RoastArchiveHistoryError::SourceRootMismatch);
        }

        let canonical_suffix = canonicalize_suffix(
            source.wallet,
            source.network,
            source.leaf_count,
            Some(source_state.digest()),
            &self.suffix,
        )?;
        if canonical_suffix != self.suffix {
            return Err(RoastArchiveHistoryError::NonCanonicalProof);
        }

        let mut target = source.clone();
        for summary in &self.suffix {
            target.append_summary(*summary)?;
        }
        if self.suffix.is_empty() && target_state.digest() != source_state.digest() {
            return Err(RoastArchiveHistoryError::TargetEndpointMismatch);
        }
        target
            .validate_endpoint(target_state)
            .map_err(|_| RoastArchiveHistoryError::TargetEndpointMismatch)?;
        if target.root() != target_root {
            return Err(RoastArchiveHistoryError::TargetRootMismatch);
        }

        Ok(VerifiedRoastArchiveHistoryConsistency {
            source_root,
            target_root,
            source_state,
            target_state,
            target,
        })
    }

    #[must_use]
    pub const fn source_leaf_count(&self) -> u64 {
        self.source_leaf_count
    }

    #[must_use]
    pub fn source_peaks(&self) -> &[RoastArchiveHistorySummary] {
        &self.source_peaks
    }

    #[must_use]
    pub fn suffix(&self) -> &[RoastArchiveHistorySummary] {
        &self.suffix
    }

    fn validate_resource_shape(&self) -> Result<(), RoastArchiveHistoryError> {
        if self.source_peaks.len() > MAX_ROAST_ARCHIVE_HISTORY_PEAKS
            || self.suffix.len() > MAX_ROAST_ARCHIVE_HISTORY_SUFFIX_SUMMARIES
        {
            return Err(RoastArchiveHistoryError::ProofTooLarge);
        }
        for summary in self.source_peaks.iter().chain(&self.suffix) {
            summary.validate_shape()?;
        }
        Ok(())
    }
}

impl TryFrom<RoastArchiveHistoryConsistencyProofRepr> for RoastArchiveHistoryConsistencyProof {
    type Error = RoastArchiveHistoryError;

    fn try_from(value: RoastArchiveHistoryConsistencyProofRepr) -> Result<Self, Self::Error> {
        let proof = Self {
            source_leaf_count: value.source_leaf_count,
            source_peaks: value.source_peaks,
            suffix: value.suffix,
        };
        proof.validate_resource_shape()?;
        Ok(proof)
    }
}

impl<'de> Deserialize<'de> for RoastArchiveHistoryConsistencyProof {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(RoastArchiveHistoryConsistencyProofRepr::deserialize(deserializer)?)
            .map_err(D::Error::custom)
    }
}

/// Non-serializable result of exact endpoint and consistency-proof verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRoastArchiveHistoryConsistency {
    source_root: [u8; 32],
    target_root: [u8; 32],
    source_state: RoastArchiveSemanticState,
    target_state: RoastArchiveSemanticState,
    target: RoastArchiveHistoryFrontier,
}

impl VerifiedRoastArchiveHistoryConsistency {
    #[must_use]
    pub const fn source_root(&self) -> [u8; 32] {
        self.source_root
    }

    #[must_use]
    pub const fn target_root(&self) -> [u8; 32] {
        self.target_root
    }

    #[must_use]
    pub const fn source_state(&self) -> RoastArchiveSemanticState {
        self.source_state
    }

    #[must_use]
    pub const fn target_state(&self) -> RoastArchiveSemanticState {
        self.target_state
    }

    #[must_use]
    pub const fn source_generation(&self) -> u64 {
        self.source_state.generation
    }

    #[must_use]
    pub const fn target_generation(&self) -> u64 {
        self.target_state.generation
    }

    #[must_use]
    pub fn target_frontier(&self) -> &RoastArchiveHistoryFrontier {
        &self.target
    }
}

fn validate_history_domain(
    wallet: DepositWalletId,
    network: [u8; 32],
) -> Result<(), RoastArchiveHistoryError> {
    if wallet.0 == [0; 32] || network == [0; 32] {
        return Err(RoastArchiveHistoryError::InvalidFrontier);
    }
    Ok(())
}

fn summary_width(height: u8) -> Result<u64, RoastArchiveHistoryError> {
    1_u64.checked_shl(u32::from(height)).ok_or(RoastArchiveHistoryError::InvalidSummary)
}

fn history_leaf_digest(
    wallet: DepositWalletId,
    network: [u8; 32],
    summary: RoastArchiveHistorySummary,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(HISTORY_LEAF_DOMAIN);
    hasher.update(&wallet.0);
    hasher.update(&network);
    hasher.update(&summary.start_generation.to_le_bytes());
    hasher.update(&summary.end_generation.to_le_bytes());
    hasher.update(&summary.start_state);
    hasher.update(&summary.end_state);
    *hasher.finalize().as_bytes()
}

fn history_parent_digest(
    wallet: DepositWalletId,
    network: [u8; 32],
    parent: RoastArchiveHistorySummary,
    left: RoastArchiveHistorySummary,
    right: RoastArchiveHistorySummary,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(HISTORY_PARENT_DOMAIN);
    hasher.update(&wallet.0);
    hasher.update(&network);
    hasher.update(&parent.start_generation.to_le_bytes());
    hasher.update(&parent.end_generation.to_le_bytes());
    hasher.update(&parent.start_state);
    hasher.update(&parent.end_state);
    hasher.update(&[parent.height]);
    left.hash_fields(&mut hasher);
    right.hash_fields(&mut hasher);
    *hasher.finalize().as_bytes()
}

fn hash_optional_digest(hasher: &mut blake3::Hasher, digest: Option<[u8; 32]>) {
    match digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn canonicalize_suffix(
    wallet: DepositWalletId,
    network: [u8; 32],
    source_leaf_count: u64,
    source_end_state: Option<[u8; 32]>,
    suffix: &[RoastArchiveHistorySummary],
) -> Result<Vec<RoastArchiveHistorySummary>, RoastArchiveHistoryError> {
    validate_history_domain(wallet, network)?;
    let mut generation = source_leaf_count;
    let mut state = source_end_state;
    let mut compact = Vec::<RoastArchiveHistorySummary>::new();

    for summary in suffix {
        summary.validate_commitment_for_domain(wallet, network)?;
        if summary.start_generation != generation {
            return Err(RoastArchiveHistoryError::NonContiguousHistory);
        }
        if state.is_some_and(|previous| previous != summary.start_state) {
            return Err(RoastArchiveHistoryError::StateBoundaryMismatch);
        }
        generation = summary.end_generation;
        state = Some(summary.end_state);
        compact.push(*summary);

        while compact.len() >= 2 {
            let right = compact[compact.len() - 1];
            let left = compact[compact.len() - 2];
            if left.height != right.height {
                break;
            }
            let parent_height =
                left.height.checked_add(1).ok_or(RoastArchiveHistoryError::GenerationExhausted)?;
            let parent_width = summary_width(parent_height)?;
            if left.start_generation % parent_width != 0 {
                break;
            }
            let right = compact.pop().expect("length checked");
            let left = compact.pop().expect("length checked");
            compact.push(RoastArchiveHistorySummary::merge(wallet, network, left, right)?);
        }
    }
    if compact.len() > MAX_ROAST_ARCHIVE_HISTORY_SUFFIX_SUMMARIES {
        return Err(RoastArchiveHistoryError::ProofTooLarge);
    }
    Ok(compact)
}

fn deserialize_history_peaks<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<RoastArchiveHistorySummary>, D::Error> {
    deserializer.deserialize_seq(BoundedSummaryVisitor {
        maximum: MAX_ROAST_ARCHIVE_HISTORY_PEAKS,
        label: "ROAST archive history peaks",
    })
}

fn deserialize_history_suffix<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<RoastArchiveHistorySummary>, D::Error> {
    deserializer.deserialize_seq(BoundedSummaryVisitor {
        maximum: MAX_ROAST_ARCHIVE_HISTORY_SUFFIX_SUMMARIES,
        label: "ROAST archive history proof suffix",
    })
}

struct BoundedSummaryVisitor {
    maximum: usize,
    label: &'static str,
}

impl<'de> Visitor<'de> for BoundedSummaryVisitor {
    type Value = Vec<RoastArchiveHistorySummary>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} with at most {} entries", self.label, self.maximum)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        if sequence.size_hint().is_some_and(|size| size > self.maximum) {
            return Err(A::Error::custom("ROAST archive history vector exceeds its bound"));
        }
        let mut summaries = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
        while let Some(summary) = sequence.next_element()? {
            if summaries.len() == self.maximum {
                return Err(A::Error::custom("ROAST archive history vector exceeds its bound"));
            }
            summaries.push(summary);
        }
        Ok(summaries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WALLET: DepositWalletId = DepositWalletId([0x11; 32]);
    const OTHER_WALLET: DepositWalletId = DepositWalletId([0x12; 32]);
    const NETWORK: [u8; 32] = [0x21; 32];
    const OTHER_NETWORK: [u8; 32] = [0x22; 32];
    const EMPTY_VIEW_ROOT: [u8; 32] = [0x31; 32];
    const EMPTY_FAMILY_ROOT: [u8; 32] = [0x32; 32];

    fn digest(label: u64) -> [u8; 32] {
        *blake3::hash(&label.to_le_bytes()).as_bytes()
    }

    fn genesis(wallet: DepositWalletId, network: [u8; 32]) -> RoastArchiveSemanticState {
        RoastArchiveSemanticState::new(
            wallet,
            network,
            0,
            0,
            0,
            0,
            EMPTY_VIEW_ROOT,
            None,
            EMPTY_FAMILY_ROOT,
        )
        .unwrap()
    }

    fn attempt_successor(
        previous: RoastArchiveSemanticState,
        attempts: u64,
        new_family: bool,
    ) -> RoastArchiveSemanticState {
        RoastArchiveSemanticState::new(
            previous.wallet,
            previous.network,
            previous.generation.checked_add(1).unwrap(),
            previous.attempt_count.checked_add(attempts).unwrap(),
            previous.transaction_count,
            previous.family_count + u64::from(new_family),
            digest(10_000 + previous.generation),
            previous.transaction_root,
            digest(20_000 + previous.generation),
        )
        .unwrap()
    }

    fn transaction_successor(previous: RoastArchiveSemanticState) -> RoastArchiveSemanticState {
        RoastArchiveSemanticState::new(
            previous.wallet,
            previous.network,
            previous.generation.checked_add(1).unwrap(),
            previous.attempt_count,
            previous.transaction_count.checked_add(1).unwrap(),
            previous.family_count,
            previous.view_root,
            Some(digest(30_000 + previous.generation)),
            previous.family_root,
        )
        .unwrap()
    }

    fn history(
        generations: usize,
    ) -> (
        Vec<RoastArchiveSemanticState>,
        Vec<RoastArchiveHistorySummary>,
        Vec<RoastArchiveHistoryFrontier>,
    ) {
        let mut states = vec![genesis(WALLET, NETWORK)];
        let mut leaves = Vec::with_capacity(generations);
        let mut frontier = RoastArchiveHistoryFrontier::empty(WALLET, NETWORK).unwrap();
        let mut frontiers = vec![frontier.clone()];
        for generation in 0..generations {
            let previous = *states.last().unwrap();
            let current = if generation % 3 == 2 {
                transaction_successor(previous)
            } else {
                attempt_successor(previous, 1 + u64::from(generation % 2 == 1), generation == 0)
            };
            let leaf = frontier.append_transition(previous, current).unwrap();
            states.push(current);
            leaves.push(leaf);
            frontiers.push(frontier.clone());
        }
        (states, leaves, frontiers)
    }

    #[test]
    fn semantic_state_is_witness_independent_and_domain_separated() {
        let state = attempt_successor(genesis(WALLET, NETWORK), 2, true);
        assert_eq!(state.digest(), state.digest());

        let other_network = RoastArchiveSemanticState::new(
            WALLET,
            OTHER_NETWORK,
            state.generation,
            state.attempt_count,
            state.transaction_count,
            state.family_count,
            state.view_root,
            state.transaction_root,
            state.family_root,
        )
        .unwrap();
        let other_wallet = RoastArchiveSemanticState::new(
            OTHER_WALLET,
            NETWORK,
            state.generation,
            state.attempt_count,
            state.transaction_count,
            state.family_count,
            state.view_root,
            state.transaction_root,
            state.family_root,
        )
        .unwrap();
        assert_ne!(state.digest(), other_network.digest());
        assert_ne!(state.digest(), other_wallet.digest());
    }

    #[test]
    fn transitions_reject_noop_mixed_and_regressing_updates() {
        let zero = genesis(WALLET, NETWORK);
        let one = attempt_successor(zero, 1, true);
        assert!(RoastArchiveHistorySummary::leaf(zero, one).is_ok());

        let noop = RoastArchiveSemanticState::new(
            WALLET,
            NETWORK,
            2,
            one.attempt_count,
            one.transaction_count,
            one.family_count,
            one.view_root,
            one.transaction_root,
            one.family_root,
        )
        .unwrap();
        assert_eq!(
            RoastArchiveHistorySummary::leaf(one, noop),
            Err(RoastArchiveHistoryError::InvalidSemanticTransition)
        );

        let mixed = RoastArchiveSemanticState::new(
            WALLET,
            NETWORK,
            2,
            one.attempt_count + 1,
            one.transaction_count + 1,
            one.family_count,
            digest(91),
            Some(digest(92)),
            digest(93),
        )
        .unwrap();
        assert_eq!(
            RoastArchiveHistorySummary::leaf(one, mixed),
            Err(RoastArchiveHistoryError::InvalidSemanticTransition)
        );
    }

    #[test]
    fn frontier_boundaries_and_heights_cover_power_of_two_edges() {
        let (states, _, frontiers) = history(65);
        for generation in [0_usize, 1, 2, 3, 4, 63, 64, 65] {
            let frontier = &frontiers[generation];
            frontier.validate().unwrap();
            frontier.validate_endpoint(states[generation]).unwrap();
            assert_eq!(frontier.leaf_count(), u64::try_from(generation).unwrap());
            assert_eq!(frontier.peaks().len(), usize::try_from(generation.count_ones()).unwrap());
        }
        assert_eq!(
            frontiers[63].peaks().iter().map(|peak| peak.height()).collect::<Vec<_>>(),
            [5, 4, 3, 2, 1, 0]
        );
        assert_eq!(frontiers[64].peaks()[0].height(), 6);
        assert_eq!(
            frontiers[65].peaks().iter().map(|peak| peak.height()).collect::<Vec<_>>(),
            [6, 0]
        );
    }

    #[test]
    fn compact_proof_verifies_exact_authenticated_endpoints() {
        let (states, leaves, frontiers) = history(65);
        for (source, target) in [(0_usize, 1_usize), (1, 2), (2, 3), (3, 4), (5, 63), (63, 65)] {
            let proof = RoastArchiveHistoryConsistencyProof::new(
                &frontiers[source],
                states[source],
                &leaves[source..target],
            )
            .unwrap();
            assert!(proof.suffix().len() <= MAX_ROAST_ARCHIVE_HISTORY_SUFFIX_SUMMARIES);
            let verified = proof
                .verify(
                    states[source],
                    frontiers[source].root(),
                    states[target],
                    frontiers[target].root(),
                )
                .unwrap();
            assert_eq!(verified.source_generation(), u64::try_from(source).unwrap());
            assert_eq!(verified.target_generation(), u64::try_from(target).unwrap());
            assert_eq!(verified.target_frontier(), &frontiers[target]);
        }
    }

    #[test]
    fn fork_splice_is_rejected_even_if_later_counters_match() {
        let (states, leaves, frontiers) = history(4);
        let branch_one = RoastArchiveSemanticState::new(
            WALLET,
            NETWORK,
            2,
            states[1].attempt_count + 2,
            states[1].transaction_count,
            states[1].family_count,
            digest(800_001),
            states[1].transaction_root,
            digest(800_002),
        )
        .unwrap();
        let branch_two = transaction_successor(branch_one);
        assert_eq!(branch_two.attempt_count, states[3].attempt_count);
        assert_eq!(branch_two.transaction_count, states[3].transaction_count);
        assert_eq!(branch_two.family_count, states[3].family_count);
        assert_ne!(branch_two.digest(), states[3].digest());

        let branch_leaf_one = RoastArchiveHistorySummary::leaf(states[1], branch_one).unwrap();
        let branch_leaf_two = RoastArchiveHistorySummary::leaf(branch_one, branch_two).unwrap();
        let branch_proof = RoastArchiveHistoryConsistencyProof::new(
            &frontiers[1],
            states[1],
            &[branch_leaf_one, branch_leaf_two],
        )
        .unwrap();
        assert_eq!(
            branch_proof.verify(states[1], frontiers[1].root(), states[3], frontiers[3].root()),
            Err(RoastArchiveHistoryError::TargetEndpointMismatch)
        );

        let mut spliced = leaves[1];
        spliced.start_state = digest(999_999);
        spliced.digest = history_leaf_digest(WALLET, NETWORK, spliced);
        assert_eq!(
            RoastArchiveHistoryConsistencyProof::new(&frontiers[1], states[1], &[spliced]),
            Err(RoastArchiveHistoryError::StateBoundaryMismatch)
        );
    }

    #[test]
    fn missing_duplicate_and_reordered_suffixes_fail_closed() {
        let (states, leaves, frontiers) = history(8);
        let proof =
            RoastArchiveHistoryConsistencyProof::new(&frontiers[2], states[2], &leaves[2..8])
                .unwrap();
        let mut missing = proof.clone();
        missing.suffix.pop();
        assert!(
            missing.verify(states[2], frontiers[2].root(), states[8], frontiers[8].root()).is_err()
        );

        let mut duplicate = proof.clone();
        duplicate.suffix.insert(0, duplicate.suffix[0]);
        assert_eq!(
            duplicate.verify(states[2], frontiers[2].root(), states[8], frontiers[8].root()),
            Err(RoastArchiveHistoryError::NonContiguousHistory)
        );

        let mut reordered = proof;
        reordered.suffix.reverse();
        assert_eq!(
            reordered.verify(states[2], frontiers[2].root(), states[8], frontiers[8].root()),
            Err(RoastArchiveHistoryError::NonContiguousHistory)
        );
    }

    #[test]
    fn wrong_domain_and_root_replay_fail_closed() {
        let (states, leaves, frontiers) = history(3);
        let proof =
            RoastArchiveHistoryConsistencyProof::new(&frontiers[1], states[1], &leaves[1..3])
                .unwrap();
        assert_eq!(
            proof.verify(states[1], digest(400), states[3], frontiers[3].root()),
            Err(RoastArchiveHistoryError::SourceRootMismatch)
        );
        assert_eq!(
            proof.verify(states[1], frontiers[1].root(), states[3], digest(401)),
            Err(RoastArchiveHistoryError::TargetRootMismatch)
        );

        let replay_target = RoastArchiveSemanticState::new(
            OTHER_WALLET,
            NETWORK,
            states[3].generation,
            states[3].attempt_count,
            states[3].transaction_count,
            states[3].family_count,
            states[3].view_root,
            states[3].transaction_root,
            states[3].family_root,
        )
        .unwrap();
        assert_eq!(
            proof.verify(states[1], frontiers[1].root(), replay_target, frontiers[3].root()),
            Err(RoastArchiveHistoryError::WrongHistoryDomain)
        );
    }

    #[test]
    fn empty_frontier_proof_still_binds_the_certified_genesis_state() {
        let source = genesis(WALLET, NETWORK);
        let alternate = RoastArchiveSemanticState::new(
            WALLET,
            NETWORK,
            0,
            0,
            0,
            0,
            digest(700_001),
            None,
            digest(700_002),
        )
        .unwrap();
        let source_frontier = RoastArchiveHistoryFrontier::empty(WALLET, NETWORK).unwrap();
        let alternate_one = attempt_successor(alternate, 1, true);
        let alternate_leaf = RoastArchiveHistorySummary::leaf(alternate, alternate_one).unwrap();
        let mut alternate_frontier = source_frontier.clone();
        alternate_frontier.append_summary(alternate_leaf).unwrap();
        let proof = RoastArchiveHistoryConsistencyProof::new(
            &source_frontier,
            alternate,
            &[alternate_leaf],
        )
        .unwrap();

        assert_eq!(
            proof.verify(source, source_frontier.root(), alternate_one, alternate_frontier.root()),
            Err(RoastArchiveHistoryError::StateBoundaryMismatch)
        );

        let reflexive =
            RoastArchiveHistoryConsistencyProof::new(&source_frontier, source, &[]).unwrap();
        assert_eq!(
            reflexive.verify(source, source_frontier.root(), alternate, source_frontier.root()),
            Err(RoastArchiveHistoryError::TargetEndpointMismatch)
        );
    }

    #[test]
    fn source_peak_mutation_and_noncanonical_suffix_are_rejected() {
        let (states, leaves, frontiers) = history(10);
        let proof =
            RoastArchiveHistoryConsistencyProof::new(&frontiers[3], states[3], &leaves[3..10])
                .unwrap();

        let mut bad_source = proof.clone();
        bad_source.source_peaks[0].digest[0] ^= 1;
        assert_eq!(
            bad_source.verify(states[3], frontiers[3].root(), states[10], frontiers[10].root()),
            Err(RoastArchiveHistoryError::SourceRootMismatch)
        );

        let mut noncanonical = proof;
        noncanonical.suffix = leaves[3..10].to_vec();
        assert_eq!(
            noncanonical.verify(states[3], frontiers[3].root(), states[10], frontiers[10].root()),
            Err(RoastArchiveHistoryError::NonCanonicalProof)
        );
    }

    #[test]
    fn serialization_is_current_format_only_and_validates_shapes() {
        let (states, leaves, frontiers) = history(5);
        let proof =
            RoastArchiveHistoryConsistencyProof::new(&frontiers[1], states[1], &leaves[1..5])
                .unwrap();
        let encoded = postcard::to_allocvec(&proof).unwrap();
        let restored: RoastArchiveHistoryConsistencyProof = postcard::from_bytes(&encoded).unwrap();
        restored.verify(states[1], frontiers[1].root(), states[5], frontiers[5].root()).unwrap();

        let mut trailing = encoded;
        trailing.push(0);
        assert!(
            !postcard::take_from_bytes::<RoastArchiveHistoryConsistencyProof>(&trailing)
                .map(|(_, remainder)| remainder.is_empty())
                .unwrap_or(false)
        );

        let malformed = RoastArchiveHistorySummaryRepr {
            start_generation: 1,
            end_generation: 3,
            start_state: digest(1),
            end_state: digest(2),
            height: 0,
            digest: digest(3),
        };
        assert_eq!(
            RoastArchiveHistorySummary::try_from(malformed),
            Err(RoastArchiveHistoryError::InvalidSummary)
        );
    }

    #[test]
    fn generation_overflow_and_proof_resource_bounds_fail() {
        let state = RoastArchiveSemanticState::new(
            WALLET,
            NETWORK,
            u64::MAX,
            1,
            0,
            1,
            digest(1),
            None,
            digest(2),
        )
        .unwrap();
        assert_eq!(
            state.validate_successor(state),
            Err(RoastArchiveHistoryError::GenerationExhausted)
        );

        let (_, leaves, frontiers) = history(2);
        let oversized = RoastArchiveHistoryConsistencyProof {
            source_leaf_count: 0,
            source_peaks: Vec::new(),
            suffix: vec![leaves[0]; MAX_ROAST_ARCHIVE_HISTORY_SUFFIX_SUMMARIES + 1],
        };
        assert_eq!(
            oversized.validate_resource_shape(),
            Err(RoastArchiveHistoryError::ProofTooLarge)
        );
        assert_ne!(frontiers[0].root(), [0; 32]);
    }
}
