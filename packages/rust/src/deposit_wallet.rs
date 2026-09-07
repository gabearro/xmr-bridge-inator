//! Monero-specific deposit-address derivation and durable scan/sweep bookkeeping.
//!
//! This module is deliberately transport and RPC agnostic. A caller recognizes outputs through
//! [`crate::deposit_output_scanner::BoundedDepositOutputScanner`] and commits its authenticated
//! [`WalletOutput`] values to [`ScanState`]. Permanent subaddress membership lives in the durable
//! deposit index, not in a process-lifetime registration set. The state can be serialized after
//! each block and rolled back to a known ancestor before scanning a replacement branch.
//!
//! Deposit subaddresses do not require a DKG or a long-lived tweak to threshold shares. The
//! scanner's `key_offset` is the complete scalar which relates the root public spend key to an
//! output's one-time key. The session-bound signer validates untweaked root threshold keys and
//! delegates the unchanged transaction to monero-wallet, whose FROSTLASS builder applies each
//! input's exact offset.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
};

use curve25519_dalek::{
    Scalar as DalekScalar, constants::ED25519_BASEPOINT_POINT, traits::IsIdentity,
};
use monero_oxide::{
    ringct::RctType,
    transaction::{Timelock, Transaction},
};
use monero_wallet::{
    OutputWithDecoys, ViewPair, WalletOutput,
    address::{AddressError, MoneroAddress, Network, SubaddressIndex},
    ed25519::{CompressedPoint, Point, Scalar},
    send::{Change, Eventuality, SignableTransaction},
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as DeError, SeqAccess, Visitor},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    committee::SessionId,
    config::NetworkKind,
    deposit_output_scanner::{
        BoundedDepositOutputScanner, DepositOutputScannerLimits, DepositOutputScannerSetupError,
    },
};

const SCAN_STATE_VERSION: u16 = 9;
/// Monero's deterministic unlock-time clock uses the most recent sixty canonical block
/// timestamps (`BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` in `cryptonote_config.h`).
pub const MONERO_UNLOCK_TIMESTAMP_WINDOW: usize = 60;
const MONERO_BLOCK_TARGET_SECONDS: u64 = 120;
const MONERO_UNLOCK_ALLOWED_DELTA_BLOCKS: u64 = 1;
const MONERO_UNLOCK_ALLOWED_DELTA_SECONDS: u64 =
    MONERO_BLOCK_TARGET_SECONDS * MONERO_UNLOCK_ALLOWED_DELTA_BLOCKS;
// `(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 1) * DIFFICULTY_TARGET_V2 / 2`.
const MONERO_UNLOCK_MEDIAN_PROJECTION_SECONDS: u64 = 3_660;
const MAX_WALLET_OUTPUT_BYTES: usize = 64 * 1024;
/// Monero's consensus upper bound for a non-miner transaction is one million bytes.
pub const MAX_SIGNED_SWEEP_TRANSACTION_BYTES: usize = 1_000_000;
/// Hard bound for monero-wallet's private, non-consensus signing-intent encoding.
pub const MAX_SIGNABLE_SWEEP_TRANSACTION_BYTES: usize = 256 * 1024;
/// Hard bound for the opaque canonical prepared-sweep representation retained for restart.
pub const MAX_PREPARED_SWEEP_INTENT_BYTES: usize = 64 * 1024 * 1024;
/// Maximum exact retired attempt bindings retained for one sweep family.
///
/// The monotonic high-water mark is authoritative. Older burned attempts are compacted from the
/// encrypted snapshot, and can only be recognized again through deterministic reconstruction of
/// an independently quorum-certified [`crate::deposit_consolidation::AttemptBinding`].
pub const MAX_RETAINED_SWEEP_SIGNING_ATTEMPTS: usize = 64;
/// Maximum active or terminal-awaiting-portability sweep families retained locally.
pub const MAX_ACTIVE_SWEEP_RECORDS: usize = 4_096;
/// Maximum unresolved root transactions pinned beyond the ordinary reorganization window.
pub const MAX_PINNED_ROOT_TRANSACTIONS: usize = 4_096;
/// Maximum distinct, fully validated transaction variants retained for one sweep family.
pub const MAX_SWEEP_FAMILY_CANDIDATES: usize = 128;
/// Aggregate exact-byte budget for one sweep family's candidate archive.
pub const MAX_SWEEP_FAMILY_CANDIDATE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of distinct historical block bodies pinned for recognition/backfill evidence.
///
/// Thirty days at Monero's two-minute target is 21,600 blocks. The larger power-of-two bound
/// leaves room for overlapping fixed-horizon backfills without making the durable map unbounded.
pub const MAX_PINNED_HISTORICAL_BLOCKS: usize = 32_768;
/// Maximum scanner outputs admitted atomically from one authenticated historical block.
pub const MAX_HISTORICAL_OUTPUTS_PER_BLOCK: usize = 4_096;
/// Absolute bound shared with the persistent worker's retained-output policy.
pub const MAX_RETAINED_WALLET_OUTPUTS: usize = 1_000_000;
const MAX_DURABLE_STATE_BYTES: usize = 64 * 1024 * 1024;

/// Derive the sole valid FROSTLASS session for one wallet/sweep/attempt tuple.
///
/// A non-zero monotonic attempt number makes a compacted session impossible to reintroduce under a
/// later attempt. Returning `None` for attempt zero keeps malformed history out of every release
/// path without manufacturing a sentinel session.
#[must_use]
pub fn derive_sweep_signing_session(
    wallet: DepositWalletId,
    sweep: SweepId,
    attempt: u64,
) -> Option<SessionId> {
    if wallet.0 == [0_u8; 32] || sweep.0 == [0_u8; 32] || attempt == 0 {
        return None;
    }
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/sweep-signing-session/v1");
    hasher.update(&wallet.0);
    hasher.update(&sweep.0);
    hasher.update(&attempt.to_le_bytes());
    Some(SessionId(*hasher.finalize().as_bytes()))
}

/// A non-primary Monero subaddress index reserved forever once allocated.
///
/// `(0, 0)` is the root address and is rejected. Both components are immutable and the type's
/// deserializer rechecks that invariant.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DepositSubaddressIndex {
    account: u32,
    address: u32,
}

#[derive(Deserialize)]
struct DepositSubaddressIndexRepr {
    account: u32,
    address: u32,
}

impl<'de> Deserialize<'de> for DepositSubaddressIndex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = DepositSubaddressIndexRepr::deserialize(deserializer)?;
        Self::new(value.account, value.address).map_err(serde::de::Error::custom)
    }
}

impl DepositSubaddressIndex {
    /// Construct an immutable non-primary subaddress index.
    ///
    /// # Errors
    ///
    /// Returns [`DepositWalletError::PrimaryAddressIndex`] for `(0, 0)`.
    pub fn new(account: u32, address: u32) -> Result<Self, DepositWalletError> {
        SubaddressIndex::new(account, address).ok_or(DepositWalletError::PrimaryAddressIndex)?;
        Ok(Self { account, address })
    }

    /// Return the Monero account component.
    #[must_use]
    pub const fn account(self) -> u32 {
        self.account
    }

    /// Return the address component within the account.
    #[must_use]
    pub const fn address(self) -> u32 {
        self.address
    }

    fn monero(self) -> SubaddressIndex {
        SubaddressIndex::new(self.account, self.address)
            .expect("DepositSubaddressIndex excludes the primary address")
    }

    fn from_monero(value: SubaddressIndex) -> Self {
        Self { account: value.account(), address: value.address() }
    }
}

/// A canonical Monero subaddress string together with its explicit logical network and index.
///
/// Regtest intentionally uses mainnet address bytes, yet remains distinct in the `network` field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanonicalDepositAddress {
    wallet: DepositWalletId,
    network: NetworkKind,
    index: DepositSubaddressIndex,
    address: String,
}

#[derive(Deserialize)]
struct CanonicalDepositAddressRepr {
    wallet: DepositWalletId,
    network: NetworkKind,
    index: DepositSubaddressIndex,
    address: String,
}

impl<'de> Deserialize<'de> for CanonicalDepositAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = CanonicalDepositAddressRepr::deserialize(deserializer)?;
        let address = Self {
            wallet: value.wallet,
            network: value.network,
            index: value.index,
            address: value.address,
        };
        address.validate().map_err(serde::de::Error::custom)?;
        Ok(address)
    }
}

impl CanonicalDepositAddress {
    /// Return the stable wallet domain which owns this address.
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    /// Return the logical Monero network.
    #[must_use]
    pub const fn network(&self) -> NetworkKind {
        self.network
    }

    /// Return the permanent subaddress index.
    #[must_use]
    pub const fn index(&self) -> DepositSubaddressIndex {
        self.index
    }

    /// Return the canonical Base58 address.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.address
    }

    /// Recheck network, address kind, and canonical string encoding.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is invalid, for another network, is not a subaddress, or has
    /// a non-canonical representation.
    pub fn validate(&self) -> Result<(), DepositWalletError> {
        if self.wallet.0 == [0_u8; 32] {
            return Err(DepositWalletError::InvalidWalletDomain);
        }
        let parsed = MoneroAddress::from_str(address_network(self.network), &self.address)?;
        if !parsed.is_subaddress() {
            return Err(DepositWalletError::NotSubaddress);
        }
        if parsed.to_string() != self.address {
            return Err(DepositWalletError::NonCanonicalAddress);
        }
        Ok(())
    }
}

/// Stable Monero wallet domain shared across proactive threshold-key epochs.
///
/// This identifier commits to the logical network, root public spend key, and public view key. It
/// prevents an allocation or scanner journal from silently changing the common view scalar while
/// revealing no private key material.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DepositWalletId(pub [u8; 32]);

/// In-memory Monero view material used for address derivation and scanner construction.
///
/// The common private view scalar is held by monero-wallet's zeroizing [`ViewPair`] and is never
/// included in a serializable structure from this module.
pub struct DepositAddressDeriver {
    wallet: DepositWalletId,
    network: NetworkKind,
    root_spend_key: [u8; 32],
    public_view_key: [u8; 32],
    private_view_scalar: Zeroizing<[u8; 32]>,
    pair: ViewPair,
}

impl DepositAddressDeriver {
    /// Construct a deriver from the threshold wallet's root public spend key and common private
    /// view scalar. Both inputs must be canonical Ed25519 encodings and the keys must be non-zero.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed/torsioned/identity spend point or a malformed/zero view
    /// scalar.
    pub fn new(
        network: NetworkKind,
        root_spend_key: [u8; 32],
        private_view_scalar: &Zeroizing<[u8; 32]>,
    ) -> Result<Self, DepositWalletError> {
        let spend = decode_root_spend_key(root_spend_key)?;
        let view =
            Option::<DalekScalar>::from(DalekScalar::from_canonical_bytes(**private_view_scalar))
                .ok_or(DepositWalletError::InvalidPrivateViewScalar)?;
        if view == DalekScalar::ZERO {
            return Err(DepositWalletError::ZeroPrivateViewScalar);
        }
        let pair = ViewPair::new(Point::from(spend), Zeroizing::new(Scalar::from(view)))?;
        let public_view_key = pair.view().compress().to_bytes();
        let wallet = derive_wallet_id(network, root_spend_key, public_view_key);
        Ok(Self {
            wallet,
            network,
            root_spend_key,
            public_view_key,
            private_view_scalar: private_view_scalar.clone(),
            pair,
        })
    }

    /// Derive the standard network-aware Monero subaddress at an immutable non-zero index.
    #[must_use]
    pub fn derive(&self, index: DepositSubaddressIndex) -> CanonicalDepositAddress {
        let address =
            self.pair.subaddress(address_network(self.network), index.monero()).to_string();
        CanonicalDepositAddress { wallet: self.wallet, network: self.network, index, address }
    }

    /// Return the canonical primary wallet address used as the consolidation destination.
    #[must_use]
    pub fn primary_address(&self) -> String {
        self.pair.legacy_address(address_network(self.network)).to_string()
    }

    /// Return a standard Monero change specification for the primary threshold wallet.
    ///
    /// The private view scalar remains inside the zeroizing [`ViewPair`]. This is intended for
    /// constructing consolidation transactions whose change returns to the root wallet.
    #[must_use]
    pub fn primary_change(&self) -> Change {
        Change::new(self.pair.clone(), None)
    }

    /// Return the root public spend key shared by every epoch.
    #[must_use]
    pub const fn root_spend_key(&self) -> [u8; 32] {
        self.root_spend_key
    }

    /// Return the public view key committed by [`Self::wallet_id`].
    #[must_use]
    pub const fn public_view_key(&self) -> [u8; 32] {
        self.public_view_key
    }

    /// Return the stable wallet domain shared across proactive threshold-key epochs.
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    /// Construct a bounded-memory output scanner over this exact wallet view.
    ///
    /// Permanent subaddress membership is resolved through the scanner's caller-supplied durable
    /// spend-key lookup and is never copied into process memory.
    ///
    /// # Errors
    ///
    /// Returns an error only if the supplied resource limits are invalid. Wallet key material was
    /// validated when this deriver was constructed.
    pub fn bounded_output_scanner(
        &self,
        limits: DepositOutputScannerLimits,
    ) -> Result<BoundedDepositOutputScanner, DepositOutputScannerSetupError> {
        BoundedDepositOutputScanner::new(
            self.network,
            self.root_spend_key,
            &self.private_view_scalar,
            limits,
        )
    }

    /// Verify an injected/certified address against this wallet, network, account, and index.
    ///
    /// # Errors
    ///
    /// Returns an error if any bound field or the standard Monero derivation differs.
    pub fn verify_address(
        &self,
        address: &CanonicalDepositAddress,
    ) -> Result<(), DepositWalletError> {
        address.validate()?;
        if self.derive(address.index) != *address {
            return Err(DepositWalletError::WrongWalletDomain);
        }
        Ok(())
    }
}

/// A durable blockchain point.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ChainPoint {
    /// Zero-based block height.
    pub height: u64,
    /// Block hash at `height`.
    pub hash: [u8; 32],
}

impl ChainPoint {
    /// Construct a non-zero chain point.
    ///
    /// # Errors
    ///
    /// Returns an error for an all-zero block hash.
    pub fn new(height: u64, hash: [u8; 32]) -> Result<Self, DepositWalletError> {
        if hash == [0_u8; 32] {
            return Err(DepositWalletError::ZeroBlockHash);
        }
        Ok(Self { height, hash })
    }
}

/// One block presented to the scanner state, including its parent binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScannedBlock {
    /// This block's durable chain point.
    pub point: ChainPoint,
    /// Hash of the immediately preceding block.
    pub parent_hash: [u8; 32],
}

/// Non-serializable capability produced by a trusted chain-source adapter.
///
/// Construction is crate-private so an external caller cannot relabel arbitrary RPC bytes as
/// authenticated. [`ScanState::insert_authenticated_historical_outputs`] still rechecks the
/// wallet, fixed verification horizon, retained-chain overlap, timestamp, and parent binding
/// before accepting any output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedHistoricalBlockEvidence {
    wallet: DepositWalletId,
    block: ScannedBlock,
    timestamp: u64,
    verification_horizon: ChainPoint,
    portable_index_head: [u8; 32],
    portable_through_sequence: u64,
    outputs: Vec<PersistedWalletOutput>,
    root_outputs: Vec<PersistedRootOutput>,
}

impl AuthenticatedHistoricalBlockEvidence {
    /// Seal evidence after the chain-source layer authenticated the exact block header and body.
    pub(crate) fn from_authenticated_chain_source(
        wallet: DepositWalletId,
        block: ScannedBlock,
        timestamp: u64,
        verification_horizon: ChainPoint,
        portable_index_head: [u8; 32],
        portable_through_sequence: u64,
        outputs: Vec<PersistedWalletOutput>,
        root_outputs: Vec<PersistedRootOutput>,
    ) -> Result<Self, DepositWalletError> {
        ChainPoint::new(block.point.height, block.point.hash)?;
        ChainPoint::new(verification_horizon.height, verification_horizon.hash)?;
        if wallet.0 == [0; 32]
            || portable_index_head == [0; 32]
            || block.point.height > verification_horizon.height
            || (block.point.height != 0 && block.parent_hash == [0; 32])
            || outputs
                .len()
                .checked_add(root_outputs.len())
                .is_none_or(|count| count > MAX_HISTORICAL_OUTPUTS_PER_BLOCK)
            || ((!outputs.is_empty() || !root_outputs.is_empty()) && portable_through_sequence == 0)
        {
            return Err(DepositWalletError::InvalidHistoricalBlockEvidence);
        }
        Ok(Self {
            wallet,
            block,
            timestamp,
            verification_horizon,
            portable_index_head,
            portable_through_sequence,
            outputs,
            root_outputs,
        })
    }

    /// Wallet domain authenticated by the chain-source adapter.
    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    /// Exact historical block and parent binding.
    #[must_use]
    pub const fn block(&self) -> ScannedBlock {
        self.block
    }

    /// Exact canonical timestamp from the authenticated block header.
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Fixed confirmed head against which the historical body was authenticated.
    #[must_use]
    pub const fn verification_horizon(&self) -> ChainPoint {
        self.verification_horizon
    }

    /// Exact authenticated portable index head used to recognize this output batch.
    #[must_use]
    pub const fn portable_index_head(&self) -> [u8; 32] {
        self.portable_index_head
    }

    /// Last ledger sequence contained in the portable recognition snapshot.
    #[must_use]
    pub const fn portable_through_sequence(&self) -> u64 {
        self.portable_through_sequence
    }

    /// Exact scanner outputs sealed with the authenticated block and portable snapshot.
    #[must_use]
    pub fn outputs(&self) -> &[PersistedWalletOutput] {
        &self.outputs
    }

    /// Exact root/primary scanner outputs sealed with the same block and portable snapshot.
    #[must_use]
    pub fn root_outputs(&self) -> &[PersistedRootOutput] {
        &self.root_outputs
    }
}

/// API-unforgeable proof that one exact recognition anchor is authenticated locally.
///
/// This capability is intentionally neither serializable nor publicly constructible. Consumers
/// may bind a ledger admission to it synchronously, but must verify again after restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRecognitionAnchor {
    wallet: DepositWalletId,
    anchor: ChainPoint,
    verification_horizon: ChainPoint,
}

impl VerifiedRecognitionAnchor {
    /// Wallet whose scanner authenticated this anchor.
    #[must_use]
    pub const fn wallet(self) -> DepositWalletId {
        self.wallet
    }

    /// Exact authenticated recognition point.
    #[must_use]
    pub const fn anchor(self) -> ChainPoint {
        self.anchor
    }

    /// Confirmed scanner tip at verification time.
    #[must_use]
    pub const fn verification_horizon(self) -> ChainPoint {
        self.verification_horizon
    }

    /// Check the complete wallet/point authority carried by this capability.
    #[must_use]
    pub fn authorizes(self, wallet: DepositWalletId, anchor: ChainPoint) -> bool {
        self.wallet.0 == wallet.0
            && self.anchor.height == anchor.height
            && self.anchor.hash == anchor.hash
    }
}

/// Non-serializable binding to one exact completion certificate and its portable terminal record.
///
/// The worker constructs this only after re-validating
/// [`crate::deposit_worker::VerifiedPublicSweepCompletion`] and the matching portable index
/// record. Keeping this as a separate sealed capability prevents the destructive compaction API
/// from accepting raw sweep/input/transaction tuples.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedPortableSweepTerminal {
    wallet: DepositWalletId,
    sweep: SweepId,
    inputs: Vec<WalletOutputId>,
    transaction: [u8; 32],
    completion_certificate: [u8; 32],
    portable_terminal: [u8; 32],
}

impl VerifiedPortableSweepTerminal {
    /// Bind already verified worker and portable-index evidence.
    pub(crate) fn from_verified_public_completion(
        wallet: DepositWalletId,
        sweep: SweepId,
        inputs: Vec<WalletOutputId>,
        transaction: [u8; 32],
        completion_certificate: [u8; 32],
        portable_terminal: [u8; 32],
    ) -> Result<Self, DepositWalletError> {
        if wallet.0 == [0; 32]
            || sweep.0 == [0; 32]
            || inputs.is_empty()
            || inputs.windows(2).any(|window| window[0] >= window[1])
            || inputs.iter().any(|input| input.transaction == [0; 32])
            || transaction == [0; 32]
            || completion_certificate == [0; 32]
            || portable_terminal == [0; 32]
        {
            return Err(DepositWalletError::CertifiedSweepConflict);
        }
        Ok(Self { wallet, sweep, inputs, transaction, completion_certificate, portable_terminal })
    }

    /// Exact completion-certificate digest.
    #[must_use]
    pub const fn completion_certificate(&self) -> [u8; 32] {
        self.completion_certificate
    }

    /// Exact portable terminal-record digest.
    #[must_use]
    pub const fn portable_terminal(&self) -> [u8; 32] {
        self.portable_terminal
    }
}

/// Non-serializable authorization to compact one portable terminal after its transaction is
/// confirmed beyond the retained reorganization fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTerminalCompaction {
    wallet: DepositWalletId,
    sweep: SweepId,
    inputs: Vec<WalletOutputId>,
    transaction: [u8; 32],
    completion_certificate: [u8; 32],
    portable_terminal: [u8; 32],
    confirmation: ChainPoint,
    fence: ChainPoint,
    verification_horizon: ChainPoint,
}

impl VerifiedTerminalCompaction {
    /// Terminal sweep authorized for compaction.
    #[must_use]
    pub const fn sweep(&self) -> SweepId {
        self.sweep
    }

    /// Exact sorted inputs authorized for removal.
    #[must_use]
    pub fn inputs(&self) -> &[WalletOutputId] {
        &self.inputs
    }

    /// Confirmed canonical transaction authorized for root-witness removal.
    #[must_use]
    pub const fn transaction(&self) -> [u8; 32] {
        self.transaction
    }

    /// Completion certificate bound by the verified public terminal.
    #[must_use]
    pub const fn completion_certificate(&self) -> [u8; 32] {
        self.completion_certificate
    }

    /// Portable index terminal record bound by the verified public terminal.
    #[must_use]
    pub const fn portable_terminal(&self) -> [u8; 32] {
        self.portable_terminal
    }

    /// Exact inclusion point already behind the retained reorganization fence.
    #[must_use]
    pub const fn confirmation(&self) -> ChainPoint {
        self.confirmation
    }

    /// Scanner checkpoint which made the confirmation non-rollbackable locally.
    #[must_use]
    pub const fn fence(&self) -> ChainPoint {
        self.fence
    }

    /// Confirmed scanner tip at verification time.
    #[must_use]
    pub const fn verification_horizon(&self) -> ChainPoint {
        self.verification_horizon
    }
}

/// Absolute Monero output identity (`transaction hash`, `index in transaction`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct WalletOutputId {
    /// Hash of the transaction which created the output.
    pub transaction: [u8; 32],
    /// Output index within that transaction.
    pub index_in_transaction: u64,
}

/// Exact scanner output persisted with redundant public identity fields for validation/indexing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PersistedWalletOutput {
    id: WalletOutputId,
    index_on_blockchain: u64,
    output_key: [u8; 32],
    key_offset: [u8; 32],
    subaddress: DepositSubaddressIndex,
    wallet_output: Vec<u8>,
}

impl PersistedWalletOutput {
    /// Capture a monero-wallet scanner result without modifying its one-time key offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the result is not for an authenticated deposit subaddress or its
    /// private wallet encoding exceeds the durable bound.
    pub fn from_scanner(output: &WalletOutput) -> Result<Self, DepositWalletError> {
        let subaddress = output.subaddress().ok_or(DepositWalletError::MissingSubaddress)?;
        let wallet_output = output.serialize();
        if wallet_output.len() > MAX_WALLET_OUTPUT_BYTES {
            return Err(DepositWalletError::WalletOutputTooLarge);
        }
        Ok(Self {
            id: WalletOutputId {
                transaction: output.transaction(),
                index_in_transaction: output.index_in_transaction(),
            },
            index_on_blockchain: output.index_on_blockchain(),
            output_key: output.key().compress().to_bytes(),
            key_offset: <[u8; 32]>::from(output.key_offset()),
            subaddress: DepositSubaddressIndex::from_monero(subaddress),
            wallet_output,
        })
    }

    /// Return the absolute output ID.
    #[must_use]
    pub const fn id(&self) -> WalletOutputId {
        self.id
    }

    /// Return the global output index used for decoy selection.
    #[must_use]
    pub const fn index_on_blockchain(&self) -> u64 {
        self.index_on_blockchain
    }

    /// Return the compressed one-time output key used for burning-bug detection.
    #[must_use]
    pub const fn output_key(&self) -> [u8; 32] {
        self.output_key
    }

    /// Return the exact scalar offset emitted by the scanner.
    #[must_use]
    pub const fn key_offset(&self) -> [u8; 32] {
        self.key_offset
    }

    /// Return the deposit subaddress identified by the scanner.
    #[must_use]
    pub const fn subaddress(&self) -> DepositSubaddressIndex {
        self.subaddress
    }

    /// Decode and exactly validate the pinned monero-wallet private output encoding.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed/trailing bytes or a mismatch with the indexed fields.
    pub fn wallet_output(&self) -> Result<WalletOutput, DepositWalletError> {
        if self.wallet_output.len() > MAX_WALLET_OUTPUT_BYTES {
            return Err(DepositWalletError::WalletOutputTooLarge);
        }
        let mut cursor = Cursor::new(self.wallet_output.as_slice());
        let output =
            WalletOutput::read(&mut cursor).map_err(|_| DepositWalletError::InvalidWalletOutput)?;
        if usize::try_from(cursor.position()).ok() != Some(self.wallet_output.len()) {
            return Err(DepositWalletError::TrailingWalletOutputBytes);
        }
        if output.transaction() != self.id.transaction
            || output.index_in_transaction() != self.id.index_in_transaction
            || output.index_on_blockchain() != self.index_on_blockchain
            || output.key().compress().to_bytes() != self.output_key
            || <[u8; 32]>::from(output.key_offset()) != self.key_offset
            || output.subaddress().map(DepositSubaddressIndex::from_monero) != Some(self.subaddress)
        {
            return Err(DepositWalletError::WalletOutputMetadataMismatch);
        }
        Ok(output)
    }

    /// Verify that an `OutputWithDecoys` retained the scanner's exact key and key offset.
    ///
    /// This is the boundary between RPC-backed decoy selection and transaction construction. The
    /// returned offset is informational; callers must not apply it to threshold shares.
    ///
    /// # Errors
    ///
    /// Returns an error if decoy selection changed the real output material.
    pub fn verify_decoy_input(
        &self,
        input: &OutputWithDecoys,
    ) -> Result<ScannerKeyOffset, DepositWalletError> {
        let output = self.wallet_output()?;
        let signer_position =
            input.decoys().positions().get(usize::from(input.decoys().signer_index())).copied();
        if signer_position != Some(self.index_on_blockchain) {
            return Err(DepositWalletError::ScannerGlobalIndexChanged);
        }
        let signer_members = input.decoys().signer_ring_members();
        if input.key().compress().to_bytes() != self.output_key
            || <[u8; 32]>::from(input.key_offset()) != self.key_offset
            || input.commitment().mask != output.commitment().mask
            || input.commitment().amount != output.commitment().amount
            || signer_members[0].compress().to_bytes() != self.output_key
            || signer_members[1] != output.commitment().commit()
        {
            return Err(DepositWalletError::ScannerOffsetChanged);
        }
        Ok(ScannerKeyOffset(self.key_offset))
    }

    pub(crate) fn validate(&self, root_spend_key: [u8; 32]) -> Result<(), DepositWalletError> {
        self.wallet_output()?;
        let root = decode_root_spend_key(root_spend_key)?;
        let offset =
            Option::<DalekScalar>::from(DalekScalar::from_canonical_bytes(self.key_offset))
                .ok_or(DepositWalletError::InvalidScannerOffset)?;
        let expected = root + (ED25519_BASEPOINT_POINT * offset);
        if expected.compress().to_bytes() != self.output_key {
            return Err(DepositWalletError::WrongOutputKey);
        }
        Ok(())
    }
}

/// Exact primary-address scanner output retained only for cursor and burning-bug safety.
///
/// Consolidation change returns to the root address and is therefore visible to the same scanner.
/// These outputs must remain in the journal so a reorg or duplicate one-time key is handled
/// correctly, but they are deliberately absent from deposit notifications and sweep planning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PersistedRootOutput {
    id: WalletOutputId,
    index_on_blockchain: u64,
    output_key: [u8; 32],
    key_offset: [u8; 32],
    wallet_output: Vec<u8>,
}

impl PersistedRootOutput {
    /// Capture a root/primary-address scanner result.
    ///
    /// # Errors
    ///
    /// Returns an error if the scanner identified a subaddress or the private encoding exceeds
    /// its durable bound.
    pub fn from_scanner(output: &WalletOutput) -> Result<Self, DepositWalletError> {
        if output.subaddress().is_some() {
            return Err(DepositWalletError::UnexpectedSubaddress);
        }
        let wallet_output = output.serialize();
        if wallet_output.len() > MAX_WALLET_OUTPUT_BYTES {
            return Err(DepositWalletError::WalletOutputTooLarge);
        }
        Ok(Self {
            id: WalletOutputId {
                transaction: output.transaction(),
                index_in_transaction: output.index_in_transaction(),
            },
            index_on_blockchain: output.index_on_blockchain(),
            output_key: output.key().compress().to_bytes(),
            key_offset: <[u8; 32]>::from(output.key_offset()),
            wallet_output,
        })
    }

    /// Return the absolute output ID.
    #[must_use]
    pub const fn id(&self) -> WalletOutputId {
        self.id
    }

    /// Return the global output index used by Monero ring selection.
    #[must_use]
    pub const fn index_on_blockchain(&self) -> u64 {
        self.index_on_blockchain
    }

    /// Return the compressed one-time output key used for burning-bug detection.
    #[must_use]
    pub const fn output_key(&self) -> [u8; 32] {
        self.output_key
    }

    /// Return the exact scalar offset emitted by the scanner.
    #[must_use]
    pub const fn key_offset(&self) -> [u8; 32] {
        self.key_offset
    }

    /// Decode and exactly validate the pinned monero-wallet private output encoding.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed/trailing bytes, an unexpected subaddress, or indexed-field
    /// mismatch.
    pub fn wallet_output(&self) -> Result<WalletOutput, DepositWalletError> {
        if self.wallet_output.len() > MAX_WALLET_OUTPUT_BYTES {
            return Err(DepositWalletError::WalletOutputTooLarge);
        }
        let mut cursor = Cursor::new(self.wallet_output.as_slice());
        let output =
            WalletOutput::read(&mut cursor).map_err(|_| DepositWalletError::InvalidWalletOutput)?;
        if usize::try_from(cursor.position()).ok() != Some(self.wallet_output.len()) {
            return Err(DepositWalletError::TrailingWalletOutputBytes);
        }
        if output.transaction() != self.id.transaction
            || output.index_in_transaction() != self.id.index_in_transaction
            || output.index_on_blockchain() != self.index_on_blockchain
            || output.key().compress().to_bytes() != self.output_key
            || <[u8; 32]>::from(output.key_offset()) != self.key_offset
            || output.subaddress().is_some()
        {
            return Err(DepositWalletError::WalletOutputMetadataMismatch);
        }
        Ok(output)
    }

    pub(crate) fn validate(&self, root_spend_key: [u8; 32]) -> Result<(), DepositWalletError> {
        self.wallet_output()?;
        let root = decode_root_spend_key(root_spend_key)?;
        let offset =
            Option::<DalekScalar>::from(DalekScalar::from_canonical_bytes(self.key_offset))
                .ok_or(DepositWalletError::InvalidScannerOffset)?;
        if (root + (ED25519_BASEPOINT_POINT * offset)).compress().to_bytes() != self.output_key {
            return Err(DepositWalletError::WrongOutputKey);
        }
        Ok(())
    }
}

/// Exact scanner-produced key offset verified at the decoy-selection boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScannerKeyOffset([u8; 32]);

impl ScannerKeyOffset {
    /// Return canonical scalar bytes. This value is consumed internally by monero-wallet's
    /// `SignableTransaction`; it must not be pre-applied to threshold shares.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Stable identifier for one consolidation attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SweepId(pub [u8; 32]);

/// Durable, attempt-independent binding between a prepared sweep family and its key images.
///
/// A Monero ring signature proves knowledge of *a* member of each ring. It does not, by itself,
/// prove that the intended deposit output was the member spent. The ordered key images therefore
/// have to be derived by the threshold protocol and quorum-certified before signature-share
/// exposure. Once pinned, every retry/view/subset in this family must use these exact values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FamilyKeyImageBinding {
    sweep: SweepId,
    inputs: Vec<WalletOutputId>,
    key_images: Vec<[u8; 32]>,
    family_digest: [u8; 32],
    unsigned_transaction_digest: [u8; 32],
}

impl FamilyKeyImageBinding {
    /// Stable sweep family.
    #[must_use]
    pub const fn sweep(&self) -> SweepId {
        self.sweep
    }

    /// Canonically ordered intended scanner outputs.
    #[must_use]
    pub fn inputs(&self) -> &[WalletOutputId] {
        &self.inputs
    }

    /// Key images in the same order as [`Self::inputs`].
    #[must_use]
    pub fn key_images(&self) -> &[[u8; 32]] {
        &self.key_images
    }

    /// Attempt-independent digest of the exact prepared/signable family.
    #[must_use]
    pub const fn family_digest(&self) -> [u8; 32] {
        self.family_digest
    }

    /// Digest of the exact unsigned Monero prefix, RingCT base and Bulletproof+ produced after
    /// binding the key images and before producing any CLSAG share.
    #[must_use]
    pub const fn unsigned_transaction_digest(&self) -> [u8; 32] {
        self.unsigned_transaction_digest
    }
}

/// Deterministic retained root-output proof for one broadcast sweep transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SweepConfirmationEvidence {
    /// Sweep attempt eligible for confirmation.
    pub sweep: SweepId,
    /// Broadcast transaction ID.
    pub transaction: [u8; 32],
    /// Exact retained/compacted block containing a root output from this transaction.
    pub block: ChainPoint,
}

/// Durable authorization for one exact FROSTLASS signing attempt.
///
/// This records every public binding needed to reconstruct and validate the intent after restart,
/// plus monero-wallet's bounded private `SignableTransaction` encoding. Worker snapshots must be
/// encrypted because that encoding contains the outgoing-view seed and scanner offsets.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SweepSigningIntent {
    epoch: u64,
    plan_commitment: [u8; 32],
    session: [u8; 32],
    committee_digest: [u8; 32],
    group_key: [u8; 32],
    signers: Vec<u16>,
    signable_transaction: Vec<u8>,
    prepared_sweep_intent: Vec<u8>,
    transaction_commitment: [u8; 32],
    signing_context: [u8; 32],
    fee_atomic_units: u64,
    intent_digest: [u8; 32],
}

impl std::fmt::Debug for SweepSigningIntent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SweepSigningIntent")
            .field("epoch", &self.epoch)
            .field("plan_commitment", &hex::encode(self.plan_commitment))
            .field("session", &hex::encode(self.session))
            .field("committee_digest", &hex::encode(self.committee_digest))
            .field("group_key", &hex::encode(self.group_key))
            .field("signers", &self.signers)
            .field("signable_transaction", &"<redacted>")
            .field("prepared_sweep_intent", &"<redacted>")
            .field("transaction_commitment", &hex::encode(self.transaction_commitment))
            .field("signing_context", &hex::encode(self.signing_context))
            .field("fee_atomic_units", &self.fee_atomic_units)
            .field("intent_digest", &hex::encode(self.intent_digest))
            .finish()
    }
}

impl Drop for SweepSigningIntent {
    fn drop(&mut self) {
        self.signable_transaction.zeroize();
        self.prepared_sweep_intent.zeroize();
    }
}

impl SweepSigningIntent {
    #[allow(clippy::too_many_arguments)]
    /// Construct an intent at the trusted worker boundary; reservation revalidates every field.
    #[must_use]
    pub(crate) fn new(
        epoch: u64,
        plan_commitment: [u8; 32],
        session: [u8; 32],
        committee_digest: [u8; 32],
        group_key: [u8; 32],
        signers: Vec<u16>,
        signable_transaction: Vec<u8>,
        prepared_sweep_intent: Vec<u8>,
        transaction_commitment: [u8; 32],
        signing_context: [u8; 32],
        fee_atomic_units: u64,
    ) -> Self {
        let mut intent = Self {
            epoch,
            plan_commitment,
            session,
            committee_digest,
            group_key,
            signers,
            signable_transaction,
            prepared_sweep_intent,
            transaction_commitment,
            signing_context,
            fee_atomic_units,
            intent_digest: [0_u8; 32],
        };
        intent.intent_digest = sweep_intent_digest(&intent);
        intent
    }

    /// Proactive sharing epoch authorized to sign.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Stable sweep-plan commitment.
    #[must_use]
    pub const fn plan_commitment(&self) -> [u8; 32] {
        self.plan_commitment
    }

    /// Globally unique signing session.
    #[must_use]
    pub const fn session(&self) -> [u8; 32] {
        self.session
    }

    /// Versioned canonical committee digest.
    #[must_use]
    pub const fn committee_digest(&self) -> [u8; 32] {
        self.committee_digest
    }

    /// Untweaked root threshold group key.
    #[must_use]
    pub const fn group_key(&self) -> [u8; 32] {
        self.group_key
    }

    /// Canonically sorted non-zero party IDs.
    #[must_use]
    pub fn signers(&self) -> &[u16] {
        &self.signers
    }

    /// Commitment compared by every FROSTLASS signer.
    #[must_use]
    pub const fn signing_context(&self) -> [u8; 32] {
        self.signing_context
    }

    /// Exact fee authorized by the prepared intent.
    #[must_use]
    pub const fn fee_atomic_units(&self) -> u64 {
        self.fee_atomic_units
    }

    /// Commitment to the exact plan plus canonical signable transaction.
    #[must_use]
    pub const fn transaction_commitment(&self) -> [u8; 32] {
        self.transaction_commitment
    }

    /// Domain-separated digest over every durable authorization field and both private encodings.
    #[must_use]
    pub const fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }

    /// Digest of immutable transaction-family fields, excluding retry session, committee, and
    /// signer-subset choices.
    #[must_use]
    pub fn family_digest(&self) -> [u8; 32] {
        sweep_family_digest(self)
    }

    /// Decode the exact canonical private signing intent.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, trailing, or non-canonical bytes.
    pub fn signable_transaction(&self) -> Result<SignableTransaction, DepositWalletError> {
        decode_signable_transaction(&self.signable_transaction)
    }

    /// Return the opaque canonical prepared-sweep bytes needed to resend a QUIC Start after crash.
    ///
    /// The worker must decode and independently reconstruct these bytes before use. They contain
    /// private scanner and outgoing-view material and must remain inside encrypted storage and the
    /// authenticated party channel.
    #[must_use]
    pub(crate) fn prepared_sweep_intent_bytes(&self) -> &[u8] {
        &self.prepared_sweep_intent
    }

    fn validate(&self, sweep: SweepId, root_spend_key: [u8; 32]) -> Result<(), DepositWalletError> {
        if self.plan_commitment != sweep.0
            || self.session == [0_u8; 32]
            || self.committee_digest == [0_u8; 32]
            || self.group_key != root_spend_key
            || self.transaction_commitment == [0_u8; 32]
            || self.signing_context == [0_u8; 32]
            || self.prepared_sweep_intent.is_empty()
            || self.prepared_sweep_intent.len() > MAX_PREPARED_SWEEP_INTENT_BYTES
            || self.fee_atomic_units == 0
            || self.signers.is_empty()
            || self.signers.iter().any(|party| *party == 0)
            || self.signers.windows(2).any(|window| window[0] >= window[1])
        {
            return Err(DepositWalletError::InvalidSweepSigningIntent);
        }
        let signable = self.signable_transaction()?;
        if signable.necessary_fee() != self.fee_atomic_units
            || sweep_transaction_commitment(sweep, &self.signable_transaction)
                != self.transaction_commitment
            || sweep_signing_context(self) != self.signing_context
            || sweep_intent_digest(self) != self.intent_digest
        {
            return Err(DepositWalletError::InvalidSweepSigningIntent);
        }
        Ok(())
    }

    fn validate_completed_transaction(
        &self,
        input_count: usize,
        binding: &FamilyKeyImageBinding,
        signed: &SignedSweepTransaction,
    ) -> Result<(), DepositWalletError> {
        let transaction = signed.transaction()?;
        let Transaction::V2 { prefix, proofs: Some(proofs) } = &transaction else {
            return Err(DepositWalletError::SignedSweepIntentMismatch);
        };
        let mut ordered_key_images = binding.key_images.clone();
        ordered_key_images.sort_unstable_by(|left, right| right.cmp(left));
        if proofs.rct_type() != RctType::ClsagBulletproofPlus
            || proofs.base.fee != self.fee_atomic_units
            || prefix.inputs.len() != input_count
            || prefix.outputs.len() != 2
            || binding.family_digest != self.family_digest()
            || binding.key_images.len() != input_count
            || prefix.inputs.iter().zip(&ordered_key_images).any(|(input, expected_image)| {
                !matches!(
                    input,
                    monero_oxide::transaction::Input::ToKey {
                        amount: None,
                        key_offsets,
                        key_image,
                    } if key_offsets.len() == 16 && key_image.to_bytes() == *expected_image
                )
            })
        {
            return Err(DepositWalletError::SignedSweepIntentMismatch);
        }
        std::thread_local! {
            // ponytail: 64 digests per thread; revisit only if retained families exceed this bound.
            static RECENT: std::cell::RefCell<std::collections::VecDeque<[u8; 32]>> =
                const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
        }
        // Memoize only deterministic output reconstruction, never proof/quorum authorization.
        // Bind both exact byte strings; retain no private signing material in the cache.
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/sweep-eventuality-match-cache/v1");
        for bytes in [self.signable_transaction.as_slice(), signed.as_bytes()] {
            hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
            hasher.update(bytes);
        }
        let key = *hasher.finalize().as_bytes();
        RECENT.with_borrow_mut(|cached| {
            if cached.contains(&key) {
                return Ok(());
            }
            let eventuality = Eventuality::from(self.signable_transaction()?);
            let (pruned, _) = transaction.pruned_with_prunable();
            if !eventuality.matches(&pruned) {
                return Err(DepositWalletError::SignedSweepIntentMismatch);
            }
            if cached.len() == 64 {
                cached.pop_front();
            }
            cached.push_back(key);
            Ok(())
        })
    }
}

/// Size-bounded canonical bytes for one completed Monero consolidation transaction.
///
/// The exact bytes, not merely the transaction hash, are part of durable state. If a process
/// crashes after RPC submission but before persisting `Broadcast`, it can therefore resubmit the
/// byte-identical transaction from the preceding `Signed` state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedSweepTransaction {
    transaction: [u8; 32],
    #[serde(deserialize_with = "deserialize_signed_sweep_transaction_bytes")]
    bytes: Vec<u8>,
}

fn deserialize_signed_sweep_transaction_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct SignedTransactionBytesVisitor;

    impl<'de> Visitor<'de> for SignedTransactionBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {MAX_SIGNED_SWEEP_TRANSACTION_BYTES} signed transaction bytes"
            )
        }

        fn visit_bytes<E: DeError>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            if bytes.len() > MAX_SIGNED_SWEEP_TRANSACTION_BYTES {
                return Err(E::custom("signed sweep transaction exceeds its hard size bound"));
            }
            Ok(bytes.to_vec())
        }

        fn visit_byte_buf<E: DeError>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            if bytes.len() > MAX_SIGNED_SWEEP_TRANSACTION_BYTES {
                return Err(E::custom("signed sweep transaction exceeds its hard size bound"));
            }
            Ok(bytes)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence
                .size_hint()
                .is_some_and(|length| length > MAX_SIGNED_SWEEP_TRANSACTION_BYTES)
            {
                return Err(A::Error::custom(
                    "signed sweep transaction exceeds its hard size bound",
                ));
            }
            let mut bytes = Vec::with_capacity(
                sequence.size_hint().unwrap_or(0).min(MAX_SIGNED_SWEEP_TRANSACTION_BYTES),
            );
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == MAX_SIGNED_SWEEP_TRANSACTION_BYTES {
                    return Err(A::Error::custom(
                        "signed sweep transaction exceeds its hard size bound",
                    ));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_byte_buf(SignedTransactionBytesVisitor)
}

#[cfg(test)]
mod signed_sweep_transaction_decode_tests {
    use super::*;
    use monero_wallet::{ed25519::Commitment, transaction::Timelock};

    #[test]
    fn serde_rejects_oversized_transaction_bytes() {
        let oversized = SignedSweepTransaction {
            transaction: [0xA5; 32],
            bytes: vec![0; MAX_SIGNED_SWEEP_TRANSACTION_BYTES + 1],
        };
        let encoded = postcard::to_allocvec(&oversized).unwrap();
        assert!(postcard::from_bytes::<SignedSweepTransaction>(&encoded).is_err());
    }

    #[test]
    fn pinned_root_witness_survives_block_compaction_and_restart() {
        let deriver = DepositAddressDeriver::new(
            NetworkKind::Mainnet,
            (ED25519_BASEPOINT_POINT * DalekScalar::from(42_u64)).compress().to_bytes(),
            &Zeroizing::new(DalekScalar::from(17_u64).to_bytes()),
        )
        .unwrap();
        let mut state = ScanState::new(&deriver, ChainPoint::new(10, [10; 32]).unwrap()).unwrap();
        let transaction = [81; 32];
        let offset = DalekScalar::from(29_u64);
        let output_key = ED25519_BASEPOINT_POINT * (DalekScalar::from(42_u64) + offset);
        let commitment = Commitment::new(Scalar::from(DalekScalar::from(78_u64)), 9_000_000);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&transaction);
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&500_u64.to_le_bytes());
        bytes.extend_from_slice(&output_key.compress().to_bytes());
        bytes.extend_from_slice(&offset.to_bytes());
        commitment.write(&mut bytes).unwrap();
        Timelock::None.write(&mut bytes).unwrap();
        bytes.extend_from_slice(&[0, 0, 0]);
        let mut reader = Cursor::new(bytes.as_slice());
        let output = WalletOutput::read(&mut reader).unwrap();
        assert_eq!(usize::try_from(reader.position()).unwrap(), bytes.len());
        let root_output = PersistedRootOutput::from_scanner(&output).unwrap();
        let inclusion = ChainPoint::new(11, [11; 32]).unwrap();

        state
            .append_block_with_root(
                ScannedBlock { point: inclusion, parent_hash: [10; 32] },
                1_700_000_011,
                Vec::new(),
                vec![root_output.clone()],
            )
            .unwrap();
        state.pin_root_transaction(transaction, inclusion).unwrap();
        state
            .append_block(
                ScannedBlock {
                    point: ChainPoint::new(12, [12; 32]).unwrap(),
                    parent_hash: [11; 32],
                },
                1_700_000_012,
                Vec::new(),
            )
            .unwrap();
        state
            .append_block(
                ScannedBlock {
                    point: ChainPoint::new(13, [13; 32]).unwrap(),
                    parent_hash: [12; 32],
                },
                1_700_000_013,
                Vec::new(),
            )
            .unwrap();

        state.compact_reorg_window(1).unwrap();
        assert_eq!(state.anchor(), ChainPoint::new(12, [12; 32]).unwrap());
        assert_eq!(state.root_transaction_chain_point(transaction), Some(inclusion));
        assert!(state.root_transaction_observed_at(transaction, inclusion));

        let mut restored = ScanState::decode(&state.encode().unwrap()).unwrap();
        assert_eq!(restored.root_output(root_output.id()), Some(&root_output));
        assert!(restored.release_compacted_root_witness(transaction));
        assert!(restored.root_output(root_output.id()).is_none());
        restored.validate().unwrap();
    }

    fn test_deriver() -> DepositAddressDeriver {
        DepositAddressDeriver::new(
            NetworkKind::Mainnet,
            (ED25519_BASEPOINT_POINT * DalekScalar::from(42_u64)).compress().to_bytes(),
            &Zeroizing::new(DalekScalar::from(17_u64).to_bytes()),
        )
        .unwrap()
    }

    fn test_point(height: u64, byte: u8) -> ChainPoint {
        ChainPoint::new(height, [byte; 32]).unwrap()
    }

    fn test_output(
        offset: u64,
        transaction: u8,
        index_in_transaction: u64,
    ) -> PersistedWalletOutput {
        let offset = DalekScalar::from(offset);
        let output_key = ED25519_BASEPOINT_POINT * (DalekScalar::from(42_u64) + offset);
        let commitment = Commitment::new(Scalar::from(DalekScalar::from(78_u64)), 9_000_000);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[transaction; 32]);
        bytes.extend_from_slice(&index_in_transaction.to_le_bytes());
        bytes.extend_from_slice(&(500_u64 + u64::from(transaction)).to_le_bytes());
        bytes.extend_from_slice(&output_key.compress().to_bytes());
        bytes.extend_from_slice(&offset.to_bytes());
        commitment.write(&mut bytes).unwrap();
        Timelock::None.write(&mut bytes).unwrap();
        bytes.push(1);
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        let mut reader = Cursor::new(bytes.as_slice());
        let output = WalletOutput::read(&mut reader).unwrap();
        assert_eq!(usize::try_from(reader.position()).unwrap(), bytes.len());
        PersistedWalletOutput::from_scanner(&output).unwrap()
    }

    fn test_root_output(offset: u64, transaction: [u8; 32]) -> PersistedRootOutput {
        let offset = DalekScalar::from(offset);
        let output_key = ED25519_BASEPOINT_POINT * (DalekScalar::from(42_u64) + offset);
        let commitment = Commitment::new(Scalar::from(DalekScalar::from(79_u64)), 8_000_000);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&transaction);
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&700_u64.to_le_bytes());
        bytes.extend_from_slice(&output_key.compress().to_bytes());
        bytes.extend_from_slice(&offset.to_bytes());
        commitment.write(&mut bytes).unwrap();
        Timelock::None.write(&mut bytes).unwrap();
        bytes.extend_from_slice(&[0, 0, 0]);
        let mut reader = Cursor::new(bytes.as_slice());
        let output = WalletOutput::read(&mut reader).unwrap();
        assert_eq!(usize::try_from(reader.position()).unwrap(), bytes.len());
        PersistedRootOutput::from_scanner(&output).unwrap()
    }

    fn append_empty(state: &mut ScanState, point: ChainPoint, parent: ChainPoint, timestamp: u64) {
        state
            .append_block(ScannedBlock { point, parent_hash: parent.hash }, timestamp, Vec::new())
            .unwrap();
    }

    #[test]
    fn historical_output_inside_reorg_window_rolls_back() {
        let anchor = test_point(10, 10);
        let block = test_point(11, 11);
        let horizon = test_point(12, 12);
        let mut state = ScanState::new(&test_deriver(), anchor).unwrap();
        let stable_anchor = state.verify_recognition_anchor(anchor).unwrap();
        append_empty(&mut state, block, anchor, 1_700_000_011);
        append_empty(&mut state, horizon, block, 1_700_000_012);
        let output = test_output(9, 41, 0);
        let evidence = AuthenticatedHistoricalBlockEvidence::from_authenticated_chain_source(
            state.wallet_id(),
            ScannedBlock { point: block, parent_hash: anchor.hash },
            1_700_000_011,
            horizon,
            [90; 32],
            7,
            vec![output.clone()],
            Vec::new(),
        )
        .unwrap();

        assert!(state.insert_authenticated_historical_outputs(&evidence).unwrap());
        assert!(state.pin_authenticated_historical_block(&evidence).unwrap());
        assert_eq!(state.output_chain_point(output.id()), Some(block));
        assert!(!state.insert_authenticated_historical_outputs(&evidence).unwrap());
        assert!(matches!(
            state.verify_recognition_anchor(block),
            Err(DepositWalletError::UnknownChainPoint(point)) if point == block
        ));

        let report = state.rollback_to(anchor).unwrap();
        assert_eq!(report.removed_outputs.len(), 1);
        assert_eq!(state.retained_output_count(), 0);
        assert!(stable_anchor.authorizes(state.wallet_id(), anchor));
        assert!(matches!(
            state.verify_recognition_anchor(block),
            Err(DepositWalletError::UnknownChainPoint(point)) if point == block
        ));
    }

    #[test]
    fn historical_output_before_reorg_window_is_pinned_across_restart() {
        let birth = test_point(5, 5);
        let mut state = ScanState::new(&test_deriver(), birth).unwrap();
        let mut parent = birth;
        for height in 6_u64..=12 {
            let next = test_point(height, u8::try_from(height).unwrap());
            append_empty(&mut state, next, parent, 1_700_000_000 + height);
            state.compact_reorg_window(2).unwrap();
            parent = next;
        }
        assert_eq!(state.anchor(), test_point(10, 10));

        let historical = test_point(7, 7);
        let horizon = test_point(12, 12);
        let output = test_output(19, 51, 0);
        let root_transaction = [52; 32];
        let root_output = test_root_output(20, root_transaction);
        let evidence = AuthenticatedHistoricalBlockEvidence::from_authenticated_chain_source(
            state.wallet_id(),
            ScannedBlock { point: historical, parent_hash: [6; 32] },
            1_700_000_007,
            horizon,
            [90; 32],
            7,
            vec![output.clone()],
            vec![root_output.clone()],
        )
        .unwrap();
        state.insert_authenticated_historical_outputs(&evidence).unwrap();

        let mut restored = ScanState::decode(&state.encode().unwrap()).unwrap();
        let before_replay = restored.encode().unwrap();
        assert!(!restored.insert_authenticated_historical_outputs(&evidence).unwrap());
        assert_eq!(restored.encode().unwrap(), before_replay);
        assert_eq!(restored.output(output.id()), Some(&output));
        assert_eq!(restored.root_output(root_output.id()), Some(&root_output));
        assert_eq!(restored.output_chain_point(output.id()), Some(historical));
        assert_eq!(restored.root_output_chain_point(root_output.id()), Some(historical));
        assert_eq!(restored.canonical_block_timestamp(historical), Some(1_700_000_007));
        let verified = restored.verify_recognition_anchor(historical).unwrap();
        assert!(verified.authorizes(restored.wallet_id(), historical));
        assert_eq!(verified.verification_horizon(), horizon);
        let portable = VerifiedPortableSweepTerminal::from_verified_public_completion(
            restored.wallet_id(),
            SweepId([53; 32]),
            vec![output.id()],
            root_transaction,
            [54; 32],
            [55; 32],
        )
        .unwrap();
        assert!(restored.pin_verified_portable_terminal(&portable, historical).unwrap());
        restored.validate().unwrap();
    }

    #[test]
    fn historical_replay_is_idempotent_and_conflicts_are_atomic() {
        let birth = test_point(5, 5);
        let mut state = ScanState::new(&test_deriver(), birth).unwrap();
        let block = test_point(6, 6);
        append_empty(&mut state, block, birth, 1_700_000_006);
        let output = test_output(29, 61, 0);
        let root_output = test_root_output(31, [64; 32]);
        let evidence = AuthenticatedHistoricalBlockEvidence::from_authenticated_chain_source(
            state.wallet_id(),
            ScannedBlock { point: block, parent_hash: birth.hash },
            1_700_000_006,
            block,
            [90; 32],
            7,
            vec![output.clone()],
            vec![root_output.clone()],
        )
        .unwrap();
        state.insert_authenticated_historical_outputs(&evidence).unwrap();
        assert!(!state.insert_authenticated_historical_outputs(&evidence).unwrap());

        let same_id_different_body = test_output(30, 61, 0);
        let same_id_evidence =
            AuthenticatedHistoricalBlockEvidence::from_authenticated_chain_source(
                state.wallet_id(),
                evidence.block(),
                evidence.timestamp(),
                block,
                [90; 32],
                7,
                vec![same_id_different_body],
                Vec::new(),
            )
            .unwrap();
        let before_same_id = state.encode().unwrap();
        assert!(matches!(
            state.insert_authenticated_historical_outputs(&same_id_evidence),
            Err(DepositWalletError::DuplicateOutputId(_))
        ));
        assert_eq!(state.encode().unwrap(), before_same_id);
        let same_key_different_id = test_output(29, 62, 0);
        let same_key_evidence =
            AuthenticatedHistoricalBlockEvidence::from_authenticated_chain_source(
                state.wallet_id(),
                evidence.block(),
                evidence.timestamp(),
                block,
                [90; 32],
                7,
                vec![same_key_different_id],
                Vec::new(),
            )
            .unwrap();
        let before_same_key = state.encode().unwrap();
        assert!(matches!(
            state.insert_authenticated_historical_outputs(&same_key_evidence),
            Err(DepositWalletError::DuplicateOutputKey { .. })
        ));
        assert_eq!(state.encode().unwrap(), before_same_key);
        let cross_class_burning_bug = test_root_output(29, [63; 32]);
        let cross_class_evidence =
            AuthenticatedHistoricalBlockEvidence::from_authenticated_chain_source(
                state.wallet_id(),
                evidence.block(),
                evidence.timestamp(),
                block,
                [90; 32],
                7,
                Vec::new(),
                vec![cross_class_burning_bug],
            )
            .unwrap();
        let before_cross_class = state.encode().unwrap();
        assert!(matches!(
            state.insert_authenticated_historical_outputs(&cross_class_evidence),
            Err(DepositWalletError::DuplicateOutputKey { .. })
        ));
        assert_eq!(state.encode().unwrap(), before_cross_class);
        let root_same_id_different_body = test_root_output(32, [64; 32]);
        let root_id_evidence =
            AuthenticatedHistoricalBlockEvidence::from_authenticated_chain_source(
                state.wallet_id(),
                evidence.block(),
                evidence.timestamp(),
                block,
                [90; 32],
                7,
                Vec::new(),
                vec![root_same_id_different_body],
            )
            .unwrap();
        let before_root_id = state.encode().unwrap();
        assert!(matches!(
            state.insert_authenticated_historical_outputs(&root_id_evidence),
            Err(DepositWalletError::DuplicateOutputId(_))
        ));
        assert_eq!(state.encode().unwrap(), before_root_id);
        let uncommitted = test_output(33, 65, 0);
        let mixed_atomic_evidence =
            AuthenticatedHistoricalBlockEvidence::from_authenticated_chain_source(
                state.wallet_id(),
                evidence.block(),
                evidence.timestamp(),
                block,
                [90; 32],
                7,
                vec![uncommitted.clone()],
                vec![test_root_output(32, [64; 32])],
            )
            .unwrap();
        let before_mixed_batch = state.encode().unwrap();
        assert!(matches!(
            state.insert_authenticated_historical_outputs(&mixed_atomic_evidence),
            Err(DepositWalletError::DuplicateOutputId(_))
        ));
        assert!(state.output(uncommitted.id()).is_none());
        assert_eq!(state.encode().unwrap(), before_mixed_batch);
        let conflicting_timestamp =
            AuthenticatedHistoricalBlockEvidence::from_authenticated_chain_source(
                state.wallet_id(),
                evidence.block(),
                evidence.timestamp() + 1,
                block,
                [90; 32],
                7,
                Vec::new(),
                Vec::new(),
            )
            .unwrap();
        let before_timestamp = state.encode().unwrap();
        assert!(matches!(
            state.insert_authenticated_historical_outputs(&conflicting_timestamp),
            Err(DepositWalletError::ConflictingHistoricalBlock(6))
        ));
        assert_eq!(state.encode().unwrap(), before_timestamp);
        assert_eq!(state.retained_output_count(), 2);
        state.validate().unwrap();
    }

    #[test]
    fn terminal_compaction_waits_until_confirmation_is_behind_fence() {
        let anchor = test_point(10, 10);
        let confirmation = test_point(11, 11);
        let horizon = test_point(12, 12);
        let mut state = ScanState::new(&test_deriver(), anchor).unwrap();
        let output = test_output(39, 71, 0);
        let transaction = [82; 32];
        let root_output = test_root_output(40, transaction);
        state
            .append_block_with_root(
                ScannedBlock { point: confirmation, parent_hash: anchor.hash },
                1_700_000_011,
                vec![output.clone()],
                vec![root_output],
            )
            .unwrap();
        let sweep = SweepId([81; 32]);
        let portable = VerifiedPortableSweepTerminal::from_verified_public_completion(
            state.wallet_id(),
            sweep,
            vec![output.id()],
            transaction,
            [83; 32],
            [84; 32],
        )
        .unwrap();
        assert!(state.pin_verified_portable_terminal(&portable, confirmation).unwrap());
        append_empty(&mut state, horizon, confirmation, 1_700_000_012);
        assert!(matches!(
            state.verify_terminal_compaction(&portable, confirmation),
            Err(DepositWalletError::TerminalCompactionBeforeReorgFence { .. })
        ));

        state.compact_reorg_window(1).unwrap();
        let restored = ScanState::decode(&state.encode().unwrap()).unwrap();
        let wrong_transaction = VerifiedPortableSweepTerminal::from_verified_public_completion(
            restored.wallet_id(),
            sweep,
            vec![output.id()],
            [85; 32],
            [83; 32],
            [84; 32],
        )
        .unwrap();
        assert!(matches!(
            restored.verify_terminal_compaction(&wrong_transaction, confirmation),
            Err(DepositWalletError::InvalidSweepConfirmation)
        ));
        let verified = restored.verify_terminal_compaction(&portable, confirmation).unwrap();
        let mut restored = restored;
        assert!(restored.consume_verified_terminal_compaction(&verified).unwrap());
        assert!(restored.output(output.id()).is_none());
        assert!(!restored.consume_verified_terminal_compaction(&verified).unwrap());
        ScanState::decode(&restored.encode().unwrap()).unwrap();
    }
}

impl SignedSweepTransaction {
    /// Canonically serialize and bind a completed transaction to an optional expected ID.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized transaction or expected-ID mismatch.
    pub fn from_transaction(
        transaction: &Transaction,
        expected_transaction: Option<[u8; 32]>,
    ) -> Result<Self, DepositWalletError> {
        Self::from_bytes(transaction.serialize(), expected_transaction)
    }

    /// Parse exactly one canonical Monero transaction and bind it to an optional expected ID.
    ///
    /// # Errors
    ///
    /// Returns an error for empty/oversized, malformed, trailing, non-canonical, or hash-mismatched
    /// bytes.
    pub fn from_bytes(
        bytes: Vec<u8>,
        expected_transaction: Option<[u8; 32]>,
    ) -> Result<Self, DepositWalletError> {
        if bytes.len() > MAX_SIGNED_SWEEP_TRANSACTION_BYTES {
            return Err(DepositWalletError::SignedSweepTransactionTooLarge);
        }
        if bytes.is_empty() {
            return Err(DepositWalletError::InvalidSignedSweepTransaction);
        }
        let mut cursor = Cursor::new(bytes.as_slice());
        let parsed = Transaction::read(&mut cursor)
            .map_err(|_| DepositWalletError::InvalidSignedSweepTransaction)?;
        if usize::try_from(cursor.position()).ok() != Some(bytes.len()) {
            return Err(DepositWalletError::TrailingSignedSweepTransactionBytes);
        }
        if parsed.serialize() != bytes {
            return Err(DepositWalletError::NonCanonicalSignedSweepTransaction);
        }
        let transaction = parsed.hash();
        if expected_transaction.is_some_and(|expected| expected != transaction) {
            return Err(DepositWalletError::SweepTransactionHashMismatch);
        }
        Ok(Self { transaction, bytes })
    }

    /// Return the transaction ID derived from the exact bytes.
    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 32] {
        self.transaction
    }

    /// Return the exact canonical transaction bytes for RPC submission.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reparse the exact canonical transaction for the pinned daemon interface.
    ///
    /// # Errors
    ///
    /// Returns an error if durable state was corrupted.
    pub fn transaction(&self) -> Result<Transaction, DepositWalletError> {
        let validated = Self::from_bytes(self.bytes.clone(), Some(self.transaction))?;
        let mut cursor = Cursor::new(validated.bytes.as_slice());
        Transaction::read(&mut cursor)
            .map_err(|_| DepositWalletError::InvalidSignedSweepTransaction)
    }

    fn validate(&self) -> Result<(), DepositWalletError> {
        let validated = Self::from_bytes(self.bytes.clone(), Some(self.transaction))?;
        if validated != *self {
            return Err(DepositWalletError::InvalidSignedSweepTransaction);
        }
        Ok(())
    }
}

/// Durable lifecycle of an exact consolidation transaction intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SweepStatus {
    /// Inputs are exclusively reserved, but no signing nonce may yet be created.
    Reserved,
    /// The nonce-creation authorization was durably persisted for the exact signing intent.
    SigningReleased,
    /// Exact signed bytes are durable and may be submitted or resubmitted idempotently.
    Signed {
        /// Transaction ID derived from the stored canonical bytes.
        transaction: [u8; 32],
    },
    /// The signed transaction was submitted to the Monero network.
    Broadcast {
        /// Submitted transaction ID.
        transaction: [u8; 32],
    },
    /// The transaction was observed in a retained block.
    Confirmed {
        /// Confirmed transaction ID.
        transaction: [u8; 32],
        /// Block containing the transaction.
        block: ChainPoint,
    },
    /// A reorg removed an input after signing may have started; surviving inputs remain claimed.
    QuarantinedByReorg {
        /// Retained ancestor after rollback.
        ancestor: ChainPoint,
        /// Signed transaction ID, if signing had completed before quarantine.
        transaction: Option<[u8; 32]>,
    },
    /// Quorum-certified terminal closure for an unsigned, post-nonce family whose input branch
    /// disappeared. Inputs, key images, sessions, and attempt high-water remain permanently
    /// claimed, but this family can never become locally signable again.
    AbandonedByReorg {
        /// Retained ancestor authenticated by the abandonment certificate.
        ancestor: ChainPoint,
    },
}

/// Permanent tombstone for a released signing session whose in-memory FROST machine was lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetiredSweepSigningAttempt {
    attempt: u64,
    session: [u8; 32],
    intent_digest: [u8; 32],
}

impl RetiredSweepSigningAttempt {
    /// Monotonic family attempt number which consumed this session.
    #[must_use]
    pub const fn attempt(self) -> u64 {
        self.attempt
    }

    /// Session which must never create another nonce.
    #[must_use]
    pub const fn session(self) -> [u8; 32] {
        self.session
    }

    /// Exact retired durable intent digest.
    #[must_use]
    pub const fn intent_digest(self) -> [u8; 32] {
        self.intent_digest
    }
}

/// Exact durable reservation for a consolidation attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SweepRecord {
    /// Stable attempt identifier.
    pub id: SweepId,
    /// Complete bounded signing authorization and private signable intent.
    pub signing_intent: SweepSigningIntent,
    /// Highest signing-attempt number ever reserved for this family.
    ///
    /// This never decreases, including across rollback and restart. The current signing intent is
    /// always exactly this attempt.
    pub signing_attempt_high_water: u64,
    /// Bounded recent old-session tombstones created by crash recovery, in attempt order.
    pub retired_signing_attempts: Vec<RetiredSweepSigningAttempt>,
    /// Quorum-certified key-image vector shared by every retry/subset in this family.
    pub family_key_images: Option<FamilyKeyImageBinding>,
    /// Canonically sorted deposit inputs.
    pub inputs: Vec<WalletOutputId>,
    /// Exact canonical transaction bytes once threshold signing completes.
    pub signed_transaction: Option<SignedSweepTransaction>,
    /// Sorted distinct valid variants produced by retry views/subsets for the same family.
    pub family_candidates: Vec<SignedSweepTransaction>,
    /// Current durable lifecycle.
    pub status: SweepStatus,
}

/// Output IDs removed and sweep states changed by a chain rollback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackReport {
    /// Deposit outputs discarded with orphaned blocks.
    pub removed_outputs: Vec<WalletOutputId>,
    /// Root/primary outputs discarded with orphaned blocks.
    pub removed_root_outputs: Vec<WalletOutputId>,
    /// Consolidation attempts invalidated because an input disappeared.
    pub invalidated_sweeps: Vec<SweepId>,
    /// Attempts quarantined because an input disappeared after nonce authorization.
    pub quarantined_sweeps: Vec<SweepId>,
    /// Confirmations reverted to broadcast because only the sweep transaction's block disappeared.
    pub reverted_confirmations: Vec<SweepId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredBlock {
    block: ScannedBlock,
    timestamp: u64,
    outputs: Vec<WalletOutputId>,
    root_outputs: Vec<WalletOutputId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PinnedHistoricalBlock {
    block: ScannedBlock,
    timestamp: u64,
    outputs: Vec<WalletOutputId>,
    root_outputs: Vec<WalletOutputId>,
    held: bool,
}

/// Serializable scanner journal and exact consolidation reservations.
///
/// The anchor is a trusted block already incorporated before this journal. Every appended block
/// must extend the current tip. Output keys are globally unique across retained blocks, enforcing
/// monero-wallet's required burning-bug check before a scanner result is accepted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanState {
    version: u16,
    wallet: DepositWalletId,
    network: NetworkKind,
    root_spend_key: [u8; 32],
    public_view_key: [u8; 32],
    birth_anchor: ChainPoint,
    anchor: ChainPoint,
    blocks: BTreeMap<u64, StoredBlock>,
    pinned_historical_blocks: BTreeMap<u64, PinnedHistoricalBlock>,
    outputs: BTreeMap<WalletOutputId, PersistedWalletOutput>,
    output_inclusions: BTreeMap<WalletOutputId, ChainPoint>,
    root_outputs: BTreeMap<WalletOutputId, PersistedRootOutput>,
    root_output_inclusions: BTreeMap<WalletOutputId, ChainPoint>,
    pinned_root_transactions: BTreeSet<[u8; 32]>,
    sweeps: BTreeMap<SweepId, SweepRecord>,
}

impl ScanState {
    /// Start a journal at a trusted chain anchor.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid wallet domain or zero anchor hash.
    pub fn new(
        wallet: &DepositAddressDeriver,
        anchor: ChainPoint,
    ) -> Result<Self, DepositWalletError> {
        decode_root_spend_key(wallet.root_spend_key)?;
        ChainPoint::new(anchor.height, anchor.hash)?;
        Ok(Self {
            version: SCAN_STATE_VERSION,
            wallet: wallet.wallet,
            network: wallet.network,
            root_spend_key: wallet.root_spend_key,
            public_view_key: wallet.public_view_key,
            birth_anchor: anchor,
            anchor,
            blocks: BTreeMap::new(),
            pinned_historical_blocks: BTreeMap::new(),
            outputs: BTreeMap::new(),
            output_inclusions: BTreeMap::new(),
            root_outputs: BTreeMap::new(),
            root_output_inclusions: BTreeMap::new(),
            pinned_root_transactions: BTreeSet::new(),
            sweeps: BTreeMap::new(),
        })
    }

    /// Return the logical network whose chain is being scanned.
    #[must_use]
    pub const fn network(&self) -> NetworkKind {
        self.network
    }

    /// Return the stable wallet domain bound to this journal.
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    /// Return the untweaked root threshold public spend key bound to every scanner output.
    #[must_use]
    pub const fn root_spend_key(&self) -> [u8; 32] {
        self.root_spend_key
    }

    /// Return the latest retained chain point.
    #[must_use]
    pub fn tip(&self) -> ChainPoint {
        self.blocks.last_key_value().map_or(self.anchor, |(_, block)| block.block.point)
    }

    /// Return the trusted anchor at the start of this journal.
    #[must_use]
    pub const fn anchor(&self) -> ChainPoint {
        self.anchor
    }

    /// Return the immutable deployment-wide wallet birth point.
    #[must_use]
    pub const fn birth_anchor(&self) -> ChainPoint {
        self.birth_anchor
    }

    /// Number of full block bodies retained inside the bounded reorg window.
    #[must_use]
    pub fn retained_block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of full wallet outputs retained by the active and reorganization windows.
    #[must_use]
    pub fn retained_output_count(&self) -> usize {
        self.outputs.len().saturating_add(self.root_outputs.len())
    }

    /// Return the exact retained chain point at `height`, including the anchor.
    #[must_use]
    pub fn chain_point(&self, height: u64) -> Option<ChainPoint> {
        if height == self.anchor.height {
            return Some(self.anchor);
        }
        self.blocks.get(&height).map(|stored| stored.block.point)
    }

    /// Return an exact authenticated block timestamp retained for scanning or historical replay.
    #[must_use]
    pub fn canonical_block_timestamp(&self, point: ChainPoint) -> Option<u64> {
        self.blocks
            .get(&point.height)
            .filter(|stored| stored.block.point == point)
            .map(|stored| stored.timestamp)
            .or_else(|| {
                self.pinned_historical_blocks
                    .get(&point.height)
                    .filter(|stored| stored.block.point == point)
                    .map(|stored| stored.timestamp)
            })
    }

    /// Return the exact canonical point authenticated anywhere in the scanner's retained history.
    ///
    /// Unlike [`Self::chain_point`], this includes historical blocks pinned by authenticated
    /// backfill/output evidence. Conflicting evidence at the same height and points ahead of the
    /// current scanner tip are rejected.
    #[must_use]
    pub(crate) fn authenticated_canonical_chain_point(&self, height: u64) -> Option<ChainPoint> {
        (height <= self.tip().height).then(|| self.authenticated_chain_point(height)).flatten()
    }

    /// Whether an exact point remains authenticated as part of this scanner's canonical history.
    ///
    /// This includes the moving checkpoint, retained reorganization suffix, and historical points
    /// pinned by authenticated output/backfill evidence. A height-only match is never sufficient.
    /// Points ahead of the current confirmed tip are rejected even if malformed durable state
    /// somehow retained an unrelated witness at that height.
    #[must_use]
    pub(crate) fn authenticates_canonical_chain_point(&self, point: ChainPoint) -> bool {
        ChainPoint::new(point.height, point.hash).is_ok()
            && self.authenticated_canonical_chain_point(point.height) == Some(point)
    }

    /// Verify one exact client-allocation recognition anchor against authenticated local history.
    ///
    /// The moving reorganization checkpoint and older historical blocks pinned by authenticated
    /// backfill/output evidence are accepted. A height-only match is never sufficient. Retained
    /// suffix blocks newer than the checkpoint are deliberately rejected so this capability
    /// cannot become stale after a permitted rollback.
    ///
    /// # Errors
    ///
    /// Returns an error if the wallet/point is malformed, unknown, conflicting, or in the future.
    pub fn verify_recognition_anchor(
        &self,
        anchor: ChainPoint,
    ) -> Result<VerifiedRecognitionAnchor, DepositWalletError> {
        ChainPoint::new(anchor.height, anchor.hash)?;
        let verification_horizon = self.tip();
        if anchor.height < self.birth_anchor.height
            || anchor.height > self.anchor.height
            || self.authenticated_chain_point(anchor.height) != Some(anchor)
        {
            return Err(DepositWalletError::UnknownChainPoint(anchor));
        }
        Ok(VerifiedRecognitionAnchor { wallet: self.wallet, anchor, verification_horizon })
    }

    /// Evaluate a transaction-level Monero unlock time against the authenticated scanner tip.
    ///
    /// This reproduces the hard-fork-13-and-later deterministic rules used by
    /// `Blockchain::is_tx_spendtime_unlocked`: block locks receive Monero's one-block allowance;
    /// time locks use `Blockchain::get_adjusted_time` over the latest sixty canonical block
    /// timestamps and receive the corresponding 120-second allowance. Arithmetic overflow and an
    /// incomplete timestamp window fail closed. The local wall clock is never consulted.
    #[must_use]
    pub fn additional_timelock_satisfied(&self, timelock: Timelock) -> bool {
        self.additional_timelock_satisfied_at(self.tip(), timelock)
    }

    /// Evaluate a transaction-level unlock time at an exact retained canonical chain point.
    ///
    /// This lets every party validate a sweep against the timestamp window committed by the
    /// sweep's scanner tip, even if its local scanner has since advanced further.
    #[must_use]
    pub fn additional_timelock_satisfied_at(&self, tip: ChainPoint, timelock: Timelock) -> bool {
        if self.chain_point(tip.height) != Some(tip) {
            return false;
        }
        match timelock {
            Timelock::None => true,
            Timelock::Block(unlock_height) => {
                let Ok(unlock_height) = u64::try_from(unlock_height) else {
                    return false;
                };
                tip.height
                    .checked_add(MONERO_UNLOCK_ALLOWED_DELTA_BLOCKS)
                    .is_some_and(|height| height >= unlock_height)
            }
            Timelock::Time(unlock_time) => self
                .deterministic_unlock_time_at(tip)
                .and_then(|time| time.checked_add(MONERO_UNLOCK_ALLOWED_DELTA_SECONDS))
                .is_some_and(|time| time >= unlock_time),
        }
    }

    fn deterministic_unlock_time_at(&self, tip: ChainPoint) -> Option<u64> {
        if self.chain_point(tip.height) != Some(tip) {
            return None;
        }
        let mut timestamps = self
            .blocks
            .range(..=tip.height)
            .rev()
            .take(MONERO_UNLOCK_TIMESTAMP_WINDOW)
            .map(|(_, stored)| stored.timestamp)
            .collect::<Vec<_>>();
        if timestamps.len() != MONERO_UNLOCK_TIMESTAMP_WINDOW {
            return None;
        }
        timestamps.sort_unstable();
        let upper = timestamps[MONERO_UNLOCK_TIMESTAMP_WINDOW / 2];
        let lower = timestamps[(MONERO_UNLOCK_TIMESTAMP_WINDOW / 2) - 1];
        let median = lower.checked_add((upper - lower) / 2)?;
        let median_projection = median.checked_add(MONERO_UNLOCK_MEDIAN_PROJECTION_SECONDS)?;
        let latest_projection =
            self.blocks.get(&tip.height)?.timestamp.checked_add(MONERO_BLOCK_TARGET_SECONDS)?;
        Some(latest_projection.min(median_projection))
    }

    /// Return the next block height required by the scanner.
    ///
    /// # Errors
    ///
    /// Returns an error if the current height is `u64::MAX`.
    pub fn next_height(&self) -> Result<u64, DepositWalletError> {
        self.tip().height.checked_add(1).ok_or(DepositWalletError::HeightOverflow)
    }

    /// Return a retained output by absolute ID.
    #[must_use]
    pub fn output(&self, id: WalletOutputId) -> Option<&PersistedWalletOutput> {
        self.outputs.get(&id)
    }

    /// Return a retained root/primary output by absolute ID.
    #[must_use]
    pub fn root_output(&self, id: WalletOutputId) -> Option<&PersistedRootOutput> {
        self.root_outputs.get(&id)
    }

    /// Return the retained block which contains an output.
    #[must_use]
    pub fn output_chain_point(&self, id: WalletOutputId) -> Option<ChainPoint> {
        self.output_inclusions.get(&id).copied()
    }

    /// Return the retained block which contains a root/primary output.
    #[must_use]
    pub fn root_output_chain_point(&self, id: WalletOutputId) -> Option<ChainPoint> {
        self.root_output_inclusions.get(&id).copied()
    }

    /// Iterate over retained root/primary outputs for audit and rollback reconciliation.
    ///
    /// These outputs are never returned by [`Self::available_outputs`].
    pub fn root_outputs(&self) -> impl Iterator<Item = &PersistedRootOutput> {
        self.root_outputs.values()
    }

    /// Iterate over retained outputs not claimed by an active sweep.
    pub fn available_outputs(&self) -> impl Iterator<Item = &PersistedWalletOutput> {
        self.outputs.iter().filter_map(|(id, output)| (!self.is_claimed(*id)).then_some(output))
    }

    /// Return a durable sweep record.
    #[must_use]
    pub fn sweep(&self, id: SweepId) -> Option<&SweepRecord> {
        self.sweeps.get(&id)
    }

    /// Iterate over durable sweep records in stable sweep-ID order.
    ///
    /// Persistence integrations use this read-only view to prove two-way alignment with their
    /// public coordinator and to block proactive share retirement while an unportable attempt is
    /// still active.
    pub fn sweeps(&self) -> impl ExactSizeIterator<Item = &SweepRecord> {
        self.sweeps.values()
    }

    /// Return permanent old-session tombstones for one sweep attempt.
    #[must_use]
    pub fn retired_sweep_signing_attempts(
        &self,
        id: SweepId,
    ) -> Option<&[RetiredSweepSigningAttempt]> {
        self.sweeps.get(&id).map(|record| record.retired_signing_attempts.as_slice())
    }

    /// Return the monotonic attempt high-water for one sweep family.
    #[must_use]
    pub fn sweep_signing_attempt_high_water(&self, id: SweepId) -> Option<u64> {
        self.sweeps.get(&id).map(|record| record.signing_attempt_high_water)
    }

    /// Require one exact worker attempt to remain eligible for key-image authorization or
    /// signature-share exposure.
    ///
    /// A sweep-family key-image binding is attempt-independent once it is pinned, but the right
    /// to derive or expose signing material is not. Callers must recheck this predicate while
    /// holding the snapshot mutation fence immediately before crossing either boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown sweep, any lifecycle other than `SigningReleased`, or an
    /// attempt/session/intent tuple which is not the current monotonic high-water.
    pub fn validate_live_sweep_signing_attempt(
        &self,
        id: SweepId,
        attempt: u64,
        session: SessionId,
        intent_digest: [u8; 32],
    ) -> Result<(), DepositWalletError> {
        let record = self.sweeps.get(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        if record.status != SweepStatus::SigningReleased {
            return Err(DepositWalletError::InvalidSweepTransition);
        }
        if record.signing_attempt_high_water != attempt
            || derive_sweep_signing_session(self.wallet, id, attempt) != Some(session)
            || record.signing_intent.session() != session.0
            || record.signing_intent.intent_digest() != intent_digest
        {
            return Err(DepositWalletError::UnknownSweepSigningAttempt);
        }
        Ok(())
    }

    /// Validate a portable certified completion against a same-ID local intent, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if local inputs or the attempt-independent prepared family differ.
    pub(crate) fn validate_certified_local_sweep(
        &self,
        id: SweepId,
        inputs: &[WalletOutputId],
        signed: &SignedSweepTransaction,
    ) -> Result<(), DepositWalletError> {
        let Some(record) = self.sweeps.get(&id) else {
            return Ok(());
        };
        if record.inputs != inputs {
            return Err(DepositWalletError::CertifiedSweepConflict);
        }
        let binding = record
            .family_key_images
            .as_ref()
            .ok_or(DepositWalletError::MissingSweepFamilyKeyImages)?;
        record.signing_intent.validate_completed_transaction(inputs.len(), binding, signed)?;
        Ok(())
    }

    /// Return the attempt-independent key-image binding for a sweep family.
    #[must_use]
    pub fn sweep_family_key_images(&self, id: SweepId) -> Option<&FamilyKeyImageBinding> {
        self.sweeps.get(&id).and_then(|record| record.family_key_images.as_ref())
    }

    /// Derive and validate the exact key-image binding without mutating scanner state.
    ///
    /// Parties sign this preview before a quorum certificate authorizes the separate pin
    /// transition. This avoids making the attestation depend on an already-mutated local worker.
    pub fn preview_sweep_family_key_images(
        &self,
        id: SweepId,
        key_images: Vec<[u8; 32]>,
        unsigned_transaction_digest: [u8; 32],
    ) -> Result<FamilyKeyImageBinding, DepositWalletError> {
        let record = self.sweeps.get(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        if record.status != SweepStatus::SigningReleased {
            return Err(DepositWalletError::InvalidSweepTransition);
        }
        let binding = FamilyKeyImageBinding {
            sweep: id,
            inputs: record.inputs.clone(),
            key_images,
            family_digest: record.signing_intent.family_digest(),
            unsigned_transaction_digest,
        };
        validate_family_key_image_binding(record, &binding)?;
        if let Some(existing) = &record.family_key_images
            && existing != &binding
        {
            return Err(DepositWalletError::SweepFamilyKeyImageConflict);
        }
        Ok(binding)
    }

    /// Pin the exact threshold-derived key images before any signature share is exposed.
    ///
    /// The caller is responsible for validating the portable quorum evidence which produced this
    /// ordered vector. This state transition binds it to the exact local inputs and immutable
    /// prepared/signable family; an exact replay is idempotent and any change fails closed.
    pub fn pin_sweep_family_key_images(
        &mut self,
        id: SweepId,
        key_images: Vec<[u8; 32]>,
        unsigned_transaction_digest: [u8; 32],
    ) -> Result<FamilyKeyImageBinding, DepositWalletError> {
        let binding =
            self.preview_sweep_family_key_images(id, key_images, unsigned_transaction_digest)?;
        if self
            .sweeps
            .get(&id)
            .ok_or(DepositWalletError::UnknownSweep(id))?
            .family_key_images
            .is_some()
        {
            return Ok(binding);
        }
        self.sweeps.get_mut(&id).ok_or(DepositWalletError::UnknownSweep(id))?.family_key_images =
            Some(binding.clone());
        Ok(binding)
    }

    /// Validate public family invariants for a full candidate without consulting retry-specific
    /// session, committee, or signer fields.
    ///
    /// This validates canonical bytes, exact key images, transaction shape, outputs and encrypted
    /// amounts through Monero's `Eventuality`. It deliberately does not claim to verify CLSAG or
    /// Bulletproof+ cryptography; the worker additionally validates those proofs against the exact
    /// prepared rings before accepting or settling a candidate.
    pub(crate) fn validate_sweep_family_candidate_shape(
        &self,
        id: SweepId,
        signed: &SignedSweepTransaction,
    ) -> Result<(), DepositWalletError> {
        let record = self.sweeps.get(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        let binding = record
            .family_key_images
            .as_ref()
            .ok_or(DepositWalletError::MissingSweepFamilyKeyImages)?;
        validate_family_key_image_binding(record, binding)?;
        record.signing_intent.validate_completed_transaction(record.inputs.len(), binding, signed)
    }

    /// Return the active local sweep currently claiming an output, if any.
    #[must_use]
    pub(crate) fn active_sweep_claiming(&self, input: WalletOutputId) -> Option<SweepId> {
        self.sweeps.values().find_map(|sweep| {
            (is_active_sweep(sweep.status) && sweep.inputs.binary_search(&input).is_ok())
                .then_some(sweep.id)
        })
    }

    /// Iterate over byte-exact transactions which should be submitted/rebroadcast after restart.
    pub fn signed_sweeps_for_broadcast(
        &self,
    ) -> impl Iterator<Item = (SweepId, &SignedSweepTransaction)> {
        self.sweeps.values().flat_map(|record| {
            let broadcast =
                matches!(record.status, SweepStatus::Signed { .. } | SweepStatus::Broadcast { .. });
            record
                .family_candidates
                .iter()
                .filter_map(move |signed| broadcast.then_some((record.id, signed)))
        })
    }

    /// Return sorted broadcast sweeps whose exact transaction has retained root-output evidence.
    #[must_use]
    pub fn broadcast_sweep_confirmations(&self) -> Vec<SweepConfirmationEvidence> {
        self.sweeps
            .values()
            .filter_map(|record| {
                let SweepStatus::Broadcast { transaction } = record.status else {
                    return None;
                };
                self.root_transaction_chain_point(transaction)
                    .map(|block| SweepConfirmationEvidence { sweep: record.id, transaction, block })
            })
            .collect()
    }

    /// Return the exact inclusion point proven by a root output from `transaction`.
    #[must_use]
    pub fn root_transaction_chain_point(&self, transaction: [u8; 32]) -> Option<ChainPoint> {
        self.root_output_inclusions
            .iter()
            .find_map(|(id, point)| (id.transaction == transaction).then_some(*point))
    }

    /// Pin exact root-output inclusion while an active family awaits portable terminal adoption.
    pub(crate) fn pin_root_transaction(
        &mut self,
        transaction: [u8; 32],
        block: ChainPoint,
    ) -> Result<(), DepositWalletError> {
        if transaction == [0_u8; 32]
            || self.root_transaction_chain_point(transaction) != Some(block)
        {
            return Err(DepositWalletError::InvalidSweepConfirmation);
        }
        if !self.pinned_root_transactions.contains(&transaction)
            && self.pinned_root_transactions.len() == MAX_PINNED_ROOT_TRANSACTIONS
        {
            return Err(DepositWalletError::PinnedRootTransactionCapacity);
        }
        self.pinned_root_transactions.insert(transaction);
        Ok(())
    }

    /// Pin exact root-output inclusion for a verified portable completion.
    ///
    /// Late joiners may not have a local sweep record, so the portable capability supplies the
    /// sweep/input/transaction binding. The scanner must nevertheless have authenticated a root
    /// output from that exact transaction at `confirmation`; a bare chain point is insufficient.
    pub(crate) fn pin_verified_portable_terminal(
        &mut self,
        portable: &VerifiedPortableSweepTerminal,
        confirmation: ChainPoint,
    ) -> Result<bool, DepositWalletError> {
        self.validate_verified_portable_terminal_binding(portable)?;
        ChainPoint::new(confirmation.height, confirmation.hash)?;
        if confirmation.height > self.tip().height
            || self.authenticated_chain_point(confirmation.height) != Some(confirmation)
            || !self.root_transaction_observed_at(portable.transaction, confirmation)
        {
            return Err(DepositWalletError::InvalidSweepConfirmation);
        }
        let changed = !self.pinned_root_transactions.contains(&portable.transaction);
        self.pin_root_transaction(portable.transaction, confirmation)?;
        Ok(changed)
    }

    /// Release root inclusion only from the fence-gated terminal compaction transition.
    fn release_compacted_root_witness(&mut self, transaction: [u8; 32]) -> bool {
        let mut changed = self.pinned_root_transactions.remove(&transaction);
        let removable = self
            .root_output_inclusions
            .keys()
            .filter(|id| id.transaction == transaction)
            .copied()
            .collect::<Vec<_>>();
        for id in removable {
            changed |= self.root_outputs.remove(&id).is_some();
            self.root_output_inclusions.remove(&id);
            for stored in self.blocks.values_mut() {
                if let Ok(position) = stored.root_outputs.binary_search(&id) {
                    stored.root_outputs.remove(position);
                }
            }
            for pinned in self.pinned_historical_blocks.values_mut() {
                if let Ok(position) = pinned.root_outputs.binary_search(&id) {
                    pinned.root_outputs.remove(position);
                }
            }
        }
        let empty_unheld = self
            .pinned_historical_blocks
            .iter()
            .filter_map(|(height, pinned)| {
                (pinned.outputs.is_empty() && pinned.root_outputs.is_empty() && !pinned.held)
                    .then_some(*height)
            })
            .collect::<Vec<_>>();
        for height in empty_unheld {
            self.pinned_historical_blocks.remove(&height);
        }
        changed
    }

    pub(crate) fn pinned_root_transactions(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.pinned_root_transactions.iter().copied()
    }

    /// Exact historical chain points whose empty/full block bodies are held by a durable worker
    /// obligation rather than only by retained wallet outputs.
    pub(crate) fn held_historical_chain_points(&self) -> impl Iterator<Item = ChainPoint> + '_ {
        self.pinned_historical_blocks
            .values()
            .filter(|pinned| pinned.held)
            .map(|pinned| pinned.block.point)
    }

    /// Re-seal one exact retained/pinned block header for a backfill or recognition hold.
    ///
    /// This avoids asking the chain source for a block which is already authenticated locally.
    /// The output vectors are intentionally empty: a hold protects an already-validated local
    /// block, while output-bearing historical evidence additionally requires a non-genesis
    /// portable sequence before it may import wallet state.
    pub(crate) fn authenticated_historical_block_header_evidence(
        &self,
        point: ChainPoint,
        portable_index_head: [u8; 32],
        portable_through_sequence: u64,
    ) -> Result<AuthenticatedHistoricalBlockEvidence, DepositWalletError> {
        let (block, timestamp) = self
            .blocks
            .get(&point.height)
            .filter(|stored| stored.block.point == point)
            .map(|stored| (stored.block, stored.timestamp))
            .or_else(|| {
                self.pinned_historical_blocks
                    .get(&point.height)
                    .filter(|stored| stored.block.point == point)
                    .map(|stored| (stored.block, stored.timestamp))
            })
            .ok_or(DepositWalletError::UnknownChainPoint(point))?;
        AuthenticatedHistoricalBlockEvidence::from_authenticated_chain_source(
            self.wallet,
            block,
            timestamp,
            self.tip(),
            portable_index_head,
            portable_through_sequence,
            Vec::new(),
            Vec::new(),
        )
    }

    /// Persist a trusted historical block header even when it contains no wallet outputs.
    ///
    /// Fixed-horizon backfill uses this for its horizon before the ordinary reorganization window
    /// can compact past it. A held pin participates in rollback while it remains inside that
    /// window. The caller should release an empty hold after the durable backfill frontier passes.
    pub(crate) fn pin_authenticated_historical_block(
        &mut self,
        evidence: &AuthenticatedHistoricalBlockEvidence,
    ) -> Result<bool, DepositWalletError> {
        self.validate_authenticated_historical_evidence(evidence)?;
        let point = evidence.block.point;
        if let Some(existing) = self.pinned_historical_blocks.get_mut(&point.height) {
            if existing.block != evidence.block || existing.timestamp != evidence.timestamp {
                return Err(DepositWalletError::ConflictingHistoricalBlock(point.height));
            }
            let changed = !existing.held;
            existing.held = true;
            return Ok(changed);
        }
        if self.pinned_historical_blocks.len() == MAX_PINNED_HISTORICAL_BLOCKS {
            return Err(DepositWalletError::HistoricalBlockCapacity);
        }
        let outputs = self
            .blocks
            .get(&point.height)
            .filter(|stored| {
                stored.block == evidence.block && stored.timestamp == evidence.timestamp
            })
            .map_or_else(Vec::new, |stored| stored.outputs.clone());
        let root_outputs = self
            .blocks
            .get(&point.height)
            .filter(|stored| {
                stored.block == evidence.block && stored.timestamp == evidence.timestamp
            })
            .map_or_else(Vec::new, |stored| stored.root_outputs.clone());
        self.pinned_historical_blocks.insert(
            point.height,
            PinnedHistoricalBlock {
                block: evidence.block,
                timestamp: evidence.timestamp,
                outputs,
                root_outputs,
                held: true,
            },
        );
        Ok(true)
    }

    /// Release an empty fixed-horizon pin after its durable backfill has completed.
    pub(crate) fn release_authenticated_historical_block(
        &mut self,
        point: ChainPoint,
    ) -> Result<bool, DepositWalletError> {
        let Some(pinned) = self.pinned_historical_blocks.get_mut(&point.height) else {
            return Ok(false);
        };
        if pinned.block.point != point {
            return Err(DepositWalletError::ConflictingHistoricalBlock(point.height));
        }
        let changed = pinned.held;
        pinned.held = false;
        if pinned.outputs.is_empty() && pinned.root_outputs.is_empty() {
            self.pinned_historical_blocks.remove(&point.height);
        }
        Ok(changed)
    }

    /// Insert scanner outputs from one authenticated historical/backfill block atomically.
    ///
    /// Evidence which overlaps the retained reorganization suffix must exactly match its block,
    /// parent, and canonical timestamp. Such outputs are attached to the ordinary block journal
    /// and roll back with it. Older evidence is pinned with its timestamp and exact deposit/root
    /// output IDs so it remains restart-valid after the moving checkpoint advances. Exact replay
    /// is a no-op; conflicting IDs or one-time keys reject the entire batch.
    pub(crate) fn insert_authenticated_historical_outputs(
        &mut self,
        evidence: &AuthenticatedHistoricalBlockEvidence,
    ) -> Result<bool, DepositWalletError> {
        self.validate_authenticated_historical_evidence(evidence)?;
        if evidence
            .outputs
            .len()
            .checked_add(evidence.root_outputs.len())
            .is_none_or(|count| count > MAX_HISTORICAL_OUTPUTS_PER_BLOCK)
        {
            return Err(DepositWalletError::HistoricalOutputBatchCapacity);
        }
        if evidence.outputs.is_empty() && evidence.root_outputs.is_empty() {
            return Ok(false);
        }

        let mut unique = BTreeMap::<WalletOutputId, PersistedWalletOutput>::new();
        let mut unique_root = BTreeMap::<WalletOutputId, PersistedRootOutput>::new();
        let mut keys = BTreeMap::<[u8; 32], WalletOutputId>::new();
        for output in &evidence.outputs {
            output.validate(self.root_spend_key)?;
            if let Some(previous) = unique.insert(output.id, output.clone())
                && &previous != output
            {
                return Err(DepositWalletError::DuplicateOutputId(output.id));
            }
            if let Some(existing) = keys.insert(output.output_key, output.id)
                && existing != output.id
            {
                return Err(DepositWalletError::DuplicateOutputKey {
                    existing,
                    duplicate: output.id,
                });
            }
        }
        for output in &evidence.root_outputs {
            output.validate(self.root_spend_key)?;
            if unique.contains_key(&output.id) {
                return Err(DepositWalletError::DuplicateOutputId(output.id));
            }
            if let Some(previous) = unique_root.insert(output.id, output.clone())
                && &previous != output
            {
                return Err(DepositWalletError::DuplicateOutputId(output.id));
            }
            if let Some(existing) = keys.insert(output.output_key, output.id)
                && existing != output.id
            {
                return Err(DepositWalletError::DuplicateOutputKey {
                    existing,
                    duplicate: output.id,
                });
            }
        }

        let point = evidence.block.point;
        let mut additions = Vec::new();
        let mut root_additions = Vec::new();
        for output in unique.values() {
            if self.root_outputs.contains_key(&output.id) {
                return Err(DepositWalletError::DuplicateOutputId(output.id));
            }
            if let Some(existing) = self.outputs.get(&output.id) {
                if existing != output || self.output_inclusions.get(&output.id) != Some(&point) {
                    return Err(DepositWalletError::DuplicateOutputId(output.id));
                }
                continue;
            }
            if let Some(existing) = self.known_output_with_key(output.output_key) {
                return Err(DepositWalletError::DuplicateOutputKey {
                    existing,
                    duplicate: output.id,
                });
            }
            additions.push(output.clone());
        }
        for output in unique_root.values() {
            if self.outputs.contains_key(&output.id) {
                return Err(DepositWalletError::DuplicateOutputId(output.id));
            }
            if let Some(existing) = self.root_outputs.get(&output.id) {
                if existing != output || self.root_output_inclusions.get(&output.id) != Some(&point)
                {
                    return Err(DepositWalletError::DuplicateOutputId(output.id));
                }
                continue;
            }
            if let Some(existing) = self.known_output_with_key(output.output_key) {
                return Err(DepositWalletError::DuplicateOutputKey {
                    existing,
                    duplicate: output.id,
                });
            }
            root_additions.push(output.clone());
        }
        if self
            .retained_output_count()
            .checked_add(additions.len())
            .and_then(|count| count.checked_add(root_additions.len()))
            .is_none_or(|count| count > MAX_RETAINED_WALLET_OUTPUTS)
        {
            return Err(DepositWalletError::RetainedOutputCapacity);
        }

        if point.height > self.anchor.height {
            let stored = self
                .blocks
                .get(&point.height)
                .ok_or(DepositWalletError::UnknownChainPoint(point))?;
            if stored.block != evidence.block || stored.timestamp != evidence.timestamp {
                return Err(DepositWalletError::ConflictingHistoricalBlock(point.height));
            }
        } else if let Some(existing) = self.pinned_historical_blocks.get(&point.height) {
            if existing.block != evidence.block || existing.timestamp != evidence.timestamp {
                return Err(DepositWalletError::ConflictingHistoricalBlock(point.height));
            }
        } else if self.pinned_historical_blocks.len() == MAX_PINNED_HISTORICAL_BLOCKS {
            return Err(DepositWalletError::HistoricalBlockCapacity);
        }

        let mut changed = !additions.is_empty() || !root_additions.is_empty();
        for output in additions {
            self.output_inclusions.insert(output.id, point);
            self.outputs.insert(output.id, output);
        }
        for output in root_additions {
            self.root_output_inclusions.insert(output.id, point);
            self.root_outputs.insert(output.id, output);
        }
        let ids = unique.keys().copied().collect::<Vec<_>>();
        let root_ids = unique_root.keys().copied().collect::<Vec<_>>();
        if point.height > self.anchor.height {
            let stored =
                self.blocks.get_mut(&point.height).ok_or(DepositWalletError::CorruptScanState)?;
            for id in &ids {
                match stored.outputs.binary_search(id) {
                    Ok(_) => {}
                    Err(position) => {
                        stored.outputs.insert(position, *id);
                        changed = true;
                    }
                }
            }
            for id in &root_ids {
                match stored.root_outputs.binary_search(id) {
                    Ok(_) => {}
                    Err(position) => {
                        stored.root_outputs.insert(position, *id);
                        changed = true;
                    }
                }
            }
            if let Some(pinned) = self.pinned_historical_blocks.get_mut(&point.height) {
                for id in ids {
                    if let Err(position) = pinned.outputs.binary_search(&id) {
                        pinned.outputs.insert(position, id);
                        changed = true;
                    }
                }
                for id in root_ids {
                    if let Err(position) = pinned.root_outputs.binary_search(&id) {
                        pinned.root_outputs.insert(position, id);
                        changed = true;
                    }
                }
            }
        } else {
            let pinned = self.pinned_historical_blocks.entry(point.height).or_insert_with(|| {
                PinnedHistoricalBlock {
                    block: evidence.block,
                    timestamp: evidence.timestamp,
                    outputs: Vec::new(),
                    root_outputs: Vec::new(),
                    held: false,
                }
            });
            for id in ids {
                match pinned.outputs.binary_search(&id) {
                    Ok(_) => {}
                    Err(position) => {
                        pinned.outputs.insert(position, id);
                        changed = true;
                    }
                }
            }
            for id in root_ids {
                match pinned.root_outputs.binary_search(&id) {
                    Ok(_) => {}
                    Err(position) => {
                        pinned.root_outputs.insert(position, id);
                        changed = true;
                    }
                }
            }
        }
        Ok(changed)
    }

    /// Atomically append a contiguous block and its scanner results.
    ///
    /// Every result must have been authenticated by the bounded output scanner and satisfy
    /// `output_key = root_spend_key + key_offset * G`. Duplicate absolute IDs or duplicate
    /// one-time keys reject the entire block before mutation. The caller must durably install each
    /// reciprocal local-safety output binding before calling this method.
    ///
    /// # Errors
    ///
    /// Returns an error for a discontinuous block, malformed scanner result, wrong key relation,
    /// or duplicate output identity/key.
    pub fn append_block(
        &mut self,
        block: ScannedBlock,
        timestamp: u64,
        outputs: Vec<PersistedWalletOutput>,
    ) -> Result<(), DepositWalletError> {
        self.append_block_with_root(block, timestamp, outputs, Vec::new())
    }

    /// Atomically append a contiguous block with both deposit and root/primary scanner results.
    ///
    /// Root results participate in the same absolute-ID and burning-bug uniqueness checks, yet
    /// are excluded from deposit availability and consolidation selection.
    ///
    /// # Errors
    ///
    /// Returns an error for a discontinuous block, malformed scanner result, wrong key relation,
    /// or any duplicate output identity/key across either output class.
    pub fn append_block_with_root(
        &mut self,
        block: ScannedBlock,
        timestamp: u64,
        mut outputs: Vec<PersistedWalletOutput>,
        mut root_outputs: Vec<PersistedRootOutput>,
    ) -> Result<(), DepositWalletError> {
        self.validate_wallet_domain()?;
        validate_next_block(self.tip(), block)?;
        outputs.sort_unstable_by_key(PersistedWalletOutput::id);
        root_outputs.sort_unstable_by_key(PersistedRootOutput::id);

        let mut ids = BTreeSet::new();
        let mut keys = BTreeMap::<[u8; 32], WalletOutputId>::new();
        for output in &outputs {
            output.validate(self.root_spend_key)?;
            if !ids.insert(output.id)
                || self.outputs.contains_key(&output.id)
                || self.root_outputs.contains_key(&output.id)
            {
                return Err(DepositWalletError::DuplicateOutputId(output.id));
            }
            if let Some(existing) = keys.insert(output.output_key, output.id) {
                return Err(DepositWalletError::DuplicateOutputKey {
                    existing,
                    duplicate: output.id,
                });
            }
            if let Some(existing) = self.known_output_with_key(output.output_key) {
                return Err(DepositWalletError::DuplicateOutputKey {
                    existing,
                    duplicate: output.id,
                });
            }
        }
        for output in &root_outputs {
            output.validate(self.root_spend_key)?;
            if !ids.insert(output.id)
                || self.outputs.contains_key(&output.id)
                || self.root_outputs.contains_key(&output.id)
            {
                return Err(DepositWalletError::DuplicateOutputId(output.id));
            }
            if let Some(existing) = keys.insert(output.output_key, output.id) {
                return Err(DepositWalletError::DuplicateOutputKey {
                    existing,
                    duplicate: output.id,
                });
            }
            if let Some(existing) = self.known_output_with_key(output.output_key) {
                return Err(DepositWalletError::DuplicateOutputKey {
                    existing,
                    duplicate: output.id,
                });
            }
        }
        if self
            .retained_output_count()
            .checked_add(outputs.len())
            .and_then(|count| count.checked_add(root_outputs.len()))
            .is_none_or(|count| count > MAX_RETAINED_WALLET_OUTPUTS)
        {
            return Err(DepositWalletError::RetainedOutputCapacity);
        }

        let output_ids = outputs.iter().map(PersistedWalletOutput::id).collect::<Vec<_>>();
        let root_output_ids = root_outputs.iter().map(PersistedRootOutput::id).collect::<Vec<_>>();
        for output in outputs {
            self.output_inclusions.insert(output.id, block.point);
            self.outputs.insert(output.id, output);
        }
        for output in root_outputs {
            self.root_output_inclusions.insert(output.id, block.point);
            self.root_outputs.insert(output.id, output);
        }
        self.blocks.insert(
            block.point.height,
            StoredBlock { block, timestamp, outputs: output_ids, root_outputs: root_output_ids },
        );
        Ok(())
    }

    /// Reserve a canonical set of retained outputs for one exact consolidation transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty/non-canonical input set, unknown/already claimed input,
    /// duplicate attempt ID, or zero signing-context commitment.
    pub fn reserve_sweep(&mut self, mut record: SweepRecord) -> Result<(), DepositWalletError> {
        if record.id.0 == [0_u8; 32] {
            return Err(DepositWalletError::InvalidSweep);
        }
        record.signing_intent.validate(record.id, self.root_spend_key)?;
        if record.status != SweepStatus::Reserved
            || record.signed_transaction.is_some()
            || record.signing_attempt_high_water == 0
            || !record.retired_signing_attempts.is_empty()
            || record.family_key_images.is_some()
            || !record.family_candidates.is_empty()
            || derive_sweep_signing_session(
                self.wallet,
                record.id,
                record.signing_attempt_high_water,
            )
            .map(|session| session.0)
                != Some(record.signing_intent.session())
        {
            return Err(DepositWalletError::InvalidSweepTransition);
        }
        if self.sweeps.contains_key(&record.id) {
            return Err(DepositWalletError::DuplicateSweep(record.id));
        }
        if self.sweeps.len() == MAX_ACTIVE_SWEEP_RECORDS {
            return Err(DepositWalletError::SweepCapacity);
        }
        if self.signing_session_known(record.signing_intent.session()) {
            return Err(DepositWalletError::ReusedSweepSigningSession);
        }
        record.inputs.sort_unstable();
        if record.inputs.is_empty() || record.inputs.windows(2).any(|window| window[0] == window[1])
        {
            return Err(DepositWalletError::InvalidSweepInputs);
        }
        for input in &record.inputs {
            if !self.outputs.contains_key(input) {
                return Err(DepositWalletError::UnknownOutput(*input));
            }
            if self.is_claimed(*input) {
                return Err(DepositWalletError::OutputAlreadyClaimed(*input));
            }
        }
        self.sweeps.insert(record.id, record);
        Ok(())
    }

    /// Durably authorize nonce creation for an exact reserved signing intent.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown sweep or invalid lifecycle transition.
    pub fn release_sweep_for_signing(&mut self, id: SweepId) -> Result<(), DepositWalletError> {
        let record = self.sweeps.get_mut(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        match record.status {
            SweepStatus::Reserved => {
                record.status = SweepStatus::SigningReleased;
                Ok(())
            }
            _ => Err(DepositWalletError::InvalidSweepTransition),
        }
    }

    /// Tombstone a released session and replace it with a fresh, fully validated intent.
    ///
    /// Only the session/committee/signer binding may change. The epoch, exact plan, inputs,
    /// private prepared representation, signable transaction, fee, and root key remain byte-for-
    /// byte identical. Inputs remain claimed throughout. The monotonic high-water permanently
    /// consumes the old session even after its bounded exact tombstone is compacted.
    ///
    /// # Errors
    ///
    /// Returns an error unless the sweep is `SigningReleased` and the replacement is the exact
    /// deterministic successor of the durable attempt high-water.
    pub fn recover_released_sweep_signing_intent(
        &mut self,
        id: SweepId,
        replacement: SweepSigningIntent,
    ) -> Result<RetiredSweepSigningAttempt, DepositWalletError> {
        replacement.validate(id, self.root_spend_key)?;
        let record = self.sweeps.get(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        if record.status != SweepStatus::SigningReleased {
            return Err(DepositWalletError::InvalidSweepTransition);
        }
        let next_attempt = record
            .signing_attempt_high_water
            .checked_add(1)
            .ok_or(DepositWalletError::SweepSigningAttemptLimit)?;
        if derive_sweep_signing_session(self.wallet, id, next_attempt).map(|session| session.0)
            != Some(replacement.session())
        {
            return Err(DepositWalletError::ReusedSweepSigningSession);
        }
        let current = &record.signing_intent;
        if replacement.epoch != current.epoch
            || replacement.plan_commitment != current.plan_commitment
            || replacement.group_key != current.group_key
            || replacement.signable_transaction != current.signable_transaction
            || replacement.prepared_sweep_intent != current.prepared_sweep_intent
            || replacement.transaction_commitment != current.transaction_commitment
            || replacement.fee_atomic_units != current.fee_atomic_units
            || replacement.intent_digest == current.intent_digest
        {
            return Err(DepositWalletError::SweepRecoveryIntentMismatch);
        }
        let retired = RetiredSweepSigningAttempt {
            attempt: record.signing_attempt_high_water,
            session: current.session,
            intent_digest: current.intent_digest,
        };
        let record = self.sweeps.get_mut(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        record.retired_signing_attempts.push(retired);
        if record.retired_signing_attempts.len() > MAX_RETAINED_SWEEP_SIGNING_ATTEMPTS {
            record.retired_signing_attempts.remove(0);
        }
        record.signing_intent = replacement;
        record.signing_attempt_high_water = next_attempt;
        Ok(retired)
    }

    /// Advance a lagging released sweep to an authenticated later attempt without minting a nonce
    /// authorization. Every skipped deterministic session is permanently below the high-water.
    pub(crate) fn catch_up_certified_sweep_signing_intent(
        &mut self,
        id: SweepId,
        attempt: u64,
        replacement: SweepSigningIntent,
    ) -> Result<(), DepositWalletError> {
        replacement.validate(id, self.root_spend_key)?;
        let record = self.sweeps.get(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        if record.status != SweepStatus::SigningReleased
            || attempt <= record.signing_attempt_high_water
            || derive_sweep_signing_session(self.wallet, id, attempt).map(|session| session.0)
                != Some(replacement.session())
        {
            return Err(DepositWalletError::InvalidSweepTransition);
        }
        let current = &record.signing_intent;
        if replacement.epoch != current.epoch
            || replacement.plan_commitment != current.plan_commitment
            || replacement.group_key != current.group_key
            || replacement.signable_transaction != current.signable_transaction
            || replacement.prepared_sweep_intent != current.prepared_sweep_intent
            || replacement.transaction_commitment != current.transaction_commitment
            || replacement.fee_atomic_units != current.fee_atomic_units
        {
            return Err(DepositWalletError::SweepRecoveryIntentMismatch);
        }
        let retired = RetiredSweepSigningAttempt {
            attempt: record.signing_attempt_high_water,
            session: current.session,
            intent_digest: current.intent_digest,
        };
        let record = self.sweeps.get_mut(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        record.retired_signing_attempts.push(retired);
        if record.retired_signing_attempts.len() > MAX_RETAINED_SWEEP_SIGNING_ATTEMPTS {
            record.retired_signing_attempts.remove(0);
        }
        record.signing_intent = replacement;
        record.signing_attempt_high_water = attempt;
        Ok(())
    }

    /// Install a quorum-certified terminal abandonment for an unsigned post-nonce family.
    ///
    /// The worker has already reconstructed `certified_intent` from the authenticated attempt.
    /// A later attempt may advance the high-water, but no transition here releases signing or
    /// clears any input/key-image/session claim. Exact replay is read-only.
    pub(crate) fn record_certified_sweep_abandonment(
        &mut self,
        id: SweepId,
        attempt: u64,
        certified_intent: SweepSigningIntent,
        ancestor: ChainPoint,
    ) -> Result<bool, DepositWalletError> {
        certified_intent.validate(id, self.root_spend_key)?;
        if !self.contains_chain_point(ancestor)
            || derive_sweep_signing_session(self.wallet, id, attempt).map(|session| session.0)
                != Some(certified_intent.session())
        {
            return Err(DepositWalletError::InvalidSweepTransition);
        }
        let record = self.sweeps.get(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        let already_abandoned = match record.status {
            SweepStatus::AbandonedByReorg { ancestor: known } if known == ancestor => true,
            SweepStatus::QuarantinedByReorg { ancestor: known, transaction: None }
                if known == ancestor =>
            {
                false
            }
            _ => return Err(DepositWalletError::InvalidSweepTransition),
        };
        let current = &record.signing_intent;
        if certified_intent.epoch != current.epoch
            || certified_intent.plan_commitment != current.plan_commitment
            || certified_intent.group_key != current.group_key
            || certified_intent.signable_transaction != current.signable_transaction
            || certified_intent.prepared_sweep_intent != current.prepared_sweep_intent
            || certified_intent.transaction_commitment != current.transaction_commitment
            || certified_intent.fee_atomic_units != current.fee_atomic_units
        {
            return Err(DepositWalletError::SweepRecoveryIntentMismatch);
        }
        if attempt == record.signing_attempt_high_water
            && (certified_intent.session() != current.session()
                || certified_intent.intent_digest() != current.intent_digest())
        {
            return Err(DepositWalletError::UnknownSweepSigningAttempt);
        }

        let advanced_high_water = attempt > record.signing_attempt_high_water;
        let record = self.sweeps.get_mut(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        if attempt > record.signing_attempt_high_water {
            record.retired_signing_attempts.push(RetiredSweepSigningAttempt {
                attempt: record.signing_attempt_high_water,
                session: record.signing_intent.session,
                intent_digest: record.signing_intent.intent_digest,
            });
            if record.retired_signing_attempts.len() > MAX_RETAINED_SWEEP_SIGNING_ATTEMPTS {
                record.retired_signing_attempts.remove(0);
            }
            record.signing_intent = certified_intent;
            record.signing_attempt_high_water = attempt;
        }
        record.status = SweepStatus::AbandonedByReorg { ancestor };
        Ok(!already_abandoned || advanced_high_water)
    }

    /// Persist the exact canonical transaction after threshold signing and before RPC submission.
    ///
    /// Replaying an identical transaction is idempotent. Distinct fully matching variants from
    /// later retry views/subsets are retained in a bounded sorted family archive; retry-specific
    /// signatures and pseudo-outs may change without changing inputs, key images, or outputs.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown sweep, malformed/mismatched bytes, or invalid state.
    pub fn mark_sweep_signed(
        &mut self,
        id: SweepId,
        signed: SignedSweepTransaction,
    ) -> Result<(), DepositWalletError> {
        signed.validate()?;
        let transaction = signed.transaction_id();
        let record = self.sweeps.get_mut(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        let binding = record
            .family_key_images
            .as_ref()
            .ok_or(DepositWalletError::MissingSweepFamilyKeyImages)?;
        record.signing_intent.validate_completed_transaction(
            record.inputs.len(),
            binding,
            &signed,
        )?;
        match record.status {
            SweepStatus::SigningReleased => {
                if record.signed_transaction.is_some() {
                    return Err(DepositWalletError::InvalidSweepTransition);
                }
                insert_family_candidate(record, signed.clone())?;
                record.signed_transaction = Some(signed);
                record.status = SweepStatus::Signed { transaction };
                Ok(())
            }
            SweepStatus::Signed { .. } | SweepStatus::Broadcast { .. } => {
                insert_family_candidate(record, signed)?;
                Ok(())
            }
            SweepStatus::Confirmed { .. }
                if record
                    .family_candidates
                    .binary_search_by_key(&transaction, SignedSweepTransaction::transaction_id)
                    .is_ok() =>
            {
                Ok(())
            }
            _ => Err(DepositWalletError::InvalidSweepTransition),
        }
    }

    /// Adopt a portable-certified same-family transaction from an exact known signing attempt.
    ///
    /// The exact `(session, intent digest)` must identify either the current released intent or a
    /// permanent crash-recovery tombstone. A retired attempt remains burned for nonce creation;
    /// recognizing its already-produced result never restores that authority. Before adoption,
    /// the transaction is independently checked against the durable prepared family, pinned key
    /// images, rings, CLSAGs, Bulletproof+, outputs, and balance policy.
    pub(crate) fn adopt_portable_sweep_signed(
        &mut self,
        id: SweepId,
        attempt: u64,
        attempt_session: [u8; 32],
        attempt_intent_digest: [u8; 32],
        signed: SignedSweepTransaction,
    ) -> Result<(), DepositWalletError> {
        self.adopt_portable_sweep_signed_inner(
            id,
            Some(attempt),
            attempt_session,
            attempt_intent_digest,
            None,
            signed,
        )
    }

    /// Adopt a candidate whose compacted attempt was deterministically reconstructed by the
    /// encrypted worker from an independently authenticated quorum certificate.
    pub(crate) fn adopt_verified_portable_sweep_signed(
        &mut self,
        id: SweepId,
        attempt: u64,
        attempt_session: [u8; 32],
        attempt_intent_digest: [u8; 32],
        reconstructed_intent: SweepSigningIntent,
        signed: SignedSweepTransaction,
    ) -> Result<(), DepositWalletError> {
        reconstructed_intent.validate(id, self.root_spend_key)?;
        if reconstructed_intent.session() != attempt_session
            || reconstructed_intent.intent_digest() != attempt_intent_digest
        {
            return Err(DepositWalletError::UnknownSweepSigningAttempt);
        }
        self.adopt_portable_sweep_signed_inner(
            id,
            Some(attempt),
            attempt_session,
            attempt_intent_digest,
            Some(reconstructed_intent),
            signed,
        )
    }

    fn adopt_portable_sweep_signed_inner(
        &mut self,
        id: SweepId,
        certified_attempt: Option<u64>,
        attempt_session: [u8; 32],
        attempt_intent_digest: [u8; 32],
        mut reconstructed_intent: Option<SweepSigningIntent>,
        signed: SignedSweepTransaction,
    ) -> Result<(), DepositWalletError> {
        signed.validate()?;
        let transaction = signed.transaction_id();
        let record = self.sweeps.get_mut(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        let binding = record
            .family_key_images
            .as_ref()
            .ok_or(DepositWalletError::MissingSweepFamilyKeyImages)?;
        record.signing_intent.validate_completed_transaction(
            record.inputs.len(),
            binding,
            &signed,
        )?;
        let current_attempt = record.signing_attempt_high_water == certified_attempt.unwrap_or(0)
            && record.signing_intent.session() == attempt_session
            && record.signing_intent.intent_digest() == attempt_intent_digest;
        let retired_attempt = record.retired_signing_attempts.iter().any(|attempt| {
            Some(attempt.attempt) == certified_attempt
                && attempt.session == attempt_session
                && attempt.intent_digest == attempt_intent_digest
        });
        // A reconstructed adoption is acceptable only with an authenticated reconstructed intent:
        // the derived session alone authenticates (wallet, sweep, attempt), never the intent
        // digest, so a digest-less acceptance would let a forged tombstone bind an arbitrary
        // digest to a real retired session. Attempts whose tombstones were compacted away must
        // arrive through the verified entry point carrying the quorum-reconstructed intent.
        let reconstructed_attempt = certified_attempt.is_some_and(|attempt| {
            reconstructed_intent
                .as_ref()
                .is_some_and(|intent| intent.intent_digest() == attempt_intent_digest)
                && derive_sweep_signing_session(self.wallet, id, attempt).map(|session| session.0)
                    == Some(attempt_session)
        });
        if !current_attempt && !retired_attempt && !reconstructed_attempt {
            return Err(DepositWalletError::UnknownSweepSigningAttempt);
        }

        if let Some(attempt) =
            certified_attempt.filter(|attempt| *attempt > record.signing_attempt_high_water)
        {
            if !matches!(
                record.status,
                SweepStatus::Reserved | SweepStatus::SigningReleased | SweepStatus::Signed { .. }
            ) {
                return Err(DepositWalletError::CertifiedSweepConflict);
            }
            let replacement = reconstructed_intent
                .as_ref()
                .ok_or(DepositWalletError::UnknownSweepSigningAttempt)?;
            let current = &record.signing_intent;
            if replacement.epoch != current.epoch
                || replacement.plan_commitment != current.plan_commitment
                || replacement.group_key != current.group_key
                || replacement.signable_transaction != current.signable_transaction
                || replacement.prepared_sweep_intent != current.prepared_sweep_intent
                || replacement.transaction_commitment != current.transaction_commitment
                || replacement.fee_atomic_units != current.fee_atomic_units
            {
                return Err(DepositWalletError::SweepRecoveryIntentMismatch);
            }
            if record.status != SweepStatus::Reserved {
                record.retired_signing_attempts.push(RetiredSweepSigningAttempt {
                    attempt: record.signing_attempt_high_water,
                    session: current.session,
                    intent_digest: current.intent_digest,
                });
                if record.retired_signing_attempts.len() > MAX_RETAINED_SWEEP_SIGNING_ATTEMPTS {
                    record.retired_signing_attempts.remove(0);
                }
            }
            record.signing_intent = reconstructed_intent
                .take()
                .ok_or(DepositWalletError::UnknownSweepSigningAttempt)?;
            record.signing_attempt_high_water = attempt;
        }

        match record.status {
            SweepStatus::Reserved | SweepStatus::SigningReleased => {
                if record.signed_transaction.is_some() {
                    return Err(DepositWalletError::InvalidSweepTransition);
                }
                insert_family_candidate(record, signed.clone())?;
                record.signed_transaction = Some(signed);
                record.status = SweepStatus::Signed { transaction };
                Ok(())
            }
            SweepStatus::Signed { .. } => {
                insert_family_candidate(record, signed.clone())?;
                record.signed_transaction = Some(signed);
                record.status = SweepStatus::Signed { transaction };
                Ok(())
            }
            SweepStatus::Broadcast { .. } | SweepStatus::Confirmed { .. }
                if record.signed_transaction.as_ref() == Some(&signed) =>
            {
                insert_family_candidate(record, signed)?;
                Ok(())
            }
            SweepStatus::Broadcast { .. } | SweepStatus::Confirmed { .. } => {
                Err(DepositWalletError::CertifiedSweepConflict)
            }
            _ => Err(DepositWalletError::InvalidSweepTransition),
        }
    }

    /// Persist that a signed consolidation transaction was broadcast.
    ///
    /// Replaying the same transaction ID is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown sweep, zero/different transaction ID, or invalid state.
    pub fn mark_sweep_broadcast(
        &mut self,
        id: SweepId,
        transaction: [u8; 32],
    ) -> Result<(), DepositWalletError> {
        if transaction == [0_u8; 32] {
            return Err(DepositWalletError::InvalidSweepTransaction);
        }
        let record = self.sweeps.get_mut(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        match record.status {
            SweepStatus::Signed { .. }
                if record
                    .family_candidates
                    .binary_search_by_key(&transaction, SignedSweepTransaction::transaction_id)
                    .is_ok() =>
            {
                record.status = SweepStatus::Broadcast { transaction };
                Ok(())
            }
            SweepStatus::Broadcast { transaction: known }
            | SweepStatus::Confirmed { transaction: known, .. }
                if known == transaction
                    || (matches!(record.status, SweepStatus::Broadcast { .. })
                        && record
                            .family_candidates
                            .binary_search_by_key(
                                &transaction,
                                SignedSweepTransaction::transaction_id,
                            )
                            .is_ok()) =>
            {
                Ok(())
            }
            _ => Err(DepositWalletError::InvalidSweepTransition),
        }
    }

    /// Persist confirmation of a broadcast consolidation transaction in a retained block.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown sweep/block, mismatched transaction ID, or invalid state.
    pub fn mark_sweep_confirmed(
        &mut self,
        id: SweepId,
        transaction: [u8; 32],
        block: ChainPoint,
    ) -> Result<(), DepositWalletError> {
        if !self.contains_chain_point(block) {
            return Err(DepositWalletError::UnknownChainPoint(block));
        }
        let inputs = &self.sweeps.get(&id).ok_or(DepositWalletError::UnknownSweep(id))?.inputs;
        let newest_input_height = inputs
            .iter()
            .filter_map(|input| self.output_height(*input))
            .max()
            .ok_or(DepositWalletError::InvalidSweepConfirmation)?;
        if block.height <= newest_input_height {
            return Err(DepositWalletError::InvalidSweepConfirmation);
        }
        if !self.root_transaction_observed_at(transaction, block) {
            return Err(DepositWalletError::InvalidSweepConfirmation);
        }
        self.pin_root_transaction(transaction, block)?;
        let record = self.sweeps.get_mut(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        match record.status {
            SweepStatus::Broadcast { transaction: known } if known == transaction => {
                record.status = SweepStatus::Confirmed { transaction, block };
                Ok(())
            }
            SweepStatus::Confirmed { transaction: known, block: known_block }
                if known == transaction && known_block == block =>
            {
                Ok(())
            }
            _ => Err(DepositWalletError::InvalidSweepTransition),
        }
    }

    /// Persist an exact, fully worker-validated same-family transaction as the canonical winner.
    ///
    /// Unlike [`Self::mark_sweep_confirmed`], this accepts an unknown transaction ID produced by a
    /// private retry/subset. The immutable family and key images are rechecked here, while the
    /// worker is responsible for CLSAG/Bulletproof+/ring verification before invoking it. Exact
    /// bytes are retained so a reorg can revert to `Broadcast` and safely republish the winner.
    pub(crate) fn mark_sweep_family_confirmed(
        &mut self,
        id: SweepId,
        signed: SignedSweepTransaction,
        block: ChainPoint,
    ) -> Result<(), DepositWalletError> {
        self.mark_sweep_family_confirmed_inner(id, None, signed, block)
    }

    pub(crate) fn mark_verified_sweep_family_confirmed(
        &mut self,
        id: SweepId,
        attempt: u64,
        reconstructed_intent: SweepSigningIntent,
        signed: SignedSweepTransaction,
        block: ChainPoint,
    ) -> Result<(), DepositWalletError> {
        reconstructed_intent.validate(id, self.root_spend_key)?;
        if derive_sweep_signing_session(self.wallet, id, attempt).map(|session| session.0)
            != Some(reconstructed_intent.session())
        {
            return Err(DepositWalletError::UnknownSweepSigningAttempt);
        }
        self.mark_sweep_family_confirmed_inner(
            id,
            Some((attempt, reconstructed_intent)),
            signed,
            block,
        )
    }

    fn mark_sweep_family_confirmed_inner(
        &mut self,
        id: SweepId,
        verified_attempt: Option<(u64, SweepSigningIntent)>,
        signed: SignedSweepTransaction,
        block: ChainPoint,
    ) -> Result<(), DepositWalletError> {
        signed.validate()?;
        if !self.contains_chain_point(block) {
            return Err(DepositWalletError::UnknownChainPoint(block));
        }
        let transaction = signed.transaction_id();
        if !self.root_transaction_observed_at(transaction, block) {
            return Err(DepositWalletError::InvalidSweepConfirmation);
        }
        self.pin_root_transaction(transaction, block)?;
        let newest_input_height = self
            .sweeps
            .get(&id)
            .ok_or(DepositWalletError::UnknownSweep(id))?
            .inputs
            .iter()
            .filter_map(|input| self.output_height(*input))
            .max()
            .ok_or(DepositWalletError::InvalidSweepConfirmation)?;
        if block.height <= newest_input_height {
            return Err(DepositWalletError::InvalidSweepConfirmation);
        }
        let record = self.sweeps.get_mut(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        let binding = record
            .family_key_images
            .as_ref()
            .ok_or(DepositWalletError::MissingSweepFamilyKeyImages)?;
        record.signing_intent.validate_completed_transaction(
            record.inputs.len(),
            binding,
            &signed,
        )?;
        let certified_reserved_adoption = verified_attempt.is_some();
        if let Some((attempt, replacement)) = verified_attempt
            && attempt > record.signing_attempt_high_water
        {
            if !matches!(
                record.status,
                SweepStatus::Reserved
                    | SweepStatus::SigningReleased
                    | SweepStatus::Signed { .. }
                    | SweepStatus::Broadcast { .. }
                    | SweepStatus::QuarantinedByReorg { .. }
                    | SweepStatus::AbandonedByReorg { .. }
            ) {
                return Err(DepositWalletError::CertifiedSweepConflict);
            }
            let current = &record.signing_intent;
            if replacement.epoch != current.epoch
                || replacement.plan_commitment != current.plan_commitment
                || replacement.group_key != current.group_key
                || replacement.signable_transaction != current.signable_transaction
                || replacement.prepared_sweep_intent != current.prepared_sweep_intent
                || replacement.transaction_commitment != current.transaction_commitment
                || replacement.fee_atomic_units != current.fee_atomic_units
            {
                return Err(DepositWalletError::SweepRecoveryIntentMismatch);
            }
            record.retired_signing_attempts.push(RetiredSweepSigningAttempt {
                attempt: record.signing_attempt_high_water,
                session: current.session,
                intent_digest: current.intent_digest,
            });
            if record.retired_signing_attempts.len() > MAX_RETAINED_SWEEP_SIGNING_ATTEMPTS {
                record.retired_signing_attempts.remove(0);
            }
            record.signing_intent = replacement;
            record.signing_attempt_high_water = attempt;
        }
        match record.status {
            SweepStatus::Reserved if certified_reserved_adoption => {
                insert_family_candidate(record, signed.clone())?;
                record.signed_transaction = Some(signed);
                record.status = SweepStatus::Confirmed { transaction, block };
                Ok(())
            }
            SweepStatus::SigningReleased
            | SweepStatus::Signed { .. }
            | SweepStatus::Broadcast { .. }
            | SweepStatus::QuarantinedByReorg { .. }
            | SweepStatus::AbandonedByReorg { .. } => {
                insert_family_candidate(record, signed.clone())?;
                record.signed_transaction = Some(signed);
                record.status = SweepStatus::Confirmed { transaction, block };
                Ok(())
            }
            SweepStatus::Confirmed { transaction: known, block: known_block }
                if known == transaction && known_block == block =>
            {
                insert_family_candidate(record, signed.clone())?;
                if record.signed_transaction.as_ref() != Some(&signed) {
                    return Err(DepositWalletError::InvalidSweepTransition);
                }
                Ok(())
            }
            _ => Err(DepositWalletError::InvalidSweepTransition),
        }
    }

    /// Verify that a portable completion is old enough for destructive local compaction.
    ///
    /// Portable certification is necessary but not sufficient: the exact transaction inclusion
    /// must also be authenticated at or behind the moving scanner checkpoint. A local sweep, when
    /// present, must name the same inputs/transaction and cannot be an unsigned lineage.
    pub(crate) fn verify_terminal_compaction(
        &self,
        portable: &VerifiedPortableSweepTerminal,
        confirmation: ChainPoint,
    ) -> Result<VerifiedTerminalCompaction, DepositWalletError> {
        self.validate_verified_portable_terminal_binding(portable)?;
        let id = portable.sweep;
        let inputs = portable.inputs.as_slice();
        let transaction = portable.transaction;
        ChainPoint::new(confirmation.height, confirmation.hash)?;
        let verification_horizon = self.tip();
        if confirmation.height > self.anchor.height
            || confirmation.height > verification_horizon.height
            || self.authenticated_chain_point(confirmation.height) != Some(confirmation)
        {
            return Err(DepositWalletError::TerminalCompactionBeforeReorgFence {
                confirmation,
                fence: self.anchor,
            });
        }
        if !self.root_transaction_observed_at(transaction, confirmation) {
            return Err(DepositWalletError::InvalidSweepConfirmation);
        }
        if let Some(local) = self.sweeps.get(&id) {
            if local.inputs != inputs
                || matches!(
                    local.status,
                    SweepStatus::Reserved
                        | SweepStatus::SigningReleased
                        | SweepStatus::AbandonedByReorg { .. }
                )
                || local.signed_transaction.as_ref().map(SignedSweepTransaction::transaction_id)
                    != Some(transaction)
            {
                return Err(DepositWalletError::CertifiedSweepConflict);
            }
            if let SweepStatus::Confirmed { transaction: known, block } = local.status
                && (known != transaction || block != confirmation)
            {
                return Err(DepositWalletError::CertifiedSweepConflict);
            }
        }
        Ok(VerifiedTerminalCompaction {
            wallet: self.wallet,
            sweep: id,
            inputs: inputs.to_vec(),
            transaction,
            completion_certificate: portable.completion_certificate,
            portable_terminal: portable.portable_terminal,
            confirmation,
            fence: self.anchor,
            verification_horizon,
        })
    }

    /// Consume only the sweep/output/root-witness state authorized by a fresh compaction token.
    ///
    /// The token cannot survive serialization and is rechecked against the monotonic checkpoint
    /// immediately before mutation. Exact replay with the same in-memory token is a no-op.
    pub(crate) fn consume_verified_terminal_compaction(
        &mut self,
        verified: &VerifiedTerminalCompaction,
    ) -> Result<bool, DepositWalletError> {
        if verified.wallet != self.wallet
            || verified.sweep.0 == [0; 32]
            || verified.transaction == [0; 32]
            || verified.completion_certificate == [0; 32]
            || verified.portable_terminal == [0; 32]
            || verified.inputs.is_empty()
            || verified.inputs.windows(2).any(|window| window[0] >= window[1])
            || verified.confirmation.height > verified.fence.height
            || verified.fence.height > self.anchor.height
            || (verified.fence.height == self.anchor.height && verified.fence != self.anchor)
            || verified.verification_horizon.height > self.tip().height
            || (verified.verification_horizon.height == self.tip().height
                && verified.verification_horizon != self.tip())
        {
            return Err(DepositWalletError::CertifiedSweepConflict);
        }
        let terminal_state_remains = self.sweeps.contains_key(&verified.sweep)
            || verified.inputs.iter().any(|input| self.outputs.contains_key(input))
            || self.pinned_root_transactions.contains(&verified.transaction)
            || self.root_output_inclusions.keys().any(|id| id.transaction == verified.transaction);
        if terminal_state_remains
            && (self.authenticated_chain_point(verified.confirmation.height)
                != Some(verified.confirmation)
                || !self.root_transaction_observed_at(verified.transaction, verified.confirmation))
        {
            return Err(DepositWalletError::CertifiedSweepConflict);
        }
        if let Some(local) = self.sweeps.get(&verified.sweep)
            && (local.inputs.as_slice() != verified.inputs.as_slice()
                || local.signed_transaction.as_ref().map(SignedSweepTransaction::transaction_id)
                    != Some(verified.transaction))
        {
            return Err(DepositWalletError::CertifiedSweepConflict);
        }
        for input in &verified.inputs {
            if self.root_outputs.contains_key(input)
                || self.active_sweep_claiming(*input).is_some_and(|claim| claim != verified.sweep)
            {
                return Err(DepositWalletError::CertifiedSweepConflict);
            }
            if self.outputs.contains_key(input) != self.output_inclusions.contains_key(input) {
                return Err(DepositWalletError::CorruptScanState);
            }
        }

        let root_ids = self
            .root_output_inclusions
            .keys()
            .filter(|id| id.transaction == verified.transaction)
            .copied()
            .collect::<Vec<_>>();
        if root_ids.iter().any(|id| !self.root_outputs.contains_key(id))
            || self
                .root_outputs
                .keys()
                .any(|id| id.transaction == verified.transaction && !root_ids.contains(id))
        {
            return Err(DepositWalletError::CorruptScanState);
        }
        let mut changed = self.sweeps.remove(&verified.sweep).is_some();
        for input in &verified.inputs {
            let removed_output = self.outputs.remove(input);
            let removed_inclusion = self.output_inclusions.remove(input);
            debug_assert_eq!(removed_output.is_some(), removed_inclusion.is_some());
            changed |= removed_output.is_some();
            for stored in self.blocks.values_mut() {
                if let Ok(position) = stored.outputs.binary_search(input) {
                    stored.outputs.remove(position);
                }
            }
            for pinned in self.pinned_historical_blocks.values_mut() {
                if let Ok(position) = pinned.outputs.binary_search(input) {
                    pinned.outputs.remove(position);
                }
            }
        }
        let empty_unheld = self
            .pinned_historical_blocks
            .iter()
            .filter_map(|(height, pinned)| {
                (pinned.outputs.is_empty() && pinned.root_outputs.is_empty() && !pinned.held)
                    .then_some(*height)
            })
            .collect::<Vec<_>>();
        for height in empty_unheld {
            self.pinned_historical_blocks.remove(&height);
        }

        changed |= self.release_compacted_root_witness(verified.transaction);
        Ok(changed)
    }

    /// Abort and remove a reservation before signing, making its inputs available again.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown sweep or any post-broadcast state.
    pub fn abort_sweep(&mut self, id: SweepId) -> Result<(), DepositWalletError> {
        let record = self.sweeps.get(&id).ok_or(DepositWalletError::UnknownSweep(id))?;
        if record.status != SweepStatus::Reserved {
            return Err(DepositWalletError::InvalidSweepTransition);
        }
        self.sweeps.remove(&id);
        Ok(())
    }

    /// Roll back orphaned blocks and all outputs bound to them.
    ///
    /// A sweep loses its confirmation if only the confirmation block was removed. It is fully
    /// invalidated if any of its inputs disappeared. Retained inputs of an invalidated sweep are
    /// released for a future attempt.
    ///
    /// # Errors
    ///
    /// Returns an error unless `ancestor` is the anchor or an exactly retained chain point.
    pub fn rollback_to(
        &mut self,
        ancestor: ChainPoint,
    ) -> Result<RollbackReport, DepositWalletError> {
        if !self.contains_chain_point(ancestor) {
            return Err(DepositWalletError::UnknownChainPoint(ancestor));
        }
        let removed_outputs = self
            .blocks
            .iter()
            .filter(|(height, _)| **height > ancestor.height)
            .flat_map(|(_, block)| block.outputs.iter().copied())
            .collect::<BTreeSet<_>>();
        let removed_root_outputs = self
            .blocks
            .iter()
            .filter(|(height, _)| **height > ancestor.height)
            .flat_map(|(_, block)| block.root_outputs.iter().copied())
            .collect::<BTreeSet<_>>();

        let mut invalidated_sweeps = Vec::new();
        let mut quarantined_sweeps = Vec::new();
        let mut reverted_confirmations = Vec::new();
        for record in self.sweeps.values_mut() {
            if record.inputs.iter().any(|input| removed_outputs.contains(input)) {
                match record.status {
                    SweepStatus::Reserved => {
                        invalidated_sweeps.push(record.id);
                    }
                    SweepStatus::SigningReleased => {
                        record.status =
                            SweepStatus::QuarantinedByReorg { ancestor, transaction: None };
                        quarantined_sweeps.push(record.id);
                    }
                    SweepStatus::Signed { transaction }
                    | SweepStatus::Broadcast { transaction }
                    | SweepStatus::Confirmed { transaction, .. } => {
                        record.status = SweepStatus::QuarantinedByReorg {
                            ancestor,
                            transaction: Some(transaction),
                        };
                        quarantined_sweeps.push(record.id);
                    }
                    SweepStatus::QuarantinedByReorg { transaction, .. } => {
                        record.status = SweepStatus::QuarantinedByReorg { ancestor, transaction };
                        quarantined_sweeps.push(record.id);
                    }
                    SweepStatus::AbandonedByReorg { .. } => {
                        record.status = SweepStatus::AbandonedByReorg { ancestor };
                        quarantined_sweeps.push(record.id);
                    }
                }
                continue;
            }
            if let SweepStatus::Confirmed { transaction, block } = record.status
                && block.height > ancestor.height
            {
                record.status = SweepStatus::Broadcast { transaction };
                reverted_confirmations.push(record.id);
            }
        }
        for id in &invalidated_sweeps {
            self.sweeps.remove(id);
        }

        for id in &removed_outputs {
            self.outputs.remove(id);
            self.output_inclusions.remove(id);
        }
        for id in &removed_root_outputs {
            self.root_outputs.remove(id);
            self.root_output_inclusions.remove(id);
        }
        self.pinned_historical_blocks.retain(|height, _| *height <= ancestor.height);
        self.pinned_root_transactions.retain(|transaction| {
            self.root_outputs.keys().any(|output| output.transaction == *transaction)
        });
        self.blocks.retain(|height, _| *height <= ancestor.height);

        invalidated_sweeps.sort_unstable();
        quarantined_sweeps.sort_unstable();
        reverted_confirmations.sort_unstable();
        Ok(RollbackReport {
            removed_outputs: removed_outputs.into_iter().collect(),
            removed_root_outputs: removed_root_outputs.into_iter().collect(),
            invalidated_sweeps,
            quarantined_sweeps,
            reverted_confirmations,
        })
    }

    /// Advance the trusted checkpoint so only a bounded full-block reorg window remains.
    ///
    /// Primary outputs at or before the new checkpoint are dropped after their permanent
    /// ID/key safety bindings have been installed in the authenticated party-local index. Deposit
    /// outputs remain fully available until a verified portable terminal consumes them. A reorg
    /// crossing the resulting anchor is rejected by [`Self::rollback_to`] and must be resolved
    /// through an operator checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero window or inconsistent retained journal.
    pub fn compact_reorg_window(&mut self, max_reorg_depth: u32) -> Result<(), DepositWalletError> {
        if max_reorg_depth == 0 {
            return Err(DepositWalletError::InvalidReorgWindow);
        }
        let tip = self.tip();
        let Some(checkpoint_height) = tip.height.checked_sub(u64::from(max_reorg_depth)) else {
            return Ok(());
        };
        if checkpoint_height <= self.anchor.height {
            return Ok(());
        }
        let checkpoint = self
            .blocks
            .get(&checkpoint_height)
            .map(|stored| stored.block.point)
            .ok_or(DepositWalletError::CorruptScanState)?;

        let compact_root_ids = self
            .root_output_inclusions
            .iter()
            .filter_map(|(id, inclusion)| {
                (inclusion.height <= checkpoint_height
                    && !self.pinned_root_transactions.contains(&id.transaction))
                .then_some(*id)
            })
            .collect::<BTreeSet<_>>();
        if compact_root_ids.iter().any(|id| !self.root_outputs.contains_key(id)) {
            return Err(DepositWalletError::CorruptScanState);
        }

        let promotion_heights = self
            .blocks
            .range(..=checkpoint_height)
            .filter_map(|(height, stored)| {
                let retained_root =
                    stored.root_outputs.iter().any(|id| !compact_root_ids.contains(id));
                ((!stored.outputs.is_empty() || retained_root)
                    && !self.pinned_historical_blocks.contains_key(height))
                .then_some(*height)
            })
            .collect::<Vec<_>>();
        if self
            .pinned_historical_blocks
            .len()
            .checked_add(promotion_heights.len())
            .is_none_or(|count| count > MAX_PINNED_HISTORICAL_BLOCKS)
        {
            return Err(DepositWalletError::HistoricalBlockCapacity);
        }
        for (height, stored) in self.blocks.range(..=checkpoint_height) {
            if let Some(existing) = self.pinned_historical_blocks.get(height)
                && (existing.block != stored.block
                    || existing.timestamp != stored.timestamp
                    || existing.outputs != stored.outputs
                    || existing.root_outputs != stored.root_outputs)
            {
                return Err(DepositWalletError::CorruptScanState);
            }
        }
        for (height, stored) in self.blocks.range(..=checkpoint_height) {
            let retained_root_outputs = stored
                .root_outputs
                .iter()
                .filter(|id| !compact_root_ids.contains(*id))
                .copied()
                .collect::<Vec<_>>();
            if stored.outputs.is_empty()
                && retained_root_outputs.is_empty()
                && !self.pinned_historical_blocks.get(height).is_some_and(|pinned| pinned.held)
            {
                continue;
            }
            let pinned = self.pinned_historical_blocks.entry(*height).or_insert_with(|| {
                PinnedHistoricalBlock {
                    block: stored.block,
                    timestamp: stored.timestamp,
                    outputs: stored.outputs.clone(),
                    root_outputs: Vec::new(),
                    held: false,
                }
            });
            pinned.root_outputs = retained_root_outputs;
        }
        for id in compact_root_ids {
            self.root_outputs.remove(&id).ok_or(DepositWalletError::CorruptScanState)?;
            self.root_output_inclusions.remove(&id).ok_or(DepositWalletError::CorruptScanState)?;
            for pinned in self.pinned_historical_blocks.values_mut() {
                if let Ok(position) = pinned.root_outputs.binary_search(&id) {
                    pinned.root_outputs.remove(position);
                }
            }
        }
        let empty_unheld = self
            .pinned_historical_blocks
            .iter()
            .filter_map(|(height, pinned)| {
                (pinned.outputs.is_empty() && pinned.root_outputs.is_empty() && !pinned.held)
                    .then_some(*height)
            })
            .collect::<Vec<_>>();
        for height in empty_unheld {
            self.pinned_historical_blocks.remove(&height);
        }
        self.blocks.retain(|height, _| *height > checkpoint_height);
        self.anchor = checkpoint;
        Ok(())
    }

    /// Validate all chain, output, burning-bug, and active-sweep invariants after restore.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported or corrupt state.
    pub fn validate(&self) -> Result<(), DepositWalletError> {
        if self.version != SCAN_STATE_VERSION {
            return Err(DepositWalletError::UnsupportedScanStateVersion(self.version));
        }
        self.validate_wallet_domain()?;
        ChainPoint::new(self.birth_anchor.height, self.birth_anchor.hash)?;
        ChainPoint::new(self.anchor.height, self.anchor.hash)?;
        if self.birth_anchor.height > self.anchor.height
            || (self.birth_anchor.height == self.anchor.height && self.birth_anchor != self.anchor)
        {
            return Err(DepositWalletError::CorruptScanState);
        }

        let mut prior = self.anchor;
        let mut referenced_outputs = BTreeSet::new();
        let mut referenced_root_outputs = BTreeSet::new();
        for (height, stored) in &self.blocks {
            if *height != stored.block.point.height {
                return Err(DepositWalletError::CorruptScanState);
            }
            validate_next_block(prior, stored.block)?;
            if stored.outputs.windows(2).any(|window| window[0] >= window[1])
                || stored.root_outputs.windows(2).any(|window| window[0] >= window[1])
            {
                return Err(DepositWalletError::CorruptScanState);
            }
            for id in &stored.outputs {
                if !referenced_outputs.insert(*id)
                    || referenced_root_outputs.contains(id)
                    || !self.outputs.contains_key(id)
                    || self.output_inclusions.get(id) != Some(&stored.block.point)
                {
                    return Err(DepositWalletError::CorruptScanState);
                }
            }
            for id in &stored.root_outputs {
                if !referenced_root_outputs.insert(*id)
                    || referenced_outputs.contains(id)
                    || !self.root_outputs.contains_key(id)
                    || self.root_output_inclusions.get(id) != Some(&stored.block.point)
                {
                    return Err(DepositWalletError::CorruptScanState);
                }
            }
            prior = stored.block.point;
        }
        let mut pinned_outputs = BTreeSet::new();
        let mut pinned_root_outputs = BTreeSet::new();
        if self.pinned_historical_blocks.len() > MAX_PINNED_HISTORICAL_BLOCKS {
            return Err(DepositWalletError::CorruptScanState);
        }
        for (height, pinned) in &self.pinned_historical_blocks {
            if *height != pinned.block.point.height
                || *height < self.birth_anchor.height
                || *height > self.tip().height
                || (*height != 0 && pinned.block.parent_hash == [0; 32])
                || (pinned.outputs.is_empty() && pinned.root_outputs.is_empty() && !pinned.held)
                || pinned.outputs.windows(2).any(|window| window[0] >= window[1])
                || pinned.root_outputs.windows(2).any(|window| window[0] >= window[1])
            {
                return Err(DepositWalletError::CorruptScanState);
            }
            ChainPoint::new(pinned.block.point.height, pinned.block.point.hash)?;
            if *height > self.anchor.height {
                let stored = self.blocks.get(height).ok_or(DepositWalletError::CorruptScanState)?;
                if stored.block != pinned.block
                    || stored.timestamp != pinned.timestamp
                    || stored.outputs != pinned.outputs
                    || stored.root_outputs != pinned.root_outputs
                {
                    return Err(DepositWalletError::CorruptScanState);
                }
            } else if *height == self.anchor.height && pinned.block.point != self.anchor {
                return Err(DepositWalletError::CorruptScanState);
            }
            for id in &pinned.outputs {
                if !pinned_outputs.insert(*id)
                    || pinned_root_outputs.contains(id)
                    || !self.outputs.contains_key(id)
                    || self.output_inclusions.get(id) != Some(&pinned.block.point)
                {
                    return Err(DepositWalletError::CorruptScanState);
                }
            }
            for id in &pinned.root_outputs {
                if !pinned_root_outputs.insert(*id)
                    || pinned_outputs.contains(id)
                    || !self.root_outputs.contains_key(id)
                    || self.root_output_inclusions.get(id) != Some(&pinned.block.point)
                {
                    return Err(DepositWalletError::CorruptScanState);
                }
            }
        }
        if self.output_inclusions.len() != self.outputs.len()
            || self.root_output_inclusions.len() != self.root_outputs.len()
            || self.pinned_root_transactions.len() > MAX_PINNED_ROOT_TRANSACTIONS
            || self.sweeps.len() > MAX_ACTIVE_SWEEP_RECORDS
            || self.retained_output_count() > MAX_RETAINED_WALLET_OUTPUTS
        {
            return Err(DepositWalletError::CorruptScanState);
        }

        let mut output_keys = BTreeMap::<[u8; 32], WalletOutputId>::new();
        for (id, output) in &self.outputs {
            if *id != output.id {
                return Err(DepositWalletError::CorruptScanState);
            }
            let inclusion =
                self.output_inclusions.get(id).ok_or(DepositWalletError::CorruptScanState)?;
            ChainPoint::new(inclusion.height, inclusion.hash)?;
            if (inclusion.height > self.anchor.height && !referenced_outputs.contains(id))
                || (inclusion.height <= self.anchor.height && !pinned_outputs.contains(id))
            {
                return Err(DepositWalletError::CorruptScanState);
            }
            output.validate(self.root_spend_key)?;
            if let Some(existing) = output_keys.insert(output.output_key, *id) {
                return Err(DepositWalletError::DuplicateOutputKey { existing, duplicate: *id });
            }
        }
        for (id, output) in &self.root_outputs {
            if *id != output.id {
                return Err(DepositWalletError::CorruptScanState);
            }
            let inclusion =
                self.root_output_inclusions.get(id).ok_or(DepositWalletError::CorruptScanState)?;
            ChainPoint::new(inclusion.height, inclusion.hash)?;
            if inclusion.height > self.anchor.height {
                if !referenced_root_outputs.contains(id) {
                    return Err(DepositWalletError::CorruptScanState);
                }
            } else if (!self.pinned_root_transactions.contains(&id.transaction)
                && !pinned_root_outputs.contains(id))
                || referenced_root_outputs.contains(id)
            {
                return Err(DepositWalletError::CorruptScanState);
            }
            output.validate(self.root_spend_key)?;
            if let Some(existing) = output_keys.insert(output.output_key, *id) {
                return Err(DepositWalletError::DuplicateOutputKey { existing, duplicate: *id });
            }
        }
        let mut root_transaction_points = BTreeMap::<[u8; 32], ChainPoint>::new();
        for (id, inclusion) in &self.root_output_inclusions {
            if let Some(existing) = root_transaction_points.insert(id.transaction, *inclusion)
                && existing != *inclusion
            {
                return Err(DepositWalletError::CorruptScanState);
            }
        }
        if self.pinned_root_transactions.iter().any(|transaction| {
            *transaction == [0_u8; 32] || !root_transaction_points.contains_key(transaction)
        }) {
            return Err(DepositWalletError::CorruptScanState);
        }
        let mut authenticated_points = BTreeMap::<u64, ChainPoint>::new();
        for point in [self.birth_anchor, self.anchor]
            .into_iter()
            .chain(self.blocks.values().map(|stored| stored.block.point))
            .chain(self.pinned_historical_blocks.values().map(|stored| stored.block.point))
            .chain(self.output_inclusions.values().copied())
            .chain(self.root_output_inclusions.values().copied())
        {
            if let Some(existing) = authenticated_points.insert(point.height, point)
                && existing != point
            {
                return Err(DepositWalletError::CorruptScanState);
            }
        }
        let mut claims = BTreeMap::<WalletOutputId, SweepId>::new();
        let mut signing_sessions = BTreeSet::<[u8; 32]>::new();
        for (id, sweep) in &self.sweeps {
            if *id != sweep.id
                || sweep.id.0 == [0_u8; 32]
                || sweep.inputs.is_empty()
                || sweep.inputs.windows(2).any(|window| window[0] >= window[1])
            {
                return Err(DepositWalletError::CorruptScanState);
            }
            sweep.signing_intent.validate(sweep.id, self.root_spend_key)?;
            if sweep.signing_attempt_high_water == 0
                || derive_sweep_signing_session(
                    self.wallet,
                    sweep.id,
                    sweep.signing_attempt_high_water,
                )
                .map(|session| session.0)
                    != Some(sweep.signing_intent.session())
            {
                return Err(DepositWalletError::CorruptScanState);
            }
            if let Some(binding) = &sweep.family_key_images {
                validate_family_key_image_binding(sweep, binding)?;
                if sweep.status == SweepStatus::Reserved {
                    return Err(DepositWalletError::CorruptScanState);
                }
            } else if matches!(
                sweep.status,
                SweepStatus::Signed { .. }
                    | SweepStatus::Broadcast { .. }
                    | SweepStatus::Confirmed { .. }
            ) || sweep.signed_transaction.is_some()
            {
                return Err(DepositWalletError::CorruptScanState);
            }
            if !signing_sessions.insert(sweep.signing_intent.session())
                || sweep.retired_signing_attempts.len() > MAX_RETAINED_SWEEP_SIGNING_ATTEMPTS
                || (sweep.status == SweepStatus::Reserved
                    && !sweep.retired_signing_attempts.is_empty())
            {
                return Err(DepositWalletError::CorruptScanState);
            }
            let mut retired_digests = BTreeSet::new();
            let mut previous_attempt = 0_u64;
            for retired in &sweep.retired_signing_attempts {
                if retired.attempt <= previous_attempt
                    || retired.attempt >= sweep.signing_attempt_high_water
                    || derive_sweep_signing_session(self.wallet, sweep.id, retired.attempt)
                        .map(|session| session.0)
                        != Some(retired.session)
                    || retired.session == [0_u8; 32]
                    || retired.intent_digest == [0_u8; 32]
                    || !signing_sessions.insert(retired.session)
                    || !retired_digests.insert(retired.intent_digest)
                    || retired.intent_digest == sweep.signing_intent.intent_digest()
                {
                    return Err(DepositWalletError::CorruptScanState);
                }
                previous_attempt = retired.attempt;
            }
            let signed_id = if let Some(signed) = &sweep.signed_transaction {
                signed.validate()?;
                Some(signed.transaction_id())
            } else {
                None
            };
            if sweep.family_candidates.len() > MAX_SWEEP_FAMILY_CANDIDATES
                || sweep
                    .family_candidates
                    .windows(2)
                    .any(|window| window[0].transaction_id() >= window[1].transaction_id())
                || sweep
                    .family_candidates
                    .iter()
                    .try_fold(0_usize, |sum, candidate| sum.checked_add(candidate.as_bytes().len()))
                    .is_none_or(|bytes| bytes > MAX_SWEEP_FAMILY_CANDIDATE_BYTES)
                || signed_id.is_some_and(|transaction| {
                    sweep
                        .family_candidates
                        .binary_search_by_key(&transaction, SignedSweepTransaction::transaction_id)
                        .is_err()
                })
            {
                return Err(DepositWalletError::CorruptScanState);
            }
            for candidate in &sweep.family_candidates {
                candidate.validate()?;
                let binding =
                    sweep.family_key_images.as_ref().ok_or(DepositWalletError::CorruptScanState)?;
                sweep.signing_intent.validate_completed_transaction(
                    sweep.inputs.len(),
                    binding,
                    candidate,
                )?;
            }
            let signed_state_is_valid = match sweep.status {
                SweepStatus::Reserved => signed_id.is_none(),
                SweepStatus::SigningReleased => signed_id.is_none(),
                SweepStatus::Signed { transaction } | SweepStatus::Broadcast { transaction } => {
                    signed_id.is_some()
                        && sweep
                            .family_candidates
                            .binary_search_by_key(
                                &transaction,
                                SignedSweepTransaction::transaction_id,
                            )
                            .is_ok()
                }
                SweepStatus::Confirmed { transaction, .. } => signed_id == Some(transaction),
                SweepStatus::QuarantinedByReorg { transaction, .. } => signed_id == transaction,
                SweepStatus::AbandonedByReorg { .. } => signed_id.is_none(),
            };
            if !signed_state_is_valid {
                return Err(DepositWalletError::CorruptScanState);
            }
            if let Some(signed) = &sweep.signed_transaction {
                let binding =
                    sweep.family_key_images.as_ref().ok_or(DepositWalletError::CorruptScanState)?;
                sweep.signing_intent.validate_completed_transaction(
                    sweep.inputs.len(),
                    binding,
                    signed,
                )?;
            }
            if let SweepStatus::Confirmed { transaction, block } = sweep.status {
                let newest_input_height = sweep
                    .inputs
                    .iter()
                    .filter_map(|input| self.output_height(*input))
                    .max()
                    .ok_or(DepositWalletError::CorruptScanState)?;
                if (block.height > self.anchor.height && !self.contains_chain_point(block))
                    || block.height <= newest_input_height
                    || !self.root_transaction_observed_at(transaction, block)
                {
                    return Err(DepositWalletError::CorruptScanState);
                }
            }
            if let SweepStatus::QuarantinedByReorg { ancestor, .. }
            | SweepStatus::AbandonedByReorg { ancestor } = sweep.status
                && ((ancestor.height > self.anchor.height && !self.contains_chain_point(ancestor))
                    || ChainPoint::new(ancestor.height, ancestor.hash).is_err())
            {
                return Err(DepositWalletError::CorruptScanState);
            }
            if is_active_sweep(sweep.status) {
                for input in &sweep.inputs {
                    if !self.outputs.contains_key(input)
                        && !matches!(
                            sweep.status,
                            SweepStatus::QuarantinedByReorg { .. }
                                | SweepStatus::AbandonedByReorg { .. }
                        )
                    {
                        return Err(DepositWalletError::CorruptScanState);
                    }
                    if self.outputs.contains_key(input) && claims.insert(*input, *id).is_some() {
                        return Err(DepositWalletError::CorruptScanState);
                    }
                }
            }
        }
        Ok(())
    }

    /// Encode validated scan and sweep state for durable storage.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state, serialization failure, or an oversized result.
    pub fn encode(&self) -> Result<Vec<u8>, DepositWalletError> {
        self.validate()?;
        let encoded = postcard::to_allocvec(self).map_err(|_| DepositWalletError::Serialization)?;
        if encoded.len() > MAX_DURABLE_STATE_BYTES {
            return Err(DepositWalletError::StateTooLarge);
        }
        Ok(encoded)
    }

    /// Restore and validate scan and sweep state from durable bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, unsupported, or internally inconsistent state.
    pub fn decode(bytes: &[u8]) -> Result<Self, DepositWalletError> {
        if bytes.len() > MAX_DURABLE_STATE_BYTES {
            return Err(DepositWalletError::StateTooLarge);
        }
        let state: Self =
            postcard::from_bytes(bytes).map_err(|_| DepositWalletError::Serialization)?;
        state.validate()?;
        Ok(state)
    }

    fn contains_chain_point(&self, point: ChainPoint) -> bool {
        point == self.anchor
            || self.blocks.get(&point.height).is_some_and(|stored| stored.block.point == point)
    }

    fn authenticated_chain_point(&self, height: u64) -> Option<ChainPoint> {
        let mut authenticated = None;
        let mut observe = |point: ChainPoint| {
            if point.height != height {
                return true;
            }
            if authenticated.is_some_and(|known| known != point) {
                return false;
            }
            authenticated = Some(point);
            true
        };
        if !observe(self.birth_anchor) || !observe(self.anchor) {
            return None;
        }
        if let Some(stored) = self.blocks.get(&height)
            && !observe(stored.block.point)
        {
            return None;
        }
        if let Some(stored) = self.pinned_historical_blocks.get(&height)
            && !observe(stored.block.point)
        {
            return None;
        }
        for point in self
            .output_inclusions
            .values()
            .chain(self.root_output_inclusions.values())
            .copied()
            .filter(|point| point.height == height)
        {
            if !observe(point) {
                return None;
            }
        }
        authenticated
    }

    fn validate_authenticated_historical_evidence(
        &self,
        evidence: &AuthenticatedHistoricalBlockEvidence,
    ) -> Result<(), DepositWalletError> {
        if evidence.wallet != self.wallet
            || evidence.wallet.0 == [0; 32]
            || evidence.portable_index_head == [0; 32]
            || evidence
                .outputs
                .len()
                .checked_add(evidence.root_outputs.len())
                .is_none_or(|count| count > MAX_HISTORICAL_OUTPUTS_PER_BLOCK)
            || ((!evidence.outputs.is_empty() || !evidence.root_outputs.is_empty())
                && evidence.portable_through_sequence == 0)
            || evidence.block.point.height < self.birth_anchor.height
            || evidence.block.point.height > evidence.verification_horizon.height
            || evidence.verification_horizon.height > self.tip().height
            || (evidence.block.point.height != 0 && evidence.block.parent_hash == [0; 32])
        {
            return Err(DepositWalletError::InvalidHistoricalBlockEvidence);
        }
        ChainPoint::new(evidence.block.point.height, evidence.block.point.hash)?;
        ChainPoint::new(evidence.verification_horizon.height, evidence.verification_horizon.hash)?;
        if self.authenticated_chain_point(evidence.verification_horizon.height)
            != Some(evidence.verification_horizon)
        {
            return Err(DepositWalletError::UnknownChainPoint(evidence.verification_horizon));
        }
        if self
            .authenticated_chain_point(evidence.block.point.height)
            .is_some_and(|known| known != evidence.block.point)
        {
            return Err(DepositWalletError::ConflictingHistoricalBlock(
                evidence.block.point.height,
            ));
        }
        if evidence.block.point.height > self.anchor.height {
            let stored = self
                .blocks
                .get(&evidence.block.point.height)
                .ok_or(DepositWalletError::UnknownChainPoint(evidence.block.point))?;
            if stored.block != evidence.block || stored.timestamp != evidence.timestamp {
                return Err(DepositWalletError::ConflictingHistoricalBlock(
                    evidence.block.point.height,
                ));
            }
        } else if evidence.block.point.height == self.anchor.height
            && evidence.block.point != self.anchor
        {
            return Err(DepositWalletError::ConflictingHistoricalBlock(
                evidence.block.point.height,
            ));
        }
        if let Some(existing) = self.pinned_historical_blocks.get(&evidence.block.point.height)
            && (existing.block != evidence.block || existing.timestamp != evidence.timestamp)
        {
            return Err(DepositWalletError::ConflictingHistoricalBlock(
                evidence.block.point.height,
            ));
        }
        Ok(())
    }

    fn validate_verified_portable_terminal_binding(
        &self,
        portable: &VerifiedPortableSweepTerminal,
    ) -> Result<(), DepositWalletError> {
        if portable.wallet != self.wallet
            || portable.sweep.0 == [0; 32]
            || portable.inputs.is_empty()
            || portable.inputs.windows(2).any(|window| window[0] >= window[1])
            || portable.inputs.iter().any(|input| input.transaction == [0; 32])
            || portable.transaction == [0; 32]
            || portable.completion_certificate == [0; 32]
            || portable.portable_terminal == [0; 32]
        {
            return Err(DepositWalletError::CertifiedSweepConflict);
        }
        if let Some(local) = self.sweeps.get(&portable.sweep) {
            if local.inputs.as_slice() != portable.inputs.as_slice()
                || local
                    .signed_transaction
                    .as_ref()
                    .is_some_and(|signed| signed.transaction_id() != portable.transaction)
            {
                return Err(DepositWalletError::CertifiedSweepConflict);
            }
        }
        for input in &portable.inputs {
            if self.root_outputs.contains_key(input)
                || self.active_sweep_claiming(*input).is_some_and(|claim| claim != portable.sweep)
            {
                return Err(DepositWalletError::CertifiedSweepConflict);
            }
        }
        Ok(())
    }

    fn output_height(&self, id: WalletOutputId) -> Option<u64> {
        self.output_chain_point(id).map(|point| point.height)
    }

    fn known_output_with_key(&self, key: [u8; 32]) -> Option<WalletOutputId> {
        self.outputs
            .values()
            .find(|known| known.output_key == key)
            .map(PersistedWalletOutput::id)
            .or_else(|| {
                self.root_outputs
                    .values()
                    .find(|known| known.output_key == key)
                    .map(PersistedRootOutput::id)
            })
    }

    fn root_transaction_observed_at(&self, transaction: [u8; 32], point: ChainPoint) -> bool {
        self.root_transaction_chain_point(transaction) == Some(point)
    }

    fn validate_wallet_domain(&self) -> Result<(), DepositWalletError> {
        decode_root_spend_key(self.root_spend_key)?;
        decode_public_view_key(self.public_view_key)?;
        if derive_wallet_id(self.network, self.root_spend_key, self.public_view_key) != self.wallet
        {
            return Err(DepositWalletError::WrongWalletDomain);
        }
        Ok(())
    }

    fn is_claimed(&self, id: WalletOutputId) -> bool {
        self.sweeps
            .values()
            .any(|sweep| is_active_sweep(sweep.status) && sweep.inputs.binary_search(&id).is_ok())
    }

    fn signing_session_known(&self, session: [u8; 32]) -> bool {
        self.sweeps.values().any(|sweep| {
            sweep.signing_intent.session() == session
                || sweep.retired_signing_attempts.iter().any(|retired| retired.session == session)
        })
    }
}

fn decode_signable_transaction(bytes: &[u8]) -> Result<SignableTransaction, DepositWalletError> {
    if bytes.len() > MAX_SIGNABLE_SWEEP_TRANSACTION_BYTES {
        return Err(DepositWalletError::SignableSweepTransactionTooLarge);
    }
    if bytes.is_empty() {
        return Err(DepositWalletError::InvalidSignableSweepTransaction);
    }
    let mut cursor = Cursor::new(bytes);
    let transaction = SignableTransaction::read(&mut cursor)
        .map_err(|_| DepositWalletError::InvalidSignableSweepTransaction)?;
    if usize::try_from(cursor.position()).ok() != Some(bytes.len()) {
        return Err(DepositWalletError::TrailingSignableSweepTransactionBytes);
    }
    if transaction.serialize() != bytes {
        return Err(DepositWalletError::NonCanonicalSignableSweepTransaction);
    }
    Ok(transaction)
}

fn sweep_transaction_commitment(sweep: SweepId, signable_transaction: &[u8]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/deposit-frostlass-transaction/v1");
    hasher.update(&sweep.0);
    hasher.update(signable_transaction);
    *hasher.finalize().as_bytes()
}

fn sweep_signing_context(intent: &SweepSigningIntent) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/frostlass-context/v2/session-bound");
    hasher.update(&intent.session);
    hasher.update(&intent.committee_digest);
    hasher.update(&intent.group_key);
    hasher.update(
        &u32::try_from(intent.signers.len())
            .expect("a signing set cannot contain more than u16::MAX parties")
            .to_le_bytes(),
    );
    for party in &intent.signers {
        hasher.update(&party.to_le_bytes());
    }
    hasher.update(&intent.signable_transaction);
    *hasher.finalize().as_bytes()
}

fn sweep_intent_digest(intent: &SweepSigningIntent) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/deposit-sweep-signing-intent/v1");
    hasher.update(&intent.epoch.to_le_bytes());
    hasher.update(&intent.plan_commitment);
    hasher.update(&intent.session);
    hasher.update(&intent.committee_digest);
    hasher.update(&intent.group_key);
    hasher.update(&u64::try_from(intent.signers.len()).unwrap_or(u64::MAX).to_le_bytes());
    for signer in &intent.signers {
        hasher.update(&signer.to_le_bytes());
    }
    hasher.update(
        &u64::try_from(intent.signable_transaction.len()).unwrap_or(u64::MAX).to_le_bytes(),
    );
    hasher.update(&intent.signable_transaction);
    hasher.update(
        &u64::try_from(intent.prepared_sweep_intent.len()).unwrap_or(u64::MAX).to_le_bytes(),
    );
    hasher.update(&intent.prepared_sweep_intent);
    hasher.update(&intent.transaction_commitment);
    hasher.update(&intent.signing_context);
    hasher.update(&intent.fee_atomic_units.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn sweep_family_digest(intent: &SweepSigningIntent) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/deposit-sweep-family/v1");
    hasher.update(&intent.epoch.to_le_bytes());
    hasher.update(&intent.plan_commitment);
    hasher.update(&intent.group_key);
    hasher.update(
        &u64::try_from(intent.signable_transaction.len()).unwrap_or(u64::MAX).to_le_bytes(),
    );
    hasher.update(&intent.signable_transaction);
    hasher.update(
        &u64::try_from(intent.prepared_sweep_intent.len()).unwrap_or(u64::MAX).to_le_bytes(),
    );
    hasher.update(&intent.prepared_sweep_intent);
    hasher.update(&intent.transaction_commitment);
    hasher.update(&intent.fee_atomic_units.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn validate_family_key_image_binding(
    record: &SweepRecord,
    binding: &FamilyKeyImageBinding,
) -> Result<(), DepositWalletError> {
    if binding.sweep != record.id
        || binding.inputs != record.inputs
        || binding.inputs.is_empty()
        || binding.inputs.len() != binding.key_images.len()
        || binding.family_digest == [0_u8; 32]
        || binding.family_digest != record.signing_intent.family_digest()
        || binding.unsigned_transaction_digest == [0_u8; 32]
    {
        return Err(DepositWalletError::InvalidSweepFamilyKeyImages);
    }
    let mut distinct = BTreeSet::new();
    for encoded in &binding.key_images {
        let point = CompressedPoint::from(*encoded)
            .decompress()
            .ok_or(DepositWalletError::InvalidSweepFamilyKeyImages)?;
        let point: curve25519_dalek::EdwardsPoint = point.into();
        if point.is_identity() || !point.is_torsion_free() || !distinct.insert(*encoded) {
            return Err(DepositWalletError::InvalidSweepFamilyKeyImages);
        }
    }
    Ok(())
}

fn insert_family_candidate(
    record: &mut SweepRecord,
    signed: SignedSweepTransaction,
) -> Result<(), DepositWalletError> {
    let transaction = signed.transaction_id();
    match record
        .family_candidates
        .binary_search_by_key(&transaction, SignedSweepTransaction::transaction_id)
    {
        Ok(index) => {
            if record.family_candidates[index] == signed {
                return Ok(());
            }
            return Err(DepositWalletError::SweepTransactionHashMismatch);
        }
        Err(index) => {
            let aggregate = record
                .family_candidates
                .iter()
                .try_fold(signed.as_bytes().len(), |sum, candidate| {
                    sum.checked_add(candidate.as_bytes().len())
                })
                .ok_or(DepositWalletError::SweepFamilyCandidateLimit)?;
            if record.family_candidates.len() >= MAX_SWEEP_FAMILY_CANDIDATES
                || aggregate > MAX_SWEEP_FAMILY_CANDIDATE_BYTES
            {
                return Err(DepositWalletError::SweepFamilyCandidateLimit);
            }
            record.family_candidates.insert(index, signed);
        }
    }
    Ok(())
}

fn address_network(network: NetworkKind) -> Network {
    match network {
        // Monero's regtest daemon deliberately accepts/produces mainnet-format addresses.
        NetworkKind::Regtest | NetworkKind::Mainnet => Network::Mainnet,
        NetworkKind::Testnet => Network::Testnet,
    }
}

fn derive_wallet_id(
    network: NetworkKind,
    root_spend_key: [u8; 32],
    public_view_key: [u8; 32],
) -> DepositWalletId {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/deposit-wallet-domain/v1");
    hasher.update(&[match network {
        NetworkKind::Regtest => 0,
        NetworkKind::Testnet => 1,
        NetworkKind::Mainnet => 2,
    }]);
    hasher.update(&root_spend_key);
    hasher.update(&public_view_key);
    DepositWalletId(*hasher.finalize().as_bytes())
}

fn decode_root_spend_key(
    bytes: [u8; 32],
) -> Result<curve25519_dalek::EdwardsPoint, DepositWalletError> {
    let point =
        CompressedPoint::from(bytes).decompress().ok_or(DepositWalletError::InvalidRootSpendKey)?;
    let point = point.into();
    if !point.is_torsion_free() {
        return Err(DepositWalletError::InvalidRootSpendKey);
    }
    if point.is_identity() {
        return Err(DepositWalletError::IdentityRootSpendKey);
    }
    Ok(point)
}

fn decode_public_view_key(bytes: [u8; 32]) -> Result<(), DepositWalletError> {
    let point = CompressedPoint::from(bytes)
        .decompress()
        .ok_or(DepositWalletError::InvalidPublicViewKey)?;
    let point = point.into();
    if !point.is_torsion_free() || point.is_identity() {
        return Err(DepositWalletError::InvalidPublicViewKey);
    }
    Ok(())
}

fn validate_next_block(prior: ChainPoint, block: ScannedBlock) -> Result<(), DepositWalletError> {
    ChainPoint::new(block.point.height, block.point.hash)?;
    if block.point.height
        != prior.height.checked_add(1).ok_or(DepositWalletError::HeightOverflow)?
        || block.parent_hash != prior.hash
    {
        return Err(DepositWalletError::DiscontinuousBlock {
            expected_height: prior.height.saturating_add(1),
            expected_parent: prior.hash,
        });
    }
    Ok(())
}

fn is_active_sweep(status: SweepStatus) -> bool {
    matches!(
        status,
        SweepStatus::Reserved
            | SweepStatus::SigningReleased
            | SweepStatus::Signed { .. }
            | SweepStatus::Broadcast { .. }
            | SweepStatus::Confirmed { .. }
            | SweepStatus::QuarantinedByReorg { .. }
            | SweepStatus::AbandonedByReorg { .. }
    )
}

#[cfg(test)]
mod live_sweep_signing_attempt_tests {
    use super::*;

    const ATTEMPT: u64 = 7;
    const INTENT_DIGEST: [u8; 32] = [0x71; 32];

    fn fixture() -> (ScanState, SweepId, SessionId) {
        let deriver = DepositAddressDeriver::new(
            NetworkKind::Mainnet,
            (ED25519_BASEPOINT_POINT * DalekScalar::from(42_u64)).compress().to_bytes(),
            &Zeroizing::new(DalekScalar::from(17_u64).to_bytes()),
        )
        .unwrap();
        let mut state = ScanState::new(&deriver, ChainPoint::new(10, [0x10; 32]).unwrap()).unwrap();
        let sweep = SweepId([0x51; 32]);
        let session = derive_sweep_signing_session(state.wallet_id(), sweep, ATTEMPT).unwrap();
        state.sweeps.insert(
            sweep,
            SweepRecord {
                id: sweep,
                signing_intent: SweepSigningIntent {
                    epoch: 11,
                    plan_commitment: sweep.0,
                    session: session.0,
                    committee_digest: [0x61; 32],
                    group_key: state.root_spend_key(),
                    signers: vec![1, 3, 7],
                    signable_transaction: Vec::new(),
                    prepared_sweep_intent: Vec::new(),
                    transaction_commitment: [0x62; 32],
                    signing_context: [0x63; 32],
                    fee_atomic_units: 1_000,
                    intent_digest: INTENT_DIGEST,
                },
                signing_attempt_high_water: ATTEMPT,
                retired_signing_attempts: Vec::new(),
                family_key_images: None,
                inputs: Vec::new(),
                signed_transaction: None,
                family_candidates: Vec::new(),
                status: SweepStatus::SigningReleased,
            },
        );
        (state, sweep, session)
    }

    #[test]
    fn exposure_requires_the_exact_current_worker_attempt() {
        let (mut state, sweep, session) = fixture();
        assert!(
            state
                .validate_live_sweep_signing_attempt(sweep, ATTEMPT, session, INTENT_DIGEST)
                .is_ok()
        );
        assert!(matches!(
            state.validate_live_sweep_signing_attempt(
                sweep,
                ATTEMPT + 1,
                derive_sweep_signing_session(state.wallet_id(), sweep, ATTEMPT + 1).unwrap(),
                INTENT_DIGEST,
            ),
            Err(DepositWalletError::UnknownSweepSigningAttempt)
        ));
        assert!(matches!(
            state.validate_live_sweep_signing_attempt(
                sweep,
                ATTEMPT,
                SessionId([0x72; 32]),
                INTENT_DIGEST,
            ),
            Err(DepositWalletError::UnknownSweepSigningAttempt)
        ));
        assert!(matches!(
            state.validate_live_sweep_signing_attempt(sweep, ATTEMPT, session, [0x73; 32]),
            Err(DepositWalletError::UnknownSweepSigningAttempt)
        ));

        let next_attempt = ATTEMPT + 1;
        let next_session =
            derive_sweep_signing_session(state.wallet_id(), sweep, next_attempt).unwrap();
        let next_digest = [0x74; 32];
        let record = state.sweeps.get_mut(&sweep).unwrap();
        record.signing_attempt_high_water = next_attempt;
        record.signing_intent.session = next_session.0;
        record.signing_intent.intent_digest = next_digest;
        assert!(matches!(
            state.validate_live_sweep_signing_attempt(sweep, ATTEMPT, session, INTENT_DIGEST),
            Err(DepositWalletError::UnknownSweepSigningAttempt)
        ));
        assert!(
            state
                .validate_live_sweep_signing_attempt(sweep, next_attempt, next_session, next_digest)
                .is_ok()
        );
    }

    #[test]
    fn terminal_and_reorg_states_cannot_authorize_exposure() {
        let (mut state, sweep, session) = fixture();
        let point = ChainPoint::new(12, [0x12; 32]).unwrap();
        for status in [
            SweepStatus::Reserved,
            SweepStatus::Signed { transaction: [0x81; 32] },
            SweepStatus::Broadcast { transaction: [0x81; 32] },
            SweepStatus::Confirmed { transaction: [0x81; 32], block: point },
            SweepStatus::QuarantinedByReorg { ancestor: point, transaction: None },
            SweepStatus::AbandonedByReorg { ancestor: point },
        ] {
            state.sweeps.get_mut(&sweep).unwrap().status = status;
            assert!(
                matches!(
                    state.validate_live_sweep_signing_attempt(
                        sweep,
                        ATTEMPT,
                        session,
                        INTENT_DIGEST
                    ),
                    Err(DepositWalletError::InvalidSweepTransition)
                ),
                "status {status:?} authorized signing exposure"
            );
        }
    }
}

/// Error returned by Monero deposit wallet material and persistence primitives.
#[derive(Debug, Error)]
pub enum DepositWalletError {
    /// `(0, 0)` names the primary address, not a deposit subaddress.
    #[error("(0, 0) is the primary address and cannot be allocated as a deposit subaddress")]
    PrimaryAddressIndex,
    /// Root threshold spend point was malformed or torsioned.
    #[error("invalid root threshold public spend key")]
    InvalidRootSpendKey,
    /// Root threshold spend point was the identity.
    #[error("root threshold public spend key is the identity")]
    IdentityRootSpendKey,
    /// Public view point was malformed, torsioned, or the identity.
    #[error("invalid public view key in wallet domain")]
    InvalidPublicViewKey,
    /// Stable wallet-domain identifier was absent or malformed.
    #[error("invalid Monero deposit wallet domain")]
    InvalidWalletDomain,
    /// Durable state or an injected address belonged to another wallet domain.
    #[error("Monero deposit wallet domain mismatch")]
    WrongWalletDomain,
    /// Common private view bytes were not a canonical scalar.
    #[error("invalid canonical private view scalar")]
    InvalidPrivateViewScalar,
    /// A zero private view scalar is not a usable wallet view key.
    #[error("private view scalar must be non-zero")]
    ZeroPrivateViewScalar,
    /// monero-wallet rejected the view pair.
    #[error("invalid Monero view pair: {0}")]
    ViewPair(#[from] monero_wallet::ViewPairError),
    /// Monero address parsing failed.
    #[error("invalid Monero address: {0}")]
    Address(#[from] AddressError),
    /// A persisted address was not a subaddress.
    #[error("deposit address is not a Monero subaddress")]
    NotSubaddress,
    /// A persisted address had a non-canonical string representation.
    #[error("non-canonical Monero address string")]
    NonCanonicalAddress,
    /// Scan-state schema version is unsupported.
    #[error("unsupported scan-state version {0}")]
    UnsupportedScanStateVersion(u16),
    /// Durable encoding or decoding failed.
    #[error("durable serialization failed")]
    Serialization,
    /// Durable state exceeded its hard size bound.
    #[error("durable state exceeds its hard size bound")]
    StateTooLarge,
    /// A block hash was all zeroes.
    #[error("block hash must not be all zeroes")]
    ZeroBlockHash,
    /// Block height arithmetic overflowed.
    #[error("block height overflow")]
    HeightOverflow,
    /// A moving-checkpoint reorg window was zero.
    #[error("reorg retention window must be non-zero")]
    InvalidReorgWindow,
    /// Active families exhausted the bounded root-inclusion witness set.
    #[error("too many unresolved root transactions are pinned")]
    PinnedRootTransactionCapacity,
    /// Authenticated historical block evidence was structurally invalid or for another wallet.
    #[error("invalid authenticated historical block evidence")]
    InvalidHistoricalBlockEvidence,
    /// Historical evidence disagreed on the exact block, parent, or canonical timestamp.
    #[error("conflicting authenticated historical block evidence at height {0}")]
    ConflictingHistoricalBlock(u64),
    /// The bounded set of pinned historical block bodies was exhausted.
    #[error("too many authenticated historical blocks are pinned")]
    HistoricalBlockCapacity,
    /// One historical block exceeded the atomic scanner-output admission bound.
    #[error("authenticated historical block contains too many wallet outputs")]
    HistoricalOutputBatchCapacity,
    /// The scanner reached its absolute retained wallet-output bound.
    #[error("too many wallet outputs are retained")]
    RetainedOutputCapacity,
    /// A block did not extend the retained tip.
    #[error(
        "block does not extend tip (expected height {expected_height} and parent {})",
        hex::encode(expected_parent)
    )]
    DiscontinuousBlock {
        /// Required next height.
        expected_height: u64,
        /// Required parent hash.
        expected_parent: [u8; 32],
    },
    /// Requested rollback/confirmation point was not retained.
    #[error("unknown retained chain point at height {}", .0.height)]
    UnknownChainPoint(ChainPoint),
    /// Scanner result was for the root address instead of a deposit subaddress.
    #[error("scanner output did not identify a deposit subaddress")]
    MissingSubaddress,
    /// A root-output wrapper was asked to persist a deposit subaddress result.
    #[error("scanner output unexpectedly identified a deposit subaddress")]
    UnexpectedSubaddress,
    /// Private monero-wallet output encoding exceeded its bound.
    #[error("serialized wallet output exceeds its hard size bound")]
    WalletOutputTooLarge,
    /// Private monero-wallet output encoding was malformed.
    #[error("invalid serialized monero-wallet output")]
    InvalidWalletOutput,
    /// Private monero-wallet output encoding had trailing bytes.
    #[error("serialized monero-wallet output has trailing bytes")]
    TrailingWalletOutputBytes,
    /// Indexed fields differed from the private wallet encoding.
    #[error("persisted wallet output metadata does not match its private encoding")]
    WalletOutputMetadataMismatch,
    /// Scanner offset was not a canonical scalar.
    #[error("scanner returned a non-canonical key offset")]
    InvalidScannerOffset,
    /// Scanner output key did not equal the root key plus its exact offset.
    #[error("scanner output key is not bound to the root threshold spend key")]
    WrongOutputKey,
    /// Decoy selection altered the scanner output key or scalar offset.
    #[error("decoy input did not preserve the scanner key offset")]
    ScannerOffsetChanged,
    /// Decoy selection placed the real output at another absolute chain position.
    #[error("decoy input did not preserve the scanner global output index")]
    ScannerGlobalIndexChanged,
    /// Absolute output identity was already retained.
    #[error("duplicate absolute wallet output ID {0:?}")]
    DuplicateOutputId(WalletOutputId),
    /// A one-time output key was observed more than once (the Monero burning bug).
    #[error("duplicate one-time output key for {duplicate:?}; first seen as {existing:?}")]
    DuplicateOutputKey {
        /// Previously accepted output.
        existing: WalletOutputId,
        /// Conflicting newly observed output.
        duplicate: WalletOutputId,
    },
    /// Restored state failed an internal invariant.
    #[error("corrupt durable scanner state")]
    CorruptScanState,
    /// Sweep record fields were invalid.
    #[error("invalid sweep record")]
    InvalidSweep,
    /// Active or terminal-awaiting-portability sweep capacity was exhausted.
    #[error("too many active sweep records")]
    SweepCapacity,
    /// Complete durable signing-intent fields were invalid or internally inconsistent.
    #[error("invalid durable sweep signing intent")]
    InvalidSweepSigningIntent,
    /// A signing session was current or permanently tombstoned already.
    #[error("FROSTLASS signing session was already used")]
    ReusedSweepSigningSession,
    /// A portable result named neither the current attempt nor one exact permanent tombstone.
    #[error("portable sweep result names an unknown FROSTLASS signing attempt")]
    UnknownSweepSigningAttempt,
    /// Crash recovery attempted to alter the exact authorized plan/transaction/private intent.
    #[error("replacement FROSTLASS intent does not match the released sweep")]
    SweepRecoveryIntentMismatch,
    /// Monotonic fresh-session attempt counter reached `u64::MAX`.
    #[error("FROSTLASS signing recovery attempt sequence exhausted")]
    SweepSigningAttemptLimit,
    /// Portable certified completion conflicted with a same-ID local intent or signed bytes.
    #[error("portable certified sweep conflicts with local sweep state")]
    CertifiedSweepConflict,
    /// A portable completion was not yet confirmed behind the moving reorganization checkpoint.
    #[error(
        "terminal confirmation at height {} is not behind reorganization fence at height {}",
        confirmation.height,
        fence.height
    )]
    TerminalCompactionBeforeReorgFence {
        /// Exact candidate transaction inclusion.
        confirmation: ChainPoint,
        /// Current moving scanner checkpoint.
        fence: ChainPoint,
    },
    /// Private signable-transaction bytes exceeded their hard bound.
    #[error("signable sweep transaction exceeds its hard size bound")]
    SignableSweepTransactionTooLarge,
    /// Private signable-transaction bytes were malformed.
    #[error("invalid signable Monero sweep transaction")]
    InvalidSignableSweepTransaction,
    /// Additional bytes followed the private signable transaction.
    #[error("signable Monero sweep transaction has trailing bytes")]
    TrailingSignableSweepTransactionBytes,
    /// The private signable transaction did not use its canonical pinned encoding.
    #[error("signable Monero sweep transaction is not canonically encoded")]
    NonCanonicalSignableSweepTransaction,
    /// Sweep inputs were empty or not distinct.
    #[error("sweep inputs must be a non-empty distinct set")]
    InvalidSweepInputs,
    /// Sweep attempt ID was already used.
    #[error("duplicate sweep attempt {0:?}")]
    DuplicateSweep(SweepId),
    /// Sweep input was not retained.
    #[error("unknown retained output {0:?}")]
    UnknownOutput(WalletOutputId),
    /// Sweep input was already reserved or spent by another active attempt.
    #[error("output is already claimed by an active sweep: {0:?}")]
    OutputAlreadyClaimed(WalletOutputId),
    /// Sweep attempt was unknown.
    #[error("unknown sweep attempt {0:?}")]
    UnknownSweep(SweepId),
    /// Sweep transaction ID was invalid.
    #[error("sweep transaction ID must not be all zeroes")]
    InvalidSweepTransaction,
    /// Exact signed transaction bytes exceeded Monero's non-miner transaction bound.
    #[error("signed sweep transaction exceeds its hard size bound")]
    SignedSweepTransactionTooLarge,
    /// Exact signed transaction bytes did not parse as one Monero transaction.
    #[error("invalid signed Monero sweep transaction")]
    InvalidSignedSweepTransaction,
    /// Additional bytes followed the signed Monero transaction.
    #[error("signed Monero sweep transaction has trailing bytes")]
    TrailingSignedSweepTransactionBytes,
    /// Parsed transaction bytes were not the canonical Monero encoding.
    #[error("signed Monero sweep transaction is not canonically encoded")]
    NonCanonicalSignedSweepTransaction,
    /// Signed transaction bytes hashed to a different transaction ID.
    #[error("signed Monero sweep transaction hash does not match the expected transaction ID")]
    SweepTransactionHashMismatch,
    /// Completed transaction did not satisfy the authorized FROSTLASS intent and policy.
    #[error("signed Monero sweep transaction does not match its durable signing intent")]
    SignedSweepIntentMismatch,
    /// No quorum-certified key-image vector was pinned before candidate validation.
    #[error("sweep family has no quorum-certified key-image binding")]
    MissingSweepFamilyKeyImages,
    /// A durable sweep-family key-image binding was malformed or belonged to another family.
    #[error("invalid sweep-family key-image binding")]
    InvalidSweepFamilyKeyImages,
    /// A retry attempted to change the already-pinned sweep-family key images.
    #[error("sweep-family key images conflict with the durable binding")]
    SweepFamilyKeyImageConflict,
    /// The bounded exact-byte archive for one sweep family was exhausted.
    #[error("sweep-family transaction candidate archive limit reached")]
    SweepFamilyCandidateLimit,
    /// Sweep confirmation preceded one or more of its inputs.
    #[error("sweep confirmation must follow every reserved input block")]
    InvalidSweepConfirmation,
    /// Requested sweep lifecycle transition was invalid.
    #[error("invalid sweep lifecycle transition")]
    InvalidSweepTransition,
}
