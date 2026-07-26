//! Autonomous, durable Monero deposit scanning and consolidation preparation.
//!
//! The worker scans only blocks which reached the configured confirmation depth. Every cursor
//! advance, detection, and deep-reorg rollback is first staged in [`DepositWorkerState`]. A caller
//! must persist the returned [`WorkerPersistEffect`] before reading the staged
//! [`WorkerEventBatch`]. Event delivery is at-least-once: after applying a batch idempotently, the
//! caller acknowledges and persists its removal before asking for another tick.
//!
//! [`PinnedMoneroDaemon`] is the production chain source. It uses monero-oxide's pinned daemon
//! interface, which validates block numbers, hashes, transaction bindings, and applies response
//! size limits. It additionally bounds expanded block size/count and rejects hardfork versions
//! newer than this crate has audited. A single daemon remains a trust and privacy boundary: an
//! active malicious RPC can lie about the best chain or bias decoy selection. Byzantine daemon
//! quorum/checkpoint verification belongs above this module.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    io::Cursor,
    mem::size_of,
    pin::Pin,
    time::Duration,
};

use curve25519_dalek::{EdwardsPoint, Scalar as DalekScalar, traits::Identity};
use monero_oxide::{
    ed25519::CompressedPoint as MoneroCompressedPoint,
    ringct::RctPrunable,
    transaction::{Input, Pruned, Transaction},
};
use monero_simple_request_rpc::{
    SimpleRequestTransport,
    prelude::{
        EvaluateUnlocked, ExpandToScannableBlock, FeePriority, HttpTransport, MoneroDaemon,
        ProvidesBlockchain, ProvidesBlockchainMeta, ProvidesDecoys, ProvidesFeeRates,
        ProvidesTransactions, PublishTransaction,
    },
};
use monero_wallet::{
    DEFAULT_LOCK_WINDOW, OutputWithDecoys,
    address::{MoneroAddress, Network},
    interface::FeeRate,
    ringct::RctType,
    send::{SendError, SignableTransaction},
};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as DeError, SeqAccess, Visitor},
};
use thiserror::Error;
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    NetworkKind,
    committee::{Committee, SessionId},
    consolidation_roast::RoastAttemptPrefixSeal,
    deposit_consolidation::{
        AttemptBinding, SignedTransactionBinding, TransactionAuthorization,
        consolidation_input_set_binding, consolidation_signed_bytes_binding,
    },
    deposit_index::{
        PortableAllocationRecord, PortableConsolidationStatus, PortableConsolidationTerminalRecord,
        VerifiedPortableScannerSnapshot, VerifiedPortableScannerTransition,
    },
    deposit_ledger::{AllocationStatement, DepositObservationStatement, LedgerPayload},
    deposit_output_scanner::{
        DepositOutputScanFailure, DepositOutputScannerLimits, DepositTransactionScanCursor,
    },
    deposit_wallet::{
        AuthenticatedHistoricalBlockEvidence, ChainPoint, DepositAddressDeriver,
        DepositSubaddressIndex, DepositWalletError, DepositWalletId, FamilyKeyImageBinding,
        MONERO_UNLOCK_TIMESTAMP_WINDOW, PersistedRootOutput, PersistedWalletOutput, RollbackReport,
        ScanState, ScannedBlock, SignedSweepTransaction, SweepConfirmationEvidence, SweepId,
        SweepRecord, SweepSigningIntent, SweepStatus, VerifiedPortableSweepTerminal,
        WalletOutputId, derive_sweep_signing_session,
    },
    roast_attempt_archive::VerifiedArchivedPrefixTransaction,
    signing::{CanonicalSignerSet, signing_context_in_session},
};

const WORKER_STATE_VERSION: u16 = 14;
const ALLOCATION_BACKFILL_VERSION: u16 = 2;
const CERTIFIED_SWEEP_PUBLICATION_VERSION: u16 = 1;
const EVENT_BATCH_VERSION: u16 = 2;
const MAX_WORKER_STATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_SUPPORTED_HARDFORK: u8 = 16;
const MAX_CONFIRMATION_DEPTH: u32 = 100_000;
const MAX_BLOCKS_PER_TICK: u16 = 1024;
const MAX_REORG_DEPTH: u32 = 100_000;
const MAX_OUTPUTS_PER_BLOCK: u16 = 4096;
const MAX_ATOMIC_OUTPUT_BINDINGS: usize = 256;
const MAX_SWEEP_INPUTS: u16 = 1024;
const MAX_RETAINED_OUTPUTS: u32 = 1_000_000;
const MAX_REQUEST_TIMEOUT_MILLIS: u64 = 10 * 60 * 1000;
const MAX_EXPANDED_BLOCK_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRANSACTIONS_PER_BLOCK: usize = 100_000;
const PREPARED_SWEEP_INTENT_VERSION: u16 = 1;
const MAX_PREPARED_SWEEP_INTENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_PREPARED_DECOY_INPUT_BYTES: usize = 64 * 1024;
const MAX_DAEMON_INFO_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_CERTIFIED_SWEEP_PUBLICATIONS: usize = 4_096;

/// Boxed future used by the mockable chain-source interface.
pub type ChainFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ChainSourceError>> + Send + 'a>>;

/// One authenticated deposit output which must be visible in the local burning-bug index before
/// the worker may durably advance its chain cursor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DepositOutputBinding {
    /// Exact transaction/output position.
    pub output: WalletOutputId,
    /// Exact one-time output key.
    pub output_key: [u8; 32],
    /// Certified permanent deposit subaddress, or `None` for the root/consolidation wallet.
    pub subaddress: Option<DepositSubaddressIndex>,
    /// Decrypted amount authenticated by the RingCT commitment.
    pub amount_atomic_units: u64,
    /// Canonical block timestamp used to burn a deposit allocation permanently on first use.
    pub observed_at: u64,
}

/// Narrow authenticated-index seam used by the bounded output scanner.
///
/// The portable snapshot binding must name one immutable deposit-index head. Preloads at another
/// head must fail rather than mixing allocation views across a resumable block scan. `bind_outputs`
/// must atomically apply the entire slice to the party-local safety index and be exactly
/// idempotent; a conflicting output ID or output key must fail closed.
pub trait DepositOutputIndexBackend: Send + Sync {
    /// Return the current authenticated portable allocation-index head binding.
    fn portable_snapshot(&self, wallet: DepositWalletId) -> ChainFuture<'_, [u8; 32]>;

    /// Resolve a bounded set of exact spend points at one pinned portable snapshot.
    ///
    /// Results must have exactly the same length and order as `spend_keys`.
    fn preload_subaddress_spend_keys<'a>(
        &'a self,
        wallet: DepositWalletId,
        portable_snapshot: [u8; 32],
        spend_keys: &'a [[u8; 32]],
    ) -> ChainFuture<'a, Vec<Option<DepositSubaddressIndex>>>;

    /// Require the portable head still equals `portable_snapshot`, then atomically expose exact
    /// recognized outputs in the local burning-bug index.
    fn bind_outputs<'a>(
        &'a self,
        wallet: DepositWalletId,
        portable_snapshot: [u8; 32],
        bindings: &'a [DepositOutputBinding],
    ) -> ChainFuture<'a, ()>;
}

impl<T> DepositOutputIndexBackend for std::sync::Arc<T>
where
    T: DepositOutputIndexBackend + ?Sized,
{
    fn portable_snapshot(&self, wallet: DepositWalletId) -> ChainFuture<'_, [u8; 32]> {
        self.as_ref().portable_snapshot(wallet)
    }

    fn preload_subaddress_spend_keys<'a>(
        &'a self,
        wallet: DepositWalletId,
        portable_snapshot: [u8; 32],
        spend_keys: &'a [[u8; 32]],
    ) -> ChainFuture<'a, Vec<Option<DepositSubaddressIndex>>> {
        self.as_ref().preload_subaddress_spend_keys(wallet, portable_snapshot, spend_keys)
    }

    fn bind_outputs<'a>(
        &'a self,
        wallet: DepositWalletId,
        portable_snapshot: [u8; 32],
        bindings: &'a [DepositOutputBinding],
    ) -> ChainFuture<'a, ()> {
        self.as_ref().bind_outputs(wallet, portable_snapshot, bindings)
    }
}

/// Resource and finality policy persisted with one scanner state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositWorkerConfig {
    /// Confirmations, counting the inclusion block, required before an output is reported.
    pub confirmation_depth: u32,
    /// Maximum blocks incorporated by one tick.
    pub max_blocks_per_tick: u16,
    /// Maximum retained blocks searched during one reorganization. This must retain at least
    /// Monero's sixty-block deterministic unlock-time timestamp window.
    pub max_reorg_depth: u32,
    /// Maximum wallet-owned outputs accepted in one block.
    pub max_outputs_per_block: u16,
    /// Maximum inputs selected for one consolidation transaction.
    pub max_sweep_inputs: u16,
    /// Maximum full outputs plus compact permanent burn-evidence entries retained in one snapshot.
    /// Reaching this bound fails closed; no spendable output or burn evidence is silently pruned.
    pub max_retained_outputs: u32,
    /// Deadline applied independently to every daemon operation.
    pub request_timeout_millis: u64,
    /// Do not prepare a sweep below this aggregate input amount.
    pub minimum_sweep_atomic_units: u64,
    /// Reject a constructed transaction whose necessary fee exceeds this amount.
    pub maximum_fee_atomic_units: u64,
}

impl Default for DepositWorkerConfig {
    fn default() -> Self {
        Self {
            confirmation_depth: 10,
            max_blocks_per_tick: 64,
            max_reorg_depth: 720,
            max_outputs_per_block: 1024,
            max_sweep_inputs: 64,
            max_retained_outputs: 100_000,
            request_timeout_millis: 30_000,
            minimum_sweep_atomic_units: 100_000,
            maximum_fee_atomic_units: 1_000_000_000,
        }
    }
}

impl DepositWorkerConfig {
    /// Check persisted limits against hard process bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero limit or one above its hard bound.
    pub fn validate(self) -> Result<Self, DepositWorkerError> {
        if self.confirmation_depth == 0
            || self.confirmation_depth > MAX_CONFIRMATION_DEPTH
            || self.max_blocks_per_tick == 0
            || self.max_blocks_per_tick > MAX_BLOCKS_PER_TICK
            || usize::try_from(self.max_reorg_depth)
                .map_or(true, |depth| depth < MONERO_UNLOCK_TIMESTAMP_WINDOW)
            || self.max_reorg_depth > MAX_REORG_DEPTH
            || self.max_outputs_per_block == 0
            || self.max_outputs_per_block > MAX_OUTPUTS_PER_BLOCK
            || self.max_sweep_inputs == 0
            || self.max_sweep_inputs > MAX_SWEEP_INPUTS
            || self.max_retained_outputs == 0
            || self.max_retained_outputs > MAX_RETAINED_OUTPUTS
            || self.request_timeout_millis == 0
            || self.request_timeout_millis > MAX_REQUEST_TIMEOUT_MILLIS
            || self.minimum_sweep_atomic_units == 0
            || self.maximum_fee_atomic_units == 0
        {
            return Err(DepositWorkerError::InvalidConfig);
        }
        Ok(self)
    }

    fn request_timeout(self) -> Duration {
        Duration::from_millis(self.request_timeout_millis)
    }
}

/// Additional hard limits for the concrete Monero daemon adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MoneroRpcLimits {
    /// Transport and whole-operation deadline.
    pub request_timeout: Duration,
    /// Maximum serialized expanded block accepted after the bounded RPC response is parsed.
    pub max_expanded_block_bytes: usize,
    /// Maximum non-miner transactions in one expanded block.
    pub max_transactions_per_block: usize,
}

impl Default for MoneroRpcLimits {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            max_expanded_block_bytes: 32 * 1024 * 1024,
            max_transactions_per_block: 16_384,
        }
    }
}

impl MoneroRpcLimits {
    fn validate(self) -> Result<Self, DepositWorkerError> {
        if self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MILLIS)
            || self.max_expanded_block_bytes == 0
            || self.max_expanded_block_bytes > MAX_EXPANDED_BLOCK_BYTES
            || self.max_transactions_per_block == 0
            || self.max_transactions_per_block > MAX_TRANSACTIONS_PER_BLOCK
        {
            return Err(DepositWorkerError::InvalidRpcLimits);
        }
        Ok(self)
    }
}

/// One expanded and locally scanned block returned by a chain source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchedDepositBlock {
    /// Exact block/parent binding.
    pub block: ScannedBlock,
    /// Consensus block timestamp. This feeds Monero's deterministic transaction-unlock clock but
    /// must not replace local wall time for deposit-allocation expiry.
    pub timestamp: u64,
    /// Protocol version declared by the block.
    pub hardfork_version: u8,
    /// Wallet-owned outputs found by the registered subaddress scanner.
    pub outputs: Vec<PersistedWalletOutput>,
    /// Root/primary outputs retained for cursor, reorg, and burning-bug safety only.
    pub root_outputs: Vec<PersistedRootOutput>,
}

/// One scanner result together with exact full transactions bound to that canonical block.
///
/// The transaction list is ephemeral until a candidate matches a pinned family. Implementations
/// must return only canonical bytes whose transaction IDs are committed by `block.block`; an
/// empty list is permitted for scanner-only backends and causes family settlement to fail closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchedDepositBlockEvidence {
    /// Wallet scanner result and exact chain point.
    pub block: FetchedDepositBlock,
    /// Canonical full non-miner transactions included in this block.
    pub transactions: Vec<SignedSweepTransaction>,
    /// Hash-bound key-image vectors from canonical pruned block transactions.
    pub transaction_key_images: Vec<CanonicalTransactionKeyImages>,
    /// Whether `transaction_key_images` covers every spend-capable non-miner transaction.
    ///
    /// This may be false for a scanner-only implementation. A worker with any pinned sweep
    /// family then refuses to advance, since omission would otherwise hide a conflicting spend
    /// which changed every prepared output.
    pub transaction_key_images_complete: bool,
}

/// Durable continuation for one bounded production block scan.
///
/// The exact block and portable index snapshot prevent a resumed scan from mixing canonical
/// branches or allocation-index heads. `global_output_index` is independently recomputed from the
/// expanded block on every resume and must match before any lookup is performed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositBlockScanCursor {
    block: ScannedBlock,
    portable_snapshot: [u8; 32],
    transaction_index: u32,
    transaction_cursor: DepositTransactionScanCursor,
    global_output_index: u64,
}

impl DepositBlockScanCursor {
    /// Construct a cursor for a chain-source implementation.
    ///
    /// The worker revalidates every field against the returned block, portable snapshot, and
    /// locally expanded transaction sequence before accepting or persisting it.
    #[must_use]
    pub const fn new(
        block: ScannedBlock,
        portable_snapshot: [u8; 32],
        transaction_index: u32,
        transaction_cursor: DepositTransactionScanCursor,
        global_output_index: u64,
    ) -> Self {
        Self {
            block,
            portable_snapshot,
            transaction_index,
            transaction_cursor,
            global_output_index,
        }
    }

    /// Exact canonical block being scanned.
    #[must_use]
    pub const fn block(self) -> ScannedBlock {
        self.block
    }

    /// Immutable portable allocation-index view used throughout this block.
    #[must_use]
    pub const fn portable_snapshot(self) -> [u8; 32] {
        self.portable_snapshot
    }

    /// Miner-plus-non-miner transaction position.
    #[must_use]
    pub const fn transaction_index(self) -> u32 {
        self.transaction_index
    }

    /// Cursor within the current transaction.
    #[must_use]
    pub const fn transaction_cursor(self) -> DepositTransactionScanCursor {
        self.transaction_cursor
    }

    /// Expected first global RingCT output index for the current transaction.
    #[must_use]
    pub const fn global_output_index(self) -> u64 {
        self.global_output_index
    }
}

/// Result of one bounded chain-source scan operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DepositBlockScanResult {
    /// A complete block plus all required family evidence.
    Complete(FetchedDepositBlockEvidence),
    /// One resumable chunk. The worker persists and byte-exactly merges its candidates.
    Deferred {
        /// Exact block metadata and candidates recognized in this chunk.
        block: FetchedDepositBlock,
        /// Deterministic continuation for a later worker tick.
        next_cursor: DepositBlockScanCursor,
    },
}

/// Minimal canonical prefix evidence used to discover any spend of a pinned family image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalTransactionKeyImages {
    /// Transaction ID committed by the exact block transaction list.
    pub transaction: [u8; 32],
    /// Key images in Monero wire order.
    pub key_images: Vec<[u8; 32]>,
}

/// Mockable source of a canonical Monero chain view and expanded scanner results.
pub trait DepositChainSource: Send + Sync {
    /// Return the zero-based latest block height.
    fn latest_height(&self) -> ChainFuture<'_, u64>;

    /// Return the canonical hash claimed for a retained height.
    fn block_hash(&self, height: u64) -> ChainFuture<'_, [u8; 32]>;

    /// Fetch one bounded piece of an exact block while retaining family evidence on completion.
    ///
    /// Implementations which always return a complete pre-scanned block may ignore `resume`.
    /// Production implementations must perform at most one configured scanner chunk and return
    /// `Deferred` when more work remains.
    fn scanned_block_evidence<'a>(
        &'a self,
        height: u64,
        deriver: &'a DepositAddressDeriver,
        output_index: &'a dyn DepositOutputIndexBackend,
        portable_snapshot: [u8; 32],
        resume: Option<DepositBlockScanCursor>,
    ) -> ChainFuture<'a, DepositBlockScanResult>;

    /// Fetch exact canonical bytes for a transaction ID, when the backend supports it.
    ///
    /// The worker still requires independent retained block/root-output inclusion evidence; a
    /// successful daemon lookup alone never proves settlement.
    fn full_transaction(
        &self,
        _transaction: [u8; 32],
    ) -> ChainFuture<'_, Option<SignedSweepTransaction>> {
        Box::pin(async { Ok(None) })
    }
}

/// Object-safe asynchronous backend for autonomous consolidation preparation and publication.
///
/// This is separate from [`DepositChainSource`] so scanner-only deployments and test fakes may
/// deliberately configure no transaction backend.
pub trait DepositConsolidationBackend: Send + Sync {
    /// Obtain decoys/fees and construct the exact locally verified root-only BP+ sweep.
    fn prepare_sweep<'a>(
        &'a self,
        state: &'a DepositWorkerState,
        deriver: &'a DepositAddressDeriver,
        plan: &'a SweepPlan,
    ) -> ChainFuture<'a, PreparedFrostlassSweep>;

    /// Re-query every absolute ring position and require byte-exact key/commitment equality with
    /// the prepared transaction before any party is allowed to create a signing nonce.
    fn validate_prepared_sweep<'a>(
        &'a self,
        state: &'a DepositWorkerState,
        prepared: &'a PreparedFrostlassSweep,
    ) -> ChainFuture<'a, ()>;

    /// Publish or republish the exact canonical transaction.
    fn publish_sweep<'a>(&'a self, transaction: &'a Transaction) -> ChainFuture<'a, ()>;
}

impl<T> DepositConsolidationBackend for std::sync::Arc<T>
where
    T: DepositConsolidationBackend + ?Sized,
{
    fn prepare_sweep<'a>(
        &'a self,
        state: &'a DepositWorkerState,
        deriver: &'a DepositAddressDeriver,
        plan: &'a SweepPlan,
    ) -> ChainFuture<'a, PreparedFrostlassSweep> {
        self.as_ref().prepare_sweep(state, deriver, plan)
    }

    fn validate_prepared_sweep<'a>(
        &'a self,
        state: &'a DepositWorkerState,
        prepared: &'a PreparedFrostlassSweep,
    ) -> ChainFuture<'a, ()> {
        self.as_ref().validate_prepared_sweep(state, prepared)
    }

    fn publish_sweep<'a>(&'a self, transaction: &'a Transaction) -> ChainFuture<'a, ()> {
        self.as_ref().publish_sweep(transaction)
    }
}

impl<T> DepositConsolidationBackend for Option<T>
where
    T: DepositConsolidationBackend,
{
    fn prepare_sweep<'a>(
        &'a self,
        state: &'a DepositWorkerState,
        deriver: &'a DepositAddressDeriver,
        plan: &'a SweepPlan,
    ) -> ChainFuture<'a, PreparedFrostlassSweep> {
        match self {
            Some(backend) => backend.prepare_sweep(state, deriver, plan),
            None => Box::pin(async { Err(ChainSourceError::BackendUnavailable) }),
        }
    }

    fn validate_prepared_sweep<'a>(
        &'a self,
        state: &'a DepositWorkerState,
        prepared: &'a PreparedFrostlassSweep,
    ) -> ChainFuture<'a, ()> {
        match self {
            Some(backend) => backend.validate_prepared_sweep(state, prepared),
            None => Box::pin(async {
                Err(ChainSourceError::Consolidation(
                    "consolidation backend is not configured".to_owned(),
                ))
            }),
        }
    }

    fn publish_sweep<'a>(&'a self, transaction: &'a Transaction) -> ChainFuture<'a, ()> {
        match self {
            Some(backend) => backend.publish_sweep(transaction),
            None => Box::pin(async { Err(ChainSourceError::BackendUnavailable) }),
        }
    }
}

/// Concrete source backed by one configured monerod endpoint and the pinned monero-oxide RPC.
#[derive(Clone, Debug)]
pub struct PinnedMoneroDaemon {
    daemon: MoneroDaemon<SimpleRequestTransport>,
    limits: MoneroRpcLimits,
    network: NetworkKind,
    genesis_hash: [u8; 32],
}

#[derive(Debug, Deserialize)]
struct DaemonNetworkReport {
    status: String,
    untrusted: bool,
    nettype: String,
    mainnet: bool,
    testnet: bool,
    stagenet: bool,
}

impl PinnedMoneroDaemon {
    /// Connect to a daemon and prove it serves the configured Monero network.
    ///
    /// A production caller should use a local/authenticated endpoint or HTTPS. This constructor
    /// requires a locally answered `get_info` response, its exact network flags/type, and the
    /// canonical block-zero hash before returning. It does not turn a single daemon into a
    /// Byzantine-trusted source.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits, endpoint initialization, or the initial RPC probe.
    pub async fn connect(
        endpoint: String,
        expected_network: NetworkKind,
        limits: MoneroRpcLimits,
    ) -> Result<Self, DepositWorkerError> {
        let limits = limits.validate()?;
        let daemon = SimpleRequestTransport::with_custom_timeout(endpoint, limits.request_timeout)
            .await
            .map_err(|error| DepositWorkerError::Daemon(error.to_string()))?;
        let genesis_hash =
            verify_daemon_network_identity(&daemon, expected_network, limits.request_timeout)
                .await?;
        Ok(Self { daemon, limits, network: expected_network, genesis_hash })
    }

    /// Access the pinned daemon interface for transaction publication by the host application.
    #[must_use]
    pub const fn daemon(&self) -> &MoneroDaemon<SimpleRequestTransport> {
        &self.daemon
    }

    /// Logical network proven by `get_info.nettype` and block zero during construction.
    #[must_use]
    pub const fn network(&self) -> NetworkKind {
        self.network
    }

    /// Block-zero hash observed and matched against the configured network during construction.
    #[must_use]
    pub const fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    /// Select real decoys and construct the exact root-wallet consolidation transaction.
    ///
    /// The result still requires a normal committee/signers-bound `signing_context` and
    /// [`DepositWorkerState::reserve_prepared_sweep`] before FROSTLASS begins. The constructor
    /// emits a one-atomic-unit payment plus standard change, both to the primary wallet, because
    /// Monero requires at least two outputs. All remaining value less the fee is therefore
    /// consolidated under the root wallet.
    ///
    /// # Errors
    ///
    /// Fails closed if the plan is stale, the daemon tip differs from the scanner tip, the
    /// hardfork is not CLSAG/BP+, decoy selection changes scanner material, or the fee exceeds the
    /// persisted cap.
    #[allow(clippy::too_many_lines)]
    pub async fn prepare_frostlass_sweep<R: RngCore + CryptoRng + Send + Sync>(
        &self,
        state: &DepositWorkerState,
        deriver: &DepositAddressDeriver,
        plan: &SweepPlan,
        rng: &mut R,
    ) -> Result<PreparedFrostlassSweep, DepositWorkerError> {
        state.validate_plan(plan)?;
        if state.scan.network() != self.network {
            return Err(DepositWorkerError::DaemonNetworkMismatch {
                expected: state.scan.network().daemon_nettype(),
                actual: self.network.daemon_nettype().to_owned(),
            });
        }
        if state.wallet_id() != deriver.wallet_id() {
            return Err(DepositWorkerError::WrongWalletDomain);
        }
        if plan.destination_binding != root_consolidation_destination_binding(deriver, state.config)
        {
            return Err(DepositWorkerError::DestinationPolicyMismatch);
        }

        let latest = timeout(self.limits.request_timeout, self.daemon.latest_block_number())
            .await
            .map_err(|_| DepositWorkerError::RequestTimeout {
                operation: "latest block for sweep",
                height: None,
            })?
            .map_err(|error| DepositWorkerError::Daemon(error.to_string()))?;
        let latest_u64 = u64::try_from(latest).map_err(|_| DepositWorkerError::HeightOverflow)?;
        if latest_u64 < state.scan.tip().height {
            return Err(DepositWorkerError::DaemonBehindState {
                daemon: latest_u64,
                state: state.scan.tip().height,
            });
        }
        let canonical_tip = timeout(
            self.limits.request_timeout,
            self.daemon.block_hash(usize_height(state.scan.tip().height)?),
        )
        .await
        .map_err(|_| DepositWorkerError::RequestTimeout {
            operation: "scanner-tip hash for sweep",
            height: Some(state.scan.tip().height),
        })?
        .map_err(|error| DepositWorkerError::Daemon(error.to_string()))?;
        if canonical_tip != state.scan.tip().hash {
            return Err(DepositWorkerError::StaleSweepPlan);
        }

        let latest_block =
            timeout(self.limits.request_timeout, self.daemon.block_by_number(latest))
                .await
                .map_err(|_| DepositWorkerError::RequestTimeout {
                    operation: "latest block for hardfork",
                    height: Some(latest_u64),
                })?
                .map_err(|error| DepositWorkerError::Daemon(error.to_string()))?;
        if !matches!(latest_block.header.hardfork_version, 15 | 16) {
            return Err(DepositWorkerError::UnsupportedSigningHardfork(
                latest_block.header.hardfork_version,
            ));
        }

        let mut inputs = Vec::with_capacity(plan.inputs.len());
        for id in &plan.inputs {
            let persisted = state.scan.output(*id).ok_or(DepositWorkerError::StaleSweepPlan)?;
            let wallet_output = persisted.wallet_output()?;
            let input = timeout(
                self.limits.request_timeout,
                OutputWithDecoys::new(rng, &self.daemon, 16, latest, wallet_output),
            )
            .await
            .map_err(|_| DepositWorkerError::RequestTimeout {
                operation: "decoy selection",
                height: Some(latest_u64),
            })?
            .map_err(|error| DepositWorkerError::Daemon(error.to_string()))?;
            persisted.verify_decoy_input(&input)?;
            inputs.push(input);
        }

        let fee_rate = timeout(
            self.limits.request_timeout,
            self.daemon.fee_rate(FeePriority::Unimportant, u64::MAX),
        )
        .await
        .map_err(|_| DepositWorkerError::RequestTimeout {
            operation: "fee rate",
            height: Some(latest_u64),
        })?
        .map_err(|error| DepositWorkerError::Daemon(error.to_string()))?;

        let primary = MoneroAddress::from_str(
            address_network(state.scan.network()),
            &deriver.primary_address(),
        )
        .map_err(|error| DepositWorkerError::Address(error.to_string()))?;
        let mut outgoing_view_key = Zeroizing::new([0_u8; 32]);
        rng.fill_bytes(outgoing_view_key.as_mut());
        if outgoing_view_key.as_ref() == &[0_u8; 32] {
            return Err(DepositWorkerError::InvalidPreparedSweep);
        }
        let outgoing_view_key_bytes = *outgoing_view_key;
        let decoy_inputs = inputs.iter().map(OutputWithDecoys::serialize).collect::<Vec<_>>();
        let fee_rate_bytes = fee_rate.serialize();
        let transaction = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            outgoing_view_key,
            inputs,
            vec![(primary, 1)],
            deriver.primary_change(),
            vec![],
            fee_rate,
        )?;
        let fee = transaction.necessary_fee();
        if fee > state.config.maximum_fee_atomic_units {
            return Err(DepositWorkerError::FeeAbovePolicy {
                actual: fee,
                maximum: state.config.maximum_fee_atomic_units,
            });
        }

        let transaction_commitment = transaction_commitment(plan, &transaction);
        let prepared_intent = PreparedSweepIntent {
            version: PREPARED_SWEEP_INTENT_VERSION,
            plan: plan.clone(),
            outgoing_view_key: outgoing_view_key_bytes,
            decoy_inputs,
            fee_rate: fee_rate_bytes,
            transaction_commitment,
            fee_atomic_units: fee,
        };
        prepared_intent.validate_structure()?;
        // Use the same reconstruction/validation path required of every follower.
        drop(transaction);
        state.verify_prepared_sweep_intent(deriver, &prepared_intent)
    }
}

async fn verify_daemon_network_identity<T: HttpTransport>(
    daemon: &MoneroDaemon<T>,
    expected_network: NetworkKind,
    request_timeout: Duration,
) -> Result<[u8; 32], DepositWorkerError> {
    let report = timeout(
        request_timeout,
        daemon.json_rpc_call("get_info", None, MAX_DAEMON_INFO_RESPONSE_BYTES),
    )
    .await
    .map_err(|_| DepositWorkerError::RequestTimeout {
        operation: "daemon network identity",
        height: None,
    })?
    .map_err(|error| DepositWorkerError::Daemon(error.to_string()))?;
    let report: DaemonNetworkReport = serde_json::from_str(&report)
        .map_err(|error| DepositWorkerError::InvalidDaemonNetworkReport(error.to_string()))?;
    if report.status != "OK" {
        return Err(DepositWorkerError::DaemonStatus(report.status));
    }
    if report.untrusted {
        return Err(DepositWorkerError::UntrustedDaemonNetworkReport);
    }
    let expected_nettype = expected_network.daemon_nettype();
    if report.nettype != expected_nettype {
        return Err(DepositWorkerError::DaemonNetworkMismatch {
            expected: expected_nettype,
            actual: report.nettype,
        });
    }
    if (report.mainnet, report.testnet, report.stagenet) != expected_network.daemon_network_flags()
    {
        return Err(DepositWorkerError::InconsistentDaemonNetworkFlags {
            nettype: report.nettype,
            mainnet: report.mainnet,
            testnet: report.testnet,
            stagenet: report.stagenet,
        });
    }

    let observed = timeout(request_timeout, daemon.block_hash(0))
        .await
        .map_err(|_| DepositWorkerError::RequestTimeout {
            operation: "daemon genesis hash",
            height: Some(0),
        })?
        .map_err(|error| DepositWorkerError::Daemon(error.to_string()))?;
    let expected = expected_network.genesis_hash();
    if observed != expected {
        return Err(DepositWorkerError::DaemonGenesisMismatch { expected, actual: observed });
    }
    Ok(observed)
}

impl DepositConsolidationBackend for PinnedMoneroDaemon {
    fn prepare_sweep<'a>(
        &'a self,
        state: &'a DepositWorkerState,
        deriver: &'a DepositAddressDeriver,
        plan: &'a SweepPlan,
    ) -> ChainFuture<'a, PreparedFrostlassSweep> {
        Box::pin(async move {
            let mut rng = OsRng;
            self.prepare_frostlass_sweep(state, deriver, plan, &mut rng)
                .await
                .map_err(|error| ChainSourceError::Consolidation(error.to_string()))
        })
    }

    fn validate_prepared_sweep<'a>(
        &'a self,
        state: &'a DepositWorkerState,
        prepared: &'a PreparedFrostlassSweep,
    ) -> ChainFuture<'a, ()> {
        Box::pin(async move {
            if state.scan.network() != self.network {
                return Err(ChainSourceError::Consolidation(format!(
                    "daemon network {} differs from durable worker network {}",
                    self.network.daemon_nettype(),
                    state.scan.network().daemon_nettype()
                )));
            }
            prepared
                .prepared_intent
                .validate_structure()
                .map_err(|error| ChainSourceError::Consolidation(error.to_string()))?;
            if prepared.plan() != prepared.prepared_intent.plan()
                || prepared.plan().wallet != state.wallet_id()
            {
                return Err(ChainSourceError::Consolidation(
                    "prepared sweep belongs to another worker state".to_owned(),
                ));
            }

            let latest = timeout(self.limits.request_timeout, self.daemon.latest_block_number())
                .await
                .map_err(|_| {
                    ChainSourceError::Consolidation(
                        "timed out validating consolidation chain tip".to_owned(),
                    )
                })?
                .map_err(|error| ChainSourceError::Consolidation(error.to_string()))?;
            let latest = u64::try_from(latest).map_err(|_| ChainSourceError::HeightOverflow)?;
            if latest < state.scan.tip().height {
                return Err(ChainSourceError::Consolidation(
                    "daemon is behind the durable consolidation scanner".to_owned(),
                ));
            }
            let tip_hash = timeout(
                self.limits.request_timeout,
                self.daemon.block_hash(usize_height_source(state.scan.tip().height)?),
            )
            .await
            .map_err(|_| {
                ChainSourceError::Consolidation(
                    "timed out validating consolidation scanner tip".to_owned(),
                )
            })?
            .map_err(|error| ChainSourceError::Consolidation(error.to_string()))?;
            if tip_hash != state.scan.tip().hash {
                return Err(ChainSourceError::Consolidation(
                    "durable consolidation scanner tip is no longer canonical".to_owned(),
                ));
            }

            let mut positions = Vec::new();
            let mut expected = Vec::new();
            for (id, bytes) in
                prepared.plan().inputs.iter().zip(&prepared.prepared_intent.decoy_inputs)
            {
                let persisted = state.scan.output(*id).ok_or_else(|| {
                    ChainSourceError::Consolidation(
                        "prepared consolidation input is absent from the canonical scanner"
                            .to_owned(),
                    )
                })?;
                let input = decode_decoy_input(bytes)
                    .map_err(|error| ChainSourceError::Consolidation(error.to_string()))?;
                persisted
                    .verify_decoy_input(&input)
                    .map_err(|error| ChainSourceError::Consolidation(error.to_string()))?;
                // The audited Monero CLSAG construction uses exactly sixteen members. This also
                // bounds the follower's daemon query independently of serialized input size.
                if input.decoys().len() != 16 {
                    return Err(ChainSourceError::Consolidation(
                        "prepared consolidation has a non-consensus ring size".to_owned(),
                    ));
                }
                positions.extend(input.decoys().positions());
                expected.extend_from_slice(input.decoys().ring());
            }
            if positions.is_empty() || positions.len() != expected.len() {
                return Err(ChainSourceError::Consolidation(
                    "prepared consolidation ring set is malformed".to_owned(),
                ));
            }
            let observed = timeout(
                self.limits.request_timeout,
                self.daemon.unlocked_ringct_outputs(&positions, EvaluateUnlocked::Normal),
            )
            .await
            .map_err(|_| {
                ChainSourceError::Consolidation(
                    "timed out validating consolidation ring members".to_owned(),
                )
            })?
            .map_err(|error| ChainSourceError::Consolidation(error.to_string()))?;
            if observed.len() != expected.len()
                || observed
                    .iter()
                    .zip(&expected)
                    .any(|(observed, expected)| observed.as_ref() != Some(expected))
            {
                return Err(ChainSourceError::Consolidation(
                    "prepared consolidation ring differs from canonical daemon outputs".to_owned(),
                ));
            }
            Ok(())
        })
    }

    fn publish_sweep<'a>(&'a self, transaction: &'a Transaction) -> ChainFuture<'a, ()> {
        Box::pin(async move {
            self.daemon
                .publish_transaction(transaction)
                .await
                .map_err(|error| ChainSourceError::Publication(error.to_string()))
        })
    }
}

impl DepositChainSource for PinnedMoneroDaemon {
    fn latest_height(&self) -> ChainFuture<'_, u64> {
        Box::pin(async move {
            let height = self
                .daemon
                .latest_block_number()
                .await
                .map_err(|error| ChainSourceError::Rpc(error.to_string()))?;
            u64::try_from(height).map_err(|_| ChainSourceError::HeightOverflow)
        })
    }

    fn block_hash(&self, height: u64) -> ChainFuture<'_, [u8; 32]> {
        Box::pin(async move {
            self.daemon
                .block_hash(usize_height_source(height)?)
                .await
                .map_err(|error| ChainSourceError::Rpc(error.to_string()))
        })
    }

    fn scanned_block_evidence<'a>(
        &'a self,
        height: u64,
        deriver: &'a DepositAddressDeriver,
        output_index: &'a dyn DepositOutputIndexBackend,
        portable_snapshot: [u8; 32],
        resume: Option<DepositBlockScanCursor>,
    ) -> ChainFuture<'a, DepositBlockScanResult> {
        Box::pin(async move {
            let height_usize = usize_height_source(height)?;
            let block = self
                .daemon
                .block_by_number(height_usize)
                .await
                .map_err(|error| ChainSourceError::Rpc(error.to_string()))?;
            if block.header.hardfork_version > MAX_SUPPORTED_HARDFORK {
                return Err(ChainSourceError::UnsupportedHardfork(block.header.hardfork_version));
            }
            let point = ChainPoint::new(height, block.hash())
                .map_err(|error| ChainSourceError::Invalid(error.to_string()))?;
            let scanned_block = ScannedBlock { point, parent_hash: block.header.previous };
            if let Some(cursor) = resume
                && (cursor.block != scanned_block || cursor.portable_snapshot != portable_snapshot)
            {
                return Err(ChainSourceError::Invalid(
                    "resumable block scan binding changed".to_owned(),
                ));
            }
            let included_transaction_ids = block.transactions.clone();
            let timestamp = block.header.timestamp;
            let hardfork_version = block.header.hardfork_version;
            let expanded = self
                .daemon
                .expand_to_scannable_block(block)
                .await
                .map_err(|error| ChainSourceError::Rpc(error.to_string()))?;
            if expanded.transactions.len() > self.limits.max_transactions_per_block {
                return Err(ChainSourceError::TooManyTransactions {
                    actual: expanded.transactions.len(),
                    maximum: self.limits.max_transactions_per_block,
                });
            }
            let mut expanded_bytes = expanded.block.serialize().len();
            if expanded_bytes > self.limits.max_expanded_block_bytes {
                return Err(ChainSourceError::ExpandedBlockTooLarge {
                    actual: expanded_bytes,
                    maximum: self.limits.max_expanded_block_bytes,
                });
            }
            for transaction in &expanded.transactions {
                expanded_bytes = expanded_bytes.checked_add(transaction.serialize().len()).ok_or(
                    ChainSourceError::ExpandedBlockTooLarge {
                        actual: usize::MAX,
                        maximum: self.limits.max_expanded_block_bytes,
                    },
                )?;
                if expanded_bytes > self.limits.max_expanded_block_bytes {
                    return Err(ChainSourceError::ExpandedBlockTooLarge {
                        actual: expanded_bytes,
                        maximum: self.limits.max_expanded_block_bytes,
                    });
                }
            }
            if included_transaction_ids.len() != expanded.transactions.len() {
                return Err(ChainSourceError::Invalid(
                    "expanded transaction count differs from canonical block".to_owned(),
                ));
            }
            let transaction_key_images = included_transaction_ids
                .iter()
                .copied()
                .zip(&expanded.transactions)
                .filter_map(|(transaction, candidate)| {
                    let Transaction::V2 { prefix, proofs: Some(_), .. } = candidate else {
                        return None;
                    };
                    let key_images = prefix
                        .inputs
                        .iter()
                        .map(|input| match input {
                            Input::ToKey { key_image, .. } => Some(key_image.to_bytes()),
                            Input::Gen(_) => None,
                        })
                        .collect::<Option<Vec<_>>>()?;
                    Some(CanonicalTransactionKeyImages { transaction, key_images })
                })
                .collect::<Vec<_>>();

            let scanner = deriver
                .bounded_output_scanner(DepositOutputScannerLimits::default())
                .map_err(|error| ChainSourceError::Invalid(error.to_string()))?;
            let miner_hash = expanded.block.miner_transaction().hash();
            let miner = Transaction::<Pruned>::from(expanded.block.miner_transaction().clone());
            let transaction_count =
                expanded.transactions.len().checked_add(1).ok_or_else(|| {
                    ChainSourceError::Invalid("transaction count overflow".to_owned())
                })?;
            let has_ringct_outputs = (0..transaction_count).any(|index| {
                expanded_transaction_at(
                    miner_hash,
                    &miner,
                    &included_transaction_ids,
                    &expanded.transactions,
                    index,
                )
                .is_some_and(|(_, transaction)| {
                    transaction.version() == 2 && !transaction.prefix().outputs.is_empty()
                })
            });
            let first_global_output_index = match expanded.output_index_for_first_ringct_output {
                Some(index) => index,
                None if has_ringct_outputs => {
                    return Err(ChainSourceError::Invalid(
                        "expanded block omitted its first global RingCT output index".to_owned(),
                    ));
                }
                None => 0,
            };
            let mut transaction_index = match resume {
                Some(cursor) => usize::try_from(cursor.transaction_index)
                    .map_err(|_| ChainSourceError::Invalid("scan cursor overflow".to_owned()))?,
                None => 0,
            };
            if transaction_index >= transaction_count {
                return Err(ChainSourceError::Invalid(
                    "scan cursor transaction is outside the block".to_owned(),
                ));
            }
            let mut global_output_index = first_global_output_index;
            for prior in 0..transaction_index {
                let (_, transaction) = expanded_transaction_at(
                    miner_hash,
                    &miner,
                    &included_transaction_ids,
                    &expanded.transactions,
                    prior,
                )
                .ok_or_else(|| {
                    ChainSourceError::Invalid("scan cursor transaction is missing".to_owned())
                })?;
                if transaction.version() == 2 {
                    global_output_index = global_output_index
                        .checked_add(u64::try_from(transaction.prefix().outputs.len()).map_err(
                            |_| {
                                ChainSourceError::Invalid("global output index overflow".to_owned())
                            },
                        )?)
                        .ok_or_else(|| {
                            ChainSourceError::Invalid("global output index overflow".to_owned())
                        })?;
                }
            }
            if resume.is_some_and(|cursor| cursor.global_output_index != global_output_index) {
                return Err(ChainSourceError::Invalid(
                    "resumed global RingCT output index changed".to_owned(),
                ));
            }
            while transaction_index < transaction_count
                && expanded_transaction_at(
                    miner_hash,
                    &miner,
                    &included_transaction_ids,
                    &expanded.transactions,
                    transaction_index,
                )
                .is_some_and(|(_, transaction)| transaction.version() != 2)
            {
                transaction_index += 1;
            }

            let mut recognized = Vec::new();
            let mut next_cursor = None;
            if transaction_index < transaction_count {
                let (transaction_hash, transaction) = expanded_transaction_at(
                    miner_hash,
                    &miner,
                    &included_transaction_ids,
                    &expanded.transactions,
                    transaction_index,
                )
                .ok_or_else(|| {
                    ChainSourceError::Invalid("scan cursor transaction is missing".to_owned())
                })?;
                let transaction_cursor = resume
                    .filter(|cursor| {
                        usize::try_from(cursor.transaction_index).ok() == Some(transaction_index)
                    })
                    .map_or(DepositTransactionScanCursor::start(), |cursor| {
                        cursor.transaction_cursor
                    });

                let mut spend_keys = BTreeSet::new();
                let preview = scanner
                    .scan_transaction_chunk(
                        hardfork_version,
                        transaction_hash,
                        global_output_index,
                        transaction,
                        transaction_cursor,
                        &mut |wallet, spend_key| {
                            debug_assert_eq!(wallet, deriver.wallet_id());
                            spend_keys.insert(spend_key);
                            Ok::<_, std::convert::Infallible>(None)
                        },
                    )
                    .map_err(output_scan_failure)?;
                let spend_keys = spend_keys.into_iter().collect::<Vec<_>>();
                let preloaded = output_index
                    .preload_subaddress_spend_keys(
                        deriver.wallet_id(),
                        portable_snapshot,
                        &spend_keys,
                    )
                    .await?;
                if preloaded.len() != spend_keys.len() {
                    return Err(ChainSourceError::Invalid(
                        "deposit-index preload returned the wrong result count".to_owned(),
                    ));
                }
                let cached = spend_keys.into_iter().zip(preloaded).collect::<BTreeMap<_, _>>();
                let actual = scanner
                    .scan_transaction_chunk(
                        hardfork_version,
                        transaction_hash,
                        global_output_index,
                        transaction,
                        transaction_cursor,
                        &mut |wallet, spend_key| {
                            if wallet != deriver.wallet_id() {
                                return Err("bounded scanner changed wallet domain");
                            }
                            cached
                                .get(&spend_key)
                                .copied()
                                .ok_or("bounded scanner requested a key absent from its preload")
                        },
                    )
                    .map_err(output_scan_failure)?;
                if actual.next_cursor() != preview.next_cursor() {
                    return Err(ChainSourceError::Invalid(
                        "deposit-index results changed deterministic scanner progress".to_owned(),
                    ));
                }
                let (chunk_outputs, transaction_continuation) = actual.into_parts();
                recognized = chunk_outputs;
                next_cursor = match transaction_continuation {
                    Some(transaction_cursor) => Some(DepositBlockScanCursor {
                        block: scanned_block,
                        portable_snapshot,
                        transaction_index: u32::try_from(transaction_index).map_err(|_| {
                            ChainSourceError::Invalid("scan cursor overflow".to_owned())
                        })?,
                        transaction_cursor,
                        global_output_index,
                    }),
                    None => {
                        global_output_index = global_output_index
                            .checked_add(
                                u64::try_from(transaction.prefix().outputs.len()).map_err(
                                    |_| {
                                        ChainSourceError::Invalid(
                                            "global output index overflow".to_owned(),
                                        )
                                    },
                                )?,
                            )
                            .ok_or_else(|| {
                                ChainSourceError::Invalid("global output index overflow".to_owned())
                            })?;
                        transaction_index += 1;
                        while transaction_index < transaction_count
                            && expanded_transaction_at(
                                miner_hash,
                                &miner,
                                &included_transaction_ids,
                                &expanded.transactions,
                                transaction_index,
                            )
                            .is_some_and(|(_, candidate)| candidate.version() != 2)
                        {
                            transaction_index += 1;
                        }
                        (transaction_index < transaction_count)
                            .then(|| {
                                Ok(DepositBlockScanCursor {
                                    block: scanned_block,
                                    portable_snapshot,
                                    transaction_index: u32::try_from(transaction_index).map_err(
                                        |_| {
                                            ChainSourceError::Invalid(
                                                "scan cursor overflow".to_owned(),
                                            )
                                        },
                                    )?,
                                    transaction_cursor: DepositTransactionScanCursor::start(),
                                    global_output_index,
                                })
                            })
                            .transpose()?
                    }
                };
            }

            let mut outputs = Vec::new();
            let mut root_outputs = Vec::new();
            for recognized in recognized {
                if recognized.subaddress().is_some() {
                    outputs.push(
                        PersistedWalletOutput::from_scanner(recognized.output())
                            .map_err(|error| ChainSourceError::Invalid(error.to_string()))?,
                    );
                } else {
                    root_outputs.push(
                        PersistedRootOutput::from_scanner(recognized.output())
                            .map_err(|error| ChainSourceError::Invalid(error.to_string()))?,
                    );
                }
            }
            let fetched = FetchedDepositBlock {
                block: scanned_block,
                timestamp,
                hardfork_version,
                outputs,
                root_outputs,
            };
            if let Some(next_cursor) = next_cursor {
                return Ok(DepositBlockScanResult::Deferred { block: fetched, next_cursor });
            }

            let mut transaction_ids = fetched
                .root_outputs
                .iter()
                .map(|output| output.id().transaction)
                .collect::<BTreeSet<_>>();
            let mut transactions = Vec::with_capacity(transaction_ids.len());
            while let Some(transaction) = transaction_ids.pop_first() {
                let full = self
                    .daemon
                    .transaction(transaction)
                    .await
                    .map_err(|error| ChainSourceError::Rpc(error.to_string()))?;
                transactions.push(
                    SignedSweepTransaction::from_transaction(&full, Some(transaction))
                        .map_err(|error| ChainSourceError::Invalid(error.to_string()))?,
                );
            }
            Ok(DepositBlockScanResult::Complete(FetchedDepositBlockEvidence {
                block: fetched,
                transactions,
                transaction_key_images,
                transaction_key_images_complete: true,
            }))
        })
    }

    fn full_transaction(
        &self,
        transaction: [u8; 32],
    ) -> ChainFuture<'_, Option<SignedSweepTransaction>> {
        Box::pin(async move {
            let fetched = self
                .daemon
                .transaction(transaction)
                .await
                .map_err(|error| ChainSourceError::Rpc(error.to_string()))?;
            SignedSweepTransaction::from_transaction(&fetched, Some(transaction))
                .map(Some)
                .map_err(|error| ChainSourceError::Invalid(error.to_string()))
        })
    }
}

/// One confirmed deposit released only after the corresponding cursor state is persisted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositDetection {
    /// Absolute replay-safe Monero output ID.
    pub output: WalletOutputId,
    /// Global `RingCT` output index used for decoy selection.
    pub index_on_blockchain: u64,
    /// Allocated subaddress which received the output.
    pub subaddress: DepositSubaddressIndex,
    /// Decrypted atomic-unit amount.
    pub amount_atomic_units: u64,
    /// Confirmed block containing the output.
    pub observed_block: ChainPoint,
    /// Informational consensus timestamp of the containing block.
    pub block_timestamp: u64,
}

/// Exact canonical observation removed by a chain reorganization.
///
/// Consumers must conditionally retract an observation only if all fields match their currently
/// stored value. The all-time "address was ever used" marker is deliberately not retractable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OrphanedDeposit {
    /// Absolute output ID.
    pub output: WalletOutputId,
    /// Global output index on the orphaned branch.
    pub index_on_blockchain: u64,
    /// Deposit subaddress observed on the orphaned branch.
    pub subaddress: DepositSubaddressIndex,
    /// Decrypted amount observed on the orphaned branch.
    pub amount_atomic_units: u64,
    /// Exact orphaned block containing the observation.
    pub observed_block: ChainPoint,
}

/// Reorg consequences which the host applies idempotently after scanner persistence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositRollback {
    /// Exact retained common ancestor.
    pub ancestor: ChainPoint,
    /// Deposit output IDs removed with orphaned blocks.
    ///
    /// This is diagnostic/indexing data. Consumers must use [`Self::orphaned_deposits`] rather
    /// than retracting an observation by ID alone.
    pub removed_outputs: Vec<WalletOutputId>,
    /// Exact prior canonical metadata for conditional observation retraction.
    pub orphaned_deposits: Vec<OrphanedDeposit>,
    /// Root/primary outputs removed with orphaned blocks; never client deposits.
    pub removed_root_outputs: Vec<WalletOutputId>,
    /// Sweep attempts whose inputs disappeared.
    pub invalidated_sweeps: Vec<SweepId>,
    /// Sweep attempts quarantined because signing may already have started.
    pub quarantined_sweeps: Vec<SweepId>,
    /// Sweep confirmations reverted to broadcast.
    pub reverted_confirmations: Vec<SweepId>,
}

impl DepositRollback {
    fn from_report(
        ancestor: ChainPoint,
        report: RollbackReport,
        prior: &ScanState,
    ) -> Result<Self, DepositWorkerError> {
        let mut orphaned_deposits = Vec::with_capacity(report.removed_outputs.len());
        for id in &report.removed_outputs {
            let output = prior.output(*id).ok_or(DepositWorkerError::CorruptState)?;
            let wallet_output = output.wallet_output()?;
            let observed_block =
                prior.output_chain_point(*id).ok_or(DepositWorkerError::CorruptState)?;
            if observed_block.height <= ancestor.height {
                return Err(DepositWorkerError::CorruptState);
            }
            orphaned_deposits.push(OrphanedDeposit {
                output: *id,
                index_on_blockchain: output.index_on_blockchain(),
                subaddress: output.subaddress(),
                amount_atomic_units: wallet_output.commitment().amount,
                observed_block,
            });
        }
        Ok(Self {
            ancestor,
            removed_outputs: report.removed_outputs,
            orphaned_deposits,
            removed_root_outputs: report.removed_root_outputs,
            invalidated_sweeps: report.invalidated_sweeps,
            quarantined_sweeps: report.quarantined_sweeps,
            reverted_confirmations: report.reverted_confirmations,
        })
    }
}

/// Durable at-least-once event batch associated with one scanner revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerEventBatch {
    /// Stable replay identifier.
    pub id: [u8; 32],
    /// Worker revision which first stored this batch.
    pub revision: u64,
    /// Newly confirmed deposits in chain and output order.
    pub detections: Vec<DepositDetection>,
    /// Deep-confirmation reorg, if one was observed.
    pub rollback: Option<DepositRollback>,
}

/// Exact state persistence obligation returned by a worker mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerPersistEffect {
    revision: u64,
    state_commitment: [u8; 32],
}

impl WorkerPersistEffect {
    /// Revision which must be used for the encrypted wallet snapshot.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Commitment to the exact canonical plaintext state which must be persisted.
    #[must_use]
    pub const fn state_commitment(self) -> [u8; 32] {
        self.state_commitment
    }
}

/// Durable reservation result. This does not authorize nonce creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedSweepReservation {
    /// State persistence required before the separate signing-release transition.
    pub persistence: WorkerPersistEffect,
    /// Reserved sweep attempt.
    pub sweep: SweepId,
}

/// Durable result of pinning quorum-certified threshold key images to a sweep family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FamilyKeyImagePin {
    /// Snapshot persistence required before any signature share is exposed.
    pub persistence: WorkerPersistEffect,
    /// Exact attempt-independent binding which was stored.
    pub binding: FamilyKeyImageBinding,
}

/// Single-state-lineage receipt for one durable `Reserved -> SigningReleased` transition.
///
/// This value is deliberately neither `Clone` nor `Copy`. Persist its obligation, then consume the
/// receipt exactly once with [`DepositWorkerState::signing_authorization_after_persist`]. Losing it
/// after persistence requires fresh-session recovery; calling release again cannot mint another.
/// It is not a distributed CAS capability: cloned pre-release worker snapshots can each transition,
/// so the encrypted service snapshot CAS and PartyServer/ProtocolStore session tombstone remain the
/// authoritative cross-process nonce boundary.
#[derive(Debug, Eq, PartialEq)]
pub struct SigningReleaseReceipt {
    persistence: WorkerPersistEffect,
    sweep: SweepId,
    attempt_high_water: u64,
    session: SessionId,
    intent_digest: [u8; 32],
}

impl SigningReleaseReceipt {
    /// Exact worker snapshot obligation which must be durably stored first.
    #[must_use]
    pub const fn persistence(&self) -> WorkerPersistEffect {
        self.persistence
    }

    /// Sweep whose sole authorization issuance this receipt permits.
    #[must_use]
    pub const fn sweep(&self) -> SweepId {
        self.sweep
    }

    /// Monotonic family attempt which must be closed in the protocol store before nonce release.
    #[must_use]
    pub const fn attempt_high_water(&self) -> u64 {
        self.attempt_high_water
    }
}

/// Persisted capability authorizing nonce creation for one exact signing intent.
#[derive(Debug, Eq, PartialEq)]
pub struct SweepSigningAuthorization {
    /// Authorized sweep attempt.
    sweep: SweepId,
    /// Exact monotonic family attempt authorized by the persisted worker snapshot.
    attempt: u64,
    /// Globally unique FROSTLASS session.
    session: SessionId,
    /// Exact session/committee/signer/group-key/transaction context to compare.
    signing_context: [u8; 32],
    /// Canonically sorted party IDs authorized for this attempt.
    signers: Vec<u16>,
    /// Untweaked root threshold group key.
    group_key: [u8; 32],
    /// Digest of the exact durable worker intent which a one-use protocol tombstone must bind.
    intent_digest: [u8; 32],
}

impl SweepSigningAuthorization {
    /// Authorized sweep attempt.
    #[must_use]
    pub const fn sweep(&self) -> SweepId {
        self.sweep
    }

    /// Exact monotonic family attempt authorized to create one nonce set.
    #[must_use]
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }

    /// Globally unique FROSTLASS session; it must be durably consumed exactly once by the host.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Exact session/committee/signer/group-key/transaction context.
    #[must_use]
    pub const fn signing_context(&self) -> [u8; 32] {
        self.signing_context
    }

    /// Canonically sorted party IDs authorized for this attempt.
    #[must_use]
    pub fn signers(&self) -> &[u16] {
        &self.signers
    }

    /// Untweaked root threshold group key.
    #[must_use]
    pub const fn group_key(&self) -> [u8; 32] {
        self.group_key
    }

    /// Exact durable intent digest for the host's one-use session tombstone.
    #[must_use]
    pub const fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }
}

/// Read-only permanent tombstone for a superseded signing session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SweepSigningSessionTombstone {
    /// Monotonic family attempt which consumed this session.
    pub attempt: u64,
    /// Session which must never be authorized again.
    pub session: SessionId,
    /// Exact retired worker-intent digest.
    pub intent_digest: [u8; 32],
}

/// Current and permanently retired sessions for one exact sweep.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SweepSigningAttemptStatus {
    /// Current intent's attempt number.
    pub current_attempt: u64,
    /// Highest attempt ever reserved for the family. This never decreases.
    pub attempt_high_water: u64,
    /// Current fresh signing session.
    pub current_session: SessionId,
    /// Current exact worker-intent digest.
    pub current_intent_digest: [u8; 32],
    /// Old sessions in supersession order.
    pub retired: Vec<SweepSigningSessionTombstone>,
}

/// Sealed proof that the encrypted worker deterministically reconstructed a certified attempt.
///
/// The portable consensus/service layer must authenticate the quorum certificate before asking the
/// worker to mint this value. It can authorize adoption of an already-completed candidate, but is
/// intentionally unrelated to [`SigningReleaseReceipt`] and can never authorize nonce creation.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedSweepSigningAttempt {
    sweep: SweepId,
    exact_attempt: AttemptBinding,
    reconstructed_intent: SweepSigningIntent,
}

impl VerifiedSweepSigningAttempt {
    #[must_use]
    pub const fn sweep(&self) -> SweepId {
        self.sweep
    }

    #[must_use]
    pub const fn attempt(&self) -> u64 {
        self.exact_attempt.attempt()
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.exact_attempt.session()
    }

    #[must_use]
    pub const fn intent_digest(&self) -> [u8; 32] {
        self.exact_attempt.worker_intent_digest()
    }

    pub(crate) fn exact_attempt(&self) -> &AttemptBinding {
        &self.exact_attempt
    }
}

/// Commitments produced from a non-serializable archive prefix-membership token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CertifiedLateSweepPrefixMembership {
    abandonment_certificate_digest: [u8; 32],
    attempt_prefix: RoastAttemptPrefixSeal,
    archive_membership_digest: [u8; 32],
    inclusion_certificate_digest: [u8; 32],
    inclusion: ChainPoint,
    observation_tip: ChainPoint,
    finality_depth: u32,
}

/// Sealed, non-serializable public terminal completion verified at the service/worker boundary.
///
/// This contains no private prepared intent and cannot be converted into a signing release. The
/// constructor binds the complete public authorization/plan/attempt graph, exact transaction
/// bytes and the key-image vector authenticated by completion consensus.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedPublicSweepCompletion {
    certificate_digest: [u8; 32],
    authorization: TransactionAuthorization,
    plan: SweepPlan,
    attempt: AttemptBinding,
    signed_binding: SignedTransactionBinding,
    key_images: Vec<[u8; 32]>,
    signed_transaction: SignedSweepTransaction,
    late_prefix_membership: Option<CertifiedLateSweepPrefixMembership>,
}

/// API-unforgeable result of a current-committee canonical inclusion certificate.
///
/// The service mints this only after verifying the canonical n-f certificate and reproducing the
/// observation from its local scanner/daemon view. It is intentionally non-serializable and has no
/// public constructor. The worker persists only its authenticated commitments beside the terminal
/// late-settlement record.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedCanonicalSweepInclusion {
    certificate_digest: [u8; 32],
    family: [u8; 32],
    transaction: [u8; 32],
    exact_bytes_digest: [u8; 32],
    attempt_prefix: RoastAttemptPrefixSeal,
    inclusion: ChainPoint,
    observation_tip: ChainPoint,
    finality_depth: u32,
}

impl VerifiedCanonicalSweepInclusion {
    /// Seal an already verified current-committee observation for worker admission.
    ///
    /// This constructor is crate-private so network or API callers cannot turn self-declared chain
    /// coordinates into settlement authority.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_current_committee_certificate(
        certificate_digest: [u8; 32],
        family: [u8; 32],
        transaction: [u8; 32],
        exact_bytes_digest: [u8; 32],
        attempt_prefix: RoastAttemptPrefixSeal,
        inclusion: ChainPoint,
        observation_tip: ChainPoint,
        finality_depth: u32,
    ) -> Result<Self, DepositWorkerError> {
        let expected_tip = inclusion
            .height
            .checked_add(u64::from(finality_depth))
            .ok_or(DepositWorkerError::InvalidCertifiedSweep)?;
        if certificate_digest == [0_u8; 32]
            || family == [0_u8; 32]
            || family != attempt_prefix.family()
            || transaction == [0_u8; 32]
            || exact_bytes_digest == [0_u8; 32]
            || attempt_prefix.family_anchor() == [0_u8; 32]
            || attempt_prefix.accumulator() == [0_u8; 32]
            || attempt_prefix.closed_through_view().checked_add(1)
                != Some(attempt_prefix.closed_through_attempt())
            || finality_depth == 0
            || ChainPoint::new(inclusion.height, inclusion.hash).is_err()
            || ChainPoint::new(observation_tip.height, observation_tip.hash).is_err()
            || observation_tip.height != expected_tip
            || observation_tip.height <= inclusion.height
        {
            return Err(DepositWorkerError::InvalidCertifiedSweep);
        }
        Ok(Self {
            certificate_digest,
            family,
            transaction,
            exact_bytes_digest,
            attempt_prefix,
            inclusion,
            observation_tip,
            finality_depth,
        })
    }
}

/// API-unforgeable authorization to settle an already abandoned coordinator family.
///
/// The worker mints this only after verifying both exact semantic-prefix membership in the
/// immutable ROAST archive and a current-committee canonical inclusion certificate. It is
/// deliberately non-serializable and non-cloneable: portable bytes must be reverified at the
/// worker boundary after every restart.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedArchivedSweepSettlement {
    sweep: SweepId,
    attempt: AttemptBinding,
    signed_binding: SignedTransactionBinding,
    transaction: [u8; 32],
    prefix: RoastAttemptPrefixSeal,
    archive_membership_digest: [u8; 32],
    inclusion_certificate_digest: [u8; 32],
    inclusion: ChainPoint,
}

impl VerifiedArchivedSweepSettlement {
    pub(crate) const fn sweep(&self) -> SweepId {
        self.sweep
    }

    pub(crate) const fn attempt(&self) -> &AttemptBinding {
        &self.attempt
    }

    pub(crate) const fn signed_binding(&self) -> SignedTransactionBinding {
        self.signed_binding
    }

    pub(crate) const fn transaction(&self) -> [u8; 32] {
        self.transaction
    }

    pub(crate) const fn prefix(&self) -> RoastAttemptPrefixSeal {
        self.prefix
    }

    pub(crate) const fn archive_membership_digest(&self) -> [u8; 32] {
        self.archive_membership_digest
    }

    pub(crate) const fn inclusion_certificate_digest(&self) -> [u8; 32] {
        self.inclusion_certificate_digest
    }

    pub(crate) const fn inclusion(&self) -> ChainPoint {
        self.inclusion
    }
}

/// Sealed public abandonment proof verified without reconstructing any private sweep intent.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedPublicSweepAbandonment {
    certificate_digest: [u8; 32],
    authorization: TransactionAuthorization,
    attempt_prefix: RoastAttemptPrefixSeal,
    attempt: AttemptBinding,
    sweep_sequence: u64,
    inputs: Vec<WalletOutputId>,
    key_images: Vec<[u8; 32]>,
    missing_inputs: Vec<WalletOutputId>,
    ancestor: ChainPoint,
    observation_tip: ChainPoint,
    finality_depth: u32,
}

/// Exact full same-family transaction observed in a canonical retained block.
///
/// This is durable reconciliation evidence, not a daemon-status assertion. It is emitted only
/// after full family/CLSAG/Bulletproof+/balance validation and exact scanner inclusion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SweepFamilySettlementEvidence {
    /// Sweep family whose pinned key images and prepared intent matched.
    pub sweep: SweepId,
    /// Exact canonical winner bytes.
    pub signed_transaction: SignedSweepTransaction,
    /// Canonical retained block containing the transaction.
    pub block: ChainPoint,
}

impl SweepFamilySettlementEvidence {
    /// Transaction ID derived from [`Self::signed_transaction`].
    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 32] {
        self.signed_transaction.transaction_id()
    }
}

/// Result of one bounded scanner iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerTick {
    /// Persistence required for a cursor, output, or rollback change.
    pub persistence: Option<WorkerPersistEffect>,
    /// Best height observed at the start of the tick.
    pub daemon_height: u64,
    /// Durable scanner tip after this tick.
    pub scanner_tip: ChainPoint,
    /// Whether this mutation staged an event batch which must be delivered after persistence.
    pub staged_events: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PendingDepositBlockScan {
    cursor: DepositBlockScanCursor,
    timestamp: u64,
    hardfork_version: u8,
    outputs: Vec<PersistedWalletOutput>,
    root_outputs: Vec<PersistedRootOutput>,
}

/// Durable, fixed-horizon historical scan required before a newer portable allocation view is
/// allowed to drive status or forward scanning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositAllocationBackfill {
    version: u16,
    portable_head: [u8; 32],
    through_sequence: u64,
    minimum_anchor: ChainPoint,
    anchor_authenticated: bool,
    next_height: u64,
    previous: ChainPoint,
    confirmed_horizon: ChainPoint,
    pending: Option<PendingDepositBlockScan>,
    held_points: Vec<ChainPoint>,
}

impl DepositAllocationBackfill {
    #[must_use]
    pub const fn portable_head(&self) -> [u8; 32] {
        self.portable_head
    }

    #[must_use]
    pub const fn through_sequence(&self) -> u64 {
        self.through_sequence
    }

    #[must_use]
    pub const fn minimum_anchor(&self) -> ChainPoint {
        self.minimum_anchor
    }

    #[must_use]
    pub const fn anchor_authenticated(&self) -> bool {
        self.anchor_authenticated
    }

    #[must_use]
    pub const fn next_height(&self) -> u64 {
        self.next_height
    }

    #[must_use]
    pub const fn confirmed_horizon(&self) -> ChainPoint {
        self.confirmed_horizon
    }
}

/// Exact certified transaction bytes retained until canonical inclusion passes the reorg fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertifiedSweepPublication {
    version: u16,
    certificate_digest: [u8; 32],
    portable_terminal_digest: [u8; 32],
    sweep: SweepId,
    inputs: Vec<WalletOutputId>,
    signed_transaction: SignedSweepTransaction,
    confirmation: Option<ChainPoint>,
}

impl CertifiedSweepPublication {
    #[must_use]
    pub const fn certificate_digest(&self) -> [u8; 32] {
        self.certificate_digest
    }

    #[must_use]
    pub const fn portable_terminal_digest(&self) -> [u8; 32] {
        self.portable_terminal_digest
    }

    #[must_use]
    pub const fn sweep(&self) -> SweepId {
        self.sweep
    }

    #[must_use]
    pub fn inputs(&self) -> &[WalletOutputId] {
        &self.inputs
    }

    #[must_use]
    pub const fn signed_transaction(&self) -> &SignedSweepTransaction {
        &self.signed_transaction
    }

    #[must_use]
    pub const fn confirmation(&self) -> Option<ChainPoint> {
        self.confirmation
    }
}

/// Non-serializable proof that an observation statement exactly matches this party's confirmed
/// authenticated scanner and the certified allocation it references.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedLocalDepositObservation {
    wallet: DepositWalletId,
    allocation_statement: [u8; 32],
    observation_statement: [u8; 32],
    output: WalletOutputId,
    verification_horizon: ChainPoint,
}

impl VerifiedLocalDepositObservation {
    #[cfg(test)]
    pub(crate) const fn for_test(
        wallet: DepositWalletId,
        allocation_statement: [u8; 32],
        observation_statement: [u8; 32],
        output: WalletOutputId,
        verification_horizon: ChainPoint,
    ) -> Self {
        Self { wallet, allocation_statement, observation_statement, output, verification_horizon }
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn allocation_statement(&self) -> [u8; 32] {
        self.allocation_statement
    }

    #[must_use]
    pub const fn observation_statement(&self) -> [u8; 32] {
        self.observation_statement
    }

    #[must_use]
    pub const fn output(&self) -> WalletOutputId {
        self.output
    }

    #[must_use]
    pub const fn verification_horizon(&self) -> ChainPoint {
        self.verification_horizon
    }
}

/// Durable scanner, resumable block progress, event outbox, and sweep attempt sequence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositWorkerState {
    version: u16,
    config: DepositWorkerConfig,
    revision: u64,
    scan: ScanState,
    next_sweep_sequence: u64,
    portable_index_head: Option<[u8; 32]>,
    portable_through_sequence: Option<u64>,
    allocation_backfill: Option<DepositAllocationBackfill>,
    pending_block_scan: Option<PendingDepositBlockScan>,
    certified_sweep_publications: BTreeMap<SweepId, CertifiedSweepPublication>,
    observed_family_settlements: BTreeMap<SweepId, SweepFamilySettlementEvidence>,
    pending_events: Option<WorkerEventBatch>,
}

impl DepositWorkerState {
    /// Create a worker at an externally trusted chain anchor.
    ///
    /// The initial state is revision zero and must be persisted before the worker is made live.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits or an invalid anchor.
    pub fn new(
        deriver: &DepositAddressDeriver,
        anchor: ChainPoint,
        config: DepositWorkerConfig,
    ) -> Result<Self, DepositWorkerError> {
        config.validate()?;
        let scan = ScanState::new(deriver, anchor)?;
        let state = Self {
            version: WORKER_STATE_VERSION,
            config,
            revision: 0,
            scan,
            next_sweep_sequence: 0,
            portable_index_head: None,
            portable_through_sequence: None,
            allocation_backfill: None,
            pending_block_scan: None,
            certified_sweep_publications: BTreeMap::new(),
            observed_family_settlements: BTreeMap::new(),
            pending_events: None,
        };
        state.validate(Some(deriver))?;
        Ok(state)
    }

    /// Return the stable threshold wallet domain.
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.scan.wallet_id()
    }

    /// Return the immutable deployment-wide wallet birth point.
    #[must_use]
    pub const fn birth_anchor(&self) -> ChainPoint {
        self.scan.birth_anchor()
    }

    /// Return the moving trusted checkpoint at the start of the retained reorg window.
    #[must_use]
    pub const fn reorg_checkpoint(&self) -> ChainPoint {
        self.scan.anchor()
    }

    /// Return the current state revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Next locally usable sweep-plan sequence.
    ///
    /// Local reservations advance this immediately. Portable certificates raise it to at least one
    /// past their authenticated plan sequence, allowing non-signers and future committee members to
    /// catch up without lowering a party which already burned later local sequences.
    #[must_use]
    pub const fn next_sweep_sequence(&self) -> u64 {
        self.next_sweep_sequence
    }

    /// Return the persisted finality/resource policy.
    #[must_use]
    pub const fn config(&self) -> DepositWorkerConfig {
        self.config
    }

    /// Read the durable scan/sweep journal.
    #[must_use]
    pub const fn scan_state(&self) -> &ScanState {
        &self.scan
    }

    /// Whether a bounded production block scan has durable continuation work.
    #[must_use]
    pub const fn has_pending_block_scan(&self) -> bool {
        self.pending_block_scan.is_some()
    }

    /// Authenticated portable head whose allocation history has been completely recognized.
    #[must_use]
    pub const fn portable_index_head(&self) -> Option<[u8; 32]> {
        self.portable_index_head
    }

    /// Certified ledger sequence represented by the recognized portable head.
    #[must_use]
    pub const fn portable_through_sequence(&self) -> Option<u64> {
        self.portable_through_sequence
    }

    /// Durable historical scan which currently gates allocation status and forward scanning.
    #[must_use]
    pub const fn allocation_backfill(&self) -> Option<&DepositAllocationBackfill> {
        self.allocation_backfill.as_ref()
    }

    /// Whether the current portable allocation view is safe to expose or use for expiry.
    #[must_use]
    pub const fn allocation_view_ready(&self) -> bool {
        self.portable_index_head.is_some()
            && self.portable_through_sequence.is_some()
            && self.allocation_backfill.is_none()
    }

    /// Initialize the empty portable view before this fresh worker advances beyond its birth
    /// anchor. Subsequent head changes require a verified index transition.
    ///
    /// Public because [`Self::new`] and [`Self::tick`] are public and `tick` fails closed with
    /// [`DepositWorkerError::PortableIndexHeadUninitialized`] until this bootstrap runs; external
    /// callers must be able to satisfy that precondition.
    pub fn initialize_portable_index_head(
        &mut self,
        portable_head: [u8; 32],
    ) -> Result<WorkerPersistEffect, DepositWorkerError> {
        self.require_no_pending_events()?;
        if portable_head == [0; 32]
            || self.portable_index_head.is_some()
            || self.allocation_backfill.is_some()
            || self.scan.tip() != self.scan.birth_anchor()
        {
            return Err(DepositWorkerError::InvalidPortableIndexTransition);
        }
        let mut candidate = self.clone();
        candidate.portable_index_head = Some(portable_head);
        candidate.portable_through_sequence = Some(0);
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(effect)
    }

    /// Adopt one semantically replayed portable-index transition.
    ///
    /// An allocation transition fixes a confirmed horizon and starts/rewinds a durable backfill
    /// from the minimum new recognition anchor. The new head is not reported ready until every
    /// historical output binding and event has been persisted.
    pub(crate) fn adopt_verified_portable_scanner_transition(
        &mut self,
        transition: &VerifiedPortableScannerTransition,
    ) -> Result<Option<WorkerPersistEffect>, DepositWorkerError> {
        self.require_no_pending_events()?;
        if transition.wallet_id() != self.wallet_id()
            || transition.resulting_head_digest() == [0; 32]
            || transition.expected_head_digest() == transition.resulting_head_digest()
        {
            return Err(DepositWorkerError::InvalidPortableIndexTransition);
        }
        let current_target = self
            .allocation_backfill
            .as_ref()
            .map_or(self.portable_index_head, |backfill| Some(backfill.portable_head));
        let current_sequence = self
            .allocation_backfill
            .as_ref()
            .map_or(self.portable_through_sequence, |backfill| Some(backfill.through_sequence));
        if current_target != Some(transition.expected_head_digest()) {
            return Err(DepositWorkerError::InvalidPortableIndexTransition);
        }
        if current_sequence.is_none_or(|sequence| transition.through_sequence() < sequence) {
            return Err(DepositWorkerError::InvalidPortableIndexTransition);
        }
        self.adopt_portable_scanner_target(
            transition.resulting_head_digest(),
            transition.through_sequence(),
            transition.allocation_anchors(),
            true,
        )
    }

    /// Adopt a complete imported portable graph whose exact head was authenticated by a verified
    /// n-f checkpoint.
    ///
    /// Unlike ordinary transition adoption, this path does not trust a peer-supplied journal. The
    /// snapshot token proves a semantic traversal of the entire graph and carries every allocation
    /// recognition anchor, so journal loss or fresh join always schedules the required historical
    /// rescan before the imported view becomes visible.
    pub(crate) fn adopt_verified_portable_scanner_snapshot(
        &mut self,
        snapshot: &VerifiedPortableScannerSnapshot,
    ) -> Result<Option<WorkerPersistEffect>, DepositWorkerError> {
        self.require_no_pending_events()?;
        if snapshot.wallet_id() != self.wallet_id() || snapshot.head_digest() == [0; 32] {
            return Err(DepositWorkerError::InvalidPortableIndexTransition);
        }
        let current_target = self
            .allocation_backfill
            .as_ref()
            .map_or(self.portable_index_head, |backfill| Some(backfill.portable_head));
        let current_sequence = self
            .allocation_backfill
            .as_ref()
            .map_or(self.portable_through_sequence, |backfill| Some(backfill.through_sequence));
        let Some(current_sequence) = current_sequence else {
            return Err(DepositWorkerError::PortableIndexHeadUninitialized);
        };
        if snapshot.through_sequence() < current_sequence
            || (snapshot.through_sequence() == current_sequence
                && current_target != Some(snapshot.head_digest()))
        {
            return Err(DepositWorkerError::InvalidPortableIndexTransition);
        }
        if current_target == Some(snapshot.head_digest())
            && current_sequence == snapshot.through_sequence()
        {
            return Ok(None);
        }
        self.adopt_portable_scanner_target(
            snapshot.head_digest(),
            snapshot.through_sequence(),
            snapshot.allocation_anchors(),
            false,
        )
    }

    fn adopt_portable_scanner_target(
        &mut self,
        resulting_head: [u8; 32],
        through_sequence: u64,
        allocation_anchors: &[ChainPoint],
        anchors_locally_authenticated: bool,
    ) -> Result<Option<WorkerPersistEffect>, DepositWorkerError> {
        let mut candidate = self.clone();
        candidate.pending_block_scan = None;
        if allocation_anchors.is_empty() {
            if let Some(backfill) = candidate.allocation_backfill.as_mut() {
                backfill.portable_head = resulting_head;
                backfill.through_sequence = through_sequence;
            } else {
                candidate.portable_index_head = Some(resulting_head);
                candidate.portable_through_sequence = Some(through_sequence);
            }
        } else {
            let mut anchors = allocation_anchors.to_vec();
            anchors.sort_unstable();
            anchors.dedup();
            if anchors_locally_authenticated {
                for anchor in &anchors {
                    candidate.scan.verify_recognition_anchor(*anchor)?;
                }
            }
            let supplied_minimum =
                *anchors.first().ok_or(DepositWorkerError::InvalidPortableIndexTransition)?;
            let previous_job = candidate.allocation_backfill.take();
            let minimum_anchor = previous_job
                .as_ref()
                .map_or(supplied_minimum, |job| job.minimum_anchor.min(supplied_minimum));
            let confirmed_horizon = candidate.scan.tip();
            let mut held_points =
                previous_job.as_ref().map_or_else(Vec::new, |job| job.held_points.clone());
            held_points.retain(|point| *point == minimum_anchor || *point == confirmed_horizon);
            let minimum_anchor_verified =
                candidate.scan.verify_recognition_anchor(minimum_anchor).is_ok();

            let anchor_authenticated = match candidate.scan.authenticated_historical_block_evidence(
                minimum_anchor,
                resulting_head,
                through_sequence,
            ) {
                Ok(evidence) => {
                    candidate.scan.pin_authenticated_historical_block(&evidence)?;
                    held_points.push(minimum_anchor);
                    true
                }
                Err(DepositWalletError::UnknownChainPoint(point))
                    if point == minimum_anchor && minimum_anchor_verified =>
                {
                    true
                }
                Err(DepositWalletError::UnknownChainPoint(point))
                    if point == minimum_anchor && !anchors_locally_authenticated =>
                {
                    false
                }
                Err(error) => return Err(error.into()),
            };
            match candidate.scan.authenticated_historical_block_evidence(
                confirmed_horizon,
                resulting_head,
                through_sequence,
            ) {
                Ok(evidence) => {
                    candidate.scan.pin_authenticated_historical_block(&evidence)?;
                    held_points.push(confirmed_horizon);
                }
                Err(DepositWalletError::UnknownChainPoint(point))
                    if point == confirmed_horizon
                        && candidate.scan.verify_recognition_anchor(point).is_ok() => {}
                Err(error) => return Err(error.into()),
            }
            held_points.sort_unstable();
            held_points.dedup();
            let next_height = if anchor_authenticated {
                minimum_anchor.height.checked_add(1).ok_or(DepositWorkerError::HeightOverflow)?
            } else {
                minimum_anchor.height
            };
            // Before authentication this hash is an expected block hash, not a parent claim.
            let previous = minimum_anchor;

            for point in previous_job
                .iter()
                .flat_map(|job| job.held_points.iter())
                .copied()
                .filter(|point| held_points.binary_search(point).is_err())
            {
                candidate.scan.release_authenticated_historical_block(point)?;
            }

            if next_height > confirmed_horizon.height {
                for point in held_points {
                    candidate.scan.release_authenticated_historical_block(point)?;
                }
                candidate.portable_index_head = Some(resulting_head);
                candidate.portable_through_sequence = Some(through_sequence);
                candidate.allocation_backfill = None;
            } else {
                candidate.allocation_backfill = Some(DepositAllocationBackfill {
                    version: ALLOCATION_BACKFILL_VERSION,
                    portable_head: resulting_head,
                    through_sequence,
                    minimum_anchor,
                    anchor_authenticated,
                    next_height,
                    previous,
                    confirmed_horizon,
                    pending: None,
                    held_points,
                });
            }
        }
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(Some(effect))
    }

    /// Recheck one proposed n-f observation against the exact local confirmed output.
    pub fn verify_local_deposit_observation(
        &self,
        allocation_record: &PortableAllocationRecord,
        observation: &DepositObservationStatement,
    ) -> Result<VerifiedLocalDepositObservation, DepositWorkerError> {
        let LedgerPayload::Allocation(allocation) = &allocation_record.statement().payload else {
            return Err(DepositWorkerError::InvalidDepositObservation);
        };
        verify_deposit_observation_against_scan(
            &self.scan,
            self.config.confirmation_depth,
            self.wallet_id(),
            allocation_record.statement().sequence,
            allocation_record.statement_digest(),
            allocation,
            observation,
        )
    }

    /// Exact certified publications which remain eligible for deterministic (re)broadcast.
    pub fn certified_sweep_publications(
        &self,
    ) -> impl ExactSizeIterator<Item = &CertifiedSweepPublication> {
        self.certified_sweep_publications.values()
    }

    #[must_use]
    pub fn certified_sweep_publication(
        &self,
        sweep: SweepId,
    ) -> Option<&CertifiedSweepPublication> {
        self.certified_sweep_publications.get(&sweep)
    }

    /// Pin canonical root-output inclusion for a retained certified publication.
    pub fn mark_certified_sweep_publication_confirmed(
        &mut self,
        sweep: SweepId,
        confirmation: ChainPoint,
    ) -> Result<Option<WorkerPersistEffect>, DepositWorkerError> {
        self.require_no_pending_events()?;
        let publication = self
            .certified_sweep_publications
            .get(&sweep)
            .ok_or(DepositWorkerError::UnknownCertifiedPublication)?
            .clone();
        if publication.confirmation.is_some_and(|known| known != confirmation) {
            return Err(DepositWorkerError::CertifiedSweepConflict);
        }
        let terminal = verified_portable_publication(&publication, self.wallet_id())?;
        let mut candidate = self.clone();
        let mut changed = candidate.scan.pin_verified_portable_terminal(&terminal, confirmation)?;
        let stored = candidate
            .certified_sweep_publications
            .get_mut(&sweep)
            .ok_or(DepositWorkerError::CorruptState)?;
        if stored.confirmation.is_none() {
            stored.confirmation = Some(confirmation);
            changed = true;
        }
        if !changed {
            return Ok(None);
        }
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(Some(effect))
    }

    /// Compact a certified completion only after its exact transaction is behind the moving
    /// reorganization fence. Until then its inputs, sweep, root witness, and exact bytes remain
    /// durable and eligible for rebroadcast.
    pub fn compact_certified_sweep_publication(
        &mut self,
        sweep: SweepId,
    ) -> Result<Option<WorkerPersistEffect>, DepositWorkerError> {
        self.require_no_pending_events()?;
        let publication = self
            .certified_sweep_publications
            .get(&sweep)
            .ok_or(DepositWorkerError::UnknownCertifiedPublication)?
            .clone();
        let confirmation =
            publication.confirmation.ok_or(DepositWorkerError::CertifiedPublicationUnconfirmed)?;
        let terminal = verified_portable_publication(&publication, self.wallet_id())?;
        let verified = self.scan.verify_terminal_compaction(&terminal, confirmation)?;
        let mut candidate = self.clone();
        let mut changed = candidate.scan.consume_verified_terminal_compaction(&verified)?;
        changed |= candidate.certified_sweep_publications.remove(&sweep).is_some();
        changed |= candidate.observed_family_settlements.remove(&sweep).is_some();
        if !changed {
            return Ok(None);
        }
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(Some(effect))
    }

    /// Verify the complete public proof graph for an externally quorum-certified completion.
    ///
    /// The caller must first authenticate the enclosing BA or ledger certificate and pass its
    /// digest plus the key-image vector authenticated by that evidence in canonical transaction
    /// input order. This method binds the full authorization, plan, exact attempt, exact bytes,
    /// fee policy, destination policy, root key, and key images into an API-unforgeable token. It
    /// is read-only and can never authorize nonce creation.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign wallet, malformed or inconsistent public proof graph,
    /// non-canonical transaction, unsupported transaction shape/fee, or a conflicting private
    /// local family.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_public_sweep_completion(
        &self,
        certificate_digest: [u8; 32],
        authorization: &TransactionAuthorization,
        plan: &SweepPlan,
        attempt: &AttemptBinding,
        signed_binding: SignedTransactionBinding,
        signed_transaction: &SignedSweepTransaction,
        certified_key_images: Vec<[u8; 32]>,
    ) -> Result<VerifiedPublicSweepCompletion, DepositWorkerError> {
        self.validate_public_sweep_completion(
            certificate_digest,
            authorization,
            plan,
            attempt,
            signed_binding,
            signed_transaction,
            &certified_key_images,
            None,
        )?;
        Ok(VerifiedPublicSweepCompletion {
            certificate_digest,
            authorization: authorization.clone(),
            plan: plan.clone(),
            attempt: attempt.clone(),
            signed_binding,
            key_images: certified_key_images,
            signed_transaction: signed_transaction.clone(),
            late_prefix_membership: None,
        })
    }

    /// Verify an older, fully archived completion which canonically settled an abandoned family.
    ///
    /// Neither a raw archive mapping nor a numeric `attempt <= high-water` comparison is accepted.
    /// `archived` proves exact semantic-prefix membership and full historical completion evidence;
    /// `inclusion` proves a current-committee n-f canonical observation at configured finality.
    /// Both types have private fields and no public constructor.
    ///
    /// # Errors
    ///
    /// Returns an error if either sealed proof belongs to another family/transaction, the durable
    /// abandonment differs, the plan/public proof graph is inconsistent, or local canonical
    /// scanner evidence contradicts the certified inclusion.
    pub fn verify_archived_prefix_sweep_completion(
        &self,
        certificate_digest: [u8; 32],
        plan: &SweepPlan,
        archived: VerifiedArchivedPrefixTransaction,
        inclusion: VerifiedCanonicalSweepInclusion,
        prior_abandonment: &PortableConsolidationTerminalRecord,
    ) -> Result<(VerifiedPublicSweepCompletion, VerifiedArchivedSweepSettlement), DepositWorkerError>
    {
        let prefix = archived.prefix_seal();
        let archive_membership_digest = archived.membership_digest();
        let record = archived.attempt_record();
        let mapping = archived.mapping();
        let authorization = record.intent().authorization();
        let attempt = record.intent().attempt();
        let signed_binding = mapping.signed_binding();
        let signed_transaction = mapping.signed_transaction();
        let transaction = signed_transaction.transaction_id();
        let inclusion_certificate_digest = inclusion.certificate_digest;
        let inclusion_point = inclusion.inclusion;
        let exact_bytes_digest = consolidation_signed_bytes_binding(signed_transaction.as_bytes());
        if inclusion.family != prefix.family()
            || inclusion.attempt_prefix != prefix
            || inclusion.transaction != transaction
            || inclusion.exact_bytes_digest != exact_bytes_digest
            || signed_binding.exact_bytes_digest() != exact_bytes_digest
            || inclusion.finality_depth != self.config.confirmation_depth
            || record.wallet_id() != self.wallet_id()
            || mapping.wallet_id() != self.wallet_id()
            || mapping.family() != prefix.family()
            || mapping.family_anchor() != prefix.family_anchor()
            || mapping.plan() != plan
            || mapping.attempt() != attempt.attempt()
            || mapping.view().checked_add(1) != Some(mapping.attempt())
        {
            return Err(DepositWorkerError::InvalidCertifiedSweep);
        }
        let PortableConsolidationStatus::Abandoned { evidence } = prior_abandonment.status() else {
            return Err(DepositWorkerError::CertifiedSweepConflict);
        };
        if prior_abandonment.wallet_id() != self.wallet_id()
            || prior_abandonment.consolidation_id() != authorization.id()
            || prior_abandonment.sweep_id() != authorization.sweep_id()
            || prior_abandonment.sweep_sequence() != plan.sequence
            || prior_abandonment.inputs() != plan.inputs.as_slice()
            || prior_abandonment.attempt_high_water() != prefix.closed_through_attempt()
            || evidence.attempt_prefix() != prefix
            || evidence.roast_family() != prefix.family()
            || evidence.terminal_attempt() != prefix.closed_through_attempt()
        {
            return Err(DepositWorkerError::CertifiedSweepConflict);
        }
        let late_prefix_membership = CertifiedLateSweepPrefixMembership {
            abandonment_certificate_digest: evidence.statement_digest(),
            attempt_prefix: prefix,
            archive_membership_digest,
            inclusion_certificate_digest: inclusion.certificate_digest,
            inclusion: inclusion.inclusion,
            observation_tip: inclusion.observation_tip,
            finality_depth: inclusion.finality_depth,
        };
        let certified_key_images = certified_sweep_key_images(signed_transaction)?;
        self.validate_public_sweep_completion(
            certificate_digest,
            authorization,
            plan,
            attempt,
            signed_binding,
            signed_transaction,
            &certified_key_images,
            Some(&late_prefix_membership),
        )?;
        Ok((
            VerifiedPublicSweepCompletion {
                certificate_digest,
                authorization: authorization.clone(),
                plan: plan.clone(),
                attempt: attempt.clone(),
                signed_binding,
                key_images: certified_key_images,
                signed_transaction: signed_transaction.clone(),
                late_prefix_membership: Some(late_prefix_membership),
            },
            VerifiedArchivedSweepSettlement {
                sweep: authorization.sweep_id(),
                attempt: attempt.clone(),
                signed_binding,
                transaction,
                prefix,
                archive_membership_digest,
                inclusion_certificate_digest,
                inclusion: inclusion_point,
            },
        ))
    }

    /// Consume a verified public completion whose terminal record was authenticated by the
    /// portable index.
    ///
    /// This transition is intended for portable history and late joiners. The authenticated index
    /// permanently owns terminal aliases, input claims, and session tombstones; the worker removes
    /// its duplicate full sweep/output state. Exact replay is a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if the sealed token no longer matches this worker, conflicts with local
    /// state, overlaps another permanent claim, or cannot be persisted.
    pub(crate) fn adopt_verified_public_sweep_completion(
        &mut self,
        completion: VerifiedPublicSweepCompletion,
        portable_terminal: &PortableConsolidationTerminalRecord,
    ) -> Result<Option<WorkerPersistEffect>, DepositWorkerError> {
        self.require_no_pending_events()?;
        self.validate_public_sweep_completion(
            completion.certificate_digest,
            &completion.authorization,
            &completion.plan,
            &completion.attempt,
            completion.signed_binding,
            &completion.signed_transaction,
            &completion.key_images,
            completion.late_prefix_membership.as_ref(),
        )?;
        self.validate_portable_completion_terminal(&completion, portable_terminal)?;
        let sweep = completion.authorization.sweep_id();
        let certified_next = completion
            .plan
            .sequence
            .checked_add(1)
            .ok_or(DepositWorkerError::SweepSequenceExhausted)?;
        self.scan.validate_certified_local_sweep(
            sweep,
            &completion.plan.inputs,
            &completion.signed_transaction,
        )?;
        if self.scan.sweep(sweep).is_some() {
            validate_sweep_family_candidate(&self.scan, sweep, &completion.signed_transaction)?;
        }
        for input in &completion.plan.inputs {
            if self.scan.active_sweep_claiming(*input).is_some_and(|claim| claim != sweep) {
                return Err(DepositWorkerError::CertifiedSweepConflict);
            }
        }

        let mut candidate = self.clone();
        let publication = CertifiedSweepPublication {
            version: CERTIFIED_SWEEP_PUBLICATION_VERSION,
            certificate_digest: completion.certificate_digest,
            portable_terminal_digest: portable_terminal.digest(),
            sweep,
            inputs: completion.plan.inputs.clone(),
            signed_transaction: completion.signed_transaction.clone(),
            confirmation: candidate
                .scan
                .root_transaction_chain_point(completion.signed_transaction.transaction_id()),
        };
        let mut changed = match candidate.certified_sweep_publications.get_mut(&sweep) {
            Some(existing)
                if existing.version == publication.version
                    && existing.certificate_digest == publication.certificate_digest
                    && existing.portable_terminal_digest
                        == publication.portable_terminal_digest
                    && existing.sweep == publication.sweep
                    && existing.inputs == publication.inputs
                    && existing.signed_transaction == publication.signed_transaction =>
            {
                match (existing.confirmation, publication.confirmation) {
                    (None, Some(confirmation)) => {
                        existing.confirmation = Some(confirmation);
                        true
                    }
                    (Some(found), Some(candidate)) if found != candidate => {
                        return Err(DepositWorkerError::CertifiedSweepConflict);
                    }
                    _ => false,
                }
            }
            Some(_) => return Err(DepositWorkerError::CertifiedSweepConflict),
            None => {
                if candidate.certified_sweep_publications.len() == MAX_CERTIFIED_SWEEP_PUBLICATIONS
                {
                    return Err(DepositWorkerError::CertifiedPublicationCapacity);
                }
                candidate.certified_sweep_publications.insert(sweep, publication);
                true
            }
        };
        if let Some(confirmation) = candidate
            .certified_sweep_publications
            .get(&sweep)
            .and_then(CertifiedSweepPublication::confirmation)
        {
            let publication = candidate
                .certified_sweep_publications
                .get(&sweep)
                .ok_or(DepositWorkerError::CorruptState)?;
            let terminal = verified_portable_publication(publication, candidate.wallet_id())?;
            changed |= candidate.scan.pin_verified_portable_terminal(&terminal, confirmation)?;
        }
        changed |= candidate.next_sweep_sequence < certified_next;
        candidate.next_sweep_sequence = candidate.next_sweep_sequence.max(certified_next);
        if !changed {
            return Ok(None);
        }
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(Some(effect))
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_public_sweep_completion(
        &self,
        certificate_digest: [u8; 32],
        authorization: &TransactionAuthorization,
        plan: &SweepPlan,
        attempt: &AttemptBinding,
        signed_binding: SignedTransactionBinding,
        signed_transaction: &SignedSweepTransaction,
        certified_key_images: &[[u8; 32]],
        late_prefix_membership: Option<&CertifiedLateSweepPrefixMembership>,
    ) -> Result<(), DepositWorkerError> {
        authorization.validate().map_err(|_| DepositWorkerError::InvalidCertifiedSweep)?;
        attempt.validate().map_err(|_| DepositWorkerError::InvalidCertifiedSweep)?;
        signed_binding.validate().map_err(|_| DepositWorkerError::InvalidCertifiedSweep)?;
        let input_count = u32::try_from(plan.inputs.len())
            .map_err(|_| DepositWorkerError::InvalidCertifiedSweep)?;
        if authorization.wallet_id() != self.wallet_id() || plan.wallet != self.wallet_id() {
            return Err(DepositWorkerError::WrongWalletDomain);
        }
        if certificate_digest == [0_u8; 32]
            || plan.id.0 == [0_u8; 32]
            || plan.id.0 != sweep_plan_commitment(plan)
            || plan.destination_binding == [0_u8; 32]
            || plan.inputs.is_empty()
            || plan.inputs.len() > usize::from(self.config.max_sweep_inputs)
            || plan.inputs.windows(2).any(|window| window[0] >= window[1])
            || plan.inputs.iter().any(|input| input.transaction == [0_u8; 32])
            || ChainPoint::new(plan.at_tip.height, plan.at_tip.hash).is_err()
            || authorization.sweep_id() != plan.id
            || authorization.input_set() != consolidation_input_set_binding(&plan.inputs)
            || authorization.destination_policy() != plan.destination_binding
            || authorization.root_group_key() != self.scan.root_spend_key()
            || authorization.input_count() != input_count
            || authorization.total_input_atomic_units() != plan.total_input_atomic_units
            || authorization.maximum_fee_atomic_units() != self.config.maximum_fee_atomic_units
            || attempt.epoch() != plan.epoch
            || attempt.root_group_key() != authorization.root_group_key()
            || derive_sweep_signing_session(plan.wallet, plan.id, attempt.attempt())
                != Some(attempt.session())
            || signed_binding.authorization_digest() != authorization.digest()
            || signed_binding.attempt() != attempt.attempt()
            || signed_binding.attempt_binding_digest() != attempt.digest()
            || signed_binding.session() != attempt.session()
            || signed_binding.signing_context() != attempt.signing_context()
            || signed_binding.opaque_intent() != authorization.opaque_intent()
            || !signed_binding_matches_certified_bytes(signed_binding, signed_transaction)
        {
            return Err(DepositWorkerError::InvalidCertifiedSweep);
        }
        let canonical = SignedSweepTransaction::from_bytes(
            signed_transaction.as_bytes().to_vec(),
            Some(signed_binding.transaction()),
        )?;
        if canonical != *signed_transaction {
            return Err(DepositWorkerError::InvalidCertifiedSweep);
        }
        validate_certified_sweep_transaction(
            signed_transaction,
            plan.inputs.len(),
            self.config.maximum_fee_atomic_units,
        )?;
        if certified_sweep_fee(signed_transaction)? != authorization.fee_atomic_units()
            || certified_key_images != certified_sweep_key_images(signed_transaction)?
        {
            return Err(DepositWorkerError::InvalidCertifiedSweep);
        }
        self.scan.validate_certified_local_sweep(plan.id, &plan.inputs, signed_transaction)?;
        if self.scan.sweep(plan.id).is_some() {
            validate_sweep_family_candidate(&self.scan, plan.id, signed_transaction)?;
        }
        if let Some(membership) = late_prefix_membership {
            if membership.abandonment_certificate_digest == [0_u8; 32]
                || certificate_digest == membership.abandonment_certificate_digest
                || membership.archive_membership_digest == [0_u8; 32]
                || membership.inclusion_certificate_digest == [0_u8; 32]
                || membership.finality_depth != self.config.confirmation_depth
                || membership.inclusion.height.checked_add(u64::from(membership.finality_depth))
                    != Some(membership.observation_tip.height)
                || ChainPoint::new(membership.inclusion.height, membership.inclusion.hash).is_err()
                || ChainPoint::new(
                    membership.observation_tip.height,
                    membership.observation_tip.hash,
                )
                .is_err()
                || self
                    .scan
                    .root_transaction_chain_point(signed_transaction.transaction_id())
                    .is_some_and(|point| point != membership.inclusion)
                || attempt.attempt() > membership.attempt_prefix.closed_through_attempt()
                || attempt
                    .attempt()
                    .checked_sub(1)
                    .is_none_or(|view| view > membership.attempt_prefix.closed_through_view())
            {
                return Err(DepositWorkerError::CertifiedSweepConflict);
            }
        }
        Ok(())
    }

    fn validate_portable_completion_terminal(
        &self,
        completion: &VerifiedPublicSweepCompletion,
        terminal: &PortableConsolidationTerminalRecord,
    ) -> Result<(), DepositWorkerError> {
        let expected_high_water = completion.late_prefix_membership.as_ref().map_or_else(
            || completion.attempt.attempt(),
            |membership| membership.attempt_prefix.closed_through_attempt(),
        );
        if terminal.wallet_id() != self.wallet_id()
            || terminal.consolidation_id() != completion.authorization.id()
            || terminal.sweep_id() != completion.authorization.sweep_id()
            || terminal.sweep_sequence() != completion.plan.sequence
            || terminal.inputs() != completion.plan.inputs.as_slice()
            || terminal.attempt_high_water() != expected_high_water
        {
            return Err(DepositWorkerError::CertifiedSweepConflict);
        }
        match (completion.late_prefix_membership.as_ref(), terminal.status()) {
            (
                None,
                PortableConsolidationStatus::Completed {
                    statement_digest,
                    attempt,
                    session,
                    transaction,
                    ..
                },
            ) if *statement_digest == completion.certificate_digest
                && *attempt == completion.attempt.attempt()
                && *session == completion.attempt.session()
                && *transaction == completion.signed_transaction.transaction_id() =>
            {
                Ok(())
            }
            (
                Some(membership),
                PortableConsolidationStatus::LateSettled {
                    settlement_digest,
                    historical_attempt,
                    historical_session,
                    transaction,
                    abandonment,
                    ..
                },
            ) if *settlement_digest == completion.certificate_digest
                && *historical_attempt == completion.attempt.attempt()
                && *historical_session == completion.attempt.session()
                && *transaction == completion.signed_transaction.transaction_id()
                && abandonment.statement_digest() == membership.abandonment_certificate_digest
                && abandonment.attempt_prefix() == membership.attempt_prefix
                && abandonment.roast_family() == membership.attempt_prefix.family()
                && abandonment.terminal_attempt()
                    == membership.attempt_prefix.closed_through_attempt() =>
            {
                Ok(())
            }
            _ => Err(DepositWorkerError::CertifiedSweepConflict),
        }
    }

    /// Verify a self-contained quorum-certified abandonment without private sweep material.
    ///
    /// `certified_key_images` must be the exact vector authenticated by the all-selected
    /// key-image certificate, in the same order as `inputs`. The resulting token is terminal-only:
    /// it cannot be converted to a release receipt or signing authorization.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_public_sweep_abandonment(
        &self,
        certificate_digest: [u8; 32],
        authorization: &TransactionAuthorization,
        attempt_prefix: RoastAttemptPrefixSeal,
        attempt: &AttemptBinding,
        sweep_sequence: u64,
        inputs: Vec<WalletOutputId>,
        certified_key_images: Vec<[u8; 32]>,
        missing_inputs: Vec<WalletOutputId>,
        ancestor: ChainPoint,
        observation_tip: ChainPoint,
        finality_depth: u32,
    ) -> Result<VerifiedPublicSweepAbandonment, DepositWorkerError> {
        self.validate_public_sweep_abandonment(
            certificate_digest,
            authorization,
            attempt_prefix,
            attempt,
            sweep_sequence,
            &inputs,
            &certified_key_images,
            &missing_inputs,
            ancestor,
            observation_tip,
            finality_depth,
        )?;
        Ok(VerifiedPublicSweepAbandonment {
            certificate_digest,
            authorization: authorization.clone(),
            attempt_prefix,
            attempt: attempt.clone(),
            sweep_sequence,
            inputs,
            key_images: certified_key_images,
            missing_inputs,
            ancestor,
            observation_tip,
            finality_depth,
        })
    }

    /// Consume a verified public abandonment whose terminal record was authenticated by the
    /// portable index.
    ///
    /// This advances only public allocation and attempt floors. It does not create a private
    /// `SweepRecord`, a nonce release, or a replacement-spend path.
    pub(crate) fn adopt_verified_public_sweep_abandonment(
        &mut self,
        abandonment: VerifiedPublicSweepAbandonment,
        portable_terminal: &PortableConsolidationTerminalRecord,
    ) -> Result<Option<WorkerPersistEffect>, DepositWorkerError> {
        self.require_no_pending_events()?;
        self.validate_public_sweep_abandonment(
            abandonment.certificate_digest,
            &abandonment.authorization,
            abandonment.attempt_prefix,
            &abandonment.attempt,
            abandonment.sweep_sequence,
            &abandonment.inputs,
            &abandonment.key_images,
            &abandonment.missing_inputs,
            abandonment.ancestor,
            abandonment.observation_tip,
            abandonment.finality_depth,
        )?;
        self.validate_portable_abandonment_terminal(&abandonment, portable_terminal)?;
        let sweep = abandonment.authorization.sweep_id();
        let certified_next = abandonment
            .sweep_sequence
            .checked_add(1)
            .ok_or(DepositWorkerError::SweepSequenceExhausted)?;
        if self.observed_family_settlements.contains_key(&sweep) {
            return Err(DepositWorkerError::CertifiedSweepConflict);
        }
        for input in &abandonment.inputs {
            if self.scan.active_sweep_claiming(*input).is_some_and(|claim| claim != sweep) {
                return Err(DepositWorkerError::CertifiedSweepConflict);
            }
        }

        let mut candidate = self.clone();
        // An abandonment has no canonical transaction inclusion fence. Retain the local family,
        // inputs, key images, and nonce tombstones permanently; only advance the public sequence
        // floor authenticated by the portable terminal.
        let changed = candidate.next_sweep_sequence < certified_next;
        candidate.next_sweep_sequence = candidate.next_sweep_sequence.max(certified_next);
        if !changed {
            return Ok(None);
        }
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(Some(effect))
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_public_sweep_abandonment(
        &self,
        certificate_digest: [u8; 32],
        authorization: &TransactionAuthorization,
        attempt_prefix: RoastAttemptPrefixSeal,
        attempt: &AttemptBinding,
        sweep_sequence: u64,
        inputs: &[WalletOutputId],
        certified_key_images: &[[u8; 32]],
        missing_inputs: &[WalletOutputId],
        ancestor: ChainPoint,
        observation_tip: ChainPoint,
        finality_depth: u32,
    ) -> Result<(), DepositWorkerError> {
        authorization.validate().map_err(|_| DepositWorkerError::InvalidCertifiedSweep)?;
        attempt.validate().map_err(|_| DepositWorkerError::InvalidCertifiedSweep)?;
        let input_count =
            u32::try_from(inputs.len()).map_err(|_| DepositWorkerError::InvalidCertifiedSweep)?;
        let expected_tip_height = ancestor
            .height
            .checked_add(u64::from(finality_depth))
            .ok_or(DepositWorkerError::InvalidCertifiedSweep)?;
        if authorization.wallet_id() != self.wallet_id() {
            return Err(DepositWorkerError::WrongWalletDomain);
        }
        if certificate_digest == [0_u8; 32]
            || attempt_prefix.family() == [0_u8; 32]
            || attempt_prefix.family_anchor() == [0_u8; 32]
            || attempt_prefix.accumulator() == [0_u8; 32]
            || attempt_prefix.closed_through_attempt() != attempt.attempt()
            || attempt_prefix.closed_through_view().checked_add(1)
                != Some(attempt_prefix.closed_through_attempt())
            || sweep_sequence == u64::MAX
            || authorization.input_set() != consolidation_input_set_binding(inputs)
            || authorization.input_count() != input_count
            || authorization.root_group_key() != self.scan.root_spend_key()
            || authorization.maximum_fee_atomic_units() != self.config.maximum_fee_atomic_units
            || attempt.root_group_key() != authorization.root_group_key()
            || derive_sweep_signing_session(
                authorization.wallet_id(),
                authorization.sweep_id(),
                attempt.attempt(),
            ) != Some(attempt.session())
            || inputs.is_empty()
            || inputs.len() > usize::from(self.config.max_sweep_inputs)
            || inputs.windows(2).any(|window| window[0] >= window[1])
            || inputs.iter().any(|input| input.transaction == [0_u8; 32])
            || certified_key_images.len() != inputs.len()
            || certified_key_images.iter().any(|image| *image == [0_u8; 32])
            || certified_key_images.iter().copied().collect::<BTreeSet<_>>().len()
                != certified_key_images.len()
            || missing_inputs.is_empty()
            || missing_inputs.windows(2).any(|window| window[0] >= window[1])
            || missing_inputs.iter().any(|input| inputs.binary_search(input).is_err())
            || finality_depth == 0
            || finality_depth != self.config.confirmation_depth
            || ChainPoint::new(ancestor.height, ancestor.hash).is_err()
            || ChainPoint::new(observation_tip.height, observation_tip.hash).is_err()
            || observation_tip.height != expected_tip_height
        {
            return Err(DepositWorkerError::InvalidCertifiedSweep);
        }
        if let Some(local) = self.scan.sweep(authorization.sweep_id()) {
            if local.inputs != inputs
                || local.family_key_images.as_ref().is_some_and(|binding| {
                    binding.inputs() != inputs || binding.key_images() != certified_key_images
                })
            {
                return Err(DepositWorkerError::CertifiedSweepConflict);
            }
        }
        Ok(())
    }

    fn validate_portable_abandonment_terminal(
        &self,
        abandonment: &VerifiedPublicSweepAbandonment,
        terminal: &PortableConsolidationTerminalRecord,
    ) -> Result<(), DepositWorkerError> {
        if terminal.wallet_id() != self.wallet_id()
            || terminal.consolidation_id() != abandonment.authorization.id()
            || terminal.sweep_id() != abandonment.authorization.sweep_id()
            || terminal.sweep_sequence() != abandonment.sweep_sequence
            || terminal.inputs() != abandonment.inputs.as_slice()
            || terminal.attempt_high_water() != abandonment.attempt_prefix.closed_through_attempt()
        {
            return Err(DepositWorkerError::CertifiedSweepConflict);
        }
        let PortableConsolidationStatus::Abandoned { evidence } = terminal.status() else {
            return Err(DepositWorkerError::CertifiedSweepConflict);
        };
        if evidence.statement_digest() != abandonment.certificate_digest
            || evidence.roast_family() != abandonment.attempt_prefix.family()
            || evidence.attempt_prefix() != abandonment.attempt_prefix
            || evidence.terminal_attempt() != abandonment.attempt.attempt()
            || evidence.terminal_session() != abandonment.attempt.session()
        {
            return Err(DepositWorkerError::CertifiedSweepConflict);
        }
        Ok(())
    }

    /// Advance at most one fixed-horizon allocation-backfill block.
    ///
    /// Every discovered output is first atomically bound in the local burning-bug/first-use
    /// index. Only then are authenticated historical outputs and the durable frontier persisted.
    /// Deferred scanner chunks retain the exact portable head and cursor, so restart cannot mix
    /// allocation views.
    pub async fn tick_allocation_backfill<S: DepositChainSource + ?Sized>(
        &mut self,
        source: &S,
        deriver: &DepositAddressDeriver,
        output_index: &dyn DepositOutputIndexBackend,
    ) -> Result<WorkerTick, DepositWorkerError> {
        self.validate(Some(deriver))?;
        self.require_no_pending_events()?;
        let backfill = self
            .allocation_backfill
            .as_ref()
            .ok_or(DepositWorkerError::AllocationBackfillNotPending)?
            .clone();
        let request_timeout = self.config.request_timeout();
        let daemon_height =
            request(request_timeout, "latest height", None, source.latest_height()).await?;
        if daemon_height < backfill.confirmed_horizon.height {
            return Err(DepositWorkerError::DaemonBehindState {
                daemon: daemon_height,
                state: backfill.confirmed_horizon.height,
            });
        }
        let horizon_hash = request(
            request_timeout,
            "allocation backfill horizon hash",
            Some(backfill.confirmed_horizon.height),
            source.block_hash(backfill.confirmed_horizon.height),
        )
        .await?;
        if horizon_hash != backfill.confirmed_horizon.hash {
            let Some(ancestor) = self.find_reorg_ancestor(source, request_timeout).await? else {
                return Err(DepositWorkerError::AllocationBackfillBranchChanged);
            };
            let mut candidate = self.clone();
            let report = candidate.scan.rollback_to(ancestor)?;
            candidate
                .observed_family_settlements
                .retain(|_, evidence| evidence.block.height <= ancestor.height);
            for publication in candidate.certified_sweep_publications.values_mut() {
                if publication
                    .confirmation
                    .is_some_and(|confirmation| confirmation.height > ancestor.height)
                {
                    publication.confirmation = None;
                }
            }
            candidate.pending_block_scan = None;
            let (portable_head, through_sequence, minimum_anchor, anchor_authenticated) = {
                let progress = candidate
                    .allocation_backfill
                    .as_ref()
                    .ok_or(DepositWorkerError::CorruptState)?;
                (
                    progress.portable_head,
                    progress.through_sequence,
                    progress.minimum_anchor,
                    progress.anchor_authenticated,
                )
            };
            if ancestor.height < minimum_anchor.height {
                return Err(DepositWorkerError::AllocationBackfillBranchChanged);
            }
            let ancestor_evidence = candidate.scan.authenticated_historical_block_evidence(
                ancestor,
                portable_head,
                through_sequence,
            )?;
            candidate.scan.pin_authenticated_historical_block(&ancestor_evidence)?;
            let complete = {
                let progress = candidate
                    .allocation_backfill
                    .as_mut()
                    .ok_or(DepositWorkerError::CorruptState)?;
                progress.confirmed_horizon = ancestor;
                progress.pending = None;
                progress.held_points.retain(|point| point.height <= ancestor.height);
                progress.held_points.push(ancestor);
                progress.held_points.sort_unstable();
                progress.held_points.dedup();
                anchor_authenticated && progress.next_height > ancestor.height
            };
            if complete {
                let completed =
                    candidate.allocation_backfill.take().ok_or(DepositWorkerError::CorruptState)?;
                for point in completed.held_points {
                    candidate.scan.release_authenticated_historical_block(point)?;
                }
                candidate.portable_index_head = Some(completed.portable_head);
                candidate.portable_through_sequence = Some(completed.through_sequence);
            }
            let rollback = DepositRollback::from_report(ancestor, report, &self.scan)?;
            candidate.stage_events(Vec::new(), Some(rollback))?;
            let effect = candidate.finish_mutation()?;
            let scanner_tip = candidate.scan.tip();
            *self = candidate;
            return Ok(WorkerTick {
                persistence: Some(effect),
                daemon_height,
                scanner_tip,
                staged_events: true,
            });
        }
        let portable_snapshot = request(
            request_timeout,
            "portable deposit-index snapshot",
            Some(backfill.next_height),
            output_index.portable_snapshot(self.wallet_id()),
        )
        .await?;
        if portable_snapshot != backfill.portable_head {
            return Err(DepositWorkerError::PortableIndexHeadChanged);
        }

        let height = backfill.next_height;
        if height > backfill.confirmed_horizon.height {
            return Err(DepositWorkerError::CorruptState);
        }
        let canonical_hash = request(
            request_timeout,
            "allocation backfill block hash",
            Some(height),
            source.block_hash(height),
        )
        .await?;
        let resume = backfill.pending.as_ref().map(|progress| progress.cursor);
        let scan_result = request(
            request_timeout,
            "allocation backfill expanded block",
            Some(height),
            source.scanned_block_evidence(height, deriver, output_index, portable_snapshot, resume),
        )
        .await?;
        let (mut evidence, binding_chunk) = match scan_result {
            DepositBlockScanResult::Complete(mut evidence) => {
                validate_fetched_block_shape(self.config, &evidence.block, height)?;
                validate_fetched_output_chunk(self.scan.root_spend_key(), &evidence.block)?;
                let binding_chunk = output_bindings(&evidence.block)?;
                if let Some(progress) = &backfill.pending {
                    if progress.cursor.block != evidence.block.block
                        || progress.timestamp != evidence.block.timestamp
                        || progress.hardfork_version != evidence.block.hardfork_version
                        || progress.cursor.portable_snapshot != portable_snapshot
                    {
                        return Err(DepositWorkerError::CorruptState);
                    }
                    merge_wallet_output_chunks(
                        &mut evidence.block.outputs,
                        progress.outputs.clone(),
                    )?;
                    merge_root_output_chunks(
                        &mut evidence.block.root_outputs,
                        progress.root_outputs.clone(),
                    )?;
                }
                (evidence, binding_chunk)
            }
            DepositBlockScanResult::Deferred { block, next_cursor } => {
                validate_fetched_block_shape(self.config, &block, height)?;
                validate_fetched_output_chunk(self.scan.root_spend_key(), &block)?;
                if next_cursor.block != block.block
                    || next_cursor.portable_snapshot != portable_snapshot
                    || block.block.point.hash != canonical_hash
                    || if backfill.anchor_authenticated {
                        block.block.parent_hash != backfill.previous.hash
                    } else {
                        block.block.point != backfill.minimum_anchor
                    }
                {
                    return Err(DepositWorkerError::AllocationBackfillBranchChanged);
                }
                let binding_chunk = output_bindings(&block)?;
                if !binding_chunk.is_empty() {
                    bind_local_outputs(output_index.bind_outputs(
                        self.wallet_id(),
                        portable_snapshot,
                        &binding_chunk,
                    ))
                    .await?;
                }
                let mut progress = backfill.pending.clone().unwrap_or(PendingDepositBlockScan {
                    cursor: next_cursor,
                    timestamp: block.timestamp,
                    hardfork_version: block.hardfork_version,
                    outputs: Vec::new(),
                    root_outputs: Vec::new(),
                });
                if progress.cursor.block != block.block
                    || progress.timestamp != block.timestamp
                    || progress.hardfork_version != block.hardfork_version
                    || progress.cursor.portable_snapshot != portable_snapshot
                {
                    return Err(DepositWorkerError::CorruptState);
                }
                merge_wallet_output_chunks(&mut progress.outputs, block.outputs)?;
                merge_root_output_chunks(&mut progress.root_outputs, block.root_outputs)?;
                if progress
                    .outputs
                    .len()
                    .checked_add(progress.root_outputs.len())
                    .is_none_or(|count| count > usize::from(self.config.max_outputs_per_block))
                {
                    return Err(DepositWorkerError::TooManyWalletOutputs {
                        actual: progress.outputs.len().saturating_add(progress.root_outputs.len()),
                        maximum: self.config.max_outputs_per_block,
                    });
                }
                progress.cursor = next_cursor;
                let mut candidate = self.clone();
                candidate
                    .allocation_backfill
                    .as_mut()
                    .ok_or(DepositWorkerError::CorruptState)?
                    .pending = Some(progress);
                let effect = candidate.finish_mutation()?;
                let scanner_tip = candidate.scan.tip();
                *self = candidate;
                return Ok(WorkerTick {
                    persistence: Some(effect),
                    daemon_height,
                    scanner_tip,
                    staged_events: false,
                });
            }
        };
        evidence.block.outputs.sort_unstable_by_key(PersistedWalletOutput::id);
        evidence.block.root_outputs.sort_unstable_by_key(PersistedRootOutput::id);
        if evidence.block.block.point.hash != canonical_hash
            || if backfill.anchor_authenticated {
                evidence.block.block.parent_hash != backfill.previous.hash
            } else {
                evidence.block.block.point != backfill.minimum_anchor
            }
            || evidence.block.outputs.windows(2).any(|window| window[0].id() >= window[1].id())
            || evidence.block.root_outputs.windows(2).any(|window| window[0].id() >= window[1].id())
        {
            return Err(DepositWorkerError::AllocationBackfillBranchChanged);
        }
        if !binding_chunk.is_empty() {
            bind_local_outputs(output_index.bind_outputs(
                self.wallet_id(),
                portable_snapshot,
                &binding_chunk,
            ))
            .await?;
        }

        let block = evidence.block;
        let historical = AuthenticatedHistoricalBlockEvidence::from_authenticated_chain_source(
            self.wallet_id(),
            block.block,
            block.timestamp,
            backfill.confirmed_horizon,
            portable_snapshot,
            backfill.through_sequence,
            block.outputs.clone(),
            block.root_outputs.clone(),
        )?;
        let mut candidate = self.clone();
        candidate.scan.pin_authenticated_historical_block(&historical)?;
        candidate.scan.insert_authenticated_historical_outputs(&historical)?;
        if backfill.anchor_authenticated {
            if backfill.held_points.binary_search(&block.block.point).is_err() {
                candidate.scan.release_authenticated_historical_block(block.block.point)?;
            }
        }

        let detections = block
            .outputs
            .iter()
            .map(|output| {
                let wallet_output = output.wallet_output()?;
                Ok(DepositDetection {
                    output: output.id(),
                    index_on_blockchain: output.index_on_blockchain(),
                    subaddress: output.subaddress(),
                    amount_atomic_units: wallet_output.commitment().amount,
                    observed_block: block.block.point,
                    block_timestamp: block.timestamp,
                })
            })
            .collect::<Result<Vec<_>, DepositWorkerError>>()?;
        let next_height = height.checked_add(1).ok_or(DepositWorkerError::HeightOverflow)?;
        {
            let progress =
                candidate.allocation_backfill.as_mut().ok_or(DepositWorkerError::CorruptState)?;
            if !progress.anchor_authenticated {
                if block.block.point != progress.minimum_anchor {
                    return Err(DepositWorkerError::AllocationBackfillBranchChanged);
                }
                progress.anchor_authenticated = true;
                progress.held_points.push(block.block.point);
                progress.held_points.sort_unstable();
                progress.held_points.dedup();
            }
            progress.previous = block.block.point;
            progress.next_height = next_height;
            progress.pending = None;
        }
        let completed = next_height > backfill.confirmed_horizon.height;
        if completed {
            let completed_job =
                candidate.allocation_backfill.take().ok_or(DepositWorkerError::CorruptState)?;
            if completed_job.previous != completed_job.confirmed_horizon {
                return Err(DepositWorkerError::AllocationBackfillBranchChanged);
            }
            for point in completed_job.held_points {
                candidate.scan.release_authenticated_historical_block(point)?;
            }
            candidate.portable_index_head = Some(completed_job.portable_head);
            candidate.portable_through_sequence = Some(completed_job.through_sequence);
        }
        if !detections.is_empty() {
            candidate.stage_events(detections, None)?;
        }
        let effect = candidate.finish_mutation()?;
        let scanner_tip = candidate.scan.tip();
        let staged_events = candidate.pending_events.is_some();
        *self = candidate;
        Ok(WorkerTick { persistence: Some(effect), daemon_height, scanner_tip, staged_events })
    }

    /// Scan a bounded confirmed prefix or durably stage one reorganization rollback.
    ///
    /// If a retained tip is no longer canonical, this tick performs only the rollback. A later
    /// tick scans the replacement branch. This ensures a temporary replacement-block RPC failure
    /// cannot delay persistence of the retraction.
    ///
    /// # Errors
    ///
    /// Returns an error without changing `self` for RPC failures, discontinuities, bounds, an
    /// over-deep reorg, or a pending event batch.
    #[allow(clippy::too_many_lines)]
    pub async fn tick<S: DepositChainSource + ?Sized>(
        &mut self,
        source: &S,
        deriver: &DepositAddressDeriver,
        output_index: &dyn DepositOutputIndexBackend,
    ) -> Result<WorkerTick, DepositWorkerError> {
        self.validate(Some(deriver))?;
        self.require_no_pending_events()?;
        if self.allocation_backfill.is_some() {
            return Err(DepositWorkerError::AllocationBackfillRequired);
        }
        let expected_portable_head =
            self.portable_index_head.ok_or(DepositWorkerError::PortableIndexHeadUninitialized)?;
        let request_timeout = self.config.request_timeout();
        let daemon_height =
            request(request_timeout, "latest height", None, source.latest_height()).await?;
        if daemon_height < self.scan.anchor().height {
            return Err(DepositWorkerError::DaemonBehindAnchor {
                daemon: daemon_height,
                anchor: self.scan.anchor().height,
            });
        }
        if daemon_height < self.scan.tip().height {
            return Err(DepositWorkerError::DaemonBehindState {
                daemon: daemon_height,
                state: self.scan.tip().height,
            });
        }

        if let Some(ancestor) = self.find_reorg_ancestor(source, request_timeout).await? {
            let mut candidate = self.clone();
            let report = candidate.scan.rollback_to(ancestor)?;
            candidate
                .observed_family_settlements
                .retain(|_, evidence| evidence.block.height <= ancestor.height);
            for publication in candidate.certified_sweep_publications.values_mut() {
                if publication
                    .confirmation
                    .is_some_and(|confirmation| confirmation.height > ancestor.height)
                {
                    publication.confirmation = None;
                }
            }
            candidate.pending_block_scan = None;
            let rollback = DepositRollback::from_report(ancestor, report, &self.scan)?;
            candidate.stage_events(Vec::new(), Some(rollback))?;
            let effect = candidate.finish_mutation()?;
            let scanner_tip = candidate.scan.tip();
            *self = candidate;
            return Ok(WorkerTick {
                persistence: Some(effect),
                daemon_height,
                scanner_tip,
                staged_events: true,
            });
        }

        let chain_length =
            daemon_height.checked_add(1).ok_or(DepositWorkerError::HeightOverflow)?;
        let Some(confirmed_height) =
            chain_length.checked_sub(u64::from(self.config.confirmation_depth))
        else {
            return Ok(WorkerTick {
                persistence: None,
                daemon_height,
                scanner_tip: self.scan.tip(),
                staged_events: false,
            });
        };
        let next_height = self.scan.next_height()?;
        if confirmed_height < next_height {
            return Ok(WorkerTick {
                persistence: None,
                daemon_height,
                scanner_tip: self.scan.tip(),
                staged_events: false,
            });
        }
        let last_height = if self.pending_block_scan.is_some() {
            next_height
        } else {
            confirmed_height.min(
                next_height
                    .checked_add(u64::from(self.config.max_blocks_per_tick) - 1)
                    .ok_or(DepositWorkerError::HeightOverflow)?,
            )
        };
        let portable_snapshot = request(
            request_timeout,
            "portable deposit-index snapshot",
            Some(next_height),
            output_index.portable_snapshot(self.wallet_id()),
        )
        .await?;
        if portable_snapshot != expected_portable_head {
            return Err(DepositWorkerError::PortableIndexHeadChanged);
        }
        if let Some(progress) = &self.pending_block_scan {
            let canonical_hash = request(
                request_timeout,
                "resumable block hash",
                Some(next_height),
                source.block_hash(next_height),
            )
            .await?;
            if progress.cursor.block.point.height != next_height
                || progress.cursor.block.point.hash != canonical_hash
                || progress.cursor.portable_snapshot != portable_snapshot
            {
                let mut candidate = self.clone();
                candidate.pending_block_scan = None;
                let effect = candidate.finish_mutation()?;
                let scanner_tip = candidate.scan.tip();
                *self = candidate;
                return Ok(WorkerTick {
                    persistence: Some(effect),
                    daemon_height,
                    scanner_tip,
                    staged_events: false,
                });
            }
        }
        let pinned_families = self
            .scan
            .sweeps()
            .filter_map(|record| {
                record.family_key_images.as_ref().map(|binding| {
                    (record.id, binding.key_images().iter().copied().collect::<BTreeSet<_>>())
                })
            })
            .collect::<Vec<_>>();

        let mut fetched = Vec::with_capacity(
            usize::try_from(last_height - next_height + 1)
                .map_err(|_| DepositWorkerError::HeightOverflow)?,
        );
        for height in next_height..=last_height {
            let resume = self
                .pending_block_scan
                .as_ref()
                .filter(|progress| progress.cursor.block.point.height == height)
                .map(|progress| progress.cursor);
            let scan_result = request(
                request_timeout,
                "expanded block",
                Some(height),
                source.scanned_block_evidence(
                    height,
                    deriver,
                    output_index,
                    portable_snapshot,
                    resume,
                ),
            )
            .await?;
            let (mut evidence, binding_chunk) = match scan_result {
                DepositBlockScanResult::Complete(mut evidence) => {
                    validate_fetched_block_shape(self.config, &evidence.block, height)?;
                    validate_fetched_output_chunk(self.scan.root_spend_key(), &evidence.block)?;
                    let binding_chunk = output_bindings(&evidence.block)?;
                    if let Some(progress) = &self.pending_block_scan {
                        if progress.cursor.block != evidence.block.block
                            || progress.timestamp != evidence.block.timestamp
                            || progress.hardfork_version != evidence.block.hardfork_version
                        {
                            return Err(DepositWorkerError::CorruptState);
                        }
                        merge_wallet_output_chunks(
                            &mut evidence.block.outputs,
                            progress.outputs.clone(),
                        )?;
                        merge_root_output_chunks(
                            &mut evidence.block.root_outputs,
                            progress.root_outputs.clone(),
                        )?;
                    }
                    (evidence, binding_chunk)
                }
                DepositBlockScanResult::Deferred { block, next_cursor } => {
                    validate_fetched_block_shape(self.config, &block, height)?;
                    validate_fetched_output_chunk(self.scan.root_spend_key(), &block)?;
                    if next_cursor.block != block.block
                        || next_cursor.portable_snapshot != portable_snapshot
                    {
                        return Err(DepositWorkerError::CorruptState);
                    }
                    let binding_chunk = output_bindings(&block)?;
                    let mut progress = match &self.pending_block_scan {
                        Some(existing) => {
                            if existing.cursor.block != block.block
                                || existing.timestamp != block.timestamp
                                || existing.hardfork_version != block.hardfork_version
                            {
                                return Err(DepositWorkerError::CorruptState);
                            }
                            existing.clone()
                        }
                        None => PendingDepositBlockScan {
                            cursor: next_cursor,
                            timestamp: block.timestamp,
                            hardfork_version: block.hardfork_version,
                            outputs: Vec::new(),
                            root_outputs: Vec::new(),
                        },
                    };
                    merge_wallet_output_chunks(&mut progress.outputs, block.outputs)?;
                    merge_root_output_chunks(&mut progress.root_outputs, block.root_outputs)?;
                    let pending_count = progress
                        .outputs
                        .len()
                        .checked_add(progress.root_outputs.len())
                        .ok_or(DepositWorkerError::CorruptState)?;
                    if pending_count > usize::from(self.config.max_outputs_per_block) {
                        return Err(DepositWorkerError::TooManyWalletOutputs {
                            actual: pending_count,
                            maximum: self.config.max_outputs_per_block,
                        });
                    }
                    progress.cursor = next_cursor;
                    if !binding_chunk.is_empty() {
                        bind_local_outputs(output_index.bind_outputs(
                            self.wallet_id(),
                            portable_snapshot,
                            &binding_chunk,
                        ))
                        .await?;
                    }
                    let mut candidate = self.clone();
                    candidate.pending_block_scan = Some(progress);
                    let effect = candidate.finish_mutation()?;
                    let scanner_tip = candidate.scan.tip();
                    *self = candidate;
                    return Ok(WorkerTick {
                        persistence: Some(effect),
                        daemon_height,
                        scanner_tip,
                        staged_events: false,
                    });
                }
            };
            evidence.block.outputs.sort_unstable_by_key(PersistedWalletOutput::id);
            evidence.block.root_outputs.sort_unstable_by_key(PersistedRootOutput::id);
            if evidence.block.outputs.windows(2).any(|window| window[0].id() >= window[1].id())
                || evidence
                    .block
                    .root_outputs
                    .windows(2)
                    .any(|window| window[0].id() >= window[1].id())
                || evidence.block.outputs.iter().any(|output| {
                    evidence
                        .block
                        .root_outputs
                        .binary_search_by_key(&output.id(), PersistedRootOutput::id)
                        .is_ok()
                })
            {
                return Err(DepositWorkerError::CorruptState);
            }
            let block = &evidence.block;
            validate_fetched_block_shape(self.config, block, height)?;
            if !pinned_families.is_empty() && !evidence.transaction_key_images_complete {
                return Err(DepositWorkerError::IncompleteSweepFamilyChainEvidence(height));
            }
            if evidence.transaction_key_images.len() > MAX_TRANSACTIONS_PER_BLOCK
                || evidence.transactions.len() > MAX_TRANSACTIONS_PER_BLOCK
            {
                return Err(DepositWorkerError::InvalidSweepFamilyChainEvidence);
            }
            let mut summarized_transactions = BTreeSet::new();
            let mut summarized_bytes = 0_usize;
            for summary in &evidence.transaction_key_images {
                summarized_bytes = summarized_bytes
                    .checked_add(size_of::<[u8; 32]>())
                    .and_then(|bytes| {
                        summary
                            .key_images
                            .len()
                            .checked_mul(size_of::<[u8; 32]>())
                            .and_then(|images| bytes.checked_add(images))
                    })
                    .ok_or(DepositWorkerError::InvalidSweepFamilyChainEvidence)?;
                let observed = summary.key_images.iter().copied().collect::<BTreeSet<_>>();
                if !summarized_transactions.insert(summary.transaction)
                    || summary.key_images.is_empty()
                    || observed.len() != summary.key_images.len()
                    || summarized_bytes > MAX_EXPANDED_BLOCK_BYTES
                {
                    return Err(DepositWorkerError::InvalidSweepFamilyChainEvidence);
                }
                for (sweep, expected) in &pinned_families {
                    if observed.is_disjoint(expected) {
                        continue;
                    }
                    if &observed != expected {
                        return Err(DepositWorkerError::SweepFamilySpendConflict(*sweep));
                    }
                }
            }
            let root_transactions = block
                .root_outputs
                .iter()
                .map(|output| output.id().transaction)
                .collect::<BTreeSet<_>>();
            for transaction in root_transactions {
                if evidence
                    .transactions
                    .iter()
                    .any(|candidate| candidate.transaction_id() == transaction)
                {
                    continue;
                }
                if let Some(candidate) = request(
                    request_timeout,
                    "full transaction for consolidation settlement",
                    Some(height),
                    source.full_transaction(transaction),
                )
                .await?
                {
                    if candidate.transaction_id() != transaction {
                        return Err(DepositWorkerError::InvalidSweepFamilyChainEvidence);
                    }
                    evidence.transactions.push(candidate);
                } else if !pinned_families.is_empty() {
                    return Err(DepositWorkerError::SweepFamilyTransactionBytesUnavailable {
                        transaction,
                        height,
                    });
                }
            }
            for summary in &evidence.transaction_key_images {
                let observed = summary.key_images.iter().copied().collect::<BTreeSet<_>>();
                if !pinned_families.iter().any(|(_, expected)| !observed.is_disjoint(expected)) {
                    continue;
                }
                if evidence
                    .transactions
                    .iter()
                    .any(|candidate| candidate.transaction_id() == summary.transaction)
                {
                    continue;
                }
                let Some(candidate) = request(
                    request_timeout,
                    "full transaction for pinned sweep-family spend",
                    Some(height),
                    source.full_transaction(summary.transaction),
                )
                .await?
                else {
                    return Err(DepositWorkerError::SweepFamilyTransactionBytesUnavailable {
                        transaction: summary.transaction,
                        height,
                    });
                };
                if candidate.transaction_id() != summary.transaction {
                    return Err(DepositWorkerError::InvalidSweepFamilyChainEvidence);
                }
                evidence.transactions.push(candidate);
            }
            evidence.transactions.sort_unstable_by_key(SignedSweepTransaction::transaction_id);
            let transaction_evidence_bytes = evidence
                .transactions
                .iter()
                .try_fold(0_usize, |sum, transaction| sum.checked_add(transaction.as_bytes().len()))
                .ok_or(DepositWorkerError::InvalidSweepFamilyCandidate)?;
            if transaction_evidence_bytes > MAX_EXPANDED_BLOCK_BYTES
                || evidence
                    .transactions
                    .windows(2)
                    .any(|window| window[0].transaction_id() == window[1].transaction_id())
            {
                return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
            }
            if evidence.transaction_key_images_complete {
                for candidate in &evidence.transactions {
                    let transaction = candidate
                        .transaction()
                        .map_err(|_| DepositWorkerError::InvalidSweepFamilyChainEvidence)?;
                    let Some(key_images) = transaction_key_images(&transaction) else {
                        continue;
                    };
                    if !evidence.transaction_key_images.iter().any(|summary| {
                        summary.transaction == candidate.transaction_id()
                            && summary.key_images == key_images
                    }) {
                        return Err(DepositWorkerError::InvalidSweepFamilyChainEvidence);
                    }
                }
            }
            if !binding_chunk.is_empty() {
                bind_local_outputs(output_index.bind_outputs(
                    self.wallet_id(),
                    portable_snapshot,
                    &binding_chunk,
                ))
                .await?;
            }
            fetched.push(evidence);
        }

        let mut candidate = self.clone();
        candidate.pending_block_scan = None;
        let mut detections = Vec::new();
        for fetched_evidence in fetched {
            let fetched_block = fetched_evidence.block;
            let mut outputs = fetched_block.outputs;
            let mut root_outputs = fetched_block.root_outputs;
            outputs.sort_unstable_by_key(PersistedWalletOutput::id);
            root_outputs.sort_unstable_by_key(PersistedRootOutput::id);
            for output in &outputs {
                let wallet_output = output.wallet_output()?;
                detections.push(DepositDetection {
                    output: output.id(),
                    index_on_blockchain: output.index_on_blockchain(),
                    subaddress: output.subaddress(),
                    amount_atomic_units: wallet_output.commitment().amount,
                    observed_block: fetched_block.block.point,
                    block_timestamp: fetched_block.timestamp,
                });
            }
            candidate.scan.append_block_with_root(
                fetched_block.block,
                fetched_block.timestamp,
                outputs,
                root_outputs,
            )?;
            candidate.observe_sweep_family_transactions(
                fetched_block.block.point,
                &fetched_evidence.transactions,
            )?;
        }
        candidate.scan.compact_reorg_window(candidate.config.max_reorg_depth)?;
        let retained_outputs = candidate.scan.retained_output_count();
        if retained_outputs
            > usize::try_from(candidate.config.max_retained_outputs)
                .map_err(|_| DepositWorkerError::CorruptState)?
        {
            return Err(DepositWorkerError::RetentionCapacityExceeded {
                retained: retained_outputs,
                maximum: candidate.config.max_retained_outputs,
            });
        }
        if !detections.is_empty() {
            candidate.stage_events(detections, None)?;
        }
        let staged_events = candidate.pending_events.is_some();
        let effect = candidate.finish_mutation()?;
        let scanner_tip = candidate.scan.tip();
        *self = candidate;
        Ok(WorkerTick { persistence: Some(effect), daemon_height, scanner_tip, staged_events })
    }

    /// Release the staged batch after the exact state effect was durably stored.
    ///
    /// This does not clear the batch. Apply it idempotently, call [`Self::acknowledge_events`],
    /// then persist the returned clearing effect. A crash before that second save replays the same
    /// batch.
    ///
    /// # Errors
    ///
    /// Returns an error if the supplied effect/revision does not name the current exact state.
    pub fn events_after_persist(
        &self,
        effect: WorkerPersistEffect,
        persisted_revision: u64,
    ) -> Result<Option<WorkerEventBatch>, DepositWorkerError> {
        self.verify_effect(effect, persisted_revision)?;
        Ok(self.pending_events.clone())
    }

    /// Validate and replay an event batch restored from an authenticated durable snapshot.
    ///
    /// A host must apply and durably acknowledge this batch before calling [`Self::tick`] after a
    /// restart. The owned return value prevents later state mutation from changing what is applied.
    ///
    /// # Errors
    ///
    /// Returns an error if any durable worker or event invariant is invalid.
    pub fn replay_pending_events(&self) -> Result<Option<WorkerEventBatch>, DepositWorkerError> {
        self.validate(None)?;
        Ok(self.pending_events.clone())
    }

    /// Clear an idempotently applied event batch and return the required persistence effect.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong batch ID or revision exhaustion.
    pub fn acknowledge_events(
        &mut self,
        batch_id: [u8; 32],
    ) -> Result<WorkerPersistEffect, DepositWorkerError> {
        let pending = self.pending_events.as_ref().ok_or(DepositWorkerError::NoPendingEvents)?;
        if pending.id != batch_id {
            return Err(DepositWorkerError::WrongEventBatch);
        }
        let mut candidate = self.clone();
        candidate.pending_events = None;
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(effect)
    }

    /// Deterministically select mature, unclaimed deposit outputs for consolidation.
    ///
    /// Standard outputs must have Monero's full default ten-block lock window in the retained
    /// confirmed journal. Additional block/time locks are evaluated from the exact authenticated
    /// scanner tip and its retained deterministic timestamp window. The returned plan is stable
    /// until it is reserved or its chain is reorganized.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid destination binding, pending event delivery, malformed
    /// output data, amount overflow, or an exhausted attempt sequence.
    pub fn plan_sweep(
        &self,
        epoch: u64,
        destination_binding: [u8; 32],
    ) -> Result<Option<SweepPlan>, DepositWorkerError> {
        self.require_no_pending_events()?;
        if !self.allocation_view_ready() {
            return Err(DepositWorkerError::AllocationBackfillRequired);
        }
        if destination_binding == [0_u8; 32] {
            return Err(DepositWorkerError::InvalidDestinationBinding);
        }
        if self.next_sweep_sequence == u64::MAX {
            return Err(DepositWorkerError::SweepSequenceExhausted);
        }
        let tip = self.scan.tip();
        let mut candidates = Vec::<(u64, WalletOutputId)>::new();
        for output in self.scan.available_outputs() {
            let Some(inclusion) = self.scan.output_chain_point(output.id()) else {
                return Err(DepositWorkerError::CorruptState);
            };
            let confirmations = tip.height.saturating_sub(inclusion.height).saturating_add(1);
            if confirmations
                < u64::try_from(DEFAULT_LOCK_WINDOW)
                    .map_err(|_| DepositWorkerError::HeightOverflow)?
            {
                continue;
            }
            let wallet_output = output.wallet_output()?;
            if !self.scan.additional_timelock_satisfied(wallet_output.additional_timelock()) {
                continue;
            }
            candidates.push((wallet_output.commitment().amount, output.id()));
        }
        // Select the maximum-value bounded set, then restore canonical input-ID order. This
        // prevents an early prefix of dust from indefinitely hiding a later profitable output.
        candidates.sort_unstable_by(|(left_amount, left_id), (right_amount, right_id)| {
            right_amount.cmp(left_amount).then_with(|| left_id.cmp(right_id))
        });
        candidates.truncate(usize::from(self.config.max_sweep_inputs));
        let total = candidates.iter().try_fold(0_u64, |sum, (amount, _)| {
            sum.checked_add(*amount).ok_or(DepositWorkerError::AmountOverflow)
        })?;
        let mut inputs = candidates.into_iter().map(|(_, id)| id).collect::<Vec<_>>();
        inputs.sort_unstable();
        if inputs.is_empty() || total < self.config.minimum_sweep_atomic_units {
            return Ok(None);
        }
        let mut plan = SweepPlan {
            id: SweepId([0_u8; 32]),
            wallet: self.wallet_id(),
            sequence: self.next_sweep_sequence,
            epoch,
            destination_binding,
            at_tip: tip,
            inputs,
            total_input_atomic_units: total,
        };
        plan.id = SweepId(sweep_plan_commitment(&plan));
        Ok(Some(plan))
    }

    /// Independently reconstruct a leader-proposed root-only BP+ sweep before reservation.
    ///
    /// Every exact decoy input is decoded canonically and checked against this party's durable
    /// scanner output/key offset. The method then reconstructs `SignableTransaction::new` using
    /// the fixed one-atomic-unit payment plus primary change policy and verifies fee and
    /// transaction commitments. A follower must call this method; accepting a serialized
    /// [`SweepSigningIntent`] directly is not a trusted protocol boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/foreign plan, malformed decoys/fee rate, scanner mismatch,
    /// wrong destination policy, fee-policy violation, or commitment mismatch.
    pub fn verify_prepared_sweep_intent(
        &self,
        deriver: &DepositAddressDeriver,
        intent: &PreparedSweepIntent,
    ) -> Result<PreparedFrostlassSweep, DepositWorkerError> {
        self.require_no_pending_events()?;
        self.validate_plan(&intent.plan)?;
        self.reconstruct_prepared_sweep_intent(deriver, intent)
    }

    /// Verify a remote leader's prepared intent against an authenticated portable sequence floor.
    ///
    /// Unlike [`Self::verify_prepared_sweep_intent`], this follower-only path deliberately does
    /// not require equality with the party-local allocator. Local reservations may have burned
    /// sequences which are absent on a newly joined member, while the new leader may likewise be
    /// behind an old member. Callers must derive `authenticated_minimum` from certified ledger
    /// history; it is a lower bound, not an authorization for the leader's chosen forward jump.
    pub(crate) fn verify_prepared_sweep_intent_at_or_above(
        &self,
        deriver: &DepositAddressDeriver,
        intent: &PreparedSweepIntent,
        authenticated_minimum: u64,
    ) -> Result<PreparedFrostlassSweep, DepositWorkerError> {
        self.require_no_pending_events()?;
        self.validate_plan_at_or_above(&intent.plan, authenticated_minimum)?;
        self.reconstruct_prepared_sweep_intent(deriver, intent)
    }

    /// Reconstruct and validate the exact private sweep retained in a durable reservation.
    ///
    /// This restart path deliberately does not require the inputs to be "available": this sweep
    /// itself owns their durable claims. It re-decodes the canonical prepared bytes, verifies every
    /// decoy against scanner state, reconstructs the transaction, and compares the complete stored
    /// signable encoding and commitment before returning anything usable by the host.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown/non-startable sweep, missing/reorganized input, or any
    /// mismatch between durable prepared bytes and the signing reservation.
    pub fn reconstruct_reserved_sweep(
        &self,
        deriver: &DepositAddressDeriver,
        id: SweepId,
    ) -> Result<PreparedFrostlassSweep, DepositWorkerError> {
        self.validate(Some(deriver))?;
        let record = self.scan.sweep(id).ok_or(DepositWalletError::UnknownSweep(id))?;
        if !matches!(record.status, SweepStatus::Reserved | SweepStatus::SigningReleased) {
            return Err(DepositWalletError::InvalidSweepTransition.into());
        }
        let intent =
            PreparedSweepIntent::decode(record.signing_intent.prepared_sweep_intent_bytes())?;
        if intent.plan.id != id || intent.plan.inputs != record.inputs {
            return Err(DepositWorkerError::InvalidPreparedSweep);
        }
        let prepared = self.reconstruct_prepared_sweep_intent(deriver, &intent)?;
        if prepared.transaction.serialize()
            != record.signing_intent.signable_transaction()?.serialize()
            || prepared.transaction_commitment() != record.signing_intent.transaction_commitment()
            || prepared.fee_atomic_units() != record.signing_intent.fee_atomic_units()
        {
            return Err(DepositWorkerError::InvalidPreparedSweep);
        }
        Ok(prepared)
    }

    /// Return a fully revalidated canonical prepared intent for QUIC Start replay after restart.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::reconstruct_reserved_sweep`].
    pub fn prepared_sweep_intent_for_restart(
        &self,
        deriver: &DepositAddressDeriver,
        id: SweepId,
    ) -> Result<PreparedSweepIntent, DepositWorkerError> {
        Ok(self.reconstruct_reserved_sweep(deriver, id)?.prepared_intent.clone())
    }

    fn reconstruct_prepared_sweep_intent(
        &self,
        deriver: &DepositAddressDeriver,
        intent: &PreparedSweepIntent,
    ) -> Result<PreparedFrostlassSweep, DepositWorkerError> {
        intent.validate_structure()?;
        if self.wallet_id() != deriver.wallet_id() {
            return Err(DepositWorkerError::WrongWalletDomain);
        }
        if intent.plan.destination_binding
            != root_consolidation_destination_binding(deriver, self.config)
        {
            return Err(DepositWorkerError::DestinationPolicyMismatch);
        }
        let mut inputs = Vec::with_capacity(intent.decoy_inputs.len());
        for (id, bytes) in intent.plan.inputs.iter().zip(&intent.decoy_inputs) {
            let persisted = self.scan.output(*id).ok_or(DepositWorkerError::StaleSweepPlan)?;
            let input = decode_decoy_input(bytes)?;
            persisted.verify_decoy_input(&input)?;
            inputs.push(input);
        }
        let fee_rate = decode_fee_rate(&intent.fee_rate)?;
        let primary = MoneroAddress::from_str(
            address_network(self.scan.network()),
            &deriver.primary_address(),
        )
        .map_err(|error| DepositWorkerError::Address(error.to_string()))?;
        let transaction = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            Zeroizing::new(intent.outgoing_view_key),
            inputs,
            vec![(primary, 1)],
            deriver.primary_change(),
            vec![],
            fee_rate,
        )?;
        let fee_atomic_units = transaction.necessary_fee();
        let transaction_commitment = transaction_commitment(&intent.plan, &transaction);
        if fee_atomic_units != intent.fee_atomic_units
            || fee_atomic_units > self.config.maximum_fee_atomic_units
            || transaction_commitment != intent.transaction_commitment
        {
            return Err(DepositWorkerError::InvalidPreparedSweep);
        }
        Ok(PreparedFrostlassSweep {
            plan: intent.plan.clone(),
            transaction,
            transaction_commitment,
            fee_atomic_units,
            prepared_intent: intent.clone(),
        })
    }

    /// Build the canonical sensitive intent from locally obtained decoys and fee policy.
    ///
    /// This is the trusted constructor used by leaders and tests. It verifies each decoy against
    /// the locally scanned output before creating the root-only BP+ transaction. The outgoing-view
    /// seed must be unique private randomness and the returned representation must only travel on
    /// the authenticated encrypted party channel.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale plan, foreign wallet, invalid destination, decoy mismatch,
    /// zero outgoing seed, transaction construction failure, or excessive fee.
    pub fn prepare_sweep_from_components(
        &self,
        deriver: &DepositAddressDeriver,
        plan: &SweepPlan,
        outgoing_view_key: [u8; 32],
        inputs: Vec<OutputWithDecoys>,
        fee_rate: FeeRate,
    ) -> Result<PreparedFrostlassSweep, DepositWorkerError> {
        self.require_no_pending_events()?;
        self.validate_plan(plan)?;
        if self.wallet_id() != deriver.wallet_id() {
            return Err(DepositWorkerError::WrongWalletDomain);
        }
        if plan.destination_binding != root_consolidation_destination_binding(deriver, self.config)
        {
            return Err(DepositWorkerError::DestinationPolicyMismatch);
        }
        if outgoing_view_key == [0_u8; 32] || inputs.len() != plan.inputs.len() {
            return Err(DepositWorkerError::InvalidPreparedSweep);
        }
        for (id, input) in plan.inputs.iter().zip(&inputs) {
            self.scan
                .output(*id)
                .ok_or(DepositWorkerError::StaleSweepPlan)?
                .verify_decoy_input(input)?;
        }
        let decoy_inputs = inputs.iter().map(OutputWithDecoys::serialize).collect::<Vec<_>>();
        let fee_rate_bytes = fee_rate.serialize();
        let primary = MoneroAddress::from_str(
            address_network(self.scan.network()),
            &deriver.primary_address(),
        )
        .map_err(|error| DepositWorkerError::Address(error.to_string()))?;
        let transaction = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            Zeroizing::new(outgoing_view_key),
            inputs,
            vec![(primary, 1)],
            deriver.primary_change(),
            vec![],
            fee_rate,
        )?;
        let fee_atomic_units = transaction.necessary_fee();
        if fee_atomic_units > self.config.maximum_fee_atomic_units {
            return Err(DepositWorkerError::FeeAbovePolicy {
                actual: fee_atomic_units,
                maximum: self.config.maximum_fee_atomic_units,
            });
        }
        let transaction_commitment = transaction_commitment(plan, &transaction);
        let prepared_intent = PreparedSweepIntent {
            version: PREPARED_SWEEP_INTENT_VERSION,
            plan: plan.clone(),
            outgoing_view_key,
            decoy_inputs,
            fee_rate: fee_rate_bytes,
            transaction_commitment,
            fee_atomic_units,
        };
        prepared_intent.validate_structure()?;
        Ok(PreparedFrostlassSweep {
            plan: plan.clone(),
            transaction,
            transaction_commitment,
            fee_atomic_units,
            prepared_intent,
        })
    }

    /// Reserve an exact prepared transaction against its committee/signers-bound FROSTLASS
    /// context.
    ///
    /// This method computes the session-bound signing context itself and verifies the epoch and
    /// root group key. Persist the returned effect before any signer creates a nonce. Signers must
    /// use the returned context and the same session.
    ///
    /// # Errors
    ///
    /// Returns an error for stale plans, a zero context, claimed inputs, pending events, or
    /// revision/sequence exhaustion.
    pub(crate) fn prepared_signing_binding(
        &self,
        prepared: &PreparedFrostlassSweep,
        committee: &Committee,
        signers: &CanonicalSignerSet,
        expected_group_key: [u8; 32],
        session: SessionId,
    ) -> Result<([u8; 32], [u8; 32]), DepositWorkerError> {
        committee
            .validate()
            .map_err(|error| DepositWorkerError::InvalidSigningCommittee(error.to_string()))?;
        if committee.epoch != prepared.plan.epoch {
            return Err(DepositWorkerError::WrongSigningEpoch {
                plan: prepared.plan.epoch,
                committee: committee.epoch,
            });
        }
        if expected_group_key != self.scan.root_spend_key() {
            return Err(DepositWorkerError::WrongSigningGroupKey);
        }
        if session.0 == [0_u8; 32]
            || prepared.transaction_commitment
                != transaction_commitment(&prepared.plan, &prepared.transaction)
        {
            return Err(DepositWorkerError::InvalidPreparedSweep);
        }
        let signing_context = signing_context_in_session(
            &prepared.transaction,
            committee,
            signers,
            expected_group_key,
            session,
        )
        .into_bytes();
        let signing_intent = SweepSigningIntent::new(
            prepared.plan.epoch,
            prepared.plan.id.0,
            session.0,
            committee.digest(),
            expected_group_key,
            signers.parties().iter().map(|party| party.0).collect(),
            prepared.transaction.serialize(),
            prepared.prepared_intent.encode()?,
            prepared.transaction_commitment,
            signing_context,
            prepared.fee_atomic_units,
        );
        Ok((signing_intent.intent_digest(), signing_context))
    }

    pub fn reserve_prepared_sweep(
        &mut self,
        prepared: &PreparedFrostlassSweep,
        committee: &Committee,
        signers: &CanonicalSignerSet,
        expected_group_key: [u8; 32],
        session: SessionId,
    ) -> Result<PreparedSweepReservation, DepositWorkerError> {
        self.require_no_pending_events()?;
        self.validate_plan(&prepared.plan)?;
        self.reserve_validated_prepared_sweep(
            prepared,
            committee,
            signers,
            expected_group_key,
            1,
            session,
            true,
        )
    }

    fn reserve_validated_prepared_sweep(
        &mut self,
        prepared: &PreparedFrostlassSweep,
        committee: &Committee,
        signers: &CanonicalSignerSet,
        expected_group_key: [u8; 32],
        initial_signing_attempt: u64,
        session: SessionId,
        advance_local_allocator: bool,
    ) -> Result<PreparedSweepReservation, DepositWorkerError> {
        if derive_sweep_signing_session(
            self.scan.wallet_id(),
            prepared.plan.id,
            initial_signing_attempt,
        ) != Some(session)
        {
            return Err(DepositWorkerError::InvalidSweepSigningAttempt);
        }
        let reserved_next = prepared
            .plan
            .sequence
            .checked_add(1)
            .ok_or(DepositWorkerError::SweepSequenceExhausted)?;
        let (_, signing_context) = self.prepared_signing_binding(
            prepared,
            committee,
            signers,
            expected_group_key,
            session,
        )?;
        let signable_transaction = prepared.transaction.serialize();
        let prepared_sweep_intent = prepared.prepared_intent.encode()?;
        let signing_intent = SweepSigningIntent::new(
            prepared.plan.epoch,
            prepared.plan.id.0,
            session.0,
            committee.digest(),
            expected_group_key,
            signers.parties().iter().map(|party| party.0).collect(),
            signable_transaction,
            prepared_sweep_intent,
            prepared.transaction_commitment,
            signing_context,
            prepared.fee_atomic_units,
        );
        let mut candidate = self.clone();
        candidate.scan.reserve_sweep(SweepRecord {
            id: prepared.plan.id,
            signing_intent,
            signing_attempt_high_water: initial_signing_attempt,
            retired_signing_attempts: Vec::new(),
            family_key_images: None,
            inputs: prepared.plan.inputs.clone(),
            signed_transaction: None,
            family_candidates: Vec::new(),
            status: SweepStatus::Reserved,
        })?;
        if advance_local_allocator {
            candidate.next_sweep_sequence = candidate.next_sweep_sequence.max(reserved_next);
        }
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(PreparedSweepReservation { persistence: effect, sweep: prepared.plan.id })
    }

    /// Transition a reservation to durable nonce authorization.
    ///
    /// Persist the returned effect before releasing any FROSTLASS preprocess/nonces. Merely
    /// reserving an attempt is insufficient authorization and remains safely abortable.
    ///
    /// # Errors
    ///
    /// Returns an error for pending events, an unknown sweep, an invalid transition, or revision
    /// exhaustion.
    pub fn release_sweep_for_signing(
        &mut self,
        id: SweepId,
    ) -> Result<SigningReleaseReceipt, DepositWorkerError> {
        self.require_no_pending_events()?;
        let mut candidate = self.clone();
        candidate.scan.release_sweep_for_signing(id)?;
        let effect = candidate.finish_mutation()?;
        let record = candidate.scan.sweep(id).ok_or(DepositWalletError::UnknownSweep(id))?;
        let receipt = SigningReleaseReceipt {
            persistence: effect,
            sweep: id,
            attempt_high_water: record.signing_attempt_high_water,
            session: SessionId(record.signing_intent.session()),
            intent_digest: record.signing_intent.intent_digest(),
        };
        *self = candidate;
        Ok(receipt)
    }

    /// Derive the exact sweep-family binding without changing durable worker state.
    ///
    /// `key_images` must be in original prepared-input order and must already be backed by
    /// round-one DLEq proofs tying each threshold verification share to its key-image share. The
    /// consolidation protocol signs identical previews from distinct parties and obtains its
    /// `n-f` authorization certificate before calling [`Self::pin_sweep_family_key_image_binding`].
    pub fn preview_sweep_family_key_images(
        &self,
        id: SweepId,
        key_images: Vec<[u8; 32]>,
    ) -> Result<FamilyKeyImageBinding, DepositWorkerError> {
        self.validate(None)?;
        let record = self.scan.sweep(id).ok_or(DepositWalletError::UnknownSweep(id))?;
        let unsigned = record
            .signing_intent
            .signable_transaction()?
            .unsigned_transaction(
                key_images.iter().copied().map(MoneroCompressedPoint::from).collect(),
            )
            .ok_or(DepositWorkerError::InvalidSweepFamilyCandidate)?;
        let unsigned_transaction_digest = unsigned_sweep_transaction_digest(&unsigned)?;
        self.scan
            .preview_sweep_family_key_images(id, key_images, unsigned_transaction_digest)
            .map_err(Into::into)
    }

    /// Atomically pin one externally quorum-authorized preview.
    ///
    /// The binding is recomputed from local durable state and must match byte-for-byte. Persist the
    /// returned effect before exposing any CLSAG signature share.
    pub fn pin_sweep_family_key_image_binding(
        &mut self,
        binding: FamilyKeyImageBinding,
    ) -> Result<FamilyKeyImagePin, DepositWorkerError> {
        self.require_no_pending_events()?;
        let preview =
            self.preview_sweep_family_key_images(binding.sweep(), binding.key_images().to_vec())?;
        if preview != binding {
            return Err(DepositWalletError::SweepFamilyKeyImageConflict.into());
        }
        let mut candidate = self.clone();
        let stored = candidate.scan.pin_sweep_family_key_images(
            binding.sweep(),
            binding.key_images().to_vec(),
            binding.unsigned_transaction_digest(),
        )?;
        if stored != binding {
            return Err(DepositWalletError::SweepFamilyKeyImageConflict.into());
        }
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(FamilyKeyImagePin { persistence: effect, binding: stored })
    }

    /// Durably pin quorum-certified key images for the immutable prepared sweep family.
    ///
    /// The portable consolidation reducer must authenticate the completed threshold-commitment
    /// evidence before calling this method. Persist the returned effect before exposing a
    /// signature share. The worker independently checks canonical, distinct prime-order images and
    /// binds their order to the exact scanner inputs and attempt-independent prepared intent.
    pub fn pin_sweep_family_key_images(
        &mut self,
        id: SweepId,
        key_images: Vec<[u8; 32]>,
    ) -> Result<FamilyKeyImagePin, DepositWorkerError> {
        let binding = self.preview_sweep_family_key_images(id, key_images)?;
        self.pin_sweep_family_key_image_binding(binding)
    }

    /// Return the durable attempt-independent key-image binding for portable recovery.
    #[must_use]
    pub fn sweep_family_key_images(&self, id: SweepId) -> Option<&FamilyKeyImageBinding> {
        self.scan.sweep_family_key_images(id)
    }

    /// Fully validate an exact candidate against the durable prepared family.
    ///
    /// In addition to canonical parsing, exact key images and `Eventuality` output matching, this
    /// verifies exact prepared ring offsets/members, every CLSAG, the aggregate Bulletproof+, and
    /// the RingCT input/output/fee commitment balance. It is independent of retry session,
    /// committee and signer-subset fields.
    pub fn validate_sweep_family_candidate(
        &self,
        id: SweepId,
        signed: &SignedSweepTransaction,
    ) -> Result<(), DepositWorkerError> {
        validate_sweep_family_candidate(&self.scan, id, signed)
    }

    /// Release the exact signing authorization only after its state effect was persisted.
    ///
    /// # Errors
    ///
    /// Returns an error for a persistence mismatch, unknown sweep, or non-released state.
    pub fn signing_authorization_after_persist(
        &self,
        receipt: SigningReleaseReceipt,
        persisted_revision: u64,
    ) -> Result<SweepSigningAuthorization, DepositWorkerError> {
        self.verify_effect(receipt.persistence, persisted_revision)?;
        let record = self
            .scan
            .sweep(receipt.sweep)
            .ok_or(DepositWalletError::UnknownSweep(receipt.sweep))?;
        if record.status != SweepStatus::SigningReleased {
            return Err(DepositWalletError::InvalidSweepTransition.into());
        }
        if SessionId(record.signing_intent.session()) != receipt.session
            || record.signing_intent.intent_digest() != receipt.intent_digest
            || record.signing_attempt_high_water != receipt.attempt_high_water
        {
            return Err(DepositWorkerError::PersistenceMismatch);
        }
        Ok(SweepSigningAuthorization {
            sweep: receipt.sweep,
            attempt: receipt.attempt_high_water,
            session: SessionId(record.signing_intent.session()),
            signing_context: record.signing_intent.signing_context(),
            signers: record.signing_intent.signers().to_vec(),
            group_key: record.signing_intent.group_key(),
            intent_digest: record.signing_intent.intent_digest(),
        })
    }

    /// Return the current released session and every permanent crash-recovery tombstone.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown sweep or invalid durable state.
    pub fn sweep_signing_attempt_status(
        &self,
        id: SweepId,
    ) -> Result<SweepSigningAttemptStatus, DepositWorkerError> {
        self.validate(None)?;
        let record = self.scan.sweep(id).ok_or(DepositWalletError::UnknownSweep(id))?;
        Ok(SweepSigningAttemptStatus {
            current_attempt: record.signing_attempt_high_water,
            attempt_high_water: record.signing_attempt_high_water,
            current_session: SessionId(record.signing_intent.session()),
            current_intent_digest: record.signing_intent.intent_digest(),
            retired: record
                .retired_signing_attempts
                .iter()
                .map(|retired| SweepSigningSessionTombstone {
                    attempt: retired.attempt(),
                    session: SessionId(retired.session()),
                    intent_digest: retired.intent_digest(),
                })
                .collect(),
        })
    }

    /// Return the monotonic durable attempt high-water used by protocol-store CAS integration.
    pub fn sweep_signing_attempt_high_water(&self, id: SweepId) -> Result<u64, DepositWorkerError> {
        self.validate(None)?;
        self.scan
            .sweep_signing_attempt_high_water(id)
            .ok_or_else(|| DepositWalletError::UnknownSweep(id).into())
    }

    /// Reconstruct an authenticated compacted attempt from the encrypted immutable sweep family.
    ///
    /// The caller must first authenticate the quorum certificate over `exact_attempt`. This method
    /// then independently re-derives its deterministic session, signer set, signing context and
    /// private worker-intent digest. A certified terminal attempt may be above the local high-water;
    /// consuming the sealed capability advances that mark without releasing a nonce. Successful
    /// verification cannot be converted into a release receipt or signing authorization.
    pub fn verify_certified_sweep_signing_attempt(
        &self,
        id: SweepId,
        exact_attempt: &AttemptBinding,
        committee: &Committee,
    ) -> Result<VerifiedSweepSigningAttempt, DepositWorkerError> {
        self.validate(None)?;
        exact_attempt.validate().map_err(|_| DepositWorkerError::InvalidSweepSigningAttempt)?;
        committee
            .validate()
            .map_err(|error| DepositWorkerError::InvalidSigningCommittee(error.to_string()))?;
        let record = self.scan.sweep(id).ok_or(DepositWalletError::UnknownSweep(id))?;
        let current = &record.signing_intent;
        if derive_sweep_signing_session(self.scan.wallet_id(), id, exact_attempt.attempt())
            != Some(exact_attempt.session())
            || exact_attempt.epoch() != current.epoch()
            || committee.epoch != current.epoch()
            || exact_attempt.committee_digest() != committee.digest()
            || exact_attempt.threshold() != committee.threshold
            || exact_attempt.root_group_key() != current.group_key()
            || exact_attempt.root_group_key() != self.scan.root_spend_key()
        {
            return Err(DepositWorkerError::InvalidSweepSigningAttempt);
        }
        let local_party = *exact_attempt
            .signers()
            .first()
            .ok_or(DepositWorkerError::InvalidSweepSigningAttempt)?;
        let signers = CanonicalSignerSet::new(
            committee,
            local_party,
            exact_attempt.signers().iter().copied(),
        )
        .map_err(|_| DepositWorkerError::InvalidSweepSigningAttempt)?;
        let transaction = current.signable_transaction()?;
        let signing_context = signing_context_in_session(
            &transaction,
            committee,
            &signers,
            current.group_key(),
            exact_attempt.session(),
        )
        .into_bytes();
        if signing_context != exact_attempt.signing_context() {
            return Err(DepositWorkerError::InvalidSweepSigningAttempt);
        }
        let reconstructed = SweepSigningIntent::new(
            current.epoch(),
            current.plan_commitment(),
            exact_attempt.session().0,
            committee.digest(),
            current.group_key(),
            signers.parties().iter().map(|party| party.0).collect(),
            transaction.serialize(),
            current.prepared_sweep_intent_bytes().to_vec(),
            current.transaction_commitment(),
            signing_context,
            current.fee_atomic_units(),
        );
        if reconstructed.intent_digest() != exact_attempt.worker_intent_digest() {
            return Err(DepositWorkerError::InvalidSweepSigningAttempt);
        }
        Ok(VerifiedSweepSigningAttempt {
            sweep: id,
            exact_attempt: exact_attempt.clone(),
            reconstructed_intent: reconstructed,
        })
    }

    /// Persist an authenticated later attempt as burned catch-up history without nonce release.
    ///
    /// This is the bounded predecessor-chain hook for lagging parties. The returned generic worker
    /// effect has no path to [`SweepSigningAuthorization`]; callers may release only a separately
    /// reconstructed exact successor after both worker and coordinator high-waters are durable.
    pub fn catch_up_certified_sweep_signing_attempt(
        &mut self,
        id: SweepId,
        exact_attempt: &AttemptBinding,
        committee: &Committee,
    ) -> Result<Option<WorkerPersistEffect>, DepositWorkerError> {
        self.require_no_pending_events()?;
        let verified = self.verify_certified_sweep_signing_attempt(id, exact_attempt, committee)?;
        let current = self.sweep_signing_attempt_high_water(id)?;
        if verified.attempt() <= current {
            return Ok(None);
        }
        let mut candidate = self.clone();
        candidate.scan.catch_up_certified_sweep_signing_intent(
            id,
            verified.attempt(),
            verified.reconstructed_intent,
        )?;
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(Some(effect))
    }

    /// Permanently close an unsigned post-nonce family after a quorum-certified input-reorg
    /// abandonment decision.
    ///
    /// The exact attempt is reconstructed against the encrypted private family first. This may
    /// advance the attempt high-water, but the returned generic persistence effect has no route to
    /// a release receipt or signing authorization. Inputs, key images and every consumed session
    /// remain claimed so a later old-branch transaction can only settle through the separately
    /// verified retained-chain path.
    pub fn record_certified_sweep_abandonment(
        &mut self,
        id: SweepId,
        exact_attempt: &AttemptBinding,
        committee: &Committee,
        ancestor: ChainPoint,
    ) -> Result<Option<WorkerPersistEffect>, DepositWorkerError> {
        self.require_no_pending_events()?;
        let verified = self.verify_certified_sweep_signing_attempt(id, exact_attempt, committee)?;
        let mut candidate = self.clone();
        let changed = candidate.scan.record_certified_sweep_abandonment(
            id,
            verified.attempt(),
            verified.reconstructed_intent,
            ancestor,
        )?;
        if !changed {
            return Ok(None);
        }
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(Some(effect))
    }

    /// Replace a released-but-lost FROST machine with one fresh durable session.
    ///
    /// The stored prepared representation is decoded and independently reconstructed first. The
    /// replacement is then restricted to the same exact plan, inputs, transaction, private intent,
    /// fee, epoch, and root key. The old `(session, intent digest)` is permanently tombstoned and
    /// inputs never become available. Persist the returned effect atomically with the protocol
    /// store's one-use session tombstone before requesting authorization or creating a nonce.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-released sweep, stale/reorganized input, reused/zero session,
    /// invalid committee/key binding, attempt-cap exhaustion, or persistence failure.
    pub fn recover_released_sweep_signing(
        &mut self,
        deriver: &DepositAddressDeriver,
        id: SweepId,
        committee: &Committee,
        signers: &CanonicalSignerSet,
        expected_group_key: [u8; 32],
        fresh_session: SessionId,
    ) -> Result<SigningReleaseReceipt, DepositWorkerError> {
        self.require_no_pending_events()?;
        let prepared = self.reconstruct_reserved_sweep(deriver, id)?;
        let record = self.scan.sweep(id).ok_or(DepositWalletError::UnknownSweep(id))?;
        if record.status != SweepStatus::SigningReleased {
            return Err(DepositWalletError::InvalidSweepTransition.into());
        }
        committee
            .validate()
            .map_err(|error| DepositWorkerError::InvalidSigningCommittee(error.to_string()))?;
        if committee.epoch != prepared.plan.epoch {
            return Err(DepositWorkerError::WrongSigningEpoch {
                plan: prepared.plan.epoch,
                committee: committee.epoch,
            });
        }
        if expected_group_key != self.scan.root_spend_key() {
            return Err(DepositWorkerError::WrongSigningGroupKey);
        }
        if fresh_session.0 == [0_u8; 32] {
            return Err(DepositWorkerError::InvalidPreparedSweep);
        }
        let signing_context = signing_context_in_session(
            &prepared.transaction,
            committee,
            signers,
            expected_group_key,
            fresh_session,
        );
        let replacement = SweepSigningIntent::new(
            prepared.plan.epoch,
            prepared.plan.id.0,
            fresh_session.0,
            committee.digest(),
            expected_group_key,
            signers.parties().iter().map(|party| party.0).collect(),
            prepared.transaction.serialize(),
            prepared.prepared_intent.encode()?,
            prepared.transaction_commitment,
            signing_context.into_bytes(),
            prepared.fee_atomic_units,
        );
        let mut candidate = self.clone();
        candidate.scan.recover_released_sweep_signing_intent(id, replacement)?;
        let effect = candidate.finish_mutation()?;
        let record = candidate.scan.sweep(id).ok_or(DepositWalletError::UnknownSweep(id))?;
        let receipt = SigningReleaseReceipt {
            persistence: effect,
            sweep: id,
            attempt_high_water: record.signing_attempt_high_water,
            session: SessionId(record.signing_intent.session()),
            intent_digest: record.signing_intent.intent_digest(),
        };
        *self = candidate;
        Ok(receipt)
    }

    /// Persist exact canonical transaction bytes after threshold signing and before submission.
    ///
    /// The optional expected transaction ID is checked against the hash of the parsed bytes when
    /// the caller already has an independently committed ID. Persist the returned effect before
    /// asking for the bytes via [`Self::signed_sweep_after_persist`] or invoking monerod.
    ///
    /// # Errors
    ///
    /// Returns an error for a pending event batch, malformed/oversized transaction, hash mismatch,
    /// invalid sweep transition, or persistence revision failure.
    pub fn mark_sweep_signed(
        &mut self,
        id: SweepId,
        transaction: &Transaction,
        expected_transaction: Option<[u8; 32]>,
    ) -> Result<WorkerPersistEffect, DepositWorkerError> {
        self.require_no_pending_events()?;
        let signed = SignedSweepTransaction::from_transaction(transaction, expected_transaction)?;
        self.validate_sweep_family_candidate(id, &signed)?;
        let mut candidate = self.clone();
        candidate.scan.mark_sweep_signed(id, signed)?;
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(effect)
    }

    /// Adopt a portable-certified transaction from an exact current or retired attempt.
    ///
    /// Portable consensus is responsible for establishing the f+1 certificate before invoking
    /// this method. The worker nevertheless verifies the complete transaction against its private
    /// prepared sweep and pinned family key images, and requires the exact `(session, worker
    /// intent)` pair to exist in durable local history. A retired attempt is only recognized as
    /// provenance for an already-produced result: its nonce authority is never recreated. A
    /// distinct valid candidate may replace a merely local `Signed` candidate, but never one
    /// which has already reached `Broadcast` or `Confirmed`.
    ///
    /// Persist the returned effect before requesting the canonical bytes through
    /// [`Self::signed_sweep_after_persist`].
    pub fn adopt_portable_sweep_family_candidate(
        &mut self,
        id: SweepId,
        exact_attempt: SweepSigningSessionTombstone,
        signed: &SignedSweepTransaction,
    ) -> Result<WorkerPersistEffect, DepositWorkerError> {
        self.require_no_pending_events()?;
        self.validate_sweep_family_candidate(id, signed)?;
        let mut candidate = self.clone();
        candidate.scan.adopt_portable_sweep_signed(
            id,
            exact_attempt.attempt,
            exact_attempt.session.0,
            exact_attempt.intent_digest,
            signed.clone(),
        )?;
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(effect)
    }

    /// Adopt a certified candidate from a deterministically reconstructed retained or compacted
    /// attempt. This path never changes the attempt high-water and never returns a release receipt.
    pub fn adopt_verified_portable_sweep_family_candidate(
        &mut self,
        verified_attempt: &VerifiedSweepSigningAttempt,
        signed: &SignedSweepTransaction,
    ) -> Result<WorkerPersistEffect, DepositWorkerError> {
        self.require_no_pending_events()?;
        let id = verified_attempt.sweep;
        self.validate_sweep_family_candidate(id, signed)?;
        let mut candidate = self.clone();
        candidate.scan.adopt_verified_portable_sweep_signed(
            id,
            verified_attempt.exact_attempt.attempt(),
            verified_attempt.exact_attempt.session().0,
            verified_attempt.exact_attempt.worker_intent_digest(),
            verified_attempt.reconstructed_intent.clone(),
            signed.clone(),
        )?;
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(effect)
    }

    /// Release one exact signed transaction only after its snapshot was durably stored.
    ///
    /// # Errors
    ///
    /// Returns an error for a persistence mismatch, unknown sweep, or non-`Signed` state.
    pub fn signed_sweep_after_persist(
        &self,
        effect: WorkerPersistEffect,
        persisted_revision: u64,
        id: SweepId,
    ) -> Result<SignedSweepTransaction, DepositWorkerError> {
        self.verify_effect(effect, persisted_revision)?;
        let record = self.scan.sweep(id).ok_or(DepositWalletError::UnknownSweep(id))?;
        if !matches!(record.status, SweepStatus::Signed { .. }) {
            return Err(DepositWalletError::InvalidSweepTransition.into());
        }
        record.signed_transaction.clone().ok_or(DepositWalletError::InvalidSweepTransition.into())
    }

    /// Validate and return all already-durable signed transactions awaiting RPC submission.
    ///
    /// This is the restart path. Submitting the same Monero transaction bytes is idempotent; only
    /// persist `Broadcast` after monerod reports success or that the exact transaction is known.
    ///
    /// # Errors
    ///
    /// Returns an error if durable worker state is invalid.
    pub fn replay_signed_sweeps(
        &self,
    ) -> Result<Vec<(SweepId, SignedSweepTransaction)>, DepositWorkerError> {
        self.validate(None)?;
        Ok(self
            .scan
            .signed_sweeps_for_broadcast()
            .map(|(id, signed)| (id, signed.clone()))
            .collect())
    }

    /// Reconcile broadcast attempts against deterministic retained root-output inclusion proof.
    ///
    /// The result is sorted by sweep ID and contains only exact transaction IDs observed at an
    /// exact retained or compacted chain point. A coordinator may pass each tuple to
    /// [`Self::mark_sweep_confirmed`]; it must not invent a confirmation point from daemon status.
    ///
    /// # Errors
    ///
    /// Returns an error if durable worker state is invalid.
    pub fn reconcile_broadcast_confirmations(
        &self,
    ) -> Result<Vec<SweepConfirmationEvidence>, DepositWorkerError> {
        self.validate(None)?;
        let mut confirmations = self
            .scan
            .broadcast_sweep_confirmations()
            .into_iter()
            .map(|evidence| (evidence.sweep, evidence))
            .collect::<BTreeMap<_, _>>();
        for evidence in self.observed_family_settlements.values() {
            confirmations.insert(
                evidence.sweep,
                SweepConfirmationEvidence {
                    sweep: evidence.sweep,
                    transaction: evidence.transaction_id(),
                    block: evidence.block,
                },
            );
        }
        Ok(confirmations.into_values().collect())
    }

    /// Return exact fully validated same-family transactions observed on the retained chain.
    ///
    /// These bytes remain durable until atomically promoted with the public consolidation state.
    /// Scanner-only backends cannot populate this evidence and therefore cannot settle an unknown
    /// privately aggregated transaction.
    pub fn reconcile_sweep_family_settlements(
        &self,
    ) -> Result<Vec<SweepFamilySettlementEvidence>, DepositWorkerError> {
        self.validate(None)?;
        Ok(self.observed_family_settlements.values().cloned().collect())
    }

    /// Validate and durably stage exact full bytes fetched after the scanner retained inclusion.
    ///
    /// This is the recovery path for scanner-only block sources: the caller may later fetch the
    /// exact transaction by the retained root-output txid. The hash, full family cryptography and
    /// exact retained block/output indexes are all rechecked; RPC availability/status alone is not
    /// evidence. An exact already-staged replay returns `Ok(None)`.
    pub fn stage_sweep_family_settlement_candidate(
        &mut self,
        id: SweepId,
        signed: SignedSweepTransaction,
        block: ChainPoint,
    ) -> Result<Option<WorkerPersistEffect>, DepositWorkerError> {
        self.require_no_pending_events()?;
        let before = self.observed_family_settlements.get(&id).cloned();
        let mut candidate = self.clone();
        candidate.observe_sweep_family_transactions(block, &[signed])?;
        if candidate.observed_family_settlements.get(&id).is_none() {
            return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
        }
        if candidate.observed_family_settlements.get(&id) == before.as_ref() {
            return Ok(None);
        }
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(Some(effect))
    }

    /// Mark a reserved sweep as broadcast and return the required persistence effect.
    ///
    /// # Errors
    ///
    /// Returns an error for a pending event batch, invalid sweep transition, or persistence
    /// revision failure.
    pub fn mark_sweep_broadcast(
        &mut self,
        id: SweepId,
        transaction: [u8; 32],
    ) -> Result<WorkerPersistEffect, DepositWorkerError> {
        self.require_no_pending_events()?;
        let mut candidate = self.clone();
        candidate.scan.mark_sweep_broadcast(id, transaction)?;
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(effect)
    }

    /// Mark a broadcast sweep as confirmed and return the required persistence effect.
    ///
    /// # Errors
    ///
    /// Returns an error for a pending event batch, unknown chain point, invalid transition, or
    /// persistence revision failure.
    pub fn mark_sweep_confirmed(
        &mut self,
        id: SweepId,
        transaction: [u8; 32],
        block: ChainPoint,
    ) -> Result<WorkerPersistEffect, DepositWorkerError> {
        self.require_no_pending_events()?;
        let mut candidate = self.clone();
        if let Some(observed) = candidate.observed_family_settlements.get(&id).cloned() {
            if observed.transaction_id() != transaction || observed.block != block {
                return Err(DepositWorkerError::SweepFamilySpendConflict(id));
            }
            validate_sweep_family_candidate(&candidate.scan, id, &observed.signed_transaction)?;
            candidate.scan.mark_sweep_family_confirmed(id, observed.signed_transaction, block)?;
            candidate.observed_family_settlements.remove(&id);
        } else {
            candidate.scan.mark_sweep_confirmed(id, transaction, block)?;
        }
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(effect)
    }

    /// Atomically promote canonical same-family bytes and a certified reconstructed attempt.
    ///
    /// This is the chain-authoritative lagger path. It may advance the worker attempt high-water,
    /// including over a locally broadcast alternative, but can never yield a signing release.
    pub fn mark_verified_sweep_family_confirmed(
        &mut self,
        verified_attempt: &VerifiedSweepSigningAttempt,
        signed: &SignedSweepTransaction,
        block: ChainPoint,
    ) -> Result<WorkerPersistEffect, DepositWorkerError> {
        self.require_no_pending_events()?;
        let id = verified_attempt.sweep;
        self.validate_sweep_family_candidate(id, signed)?;
        let mut candidate = self.clone();
        let observed = candidate
            .observed_family_settlements
            .get(&id)
            .ok_or(DepositWorkerError::InvalidSweepFamilyCandidate)?;
        if observed.signed_transaction != *signed || observed.block != block {
            return Err(DepositWorkerError::SweepFamilySpendConflict(id));
        }
        candidate.scan.mark_verified_sweep_family_confirmed(
            id,
            verified_attempt.exact_attempt.attempt(),
            verified_attempt.reconstructed_intent.clone(),
            signed.clone(),
            block,
        )?;
        candidate.observed_family_settlements.remove(&id);
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(effect)
    }

    /// Abort a pre-broadcast sweep reservation and return the required persistence effect.
    ///
    /// # Errors
    ///
    /// Returns an error for a pending event batch, invalid transition, or persistence revision
    /// failure.
    pub fn abort_sweep(&mut self, id: SweepId) -> Result<WorkerPersistEffect, DepositWorkerError> {
        self.require_no_pending_events()?;
        let mut candidate = self.clone();
        candidate.scan.abort_sweep(id)?;
        let effect = candidate.finish_mutation()?;
        *self = candidate;
        Ok(effect)
    }

    /// Encode the complete validated worker state for encrypted wallet-snapshot storage.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/corrupt state, serialization failure, or the hard size bound.
    pub fn encode(&self) -> Result<Vec<u8>, DepositWorkerError> {
        self.validate(None)?;
        let encoded = postcard::to_allocvec(self).map_err(|_| DepositWorkerError::Serialization)?;
        if encoded.len() > MAX_WORKER_STATE_BYTES {
            return Err(DepositWorkerError::StateTooLarge);
        }
        Ok(encoded)
    }

    /// Restore a complete worker state and bind it to the in-memory private view material.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, non-canonical, corrupt, or wrong-wallet state.
    pub fn decode(
        bytes: &[u8],
        deriver: &DepositAddressDeriver,
    ) -> Result<Self, DepositWorkerError> {
        if bytes.len() > MAX_WORKER_STATE_BYTES {
            return Err(DepositWorkerError::StateTooLarge);
        }
        let state: Self =
            postcard::from_bytes(bytes).map_err(|_| DepositWorkerError::Serialization)?;
        let canonical =
            postcard::to_allocvec(&state).map_err(|_| DepositWorkerError::Serialization)?;
        if canonical != bytes {
            return Err(DepositWorkerError::NonCanonicalState);
        }
        state.validate(Some(deriver))?;
        Ok(state)
    }

    async fn find_reorg_ancestor<S: DepositChainSource + ?Sized>(
        &self,
        source: &S,
        request_timeout: Duration,
    ) -> Result<Option<ChainPoint>, DepositWorkerError> {
        let tip = self.scan.tip();
        let canonical_tip = request(
            request_timeout,
            "retained block hash",
            Some(tip.height),
            source.block_hash(tip.height),
        )
        .await?;
        if canonical_tip == tip.hash {
            return Ok(None);
        }

        let anchor = self.scan.anchor();
        let mut height = tip.height;
        let mut searched = 0_u32;
        loop {
            if height == anchor.height {
                return Err(DepositWorkerError::AnchorMismatch(anchor));
            }
            height = height.checked_sub(1).ok_or(DepositWorkerError::HeightOverflow)?;
            searched = searched.checked_add(1).ok_or(DepositWorkerError::ReorgDepthExceeded {
                maximum: self.config.max_reorg_depth,
            })?;
            if searched > self.config.max_reorg_depth {
                return Err(DepositWorkerError::ReorgDepthExceeded {
                    maximum: self.config.max_reorg_depth,
                });
            }
            let retained = self.scan.chain_point(height).ok_or(DepositWorkerError::CorruptState)?;
            let canonical = request(
                request_timeout,
                "reorg ancestor hash",
                Some(height),
                source.block_hash(height),
            )
            .await?;
            if canonical == retained.hash {
                return Ok(Some(retained));
            }
        }
    }

    fn validate_plan(&self, plan: &SweepPlan) -> Result<(), DepositWorkerError> {
        if plan.sequence != self.next_sweep_sequence {
            return Err(DepositWorkerError::StaleSweepPlan);
        }
        self.validate_plan_at_or_above(plan, self.next_sweep_sequence)
    }

    fn validate_plan_at_or_above(
        &self,
        plan: &SweepPlan,
        authenticated_minimum: u64,
    ) -> Result<(), DepositWorkerError> {
        self.require_no_pending_events()?;
        if plan.wallet != self.wallet_id()
            || plan.sequence < authenticated_minimum
            || plan.destination_binding == [0_u8; 32]
            || plan.inputs.is_empty()
            || plan.inputs.len() > usize::from(self.config.max_sweep_inputs)
            || plan.inputs.windows(2).any(|window| window[0] >= window[1])
            || plan.id.0 != sweep_plan_commitment(plan)
            || self.scan.chain_point(plan.at_tip.height) != Some(plan.at_tip)
        {
            return Err(DepositWorkerError::StaleSweepPlan);
        }
        let mut total = 0_u64;
        for id in &plan.inputs {
            let output = self.scan.output(*id).ok_or(DepositWorkerError::StaleSweepPlan)?;
            if !self.scan.available_outputs().any(|available| available.id() == *id) {
                return Err(DepositWorkerError::StaleSweepPlan);
            }
            let inclusion =
                self.scan.output_chain_point(*id).ok_or(DepositWorkerError::StaleSweepPlan)?;
            let confirmations = plan
                .at_tip
                .height
                .checked_sub(inclusion.height)
                .and_then(|distance| distance.checked_add(1))
                .ok_or(DepositWorkerError::StaleSweepPlan)?;
            if confirmations
                < u64::try_from(DEFAULT_LOCK_WINDOW)
                    .map_err(|_| DepositWorkerError::HeightOverflow)?
            {
                return Err(DepositWorkerError::StaleSweepPlan);
            }
            let wallet_output = output.wallet_output()?;
            if !self
                .scan
                .additional_timelock_satisfied_at(plan.at_tip, wallet_output.additional_timelock())
            {
                return Err(DepositWorkerError::StaleSweepPlan);
            }
            total = total
                .checked_add(wallet_output.commitment().amount)
                .ok_or(DepositWorkerError::AmountOverflow)?;
        }
        if total != plan.total_input_atomic_units || total < self.config.minimum_sweep_atomic_units
        {
            return Err(DepositWorkerError::StaleSweepPlan);
        }
        Ok(())
    }

    fn stage_events(
        &mut self,
        mut detections: Vec<DepositDetection>,
        rollback: Option<DepositRollback>,
    ) -> Result<(), DepositWorkerError> {
        if self.pending_events.is_some() || (detections.is_empty() && rollback.is_none()) {
            return Err(DepositWorkerError::InvalidEventBatch);
        }
        detections
            .sort_unstable_by_key(|detection| (detection.observed_block.height, detection.output));
        let revision = self.revision.checked_add(1).ok_or(DepositWorkerError::RevisionExhausted)?;
        let mut batch = WorkerEventBatch { id: [0_u8; 32], revision, detections, rollback };
        batch.id = event_batch_id(&batch);
        self.pending_events = Some(batch);
        Ok(())
    }

    fn finish_mutation(&mut self) -> Result<WorkerPersistEffect, DepositWorkerError> {
        self.revision =
            self.revision.checked_add(1).ok_or(DepositWorkerError::RevisionExhausted)?;
        if let Some(batch) = &self.pending_events
            && batch.revision != self.revision
        {
            return Err(DepositWorkerError::InvalidEventBatch);
        }
        self.validate(None)?;
        let state_commitment = self.state_commitment()?;
        Ok(WorkerPersistEffect { revision: self.revision, state_commitment })
    }

    fn verify_effect(
        &self,
        effect: WorkerPersistEffect,
        persisted_revision: u64,
    ) -> Result<(), DepositWorkerError> {
        if effect.revision != self.revision
            || persisted_revision != self.revision
            || effect.state_commitment != self.state_commitment()?
        {
            return Err(DepositWorkerError::PersistenceMismatch);
        }
        Ok(())
    }

    fn state_commitment(&self) -> Result<[u8; 32], DepositWorkerError> {
        let encoded = postcard::to_allocvec(self).map_err(|_| DepositWorkerError::Serialization)?;
        if encoded.len() > MAX_WORKER_STATE_BYTES {
            return Err(DepositWorkerError::StateTooLarge);
        }
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/deposit-worker-state/v1");
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }

    fn validate(&self, deriver: Option<&DepositAddressDeriver>) -> Result<(), DepositWorkerError> {
        if self.version != WORKER_STATE_VERSION {
            return Err(DepositWorkerError::UnsupportedStateVersion(self.version));
        }
        self.config.validate()?;
        self.scan.validate()?;
        if let Some(progress) = &self.pending_block_scan {
            ChainPoint::new(progress.cursor.block.point.height, progress.cursor.block.point.hash)
                .map_err(|_| DepositWorkerError::CorruptState)?;
            let expected_height = self.scan.next_height()?;
            let pending_count = progress
                .outputs
                .len()
                .checked_add(progress.root_outputs.len())
                .ok_or(DepositWorkerError::CorruptState)?;
            if progress.cursor.block.point.height != expected_height
                || progress.hardfork_version > MAX_SUPPORTED_HARDFORK
                || usize::try_from(progress.cursor.transaction_index)
                    .map_or(true, |index| index > MAX_TRANSACTIONS_PER_BLOCK)
                || pending_count > usize::from(self.config.max_outputs_per_block)
                || progress.outputs.windows(2).any(|window| window[0].id() >= window[1].id())
                || progress.root_outputs.windows(2).any(|window| window[0].id() >= window[1].id())
                || progress.outputs.iter().any(|output| {
                    progress
                        .root_outputs
                        .binary_search_by_key(&output.id(), PersistedRootOutput::id)
                        .is_ok()
                })
            {
                return Err(DepositWorkerError::CorruptState);
            }
            for output in &progress.outputs {
                output.validate(self.scan.root_spend_key())?;
            }
            for output in &progress.root_outputs {
                output.validate(self.scan.root_spend_key())?;
            }
        }
        if self.portable_index_head.is_some() != self.portable_through_sequence.is_some()
            || self.portable_index_head.is_some_and(|head| head == [0; 32])
            || self.portable_through_sequence == Some(u64::MAX)
        {
            return Err(DepositWorkerError::CorruptState);
        }
        if let Some(backfill) = &self.allocation_backfill {
            ChainPoint::new(backfill.minimum_anchor.height, backfill.minimum_anchor.hash)
                .map_err(|_| DepositWorkerError::CorruptState)?;
            ChainPoint::new(backfill.previous.height, backfill.previous.hash)
                .map_err(|_| DepositWorkerError::CorruptState)?;
            ChainPoint::new(backfill.confirmed_horizon.height, backfill.confirmed_horizon.hash)
                .map_err(|_| DepositWorkerError::CorruptState)?;
            if backfill.version != ALLOCATION_BACKFILL_VERSION
                || backfill.portable_head == [0; 32]
                || backfill.through_sequence == u64::MAX
                || self
                    .portable_through_sequence
                    .is_none_or(|recognized| recognized > backfill.through_sequence)
                || if backfill.anchor_authenticated {
                    backfill.minimum_anchor.height >= backfill.next_height
                        || backfill.previous.height.checked_add(1) != Some(backfill.next_height)
                } else {
                    backfill.next_height != backfill.minimum_anchor.height
                        || backfill.previous != backfill.minimum_anchor
                }
                || backfill.next_height > backfill.confirmed_horizon.height.saturating_add(1)
                || backfill.minimum_anchor.height > backfill.confirmed_horizon.height
                || backfill.previous.height > backfill.confirmed_horizon.height
                || backfill.held_points.windows(2).any(|points| points[0] >= points[1])
                || backfill.held_points.iter().any(|point| {
                    self.scan
                        .authenticated_historical_block_evidence(
                            *point,
                            backfill.portable_head,
                            backfill.through_sequence,
                        )
                        .is_err()
                })
            {
                return Err(DepositWorkerError::CorruptState);
            }
            if let Some(progress) = &backfill.pending {
                let pending_count = progress
                    .outputs
                    .len()
                    .checked_add(progress.root_outputs.len())
                    .ok_or(DepositWorkerError::CorruptState)?;
                if progress.cursor.block.point.height != backfill.next_height
                    || if backfill.anchor_authenticated {
                        progress.cursor.block.parent_hash != backfill.previous.hash
                    } else {
                        progress.cursor.block.point != backfill.minimum_anchor
                    }
                    || progress.cursor.portable_snapshot != backfill.portable_head
                    || pending_count > usize::from(self.config.max_outputs_per_block)
                {
                    return Err(DepositWorkerError::CorruptState);
                }
            }
        }
        if self.certified_sweep_publications.len() > MAX_CERTIFIED_SWEEP_PUBLICATIONS {
            return Err(DepositWorkerError::CorruptState);
        }
        let mut publication_transactions = BTreeSet::new();
        for (sweep, publication) in &self.certified_sweep_publications {
            if publication.version != CERTIFIED_SWEEP_PUBLICATION_VERSION
                || *sweep != publication.sweep
                || publication.certificate_digest == [0; 32]
                || publication.portable_terminal_digest == [0; 32]
                || publication.inputs.is_empty()
                || publication.inputs.len() > usize::from(self.config.max_sweep_inputs)
                || publication.inputs.windows(2).any(|inputs| inputs[0] >= inputs[1])
                || publication.inputs.iter().any(|input| input.transaction == [0; 32])
                || !publication_transactions.insert(publication.signed_transaction.transaction_id())
            {
                return Err(DepositWorkerError::CorruptState);
            }
            let canonical = SignedSweepTransaction::from_bytes(
                publication.signed_transaction.as_bytes().to_vec(),
                Some(publication.signed_transaction.transaction_id()),
            )?;
            if canonical != publication.signed_transaction {
                return Err(DepositWorkerError::CorruptState);
            }
            if let Some(confirmation) = publication.confirmation {
                ChainPoint::new(confirmation.height, confirmation.hash)
                    .map_err(|_| DepositWorkerError::CorruptState)?;
                if self
                    .scan
                    .root_transaction_chain_point(publication.signed_transaction.transaction_id())
                    != Some(confirmation)
                {
                    return Err(DepositWorkerError::CorruptState);
                }
            }
        }
        if self.scan.retained_block_count()
            > usize::try_from(self.config.max_reorg_depth)
                .map_err(|_| DepositWorkerError::CorruptState)?
        {
            return Err(DepositWorkerError::CorruptState);
        }
        let retained_outputs = self.scan.retained_output_count();
        if retained_outputs
            > usize::try_from(self.config.max_retained_outputs)
                .map_err(|_| DepositWorkerError::CorruptState)?
        {
            return Err(DepositWorkerError::RetentionCapacityExceeded {
                retained: retained_outputs,
                maximum: self.config.max_retained_outputs,
            });
        }
        for sweep in self.scan.sweeps() {
            if let Some(binding) = &sweep.family_key_images {
                let unsigned = sweep
                    .signing_intent
                    .signable_transaction()?
                    .unsigned_transaction(
                        binding
                            .key_images()
                            .iter()
                            .copied()
                            .map(MoneroCompressedPoint::from)
                            .collect(),
                    )
                    .ok_or(DepositWorkerError::CorruptState)?;
                if unsigned_sweep_transaction_digest(&unsigned)?
                    != binding.unsigned_transaction_digest()
                {
                    return Err(DepositWorkerError::CorruptState);
                }
            }
            for signed in &sweep.family_candidates {
                validate_sweep_family_candidate(&self.scan, sweep.id, signed)?;
            }
        }
        let mut observed_transactions = BTreeSet::new();
        for (sweep, evidence) in &self.observed_family_settlements {
            if *sweep != evidence.sweep
                || !observed_transactions.insert(evidence.transaction_id())
                || self.scan.root_transaction_chain_point(evidence.transaction_id())
                    != Some(evidence.block)
                || !matches!(
                    self.scan.sweep(*sweep).map(|record| record.status),
                    Some(
                        SweepStatus::SigningReleased
                            | SweepStatus::Signed { .. }
                            | SweepStatus::Broadcast { .. }
                            | SweepStatus::QuarantinedByReorg { .. }
                            | SweepStatus::AbandonedByReorg { .. }
                    )
                )
            {
                return Err(DepositWorkerError::CorruptState);
            }
            validate_sweep_family_candidate(&self.scan, *sweep, &evidence.signed_transaction)?;
            let transaction = evidence.signed_transaction.transaction()?;
            let Transaction::V2 { prefix, .. } = transaction else {
                return Err(DepositWorkerError::CorruptState);
            };
            let root_indexes = self
                .scan
                .root_outputs()
                .filter(|output| {
                    output.id().transaction == evidence.transaction_id()
                        && self.scan.root_output_chain_point(output.id()) == Some(evidence.block)
                })
                .map(|output| output.id().index_in_transaction)
                .collect::<BTreeSet<_>>();
            if root_indexes
                != (0..prefix.outputs.len())
                    .map(|index| u64::try_from(index).map_err(|_| DepositWorkerError::CorruptState))
                    .collect::<Result<BTreeSet<_>, _>>()?
            {
                return Err(DepositWorkerError::CorruptState);
            }
        }
        let mut expected_pinned_root_transactions = self
            .scan
            .sweeps()
            .filter_map(|sweep| match sweep.status {
                SweepStatus::Confirmed { transaction, .. } => Some(transaction),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        expected_pinned_root_transactions.extend(observed_transactions);
        if self.scan.pinned_root_transactions().collect::<BTreeSet<_>>()
            != expected_pinned_root_transactions
        {
            return Err(DepositWorkerError::CorruptState);
        }
        if let Some(deriver) = deriver
            && self.wallet_id() != deriver.wallet_id()
        {
            return Err(DepositWorkerError::WrongWalletDomain);
        }
        if let Some(batch) = &self.pending_events {
            self.validate_event_batch(batch)?;
        }
        Ok(())
    }

    fn validate_event_batch(&self, batch: &WorkerEventBatch) -> Result<(), DepositWorkerError> {
        let maximum_detections = usize::from(self.config.max_blocks_per_tick)
            .checked_mul(usize::from(self.config.max_outputs_per_block))
            .ok_or(DepositWorkerError::InvalidEventBatch)?;
        if batch.revision != self.revision
            || batch.revision == 0
            || batch.id != event_batch_id(batch)
            || batch.detections.len() > maximum_detections
            || (batch.detections.is_empty() == batch.rollback.is_none())
            || batch.detections.windows(2).any(|window| {
                (window[0].observed_block.height, window[0].output)
                    >= (window[1].observed_block.height, window[1].output)
            })
        {
            return Err(DepositWorkerError::InvalidEventBatch);
        }
        for detection in &batch.detections {
            let output =
                self.scan.output(detection.output).ok_or(DepositWorkerError::InvalidEventBatch)?;
            let wallet_output = output.wallet_output()?;
            if self.scan.output_chain_point(detection.output) != Some(detection.observed_block)
                || output.index_on_blockchain() != detection.index_on_blockchain
                || output.subaddress() != detection.subaddress
                || wallet_output.commitment().amount != detection.amount_atomic_units
            {
                return Err(DepositWorkerError::InvalidEventBatch);
            }
        }
        if let Some(rollback) = &batch.rollback {
            let orphaned_ids = rollback
                .orphaned_deposits
                .iter()
                .map(|orphaned| orphaned.output)
                .collect::<Vec<_>>();
            if rollback.ancestor != self.scan.tip()
                || !strictly_sorted(&rollback.removed_outputs)
                || !strictly_sorted(&rollback.removed_root_outputs)
                || !strictly_sorted(&rollback.invalidated_sweeps)
                || !strictly_sorted(&rollback.quarantined_sweeps)
                || !strictly_sorted(&rollback.reverted_confirmations)
                || !rollback
                    .orphaned_deposits
                    .windows(2)
                    .all(|window| window[0].output < window[1].output)
                || orphaned_ids != rollback.removed_outputs
                || rollback
                    .removed_outputs
                    .iter()
                    .any(|id| rollback.removed_root_outputs.binary_search(id).is_ok())
                || rollback.removed_outputs.iter().any(|id| self.scan.output(*id).is_some())
                || rollback
                    .removed_root_outputs
                    .iter()
                    .any(|id| self.scan.root_output(*id).is_some())
            {
                return Err(DepositWorkerError::InvalidEventBatch);
            }
            for orphaned in &rollback.orphaned_deposits {
                ChainPoint::new(orphaned.observed_block.height, orphaned.observed_block.hash)
                    .map_err(|_| DepositWorkerError::InvalidEventBatch)?;
                if orphaned.observed_block.height <= rollback.ancestor.height {
                    return Err(DepositWorkerError::InvalidEventBatch);
                }
            }
            for id in &rollback.invalidated_sweeps {
                if self.scan.sweep(*id).is_some() {
                    return Err(DepositWorkerError::InvalidEventBatch);
                }
            }
            for id in &rollback.quarantined_sweeps {
                if !matches!(
                    self.scan.sweep(*id).map(|record| record.status),
                    Some(
                        SweepStatus::QuarantinedByReorg { ancestor, .. }
                            | SweepStatus::AbandonedByReorg { ancestor }
                    )
                        if ancestor == rollback.ancestor
                ) {
                    return Err(DepositWorkerError::InvalidEventBatch);
                }
            }
            for id in &rollback.reverted_confirmations {
                if !matches!(
                    self.scan.sweep(*id).map(|record| record.status),
                    Some(SweepStatus::Broadcast { .. })
                ) {
                    return Err(DepositWorkerError::InvalidEventBatch);
                }
            }
        }
        Ok(())
    }

    fn require_no_pending_events(&self) -> Result<(), DepositWorkerError> {
        if let Some(batch) = &self.pending_events {
            return Err(DepositWorkerError::PendingEvents(batch.id));
        }
        Ok(())
    }

    fn observe_sweep_family_transactions(
        &mut self,
        block: ChainPoint,
        transactions: &[SignedSweepTransaction],
    ) -> Result<(), DepositWorkerError> {
        let families = self
            .scan
            .sweeps()
            .filter_map(|record| {
                record.family_key_images.as_ref().map(|binding| {
                    (record.id, binding.key_images().iter().copied().collect::<BTreeSet<_>>())
                })
            })
            .collect::<Vec<_>>();
        for signed in transactions {
            let transaction = signed.transaction()?;
            let Some(observed_images) = transaction_key_images(&transaction) else {
                continue;
            };
            let observed_set = observed_images.iter().copied().collect::<BTreeSet<_>>();
            for (sweep, expected_set) in &families {
                if observed_set.is_disjoint(expected_set) {
                    continue;
                }
                // Any transaction which spends even one pinned family image is security-relevant.
                // A partial/mixed vector or changed destination must halt reconciliation rather
                // than being mistaken for an unrelated root-wallet payment.
                if &observed_set != expected_set {
                    return Err(DepositWorkerError::SweepFamilySpendConflict(*sweep));
                }
                validate_sweep_family_candidate(&self.scan, *sweep, signed)
                    .map_err(|_| DepositWorkerError::SweepFamilySpendConflict(*sweep))?;
                let transaction_id = signed.transaction_id();
                if self.scan.root_transaction_chain_point(transaction_id) != Some(block) {
                    return Err(DepositWorkerError::SweepFamilySpendConflict(*sweep));
                }
                let Transaction::V2 { prefix, .. } = &transaction else {
                    return Err(DepositWorkerError::SweepFamilySpendConflict(*sweep));
                };
                let observed_root_indexes = self
                    .scan
                    .root_outputs()
                    .filter(|output| {
                        output.id().transaction == transaction_id
                            && self.scan.root_output_chain_point(output.id()) == Some(block)
                    })
                    .map(|output| output.id().index_in_transaction)
                    .collect::<BTreeSet<_>>();
                let expected_root_indexes = (0..prefix.outputs.len())
                    .map(|index| {
                        u64::try_from(index).map_err(|_| DepositWorkerError::HeightOverflow)
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?;
                if observed_root_indexes != expected_root_indexes {
                    return Err(DepositWorkerError::SweepFamilySpendConflict(*sweep));
                }
                self.scan.pin_root_transaction(transaction_id, block)?;
                let evidence = SweepFamilySettlementEvidence {
                    sweep: *sweep,
                    signed_transaction: signed.clone(),
                    block,
                };
                if let Some(existing) = self.observed_family_settlements.get(sweep) {
                    if existing != &evidence {
                        return Err(DepositWorkerError::SweepFamilySpendConflict(*sweep));
                    }
                } else {
                    self.observed_family_settlements.insert(*sweep, evidence);
                }
            }
        }
        Ok(())
    }
}

fn verify_deposit_observation_against_scan(
    scan: &ScanState,
    confirmation_depth: u32,
    wallet: DepositWalletId,
    allocation_sequence: u64,
    allocation_statement: [u8; 32],
    allocation: &AllocationStatement,
    observation: &DepositObservationStatement,
) -> Result<VerifiedLocalDepositObservation, DepositWorkerError> {
    let output =
        scan.output(observation.output()).ok_or(DepositWorkerError::InvalidDepositObservation)?;
    let wallet_output = output.wallet_output()?;
    let inclusion = scan
        .output_chain_point(observation.output())
        .ok_or(DepositWorkerError::InvalidDepositObservation)?;
    let current_horizon = scan.tip();
    let statement_horizon = observation.confirmation_horizon();
    let required_distance = u64::from(
        confirmation_depth.checked_sub(1).ok_or(DepositWorkerError::InvalidDepositObservation)?,
    );
    if scan.wallet_id() != wallet
        || observation.wallet_id() != wallet
        || observation.allocation_sequence() != allocation_sequence
        || observation.allocation_statement() != allocation_statement
        || observation.index() != allocation.address.index()
        || observation.output_key() != output.output_key()
        || observation.index_on_blockchain() != output.index_on_blockchain()
        || observation.amount_atomic_units() != wallet_output.commitment().amount
        || observation.observed_block() != inclusion
        || observation.block_timestamp()
            != scan
                .canonical_block_timestamp(inclusion)
                .ok_or(DepositWorkerError::InvalidDepositObservation)?
        || observation.confirmation_depth() != confirmation_depth
        || !scan.authenticates_canonical_chain_point(statement_horizon)
        || inclusion
            .height
            .checked_add(required_distance)
            .is_none_or(|required_horizon| required_horizon > statement_horizon.height)
        || output.subaddress() != observation.index()
        || inclusion.height < allocation.recognition_anchor.height
    {
        return Err(DepositWorkerError::InvalidDepositObservation);
    }
    Ok(VerifiedLocalDepositObservation {
        wallet,
        allocation_statement,
        observation_statement: observation.digest(),
        output: observation.output(),
        verification_horizon: current_horizon,
    })
}

#[cfg(test)]
mod deposit_observation_validation_tests {
    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};
    use monero_wallet::{
        WalletOutput,
        ed25519::{Commitment, Scalar as MoneroScalar},
        transaction::Timelock,
    };

    use super::*;
    use crate::{
        committee::{Member, PartyId},
        compact_epoch_registry::{CompactEpochRegistry, compact_registry_genesis_ledger_head},
        compact_registry_archive::prepare_compact_registry_genesis,
        deposit_index::DepositIndexHead,
        deposit_ledger::{
            LedgerRequestId, LedgerStatement, RequestBinding, sign_deposit_observation_attestation,
        },
        identity::Identity as PartyIdentity,
        key_rotation::VerifiedRegistryHandoffTarget,
    };

    struct ObservationFixture {
        scan: ScanState,
        registry: CompactEpochRegistry,
        allocation: LedgerStatement,
        statement: DepositObservationStatement,
        signer: PartyIdentity,
    }

    fn point(height: u64, byte: u8) -> ChainPoint {
        ChainPoint::new(height, [byte; 32]).unwrap()
    }

    fn append_empty(scan: &mut ScanState, point: ChainPoint, parent: ChainPoint) {
        scan.append_block(
            ScannedBlock { point, parent_hash: parent.hash },
            1_700_000_000 + point.height,
            Vec::new(),
        )
        .unwrap();
    }

    fn test_identity(party: PartyId) -> PartyIdentity {
        let mut signing_seed = [0x41; 32];
        signing_seed[10..12].copy_from_slice(&party.0.to_le_bytes());
        let mut x25519_secret = [0x81; 32];
        x25519_secret[10..12].copy_from_slice(&party.0.to_le_bytes());
        PartyIdentity::from_test_secrets(party, 0, &signing_seed, x25519_secret).unwrap()
    }

    fn persisted_fixture() -> ObservationFixture {
        let root_secret = Scalar::from(42_u64);
        let deriver = DepositAddressDeriver::new(
            NetworkKind::Regtest,
            (ED25519_BASEPOINT_POINT * root_secret).compress().to_bytes(),
            &Zeroizing::new(Scalar::from(17_u64).to_bytes()),
        )
        .unwrap();
        let identities = (1_u16..=4).map(|party| test_identity(PartyId(party))).collect::<Vec<_>>();
        let committee = Committee {
            epoch: 0,
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
        let target = VerifiedRegistryHandoffTarget::for_test(
            committee,
            1,
            [0x51; 32],
            [0x52; 32],
            deriver.wallet_id(),
            [0x53; 32],
            deriver.root_spend_key(),
        )
        .unwrap();
        let first_index = DepositSubaddressIndex::new(0, 1).unwrap();
        let initial_index =
            DepositIndexHead::empty_portable(deriver.wallet_id(), first_index).unwrap();
        let pending =
            prepare_compact_registry_genesis(&target, first_index, initial_index.digest()).unwrap();
        let registry = pending.proposed_head().registry().clone();
        let allocation = LedgerStatement::allocation(
            &registry,
            1,
            compact_registry_genesis_ledger_head(deriver.wallet_id()),
            LedgerRequestId([0x61; 32]),
            RequestBinding([0x62; 32]),
            deriver.derive(first_index),
            point(10, 10),
            1_700_000_000,
        )
        .unwrap();

        let offset = Scalar::from(29_u64);
        let output_key = ED25519_BASEPOINT_POINT * (root_secret + offset);
        let commitment = Commitment::new(MoneroScalar::from(Scalar::from(77_u64)), 9_000_000);
        let mut output_bytes = Vec::new();
        output_bytes.extend_from_slice(&[0x71; 32]);
        output_bytes.extend_from_slice(&0_u64.to_le_bytes());
        output_bytes.extend_from_slice(&577_u64.to_le_bytes());
        output_bytes.extend_from_slice(&output_key.compress().to_bytes());
        output_bytes.extend_from_slice(&offset.to_bytes());
        commitment.write(&mut output_bytes).unwrap();
        Timelock::None.write(&mut output_bytes).unwrap();
        output_bytes.push(1);
        output_bytes.extend_from_slice(&0_u32.to_le_bytes());
        output_bytes.extend_from_slice(&1_u32.to_le_bytes());
        output_bytes.extend_from_slice(&[0, 0]);
        let mut reader = Cursor::new(output_bytes.as_slice());
        let wallet_output = WalletOutput::read(&mut reader).unwrap();
        assert_eq!(usize::try_from(reader.position()).unwrap(), output_bytes.len());
        let output = PersistedWalletOutput::from_scanner(&wallet_output).unwrap();

        let anchor = point(10, 10);
        let inclusion = point(11, 11);
        let statement_horizon = point(12, 12);
        let mut scan = ScanState::new(&deriver, anchor).unwrap();
        scan.append_block(
            ScannedBlock { point: inclusion, parent_hash: anchor.hash },
            1_700_000_011,
            vec![output.clone()],
        )
        .unwrap();
        append_empty(&mut scan, statement_horizon, inclusion);
        let statement = DepositObservationStatement::new(
            &registry,
            &allocation,
            output.id(),
            output.output_key(),
            output.index_on_blockchain(),
            wallet_output.commitment().amount,
            inclusion,
            1_700_000_011,
            statement_horizon,
            2,
        )
        .unwrap();
        let encoded = postcard::to_allocvec(&statement).unwrap();
        let statement: DepositObservationStatement = postcard::from_bytes(&encoded).unwrap();
        statement.validate_active(&registry).unwrap();

        ObservationFixture {
            scan,
            registry,
            allocation,
            statement,
            signer: identities.into_iter().next().unwrap(),
        }
    }

    fn verify(
        fixture: &ObservationFixture,
        scan: &ScanState,
    ) -> Result<VerifiedLocalDepositObservation, DepositWorkerError> {
        let LedgerPayload::Allocation(allocation) = &fixture.allocation.payload else {
            unreachable!();
        };
        verify_deposit_observation_against_scan(
            scan,
            2,
            scan.wallet_id(),
            fixture.allocation.sequence,
            fixture.allocation.digest(),
            allocation,
            &fixture.statement,
        )
    }

    #[test]
    fn persisted_observation_remains_signable_after_scanner_advances() {
        let mut fixture = persisted_fixture();
        append_empty(&mut fixture.scan, point(13, 13), point(12, 12));

        let verified = verify(&fixture, &fixture.scan).unwrap();
        assert_eq!(verified.observation_statement(), fixture.statement.digest());
        assert_eq!(verified.verification_horizon(), point(13, 13));
        sign_deposit_observation_attestation(
            &fixture.signer,
            &fixture.registry,
            &fixture.statement,
        )
        .unwrap();
    }

    #[test]
    fn observation_rejects_replaced_bound_tip_or_output_history() {
        let fixture = persisted_fixture();

        let mut replaced_horizon = fixture.scan.clone();
        replaced_horizon.rollback_to(point(11, 11)).unwrap();
        append_empty(&mut replaced_horizon, point(12, 22), point(11, 11));
        append_empty(&mut replaced_horizon, point(13, 23), point(12, 22));
        assert!(matches!(
            verify(&fixture, &replaced_horizon),
            Err(DepositWorkerError::InvalidDepositObservation)
        ));

        let mut replaced_output = fixture.scan.clone();
        replaced_output.rollback_to(point(10, 10)).unwrap();
        append_empty(&mut replaced_output, point(11, 21), point(10, 10));
        append_empty(&mut replaced_output, point(12, 22), point(11, 21));
        append_empty(&mut replaced_output, point(13, 23), point(12, 22));
        assert!(matches!(
            verify(&fixture, &replaced_output),
            Err(DepositWorkerError::InvalidDepositObservation)
        ));
    }
}

/// Deterministic mature-input consolidation plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SweepPlan {
    /// Stable plan/attempt identifier.
    pub id: SweepId,
    /// Wallet domain.
    pub wallet: DepositWalletId,
    /// Monotonic attempt sequence, consumed on durable reservation.
    pub sequence: u64,
    /// Active proactive-key epoch which will sign.
    pub epoch: u64,
    /// Commitment to the root destination and host policy.
    pub destination_binding: [u8; 32],
    /// Retained point at which maturity was evaluated.
    pub at_tip: ChainPoint,
    /// Sorted, distinct scanner output IDs.
    #[serde(deserialize_with = "deserialize_sweep_plan_inputs")]
    pub inputs: Vec<WalletOutputId>,
    /// Exact decrypted input sum.
    pub total_input_atomic_units: u64,
}

fn deserialize_sweep_plan_inputs<'de, D>(deserializer: D) -> Result<Vec<WalletOutputId>, D::Error>
where
    D: Deserializer<'de>,
{
    struct SweepPlanInputsVisitor;

    impl<'de> Visitor<'de> for SweepPlanInputsVisitor {
        type Value = Vec<WalletOutputId>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "at most {MAX_SWEEP_INPUTS} sweep-plan inputs")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let maximum = usize::from(MAX_SWEEP_INPUTS);
            if sequence.size_hint().is_some_and(|length| length > maximum) {
                return Err(A::Error::custom("sweep plan exceeds its input-count bound"));
            }
            let mut inputs = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(maximum));
            while let Some(input) = sequence.next_element()? {
                if inputs.len() == maximum {
                    return Err(A::Error::custom("sweep plan exceeds its input-count bound"));
                }
                inputs.push(input);
            }
            Ok(inputs)
        }
    }

    deserializer.deserialize_seq(SweepPlanInputsVisitor)
}

#[cfg(test)]
mod sweep_plan_decode_tests {
    use super::*;

    #[test]
    fn serde_rejects_oversized_input_vector() {
        let plan = SweepPlan {
            id: SweepId([1; 32]),
            wallet: DepositWalletId([2; 32]),
            sequence: 1,
            epoch: 1,
            destination_binding: [3; 32],
            at_tip: ChainPoint::new(1, [4; 32]).unwrap(),
            inputs: vec![
                WalletOutputId { transaction: [5; 32], index_in_transaction: 0 };
                usize::from(MAX_SWEEP_INPUTS) + 1
            ],
            total_input_atomic_units: 1,
        };
        let encoded = postcard::to_allocvec(&plan).unwrap();
        assert!(postcard::from_bytes::<SweepPlan>(&encoded).is_err());
    }
}

impl SweepPlan {
    /// Verify the self-contained public structure and its content-derived sweep identifier.
    ///
    /// This intentionally does not require local scanner state: archive/BA voters use it before a
    /// public successor has reconstructed historical outputs. State-dependent maturity, inclusion,
    /// amount, and destination policy checks remain separate worker admission requirements.
    pub fn validate_public(&self) -> Result<(), DepositWorkerError> {
        if self.id.0 == [0; 32]
            || self.wallet.0 == [0; 32]
            || self.destination_binding == [0; 32]
            || self.at_tip.hash == [0; 32]
            || self.inputs.is_empty()
            || self.inputs.len() > usize::from(MAX_SWEEP_INPUTS)
            || self.inputs.windows(2).any(|window| window[0] >= window[1])
            || self.total_input_atomic_units == 0
            || self.id.0 != sweep_plan_commitment(self)
        {
            return Err(DepositWorkerError::StaleSweepPlan);
        }
        Ok(())
    }

    /// Stable commitment used as the sweep ID and bound into transaction authorization.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        sweep_plan_commitment(self)
    }
}

/// Canonical, sensitive prepared intent which every signer independently reconstructs.
///
/// The outgoing-view seed and exact decoy inputs are private wallet material. Carry this only over
/// the authenticated encrypted party channel and store it only inside encrypted snapshots.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedSweepIntent {
    version: u16,
    plan: SweepPlan,
    outgoing_view_key: [u8; 32],
    decoy_inputs: Vec<Vec<u8>>,
    fee_rate: Vec<u8>,
    transaction_commitment: [u8; 32],
    fee_atomic_units: u64,
}

impl std::fmt::Debug for PreparedSweepIntent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSweepIntent")
            .field("version", &self.version)
            .field("plan", &self.plan)
            .field("outgoing_view_key", &"<redacted>")
            .field("decoy_inputs", &"<redacted>")
            .field("fee_rate", &"<redacted>")
            .field("transaction_commitment", &hex::encode(self.transaction_commitment))
            .field("fee_atomic_units", &self.fee_atomic_units)
            .finish()
    }
}

impl Drop for PreparedSweepIntent {
    fn drop(&mut self) {
        self.outgoing_view_key.zeroize();
        for input in &mut self.decoy_inputs {
            input.zeroize();
        }
        self.fee_rate.zeroize();
    }
}

impl PreparedSweepIntent {
    /// Return the exact sweep plan authorized by this representation.
    #[must_use]
    pub const fn plan(&self) -> &SweepPlan {
        &self.plan
    }

    /// Commitment to the reconstructed signable transaction and plan.
    #[must_use]
    pub const fn transaction_commitment(&self) -> [u8; 32] {
        self.transaction_commitment
    }

    /// Exact fee encoded by this prepared representation and recomputed during worker validation.
    #[must_use]
    pub const fn fee_atomic_units(&self) -> u64 {
        self.fee_atomic_units
    }

    /// Domain-separated digest of the complete canonical prepared representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the private representation is structurally invalid or oversized.
    pub fn digest(&self) -> Result<[u8; 32], DepositWorkerError> {
        let encoded = Zeroizing::new(self.encode()?);
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/prepared-sweep-intent/v1");
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Canonically encode the sensitive representation with a hard message bound.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed structure, serialization failure, or oversize output.
    pub fn encode(&self) -> Result<Vec<u8>, DepositWorkerError> {
        self.validate_structure()?;
        let bytes = postcard::to_allocvec(self).map_err(|_| DepositWorkerError::Serialization)?;
        if bytes.len() > MAX_PREPARED_SWEEP_INTENT_BYTES {
            return Err(DepositWorkerError::PreparedSweepIntentTooLarge);
        }
        Ok(bytes)
    }

    /// Decode exactly one canonical, size-bounded sensitive representation.
    ///
    /// This checks only structural/canonical fields. Call
    /// [`DepositWorkerState::verify_prepared_sweep_intent`] before reservation or signing.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, trailing, non-canonical, or invalid structure.
    pub fn decode(bytes: &[u8]) -> Result<Self, DepositWorkerError> {
        if bytes.len() > MAX_PREPARED_SWEEP_INTENT_BYTES {
            return Err(DepositWorkerError::PreparedSweepIntentTooLarge);
        }
        let (intent, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| DepositWorkerError::Serialization)?;
        if !trailing.is_empty() {
            return Err(DepositWorkerError::NonCanonicalPreparedSweepIntent);
        }
        intent.validate_structure()?;
        if intent.encode()? != bytes {
            return Err(DepositWorkerError::NonCanonicalPreparedSweepIntent);
        }
        Ok(intent)
    }

    fn validate_structure(&self) -> Result<(), DepositWorkerError> {
        if self.version != PREPARED_SWEEP_INTENT_VERSION
            || self.plan.id.0 != sweep_plan_commitment(&self.plan)
            || self.outgoing_view_key == [0_u8; 32]
            || self.decoy_inputs.len() != self.plan.inputs.len()
            || self.decoy_inputs.is_empty()
            || self
                .decoy_inputs
                .iter()
                .any(|input| input.is_empty() || input.len() > MAX_PREPARED_DECOY_INPUT_BYTES)
            || self.transaction_commitment == [0_u8; 32]
            || self.fee_atomic_units == 0
        {
            return Err(DepositWorkerError::InvalidPreparedSweep);
        }
        decode_fee_rate(&self.fee_rate)?;
        Ok(())
    }
}

/// Exact Monero transaction ready for a normal root-key FROSTLASS signing session.
pub struct PreparedFrostlassSweep {
    plan: SweepPlan,
    transaction: SignableTransaction,
    transaction_commitment: [u8; 32],
    fee_atomic_units: u64,
    prepared_intent: PreparedSweepIntent,
}

impl std::fmt::Debug for PreparedFrostlassSweep {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedFrostlassSweep")
            .field("plan", &self.plan)
            .field("transaction_commitment", &hex::encode(self.transaction_commitment))
            .field("fee_atomic_units", &self.fee_atomic_units)
            .finish_non_exhaustive()
    }
}

impl PreparedFrostlassSweep {
    /// Return the exact deterministic input plan.
    #[must_use]
    pub const fn plan(&self) -> &SweepPlan {
        &self.plan
    }

    /// Return the transaction for signing-context calculation and FROSTLASS.
    #[must_use]
    pub const fn transaction(&self) -> &SignableTransaction {
        &self.transaction
    }

    /// Commitment to the plan and complete serialized signable transaction.
    #[must_use]
    pub const fn transaction_commitment(&self) -> [u8; 32] {
        self.transaction_commitment
    }

    /// Exact necessary fee calculated by monero-wallet.
    #[must_use]
    pub const fn fee_atomic_units(&self) -> u64 {
        self.fee_atomic_units
    }

    /// Return the canonical sensitive representation for authenticated follower validation.
    #[must_use]
    pub const fn prepared_intent(&self) -> &PreparedSweepIntent {
        &self.prepared_intent
    }

    /// Consume the wrapper and return the exact signable transaction.
    #[must_use]
    pub fn into_transaction(self) -> SignableTransaction {
        self.transaction.clone()
    }
}

fn validate_fetched_block_shape(
    config: DepositWorkerConfig,
    block: &FetchedDepositBlock,
    requested_height: u64,
) -> Result<(), DepositWorkerError> {
    if block.hardfork_version > MAX_SUPPORTED_HARDFORK {
        return Err(DepositWorkerError::UnsupportedHardfork(block.hardfork_version));
    }
    if block.block.point.height != requested_height {
        return Err(DepositWorkerError::WrongBlockHeight {
            requested: requested_height,
            received: block.block.point.height,
        });
    }
    let output_count = block.outputs.len().checked_add(block.root_outputs.len()).ok_or(
        DepositWorkerError::TooManyWalletOutputs {
            actual: usize::MAX,
            maximum: config.max_outputs_per_block,
        },
    )?;
    if output_count > usize::from(config.max_outputs_per_block) {
        return Err(DepositWorkerError::TooManyWalletOutputs {
            actual: output_count,
            maximum: config.max_outputs_per_block,
        });
    }
    Ok(())
}

fn output_bindings(
    block: &FetchedDepositBlock,
) -> Result<Vec<DepositOutputBinding>, DepositWorkerError> {
    let output_count = block.outputs.len().checked_add(block.root_outputs.len()).ok_or(
        DepositWorkerError::TooManyAtomicOutputBindings {
            actual: usize::MAX,
            maximum: MAX_ATOMIC_OUTPUT_BINDINGS,
        },
    )?;
    if output_count > MAX_ATOMIC_OUTPUT_BINDINGS {
        return Err(DepositWorkerError::TooManyAtomicOutputBindings {
            actual: output_count,
            maximum: MAX_ATOMIC_OUTPUT_BINDINGS,
        });
    }
    let mut bindings = block
        .outputs
        .iter()
        .map(|output| {
            let wallet_output = output.wallet_output()?;
            Ok(DepositOutputBinding {
                output: output.id(),
                output_key: output.output_key(),
                subaddress: Some(output.subaddress()),
                amount_atomic_units: wallet_output.commitment().amount,
                observed_at: block.timestamp,
            })
        })
        .chain(block.root_outputs.iter().map(|output| {
            let wallet_output = output.wallet_output()?;
            Ok(DepositOutputBinding {
                output: output.id(),
                output_key: output.output_key(),
                subaddress: None,
                amount_atomic_units: wallet_output.commitment().amount,
                observed_at: block.timestamp,
            })
        }))
        .collect::<Result<Vec<_>, DepositWorkerError>>()?;
    bindings.sort_unstable_by_key(|binding| binding.output);
    if bindings.windows(2).any(|window| window[0].output == window[1].output) {
        return Err(DepositWorkerError::CorruptState);
    }
    Ok(bindings)
}

fn validate_fetched_output_chunk(
    root_spend_key: [u8; 32],
    block: &FetchedDepositBlock,
) -> Result<(), DepositWorkerError> {
    for output in &block.outputs {
        output.validate(root_spend_key)?;
    }
    for output in &block.root_outputs {
        output.validate(root_spend_key)?;
    }
    Ok(())
}

fn merge_wallet_output_chunks(
    outputs: &mut Vec<PersistedWalletOutput>,
    additional: Vec<PersistedWalletOutput>,
) -> Result<(), DepositWorkerError> {
    outputs.extend(additional);
    outputs.sort_unstable_by_key(PersistedWalletOutput::id);
    let mut merged: Vec<PersistedWalletOutput> = Vec::with_capacity(outputs.len());
    for output in outputs.drain(..) {
        if let Some(prior) = merged.last()
            && prior.id() == output.id()
        {
            if prior != &output {
                return Err(DepositWorkerError::CorruptState);
            }
            continue;
        }
        merged.push(output);
    }
    *outputs = merged;
    Ok(())
}

fn merge_root_output_chunks(
    outputs: &mut Vec<PersistedRootOutput>,
    additional: Vec<PersistedRootOutput>,
) -> Result<(), DepositWorkerError> {
    outputs.extend(additional);
    outputs.sort_unstable_by_key(PersistedRootOutput::id);
    let mut merged: Vec<PersistedRootOutput> = Vec::with_capacity(outputs.len());
    for output in outputs.drain(..) {
        if let Some(prior) = merged.last()
            && prior.id() == output.id()
        {
            if prior != &output {
                return Err(DepositWorkerError::CorruptState);
            }
            continue;
        }
        merged.push(output);
    }
    *outputs = merged;
    Ok(())
}

async fn request<T>(
    duration: Duration,
    operation: &'static str,
    height: Option<u64>,
    future: ChainFuture<'_, T>,
) -> Result<T, DepositWorkerError> {
    timeout(duration, future)
        .await
        .map_err(|_| DepositWorkerError::RequestTimeout { operation, height })?
        .map_err(|error| match error {
            ChainSourceError::UnsupportedHardfork(version) => {
                DepositWorkerError::UnsupportedHardfork(version)
            }
            other => DepositWorkerError::ChainSource(other),
        })
}

/// Await a party-local durable output binding to completion, without the per-operation daemon
/// deadline that [`request`] applies.
///
/// `bind_outputs` writes the party-local burning-bug safety index through encrypted storage; it is
/// not a monero-daemon RPC. The daemon deadline exists to bound an unresponsive remote node, and
/// applying it to this binding is a category error with a concrete liveness failure: elapsing the
/// deadline cancels the in-flight future mid-fsync, and that interrupted attempt leaves a pending
/// index journal every retry must first roll back. When the binding cannot fit inside the deadline
/// at all, the scanner can never durably record a confirmed output and the deposit-observation
/// pipeline stalls permanently. The storage layer already fails closed on conflicting bindings and
/// recovers its own journals idempotently, so this local transition must run to completion.
async fn bind_local_outputs(future: ChainFuture<'_, ()>) -> Result<(), DepositWorkerError> {
    future.await.map_err(|error| match error {
        ChainSourceError::UnsupportedHardfork(version) => {
            DepositWorkerError::UnsupportedHardfork(version)
        }
        other => DepositWorkerError::ChainSource(other),
    })
}

fn output_scan_failure<E: std::fmt::Display>(
    error: DepositOutputScanFailure<E>,
) -> ChainSourceError {
    match error {
        DepositOutputScanFailure::Scan(
            crate::deposit_output_scanner::DepositOutputScanError::UnsupportedHardfork(version),
        ) => ChainSourceError::UnsupportedHardfork(version),
        other => ChainSourceError::Invalid(other.to_string()),
    }
}

fn expanded_transaction_at<'a>(
    miner_hash: [u8; 32],
    miner: &'a Transaction<Pruned>,
    transaction_ids: &[[u8; 32]],
    transactions: &'a [Transaction<Pruned>],
    index: usize,
) -> Option<([u8; 32], &'a Transaction<Pruned>)> {
    if index == 0 {
        Some((miner_hash, miner))
    } else {
        let index = index.checked_sub(1)?;
        Some((*transaction_ids.get(index)?, transactions.get(index)?))
    }
}

fn decode_fee_rate(bytes: &[u8]) -> Result<FeeRate, DepositWorkerError> {
    let mut cursor = Cursor::new(bytes);
    let rate = FeeRate::read(&mut cursor).map_err(|_| DepositWorkerError::InvalidPreparedSweep)?;
    if usize::try_from(cursor.position()).ok() != Some(bytes.len()) || rate.serialize() != bytes {
        return Err(DepositWorkerError::InvalidPreparedSweep);
    }
    Ok(rate)
}

fn decode_decoy_input(bytes: &[u8]) -> Result<OutputWithDecoys, DepositWorkerError> {
    if bytes.is_empty() || bytes.len() > MAX_PREPARED_DECOY_INPUT_BYTES {
        return Err(DepositWorkerError::InvalidPreparedSweep);
    }
    let mut cursor = Cursor::new(bytes);
    let input = OutputWithDecoys::read(&mut cursor)
        .map_err(|_| DepositWorkerError::InvalidPreparedSweep)?;
    if usize::try_from(cursor.position()).ok() != Some(bytes.len()) || input.serialize() != bytes {
        return Err(DepositWorkerError::InvalidPreparedSweep);
    }
    Ok(input)
}

fn validate_certified_sweep_transaction(
    signed: &SignedSweepTransaction,
    input_count: usize,
    maximum_fee: u64,
) -> Result<(), DepositWorkerError> {
    let transaction = signed.transaction()?;
    let Transaction::V2 { prefix, proofs: Some(proofs) } = transaction else {
        return Err(DepositWorkerError::InvalidCertifiedSweep);
    };
    if proofs.rct_type() != RctType::ClsagBulletproofPlus
        || proofs.base.fee == 0
        || proofs.base.fee > maximum_fee
        || prefix.inputs.len() != input_count
        || prefix.outputs.len() != 2
        || prefix.inputs.iter().any(|input| {
            !matches!(
                input,
                monero_oxide::transaction::Input::ToKey { key_offsets, .. }
                    if key_offsets.len() == 16
            )
        })
    {
        return Err(DepositWorkerError::InvalidCertifiedSweep);
    }
    Ok(())
}

fn certified_sweep_fee(signed: &SignedSweepTransaction) -> Result<u64, DepositWorkerError> {
    let transaction = signed.transaction()?;
    let Transaction::V2 { proofs: Some(proofs), .. } = transaction else {
        return Err(DepositWorkerError::InvalidCertifiedSweep);
    };
    Ok(proofs.base.fee)
}

/// Return the exact key images encoded by a canonical signed sweep, in transaction-input order.
///
/// This is useful when replaying an already authenticated ledger certificate, whose statement
/// commits to the exact transaction bytes. For live completion BA, callers should instead
/// canonicalize the separately verified all-selected key-image certificate and pass that vector to
/// [`DepositWorkerState::verify_public_sweep_completion`].
pub fn canonical_sweep_transaction_key_images(
    signed: &SignedSweepTransaction,
) -> Result<Vec<[u8; 32]>, DepositWorkerError> {
    certified_sweep_key_images(signed)
}

/// Canonicalize a verified all-selected key-image certificate into Monero transaction-input order.
///
/// Monero sorts `ToKey` inputs by key image in descending byte order. Zero or duplicate public
/// spentness markers are rejected before the vector can be bound to a public completion token.
pub fn canonicalize_certified_sweep_key_images(
    key_images: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>, DepositWorkerError> {
    if key_images.is_empty()
        || key_images.iter().any(|image| *image == [0; 32])
        || key_images.iter().copied().collect::<BTreeSet<_>>().len() != key_images.len()
    {
        return Err(DepositWorkerError::InvalidCertifiedSweep);
    }
    let mut canonical = key_images.to_vec();
    canonical.sort_unstable_by(|left, right| right.cmp(left));
    Ok(canonical)
}

fn certified_sweep_key_images(
    signed: &SignedSweepTransaction,
) -> Result<Vec<[u8; 32]>, DepositWorkerError> {
    let transaction = signed.transaction()?;
    let Transaction::V2 { prefix, .. } = transaction else {
        return Err(DepositWorkerError::InvalidCertifiedSweep);
    };
    let key_images = prefix
        .inputs
        .iter()
        .map(|input| match input {
            Input::ToKey { key_image, .. } => Ok(key_image.to_bytes()),
            Input::Gen(_) => Err(DepositWorkerError::InvalidCertifiedSweep),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if key_images.iter().any(|image| *image == [0; 32])
        || key_images.iter().copied().collect::<BTreeSet<_>>().len() != key_images.len()
    {
        return Err(DepositWorkerError::InvalidCertifiedSweep);
    }
    Ok(key_images)
}

fn verified_portable_publication(
    publication: &CertifiedSweepPublication,
    wallet: DepositWalletId,
) -> Result<VerifiedPortableSweepTerminal, DepositWorkerError> {
    VerifiedPortableSweepTerminal::from_verified_public_completion(
        wallet,
        publication.sweep,
        publication.inputs.clone(),
        publication.signed_transaction.transaction_id(),
        publication.certificate_digest,
        publication.portable_terminal_digest,
    )
    .map_err(DepositWorkerError::Wallet)
}

fn signed_binding_matches_certified_bytes(
    binding: SignedTransactionBinding,
    signed: &SignedSweepTransaction,
) -> bool {
    binding.transaction() == signed.transaction_id()
        && binding.exact_bytes_digest() == consolidation_signed_bytes_binding(signed.as_bytes())
        && usize::try_from(binding.exact_bytes_len()).ok() == Some(signed.as_bytes().len())
}

fn validate_sweep_family_candidate(
    scan: &ScanState,
    id: SweepId,
    signed: &SignedSweepTransaction,
) -> Result<(), DepositWorkerError> {
    scan.validate_sweep_family_candidate_shape(id, signed)?;
    let record = scan.sweep(id).ok_or(DepositWalletError::UnknownSweep(id))?;
    let binding =
        record.family_key_images.as_ref().ok_or(DepositWalletError::MissingSweepFamilyKeyImages)?;
    let prepared =
        PreparedSweepIntent::decode(record.signing_intent.prepared_sweep_intent_bytes())?;
    prepared.validate_structure()?;
    if prepared.plan.id != id
        || prepared.plan.inputs != record.inputs
        || prepared.decoy_inputs.len() != record.inputs.len()
        || binding.inputs() != record.inputs
    {
        return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
    }

    let decoded_inputs = prepared
        .decoy_inputs
        .iter()
        .map(|bytes| decode_decoy_input(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let transaction = signed.transaction()?;
    let Transaction::V2 { prefix, proofs: Some(proofs) } = &transaction else {
        return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
    };
    let RctPrunable::Clsag { bulletproof, clsags, pseudo_outs } = &proofs.prunable else {
        return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
    };
    if proofs.rct_type() != RctType::ClsagBulletproofPlus
        || proofs.base.fee != record.signing_intent.fee_atomic_units()
        || proofs.base.pseudo_outs.len() != 0
        || proofs.base.commitments.len() != prefix.outputs.len()
        || proofs.base.encrypted_amounts.len() != prefix.outputs.len()
        || clsags.len() != record.inputs.len()
        || pseudo_outs.len() != record.inputs.len()
        || prefix.inputs.len() != record.inputs.len()
    {
        return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
    }
    if unsigned_sweep_transaction_digest(&transaction)? != binding.unsigned_transaction_digest() {
        return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
    }

    let mut ordered_inputs =
        binding.key_images().iter().copied().zip(decoded_inputs.iter()).collect::<Vec<_>>();
    ordered_inputs.sort_unstable_by(|(left, _), (right, _)| right.cmp(left));
    for ((input, (expected_image, prepared_input)), expected_position) in
        prefix.inputs.iter().zip(&ordered_inputs).zip(0_usize..)
    {
        let Input::ToKey { amount: None, key_offsets, key_image } = input else {
            return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
        };
        if key_image.to_bytes() != *expected_image
            || key_offsets.as_slice() != prepared_input.decoys().offsets()
            || prepared_input.decoys().len() != 16
            || expected_position >= record.inputs.len()
        {
            return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
        }
    }

    let signature_hash =
        transaction.signature_hash().ok_or(DepositWorkerError::InvalidSweepFamilyCandidate)?;
    for (((clsag, pseudo_out), input), prepared_input) in clsags
        .iter()
        .zip(pseudo_outs)
        .zip(&prefix.inputs)
        .zip(ordered_inputs.iter().map(|(_, input)| *input))
    {
        let Input::ToKey { key_image, .. } = input else {
            return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
        };
        let ring = prepared_input
            .decoys()
            .ring()
            .iter()
            .map(|member| [member[0].compress(), member[1].compress()])
            .collect();
        clsag
            .verify(ring, key_image, pseudo_out, &signature_hash)
            .map_err(|_| DepositWorkerError::InvalidSweepFamilyCandidate)?;
    }

    if !bulletproof.verify(&mut OsRng, &proofs.base.commitments) {
        return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
    }
    let pseudo_sum = sum_compressed_points(pseudo_outs)?;
    let output_sum = sum_compressed_points(&proofs.base.commitments)?;
    let h: EdwardsPoint = MoneroCompressedPoint::H
        .decompress()
        .ok_or(DepositWorkerError::InvalidSweepFamilyCandidate)?
        .into();
    if pseudo_sum != output_sum + (h * DalekScalar::from(proofs.base.fee)) {
        return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
    }
    Ok(())
}

fn transaction_key_images(transaction: &Transaction) -> Option<Vec<[u8; 32]>> {
    let Transaction::V2 { prefix, proofs: Some(_), .. } = transaction else {
        return None;
    };
    prefix
        .inputs
        .iter()
        .map(|input| match input {
            Input::ToKey { key_image, .. } => Some(key_image.to_bytes()),
            Input::Gen(_) => None,
        })
        .collect()
}

fn unsigned_sweep_transaction_digest(
    transaction: &Transaction,
) -> Result<[u8; 32], DepositWorkerError> {
    let mut unsigned = transaction.clone();
    let Transaction::V2 { proofs: Some(proofs), .. } = &mut unsigned else {
        return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
    };
    let RctPrunable::Clsag { clsags, pseudo_outs, .. } = &mut proofs.prunable else {
        return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
    };
    clsags.clear();
    pseudo_outs.clear();
    let bytes = unsigned.serialize();
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/deposit-sweep-unsigned-transaction/v1");
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn sum_compressed_points(
    points: &[MoneroCompressedPoint],
) -> Result<EdwardsPoint, DepositWorkerError> {
    points.iter().try_fold(EdwardsPoint::identity(), |sum, encoded| {
        let point: EdwardsPoint =
            encoded.decompress().ok_or(DepositWorkerError::InvalidSweepFamilyCandidate)?.into();
        if !point.is_torsion_free() {
            return Err(DepositWorkerError::InvalidSweepFamilyCandidate);
        }
        Ok(sum + point)
    })
}

fn event_batch_id(batch: &WorkerEventBatch) -> [u8; 32] {
    let mut canonical = batch.clone();
    canonical.id = [0_u8; 32];
    let encoded = postcard::to_allocvec(&canonical)
        .expect("bounded worker event fields always have a postcard encoding");
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/deposit-worker-events/v1");
    hasher.update(&[u8::try_from(EVENT_BATCH_VERSION).expect("event version fits in u8")]);
    hasher.update(&encoded);
    *hasher.finalize().as_bytes()
}

fn sweep_plan_commitment(plan: &SweepPlan) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/deposit-sweep-plan/v1");
    hasher.update(&plan.wallet.0);
    hasher.update(&plan.sequence.to_le_bytes());
    hasher.update(&plan.epoch.to_le_bytes());
    hasher.update(&plan.destination_binding);
    hasher.update(&plan.at_tip.height.to_le_bytes());
    hasher.update(&plan.at_tip.hash);
    hasher.update(&u64::try_from(plan.inputs.len()).unwrap_or(u64::MAX).to_le_bytes());
    for input in &plan.inputs {
        hasher.update(&input.transaction);
        hasher.update(&input.index_in_transaction.to_le_bytes());
    }
    hasher.update(&plan.total_input_atomic_units.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn transaction_commitment(plan: &SweepPlan, transaction: &SignableTransaction) -> [u8; 32] {
    let mut encoded = transaction.serialize();
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/deposit-frostlass-transaction/v1");
    hasher.update(&plan.id.0);
    hasher.update(&encoded);
    let commitment = *hasher.finalize().as_bytes();
    encoded.zeroize();
    commitment
}

/// Commit to the exact primary-wallet consolidation destination and worker policy.
///
/// Pass this value to [`DepositWorkerState::plan_sweep`] when the transaction will be built by
/// [`PinnedMoneroDaemon::prepare_frostlass_sweep`]. The commitment includes the two-root-output
/// BP+ construction version and the persisted limits which affect input selection/finality/fees.
#[must_use]
pub fn root_consolidation_destination_binding(
    deriver: &DepositAddressDeriver,
    config: DepositWorkerConfig,
) -> [u8; 32] {
    let address = deriver.primary_address();
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/root-consolidation-policy/v1");
    hasher.update(&deriver.wallet_id().0);
    hasher.update(&u64::try_from(address.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(address.as_bytes());
    hasher.update(&config.confirmation_depth.to_le_bytes());
    hasher.update(&config.max_reorg_depth.to_le_bytes());
    hasher.update(&config.max_sweep_inputs.to_le_bytes());
    hasher.update(&config.max_retained_outputs.to_le_bytes());
    hasher.update(&config.minimum_sweep_atomic_units.to_le_bytes());
    hasher.update(&config.maximum_fee_atomic_units.to_le_bytes());
    hasher.update(b"clsag-bulletproof-plus/one-atomic-unit-payment-plus-standard-change");
    *hasher.finalize().as_bytes()
}

fn address_network(network: NetworkKind) -> Network {
    match network {
        NetworkKind::Regtest | NetworkKind::Mainnet => Network::Mainnet,
        NetworkKind::Testnet => Network::Testnet,
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn usize_height(height: u64) -> Result<usize, DepositWorkerError> {
    usize::try_from(height).map_err(|_| DepositWorkerError::HeightOverflow)
}

fn usize_height_source(height: u64) -> Result<usize, ChainSourceError> {
    usize::try_from(height).map_err(|_| ChainSourceError::HeightOverflow)
}

/// Error produced by a concrete or mock chain source.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChainSourceError {
    /// Scanner-only deployment deliberately configured no consolidation backend.
    #[error("deposit consolidation backend is not configured")]
    BackendUnavailable,
    /// Exact sweep preparation failed.
    #[error("deposit consolidation preparation failed: {0}")]
    Consolidation(String),
    /// Canonical transaction publication failed.
    #[error("deposit consolidation publication failed: {0}")]
    Publication(String),
    /// RPC or interface failure.
    #[error("Monero RPC failed: {0}")]
    Rpc(String),
    /// The daemon returned internally inconsistent scanner material.
    #[error("invalid Monero chain source response: {0}")]
    Invalid(String),
    /// A height could not fit the local daemon interface.
    #[error("Monero block height exceeds this platform")]
    HeightOverflow,
    /// The daemon reached a hardfork newer than the pinned scanner supports.
    #[error("unsupported Monero hardfork {0}")]
    UnsupportedHardfork(u8),
    /// Expanded block transaction bound was exceeded.
    #[error("expanded block has {actual} transactions; maximum is {maximum}")]
    TooManyTransactions { actual: usize, maximum: usize },
    /// Expanded block serialized-size bound was exceeded.
    #[error("expanded block has {actual} bytes; maximum is {maximum}")]
    ExpandedBlockTooLarge { actual: usize, maximum: usize },
}

/// Error returned by the autonomous deposit worker.
#[derive(Debug, Error)]
pub enum DepositWorkerError {
    /// Persisted worker resource policy was invalid.
    #[error("invalid deposit worker configuration")]
    InvalidConfig,
    /// Concrete daemon adapter limits were invalid.
    #[error("invalid Monero RPC limits")]
    InvalidRpcLimits,
    /// Worker state schema is unsupported.
    #[error("unsupported deposit worker state version {0}")]
    UnsupportedStateVersion(u16),
    /// Canonical state serialization failed.
    #[error("deposit worker serialization failed")]
    Serialization,
    /// Serialized state was not its canonical postcard encoding.
    #[error("non-canonical deposit worker state")]
    NonCanonicalState,
    /// State exceeded its hard storage bound.
    #[error("deposit worker state exceeds its hard size bound")]
    StateTooLarge,
    /// Wallet-specific validation failed.
    #[error("deposit wallet error: {0}")]
    Wallet(#[from] DepositWalletError),
    /// Private view material did not match the durable wallet domain.
    #[error("deposit worker belongs to another wallet domain")]
    WrongWalletDomain,
    /// A certified attempt could not be reconstructed below the durable family high-water.
    #[error("invalid or unrecognized sweep signing attempt")]
    InvalidSweepSigningAttempt,
    /// A chain-source operation failed.
    #[error("chain source error: {0}")]
    ChainSource(ChainSourceError),
    /// A direct concrete daemon operation failed.
    #[error("Monero daemon operation failed: {0}")]
    Daemon(String),
    /// `get_info` was not the complete bounded identity response required at startup.
    #[error("invalid Monero daemon network report: {0}")]
    InvalidDaemonNetworkReport(String),
    /// The daemon did not report a successful identity query.
    #[error("Monero daemon network report returned status {0:?}")]
    DaemonStatus(String),
    /// Bootstrap-proxied identity data cannot authenticate the configured local daemon.
    #[error("Monero daemon network report was supplied by an untrusted bootstrap daemon")]
    UntrustedDaemonNetworkReport,
    /// The configured logical network and the daemon's exact Monero nettype differ.
    #[error("Monero daemon nettype {actual:?} does not match configured nettype {expected:?}")]
    DaemonNetworkMismatch { expected: &'static str, actual: String },
    /// The redundant boolean network fields disagreed with the daemon's configured nettype.
    #[error(
        "Monero daemon nettype {nettype:?} has inconsistent flags mainnet={mainnet}, testnet={testnet}, stagenet={stagenet}"
    )]
    InconsistentDaemonNetworkFlags { nettype: String, mainnet: bool, testnet: bool, stagenet: bool },
    /// The daemon served a different chain's block zero.
    #[error(
        "Monero daemon genesis {} does not match configured genesis {}",
        hex::encode(actual),
        hex::encode(expected)
    )]
    DaemonGenesisMismatch { expected: [u8; 32], actual: [u8; 32] },
    /// A bounded daemon operation timed out.
    #[error("Monero daemon timeout during {operation} at height {height:?}")]
    RequestTimeout { operation: &'static str, height: Option<u64> },
    /// Daemon tip was before the configured trusted anchor.
    #[error("daemon height {daemon} is behind trusted anchor {anchor}")]
    DaemonBehindAnchor { daemon: u64, anchor: u64 },
    /// Daemon tip was behind already durable scanner state; no destructive rollback was attempted.
    #[error("daemon height {daemon} is behind durable scanner tip {state}")]
    DaemonBehindState { daemon: u64, state: u64 },
    /// Trusted anchor no longer matched the daemon chain.
    #[error("trusted Monero anchor no longer matches at height {}", .0.height)]
    AnchorMismatch(ChainPoint),
    /// Common ancestor search exceeded its configured bound.
    #[error("Monero reorganization exceeds maximum search depth {maximum}")]
    ReorgDepthExceeded { maximum: u32 },
    /// Fetched block height did not match the request.
    #[error("requested block {requested}, received block {received}")]
    WrongBlockHeight { requested: u64, received: u64 },
    /// Scanner result count exceeded its persisted bound.
    #[error("block has {actual} wallet outputs; maximum is {maximum}")]
    TooManyWalletOutputs { actual: usize, maximum: u16 },
    /// One resumable scanner chunk exceeded the proven atomic local-index update bound.
    #[error("scanner chunk has {actual} wallet outputs; atomic binding maximum is {maximum}")]
    TooManyAtomicOutputBindings { actual: usize, maximum: usize },
    /// Permanent output/evidence capacity was reached; nothing was silently discarded.
    #[error("deposit scanner retains {retained} outputs/evidence; configured maximum is {maximum}")]
    RetentionCapacityExceeded { retained: usize, maximum: u32 },
    /// The pinned scanner has not been audited for this hardfork.
    #[error("unsupported Monero scanner hardfork {0}")]
    UnsupportedHardfork(u8),
    /// The FROSTLASS transaction builder only supports current CLSAG/BP+ hardforks.
    #[error("unsupported Monero signing hardfork {0}")]
    UnsupportedSigningHardfork(u8),
    /// A pending batch must be applied/acknowledged before more state changes.
    #[error("deposit worker event batch {} is pending", hex::encode(.0))]
    PendingEvents([u8; 32]),
    /// No pending batch existed to acknowledge.
    #[error("deposit worker has no pending event batch")]
    NoPendingEvents,
    /// Event acknowledgement named another batch.
    #[error("wrong deposit worker event batch")]
    WrongEventBatch,
    /// Restored/staged event data was inconsistent.
    #[error("invalid durable deposit worker event batch")]
    InvalidEventBatch,
    /// Persistence acknowledgement did not name the exact current state.
    #[error("deposit worker persistence acknowledgement mismatch")]
    PersistenceMismatch,
    /// Durable revision was exhausted.
    #[error("deposit worker revision exhausted")]
    RevisionExhausted,
    /// Durable scan state was internally inconsistent.
    #[error("corrupt deposit worker state")]
    CorruptState,
    /// Portable allocation head was not initialized at the fresh worker birth anchor.
    #[error("portable deposit-index head is not initialized")]
    PortableIndexHeadUninitialized,
    /// A portable head changed without its semantically verified index transition.
    #[error("portable deposit-index head changed without a verified transition")]
    PortableIndexHeadChanged,
    /// A scanner transition did not extend the exact current ready/backfill head.
    #[error("invalid verified portable scanner transition")]
    InvalidPortableIndexTransition,
    /// Ordinary scanning/status is gated until the durable allocation backfill completes.
    #[error("allocation backfill must complete before this operation")]
    AllocationBackfillRequired,
    /// No allocation backfill was pending.
    #[error("no allocation backfill is pending")]
    AllocationBackfillNotPending,
    /// The fixed backfill branch changed before its durable frontier completed.
    #[error("allocation backfill canonical branch changed")]
    AllocationBackfillBranchChanged,
    /// Proposed portable output observation did not match the exact confirmed local rescan.
    #[error("deposit observation does not match confirmed local scanner state")]
    InvalidDepositObservation,
    /// Durable certified publication bound was reached.
    #[error("certified sweep publication capacity reached")]
    CertifiedPublicationCapacity,
    /// No retained certified publication exists for this sweep.
    #[error("unknown certified sweep publication")]
    UnknownCertifiedPublication,
    /// Certified publication has not received exact canonical root-output inclusion evidence.
    #[error("certified sweep publication is not confirmed")]
    CertifiedPublicationUnconfirmed,
    /// Height arithmetic overflowed.
    #[error("Monero block height overflow")]
    HeightOverflow,
    /// Atomic-unit sum overflowed.
    #[error("deposit amount sum overflow")]
    AmountOverflow,
    /// Sweep attempt sequence was exhausted.
    #[error("deposit sweep sequence exhausted")]
    SweepSequenceExhausted,
    /// Destination/policy binding was all zeroes.
    #[error("invalid consolidation destination binding")]
    InvalidDestinationBinding,
    /// Concrete root transaction builder was given another destination/policy commitment.
    #[error("consolidation destination binding does not match the root-wallet policy")]
    DestinationPolicyMismatch,
    /// Plan no longer exactly matched durable available/mature inputs.
    #[error("stale or invalid consolidation sweep plan")]
    StaleSweepPlan,
    /// Portable certificate fields or completed transaction shape were invalid.
    #[error("invalid portable certified consolidation sweep")]
    InvalidCertifiedSweep,
    /// Portable certificate replay changed fields or overlapped another permanent input claim.
    #[error("portable certified consolidation sweep conflicts with durable state")]
    CertifiedSweepConflict,
    /// Prepared transaction or globally unique signing session was inconsistent.
    #[error("invalid prepared FROSTLASS sweep or signing session")]
    InvalidPreparedSweep,
    /// A completed transaction failed exact family, ring, CLSAG, Bulletproof+, or balance checks.
    #[error("invalid completed Monero transaction for the durable sweep family")]
    InvalidSweepFamilyCandidate,
    /// A source could not prove that it retained every canonical transaction key-image vector.
    #[error("canonical transaction key-image evidence is incomplete at height {0}")]
    IncompleteSweepFamilyChainEvidence(u64),
    /// Canonical prefix/full-transaction evidence was malformed, duplicated, or hash-inconsistent.
    #[error("invalid canonical sweep-family chain evidence")]
    InvalidSweepFamilyChainEvidence,
    /// A relevant canonical transaction was known by hash/prefix but its exact bytes were absent.
    #[error(
        "exact bytes for canonical sweep-family transaction {} at height {height} are unavailable",
        hex::encode(transaction)
    )]
    SweepFamilyTransactionBytesUnavailable { transaction: [u8; 32], height: u64 },
    /// An included transaction used one or more pinned images but changed the exact family.
    #[error("canonical transaction conflicts with pinned sweep family {0:?}")]
    SweepFamilySpendConflict(SweepId),
    /// Canonical prepared-sweep representation exceeded its hard message bound.
    #[error("prepared sweep intent exceeds its hard size bound")]
    PreparedSweepIntentTooLarge,
    /// Prepared-sweep representation had trailing or non-canonical bytes.
    #[error("prepared sweep intent is not canonically encoded")]
    NonCanonicalPreparedSweepIntent,
    /// Committee failed its structural validation before a signing context was created.
    #[error("invalid FROSTLASS signing committee: {0}")]
    InvalidSigningCommittee(String),
    /// Prepared plan epoch and signing committee epoch differed.
    #[error("sweep plan epoch {plan} differs from signing committee epoch {committee}")]
    WrongSigningEpoch { plan: u64, committee: u64 },
    /// Signing group key was not the worker's untweaked root spend key.
    #[error("FROSTLASS signing group key differs from the root wallet spend key")]
    WrongSigningGroupKey,
    /// Monero address parsing failed.
    #[error("invalid primary Monero address: {0}")]
    Address(String),
    /// Fee exceeded persisted policy.
    #[error("Monero fee {actual} exceeds policy maximum {maximum}")]
    FeeAbovePolicy { actual: u64, maximum: u64 },
    /// monero-wallet rejected exact transaction construction.
    #[error("Monero transaction construction failed: {0}")]
    Send(#[from] SendError),
}

#[cfg(test)]
mod daemon_network_tests {
    use monero_simple_request_rpc::prelude::InterfaceError;

    use super::*;

    #[derive(Clone)]
    struct FakeDaemonTransport {
        report: String,
        genesis: [u8; 32],
    }

    impl HttpTransport for FakeDaemonTransport {
        fn post(
            &self,
            route: &str,
            body: Vec<u8>,
            _response_size_limit: Option<usize>,
        ) -> impl Send + Future<Output = Result<Vec<u8>, InterfaceError>> {
            let route = route.to_owned();
            let request = String::from_utf8(body).expect("test request is UTF-8 JSON");
            let report = self.report.clone();
            let genesis = hex::encode(self.genesis);
            async move {
                if route != "json_rpc" {
                    return Err(InterfaceError::InterfaceError("unexpected test route".to_owned()));
                }
                let response = if request.trim_start().starts_with('[') {
                    // MoneroDaemon::new probes JSON-RPC batch support with block hashes zero/one.
                    format!(
                        r#"[{{"jsonrpc":"2.0","result":"{genesis}","id":0}},{{"jsonrpc":"2.0","result":"{}","id":1}}]"#,
                        "11".repeat(32)
                    )
                } else if request.contains("get_info") {
                    format!(r#"{{"jsonrpc":"2.0","result":{report},"id":0}}"#)
                } else if request.contains("on_get_block_hash") {
                    format!(r#"{{"jsonrpc":"2.0","result":"{genesis}","id":0}}"#)
                } else {
                    return Err(InterfaceError::InterfaceError(
                        "unexpected test JSON-RPC method".to_owned(),
                    ));
                };
                Ok(response.into_bytes())
            }
        }
    }

    async fn fake_daemon(
        nettype: &str,
        mainnet: bool,
        testnet: bool,
        stagenet: bool,
        untrusted: bool,
        genesis: [u8; 32],
    ) -> MoneroDaemon<FakeDaemonTransport> {
        let report = format!(
            r#"{{"status":"OK","untrusted":{untrusted},"nettype":"{nettype}","mainnet":{mainnet},"testnet":{testnet},"stagenet":{stagenet}}}"#
        );
        MoneroDaemon::new(FakeDaemonTransport { report, genesis }).await.unwrap()
    }

    #[tokio::test]
    async fn accepts_fakechain_only_with_mainnet_genesis_and_regtest_flags() {
        let daemon = fake_daemon(
            "fakechain",
            false,
            false,
            false,
            false,
            NetworkKind::Regtest.genesis_hash(),
        )
        .await;
        assert_eq!(
            verify_daemon_network_identity(&daemon, NetworkKind::Regtest, Duration::from_secs(1))
                .await
                .unwrap(),
            NetworkKind::Regtest.genesis_hash()
        );
    }

    #[tokio::test]
    async fn rejects_daemon_from_the_wrong_network_even_with_a_known_genesis() {
        let daemon =
            fake_daemon("mainnet", true, false, false, false, NetworkKind::Mainnet.genesis_hash())
                .await;
        assert!(matches!(
            verify_daemon_network_identity(&daemon, NetworkKind::Testnet, Duration::from_secs(1))
                .await,
            Err(DepositWorkerError::DaemonNetworkMismatch {
                expected: "testnet",
                actual
            }) if actual == "mainnet"
        ));
    }

    #[tokio::test]
    async fn rejects_matching_nettype_with_the_wrong_genesis() {
        let daemon =
            fake_daemon("testnet", false, true, false, false, NetworkKind::Mainnet.genesis_hash())
                .await;
        assert!(matches!(
            verify_daemon_network_identity(&daemon, NetworkKind::Testnet, Duration::from_secs(1))
                .await,
            Err(DepositWorkerError::DaemonGenesisMismatch { expected, actual })
                if expected == NetworkKind::Testnet.genesis_hash()
                    && actual == NetworkKind::Mainnet.genesis_hash()
        ));
    }

    #[tokio::test]
    async fn rejects_bootstrap_proxied_network_identity() {
        let daemon =
            fake_daemon("testnet", false, true, false, true, NetworkKind::Testnet.genesis_hash())
                .await;
        assert!(matches!(
            verify_daemon_network_identity(&daemon, NetworkKind::Testnet, Duration::from_secs(1))
                .await,
            Err(DepositWorkerError::UntrustedDaemonNetworkReport)
        ));
    }
}
