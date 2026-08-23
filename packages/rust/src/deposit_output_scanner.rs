//! Bounded-memory recognition of Monero outputs sent to permanent deposit subaddresses.
//!
//! Monero's wallet scanner normally keeps a hash table containing the public spend point of every
//! registered subaddress. That table grows for the lifetime of a deposit wallet because an address
//! must remain detectable after it expires. This module separates the cryptographic scan from that
//! table: for each output and transaction key it derives
//! `D = P - Hs(8 a R || output_index) G`, then asks a caller-supplied authenticated, direct index
//! for `D`. The lookup is performed one candidate at a time, so process memory is independent of
//! the number of deposit addresses ever allocated.
//!
//! A returned numeric subaddress index is not trusted. It is rederived from the root public spend
//! key and private view scalar and must reproduce the exact `D` before an output is accepted. The
//! resulting [`WalletOutput`] uses monero-wallet's canonical encoding and contains the complete key
//! offset, decrypted commitment, timelock, payment ID, arbitrary data, and global output index
//! needed by the existing sweep and key-image paths.
//!
//! The direct lookup must retain an immutable
//! `(wallet_id, compressed_subaddress_spend_key) -> certified allocation` alias forever. It must
//! not be implemented by enumerating all allocations, and an expired address must remain in the
//! index. Output-key burning-bug detection remains a separate, mandatory durable check when these
//! results are committed to scanner state.

use std::{error::Error, fmt, ops::Deref as _};

use curve25519_dalek::{
    EdwardsPoint, Scalar as DalekScalar, constants::ED25519_BASEPOINT_POINT,
    traits::IsIdentity as _,
};
use monero_oxide::{
    ed25519::{Commitment, CompressedPoint, Point, Scalar as MoneroScalar},
    io::VarInt,
    primitives::keccak256,
    ringct::EncryptedAmount,
    transaction::{Pruned, Transaction},
};
use monero_wallet::{
    WalletOutput,
    extra::{Extra, PaymentId},
    interface::ScannableBlock,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    NetworkKind,
    deposit_wallet::{DepositSubaddressIndex, DepositWalletId},
};

/// Highest Monero hard-fork version whose output formats are audited by this implementation.
pub const MAX_BOUNDED_SCANNER_HARDFORK: u8 = 16;

const MAX_TRANSACTIONS_PER_BLOCK: usize = 100_000;
const MAX_OUTPUTS_PER_TRANSACTION: usize = 32_768;
const MAX_TRANSACTION_PUBLIC_KEYS: usize = 32_768;
const MAX_DERIVATIONS_PER_TRANSACTION: u64 = 4_096;
const MAX_INDEX_LOOKUPS_PER_TRANSACTION: usize = 4_096;
const MAX_RECOGNIZED_OUTPUTS_PER_CHUNK: usize = 256;

/// Resource policy for bounded output recognition.
///
/// These limits bound adversarial work and every result vector. They do not depend on, or cap, the
/// number of deposit addresses stored in the durable spend-key index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepositOutputScannerLimits {
    /// Maximum miner plus non-miner transactions accepted in one expanded block.
    pub max_transactions_per_block: usize,
    /// Maximum outputs accepted in any one transaction.
    pub max_outputs_per_transaction: usize,
    /// Maximum primary plus additional transaction keys accepted in one transaction extra.
    pub max_transaction_public_keys: usize,
    /// Maximum `(output, transaction key)` derivations performed by one resumable scan chunk.
    pub max_derivations_per_transaction: u64,
    /// Maximum direct durable-index queries performed by one resumable scan chunk.
    pub max_index_lookups_per_transaction: usize,
    /// Maximum wallet-owned outputs returned by one resumable scan chunk.
    pub max_recognized_outputs_per_chunk: usize,
}

impl Default for DepositOutputScannerLimits {
    fn default() -> Self {
        Self {
            max_transactions_per_block: MAX_TRANSACTIONS_PER_BLOCK,
            max_outputs_per_transaction: MAX_OUTPUTS_PER_TRANSACTION,
            max_transaction_public_keys: MAX_TRANSACTION_PUBLIC_KEYS,
            max_derivations_per_transaction: MAX_DERIVATIONS_PER_TRANSACTION,
            max_index_lookups_per_transaction: MAX_INDEX_LOOKUPS_PER_TRANSACTION,
            max_recognized_outputs_per_chunk: MAX_RECOGNIZED_OUTPUTS_PER_CHUNK,
        }
    }
}

impl DepositOutputScannerLimits {
    fn validate(self) -> Result<Self, DepositOutputScannerSetupError> {
        if self.max_transactions_per_block == 0
            || self.max_transactions_per_block > MAX_TRANSACTIONS_PER_BLOCK
            || self.max_outputs_per_transaction == 0
            || self.max_outputs_per_transaction > MAX_OUTPUTS_PER_TRANSACTION
            || self.max_transaction_public_keys == 0
            || self.max_transaction_public_keys > MAX_TRANSACTION_PUBLIC_KEYS
            || self.max_derivations_per_transaction == 0
            || self.max_derivations_per_transaction > MAX_DERIVATIONS_PER_TRANSACTION
            || self.max_index_lookups_per_transaction == 0
            || self.max_index_lookups_per_transaction > MAX_INDEX_LOOKUPS_PER_TRANSACTION
            || self.max_recognized_outputs_per_chunk == 0
            || self.max_recognized_outputs_per_chunk > MAX_RECOGNIZED_OUTPUTS_PER_CHUNK
        {
            return Err(DepositOutputScannerSetupError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Configuration error for [`BoundedDepositOutputScanner`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum DepositOutputScannerSetupError {
    /// The root public spend key was not a valid prime-order non-identity Ed25519 point.
    #[error("invalid root public spend key")]
    InvalidRootSpendKey,
    /// The private view scalar was not canonically encoded.
    #[error("private view scalar is not canonical")]
    InvalidPrivateViewScalar,
    /// A zero private view scalar cannot define a wallet.
    #[error("private view scalar is zero")]
    ZeroPrivateViewScalar,
    /// A configured resource limit was zero or above its hard process ceiling.
    #[error("invalid bounded output-scanner limits")]
    InvalidLimits,
}

/// Synchronous authenticated lookup used at the cryptographic recognition boundary.
///
/// Implementations should perform a direct read against the currently committed portable deposit
/// index head. The returned allocation's address and index must already be authenticated by that
/// index. The scanner independently rederives the public spend point before accepting it.
pub trait DepositSubaddressSpendKeyLookup {
    /// Backend error.
    type Error;

    /// Look up an immutable allocation by its exact compressed subaddress spend point.
    fn lookup_subaddress_spend_key(
        &mut self,
        wallet: DepositWalletId,
        subaddress_spend_key: [u8; 32],
    ) -> Result<Option<DepositSubaddressIndex>, Self::Error>;
}

impl<E, F> DepositSubaddressSpendKeyLookup for F
where
    F: FnMut(DepositWalletId, [u8; 32]) -> Result<Option<DepositSubaddressIndex>, E>,
{
    type Error = E;

    fn lookup_subaddress_spend_key(
        &mut self,
        wallet: DepositWalletId,
        subaddress_spend_key: [u8; 32],
    ) -> Result<Option<DepositSubaddressIndex>, Self::Error> {
        self(wallet, subaddress_spend_key)
    }
}

/// Cryptographic or structural failure independent of a lookup backend.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DepositOutputScanError {
    /// The expanded block and its transaction list disagreed.
    #[error("expanded block transaction count does not match its hash list")]
    TransactionCountMismatch,
    /// The block uses an output format newer than this implementation has audited.
    #[error("unsupported Monero hard-fork version {0}")]
    UnsupportedHardfork(u8),
    /// A block or transaction exceeded a configured per-operation resource bound.
    #[error("bounded output-scanner resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    /// A v2 non-miner transaction omitted RingCT base data needed to decrypt its outputs.
    #[error("non-miner v2 transaction omitted RingCT data")]
    MissingRingCtData,
    /// RingCT base vectors did not contain one entry for every output.
    #[error("RingCT output vectors are incomplete")]
    IncompleteRingCtData,
    /// An expanded block containing v2 outputs omitted their first global output index.
    #[error("expanded block omitted its first global RingCT output index")]
    MissingGlobalOutputIndex,
    /// Global output-index arithmetic overflowed.
    #[error("global RingCT output index overflow")]
    GlobalOutputIndexOverflow,
    /// An authenticated index returned an allocation which did not reproduce the queried point.
    #[error("durable subaddress-spend-key alias returned a mismatched numeric index")]
    CorruptSubaddressSpendKeyAlias,
    /// Two distinct authenticated derivations claimed the same transaction output.
    #[error("one output matched multiple distinct wallet derivations")]
    AmbiguousOutput,
    /// Internal canonical WalletOutput construction failed closed.
    #[error("failed to construct canonical Monero wallet output")]
    WalletOutputEncoding,
    /// A persisted resumable cursor did not name a canonical transaction-key boundary.
    #[error("invalid bounded output-scanner resume cursor")]
    InvalidScanCursor,
}

/// A scan failure which preserves the concrete durable-index backend error.
#[derive(Debug)]
pub enum DepositOutputScanFailure<E> {
    /// Cryptographic, structural, or resource-policy failure.
    Scan(DepositOutputScanError),
    /// Direct durable-index lookup failed.
    Lookup(E),
}

impl<E: fmt::Display> fmt::Display for DepositOutputScanFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scan(error) => error.fmt(formatter),
            Self::Lookup(error) => write!(formatter, "subaddress spend-key lookup failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for DepositOutputScanFailure<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Scan(error) => Some(error),
            Self::Lookup(error) => Some(error),
        }
    }
}

impl<E> From<DepositOutputScanError> for DepositOutputScanFailure<E> {
    fn from(error: DepositOutputScanError) -> Self {
        Self::Scan(error)
    }
}

/// Wallet-owned outputs recognized in one expanded block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedScannedOutputs {
    deposit_outputs: Vec<WalletOutput>,
    root_outputs: Vec<WalletOutput>,
}

impl BoundedScannedOutputs {
    /// Outputs sent to certified permanent deposit subaddresses.
    #[must_use]
    pub fn deposit_outputs(&self) -> &[WalletOutput] {
        &self.deposit_outputs
    }

    /// Outputs sent to the root consolidation address.
    #[must_use]
    pub fn root_outputs(&self) -> &[WalletOutput] {
        &self.root_outputs
    }

    /// Consume the result into deposit and root vectors.
    #[must_use]
    pub fn into_parts(self) -> (Vec<WalletOutput>, Vec<WalletOutput>) {
        (self.deposit_outputs, self.root_outputs)
    }
}

/// Stateless cryptographic scanner holding only one wallet's fixed root/view material.
///
/// Standard Monero outputs and standard subaddresses are supported. The non-standard
/// monero-oxide "guaranteed" address construction is deliberately not enabled because deposit
/// addresses generated by this crate are standard Monero subaddresses.
pub struct BoundedDepositOutputScanner {
    wallet: DepositWalletId,
    root_spend: EdwardsPoint,
    private_view: Zeroizing<DalekScalar>,
    limits: DepositOutputScannerLimits,
}

impl BoundedDepositOutputScanner {
    /// Bind a scanner to the same wallet domain as [`crate::deposit_wallet::DepositAddressDeriver`].
    ///
    /// # Errors
    ///
    /// Returns an error for malformed key material or invalid resource limits.
    pub fn new(
        network: NetworkKind,
        root_spend_key: [u8; 32],
        private_view_scalar: &Zeroizing<[u8; 32]>,
        limits: DepositOutputScannerLimits,
    ) -> Result<Self, DepositOutputScannerSetupError> {
        let Some(root_spend) = CompressedPoint::from(root_spend_key).decompress() else {
            return Err(DepositOutputScannerSetupError::InvalidRootSpendKey);
        };
        let root_spend = root_spend.into();
        if !root_spend.is_torsion_free() || root_spend.is_identity() {
            return Err(DepositOutputScannerSetupError::InvalidRootSpendKey);
        }

        let private_view =
            Option::<DalekScalar>::from(DalekScalar::from_canonical_bytes(**private_view_scalar))
                .ok_or(DepositOutputScannerSetupError::InvalidPrivateViewScalar)?;
        if private_view == DalekScalar::ZERO {
            return Err(DepositOutputScannerSetupError::ZeroPrivateViewScalar);
        }

        let public_view_key = (&private_view * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let wallet = derive_wallet_id(network, root_spend_key, public_view_key);
        Ok(Self {
            wallet,
            root_spend,
            private_view: Zeroizing::new(private_view),
            limits: limits.validate()?,
        })
    }

    /// Stable wallet domain used for all direct index lookups.
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    /// Scan a locally expanded block without loading the permanent address set into memory.
    ///
    /// Every non-root candidate invokes at most one direct lookup. Returned indexes are
    /// cryptographically reauthenticated before a [`WalletOutput`] is emitted.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed RingCT data, unsupported hard forks, exhausted limits, corrupt
    /// aliases, ambiguous matches, arithmetic overflow, or backend lookup failure.
    pub fn scan_block<L: DepositSubaddressSpendKeyLookup>(
        &self,
        scannable: ScannableBlock,
        lookup: &mut L,
    ) -> Result<BoundedScannedOutputs, DepositOutputScanFailure<L::Error>> {
        let ScannableBlock { block, transactions, output_index_for_first_ringct_output } =
            scannable;
        if block.transactions.len() != transactions.len() {
            return Err(DepositOutputScanError::TransactionCountMismatch.into());
        }
        if block.header.hardfork_version > MAX_BOUNDED_SCANNER_HARDFORK {
            return Err(
                DepositOutputScanError::UnsupportedHardfork(block.header.hardfork_version).into()
            );
        }
        let transaction_count = transactions
            .len()
            .checked_add(1)
            .ok_or(DepositOutputScanError::ResourceLimit("transaction count"))?;
        if transaction_count > self.limits.max_transactions_per_block {
            return Err(DepositOutputScanError::ResourceLimit("transactions per block").into());
        }

        let Some(mut global_output_index) = output_index_for_first_ringct_output else {
            let has_ringct_outputs = (block.miner_transaction().version() == 2
                && !block.miner_transaction().prefix().outputs.is_empty())
                || transactions.iter().any(|transaction| {
                    transaction.version() == 2 && !transaction.prefix().outputs.is_empty()
                });
            if has_ringct_outputs {
                return Err(DepositOutputScanError::MissingGlobalOutputIndex.into());
            }
            return Ok(BoundedScannedOutputs {
                deposit_outputs: Vec::new(),
                root_outputs: Vec::new(),
            });
        };

        let miner_hash = block.miner_transaction().hash();
        let miner = Transaction::<Pruned>::from(block.miner_transaction().clone());
        let mut deposit_outputs = Vec::new();
        let mut root_outputs = Vec::new();

        for (transaction_hash, transaction) in std::iter::once((miner_hash, miner))
            .chain(block.transactions.into_iter().zip(transactions))
        {
            if transaction.version() != 2 {
                continue;
            }
            let recognized = self.scan_transaction(
                block.header.hardfork_version,
                transaction_hash,
                global_output_index,
                &transaction,
                lookup,
            )?;
            for recognized in recognized {
                match recognized.target {
                    RecognizedTarget::Root => root_outputs.push(recognized.output),
                    RecognizedTarget::Deposit(_) => deposit_outputs.push(recognized.output),
                }
                if deposit_outputs.len() + root_outputs.len()
                    > self.limits.max_recognized_outputs_per_chunk
                {
                    return Err(DepositOutputScanError::ResourceLimit(
                        "recognized outputs per block",
                    )
                    .into());
                }
            }

            global_output_index = global_output_index
                .checked_add(
                    u64::try_from(transaction.prefix().outputs.len())
                        .map_err(|_| DepositOutputScanError::GlobalOutputIndexOverflow)?,
                )
                .ok_or(DepositOutputScanError::GlobalOutputIndexOverflow)?;
        }

        Ok(BoundedScannedOutputs { deposit_outputs, root_outputs })
    }

    /// Scan one pruned v2 transaction with an explicit trusted transaction/global-index binding.
    ///
    /// This lower-level entry point is useful for staged block pipelines. Callers must still
    /// enforce block transaction/hash binding and advance the global RingCT index across every v2
    /// transaction, including transactions with no recognized outputs.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::scan_block`].
    pub fn scan_transaction<L: DepositSubaddressSpendKeyLookup>(
        &self,
        hardfork_version: u8,
        transaction_hash: [u8; 32],
        output_index_for_first_ringct_output: u64,
        transaction: &Transaction<Pruned>,
        lookup: &mut L,
    ) -> Result<Vec<RecognizedWalletOutput>, DepositOutputScanFailure<L::Error>> {
        let chunk = self.scan_transaction_chunk(
            hardfork_version,
            transaction_hash,
            output_index_for_first_ringct_output,
            transaction,
            DepositTransactionScanCursor::start(),
            lookup,
        )?;
        let (recognized, next_cursor) = chunk.into_parts();
        if next_cursor.is_some() {
            return Err(
                DepositOutputScanError::ResourceLimit("resumable transaction scan chunk").into()
            );
        }
        Ok(recognized)
    }

    /// Scan at most one bounded piece of a pruned v2 transaction.
    ///
    /// Unlike [`Self::scan_transaction`], exhausting the per-call derivation/lookup budget is a
    /// successful yield with a deterministic cursor. This prevents a consensus-valid transaction
    /// containing many unusual transaction public keys from permanently halting a live worker.
    /// The caller should durably bind the cursor to the exact block/transaction/global-index
    /// tuple, merge repeated candidates byte-for-byte, persist, and resume in a later tick.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported formats, malformed data, a non-canonical cursor, a corrupt
    /// authenticated alias, an ambiguous match within this chunk, or backend lookup failure.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn scan_transaction_chunk<L: DepositSubaddressSpendKeyLookup>(
        &self,
        hardfork_version: u8,
        transaction_hash: [u8; 32],
        output_index_for_first_ringct_output: u64,
        transaction: &Transaction<Pruned>,
        cursor: DepositTransactionScanCursor,
        lookup: &mut L,
    ) -> Result<DepositTransactionScanChunk, DepositOutputScanFailure<L::Error>> {
        if hardfork_version > MAX_BOUNDED_SCANNER_HARDFORK {
            return Err(DepositOutputScanError::UnsupportedHardfork(hardfork_version).into());
        }
        if transaction.version() != 2 {
            if cursor != DepositTransactionScanCursor::start() {
                return Err(DepositOutputScanError::InvalidScanCursor.into());
            }
            return Ok(DepositTransactionScanChunk {
                recognized_outputs: Vec::new(),
                next_cursor: None,
            });
        }
        if transaction.prefix().outputs.len() > self.limits.max_outputs_per_transaction {
            return Err(DepositOutputScanError::ResourceLimit("outputs per transaction").into());
        }

        let extra = Extra::read(&mut transaction.prefix().extra.as_slice())
            .map_err(|_| DepositOutputScanError::WalletOutputEncoding)?;
        let Some((transaction_keys, additional_keys)) = extra.keys() else {
            if cursor != DepositTransactionScanCursor::start() {
                return Err(DepositOutputScanError::InvalidScanCursor.into());
            }
            return Ok(DepositTransactionScanChunk {
                recognized_outputs: Vec::new(),
                next_cursor: None,
            });
        };
        let total_public_keys = transaction_keys
            .len()
            .checked_add(additional_keys.as_ref().map_or(0, Vec::len))
            .ok_or(DepositOutputScanError::ResourceLimit("transaction public keys"))?;
        if total_public_keys > self.limits.max_transaction_public_keys {
            return Err(DepositOutputScanError::ResourceLimit("transaction public keys").into());
        }

        let start_output = usize::try_from(cursor.output_index)
            .map_err(|_| DepositOutputScanError::InvalidScanCursor)?;
        let start_key = usize::try_from(cursor.transaction_key_index)
            .map_err(|_| DepositOutputScanError::InvalidScanCursor)?;
        if start_output > transaction.prefix().outputs.len()
            || (start_output == transaction.prefix().outputs.len() && start_key != 0)
        {
            return Err(DepositOutputScanError::InvalidScanCursor.into());
        }
        if start_output == transaction.prefix().outputs.len() {
            return Ok(DepositTransactionScanChunk {
                recognized_outputs: Vec::new(),
                next_cursor: None,
            });
        }

        let encrypted_payment_id = extra.payment_id();
        let arbitrary_data = extra.arbitrary_data();
        let mut recognized_outputs = Vec::new();
        let mut index_lookups = 0_usize;
        let mut derivations = 0_u64;
        for (output_index, output) in
            transaction.prefix().outputs.iter().enumerate().skip(start_output)
        {
            let key_start = if output_index == start_output { start_key } else { 0 };
            if recognized_outputs.len() == self.limits.max_recognized_outputs_per_chunk {
                return Ok(DepositTransactionScanChunk {
                    recognized_outputs,
                    next_cursor: Some(DepositTransactionScanCursor {
                        output_index: u32::try_from(output_index)
                            .map_err(|_| DepositOutputScanError::InvalidScanCursor)?,
                        transaction_key_index: u32::try_from(key_start)
                            .map_err(|_| DepositOutputScanError::InvalidScanCursor)?,
                    }),
                });
            }
            if output.key == CompressedPoint::IDENTITY {
                if key_start != 0 {
                    return Err(DepositOutputScanError::InvalidScanCursor.into());
                }
                continue;
            }
            let Some(output_point) = output.key.decompress() else {
                if key_start != 0 {
                    return Err(DepositOutputScanError::InvalidScanCursor.into());
                }
                continue;
            };

            let additional_key =
                additional_keys.as_ref().and_then(|keys| keys.get(output_index)).copied();
            let key_count = transaction_keys
                .len()
                .checked_add(usize::from(additional_key.is_some()))
                .ok_or(DepositOutputScanError::ResourceLimit("transaction public keys"))?;
            if key_start >= key_count && key_count != 0 {
                return Err(DepositOutputScanError::InvalidScanCursor.into());
            }
            if key_count == 0 {
                if key_start != 0 {
                    return Err(DepositOutputScanError::InvalidScanCursor.into());
                }
                continue;
            }
            let mut recognized: Option<RecognizedWalletOutput> = None;
            for key_index in key_start..key_count {
                if derivations == self.limits.max_derivations_per_transaction
                    || index_lookups == self.limits.max_index_lookups_per_transaction
                {
                    if let Some(recognized) = recognized {
                        recognized_outputs.push(recognized);
                    }
                    return Ok(DepositTransactionScanChunk {
                        recognized_outputs,
                        next_cursor: Some(DepositTransactionScanCursor {
                            output_index: u32::try_from(output_index)
                                .map_err(|_| DepositOutputScanError::InvalidScanCursor)?,
                            transaction_key_index: u32::try_from(key_index)
                                .map_err(|_| DepositOutputScanError::InvalidScanCursor)?,
                        }),
                    });
                }
                derivations = derivations
                    .checked_add(1)
                    .ok_or(DepositOutputScanError::ResourceLimit("output derivations"))?;
                let transaction_key = if key_index < transaction_keys.len() {
                    transaction_keys[key_index]
                } else {
                    additional_key.ok_or(DepositOutputScanError::InvalidScanCursor)?
                };
                let derivation =
                    derive_output(self.private_view.deref(), transaction_key, output_index);
                if output.view_tag.is_some_and(|actual| actual != derivation.view_tag) {
                    continue;
                }

                let Some(commitment) =
                    decrypt_and_verify_commitment(transaction, output_index, &derivation)?
                else {
                    continue;
                };
                let candidate_spend =
                    output_point.into() - (derivation.shared_scalar() * ED25519_BASEPOINT_POINT);
                if !candidate_spend.is_torsion_free() {
                    continue;
                }

                let target = if candidate_spend == self.root_spend {
                    Some(RecognizedTarget::Root)
                } else {
                    let candidate_bytes = candidate_spend.compress().to_bytes();
                    index_lookups = index_lookups.checked_add(1).ok_or(
                        DepositOutputScanError::ResourceLimit("durable index lookups per chunk"),
                    )?;
                    let index = lookup
                        .lookup_subaddress_spend_key(self.wallet, candidate_bytes)
                        .map_err(DepositOutputScanFailure::Lookup)?;
                    match index {
                        None => None,
                        Some(index) => {
                            if self.derive_subaddress_spend(index) != candidate_spend {
                                return Err(
                                    DepositOutputScanError::CorruptSubaddressSpendKeyAlias.into()
                                );
                            }
                            Some(RecognizedTarget::Deposit(index))
                        }
                    }
                };
                let Some(target) = target else {
                    continue;
                };

                let payment_id = encrypted_payment_id
                    .map(|payment_id| payment_id ^ payment_id_xor(derivation.ecdh.deref()));
                let payment_id = if hardfork_version >= 12
                    && matches!(payment_id, Some(PaymentId::Unencrypted(_)))
                {
                    None
                } else {
                    payment_id
                };
                let key_offset = match target {
                    RecognizedTarget::Root => *derivation.shared,
                    RecognizedTarget::Deposit(index) => {
                        let subaddress_derivation = self.subaddress_derivation(index);
                        MoneroScalar::from(derivation.shared_scalar() + *subaddress_derivation)
                    }
                };
                let absolute_output_index = u64::try_from(output_index)
                    .map_err(|_| DepositOutputScanError::GlobalOutputIndexOverflow)?;
                let global_output_index = output_index_for_first_ringct_output
                    .checked_add(absolute_output_index)
                    .ok_or(DepositOutputScanError::GlobalOutputIndexOverflow)?;
                let wallet_output = construct_wallet_output(
                    transaction_hash,
                    absolute_output_index,
                    global_output_index,
                    output_point,
                    key_offset,
                    &commitment,
                    transaction.prefix().additional_timelock,
                    target.subaddress(),
                    payment_id,
                    &arbitrary_data,
                )?;
                let candidate = RecognizedWalletOutput { output: wallet_output, target };
                if let Some(prior) = &recognized {
                    if prior != &candidate {
                        return Err(DepositOutputScanError::AmbiguousOutput.into());
                    }
                } else {
                    recognized = Some(candidate);
                }
            }
            if let Some(recognized) = recognized {
                recognized_outputs.push(recognized);
            }
        }
        Ok(DepositTransactionScanChunk { recognized_outputs, next_cursor: None })
    }

    fn subaddress_derivation(&self, index: DepositSubaddressIndex) -> Zeroizing<DalekScalar> {
        let mut material = Zeroizing::new(Vec::with_capacity(8 + 32 + 4 + 4));
        material.extend_from_slice(b"SubAddr\0");
        material.extend_from_slice(&self.private_view.to_bytes());
        material.extend_from_slice(&index.account().to_le_bytes());
        material.extend_from_slice(&index.address().to_le_bytes());
        Zeroizing::new(MoneroScalar::hash(material.as_slice()).into())
    }

    fn derive_subaddress_spend(&self, index: DepositSubaddressIndex) -> EdwardsPoint {
        let derivation = self.subaddress_derivation(index);
        self.root_spend + (*derivation * ED25519_BASEPOINT_POINT)
    }
}

/// One recognized output plus its authenticated root/subaddress classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecognizedWalletOutput {
    output: WalletOutput,
    target: RecognizedTarget,
}

impl RecognizedWalletOutput {
    /// Canonical monero-wallet output.
    #[must_use]
    pub const fn output(&self) -> &WalletOutput {
        &self.output
    }

    /// Deposit subaddress index, or `None` for a root/consolidation output.
    #[must_use]
    pub const fn subaddress(&self) -> Option<DepositSubaddressIndex> {
        self.target.subaddress()
    }

    /// Consume this wrapper and return the canonical output.
    #[must_use]
    pub fn into_output(self) -> WalletOutput {
        self.output
    }
}

/// Canonical resume point within one transaction.
///
/// The cursor is deterministic from authenticated transaction bytes. It contains no lookup
/// result and is safe to persist between worker ticks. Callers must still bind it to the exact
/// transaction hash, block hash, and first global output index in their durable block progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositTransactionScanCursor {
    output_index: u32,
    transaction_key_index: u32,
}

impl DepositTransactionScanCursor {
    /// Start scanning at the first output and first transaction key.
    #[must_use]
    pub const fn start() -> Self {
        Self { output_index: 0, transaction_key_index: 0 }
    }

    /// Zero-based output position.
    #[must_use]
    pub const fn output_index(self) -> u32 {
        self.output_index
    }

    /// Zero-based position in the primary-keys-then-additional-key sequence for that output.
    #[must_use]
    pub const fn transaction_key_index(self) -> u32 {
        self.transaction_key_index
    }
}

/// One bounded, resumable piece of transaction output recognition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositTransactionScanChunk {
    recognized_outputs: Vec<RecognizedWalletOutput>,
    next_cursor: Option<DepositTransactionScanCursor>,
}

impl DepositTransactionScanChunk {
    /// Candidates recognized during only this chunk.
    ///
    /// A candidate for the output named by `next_cursor` may be repeated by a later chunk. The
    /// durable caller must merge repeated candidates byte-for-byte and reject any conflict; this
    /// preserves ambiguity detection across a persisted chunk boundary.
    #[must_use]
    pub fn recognized_outputs(&self) -> &[RecognizedWalletOutput] {
        &self.recognized_outputs
    }

    /// Consume this chunk into its candidates and deterministic continuation.
    #[must_use]
    pub fn into_parts(self) -> (Vec<RecognizedWalletOutput>, Option<DepositTransactionScanCursor>) {
        (self.recognized_outputs, self.next_cursor)
    }

    /// Continuation required to finish the same transaction, or `None` when complete.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<DepositTransactionScanCursor> {
        self.next_cursor
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecognizedTarget {
    Root,
    Deposit(DepositSubaddressIndex),
}

impl RecognizedTarget {
    const fn subaddress(self) -> Option<DepositSubaddressIndex> {
        match self {
            Self::Root => None,
            Self::Deposit(index) => Some(index),
        }
    }
}

struct OutputDerivation {
    view_tag: u8,
    shared: Zeroizing<MoneroScalar>,
    ecdh: Zeroizing<Point>,
}

impl OutputDerivation {
    fn shared_scalar(&self) -> DalekScalar {
        (*self.shared).into()
    }
}

fn derive_output(
    private_view: &DalekScalar,
    transaction_key: Point,
    output_index: usize,
) -> OutputDerivation {
    let ecdh = Zeroizing::new(Point::from(private_view * transaction_key.into()));
    let mut output_derivation =
        Zeroizing::new(Point::into(*ecdh).mul_by_cofactor().compress().to_bytes().to_vec());
    VarInt::write(&output_index, &mut *output_derivation).expect("writing to a Vec cannot fail");
    let view_tag = keccak256([b"view_tag".as_slice(), output_derivation.as_slice()].concat())[0];
    let shared = Zeroizing::new(MoneroScalar::hash(output_derivation.as_slice()));
    OutputDerivation { view_tag, shared, ecdh }
}

fn decrypt_and_verify_commitment<E>(
    transaction: &Transaction<Pruned>,
    output_index: usize,
    derivation: &OutputDerivation,
) -> Result<Option<Commitment>, DepositOutputScanFailure<E>> {
    let output = &transaction.prefix().outputs[output_index];
    let commitment = if let Some(amount) = output.amount {
        let mut commitment = Commitment::zero();
        commitment.amount = amount;
        commitment
    } else {
        let Transaction::V2 { proofs: Some(proofs), .. } = transaction else {
            return Err(DepositOutputScanError::MissingRingCtData.into());
        };
        let encrypted = proofs
            .base
            .encrypted_amounts
            .get(output_index)
            .ok_or(DepositOutputScanError::IncompleteRingCtData)?;
        decrypt_commitment(encrypted, derivation.shared.deref())
    };

    if output.amount.is_none() {
        let Transaction::V2 { proofs: Some(proofs), .. } = transaction else {
            return Err(DepositOutputScanError::MissingRingCtData.into());
        };
        let Some(expected) = proofs.base.commitments.get(output_index) else {
            return Err(DepositOutputScanError::IncompleteRingCtData.into());
        };
        if commitment.commit().compress() != *expected {
            return Ok(None);
        }
    }
    Ok(Some(commitment))
}

fn decrypt_commitment(encrypted: &EncryptedAmount, shared: &MoneroScalar) -> Commitment {
    match encrypted {
        EncryptedAmount::Original { mask, amount } => {
            let mask_shared = Zeroizing::new(MoneroScalar::hash(<[u8; 32]>::from(*shared)));
            let amount_shared = Zeroizing::new(MoneroScalar::hash(<[u8; 32]>::from(*mask_shared)));
            let mask = DalekScalar::from_bytes_mod_order(*mask) - MoneroScalar::into(*mask_shared);
            let amount = Zeroizing::new(
                DalekScalar::from_bytes_mod_order(*amount) - MoneroScalar::into(*amount_shared),
            );
            let amount = u64::from_le_bytes(
                amount.to_bytes()[..8]
                    .try_into()
                    .expect("a scalar encoding always has eight leading bytes"),
            );
            Commitment::new(MoneroScalar::from(mask), amount)
        }
        EncryptedAmount::Compact { amount } => {
            let mut mask_material = Zeroizing::new(b"commitment_mask".to_vec());
            mask_material.extend_from_slice(&<[u8; 32]>::from(*shared));
            let mask = MoneroScalar::hash(mask_material.as_slice());

            let mut amount_material = Zeroizing::new(b"amount".to_vec());
            amount_material.extend_from_slice(&<[u8; 32]>::from(*shared));
            let mut amount_mask = Zeroizing::new(keccak256(amount_material.as_slice()));
            let mut amount_mask_eight = [0_u8; 8];
            amount_mask_eight.copy_from_slice(&amount_mask[..8]);
            amount_mask.zeroize();
            let amount = u64::from_le_bytes(*amount) ^ u64::from_le_bytes(amount_mask_eight);
            amount_mask_eight.zeroize();
            Commitment::new(mask, amount)
        }
    }
}

fn payment_id_xor(ecdh: &Point) -> [u8; 8] {
    let mut material =
        Zeroizing::new(Point::into(*ecdh).mul_by_cofactor().compress().to_bytes().to_vec());
    material.push(0x8d);
    let mut result = [0_u8; 8];
    result.copy_from_slice(&keccak256(material.as_slice())[..8]);
    result
}

#[expect(clippy::too_many_arguments)]
fn construct_wallet_output<E>(
    transaction_hash: [u8; 32],
    output_index: u64,
    global_output_index: u64,
    output_key: Point,
    key_offset: MoneroScalar,
    commitment: &Commitment,
    timelock: monero_oxide::transaction::Timelock,
    subaddress: Option<DepositSubaddressIndex>,
    payment_id: Option<PaymentId>,
    arbitrary_data: &[Vec<u8>],
) -> Result<WalletOutput, DepositOutputScanFailure<E>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(160));
    bytes.extend_from_slice(&transaction_hash);
    bytes.extend_from_slice(&output_index.to_le_bytes());
    bytes.extend_from_slice(&global_output_index.to_le_bytes());
    bytes.extend_from_slice(&output_key.compress().to_bytes());
    key_offset.write(&mut *bytes).map_err(|_| DepositOutputScanError::WalletOutputEncoding)?;
    commitment.write(&mut *bytes).map_err(|_| DepositOutputScanError::WalletOutputEncoding)?;
    timelock.write(&mut *bytes).map_err(|_| DepositOutputScanError::WalletOutputEncoding)?;

    if let Some(subaddress) = subaddress {
        bytes.push(1);
        bytes.extend_from_slice(&subaddress.account().to_le_bytes());
        bytes.extend_from_slice(&subaddress.address().to_le_bytes());
    } else {
        bytes.push(0);
    }
    if let Some(payment_id) = payment_id {
        bytes.push(1);
        payment_id.write(&mut *bytes).map_err(|_| DepositOutputScanError::WalletOutputEncoding)?;
    } else {
        bytes.push(0);
    }
    VarInt::write(&arbitrary_data.len(), &mut *bytes)
        .map_err(|_| DepositOutputScanError::WalletOutputEncoding)?;
    for data in arbitrary_data {
        let length =
            u8::try_from(data.len()).map_err(|_| DepositOutputScanError::WalletOutputEncoding)?;
        bytes.push(length);
        bytes.extend_from_slice(data);
    }

    let mut reader = bytes.as_slice();
    let output = WalletOutput::read(&mut reader)
        .map_err(|_| DepositOutputScanError::WalletOutputEncoding)?;
    if !reader.is_empty() {
        return Err(DepositOutputScanError::WalletOutputEncoding.into());
    }
    Ok(output)
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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use monero_oxide::{
        block::{Block, BlockHeader},
        ed25519::Scalar as MoneroScalar,
        ringct::{EncryptedAmount, PrunedRctProofs, RctBase, RctType},
        transaction::{Input, Output, TransactionPrefix},
    };
    use monero_wallet::{Scanner, ViewPair, address::SubaddressIndex, extra::ExtraField};

    use super::*;
    use crate::deposit_wallet::DepositAddressDeriver;

    const REAL_SPEND_KEY: &str = "ccf0ea10e1ea64354f42fa710c2b318e581969cf49046d809d1f0aadb3fc7a02";
    const REAL_VIEW_KEY: &str = "a28b4b2085592881df94ee95da332c16b5bb773eb8bb74730208cbb236c73806";

    #[rustfmt::skip]
    const REAL_PRUNED_TRANSACTION: &str = "020001020003060101cf60390bb71aa15eb24037772012d59dc68cb4b6211e1c93206db09a6c346261020002ee8ca293511571c0005e1c144e49d09b8ff03046dbafb3e064a34cb9fc1994b600029e2e5cd08c8681dbcf2ce66071467e835f7e86613fbfed3c4fb170127b94e1072c01d3ce2a622c6e06ed465f81017dd6188c3a6e3d8e65a846f9c98416da0e150a82020901c553d35e54111bd001e0bbcbf289d701ce90e309ead2b487ec1d4d8af5d649543eb99a7620f6b54e532898527be29704f050e6f06de61e5967b2ddd506b4d6d36546065d6aae156ac7bec18c99580c07867fb98cb29853edbafec91af2df605c12f9aaa81a9165625afb6649f5a652012c5ba6612351140e1fb4a8463cc765d0a9bb7d999ba35750f365c5285d77230b76c7a612784f4845812a2899f2ca6a304fee61362db59b263115c27d2ce78af6b1d9e939c1f4036c7707851f41abe6458cf1c748353e593469ebf43536a939f7";

    #[rustfmt::skip]
    const REAL_BLOCK: &str = "0202e8e28efe04db09e2fc4d57854786220bd33e0169ff692440d27ae3932b9219df9ab1d7260b00000000014101ff050580d0acf30e02704972eb1878e94686b62fa4c0202f3e7e3a263073bd6edd751990ea769494ee80c0fc82aa0202edac72ab7c5745d4acaa95f76a3b76e238a55743cd51efb586f968e09821788d80d0dbc3f40202f9b4cf3141aac4203a1aaed01f09326615544997d1b68964928d9aafd07e38e580a0e5b9c29101023405e3aa75b1b7adf04e8c7faa3c3d45616ae740a8b11fb7cc1555dd8b9e4c9180c0dfda8ee90602d2b78accfe1c2ae57bed4fe3385f7735a988f160ef3bbc1f9d7a0c911c26ffd92101d2d55b5066d247a97696be4a84bf70873e4f149687f57e606eb6682f11650e1701b74773bbea995079805398052da9b69244bda034b089b50e4d9151dedb59a12f";

    fn scalar(value: u64) -> DalekScalar {
        DalekScalar::from(value)
    }

    fn scalar_bytes(value: u64) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(scalar(value).to_bytes())
    }

    fn scanner_for_scalars(spend: u64, view: u64) -> BoundedDepositOutputScanner {
        let root = (scalar(spend) * ED25519_BASEPOINT_POINT).compress().to_bytes();
        BoundedDepositOutputScanner::new(
            NetworkKind::Regtest,
            root,
            &scalar_bytes(view),
            DepositOutputScannerLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn wallet_domain_exactly_matches_address_deriver() {
        let root = (scalar(7) * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let view = scalar_bytes(11);
        let scanner = BoundedDepositOutputScanner::new(
            NetworkKind::Testnet,
            root,
            &view,
            DepositOutputScannerLimits::default(),
        )
        .unwrap();
        let deriver = DepositAddressDeriver::new(NetworkKind::Testnet, root, &view).unwrap();
        assert_eq!(scanner.wallet_id(), deriver.wallet_id());
    }

    #[test]
    fn recognized_output_batch_matches_atomic_local_index_capacity() {
        let root = (scalar(7) * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let view = scalar_bytes(11);
        let mut accepted = DepositOutputScannerLimits::default();
        accepted.max_recognized_outputs_per_chunk = 256;
        assert!(
            BoundedDepositOutputScanner::new(NetworkKind::Testnet, root, &view, accepted).is_ok()
        );

        let mut oversized = accepted;
        oversized.max_recognized_outputs_per_chunk = 257;
        assert!(matches!(
            BoundedDepositOutputScanner::new(NetworkKind::Testnet, root, &view, oversized),
            Err(DepositOutputScannerSetupError::InvalidLimits)
        ));
    }

    #[test]
    fn real_original_ringct_vector_matches_monero_wallet_byte_for_byte() {
        let spend_scalar =
            MoneroScalar::read(&mut hex::decode(REAL_SPEND_KEY).unwrap().as_slice()).unwrap();
        let view_bytes: [u8; 32] = hex::decode(REAL_VIEW_KEY).unwrap().try_into().unwrap();
        let private_view = Zeroizing::new(view_bytes);
        let root = (spend_scalar.into() * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let scanner = BoundedDepositOutputScanner::new(
            NetworkKind::Mainnet,
            root,
            &private_view,
            DepositOutputScannerLimits::default(),
        )
        .unwrap();

        let transaction_bytes = hex::decode(REAL_PRUNED_TRANSACTION).unwrap();
        let transaction = Transaction::<Pruned>::read(&mut transaction_bytes.as_slice()).unwrap();
        let block_bytes = hex::decode(REAL_BLOCK).unwrap();
        let block = Block::read(&mut block_bytes.as_slice()).unwrap();
        let scannable = ScannableBlock {
            block,
            transactions: vec![transaction],
            output_index_for_first_ringct_output: Some(0),
        };

        let view_scalar = MoneroScalar::read(&mut private_view.as_slice()).unwrap();
        let root_point = CompressedPoint::from(root).decompress().unwrap();
        let pair = ViewPair::new(root_point, Zeroizing::new(view_scalar)).unwrap();
        let mut reference = Scanner::new(pair);
        let expected = reference.scan(scannable.clone()).unwrap().ignore_additional_timelock();

        let mut lookup = |_: DepositWalletId, _: [u8; 32]| -> Result<_, Infallible> {
            panic!("root-address vector must not perform a durable subaddress lookup")
        };
        let actual = scanner.scan_block(scannable, &mut lookup).unwrap();
        assert!(actual.deposit_outputs().is_empty());
        assert_eq!(actual.root_outputs().len(), 2);
        assert_eq!(
            actual.root_outputs().iter().map(WalletOutput::serialize).collect::<Vec<_>>(),
            expected.iter().map(WalletOutput::serialize).collect::<Vec<_>>()
        );
        assert_eq!(actual.root_outputs()[0].commitment().amount, 10_000);
        assert_eq!(actual.root_outputs()[1].commitment().amount, 10_000);
    }

    #[test]
    fn transaction_scan_yields_and_resumes_without_repeating_lifetime_state() {
        let spend_scalar =
            MoneroScalar::read(&mut hex::decode(REAL_SPEND_KEY).unwrap().as_slice()).unwrap();
        let view_bytes: [u8; 32] = hex::decode(REAL_VIEW_KEY).unwrap().try_into().unwrap();
        let private_view = Zeroizing::new(view_bytes);
        let root = (spend_scalar.into() * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let mut limits = DepositOutputScannerLimits::default();
        limits.max_derivations_per_transaction = 1;
        let scanner =
            BoundedDepositOutputScanner::new(NetworkKind::Mainnet, root, &private_view, limits)
                .unwrap();
        let transaction_bytes = hex::decode(REAL_PRUNED_TRANSACTION).unwrap();
        let transaction = Transaction::<Pruned>::read(&mut transaction_bytes.as_slice()).unwrap();
        let transaction_hash = [91; 32];
        let mut lookup = |_: DepositWalletId, _: [u8; 32]| -> Result<_, Infallible> {
            panic!("root-address vector must not perform a durable subaddress lookup")
        };

        let mut cursor = DepositTransactionScanCursor::start();
        let mut outputs = Vec::new();
        let mut chunks = 0;
        loop {
            let chunk = scanner
                .scan_transaction_chunk(16, transaction_hash, 0, &transaction, cursor, &mut lookup)
                .unwrap();
            chunks += 1;
            let (recognized, continuation) = chunk.into_parts();
            outputs.extend(recognized);
            let Some(continuation) = continuation else {
                break;
            };
            cursor = continuation;
        }
        assert!(chunks >= 2);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].output().index_in_transaction(), 0);
        assert_eq!(outputs[1].output().index_in_transaction(), 1);
    }

    #[test]
    fn serialized_compact_ringct_additional_key_subaddress_matches_reference_scanner() {
        let spend = scalar(7);
        let view = scalar(11);
        let root = spend * ED25519_BASEPOINT_POINT;
        let index = DepositSubaddressIndex::new(0, 17).unwrap();
        let monero_index = SubaddressIndex::new(0, 17).unwrap();
        let scanner = scanner_for_scalars(7, 11);

        let subaddress_derivation = MoneroScalar::hash(
            [
                b"SubAddr\0".as_slice(),
                &view.to_bytes(),
                &0_u32.to_le_bytes(),
                &17_u32.to_le_bytes(),
            ]
            .concat(),
        )
        .into();
        let subaddress_spend = root + (subaddress_derivation * ED25519_BASEPOINT_POINT);

        let primary_secret = scalar(13);
        let additional_secret = scalar(19);
        let primary_key = primary_secret * ED25519_BASEPOINT_POINT;
        let additional_key = additional_secret * subaddress_spend;
        let shared = derive_output(&view, Point::from(additional_key), 0);
        let output_key = subaddress_spend + (shared.shared_scalar() * ED25519_BASEPOINT_POINT);
        let amount = 42_424_242_u64;
        let mask = {
            let mut material = b"commitment_mask".to_vec();
            material.extend_from_slice(&<[u8; 32]>::from(*shared.shared));
            MoneroScalar::hash(material)
        };
        let commitment = Commitment::new(mask, amount);
        let encrypted_amount = {
            let mut material = b"amount".to_vec();
            material.extend_from_slice(&<[u8; 32]>::from(*shared.shared));
            let hash = keccak256(material);
            let mut first = [0_u8; 8];
            first.copy_from_slice(&hash[..8]);
            EncryptedAmount::Compact { amount: (amount ^ u64::from_le_bytes(first)).to_le_bytes() }
        };

        let mut extra = ExtraField::PublicKey(Point::from(primary_key).compress()).serialize();
        extra.extend(
            ExtraField::PublicKeys(vec![Point::from(additional_key).compress()]).serialize(),
        );
        let transaction = Transaction::<Pruned>::V2 {
            prefix: TransactionPrefix {
                additional_timelock: monero_oxide::transaction::Timelock::None,
                inputs: vec![Input::ToKey {
                    amount: None,
                    key_offsets: vec![1],
                    key_image: Point::from(scalar(23) * ED25519_BASEPOINT_POINT).compress(),
                }],
                outputs: vec![Output {
                    amount: None,
                    key: Point::from(output_key).compress(),
                    view_tag: Some(shared.view_tag),
                }],
                extra,
            },
            proofs: Some(PrunedRctProofs {
                rct_type: RctType::ClsagBulletproofPlus,
                base: RctBase {
                    fee: 10,
                    pseudo_outs: vec![],
                    encrypted_amounts: vec![encrypted_amount],
                    commitments: vec![commitment.commit().compress()],
                },
            }),
        };
        let serialized = transaction.serialize();
        let mut serialized_reader = serialized.as_slice();
        let transaction = Transaction::<Pruned>::read(&mut serialized_reader).unwrap();
        assert!(serialized_reader.is_empty());
        assert_eq!(transaction.serialize(), serialized);

        let transaction_hash = [0x42; 32];
        let miner = Transaction::V1 {
            prefix: TransactionPrefix {
                additional_timelock: monero_oxide::transaction::Timelock::None,
                inputs: vec![Input::Gen(1)],
                outputs: vec![],
                extra: vec![],
            },
            signatures: vec![],
        };
        let block = Block::new(
            BlockHeader {
                hardfork_version: 16,
                hardfork_signal: 16,
                timestamp: 1,
                previous: [9; 32],
                nonce: 0,
            },
            miner,
            vec![transaction_hash],
        )
        .unwrap();
        let scannable = ScannableBlock {
            block,
            transactions: vec![transaction],
            output_index_for_first_ringct_output: Some(700),
        };

        let pair =
            ViewPair::new(Point::from(root), Zeroizing::new(MoneroScalar::from(view))).unwrap();
        let mut reference = Scanner::new(pair);
        reference.register_subaddress(monero_index);
        let expected = reference.scan(scannable.clone()).unwrap().ignore_additional_timelock();

        let expected_spend = subaddress_spend.compress().to_bytes();
        let mut lookups = 0_u8;
        let mut lookup = |wallet: DepositWalletId, key: [u8; 32]| {
            assert_eq!(wallet, scanner.wallet_id());
            lookups = lookups.saturating_add(1);
            Ok::<_, Infallible>((key == expected_spend).then_some(index))
        };
        let actual = scanner.scan_block(scannable, &mut lookup).unwrap();
        assert!(actual.root_outputs().is_empty());
        assert_eq!(actual.deposit_outputs().len(), 1);
        assert_eq!(lookups, 1);
        assert_eq!(actual.deposit_outputs()[0].serialize(), expected[0].serialize());
        assert_eq!(actual.deposit_outputs()[0].commitment().amount, amount);
        assert_eq!(actual.deposit_outputs()[0].subaddress(), Some(monero_index));
        assert_eq!(actual.deposit_outputs()[0].index_on_blockchain(), 700);
    }

    #[test]
    fn corrupt_reverse_alias_is_rejected_before_output_release() {
        let scanner = scanner_for_scalars(7, 11);
        let wrong = DepositSubaddressIndex::new(0, 99).unwrap();
        let transaction = compact_subaddress_transaction(7, 11, 0, 17);
        let mut lookup = |_: DepositWalletId, _: [u8; 32]| Ok::<_, Infallible>(Some(wrong));
        assert!(matches!(
            scanner.scan_transaction(16, [3; 32], 10, &transaction, &mut lookup),
            Err(DepositOutputScanFailure::Scan(
                DepositOutputScanError::CorruptSubaddressSpendKeyAlias
            ))
        ));
    }

    fn compact_subaddress_transaction(
        spend_value: u64,
        view_value: u64,
        account: u32,
        address: u32,
    ) -> Transaction<Pruned> {
        let spend = scalar(spend_value);
        let view = scalar(view_value);
        let derivation_scalar: DalekScalar = MoneroScalar::hash(
            [
                b"SubAddr\0".as_slice(),
                &view.to_bytes(),
                &account.to_le_bytes(),
                &address.to_le_bytes(),
            ]
            .concat(),
        )
        .into();
        let subaddress_spend =
            (spend * ED25519_BASEPOINT_POINT) + (derivation_scalar * ED25519_BASEPOINT_POINT);
        let transaction_key = scalar(29) * subaddress_spend;
        let shared = derive_output(&view, Point::from(transaction_key), 0);
        let output_key = subaddress_spend + (shared.shared_scalar() * ED25519_BASEPOINT_POINT);
        let amount = 5_u64;
        let mut mask_material = b"commitment_mask".to_vec();
        mask_material.extend_from_slice(&<[u8; 32]>::from(*shared.shared));
        let commitment = Commitment::new(MoneroScalar::hash(mask_material), amount);
        let mut amount_material = b"amount".to_vec();
        amount_material.extend_from_slice(&<[u8; 32]>::from(*shared.shared));
        let amount_mask = keccak256(amount_material);
        let mut first = [0_u8; 8];
        first.copy_from_slice(&amount_mask[..8]);

        Transaction::V2 {
            prefix: TransactionPrefix {
                additional_timelock: monero_oxide::transaction::Timelock::None,
                inputs: vec![Input::ToKey {
                    amount: None,
                    key_offsets: vec![1],
                    key_image: Point::from(scalar(31) * ED25519_BASEPOINT_POINT).compress(),
                }],
                outputs: vec![Output {
                    amount: None,
                    key: Point::from(output_key).compress(),
                    view_tag: Some(shared.view_tag),
                }],
                extra: ExtraField::PublicKey(Point::from(transaction_key).compress()).serialize(),
            },
            proofs: Some(PrunedRctProofs {
                rct_type: RctType::ClsagBulletproofPlus,
                base: RctBase {
                    fee: 1,
                    pseudo_outs: vec![],
                    encrypted_amounts: vec![EncryptedAmount::Compact {
                        amount: (amount ^ u64::from_le_bytes(first)).to_le_bytes(),
                    }],
                    commitments: vec![commitment.commit().compress()],
                },
            }),
        }
    }
}
