use std::{
    collections::{BTreeMap, HashMap},
    io::Cursor,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use curve25519_dalek::{Scalar as DalekScalar, constants::ED25519_BASEPOINT_POINT};
use frost::{
    Participant, ThresholdKeys, ThresholdParams,
    curve::{Ciphersuite, Ed25519},
    dkg::Interpolation,
};
use monero_wallet::{
    OutputWithDecoys, WalletOutput,
    ed25519::{Commitment, Point, Scalar},
    interface::FeeRate,
    ringct::clsag::Decoys,
    transaction::Timelock,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use threshold_monero::{
    Committee, Member, NetworkKind, PartyId, SessionId,
    deposit_consolidation::AttemptBinding,
    deposit_wallet::{
        ChainPoint, DepositAddressDeriver, DepositSubaddressIndex, DepositWalletError,
        PersistedRootOutput, PersistedWalletOutput, ScannedBlock, SignedSweepTransaction, SweepId,
        SweepStatus, WalletOutputId, derive_sweep_signing_session,
    },
    deposit_worker::{
        CanonicalTransactionKeyImages, ChainFuture, ChainSourceError, DepositBlockScanCursor,
        DepositBlockScanResult, DepositChainSource, DepositOutputBinding,
        DepositOutputIndexBackend, DepositWorkerConfig, DepositWorkerError, DepositWorkerState,
        FetchedDepositBlock, FetchedDepositBlockEvidence, PortableOutputBindingStatus,
        PreparedSweepIntent, SweepSigningSessionTombstone, root_consolidation_destination_binding,
    },
    signing::{CanonicalSignerSet, FrostlassSigner, threshold_group_key},
};
use zeroize::Zeroizing;

type FrostScalar = <Ed25519 as Ciphersuite>::F;

fn root_key(secret: u64) -> [u8; 32] {
    (ED25519_BASEPOINT_POINT * DalekScalar::from(secret)).compress().to_bytes()
}

fn single_party_keys() -> ThresholdKeys<Ed25519> {
    let participant = Participant::new(1).unwrap();
    let secret = FrostScalar::from(42_u64);
    ThresholdKeys::new(
        ThresholdParams::new(1, 1, participant).unwrap(),
        Interpolation::Lagrange,
        Zeroizing::new(secret),
        HashMap::from([(participant, <Ed25519 as Ciphersuite>::generator() * secret)]),
    )
    .unwrap()
}

fn single_party_committee() -> Committee {
    Committee {
        epoch: 7,
        threshold: 1,
        members: vec![Member { id: PartyId(1), signing_key: [31; 32], encryption_key: [32; 32] }],
    }
}

fn with_decoys(output: &WalletOutput) -> OutputWithDecoys {
    let commitment = output.commitment().clone();
    let real = [output.key(), commitment.commit()];
    let ring = (0_u64..16)
        .map(|position| {
            if position == 5 {
                real
            } else {
                let mask = Scalar::from(DalekScalar::from(100 + position));
                [
                    Point::from(ED25519_BASEPOINT_POINT * DalekScalar::from(200 + position)),
                    Commitment::new(mask, 1_000 + position).commit(),
                ]
            }
        })
        .collect::<Vec<_>>();
    let mut offsets = vec![1; 16];
    offsets[0] = output.index_on_blockchain().checked_sub(5).unwrap();
    let decoys = Decoys::new(offsets, 5, ring).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&output.key().compress().to_bytes());
    output.key_offset().write(&mut bytes).unwrap();
    commitment.write(&mut bytes).unwrap();
    decoys.write(&mut bytes).unwrap();
    let mut reader = Cursor::new(bytes.as_slice());
    let input = OutputWithDecoys::read(&mut reader).unwrap();
    assert_eq!(usize::try_from(reader.position()).unwrap(), bytes.len());
    input
}

fn transaction_key_images(transaction: &monero_oxide::transaction::Transaction) -> Vec<[u8; 32]> {
    let monero_oxide::transaction::Transaction::V2 { prefix, proofs: Some(_), .. } = transaction
    else {
        panic!("expected a signed RingCT transaction");
    };
    prefix
        .inputs
        .iter()
        .map(|input| match input {
            monero_oxide::transaction::Input::ToKey { key_image, .. } => key_image.to_bytes(),
            monero_oxide::transaction::Input::Gen(_) => panic!("unexpected miner input"),
        })
        .collect()
}

fn expected_key_image(output: &WalletOutput) -> [u8; 32] {
    let offset = Option::<DalekScalar>::from(DalekScalar::from_canonical_bytes(<[u8; 32]>::from(
        output.key_offset(),
    )))
    .unwrap();
    let secret = DalekScalar::from(42_u64) + offset;
    let generator: curve25519_dalek::EdwardsPoint =
        Point::biased_hash(output.key().compress().to_bytes()).into();
    (generator * secret).compress().to_bytes()
}

fn deriver() -> DepositAddressDeriver {
    DepositAddressDeriver::new(
        NetworkKind::Mainnet,
        root_key(42),
        &Zeroizing::new(DalekScalar::from(17_u64).to_bytes()),
    )
    .unwrap()
}

fn index(address: u32) -> DepositSubaddressIndex {
    DepositSubaddressIndex::new(0, address).unwrap()
}

fn point(height: u64, byte: u8) -> ChainPoint {
    ChainPoint::new(height, [byte; 32]).unwrap()
}

fn scanned_output(
    offset: u64,
    transaction_byte: u8,
    blockchain_index: u64,
) -> PersistedWalletOutput {
    scanned_output_at(offset, transaction_byte, 0, blockchain_index)
}

fn scanned_output_at(
    offset: u64,
    transaction_byte: u8,
    transaction_index: u64,
    blockchain_index: u64,
) -> PersistedWalletOutput {
    let offset = DalekScalar::from(offset);
    let output_key = ED25519_BASEPOINT_POINT * (DalekScalar::from(42_u64) + offset);
    let commitment = Commitment::new(Scalar::from(DalekScalar::from(77_u64)), 10_000_000);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[transaction_byte; 32]);
    bytes.extend_from_slice(&transaction_index.to_le_bytes());
    bytes.extend_from_slice(&blockchain_index.to_le_bytes());
    bytes.extend_from_slice(&output_key.compress().to_bytes());
    bytes.extend_from_slice(&offset.to_bytes());
    commitment.write(&mut bytes).unwrap();
    Timelock::None.write(&mut bytes).unwrap();
    bytes.push(1);
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.push(0);
    bytes.push(0);

    let mut reader = Cursor::new(bytes.as_slice());
    let output = WalletOutput::read(&mut reader).unwrap();
    assert_eq!(usize::try_from(reader.position()).unwrap(), bytes.len());
    PersistedWalletOutput::from_scanner(&output).unwrap()
}

fn scanned_root_output(
    offset: u64,
    transaction_byte: u8,
    blockchain_index: u64,
) -> PersistedRootOutput {
    scanned_root_output_for_transaction(offset, [transaction_byte; 32], 0, blockchain_index)
}

fn scanned_root_output_for_transaction(
    offset: u64,
    transaction: [u8; 32],
    transaction_index: u64,
    blockchain_index: u64,
) -> PersistedRootOutput {
    let offset = DalekScalar::from(offset);
    let output_key = ED25519_BASEPOINT_POINT * (DalekScalar::from(42_u64) + offset);
    let commitment = Commitment::new(Scalar::from(DalekScalar::from(78_u64)), 9_000_000);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&transaction);
    bytes.extend_from_slice(&transaction_index.to_le_bytes());
    bytes.extend_from_slice(&blockchain_index.to_le_bytes());
    bytes.extend_from_slice(&output_key.compress().to_bytes());
    bytes.extend_from_slice(&offset.to_bytes());
    commitment.write(&mut bytes).unwrap();
    Timelock::None.write(&mut bytes).unwrap();
    bytes.push(0);
    bytes.push(0);
    bytes.push(0);

    let mut reader = Cursor::new(bytes.as_slice());
    let output = WalletOutput::read(&mut reader).unwrap();
    assert_eq!(usize::try_from(reader.position()).unwrap(), bytes.len());
    PersistedRootOutput::from_scanner(&output).unwrap()
}

fn block(height: u64, hash: u8, parent: u8) -> FetchedDepositBlock {
    FetchedDepositBlock {
        block: ScannedBlock { point: point(height, hash), parent_hash: [parent; 32] },
        timestamp: 1_700_000_000 + height,
        hardfork_version: 16,
        outputs: vec![],
        root_outputs: vec![],
    }
}

#[derive(Clone)]
struct MockChain {
    latest: Arc<AtomicU64>,
    blocks: Arc<RwLock<BTreeMap<u64, FetchedDepositBlock>>>,
    transactions:
        Arc<RwLock<BTreeMap<u64, Vec<threshold_monero::deposit_wallet::SignedSweepTransaction>>>>,
    transaction_key_images: Arc<RwLock<BTreeMap<u64, Vec<CanonicalTransactionKeyImages>>>>,
    fetched_transactions:
        Arc<RwLock<BTreeMap<[u8; 32], threshold_monero::deposit_wallet::SignedSweepTransaction>>>,
    deferred_scans: Arc<AtomicU64>,
    delay: Duration,
}

impl MockChain {
    fn new(blocks: impl IntoIterator<Item = FetchedDepositBlock>) -> Self {
        let blocks = blocks
            .into_iter()
            .map(|block| (block.block.point.height, block))
            .collect::<BTreeMap<_, _>>();
        let latest = blocks.last_key_value().unwrap().0;
        Self {
            latest: Arc::new(AtomicU64::new(*latest)),
            blocks: Arc::new(RwLock::new(blocks)),
            transactions: Arc::new(RwLock::new(BTreeMap::new())),
            transaction_key_images: Arc::new(RwLock::new(BTreeMap::new())),
            fetched_transactions: Arc::new(RwLock::new(BTreeMap::new())),
            deferred_scans: Arc::new(AtomicU64::new(0)),
            delay: Duration::ZERO,
        }
    }

    fn defer_next_scan(self) -> Self {
        self.deferred_scans.store(1, Ordering::SeqCst);
        self
    }

    fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    fn replace(&self, replacement: FetchedDepositBlock) {
        let height = replacement.block.point.height;
        self.blocks.write().unwrap().insert(height, replacement);
        self.transactions.write().unwrap().remove(&height);
        self.transaction_key_images.write().unwrap().remove(&height);
    }

    fn push(&self, next: FetchedDepositBlock) {
        let height = next.block.point.height;
        self.blocks.write().unwrap().insert(height, next);
        self.latest.fetch_max(height, Ordering::SeqCst);
    }

    fn include_transaction(
        &self,
        height: u64,
        transaction: &monero_oxide::transaction::Transaction,
    ) {
        let transaction_id = transaction.hash();
        self.transactions.write().unwrap().entry(height).or_default().push(
            threshold_monero::deposit_wallet::SignedSweepTransaction::from_transaction(
                transaction,
                Some(transaction_id),
            )
            .unwrap(),
        );
        self.include_transaction_key_images(
            height,
            transaction_id,
            transaction_key_images(transaction),
        );
    }

    fn include_transaction_key_images(
        &self,
        height: u64,
        transaction: [u8; 32],
        key_images: Vec<[u8; 32]>,
    ) {
        let mut evidence = self.transaction_key_images.write().unwrap();
        let evidence = evidence.entry(height).or_default();
        if let Some(existing) = evidence.iter_mut().find(|entry| entry.transaction == transaction) {
            existing.key_images = key_images;
        } else {
            evidence.push(CanonicalTransactionKeyImages { transaction, key_images });
        }
    }

    fn set_fetched_transaction(
        &self,
        requested: [u8; 32],
        transaction: Option<&monero_oxide::transaction::Transaction>,
    ) {
        let mut fetched = self.fetched_transactions.write().unwrap();
        if let Some(transaction) = transaction {
            fetched.insert(
                requested,
                threshold_monero::deposit_wallet::SignedSweepTransaction::from_transaction(
                    transaction,
                    Some(transaction.hash()),
                )
                .unwrap(),
            );
        } else {
            fetched.remove(&requested);
        }
    }
}

impl DepositChainSource for MockChain {
    fn latest_height(&self) -> ChainFuture<'_, u64> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            Ok(self.latest.load(Ordering::SeqCst))
        })
    }

    fn block_hash(&self, height: u64) -> ChainFuture<'_, [u8; 32]> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            self.blocks
                .read()
                .unwrap()
                .get(&height)
                .map(|block| block.block.point.hash)
                .ok_or_else(|| ChainSourceError::Rpc(format!("missing mock block {height}")))
        })
    }

    fn scanned_block_evidence<'a>(
        &'a self,
        height: u64,
        _deriver: &'a DepositAddressDeriver,
        _output_index: &'a dyn DepositOutputIndexBackend,
        _portable_snapshot: [u8; 32],
        _resume: Option<DepositBlockScanCursor>,
    ) -> ChainFuture<'a, DepositBlockScanResult> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            let block = self
                .blocks
                .read()
                .unwrap()
                .get(&height)
                .cloned()
                .ok_or_else(|| ChainSourceError::Rpc(format!("missing mock block {height}")))?;
            if self
                .deferred_scans
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                let next_cursor = DepositBlockScanCursor::new(
                    block.block,
                    _portable_snapshot,
                    0,
                    threshold_monero::deposit_output_scanner::DepositTransactionScanCursor::start(),
                    0,
                );
                return Ok(DepositBlockScanResult::Deferred { block, next_cursor });
            }
            let transactions =
                self.transactions.read().unwrap().get(&height).cloned().unwrap_or_default();
            let transaction_key_images = self
                .transaction_key_images
                .read()
                .unwrap()
                .get(&height)
                .cloned()
                .unwrap_or_default();
            Ok(DepositBlockScanResult::Complete(FetchedDepositBlockEvidence {
                block,
                transactions,
                transaction_key_images,
                transaction_key_images_complete: true,
            }))
        })
    }

    fn full_transaction(
        &self,
        transaction: [u8; 32],
    ) -> ChainFuture<'_, Option<threshold_monero::deposit_wallet::SignedSweepTransaction>> {
        Box::pin(
            async move { Ok(self.fetched_transactions.read().unwrap().get(&transaction).cloned()) },
        )
    }
}

#[derive(Clone)]
struct ChunkedMockChain {
    canonical: MockChain,
    chunks: Arc<Vec<FetchedDepositBlock>>,
    next_chunk: Arc<AtomicU64>,
}

impl ChunkedMockChain {
    fn new(anchor: FetchedDepositBlock, chunks: Vec<FetchedDepositBlock>) -> Self {
        assert!(!chunks.is_empty());
        let mut canonical = chunks.last().unwrap().clone();
        canonical.outputs.clear();
        canonical.root_outputs.clear();
        Self {
            canonical: MockChain::new([anchor, canonical]),
            chunks: Arc::new(chunks),
            next_chunk: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl DepositChainSource for ChunkedMockChain {
    fn latest_height(&self) -> ChainFuture<'_, u64> {
        self.canonical.latest_height()
    }

    fn block_hash(&self, height: u64) -> ChainFuture<'_, [u8; 32]> {
        self.canonical.block_hash(height)
    }

    fn scanned_block_evidence<'a>(
        &'a self,
        height: u64,
        _deriver: &'a DepositAddressDeriver,
        _output_index: &'a dyn DepositOutputIndexBackend,
        portable_snapshot: [u8; 32],
        _resume: Option<DepositBlockScanCursor>,
    ) -> ChainFuture<'a, DepositBlockScanResult> {
        Box::pin(async move {
            let chunk_index = usize::try_from(self.next_chunk.fetch_add(1, Ordering::SeqCst))
                .map_err(|_| ChainSourceError::Invalid("mock chunk index overflow".to_owned()))?;
            let block = self
                .chunks
                .get(chunk_index)
                .cloned()
                .ok_or_else(|| ChainSourceError::Invalid("mock scan exhausted".to_owned()))?;
            if block.block.point.height != height {
                return Err(ChainSourceError::Invalid("mock chunk height mismatch".to_owned()));
            }
            if chunk_index + 1 < self.chunks.len() {
                let next_cursor = DepositBlockScanCursor::new(
                    block.block,
                    portable_snapshot,
                    0,
                    threshold_monero::deposit_output_scanner::DepositTransactionScanCursor::start(),
                    0,
                );
                Ok(DepositBlockScanResult::Deferred { block, next_cursor })
            } else {
                Ok(DepositBlockScanResult::Complete(FetchedDepositBlockEvidence {
                    block,
                    transactions: Vec::new(),
                    transaction_key_images: Vec::new(),
                    transaction_key_images_complete: true,
                }))
            }
        })
    }
}

#[derive(Clone, Default)]
struct CompletePrefixThenDeferredChain {
    scans: Arc<Mutex<Vec<(u64, bool)>>>,
}

impl CompletePrefixThenDeferredChain {
    fn scans(&self) -> Vec<(u64, bool)> {
        self.scans.lock().unwrap().clone()
    }
}

impl DepositChainSource for CompletePrefixThenDeferredChain {
    fn latest_height(&self) -> ChainFuture<'_, u64> {
        Box::pin(async { Ok(12) })
    }

    fn block_hash(&self, height: u64) -> ChainFuture<'_, [u8; 32]> {
        Box::pin(async move {
            match height {
                10..=12 => Ok([u8::try_from(height).unwrap(); 32]),
                _ => Err(ChainSourceError::Rpc(format!("missing mock block {height}"))),
            }
        })
    }

    fn scanned_block_evidence<'a>(
        &'a self,
        height: u64,
        _deriver: &'a DepositAddressDeriver,
        _output_index: &'a dyn DepositOutputIndexBackend,
        portable_snapshot: [u8; 32],
        resume: Option<DepositBlockScanCursor>,
    ) -> ChainFuture<'a, DepositBlockScanResult> {
        Box::pin(async move {
            let resuming = resume.is_some();
            self.scans.lock().unwrap().push((height, resuming));
            let mut fetched = match height {
                11 => block(11, 11, 10),
                12 => block(12, 12, 11),
                _ => {
                    return Err(ChainSourceError::Rpc(format!(
                        "unexpected mock scan at height {height}"
                    )));
                }
            };
            if height == 11 {
                fetched.outputs.push(scanned_output(9, 30, 99));
            } else if resuming {
                fetched.outputs.push(scanned_output(11, 32, 101));
            } else {
                fetched.outputs.push(scanned_output(10, 31, 100));
            }
            match (height, resume) {
                (11, None) => Ok(DepositBlockScanResult::Complete(
                    FetchedDepositBlockEvidence {
                        block: fetched,
                        transactions: Vec::new(),
                        transaction_key_images: Vec::new(),
                        transaction_key_images_complete: true,
                    },
                )),
                (12, None) => Ok(DepositBlockScanResult::Deferred {
                    next_cursor: DepositBlockScanCursor::new(
                        fetched.block,
                        portable_snapshot,
                        1,
                        threshold_monero::deposit_output_scanner::DepositTransactionScanCursor::start(
                        ),
                        0,
                    ),
                    block: fetched,
                }),
                (12, Some(cursor))
                    if cursor.block() == fetched.block
                        && cursor.portable_snapshot() == portable_snapshot =>
                {
                    Ok(DepositBlockScanResult::Complete(FetchedDepositBlockEvidence {
                        block: fetched,
                        transactions: Vec::new(),
                        transaction_key_images: Vec::new(),
                        transaction_key_images_complete: true,
                    }))
                }
                _ => Err(ChainSourceError::Invalid(
                    "invalid complete-prefix/deferred resume sequence".to_owned(),
                )),
            }
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct MockOutputIndex;

const OUTPUT_INDEX: MockOutputIndex = MockOutputIndex;

impl DepositOutputIndexBackend for MockOutputIndex {
    fn portable_snapshot(
        &self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
    ) -> ChainFuture<'_, [u8; 32]> {
        Box::pin(async { Ok([1; 32]) })
    }

    fn preload_subaddress_spend_keys<'a>(
        &'a self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
        _portable_snapshot: [u8; 32],
        spend_keys: &'a [[u8; 32]],
    ) -> ChainFuture<'a, Vec<Option<DepositSubaddressIndex>>> {
        Box::pin(async move { Ok(vec![None; spend_keys.len()]) })
    }

    fn bind_outputs<'a>(
        &'a self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
        _portable_snapshot: [u8; 32],
        _bindings: &'a [DepositOutputBinding],
    ) -> ChainFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn classify_portable_output_bindings<'a>(
        &'a self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
        _portable_snapshot: [u8; 32],
        bindings: &'a [DepositOutputBinding],
    ) -> ChainFuture<'a, Vec<PortableOutputBindingStatus>> {
        Box::pin(
            async move { Ok(vec![PortableOutputBindingStatus::UnseenUnclaimed; bindings.len()]) },
        )
    }
}

#[derive(Clone, Debug)]
struct ClassifyingOutputIndex {
    statuses: Arc<BTreeMap<WalletOutputId, PortableOutputBindingStatus>>,
}

impl ClassifyingOutputIndex {
    fn new(
        statuses: impl IntoIterator<Item = (WalletOutputId, PortableOutputBindingStatus)>,
    ) -> Self {
        Self { statuses: Arc::new(statuses.into_iter().collect()) }
    }
}

impl DepositOutputIndexBackend for ClassifyingOutputIndex {
    fn portable_snapshot(
        &self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
    ) -> ChainFuture<'_, [u8; 32]> {
        Box::pin(async { Ok([1; 32]) })
    }

    fn preload_subaddress_spend_keys<'a>(
        &'a self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
        _portable_snapshot: [u8; 32],
        spend_keys: &'a [[u8; 32]],
    ) -> ChainFuture<'a, Vec<Option<DepositSubaddressIndex>>> {
        Box::pin(async move { Ok(vec![None; spend_keys.len()]) })
    }

    fn bind_outputs<'a>(
        &'a self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
        _portable_snapshot: [u8; 32],
        _bindings: &'a [DepositOutputBinding],
    ) -> ChainFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn classify_portable_output_bindings<'a>(
        &'a self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
        _portable_snapshot: [u8; 32],
        bindings: &'a [DepositOutputBinding],
    ) -> ChainFuture<'a, Vec<PortableOutputBindingStatus>> {
        Box::pin(async move {
            Ok(bindings
                .iter()
                .map(|binding| {
                    self.statuses
                        .get(&binding.output)
                        .copied()
                        .unwrap_or(PortableOutputBindingStatus::UnseenUnclaimed)
                })
                .collect())
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct RejectingBindOutputIndex;

impl DepositOutputIndexBackend for RejectingBindOutputIndex {
    fn portable_snapshot(
        &self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
    ) -> ChainFuture<'_, [u8; 32]> {
        Box::pin(async { Ok([1; 32]) })
    }

    fn preload_subaddress_spend_keys<'a>(
        &'a self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
        _portable_snapshot: [u8; 32],
        spend_keys: &'a [[u8; 32]],
    ) -> ChainFuture<'a, Vec<Option<DepositSubaddressIndex>>> {
        Box::pin(async move { Ok(vec![None; spend_keys.len()]) })
    }

    fn bind_outputs<'a>(
        &'a self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
        _portable_snapshot: [u8; 32],
        _bindings: &'a [DepositOutputBinding],
    ) -> ChainFuture<'a, ()> {
        Box::pin(async {
            Err(ChainSourceError::Invalid("injected local output-index failure".to_owned()))
        })
    }

    fn classify_portable_output_bindings<'a>(
        &'a self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
        _portable_snapshot: [u8; 32],
        bindings: &'a [DepositOutputBinding],
    ) -> ChainFuture<'a, Vec<PortableOutputBindingStatus>> {
        Box::pin(
            async move { Ok(vec![PortableOutputBindingStatus::UnseenUnclaimed; bindings.len()]) },
        )
    }
}

#[derive(Debug, Default)]
struct RecordingOutputIndex {
    binding_chunk_lengths: Mutex<Vec<usize>>,
}

impl DepositOutputIndexBackend for RecordingOutputIndex {
    fn portable_snapshot(
        &self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
    ) -> ChainFuture<'_, [u8; 32]> {
        Box::pin(async { Ok([1; 32]) })
    }

    fn preload_subaddress_spend_keys<'a>(
        &'a self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
        _portable_snapshot: [u8; 32],
        spend_keys: &'a [[u8; 32]],
    ) -> ChainFuture<'a, Vec<Option<DepositSubaddressIndex>>> {
        Box::pin(async move { Ok(vec![None; spend_keys.len()]) })
    }

    fn bind_outputs<'a>(
        &'a self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
        _portable_snapshot: [u8; 32],
        bindings: &'a [DepositOutputBinding],
    ) -> ChainFuture<'a, ()> {
        Box::pin(async move {
            self.binding_chunk_lengths.lock().unwrap().push(bindings.len());
            Ok(())
        })
    }

    fn classify_portable_output_bindings<'a>(
        &'a self,
        _wallet: threshold_monero::deposit_wallet::DepositWalletId,
        _portable_snapshot: [u8; 32],
        bindings: &'a [DepositOutputBinding],
    ) -> ChainFuture<'a, Vec<PortableOutputBindingStatus>> {
        Box::pin(
            async move { Ok(vec![PortableOutputBindingStatus::UnseenUnclaimed; bindings.len()]) },
        )
    }
}

fn worker(config: DepositWorkerConfig) -> (DepositAddressDeriver, DepositWorkerState) {
    let deriver = deriver();
    let mut state = DepositWorkerState::new(&deriver, point(10, 10), config).unwrap();
    state.initialize_portable_index_head([1; 32]).unwrap();
    (deriver, state)
}

#[test]
fn worker_requires_moneros_full_deterministic_unlock_time_window() {
    let too_short = DepositWorkerConfig { max_reorg_depth: 59, ..Default::default() };
    assert!(matches!(too_short.validate(), Err(DepositWorkerError::InvalidConfig)));
    let exact = DepositWorkerConfig { max_reorg_depth: 60, ..Default::default() };
    assert_eq!(exact.validate().unwrap(), exact);
}

#[test]
fn pending_block_output_memory_bound_is_explicit() {
    assert!(
        DepositWorkerConfig { max_outputs_per_block: 4096, ..Default::default() }
            .validate()
            .is_ok()
    );
    assert!(matches!(
        DepositWorkerConfig { max_outputs_per_block: 4097, ..Default::default() }.validate(),
        Err(DepositWorkerError::InvalidConfig)
    ));
}

#[tokio::test]
async fn output_bindings_must_commit_before_scanner_cursor_advances() {
    let mut deposit_block = block(11, 11, 10);
    deposit_block.outputs.push(scanned_output(9, 30, 99));
    let source = MockChain::new([block(10, 10, 9), deposit_block]);
    let config = DepositWorkerConfig { confirmation_depth: 1, ..Default::default() };
    let (deriver, mut state) = worker(config);
    let before = state.clone();

    assert!(matches!(
        state.tick(&source, &deriver, &RejectingBindOutputIndex).await,
        Err(DepositWorkerError::ChainSource(ChainSourceError::Invalid(message)))
            if message == "injected local output-index failure"
    ));
    assert_eq!(state, before);
}

#[tokio::test]
async fn portable_claim_owner_is_durable_and_excludes_the_input_after_restart() {
    let output = scanned_output(9, 30, 99);
    let mut blocks = vec![block(10, 10, 9)];
    for height in 11_u64..=20 {
        let mut next =
            block(height, u8::try_from(height).unwrap(), u8::try_from(height - 1).unwrap());
        if height == 11 {
            next.outputs.push(output.clone());
        }
        blocks.push(next);
    }
    let source = MockChain::new(blocks);
    let owner = SweepId([0x41; 32]);
    let output_index = ClassifyingOutputIndex::new([(
        output.id(),
        PortableOutputBindingStatus::UnseenClaimed(owner),
    )]);
    let config = DepositWorkerConfig {
        confirmation_depth: 1,
        minimum_sweep_atomic_units: 1,
        ..Default::default()
    };
    let (deriver, mut state) = worker(config);

    let tick = state.tick(&source, &deriver, &output_index).await.unwrap();
    let effect = tick.persistence.unwrap();
    let events = state.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    assert_eq!(events.detections.len(), 1);
    assert_eq!(events.detections[0].output, output.id());
    state.acknowledge_events(events.id).unwrap();
    assert!(state.scan_state().output(output.id()).is_some());
    assert!(state.plan_sweep(7, [0x42; 32]).unwrap().is_none());

    let restored = DepositWorkerState::decode(&state.encode().unwrap(), &deriver).unwrap();
    assert!(restored.scan_state().output(output.id()).is_some());
    assert!(restored.plan_sweep(7, [0x42; 32]).unwrap().is_none());
}

#[tokio::test]
async fn exact_portable_observation_is_not_emitted_twice_but_remains_sweepable() {
    let output = scanned_output(10, 31, 100);
    let mut blocks = vec![block(10, 10, 9)];
    for height in 11_u64..=20 {
        let mut next =
            block(height, u8::try_from(height).unwrap(), u8::try_from(height - 1).unwrap());
        if height == 11 {
            next.outputs.push(output.clone());
        }
        blocks.push(next);
    }
    let source = MockChain::new(blocks);
    let output_index = ClassifyingOutputIndex::new([(
        output.id(),
        PortableOutputBindingStatus::ExactPortableUnclaimed,
    )]);
    let config = DepositWorkerConfig {
        confirmation_depth: 1,
        minimum_sweep_atomic_units: 1,
        ..Default::default()
    };
    let (deriver, mut state) = worker(config);

    let tick = state.tick(&source, &deriver, &output_index).await.unwrap();
    assert!(!tick.staged_events);
    let effect = tick.persistence.unwrap();
    assert!(state.events_after_persist(effect, effect.revision()).unwrap().is_none());
    assert_eq!(state.plan_sweep(7, [0x43; 32]).unwrap().unwrap().inputs, vec![output.id()]);
}

#[tokio::test]
async fn portable_claim_owner_cannot_replace_a_quarantined_local_signing_family() {
    let output = scanned_output(12, 33, 102);
    let mut blocks = vec![block(10, 10, 9)];
    for height in 11_u64..=20 {
        let mut next =
            block(height, u8::try_from(height).unwrap(), u8::try_from(height - 1).unwrap());
        if height == 11 {
            next.outputs.push(output.clone());
        }
        blocks.push(next);
    }
    let source = MockChain::new(blocks);
    let config = DepositWorkerConfig {
        confirmation_depth: 1,
        minimum_sweep_atomic_units: 1,
        ..Default::default()
    };
    let (deriver, mut state) = worker(config);
    let detection = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    let effect = detection.persistence.unwrap();
    let events = state.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    state.acknowledge_events(events.id).unwrap();

    let destination = root_consolidation_destination_binding(&deriver, config);
    let plan = state.plan_sweep(7, destination).unwrap().unwrap();
    let prepared = state
        .prepare_sweep_from_components(
            &deriver,
            &plan,
            [0x45; 32],
            vec![with_decoys(&output.wallet_output().unwrap())],
            FeeRate::new(1, 1).unwrap(),
        )
        .unwrap();
    let committee = single_party_committee();
    let signers = CanonicalSignerSet::new(&committee, PartyId(1), [PartyId(1)]).unwrap();
    let group_key = threshold_group_key(&single_party_keys());
    let session = derive_sweep_signing_session(deriver.wallet_id(), plan.id, 1).unwrap();
    state.reserve_prepared_sweep(&prepared, &committee, &signers, group_key, session).unwrap();
    state.release_sweep_for_signing(plan.id).unwrap();

    let mut parent = 10_u8;
    for height in 11_u64..=20 {
        let hash = 100_u8 + u8::try_from(height - 11).unwrap();
        let mut replacement = block(height, hash, parent);
        if height == 11 {
            replacement.outputs.push(output.clone());
        }
        source.replace(replacement);
        parent = hash;
    }
    let rollback = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    let effect = rollback.persistence.unwrap();
    let events = state.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    assert!(events.rollback.is_some());
    state.acknowledge_events(events.id).unwrap();
    assert!(matches!(
        state.scan_state().sweep(plan.id).unwrap().status,
        SweepStatus::QuarantinedByReorg { .. }
    ));
    assert!(state.scan_state().output(output.id()).is_none());

    let foreign = ClassifyingOutputIndex::new([(
        output.id(),
        PortableOutputBindingStatus::UnseenClaimed(SweepId([0x46; 32])),
    )]);
    let before_foreign = state.clone();
    assert!(matches!(
        state.tick(&source, &deriver, &foreign).await,
        Err(DepositWorkerError::CertifiedSweepConflict)
    ));
    assert_eq!(state, before_foreign);

    let same_owner = ClassifyingOutputIndex::new([(
        output.id(),
        PortableOutputBindingStatus::UnseenClaimed(plan.id),
    )]);
    let tick = state.tick(&source, &deriver, &same_owner).await.unwrap();
    let effect = tick.persistence.unwrap();
    let events = state.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    assert_eq!(events.detections.len(), 1);
    state.acknowledge_events(events.id).unwrap();
    let restored = DepositWorkerState::decode(&state.encode().unwrap(), &deriver).unwrap();
    assert!(restored.plan_sweep(7, destination).unwrap().is_none());
}

#[tokio::test]
async fn portable_claim_for_a_root_wallet_output_fails_without_mutating_state() {
    let root = scanned_root_output(11, 32, 101);
    let mut deposit_block = block(11, 11, 10);
    deposit_block.root_outputs.push(root.clone());
    let source = MockChain::new([block(10, 10, 9), deposit_block]);
    let output_index = ClassifyingOutputIndex::new([(
        root.id(),
        PortableOutputBindingStatus::UnseenClaimed(SweepId([0x44; 32])),
    )]);
    let config = DepositWorkerConfig { confirmation_depth: 1, ..Default::default() };
    let (deriver, mut state) = worker(config);
    let before = state.clone();

    assert!(matches!(
        state.tick(&source, &deriver, &output_index).await,
        Err(DepositWorkerError::CorruptState)
    ));
    assert_eq!(state, before);
}

#[tokio::test]
async fn deferred_cursor_is_not_persisted_until_output_bindings_commit() {
    let mut deposit_block = block(11, 11, 10);
    deposit_block.outputs.push(scanned_output(9, 30, 99));
    let source = MockChain::new([block(10, 10, 9), deposit_block]).defer_next_scan();
    let config = DepositWorkerConfig { confirmation_depth: 1, ..Default::default() };
    let (deriver, mut state) = worker(config);
    let before = state.clone();

    assert!(matches!(
        state.tick(&source, &deriver, &RejectingBindOutputIndex).await,
        Err(DepositWorkerError::ChainSource(ChainSourceError::Invalid(message)))
            if message == "injected local output-index failure"
    ));
    assert_eq!(state, before);
    assert!(!state.has_pending_block_scan());
}

#[tokio::test]
async fn unsupported_hardfork_is_an_explicit_operator_upgrade_halt() {
    let mut unsupported = block(11, 11, 10);
    unsupported.hardfork_version = 17;
    let source = MockChain::new([block(10, 10, 9), unsupported]);
    let config = DepositWorkerConfig { confirmation_depth: 1, ..Default::default() };
    let (deriver, mut state) = worker(config);
    let before = state.clone();

    assert!(matches!(
        state.tick(&source, &deriver, &OUTPUT_INDEX).await,
        Err(DepositWorkerError::UnsupportedHardfork(17))
    ));
    assert_eq!(state, before);
}

#[tokio::test]
async fn bounded_block_scan_cursor_survives_restart_and_resumes_exactly() {
    let mut deposit_block = block(11, 11, 10);
    let output = scanned_output(9, 29, 98);
    deposit_block.outputs.push(output.clone());
    let source = MockChain::new([block(10, 10, 9), deposit_block]).defer_next_scan();
    let config = DepositWorkerConfig { confirmation_depth: 1, ..Default::default() };
    let (deriver, mut state) = worker(config);

    let deferred = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    assert_eq!(deferred.scanner_tip, point(10, 10));
    assert!(!deferred.staged_events);
    assert!(state.has_pending_block_scan());

    let encoded = state.encode().unwrap();
    let mut restored = DepositWorkerState::decode(&encoded, &deriver).unwrap();
    let completed = restored.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    assert_eq!(completed.scanner_tip, point(11, 11));
    assert!(!restored.has_pending_block_scan());
    let effect = completed.persistence.unwrap();
    let events = restored.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    assert_eq!(events.detections.len(), 1);
    assert_eq!(events.detections[0].output, output.id());
}

#[tokio::test]
async fn complete_prefix_commits_before_a_later_deferred_cursor_across_restart() {
    let source = CompletePrefixThenDeferredChain::default();
    let config =
        DepositWorkerConfig { confirmation_depth: 1, max_blocks_per_tick: 2, ..Default::default() };
    let (deriver, mut state) = worker(config);
    let output_index = RecordingOutputIndex::default();

    let prefix = state.tick(&source, &deriver, &output_index).await.unwrap();
    assert_eq!(prefix.scanner_tip, point(11, 11));
    assert!(prefix.staged_events);
    assert!(!state.has_pending_block_scan());
    assert_eq!(source.scans(), vec![(11, false), (12, false)]);
    assert_eq!(*output_index.binding_chunk_lengths.lock().unwrap(), vec![1]);
    let prefix_effect = prefix.persistence.unwrap();
    assert_eq!(prefix_effect.revision(), state.revision());
    state = DepositWorkerState::decode(&state.encode().unwrap(), &deriver).unwrap();
    let events =
        state.events_after_persist(prefix_effect, prefix_effect.revision()).unwrap().unwrap();
    assert_eq!(events.detections.len(), 1);
    assert_eq!(events.detections[0].output, scanned_output(9, 30, 99).id());
    assert_eq!(state.replay_pending_events().unwrap(), Some(events.clone()));
    let acknowledgement = state.acknowledge_events(events.id).unwrap();
    assert_eq!(acknowledgement.revision(), state.revision());
    state = DepositWorkerState::decode(&state.encode().unwrap(), &deriver).unwrap();

    let deferred = state.tick(&source, &deriver, &output_index).await.unwrap();
    assert_eq!(deferred.scanner_tip, point(11, 11));
    assert!(!deferred.staged_events);
    assert!(state.has_pending_block_scan());
    assert_eq!(source.scans(), vec![(11, false), (12, false), (12, false)]);
    assert_eq!(*output_index.binding_chunk_lengths.lock().unwrap(), vec![1, 1]);
    let deferred_effect = deferred.persistence.unwrap();
    assert_eq!(deferred_effect.revision(), state.revision());
    state = DepositWorkerState::decode(&state.encode().unwrap(), &deriver).unwrap();

    let completed = state.tick(&source, &deriver, &output_index).await.unwrap();
    assert_eq!(completed.scanner_tip, point(12, 12));
    assert!(completed.staged_events);
    assert!(!state.has_pending_block_scan());
    assert_eq!(source.scans(), vec![(11, false), (12, false), (12, false), (12, true)]);
    assert_eq!(*output_index.binding_chunk_lengths.lock().unwrap(), vec![1, 1, 1]);
    let completed_effect = completed.persistence.unwrap();
    assert_eq!(completed_effect.revision(), state.revision());
    let completed_events =
        state.events_after_persist(completed_effect, completed_effect.revision()).unwrap().unwrap();
    let mut detected =
        completed_events.detections.iter().map(|detection| detection.output).collect::<Vec<_>>();
    detected.sort_unstable();
    let mut expected = vec![scanned_output(10, 31, 100).id(), scanned_output(11, 32, 101).id()];
    expected.sort_unstable();
    assert_eq!(detected, expected);
    let restored = DepositWorkerState::decode(&state.encode().unwrap(), &deriver).unwrap();
    assert_eq!(restored, state);
}

#[tokio::test]
async fn recognized_output_pressure_yields_and_completes_the_same_block() {
    let mut first = block(11, 11, 10);
    for output_index in 0_u64..256 {
        first.outputs.push(scanned_output_at(
            1_000 + output_index,
            29,
            output_index,
            10_000 + output_index,
        ));
    }
    let mut second = block(11, 11, 10);
    second.outputs.push(scanned_output_at(1_256, 29, 256, 10_256));
    let source = ChunkedMockChain::new(block(10, 10, 9), vec![first, second]);
    let output_index = RecordingOutputIndex::default();
    let config = DepositWorkerConfig {
        confirmation_depth: 1,
        max_outputs_per_block: 1024,
        ..Default::default()
    };
    let (deriver, mut state) = worker(config);

    let deferred = state.tick(&source, &deriver, &output_index).await.unwrap();
    assert_eq!(deferred.scanner_tip, point(10, 10));
    assert!(state.has_pending_block_scan());
    assert_eq!(*output_index.binding_chunk_lengths.lock().unwrap(), vec![256]);

    let completed = state.tick(&source, &deriver, &output_index).await.unwrap();
    assert_eq!(completed.scanner_tip, point(11, 11));
    assert!(!state.has_pending_block_scan());
    assert_eq!(*output_index.binding_chunk_lengths.lock().unwrap(), vec![256, 1]);
    let effect = completed.persistence.unwrap();
    let events = state.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    assert_eq!(events.detections.len(), 257);
}

#[tokio::test]
async fn confirmed_detection_is_durable_before_release_and_replays_after_restart() {
    let mut deposit_block = block(11, 11, 10);
    let output = scanned_output(9, 31, 100);
    deposit_block.outputs.push(output.clone());
    let source =
        MockChain::new([block(10, 10, 9), deposit_block, block(12, 12, 11), block(13, 13, 12)]);
    let config = DepositWorkerConfig { confirmation_depth: 3, ..Default::default() };
    let (deriver, mut state) = worker(config);

    let tick = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    assert_eq!(tick.scanner_tip, point(13, 13));
    assert!(tick.staged_events);
    assert!(matches!(
        state.tick(&source, &deriver, &OUTPUT_INDEX).await,
        Err(DepositWorkerError::PendingEvents(_))
    ));

    let effect = tick.persistence.unwrap();
    let batch = state.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    assert_eq!(batch.detections.len(), 1);
    assert_eq!(batch.detections[0].output, output.id());
    assert_eq!(batch.detections[0].amount_atomic_units, 10_000_000);
    assert_eq!(batch.detections[0].observed_block, point(11, 11));
    assert_eq!(batch.detections[0].confirmation_horizon, point(13, 13));

    let encoded = state.encode().unwrap();
    let mut restored = DepositWorkerState::decode(&encoded, &deriver).unwrap();
    assert_eq!(restored.replay_pending_events().unwrap(), Some(batch.clone()));
    let clear = restored.acknowledge_events(batch.id).unwrap();
    assert_eq!(clear.revision(), effect.revision() + 1);
    assert!(restored.replay_pending_events().unwrap().is_none());
}

#[tokio::test]
async fn immature_detection_survives_restart_and_emits_once_at_its_exact_horizon() {
    let mut deposit_block = block(11, 11, 10);
    let output = scanned_output(9, 32, 106);
    deposit_block.outputs.push(output.clone());
    let source = MockChain::new([block(10, 10, 9), deposit_block, block(12, 12, 11)]);
    let config = DepositWorkerConfig { confirmation_depth: 3, ..Default::default() };
    let (deriver, mut state) = worker(config);

    let immature = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    assert_eq!(immature.scanner_tip, point(12, 12));
    assert!(!immature.staged_events);
    assert!(immature.persistence.is_some());
    assert!(state.replay_pending_events().unwrap().is_none());

    let mut restored = DepositWorkerState::decode(&state.encode().unwrap(), &deriver).unwrap();
    source.push(block(13, 13, 12));
    let mature = restored.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    let effect = mature.persistence.unwrap();
    let events = restored.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    assert_eq!(events.detections.len(), 1);
    assert_eq!(events.detections[0].output, output.id());
    assert_eq!(events.detections[0].confirmation_horizon, point(13, 13));
    restored.acknowledge_events(events.id).unwrap();

    let idle = restored.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    assert!(idle.persistence.is_none());
    assert!(!idle.staged_events);
}

#[tokio::test]
async fn horizon_only_reorg_requeues_and_reissues_the_surviving_output() {
    let mut deposit_block = block(11, 11, 10);
    let output = scanned_output(9, 33, 107);
    deposit_block.outputs.push(output.clone());
    let source =
        MockChain::new([block(10, 10, 9), deposit_block, block(12, 12, 11), block(13, 13, 12)]);
    let config = DepositWorkerConfig { confirmation_depth: 3, ..Default::default() };
    let (deriver, mut state) = worker(config);

    let initial = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    let effect = initial.persistence.unwrap();
    let events = state.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    assert_eq!(events.detections[0].confirmation_horizon, point(13, 13));
    state.acknowledge_events(events.id).unwrap();

    source.replace(block(13, 23, 12));
    let rollback_tick = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    assert_eq!(rollback_tick.scanner_tip, point(12, 12));
    let effect = rollback_tick.persistence.unwrap();
    let rollback_batch = state.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    let rollback = rollback_batch.rollback.as_ref().unwrap();
    assert!(rollback.removed_outputs.is_empty());
    assert!(rollback.orphaned_deposits.is_empty());
    assert_eq!(
        rollback.invalidated_observation_horizons,
        vec![threshold_monero::deposit_worker::InvalidatedDepositObservationHorizon {
            output: output.id(),
            horizon: point(13, 13),
        }]
    );
    state.acknowledge_events(rollback_batch.id).unwrap();

    let replacement = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    let effect = replacement.persistence.unwrap();
    let replacement_events =
        state.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    assert_eq!(replacement_events.detections.len(), 1);
    assert_eq!(replacement_events.detections[0].output, output.id());
    assert_eq!(replacement_events.detections[0].observed_block, point(11, 11));
    assert_eq!(replacement_events.detections[0].confirmation_horizon, point(13, 23));
}

#[tokio::test]
async fn late_joiner_scans_registered_deposit_from_before_joining() {
    let output = scanned_output(19, 35, 105);
    let mut blocks = Vec::new();
    for height in 0_u64..=12 {
        let hash = u8::try_from(height + 1).unwrap();
        let parent = u8::try_from(height).unwrap();
        let mut next = block(height, hash, parent);
        if height == 3 {
            next.outputs.push(output.clone());
        }
        blocks.push(next);
    }
    // The daemon is already at height 12 before this party creates any local worker state.
    let source = MockChain::new(blocks);
    let deriver = deriver();
    let config = DepositWorkerConfig { confirmation_depth: 3, ..Default::default() };
    let mut state = DepositWorkerState::new(&deriver, point(0, 1), config).unwrap();
    state.initialize_portable_index_head([1; 32]).unwrap();

    let tick = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    // The full parent-linked tip is retained, while the historical deposit at height 3 is released
    // only because its deterministic depth-three horizon is already authenticated.
    assert_eq!(tick.scanner_tip, point(12, 13));
    let effect = tick.persistence.unwrap();
    let events = state.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    assert_eq!(events.detections.len(), 1);
    assert_eq!(events.detections[0].output, output.id());
    assert_eq!(events.detections[0].observed_block, point(3, 4));
}

#[tokio::test]
async fn reorg_is_persisted_and_released_before_replacement_branch_is_scanned() {
    let mut old_tip = block(12, 12, 11);
    let orphaned = scanned_output(9, 41, 101);
    old_tip.outputs.push(orphaned.clone());
    let source = MockChain::new([block(10, 10, 9), block(11, 11, 10), old_tip]);
    let config = DepositWorkerConfig { confirmation_depth: 1, ..Default::default() };
    let (deriver, mut state) = worker(config);

    let initial = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    let initial_effect = initial.persistence.unwrap();
    let initial_events =
        state.events_after_persist(initial_effect, initial_effect.revision()).unwrap().unwrap();
    assert_eq!(initial_events.detections[0].output, orphaned.id());
    state.acknowledge_events(initial_events.id).unwrap();

    let mut replacement = block(12, 22, 11);
    let reincluded = scanned_output(9, 41, 999);
    assert_eq!(reincluded.id(), orphaned.id());
    replacement.outputs.push(reincluded.clone());
    source.replace(replacement);
    let rollback_tick = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    assert_eq!(rollback_tick.scanner_tip, point(11, 11));
    let effect = rollback_tick.persistence.unwrap();
    let batch = state.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    let rollback = batch.rollback.as_ref().unwrap();
    assert_eq!(rollback.ancestor, point(11, 11));
    assert_eq!(rollback.removed_outputs, vec![orphaned.id()]);
    assert_eq!(rollback.orphaned_deposits.len(), 1);
    assert_eq!(rollback.orphaned_deposits[0].output, orphaned.id());
    assert_eq!(rollback.orphaned_deposits[0].index_on_blockchain, 101);
    assert_eq!(rollback.orphaned_deposits[0].subaddress, index(1));
    assert_eq!(rollback.orphaned_deposits[0].amount_atomic_units, 10_000_000);
    assert_eq!(rollback.orphaned_deposits[0].observed_block, point(12, 12));
    state.acknowledge_events(batch.id).unwrap();

    let replacement_tick = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    assert_eq!(replacement_tick.scanner_tip, point(12, 22));
    assert!(replacement_tick.staged_events);
    let replacement_effect = replacement_tick.persistence.unwrap();
    let replacement_events = state
        .events_after_persist(replacement_effect, replacement_effect.revision())
        .unwrap()
        .unwrap();
    assert_eq!(replacement_events.detections.len(), 1);
    assert_eq!(replacement_events.detections[0].output, orphaned.id());
    assert_eq!(replacement_events.detections[0].index_on_blockchain, 999);
    assert_eq!(replacement_events.detections[0].observed_block, point(12, 22));
}

#[tokio::test]
async fn timeout_and_output_bound_leave_state_unchanged() {
    let source =
        MockChain::new([block(10, 10, 9), block(11, 11, 10)]).delayed(Duration::from_millis(50));
    let config = DepositWorkerConfig {
        confirmation_depth: 1,
        request_timeout_millis: 5,
        ..Default::default()
    };
    let (deriver, mut state) = worker(config);
    let before = state.clone();
    assert!(matches!(
        state.tick(&source, &deriver, &OUTPUT_INDEX).await,
        Err(DepositWorkerError::RequestTimeout { .. })
    ));
    assert_eq!(state, before);

    let mut excessive = block(11, 11, 10);
    excessive.outputs.push(scanned_output(9, 51, 102));
    excessive.outputs.push(scanned_output(10, 52, 103));
    let source = MockChain::new([block(10, 10, 9), excessive]);
    let config = DepositWorkerConfig {
        confirmation_depth: 1,
        max_outputs_per_block: 1,
        ..Default::default()
    };
    let (deriver, mut state) = worker(config);
    let before = state.clone();
    assert!(matches!(
        state.tick(&source, &deriver, &OUTPUT_INDEX).await,
        Err(DepositWorkerError::TooManyWalletOutputs { .. })
    ));
    assert_eq!(state, before);
}

#[tokio::test]
async fn mature_sweep_plan_is_deterministic_and_exact() {
    let mut deposit_block = block(11, 11, 10);
    let output = scanned_output(9, 61, 104);
    deposit_block.outputs.push(output.clone());
    let mut blocks = vec![block(10, 10, 9), deposit_block];
    for height in 12_u64..=20 {
        blocks.push(block(
            height,
            u8::try_from(height).unwrap(),
            u8::try_from(height - 1).unwrap(),
        ));
    }
    let source = MockChain::new(blocks);
    let config = DepositWorkerConfig {
        confirmation_depth: 1,
        minimum_sweep_atomic_units: 1,
        ..Default::default()
    };
    let (deriver, mut state) = worker(config);
    let tick = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    let effect = tick.persistence.unwrap();
    let events = state.events_after_persist(effect, effect.revision()).unwrap().unwrap();
    state.acknowledge_events(events.id).unwrap();

    let destination = [71_u8; 32];
    let first = state.plan_sweep(7, destination).unwrap().unwrap();
    let replay = state.plan_sweep(7, destination).unwrap().unwrap();
    assert_eq!(first, replay);
    assert_eq!(first.inputs, vec![output.id()]);
    assert_eq!(first.total_input_atomic_units, 10_000_000);

    assert_eq!(state.plan_sweep(8, destination).unwrap().unwrap().epoch, 8);
}

#[tokio::test]
async fn primary_self_sweep_output_advances_cursor_without_deposit_or_resweep() {
    let root = scanned_root_output(29, 81, 500);
    let mut self_sweep = block(11, 11, 10);
    self_sweep.root_outputs.push(root.clone());
    let source = MockChain::new([block(10, 10, 9), self_sweep]);
    let config = DepositWorkerConfig {
        confirmation_depth: 1,
        minimum_sweep_atomic_units: 1,
        ..Default::default()
    };
    let (deriver, mut state) = worker(config);

    let tick = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    assert_eq!(tick.scanner_tip, point(11, 11));
    assert!(!tick.staged_events);
    let effect = tick.persistence.unwrap();
    assert!(state.events_after_persist(effect, effect.revision()).unwrap().is_none());
    assert!(state.replay_pending_events().unwrap().is_none());
    assert!(state.scan_state().root_output(root.id()).is_some());
    assert_eq!(state.scan_state().root_output_chain_point(root.id()), Some(point(11, 11)));
    assert!(state.plan_sweep(7, [91; 32]).unwrap().is_none());
}

#[tokio::test]
async fn high_birth_anchor_keeps_bounded_window_and_deep_reorg_fails_closed_after_restart() {
    let birth_height = 3_000_000_u64;
    let end_height = birth_height + 1_000;
    let mut blocks = Vec::new();
    let mut parent_hash = 1_u8;
    blocks.push(block(birth_height, parent_hash, 0));
    for height in (birth_height + 1)..=end_height {
        let hash = u8::try_from(((height - birth_height) % 250) + 2).unwrap();
        blocks.push(block(height, hash, parent_hash));
        parent_hash = hash;
    }
    let source = MockChain::new(blocks);
    let deriver = deriver();
    let birth = point(birth_height, 1);
    let config = DepositWorkerConfig {
        confirmation_depth: 1,
        max_blocks_per_tick: 1024,
        max_reorg_depth: 60,
        ..Default::default()
    };
    let mut state = DepositWorkerState::new(&deriver, birth, config).unwrap();
    state.initialize_portable_index_head([1; 32]).unwrap();

    let tick = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    assert_eq!(tick.scanner_tip.height, end_height);
    assert_eq!(state.birth_anchor(), birth);
    assert_eq!(state.reorg_checkpoint().height, end_height - 60);
    assert_eq!(state.scan_state().retained_block_count(), 60);
    let encoded = state.encode().unwrap();
    assert!(encoded.len() < 32 * 1024);
    let mut restored = DepositWorkerState::decode(&encoded, &deriver).unwrap();
    assert_eq!(restored.birth_anchor(), birth);
    assert_eq!(restored.scan_state().retained_block_count(), 60);

    // Replace the entire retained suffix including the moving trusted checkpoint. The worker has
    // no safe common ancestor left and must fail closed without mutating durable state.
    let checkpoint = restored.reorg_checkpoint().height;
    let mut replacement_parent = 201_u8;
    for height in checkpoint..=end_height {
        let replacement_hash = u8::try_from(202 + ((height - checkpoint) % 40)).unwrap();
        source.replace(block(height, replacement_hash, replacement_parent));
        replacement_parent = replacement_hash;
    }
    let before = restored.clone();
    assert!(matches!(
        restored.tick(&source, &deriver, &OUTPUT_INDEX).await,
        Err(DepositWorkerError::AnchorMismatch(point))
            if point == before.reorg_checkpoint()
    ));
    assert_eq!(restored, before);
}

#[tokio::test]
async fn portable_retired_attempt_winner_survives_restart_without_releasing_another_nonce() {
    let mut deposit_block = block(11, 11, 10);
    let output = scanned_output(49, 149, 1_800);
    deposit_block.outputs.push(output.clone());
    let mut blocks = vec![block(10, 10, 9), deposit_block];
    for height in 12_u64..=20 {
        blocks.push(block(
            height,
            u8::try_from(height).unwrap(),
            u8::try_from(height - 1).unwrap(),
        ));
    }
    let source = MockChain::new(blocks);
    let config = DepositWorkerConfig {
        confirmation_depth: 1,
        minimum_sweep_atomic_units: 1,
        ..Default::default()
    };
    let (deriver, mut state) = worker(config);
    let tick = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    let detection_effect = tick.persistence.unwrap();
    let detections =
        state.events_after_persist(detection_effect, detection_effect.revision()).unwrap().unwrap();
    state.acknowledge_events(detections.id).unwrap();

    let destination = root_consolidation_destination_binding(&deriver, config);
    let plan = state.plan_sweep(7, destination).unwrap().unwrap();
    let prepared = state
        .prepare_sweep_from_components(
            &deriver,
            &plan,
            [150; 32],
            vec![with_decoys(&output.wallet_output().unwrap())],
            FeeRate::new(1, 1).unwrap(),
        )
        .unwrap();
    let committee = single_party_committee();
    let signers = CanonicalSignerSet::new(&committee, PartyId(1), [PartyId(1)]).unwrap();
    let group_key = threshold_group_key(&single_party_keys());
    let old_session = derive_sweep_signing_session(deriver.wallet_id(), plan.id, 1).unwrap();
    state.reserve_prepared_sweep(&prepared, &committee, &signers, group_key, old_session).unwrap();
    let release = state.release_sweep_for_signing(plan.id).unwrap();
    let release_revision = release.persistence().revision();
    let old_authorization =
        state.signing_authorization_after_persist(release, release_revision).unwrap();
    assert_eq!(old_authorization.attempt(), 1);

    // This result is created by view 0 before its volatile machine is lost. It arrives only after
    // restart has permanently retired view 0 and released view 1.
    let mut old_rng = ChaCha20Rng::from_seed([152; 32]);
    let (old_awaiting, _) = FrostlassSigner::start_in_session(
        prepared.transaction().clone(),
        single_party_keys(),
        &committee,
        PartyId(1),
        [PartyId(1)],
        group_key,
        old_session,
        &mut old_rng,
    )
    .unwrap();
    assert_eq!(old_authorization.signing_context(), *old_awaiting.context().as_bytes());
    let (old_finalizer, _) =
        old_awaiting.bind_transaction_bound([]).unwrap().release_bound_signature_share().unwrap();
    let old_transaction = old_finalizer.complete_bound([]).unwrap();
    let old_transaction_id = old_transaction.hash();
    let old_signed =
        SignedSweepTransaction::from_transaction(&old_transaction, Some(old_transaction_id))
            .unwrap();

    // A lagger may authenticate a much later attempt after intermediate worker tombstones have
    // already compacted. Reconstructing that exact attempt advances only the durable high-water;
    // it cannot yield a signing authorization or accept an old would-be successor session.
    let mut leader = state.clone();
    let mut terminal_authorization = None;
    for attempt in 2..=70 {
        let session = derive_sweep_signing_session(deriver.wallet_id(), plan.id, attempt).unwrap();
        let receipt = leader
            .recover_released_sweep_signing(
                &deriver, plan.id, &committee, &signers, group_key, session,
            )
            .unwrap();
        let revision = receipt.persistence().revision();
        terminal_authorization =
            Some(leader.signing_authorization_after_persist(receipt, revision).unwrap());
    }
    let leader_status = leader.sweep_signing_attempt_status(plan.id).unwrap();
    assert_eq!(leader_status.attempt_high_water, 70);
    assert_eq!(leader_status.retired.len(), 64);
    assert_eq!(leader_status.retired.first().unwrap().attempt, 6);
    let terminal_authorization = terminal_authorization.unwrap();
    let terminal_attempt = AttemptBinding::new(
        terminal_authorization.attempt(),
        committee.epoch,
        [157; 32],
        committee.digest(),
        [158; 32],
        group_key,
        committee.threshold,
        vec![PartyId(1)],
        terminal_authorization.intent_digest(),
        terminal_authorization.session(),
        terminal_authorization.signing_context(),
    )
    .unwrap();
    let mut lagger = state.clone();
    let catch_up = lagger
        .catch_up_certified_sweep_signing_attempt(plan.id, &terminal_attempt, &committee)
        .unwrap()
        .unwrap();
    assert_eq!(lagger.sweep_signing_attempt_high_water(plan.id).unwrap(), 70);
    assert!(catch_up.revision() > state.revision());
    assert!(matches!(
        lagger.recover_released_sweep_signing(
            &deriver,
            plan.id,
            &committee,
            &signers,
            group_key,
            derive_sweep_signing_session(deriver.wallet_id(), plan.id, 2).unwrap(),
        ),
        Err(DepositWorkerError::Wallet(DepositWalletError::ReusedSweepSigningSession))
    ));

    let fresh_session = derive_sweep_signing_session(deriver.wallet_id(), plan.id, 2).unwrap();
    state
        .recover_released_sweep_signing(
            &deriver,
            plan.id,
            &committee,
            &signers,
            group_key,
            fresh_session,
        )
        .unwrap();
    state = DepositWorkerState::decode(&state.encode().unwrap(), &deriver).unwrap();
    let status = state.sweep_signing_attempt_status(plan.id).unwrap();
    assert_eq!(status.current_attempt, 2);
    assert_eq!(status.attempt_high_water, 2);
    assert_eq!(status.current_session, fresh_session);
    assert_eq!(status.retired.len(), 1);
    let retired = status.retired[0];
    assert_eq!(retired.session, old_session);
    assert_eq!(retired.intent_digest, old_authorization.intent_digest());

    let key_images = vec![expected_key_image(&output.wallet_output().unwrap())];
    let preview = state.preview_sweep_family_key_images(plan.id, key_images).unwrap();
    state.pin_sweep_family_key_image_binding(preview).unwrap();
    state.validate_sweep_family_candidate(plan.id, &old_signed).unwrap();

    let mut invalid_transaction = old_transaction.clone();
    let monero_oxide::transaction::Transaction::V2 { prefix, .. } = &mut invalid_transaction else {
        unreachable!()
    };
    let monero_oxide::transaction::Input::ToKey { key_image, .. } = &mut prefix.inputs[0] else {
        unreachable!()
    };
    *key_image = monero_wallet::ed25519::CompressedPoint::G;
    let invalid_signed = SignedSweepTransaction::from_transaction(
        &invalid_transaction,
        Some(invalid_transaction.hash()),
    )
    .unwrap();
    let before_invalid_candidate = state.encode().unwrap();
    assert!(matches!(
        state.adopt_portable_sweep_family_candidate(plan.id, retired, &invalid_signed),
        Err(DepositWorkerError::InvalidSweepFamilyCandidate)
            | Err(DepositWorkerError::Wallet(DepositWalletError::SignedSweepIntentMismatch))
    ));
    assert_eq!(state.encode().unwrap(), before_invalid_candidate);

    let before_rejections = state.encode().unwrap();
    let unknown = SweepSigningSessionTombstone {
        attempt: 99,
        session: SessionId([154; 32]),
        intent_digest: [155; 32],
    };
    assert!(matches!(
        state.adopt_portable_sweep_family_candidate(plan.id, unknown, &old_signed),
        Err(DepositWorkerError::Wallet(DepositWalletError::UnknownSweepSigningAttempt))
    ));
    let mismatched = SweepSigningSessionTombstone {
        attempt: retired.attempt,
        session: retired.session,
        intent_digest: status.current_intent_digest,
    };
    assert!(matches!(
        state.adopt_portable_sweep_family_candidate(plan.id, mismatched, &old_signed),
        Err(DepositWorkerError::Wallet(DepositWalletError::UnknownSweepSigningAttempt))
    ));
    assert_eq!(state.encode().unwrap(), before_rejections);

    let effect =
        state.adopt_portable_sweep_family_candidate(plan.id, retired, &old_signed).unwrap();
    let persisted = state.signed_sweep_after_persist(effect, effect.revision(), plan.id).unwrap();
    assert_eq!(persisted, old_signed);
    assert!(matches!(
        state.scan_state().sweep(plan.id).unwrap().status,
        SweepStatus::Signed { transaction } if transaction == old_transaction_id
    ));
    assert!(matches!(
        state.release_sweep_for_signing(plan.id),
        Err(DepositWorkerError::Wallet(DepositWalletError::InvalidSweepTransition))
    ));
    assert!(matches!(
        state.recover_released_sweep_signing(
            &deriver,
            plan.id,
            &committee,
            &signers,
            group_key,
            SessionId([156; 32]),
        ),
        Err(DepositWorkerError::Wallet(DepositWalletError::InvalidSweepTransition))
    ));

    let mut restored = DepositWorkerState::decode(&state.encode().unwrap(), &deriver).unwrap();
    let restored_status = restored.sweep_signing_attempt_status(plan.id).unwrap();
    assert_eq!(restored_status.attempt_high_water, 2);
    assert_eq!(restored_status.current_session, fresh_session);
    assert_eq!(restored_status.retired, vec![retired]);
    assert_eq!(restored.replay_signed_sweeps().unwrap(), vec![(plan.id, old_signed.clone())]);
    restored.mark_sweep_broadcast(plan.id, old_transaction_id).unwrap();
    let restored = DepositWorkerState::decode(&restored.encode().unwrap(), &deriver).unwrap();
    assert_eq!(restored.replay_signed_sweeps().unwrap(), vec![(plan.id, old_signed)]);
}

#[tokio::test]
async fn signed_sweep_is_persisted_replayed_and_confirmed_only_by_root_output_evidence() {
    let mut deposit_block = block(11, 11, 10);
    let output = scanned_output(9, 91, 800);
    let second_output = scanned_output(10, 92, 801);
    deposit_block.outputs.push(output.clone());
    deposit_block.outputs.push(second_output.clone());
    let mut blocks = vec![block(10, 10, 9), deposit_block];
    for height in 12_u64..=20 {
        blocks.push(block(
            height,
            u8::try_from(height).unwrap(),
            u8::try_from(height - 1).unwrap(),
        ));
    }
    let source = MockChain::new(blocks);
    let config = DepositWorkerConfig {
        confirmation_depth: 1,
        minimum_sweep_atomic_units: 1,
        ..Default::default()
    };
    let (deriver, mut state) = worker(config);
    let tick = state.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    let detection_effect = tick.persistence.unwrap();
    let detections =
        state.events_after_persist(detection_effect, detection_effect.revision()).unwrap().unwrap();
    state.acknowledge_events(detections.id).unwrap();

    let destination = root_consolidation_destination_binding(&deriver, config);
    let plan = state.plan_sweep(7, destination).unwrap().unwrap();
    let decoy_input = with_decoys(&output.wallet_output().unwrap());
    let second_decoy_input = with_decoys(&second_output.wallet_output().unwrap());
    let prepared = state
        .prepare_sweep_from_components(
            &deriver,
            &plan,
            [92; 32],
            vec![decoy_input, second_decoy_input],
            FeeRate::new(1, 1).unwrap(),
        )
        .unwrap();
    let wire = prepared.prepared_intent().encode().unwrap();
    let decoded_intent = PreparedSweepIntent::decode(&wire).unwrap();
    let follower_prepared = state.verify_prepared_sweep_intent(&deriver, &decoded_intent).unwrap();
    assert_eq!(follower_prepared.transaction_commitment(), prepared.transaction_commitment());

    let committee = single_party_committee();
    let signers = CanonicalSignerSet::new(&committee, PartyId(1), [PartyId(1)]).unwrap();
    let keys = single_party_keys();
    let group_key = threshold_group_key(&keys);
    let session = derive_sweep_signing_session(deriver.wallet_id(), plan.id, 1).unwrap();
    let reservation =
        state.reserve_prepared_sweep(&prepared, &committee, &signers, group_key, session).unwrap();
    assert_eq!(reservation.sweep, plan.id);
    assert_eq!(state.next_sweep_sequence(), plan.sequence + 1);
    // Reservation alone is intentionally not a nonce authorization.
    let reserved_snapshot = state.encode().unwrap();
    let mut restored = DepositWorkerState::decode(&reserved_snapshot, &deriver).unwrap();
    let release = restored.release_sweep_for_signing(plan.id).unwrap();
    let release_revision = release.persistence().revision();
    let old_authorization =
        restored.signing_authorization_after_persist(release, release_revision).unwrap();
    assert_eq!(old_authorization.attempt(), 1);
    assert_eq!(old_authorization.session(), session);
    assert_eq!(old_authorization.signers(), &[1]);
    assert_eq!(old_authorization.group_key(), group_key);
    let already_released = restored.clone();
    assert!(matches!(
        restored.release_sweep_for_signing(plan.id),
        Err(DepositWorkerError::Wallet(DepositWalletError::InvalidSweepTransition))
    ));
    assert_eq!(restored, already_released);
    assert_eq!(
        restored.prepared_sweep_intent_for_restart(&deriver, plan.id).unwrap(),
        prepared.prepared_intent().clone()
    );

    // Simulate a crash after nonce authorization but before the in-memory machine survives. The
    // exact same transaction is rebound to one fresh session while the old session is tombstoned.
    let released_snapshot = restored.encode().unwrap();
    let mut restored = DepositWorkerState::decode(&released_snapshot, &deriver).unwrap();
    let fresh_session = derive_sweep_signing_session(deriver.wallet_id(), plan.id, 2).unwrap();
    let recovery = restored
        .recover_released_sweep_signing(
            &deriver,
            plan.id,
            &committee,
            &signers,
            group_key,
            fresh_session,
        )
        .unwrap();
    let status = restored.sweep_signing_attempt_status(plan.id).unwrap();
    assert_eq!(status.current_attempt, 2);
    assert_eq!(status.attempt_high_water, 2);
    assert_eq!(status.current_session, fresh_session);
    assert_eq!(status.retired.len(), 1);
    assert_eq!(status.retired[0].session, session);
    assert_eq!(status.retired[0].intent_digest, old_authorization.intent_digest());
    let recovery_revision = recovery.persistence().revision();
    let authorization =
        restored.signing_authorization_after_persist(recovery, recovery_revision).unwrap();
    assert_eq!(authorization.attempt(), 2);
    assert_eq!(authorization.session(), fresh_session);
    assert_ne!(authorization.intent_digest(), old_authorization.intent_digest());
    assert_eq!(
        restored.reconstruct_reserved_sweep(&deriver, plan.id).unwrap().transaction().serialize(),
        prepared.transaction().serialize()
    );

    let mut rng = ChaCha20Rng::from_seed([94; 32]);
    let (awaiting, _) = FrostlassSigner::start_in_session(
        prepared.transaction().clone(),
        keys,
        &committee,
        PartyId(1),
        [PartyId(1)],
        group_key,
        fresh_session,
        &mut rng,
    )
    .unwrap();
    assert_eq!(authorization.signing_context(), *awaiting.context().as_bytes());
    let (finalizer, _) =
        awaiting.bind_transaction_bound([]).unwrap().release_bound_signature_share().unwrap();
    let transaction = finalizer.complete_bound([]).unwrap();
    let transaction_id = transaction.hash();
    let key_images_in_prepared_order = vec![
        expected_key_image(&output.wallet_output().unwrap()),
        expected_key_image(&second_output.wallet_output().unwrap()),
    ];
    let before_preview = restored.encode().unwrap();
    let preview = restored
        .preview_sweep_family_key_images(plan.id, key_images_in_prepared_order.clone())
        .unwrap();
    assert_eq!(
        restored
            .preview_sweep_family_key_images(plan.id, key_images_in_prepared_order.clone())
            .unwrap(),
        preview,
    );
    // Alternate inputs across the bounded deterministic cache, including FIFO eviction.
    for scalar in 12_345..12_410 {
        let mut other_images = key_images_in_prepared_order.clone();
        other_images[0] = root_key(scalar);
        let alternate =
            restored.preview_sweep_family_key_images(plan.id, other_images.clone()).unwrap();
        assert_ne!(alternate.unsigned_transaction_digest(), preview.unsigned_transaction_digest());
        assert_eq!(
            restored
                .preview_sweep_family_key_images(plan.id, key_images_in_prepared_order.clone())
                .unwrap(),
            preview,
        );
        assert_eq!(
            restored.preview_sweep_family_key_images(plan.id, other_images).unwrap(),
            alternate
        );
    }
    for _ in 0..2 {
        assert!(
            restored
                .preview_sweep_family_key_images(plan.id, vec![key_images_in_prepared_order[0]])
                .is_err()
        );
        assert!(restored.preview_sweep_family_key_images(plan.id, vec![[0xff; 32]; 2]).is_err());
    }
    assert_eq!(
        restored
            .preview_sweep_family_key_images(plan.id, key_images_in_prepared_order.clone())
            .unwrap(),
        preview,
    );
    assert_eq!(restored.encode().unwrap(), before_preview);
    let pin = restored.pin_sweep_family_key_image_binding(preview.clone()).unwrap();
    assert_eq!(pin.binding, preview);
    assert_eq!(pin.binding.sweep(), plan.id);
    assert_ne!(pin.binding.unsigned_transaction_digest(), [0; 32]);
    assert_eq!(pin.binding.key_images(), key_images_in_prepared_order);
    let mut sorted_key_images = key_images_in_prepared_order.clone();
    sorted_key_images.sort_unstable_by(|left, right| right.cmp(left));
    assert_eq!(transaction_key_images(&transaction), sorted_key_images);

    // Another retry/subset may produce different CLSAG bytes for the exact same immutable family.
    let mut alternate_rng = ChaCha20Rng::from_seed([97; 32]);
    let (alternate_awaiting, _) = FrostlassSigner::start_in_session(
        prepared.transaction().clone(),
        single_party_keys(),
        &committee,
        PartyId(1),
        [PartyId(1)],
        group_key,
        SessionId([98; 32]),
        &mut alternate_rng,
    )
    .unwrap();
    let (alternate_finalizer, _) = alternate_awaiting
        .bind_transaction_bound([])
        .unwrap()
        .release_bound_signature_share()
        .unwrap();
    let alternate_transaction = alternate_finalizer.complete_bound([]).unwrap();
    let alternate_transaction_id = alternate_transaction.hash();
    assert_ne!(alternate_transaction_id, transaction_id);
    assert_eq!(
        transaction_key_images(&alternate_transaction),
        transaction_key_images(&transaction)
    );
    let alternate_signed =
        threshold_monero::deposit_wallet::SignedSweepTransaction::from_transaction(
            &alternate_transaction,
            Some(alternate_transaction_id),
        )
        .unwrap();
    restored.validate_sweep_family_candidate(plan.id, &alternate_signed).unwrap();

    if std::env::var_os("TM_BENCH_SWEEP_VALIDATION").is_some() {
        let started = std::time::Instant::now();
        for _ in 0..32 {
            restored.validate_sweep_family_candidate(plan.id, &alternate_signed).unwrap();
        }
        eprintln!("32 complete sweep candidate validations: {:?}", started.elapsed());
    }

    let assert_invalid = |candidate: monero_oxide::transaction::Transaction| {
        let signed = threshold_monero::deposit_wallet::SignedSweepTransaction::from_transaction(
            &candidate,
            Some(candidate.hash()),
        )
        .unwrap();
        for _ in 0..2 {
            assert!(matches!(
                restored.validate_sweep_family_candidate(plan.id, &signed),
                Err(DepositWorkerError::InvalidSweepFamilyCandidate)
                    | Err(DepositWorkerError::Wallet(
                        DepositWalletError::SignedSweepIntentMismatch
                    ))
            ));
        }
    };
    let mut wrong_output = alternate_transaction.clone();
    let monero_oxide::transaction::Transaction::V2 { prefix, .. } = &mut wrong_output else {
        unreachable!()
    };
    prefix.outputs[0].key = monero_wallet::ed25519::CompressedPoint::G;
    assert_invalid(wrong_output);
    let mut wrong_image = alternate_transaction.clone();
    let monero_oxide::transaction::Transaction::V2 { prefix, .. } = &mut wrong_image else {
        unreachable!()
    };
    let monero_oxide::transaction::Input::ToKey { key_image, .. } = &mut prefix.inputs[0] else {
        unreachable!()
    };
    *key_image = monero_wallet::ed25519::CompressedPoint::G;
    assert_invalid(wrong_image);

    let mut wrong_ring = alternate_transaction.clone();
    let monero_oxide::transaction::Transaction::V2 { prefix, .. } = &mut wrong_ring else {
        unreachable!()
    };
    let monero_oxide::transaction::Input::ToKey { key_offsets, .. } = &mut prefix.inputs[0] else {
        unreachable!()
    };
    key_offsets[0] = key_offsets[0].saturating_add(1);
    assert_invalid(wrong_ring);

    let mut wrong_clsag = alternate_transaction.clone();
    let monero_oxide::transaction::Transaction::V2 { proofs: Some(proofs), .. } = &mut wrong_clsag
    else {
        unreachable!()
    };
    let monero_oxide::ringct::RctPrunable::Clsag { clsags, .. } = &mut proofs.prunable else {
        unreachable!()
    };
    clsags[0].c1 = monero_wallet::ed25519::Scalar::ZERO;
    assert_invalid(wrong_clsag.clone());
    // Fill and evict the deterministic shape cache: matching outputs never authorize a CLSAG.
    for scalar in 1_u64..=65 {
        let monero_oxide::transaction::Transaction::V2 { proofs: Some(proofs), .. } =
            &mut wrong_clsag
        else {
            unreachable!()
        };
        let monero_oxide::ringct::RctPrunable::Clsag { clsags, .. } = &mut proofs.prunable else {
            unreachable!()
        };
        clsags[0].c1 = monero_wallet::ed25519::Scalar::from(scalar.into());
        assert_invalid(wrong_clsag.clone());
    }
    restored.validate_sweep_family_candidate(plan.id, &alternate_signed).unwrap();

    let mut wrong_pseudo_out = alternate_transaction.clone();
    let monero_oxide::transaction::Transaction::V2 { proofs: Some(proofs), .. } =
        &mut wrong_pseudo_out
    else {
        unreachable!()
    };
    let monero_oxide::ringct::RctPrunable::Clsag { pseudo_outs, .. } = &mut proofs.prunable else {
        unreachable!()
    };
    pseudo_outs[0] = monero_wallet::ed25519::CompressedPoint::G;
    assert_invalid(wrong_pseudo_out);

    let mut wrong_bulletproof_statement = alternate_transaction.clone();
    let monero_oxide::transaction::Transaction::V2 { proofs: Some(proofs), .. } =
        &mut wrong_bulletproof_statement
    else {
        unreachable!()
    };
    proofs.base.commitments[0] = monero_wallet::ed25519::CompressedPoint::G;
    assert_invalid(wrong_bulletproof_statement);

    let signed_effect =
        restored.mark_sweep_signed(plan.id, &transaction, Some(transaction_id)).unwrap();
    let signed = restored
        .signed_sweep_after_persist(signed_effect, signed_effect.revision(), plan.id)
        .unwrap();
    assert_eq!(signed.transaction_id(), transaction_id);
    assert_eq!(signed.as_bytes(), transaction.serialize());
    let signed_snapshot = restored.encode().unwrap();
    let mut tampered_snapshot = signed_snapshot.clone();
    let signed_offset = tampered_snapshot
        .windows(signed.as_bytes().len())
        .position(|bytes| bytes == signed.as_bytes())
        .unwrap();
    tampered_snapshot[signed_offset + signed.as_bytes().len() - 1] ^= 1;
    assert!(
        DepositWorkerState::decode(&tampered_snapshot, &deriver).is_err(),
        "a warm validation cache must reject changed signed bytes under the same revision",
    );
    let mut restored = DepositWorkerState::decode(&signed_snapshot, &deriver).unwrap();
    assert_eq!(restored.replay_signed_sweeps().unwrap().len(), 1);
    // ROAST evidence finality is independent of local publication state. A delayed distinct
    // signer endorsement must remain fully verifiable after local adoption made the immutable
    // family `Signed`.
    restored.validate_sweep_family_candidate(plan.id, &alternate_signed).unwrap();

    let mut alternate_blocks = vec![block(10, 10, 9)];
    let mut alternate_parent = 10_u8;
    for height in 11_u64..=20 {
        let hash = u8::try_from(100 + height).unwrap();
        alternate_blocks.push(block(height, hash, alternate_parent));
        alternate_parent = hash;
    }
    let alternate = MockChain::new(alternate_blocks);
    let mut quarantined = restored.clone();
    let quarantine_tick = quarantined.tick(&alternate, &deriver, &OUTPUT_INDEX).await.unwrap();
    let quarantine_effect = quarantine_tick.persistence.unwrap();
    let quarantine_events = quarantined
        .events_after_persist(quarantine_effect, quarantine_effect.revision())
        .unwrap()
        .unwrap();
    assert_eq!(quarantine_events.rollback.as_ref().unwrap().quarantined_sweeps, vec![plan.id]);
    assert!(matches!(
        quarantined.scan_state().sweep(plan.id).unwrap().status,
        SweepStatus::QuarantinedByReorg {
            transaction: Some(known),
            ..
        } if known == transaction_id
    ));
    assert!(quarantined.replay_signed_sweeps().unwrap().is_empty());

    restored.mark_sweep_broadcast(plan.id, transaction_id).unwrap();
    let broadcast_snapshot = restored.encode().unwrap();
    let mut restored = DepositWorkerState::decode(&broadcast_snapshot, &deriver).unwrap();
    // Broadcast transactions remain replayable for restart and mempool-eviction recovery.
    assert_eq!(restored.replay_signed_sweeps().unwrap().len(), 1);
    assert!(restored.reconcile_broadcast_confirmations().unwrap().is_empty());

    let mut confirmation_block = block(21, 21, 20);
    confirmation_block.root_outputs.push(scanned_root_output_for_transaction(
        39,
        alternate_transaction_id,
        0,
        900,
    ));
    confirmation_block.root_outputs.push(scanned_root_output_for_transaction(
        40,
        alternate_transaction_id,
        1,
        901,
    ));
    source.push(confirmation_block);
    let alternate_key_images = transaction_key_images(&alternate_transaction);
    source.include_transaction_key_images(
        21,
        alternate_transaction_id,
        vec![alternate_key_images[0]],
    );
    let mut conflicting_prefix = restored.clone();
    let conflicting_prefix_snapshot = conflicting_prefix.encode().unwrap();
    assert!(matches!(
        conflicting_prefix.tick(&source, &deriver, &OUTPUT_INDEX).await,
        Err(DepositWorkerError::SweepFamilySpendConflict(sweep)) if sweep == plan.id
    ));
    assert_eq!(conflicting_prefix.encode().unwrap(), conflicting_prefix_snapshot);

    source.include_transaction_key_images(21, alternate_transaction_id, alternate_key_images);
    source.set_fetched_transaction(alternate_transaction_id, Some(&transaction));
    let mut hash_mismatch = restored.clone();
    let hash_mismatch_snapshot = hash_mismatch.encode().unwrap();
    assert!(matches!(
        hash_mismatch.tick(&source, &deriver, &OUTPUT_INDEX).await,
        Err(DepositWorkerError::InvalidSweepFamilyChainEvidence)
    ));
    assert_eq!(hash_mismatch.encode().unwrap(), hash_mismatch_snapshot);
    source.set_fetched_transaction(alternate_transaction_id, None);

    let mut scanner_only = restored.clone();
    let scanner_only_snapshot = scanner_only.encode().unwrap();
    assert!(matches!(
        scanner_only.tick(&source, &deriver, &OUTPUT_INDEX).await,
        Err(DepositWorkerError::SweepFamilyTransactionBytesUnavailable {
            transaction,
            height: 21,
        }) if transaction == alternate_transaction_id
    ));
    assert_eq!(scanner_only.encode().unwrap(), scanner_only_snapshot);
    assert_eq!(scanner_only.scan_state().tip(), point(20, 20));

    // A block source which retains full canonical bytes discovers the privately aggregated
    // variant during the same scan.
    source.include_transaction(21, &alternate_transaction);
    let confirmation_tick = restored.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    assert!(!confirmation_tick.staged_events);
    let family_evidence = restored.reconcile_sweep_family_settlements().unwrap();
    assert_eq!(family_evidence.len(), 1);
    assert_eq!(family_evidence[0].transaction_id(), alternate_transaction_id);
    assert_eq!(family_evidence[0].signed_transaction.as_bytes(), alternate_transaction.serialize());
    let evidence = restored.reconcile_broadcast_confirmations().unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].sweep, plan.id);
    assert_eq!(evidence[0].transaction, alternate_transaction_id);
    assert_eq!(evidence[0].block, point(21, 21));
    restored.mark_sweep_confirmed(plan.id, alternate_transaction_id, evidence[0].block).unwrap();
    assert!(restored.reconcile_broadcast_confirmations().unwrap().is_empty());
    assert!(matches!(
        restored.scan_state().sweep(plan.id).unwrap().status,
        SweepStatus::Confirmed { transaction, .. } if transaction == alternate_transaction_id
    ));

    // Removing only the winner's block clears settlement and returns exact bytes to rebroadcast.
    let mut replacement = block(21, 121, 20);
    replacement.root_outputs.clear();
    source.replace(replacement);
    let rollback = restored.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    let rollback_effect = rollback.persistence.unwrap();
    let rollback_events = restored
        .events_after_persist(rollback_effect, rollback_effect.revision())
        .unwrap()
        .unwrap();
    assert_eq!(rollback_events.rollback.as_ref().unwrap().reverted_confirmations, vec![plan.id]);
    restored.acknowledge_events(rollback_events.id).unwrap();
    let replacement_tick = restored.tick(&source, &deriver, &OUTPUT_INDEX).await.unwrap();
    assert!(replacement_tick.persistence.is_some());
    assert_eq!(restored.scan_state().tip(), point(21, 121));
    assert!(restored.reconcile_sweep_family_settlements().unwrap().is_empty());
    let restored = DepositWorkerState::decode(&restored.encode().unwrap(), &deriver).unwrap();
    let replay = restored.replay_signed_sweeps().unwrap();
    assert!(replay.iter().any(|(_, candidate)| {
        candidate.transaction_id() == alternate_transaction_id
            && candidate.as_bytes() == alternate_transaction.serialize()
    }));
}
