use std::{collections::HashMap, io::Cursor};

use curve25519_dalek::{Scalar as DalekScalar, constants::ED25519_BASEPOINT_POINT};
use frost::{
    Participant, ThresholdKeys, ThresholdParams,
    curve::{Ciphersuite, Ed25519},
    dkg::Interpolation,
};
use monero_wallet::{
    OutputWithDecoys, WalletOutput,
    address::{AddressType, MoneroAddress, Network},
    ed25519::{Commitment, Point, Scalar},
    interface::FeeRate,
    ringct::{RctType, clsag::Decoys},
    send::{Change, SignableTransaction},
    transaction::Timelock,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use threshold_monero::{
    Committee, Member, NetworkKind, PartyId, SessionId,
    deposit_wallet::{
        CanonicalDepositAddress, ChainPoint, DepositAddressDeriver, DepositSubaddressIndex,
        DepositWalletError, PersistedRootOutput, PersistedWalletOutput, ScanState, ScannedBlock,
        WalletOutputId,
    },
    signing::{FrostlassSigner, SigningError},
};
use zeroize::Zeroizing;

type FrostScalar = <Ed25519 as Ciphersuite>::F;

fn root_key(secret: u64) -> [u8; 32] {
    (ED25519_BASEPOINT_POINT * DalekScalar::from(secret)).compress().to_bytes()
}

fn index(address: u32) -> DepositSubaddressIndex {
    DepositSubaddressIndex::new(0, address).unwrap()
}

fn deriver(root_secret: u64) -> DepositAddressDeriver {
    DepositAddressDeriver::new(
        NetworkKind::Mainnet,
        root_key(root_secret),
        &Zeroizing::new(DalekScalar::from(17_u64).to_bytes()),
    )
    .unwrap()
}

fn point(byte: u8, height: u64) -> ChainPoint {
    ChainPoint::new(height, [byte; 32]).unwrap()
}

fn scanned_output(
    root_secret: u64,
    offset: u64,
    subaddress: DepositSubaddressIndex,
    transaction_byte: u8,
    transaction_index: u64,
    blockchain_index: u64,
) -> WalletOutput {
    let offset = DalekScalar::from(offset);
    let output_key = ED25519_BASEPOINT_POINT * (DalekScalar::from(root_secret) + offset);
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
    bytes.extend_from_slice(&subaddress.account().to_le_bytes());
    bytes.extend_from_slice(&subaddress.address().to_le_bytes());
    bytes.push(0);
    bytes.push(0);

    let mut reader = Cursor::new(bytes.as_slice());
    let output = WalletOutput::read(&mut reader).unwrap();
    assert_eq!(usize::try_from(reader.position()).unwrap(), bytes.len());
    output
}

fn scanned_root_output(
    root_secret: u64,
    offset: u64,
    transaction_byte: u8,
    transaction_index: u64,
    blockchain_index: u64,
) -> WalletOutput {
    let offset = DalekScalar::from(offset);
    let output_key = ED25519_BASEPOINT_POINT * (DalekScalar::from(root_secret) + offset);
    let commitment = Commitment::new(Scalar::from(DalekScalar::from(88_u64)), 9_000_000);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[transaction_byte; 32]);
    bytes.extend_from_slice(&transaction_index.to_le_bytes());
    bytes.extend_from_slice(&blockchain_index.to_le_bytes());
    bytes.extend_from_slice(&output_key.compress().to_bytes());
    bytes.extend_from_slice(&offset.to_bytes());
    commitment.write(&mut bytes).unwrap();
    Timelock::None.write(&mut bytes).unwrap();
    bytes.push(0); // primary/root address, not a subaddress
    bytes.push(0); // no payment ID
    bytes.push(0); // no arbitrary-data chunks

    let mut reader = Cursor::new(bytes.as_slice());
    let output = WalletOutput::read(&mut reader).unwrap();
    assert_eq!(usize::try_from(reader.position()).unwrap(), bytes.len());
    assert!(output.subaddress().is_none());
    output
}

fn with_decoys(
    output: &WalletOutput,
    replacement_offset: Option<u64>,
    replacement_position: Option<u64>,
    preserve_signer_member: bool,
) -> OutputWithDecoys {
    let offset = replacement_offset
        .map_or_else(|| output.key_offset(), |value| Scalar::from(DalekScalar::from(value)));
    let commitment = output.commitment().clone();
    let real = [output.key(), commitment.commit()];
    let ring = (0_u64..16)
        .map(|position| {
            if position == 5 && preserve_signer_member {
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
    let signer_position = replacement_position.unwrap_or_else(|| output.index_on_blockchain());
    let first_position = signer_position.checked_sub(5).unwrap();
    let mut offsets = vec![1; 16];
    offsets[0] = first_position;
    let decoys = Decoys::new(offsets, 5, ring).unwrap();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&output.key().compress().to_bytes());
    offset.write(&mut bytes).unwrap();
    commitment.write(&mut bytes).unwrap();
    decoys.write(&mut bytes).unwrap();
    let mut reader = Cursor::new(bytes.as_slice());
    let input = OutputWithDecoys::read(&mut reader).unwrap();
    assert_eq!(usize::try_from(reader.position()).unwrap(), bytes.len());
    input
}

fn threshold_keys(secret: u64) -> ThresholdKeys<Ed25519> {
    let participant = Participant::new(1).unwrap();
    let secret = FrostScalar::from(secret);
    ThresholdKeys::new(
        ThresholdParams::new(1, 1, participant).unwrap(),
        Interpolation::Lagrange,
        Zeroizing::new(secret),
        HashMap::from([(participant, <Ed25519 as Ciphersuite>::generator() * secret)]),
    )
    .unwrap()
}

fn signable(input: OutputWithDecoys) -> SignableTransaction {
    let first = MoneroAddress::new(
        Network::Mainnet,
        AddressType::Legacy,
        Point::from(ED25519_BASEPOINT_POINT * DalekScalar::from(301_u64)),
        Point::from(ED25519_BASEPOINT_POINT * DalekScalar::from(302_u64)),
    );
    let second = MoneroAddress::new(
        Network::Mainnet,
        AddressType::Legacy,
        Point::from(ED25519_BASEPOINT_POINT * DalekScalar::from(401_u64)),
        Point::from(ED25519_BASEPOINT_POINT * DalekScalar::from(402_u64)),
    );
    SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        Zeroizing::new([91_u8; 32]),
        vec![input],
        vec![(first, 100_000), (second, 200_000)],
        Change::fingerprintable(None),
        vec![],
        FeeRate::new(1, 1).unwrap(),
    )
    .unwrap()
}

fn start_context_bound_frostlass(
    transaction: SignableTransaction,
    keys: ThresholdKeys<Ed25519>,
    session_byte: u8,
) -> Result<(), SigningError> {
    let party = PartyId(1);
    let committee = Committee {
        epoch: 1,
        threshold: 1,
        members: vec![Member { id: party, signing_key: [1; 32], encryption_key: [2; 32] }],
    };
    let expected_group_key = keys.original_group_key().0.compress().to_bytes();
    let mut rng = ChaCha20Rng::from_seed([session_byte.wrapping_add(1); 32]);
    FrostlassSigner::start_in_session(
        transaction,
        keys,
        &committee,
        party,
        [party],
        expected_group_key,
        SessionId([session_byte; 32]),
        &mut rng,
    )
    .map(|_| ())
}

#[test]
fn derives_standard_canonical_network_addresses() {
    assert!(matches!(
        DepositSubaddressIndex::new(0, 0),
        Err(DepositWalletError::PrimaryAddressIndex)
    ));
    let private_view = DalekScalar::from(17_u64).to_bytes();
    let deriver = DepositAddressDeriver::new(
        NetworkKind::Mainnet,
        root_key(42),
        &Zeroizing::new(private_view),
    )
    .unwrap();
    let address = deriver.derive(index(9));
    address.validate().unwrap();
    let parsed = MoneroAddress::from_str(Network::Mainnet, address.as_str()).unwrap();
    assert!(parsed.is_subaddress());

    // Independently spell out Monero's standard SubAddr\0 derivation equation.
    let mut material = b"SubAddr\0".to_vec();
    material.extend_from_slice(&private_view);
    material.extend_from_slice(&0_u32.to_le_bytes());
    material.extend_from_slice(&9_u32.to_le_bytes());
    let derivation: DalekScalar = Scalar::hash(Zeroizing::new(material)).into();
    let spend =
        ED25519_BASEPOINT_POINT * DalekScalar::from(42_u64) + ED25519_BASEPOINT_POINT * derivation;
    let view = spend * DalekScalar::from(17_u64);
    let expected = MoneroAddress::new(
        Network::Mainnet,
        AddressType::Subaddress,
        Point::from(spend),
        Point::from(view),
    );
    assert_eq!(address.as_str(), expected.to_string());
    deriver.verify_address(&address).unwrap();

    let another_view = DepositAddressDeriver::new(
        NetworkKind::Mainnet,
        root_key(42),
        &Zeroizing::new(DalekScalar::from(18_u64).to_bytes()),
    )
    .unwrap();
    assert!(matches!(
        another_view.verify_address(&address),
        Err(DepositWalletError::WrongWalletDomain)
    ));

    let encoded = postcard::to_allocvec(&address).unwrap();
    let restored: CanonicalDepositAddress = postcard::from_bytes(&encoded).unwrap();
    assert_eq!(restored, address);

    let testnet = DepositAddressDeriver::new(
        NetworkKind::Testnet,
        root_key(42),
        &Zeroizing::new(private_view),
    )
    .unwrap()
    .derive(index(9));
    assert_ne!(testnet.as_str(), address.as_str());
    MoneroAddress::from_str(Network::Testnet, testnet.as_str()).unwrap();

    let regtest = DepositAddressDeriver::new(
        NetworkKind::Regtest,
        root_key(42),
        &Zeroizing::new(private_view),
    )
    .unwrap()
    .derive(index(9));
    assert_eq!(regtest.as_str(), address.as_str());
    assert_eq!(regtest.network(), NetworkKind::Regtest);
}

#[test]
fn rejects_duplicate_output_key_atomically_and_accepts_it_after_reorg() {
    let deriver = deriver(42);
    let anchor = point(10, 100);
    let mut state = ScanState::new(&deriver, anchor).unwrap();
    let first =
        PersistedWalletOutput::from_scanner(&scanned_output(42, 9, index(1), 1, 0, 7)).unwrap();
    state
        .append_block(
            ScannedBlock { point: point(11, 101), parent_hash: anchor.hash },
            1_700_000_101,
            vec![first.clone()],
        )
        .unwrap();

    let burning_bug =
        PersistedWalletOutput::from_scanner(&scanned_output(42, 9, index(1), 2, 0, 8)).unwrap();
    let error = state
        .append_block(
            ScannedBlock { point: point(12, 102), parent_hash: point(11, 101).hash },
            1_700_000_102,
            vec![burning_bug.clone()],
        )
        .unwrap_err();
    assert!(matches!(error, DepositWalletError::DuplicateOutputKey { .. }));
    assert_eq!(state.tip(), point(11, 101));
    assert!(state.output(burning_bug.id()).is_none());

    state.rollback_to(anchor).unwrap();
    state
        .append_block(
            ScannedBlock { point: point(13, 101), parent_hash: anchor.hash },
            1_700_000_103,
            vec![burning_bug.clone()],
        )
        .unwrap();
    assert!(state.output(burning_bug.id()).is_some());
}

#[test]
fn reorg_removes_orphaned_output_and_durable_round_trip_is_exact() {
    let deriver = deriver(42);
    let anchor = point(20, 200);
    let block_one = point(21, 201);
    let block_two = point(22, 202);
    let block_three = point(23, 203);
    let mut state = ScanState::new(&deriver, anchor).unwrap();
    let first =
        PersistedWalletOutput::from_scanner(&scanned_output(42, 9, index(1), 3, 0, 9)).unwrap();
    let second =
        PersistedWalletOutput::from_scanner(&scanned_output(42, 10, index(1), 4, 0, 10)).unwrap();
    state
        .append_block(
            ScannedBlock { point: block_one, parent_hash: anchor.hash },
            1_700_000_201,
            vec![first.clone()],
        )
        .unwrap();
    state
        .append_block(
            ScannedBlock { point: block_two, parent_hash: block_one.hash },
            1_700_000_202,
            vec![second.clone()],
        )
        .unwrap();
    state
        .append_block(
            ScannedBlock { point: block_three, parent_hash: block_two.hash },
            1_700_000_203,
            vec![],
        )
        .unwrap();

    let encoded = state.encode().unwrap();
    let mut restored = ScanState::decode(&encoded).unwrap();
    assert_eq!(restored, state);
    let report = restored.rollback_to(block_one).unwrap();
    assert_eq!(report.removed_outputs, vec![second.id()]);
    assert!(report.invalidated_sweeps.is_empty());
    assert!(report.quarantined_sweeps.is_empty());
    assert!(report.reverted_confirmations.is_empty());
    assert_eq!(
        restored.available_outputs().map(PersistedWalletOutput::id).collect::<Vec<_>>(),
        vec![first.id()]
    );
}

#[test]
fn scanner_offset_reaches_frostlass_without_share_tweak() {
    let wallet = scanned_output(42, 9, index(1), 8, 0, 12);
    let persisted = PersistedWalletOutput::from_scanner(&wallet).unwrap();
    let input = with_decoys(&wallet, None, None, true);
    assert_eq!(
        persisted.verify_decoy_input(&input).unwrap().to_bytes(),
        DalekScalar::from(9_u64).to_bytes()
    );

    // The session-bound FROSTLASS state machine validates P = B + offset*G and succeeds with
    // untweaked root shares. No address-specific DKG or persistent ThresholdKeys::offset is
    // involved.
    assert!(start_context_bound_frostlass(signable(input.clone()), threshold_keys(42), 41).is_ok());

    let tweaked = threshold_keys(42).offset(FrostScalar::from(9_u64));
    assert!(matches!(
        start_context_bound_frostlass(signable(input), tweaked, 42),
        Err(SigningError::TweakedThresholdKeys)
    ));

    let changed = with_decoys(&wallet, Some(10), None, true);
    assert!(matches!(
        persisted.verify_decoy_input(&changed),
        Err(DepositWalletError::ScannerOffsetChanged)
    ));

    let wrong_position = with_decoys(&wallet, None, Some(13), true);
    assert!(matches!(
        persisted.verify_decoy_input(&wrong_position),
        Err(DepositWalletError::ScannerGlobalIndexChanged)
    ));

    let wrong_signer_member = with_decoys(&wallet, None, None, false);
    assert!(matches!(
        persisted.verify_decoy_input(&wrong_signer_member),
        Err(DepositWalletError::ScannerOffsetChanged)
    ));
}

#[test]
fn wrong_root_binding_fails_closed() {
    let deriver = deriver(42);
    let anchor = point(40, 400);
    let mut state = ScanState::new(&deriver, anchor).unwrap();
    let wrong_root_output =
        PersistedWalletOutput::from_scanner(&scanned_output(43, 9, index(7), 10, 0, 14)).unwrap();
    assert!(matches!(
        state.append_block(
            ScannedBlock { point: point(41, 401), parent_hash: anchor.hash },
            1_700_000_401,
            vec![wrong_root_output],
        ),
        Err(DepositWalletError::WrongOutputKey)
    ));
}

#[test]
fn output_identity_is_transaction_and_index_not_one_time_key() {
    let id = WalletOutputId { transaction: [44; 32], index_in_transaction: 3 };
    let encoded = postcard::to_allocvec(&id).unwrap();
    assert_eq!(postcard::from_bytes::<WalletOutputId>(&encoded).unwrap(), id);
}

#[test]
fn moving_checkpoint_bounds_public_height_empty_journal_across_restart() {
    let deriver = deriver(42);
    let birth = point(91, 3_000_000);
    let mut state = ScanState::new(&deriver, birth).unwrap();
    let mut parent = birth;

    // A high public-network height does not imply scanning or retaining genesis history. This
    // efficiently simulates another twenty thousand blocks after a multi-million-height birth
    // point while retaining only the configured 32-block reorg suffix.
    for height in (birth.height + 1)..=(birth.height + 20_000) {
        let mut hash = [0_u8; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        hash[8] = 1;
        let next = ChainPoint::new(height, hash).unwrap();
        state
            .append_block(
                ScannedBlock { point: next, parent_hash: parent.hash },
                1_700_000_000 + height,
                vec![],
            )
            .unwrap();
        state.compact_reorg_window(32).unwrap();
        assert!(state.retained_block_count() <= 32);
        parent = next;
    }

    assert_eq!(state.birth_anchor(), birth);
    assert_eq!(state.anchor().height, state.tip().height - 32);
    let encoded = state.encode().unwrap();
    assert!(encoded.len() < 16 * 1024);
    assert_eq!(ScanState::decode(&encoded).unwrap(), state);
}

#[test]
fn monero_additional_timelock_boundaries_follow_canonical_time_and_reorgs() {
    let deriver = deriver(42);
    let anchor = point(100, 100);
    let mut state = ScanState::new(&deriver, anchor).unwrap();
    let mut parent = anchor;

    for height in 101_u64..=160 {
        let next = point(u8::try_from(height).unwrap(), height);
        state
            .append_block(
                ScannedBlock { point: next, parent_hash: parent.hash },
                1_700_000_000,
                vec![],
            )
            .unwrap();
        parent = next;
    }

    assert!(state.additional_timelock_satisfied(Timelock::None));
    assert!(state.additional_timelock_satisfied(Timelock::Block(161)));
    assert!(!state.additional_timelock_satisfied(Timelock::Block(162)));
    // adjusted_time = min(latest + 120, median + 3_660) = 1_700_000_120, followed by
    // Monero's 120-second locked-transaction allowance.
    assert!(state.additional_timelock_satisfied(Timelock::Time(1_700_000_240)));
    assert!(!state.additional_timelock_satisfied(Timelock::Time(1_700_000_241)));
    assert!(!state.additional_timelock_satisfied(Timelock::Time(u64::MAX)));

    let ancestor = point(159, 159);
    state.rollback_to(ancestor).unwrap();
    // A reorg which temporarily leaves fewer than sixty authenticated timestamps fails closed for
    // time locks, while height locks continue to use the exact replacement tip.
    assert!(!state.additional_timelock_satisfied(Timelock::Time(1_700_000_000)));
    assert!(state.additional_timelock_satisfied(Timelock::Block(160)));
    assert!(!state.additional_timelock_satisfied(Timelock::Block(161)));

    let replacement = point(200, 160);
    state
        .append_block(
            ScannedBlock { point: replacement, parent_hash: ancestor.hash },
            1_700_001_000,
            vec![],
        )
        .unwrap();
    // The replacement window has median 1_700_000_000 and latest 1_700_001_000, so adjusted_time
    // is 1_700_001_120.
    assert!(state.additional_timelock_satisfied(Timelock::Time(1_700_001_240)));
    assert!(!state.additional_timelock_satisfied(Timelock::Time(1_700_001_241)));

    let restored = ScanState::decode(&state.encode().unwrap()).unwrap();
    assert_eq!(restored, state);
    assert!(restored.additional_timelock_satisfied(Timelock::Time(1_700_001_240)));
    assert!(!restored.additional_timelock_satisfied(Timelock::Time(1_700_001_241)));
}

#[test]
fn compacted_root_outputs_leave_only_the_bounded_reorg_window() {
    let deriver = deriver(42);
    let birth = point(101, 100);
    let root_point = point(102, 101);
    let root = PersistedRootOutput::from_scanner(&scanned_root_output(42, 19, 77, 0, 700)).unwrap();
    let mut state = ScanState::new(&deriver, birth).unwrap();
    state
        .append_block_with_root(
            ScannedBlock { point: root_point, parent_hash: birth.hash },
            1_700_000_101,
            vec![],
            vec![root.clone()],
        )
        .unwrap();
    let mut parent = root_point;
    for height in 102_u64..=106 {
        let next = point(u8::try_from(height).unwrap(), height);
        state
            .append_block(
                ScannedBlock { point: next, parent_hash: parent.hash },
                1_700_000_000 + height,
                vec![],
            )
            .unwrap();
        state.compact_reorg_window(2).unwrap();
        parent = next;
    }
    assert!(state.root_output(root.id()).is_none());
    assert_eq!(state.root_output_chain_point(root.id()), None);
    assert!(state.retained_block_count() <= 2);
    assert!(matches!(
        state.rollback_to(root_point),
        Err(DepositWalletError::UnknownChainPoint(point)) if point == root_point
    ));
    let encoded = state.encode().unwrap();
    assert_eq!(ScanState::decode(&encoded).unwrap(), state);
}
