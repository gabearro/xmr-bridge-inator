use std::{
    collections::{BTreeMap, HashMap},
    io::Cursor,
};

use curve25519_dalek::{
    EdwardsPoint, Scalar as DalekScalar,
    constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
    traits::Identity,
};
use frost::{
    FrostError, Participant, ThresholdKeys, ThresholdParams,
    curve::{Ciphersuite, Ed25519},
    dkg::Interpolation,
    sign::{PreprocessMachine, SignMachine, Writable},
};
use monero_oxide::transaction::Input as MoneroInput;
use monero_wallet::{
    OutputWithDecoys,
    address::{AddressType, MoneroAddress, Network},
    ed25519::{Commitment, Point, Scalar},
    interface::FeeRate,
    ringct::{RctType, clsag::Decoys},
    send::{Change, Eventuality, SendError, SignableTransaction},
};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{CryptoRng, Error as RandError, RngCore, SeedableRng},
};
use threshold_monero::{
    Committee, Member, PartyId, SessionId,
    committee::CommitteeError,
    keys::{EpochShare, EpochShareMaterial, PointBytes, ScalarBytes},
    signing::{
        BoundPreprocessMessage, BoundSignatureShareMessage, CanonicalSignerSet, FrostlassSigner,
        MAX_FROSTLASS_MESSAGE_BYTES, PreprocessMessage, ProofVerifiedKeyImagePreview,
        SignatureShareMessage, SigningError, SigningMessageKind, signing_context_in_session,
        threshold_group_key, validate_frostlass_preprocess_shape, validate_threshold_keys,
    },
};
use zeroize::Zeroizing;

type FrostScalar = <Ed25519 as Ciphersuite>::F;

const PARTIES: [PartyId; 3] = [PartyId(10), PartyId(20), PartyId(30)];
const NONCANONICAL_SCALAR_ENCODING: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn member(id: PartyId, discriminator: u8) -> Member {
    Member {
        id,
        signing_key: [discriminator; 32],
        encryption_key: [discriminator.wrapping_add(10); 32],
    }
}

fn committee() -> Committee {
    // Deliberately not sorted: FROST indices must be based on sorted stable party IDs.
    Committee {
        epoch: 7,
        threshold: 2,
        members: vec![member(PARTIES[2], 3), member(PARTIES[0], 1), member(PARTIES[1], 2)],
    }
}

fn polynomial_share(coefficients: &[FrostScalar], participant: Participant) -> FrostScalar {
    let x = FrostScalar::from(u64::from(u16::from(participant)));
    coefficients
        .iter()
        .rev()
        .fold(FrostScalar::ZERO, |value, coefficient| (value * x) + coefficient)
}

fn threshold_keys() -> Vec<ThresholdKeys<Ed25519>> {
    let coefficients = [FrostScalar::from(42_u64), FrostScalar::from(17_u64)];
    let verification_shares = (1_u16..=3)
        .map(|index| {
            let participant = Participant::new(index).unwrap();
            let share = polynomial_share(&coefficients, participant);
            (participant, <Ed25519 as Ciphersuite>::generator() * share)
        })
        .collect::<HashMap<_, _>>();

    (1_u16..=3)
        .map(|index| {
            let participant = Participant::new(index).unwrap();
            ThresholdKeys::new(
                ThresholdParams::new(2, 3, participant).unwrap(),
                Interpolation::Lagrange,
                Zeroizing::new(polynomial_share(&coefficients, participant)),
                verification_shares.clone(),
            )
            .unwrap()
        })
        .collect()
}

fn epoch_share(committee: Committee, local_party: PartyId, slope: u64) -> EpochShare {
    let constant = DalekScalar::from(42_u64);
    let slope = DalekScalar::from(slope);
    let verification_shares = committee
        .members
        .iter()
        .map(|member| {
            let index = DalekScalar::from(u64::from(committee.frost_index(member.id).unwrap()));
            let share = constant + (slope * index);
            (member.id, PointBytes((ED25519_BASEPOINT_POINT * share).compress().to_bytes()))
        })
        .collect::<BTreeMap<_, _>>();
    let local_index = DalekScalar::from(u64::from(committee.frost_index(local_party).unwrap()));
    EpochShare::from_material(EpochShareMaterial {
        key_id: [71; 32],
        committee,
        local_party,
        secret_share: ScalarBytes((constant + (slope * local_index)).to_bytes()),
        verification_shares,
        group_key: PointBytes((ED25519_BASEPOINT_POINT * constant).compress().to_bytes()),
    })
    .unwrap()
}

struct RejectNonceRng;

impl RngCore for RejectNonceRng {
    fn next_u32(&mut self) -> u32 {
        panic!("stale epoch key validation reached nonce generation")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("stale epoch key validation reached nonce generation")
    }

    fn fill_bytes(&mut self, _destination: &mut [u8]) {
        panic!("stale epoch key validation reached nonce generation")
    }

    fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), RandError> {
        panic!("stale epoch key validation reached nonce generation")
    }
}

impl CryptoRng for RejectNonceRng {}

fn malformed_keys(
    local_participant: Participant,
    wrong_local_secret: bool,
    wrong_last_verification_share: bool,
) -> ThresholdKeys<Ed25519> {
    let coefficients = [FrostScalar::from(42_u64), FrostScalar::from(17_u64)];
    let mut verification_shares = (1_u16..=3)
        .map(|index| {
            let participant = Participant::new(index).unwrap();
            let share = polynomial_share(&coefficients, participant);
            (participant, <Ed25519 as Ciphersuite>::generator() * share)
        })
        .collect::<HashMap<_, _>>();
    if wrong_last_verification_share {
        verification_shares.insert(
            Participant::new(3).unwrap(),
            <Ed25519 as Ciphersuite>::generator() * FrostScalar::from(999_u64),
        );
    }

    let mut secret = polynomial_share(&coefficients, local_participant);
    if wrong_local_secret {
        secret += FrostScalar::ONE;
    }
    ThresholdKeys::new(
        ThresholdParams::new(2, 3, local_participant).unwrap(),
        Interpolation::Lagrange,
        Zeroizing::new(secret),
        verification_shares,
    )
    .unwrap()
}

fn point(multiplier: u64) -> Point {
    Point::from(ED25519_BASEPOINT_POINT * DalekScalar::from(multiplier))
}

/// Construct a syntactically complete, entirely local Monero transaction fixture. Its fake ring
/// references do not exist on a chain, but all key/commitment relations and the FROSTLASS witness
/// are real. No daemon is needed to exercise transaction construction and threshold CLSAG.
fn fixture_input(keys: &ThresholdKeys<Ed25519>, input_index: usize) -> OutputWithDecoys {
    let input_index_u64 = u64::try_from(input_index).unwrap();
    let output_amount = 10_000_000_u64 + (input_index_u64 * 1_000_000);
    let key_offset = DalekScalar::from(9_u64 + (input_index_u64 * 4));
    let output_key =
        Point::from(keys.original_group_key().0 + (ED25519_BASEPOINT_POINT * key_offset));
    let commitment =
        Commitment::new(Scalar::from(DalekScalar::from(77_u64 + input_index_u64)), output_amount);
    let real_index = 5_usize;

    let ring = (0_u64..16)
        .map(|index| {
            if usize::try_from(index).unwrap() == real_index {
                [output_key, commitment.commit()]
            } else {
                let discriminator = (input_index_u64 * 1_000) + index;
                let decoy_commitment = Commitment::new(
                    Scalar::from(DalekScalar::from(200 + discriminator)),
                    1_000 + discriminator,
                );
                [point(100 + discriminator), decoy_commitment.commit()]
            }
        })
        .collect::<Vec<_>>();
    let decoys = Decoys::new(
        (0_u64..16).map(|index| 1 + (input_index_u64 * 32) + index).collect(),
        u8::try_from(real_index).unwrap(),
        ring,
    )
    .unwrap();

    // OutputWithDecoys intentionally has no public unchecked constructor. Use its documented
    // format so the production parser validates this fixture in the same way as network data.
    let mut output_bytes = Vec::new();
    output_bytes.extend_from_slice(&output_key.compress().to_bytes());
    Scalar::from(key_offset).write(&mut output_bytes).unwrap();
    commitment.write(&mut output_bytes).unwrap();
    decoys.write(&mut output_bytes).unwrap();
    let mut reader = Cursor::new(output_bytes.as_slice());
    let input = OutputWithDecoys::read(&mut reader).unwrap();
    assert_eq!(usize::try_from(reader.position()).unwrap(), output_bytes.len());
    input
}

fn signable_transaction_with_input_order(
    keys: &ThresholdKeys<Ed25519>,
    first_payment: u64,
    input_order: &[usize],
) -> SignableTransaction {
    let inputs = input_order.iter().map(|index| fixture_input(keys, *index)).collect();

    let first = MoneroAddress::new(Network::Mainnet, AddressType::Legacy, point(301), point(302));
    let second = MoneroAddress::new(Network::Mainnet, AddressType::Legacy, point(401), point(402));

    SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        Zeroizing::new([91_u8; 32]),
        inputs,
        vec![(first, first_payment), (second, 200_000)],
        Change::fingerprintable(None),
        vec![],
        FeeRate::new(1, 1).unwrap(),
    )
    .unwrap()
}

fn signable_transaction_with_first_payment(
    keys: &ThresholdKeys<Ed25519>,
    first_payment: u64,
) -> SignableTransaction {
    signable_transaction_with_input_order(keys, first_payment, &[0])
}

fn multi_input_signable_transaction(keys: &ThresholdKeys<Ed25519>) -> SignableTransaction {
    // This deterministic order is intentionally opposite Monero's descending key-image order so
    // the multi-input tests exercise the consensus-required input sort.
    signable_transaction_with_input_order(keys, 100_000, &[1, 0])
}

fn signable_transaction(keys: &ThresholdKeys<Ed25519>) -> SignableTransaction {
    signable_transaction_with_first_payment(keys, 100_000)
}

fn start_two_bound(
    transaction: &SignableTransaction,
    keys: &[ThresholdKeys<Ed25519>],
    session: SessionId,
    seed: u8,
) -> (
    threshold_monero::signing::AwaitingCommitments,
    BoundPreprocessMessage,
    threshold_monero::signing::AwaitingCommitments,
    BoundPreprocessMessage,
) {
    let committee = committee();
    let expected_group_key = threshold_group_key(&keys[0]);
    let signers = [PARTIES[0], PARTIES[2]];
    let mut first_rng = ChaCha20Rng::from_seed([seed; 32]);
    let mut third_rng = ChaCha20Rng::from_seed([seed.wrapping_add(1); 32]);
    let (first_state, first_preprocess) = FrostlassSigner::start_in_session(
        transaction.clone(),
        keys[0].clone(),
        &committee,
        PARTIES[0],
        signers,
        expected_group_key,
        session,
        &mut first_rng,
    )
    .unwrap();
    let (third_state, third_preprocess) = FrostlassSigner::start_in_session(
        transaction.clone(),
        keys[2].clone(),
        &committee,
        PARTIES[2],
        signers,
        expected_group_key,
        session,
        &mut third_rng,
    )
    .unwrap();
    (first_state, first_preprocess, third_state, third_preprocess)
}

fn replace_bound_preprocess_bytes(
    message: BoundPreprocessMessage,
    bytes: Vec<u8>,
) -> BoundPreprocessMessage {
    let mut value = serde_json::to_value(message).unwrap();
    value["message"] = serde_json::to_value(bytes).unwrap();
    serde_json::from_value(value).unwrap()
}

fn replace_bound_share_bytes(
    message: BoundSignatureShareMessage,
    bytes: Vec<u8>,
) -> BoundSignatureShareMessage {
    let mut value = serde_json::to_value(message).unwrap();
    value["message"] = serde_json::to_value(bytes).unwrap();
    serde_json::from_value(value).unwrap()
}

fn first_final_and_third_share(
    transaction: &SignableTransaction,
    keys: &[ThresholdKeys<Ed25519>],
    seed: u8,
) -> (threshold_monero::signing::AwaitingShares, BoundSignatureShareMessage) {
    let session = SessionId([seed; 32]);
    let (first_state, first_preprocess, third_state, third_preprocess) =
        start_two_bound(transaction, keys, session, seed);
    let (first_final, _) = first_state
        .bind_transaction_bound([(PARTIES[2], third_preprocess)])
        .unwrap()
        .release_bound_signature_share()
        .unwrap();
    let (_, third_share) = third_state
        .bind_transaction_bound([(PARTIES[0], first_preprocess)])
        .unwrap()
        .release_bound_signature_share()
        .unwrap();
    (first_final, third_share)
}

fn start_bound_pair(
    transaction: &SignableTransaction,
    keys: &[ThresholdKeys<Ed25519>],
    key_indices: [usize; 2],
    session: SessionId,
    seed: u8,
) -> (
    threshold_monero::signing::AwaitingCommitments,
    BoundPreprocessMessage,
    threshold_monero::signing::AwaitingCommitments,
    BoundPreprocessMessage,
) {
    let committee = committee();
    let expected_group_key = threshold_group_key(&keys[0]);
    let parties = [PARTIES[key_indices[0]], PARTIES[key_indices[1]]];
    let mut first_rng = ChaCha20Rng::from_seed([seed; 32]);
    let mut second_rng = ChaCha20Rng::from_seed([seed.wrapping_add(1); 32]);
    let (first_state, first_preprocess) = FrostlassSigner::start_in_session(
        transaction.clone(),
        keys[key_indices[0]].clone(),
        &committee,
        parties[0],
        parties,
        expected_group_key,
        session,
        &mut first_rng,
    )
    .unwrap();
    let (second_state, second_preprocess) = FrostlassSigner::start_in_session(
        transaction.clone(),
        keys[key_indices[1]].clone(),
        &committee,
        parties[1],
        parties,
        expected_group_key,
        session,
        &mut second_rng,
    )
    .unwrap();
    (first_state, first_preprocess, second_state, second_preprocess)
}

#[derive(Clone, Copy)]
enum PreprocessProofField {
    KeyImageShare,
    CommitmentG,
    CommitmentH,
    Response,
}

fn tamper_preprocess_field(
    bytes: &mut [u8],
    input_quantity: usize,
    input_index: usize,
    field: PreprocessProofField,
) {
    let replacement = match field {
        PreprocessProofField::KeyImageShare => point(8_001).compress().to_bytes(),
        PreprocessProofField::CommitmentG => point(8_002).compress().to_bytes(),
        PreprocessProofField::CommitmentH => point(8_003).compress().to_bytes(),
        PreprocessProofField::Response => {
            let mut scalar = [0; 32];
            scalar[0] = 1;
            scalar
        }
    };
    replace_preprocess_field(bytes, input_quantity, input_index, field, replacement);
}

fn replace_preprocess_field(
    bytes: &mut [u8],
    input_quantity: usize,
    input_index: usize,
    field: PreprocessProofField,
    replacement: [u8; 32],
) {
    let offset = preprocess_field_offset(bytes, input_quantity, input_index, field);
    assert_ne!(&bytes[offset..offset + 32], replacement.as_slice());
    bytes[offset..offset + 32].copy_from_slice(&replacement);
}

fn preprocess_field_offset(
    bytes: &[u8],
    input_quantity: usize,
    input_index: usize,
    field: PreprocessProofField,
) -> usize {
    assert!(input_quantity > 0);
    assert!(input_index < input_quantity);
    assert_eq!(bytes.len() % input_quantity, 0);
    let stride = bytes.len() / input_quantity;
    // Each interleaved per-input encoding ends in xH (32 bytes), followed by rG/rH/z (96 bytes).
    assert!(stride >= 128);
    let proof_start = ((input_index + 1) * stride) - 96;
    match field {
        PreprocessProofField::KeyImageShare => proof_start - 32,
        PreprocessProofField::CommitmentG => proof_start,
        PreprocessProofField::CommitmentH => proof_start + 32,
        PreprocessProofField::Response => proof_start + 64,
    }
}

fn preprocess_field_bytes(
    bytes: &[u8],
    input_quantity: usize,
    input_index: usize,
    field: PreprocessProofField,
) -> [u8; 32] {
    let offset = preprocess_field_offset(bytes, input_quantity, input_index, field);
    bytes[offset..offset + 32].try_into().unwrap()
}

fn direct_preprocess_bytes(
    transaction: &SignableTransaction,
    keys: &ThresholdKeys<Ed25519>,
    context: [u8; 32],
    seed: u8,
) -> Vec<u8> {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let machine = transaction.clone().multisig_with_context(keys.clone(), context).unwrap();
    let (_, preprocess) = machine.preprocess(&mut rng);
    preprocess.serialize()
}

fn direct_bind_error(
    transaction: &SignableTransaction,
    keys: &ThresholdKeys<Ed25519>,
    context: [u8; 32],
    peer: Participant,
    peer_preprocess: &[u8],
    seed: u8,
) -> FrostError {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let machine = transaction.clone().multisig_with_context(keys.clone(), context).unwrap();
    let (machine, _) = machine.preprocess(&mut rng);
    let mut reader = Cursor::new(peer_preprocess);
    let parsed = machine.read_preprocess(&mut reader).unwrap();
    assert_eq!(usize::try_from(reader.position()).unwrap(), peer_preprocess.len());
    let result = machine.bind(HashMap::from([(peer, parsed)]));
    match result {
        Ok(_) => panic!("TransactionSignMachine::bind accepted an invalid proof"),
        Err(error) => error,
    }
}

#[test]
fn validates_keys_and_canonicalizes_signers() {
    let committee = committee();
    let keys = threshold_keys();
    let group_key = threshold_group_key(&keys[0]);

    validate_threshold_keys(&keys[0], &committee, PARTIES[0], group_key).unwrap();
    validate_threshold_keys(&keys[2], &committee, PARTIES[2], group_key).unwrap();

    let signers =
        CanonicalSignerSet::new(&committee, PARTIES[2], [PARTIES[2], PARTIES[0]]).unwrap();
    assert_eq!(signers.parties(), &[PARTIES[0], PARTIES[2]]);
    assert_eq!(signers.participant(PARTIES[0]), Participant::new(1));
    assert_eq!(signers.participant(PARTIES[2]), Participant::new(3));
}

#[test]
fn vendored_frostlass_rejects_an_unbound_zero_context() {
    let keys = threshold_keys();
    let transaction = signable_transaction(&keys[0]);
    assert!(matches!(
        transaction.multisig_with_context(keys[0].clone(), [0; 32]),
        Err(SendError::MissingMultisigContext)
    ));
}

#[test]
fn direct_transaction_sign_machine_cannot_release_a_signature_share() {
    let keys = threshold_keys();
    let transaction = signable_transaction(&keys[0]);
    let context = [109; 32];
    let peer = Participant::new(3).unwrap();
    let peer_preprocess = direct_preprocess_bytes(&transaction, &keys[2], context, 110);

    let mut rng = ChaCha20Rng::from_seed([111; 32]);
    let machine = transaction.multisig_with_context(keys[0].clone(), context).unwrap();
    let (machine, _) = machine.preprocess(&mut rng);
    let mut reader = Cursor::new(&peer_preprocess);
    let parsed = machine.read_preprocess(&mut reader).unwrap();
    assert_eq!(usize::try_from(reader.position()).unwrap(), peer_preprocess.len());

    match machine.sign(HashMap::from([(peer, parsed)]), &[]) {
        Err(error) => assert_eq!(
            error,
            FrostError::InternalError(
                "direct TransactionSignMachine::sign is disabled; bind the transaction before releasing a signature share",
            ),
        ),
        Ok(_) => panic!("direct TransactionSignMachine::sign released a signature share"),
    }
}

#[test]
fn rejects_inconsistent_threshold_keys_before_nonce_generation() {
    let committee = committee();
    let valid = threshold_keys();
    let group_key = threshold_group_key(&valid[0]);

    let wrong_participant = validate_threshold_keys(&valid[1], &committee, PARTIES[0], group_key);
    assert!(matches!(wrong_participant, Err(SigningError::KeyParameters { .. })));

    let wrong_secret = malformed_keys(Participant::new(1).unwrap(), true, false);
    let result = validate_threshold_keys(&wrong_secret, &committee, PARTIES[0], group_key);
    assert!(matches!(result, Err(SigningError::LocalShareMismatch)));

    let wrong_public_polynomial = malformed_keys(Participant::new(1).unwrap(), false, true);
    let result =
        validate_threshold_keys(&wrong_public_polynomial, &committee, PARTIES[0], group_key);
    assert!(matches!(
        result,
        Err(SigningError::InconsistentVerificationShare { participant })
            if participant == Participant::new(3).unwrap()
    ));

    let result = validate_threshold_keys(&valid[0], &committee, PARTIES[0], [0_u8; 32]);
    assert!(matches!(result, Err(SigningError::WrongGroupKey)));

    let tweaked = valid[0].clone().offset(FrostScalar::ONE);
    let result = validate_threshold_keys(&tweaked, &committee, PARTIES[0], group_key);
    assert!(matches!(result, Err(SigningError::TweakedThresholdKeys)));
}

#[test]
fn authenticated_successor_epoch_rejects_old_refresh_share_before_preprocess_generation() {
    let old_committee = committee();
    let mut successor_committee = old_committee.clone();
    successor_committee.epoch += 1;
    for member in &mut successor_committee.members {
        member.encryption_key[0] = member.encryption_key[0].wrapping_add(64);
    }

    // A proactive refresh preserves the constant term while replacing every non-constant
    // coefficient. The old share is therefore internally valid and has the right wallet key, but
    // its complete verification table is not valid for the authenticated successor epoch.
    let old = epoch_share(old_committee, PARTIES[0], 17);
    let successor = epoch_share(successor_committee, PARTIES[0], 29);
    assert_eq!(old.group_key_bytes(), successor.group_key_bytes());
    assert_ne!(old.public().verification_shares, successor.public().verification_shares);
    assert_ne!(old.activation_digest().unwrap(), successor.activation_digest().unwrap());

    let transaction = signable_transaction(&successor.to_threshold_keys().unwrap());
    let mut reject_nonce_rng = RejectNonceRng;
    let result = FrostlassSigner::start_in_authenticated_epoch_session(
        transaction,
        &old,
        &successor.public(),
        PARTIES[0],
        [PARTIES[0], PARTIES[2]],
        SessionId([113; 32]),
        &mut reject_nonce_rng,
    );
    assert!(matches!(
        result,
        Err(SigningError::EpochKeyMismatch { expected_epoch: 8, supplied_epoch: 7 })
    ));
}

#[test]
fn rejects_noncanonical_signer_sets() {
    let committee = committee();

    let duplicate = CanonicalSignerSet::new(&committee, PARTIES[0], [PARTIES[0], PARTIES[0]]);
    assert!(matches!(duplicate, Err(SigningError::DuplicateSigner(p)) if p == PARTIES[0]));

    let too_small = CanonicalSignerSet::new(&committee, PARTIES[0], [PARTIES[0]]);
    assert!(matches!(too_small, Err(SigningError::NotEnoughSigners { .. })));

    let missing_local = CanonicalSignerSet::new(&committee, PARTIES[0], [PARTIES[1], PARTIES[2]]);
    assert!(matches!(
        missing_local,
        Err(SigningError::LocalSignerMissing(p)) if p == PARTIES[0]
    ));

    let nonmember = CanonicalSignerSet::new(&committee, PARTIES[0], [PARTIES[0], PartyId(999)]);
    assert!(matches!(
        nonmember,
        Err(SigningError::Committee(CommitteeError::UnknownParty(PartyId(999))))
    ));
}

#[test]
fn wire_message_newtypes_round_trip() {
    let preprocess = PreprocessMessage::from_bytes(vec![1, 2, 3, 4]);
    let encoded = postcard::to_allocvec(&preprocess).unwrap();
    let decoded: PreprocessMessage = postcard::from_bytes(&encoded).unwrap();
    assert_eq!(decoded, preprocess);
    assert_eq!(decoded.as_bytes(), &[1, 2, 3, 4]);
    let json = serde_json::to_vec(&preprocess).unwrap();
    assert_eq!(serde_json::from_slice::<PreprocessMessage>(&json).unwrap(), preprocess);

    let share = SignatureShareMessage::from_bytes(vec![5, 6, 7]);
    let encoded = postcard::to_allocvec(&share).unwrap();
    let decoded: SignatureShareMessage = postcard::from_bytes(&encoded).unwrap();
    assert_eq!(decoded, share);
    assert_eq!(decoded.into_bytes(), vec![5, 6, 7]);

    let oversized = PreprocessMessage::from_bytes(vec![0; MAX_FROSTLASS_MESSAGE_BYTES + 1]);
    let encoded = postcard::to_allocvec(&oversized).unwrap();
    assert!(postcard::from_bytes::<PreprocessMessage>(&encoded).is_err());
}

#[test]
fn durable_preprocess_shape_parser_matches_the_live_monero_wallet_encoding() {
    let keys = threshold_keys();
    let transaction = multi_input_signable_transaction(&keys[0]);
    let (_, first, _, third) = start_two_bound(&transaction, &keys, SessionId([10; 32]), 10);

    assert_eq!(validate_frostlass_preprocess_shape(PARTIES[0], first.message(), 2).unwrap(), 512);
    assert_eq!(validate_frostlass_preprocess_shape(PARTIES[2], third.message(), 2).unwrap(), 512);

    // Warm successful replays must still bind every point, scalar, and the input count.
    for _ in 0..2 {
        assert_eq!(
            validate_frostlass_preprocess_shape(PARTIES[0], first.message(), 2).unwrap(),
            512
        );
        assert_eq!(
            validate_frostlass_preprocess_shape(PARTIES[2], third.message(), 2).unwrap(),
            512
        );
    }
    assert!(matches!(
        validate_frostlass_preprocess_shape(PARTIES[0], first.message(), 1),
        Err(SigningError::WrongMessageLength { expected: 256, actual: 512, .. })
    ));
    for field in 0..16 {
        let mut corrupt = first.message().as_bytes().to_vec();
        corrupt[field * 32..(field + 1) * 32].fill(0xff);
        let corrupt = PreprocessMessage::from_bytes(corrupt);
        for _ in 0..2 {
            assert!(matches!(
                validate_frostlass_preprocess_shape(PARTIES[0], &corrupt, 2),
                Err(SigningError::MalformedMessage { kind: SigningMessageKind::Preprocess, .. })
            ));
        }
    }
    assert_eq!(validate_frostlass_preprocess_shape(PARTIES[0], first.message(), 2).unwrap(), 512);

    let mut identity_commitment = first.message().as_bytes().to_vec();
    identity_commitment[..32]
        .copy_from_slice(&<EdwardsPoint as Identity>::identity().compress().to_bytes());
    assert!(matches!(
        validate_frostlass_preprocess_shape(
            PARTIES[0],
            &PreprocessMessage::from_bytes(identity_commitment),
            2,
        ),
        Err(SigningError::MalformedMessage { kind: SigningMessageKind::Preprocess, .. })
    ));

    let mut trailing = third.message().as_bytes().to_vec();
    trailing.push(0);
    assert!(matches!(
        validate_frostlass_preprocess_shape(
            PARTIES[2],
            &PreprocessMessage::from_bytes(trailing),
            2,
        ),
        Err(SigningError::WrongMessageLength { expected: 512, actual: 513, .. })
    ));
}

#[test]
fn signs_a_complete_monero_transaction_in_process() {
    let keys = threshold_keys();
    let transaction = signable_transaction(&keys[0]);
    let (first_state, first_preprocess, third_state, third_preprocess) =
        start_two_bound(&transaction, &keys, SessionId([11; 32]), 11);

    assert_eq!(first_state.signers().parties(), &[PARTIES[0], PARTIES[2]]);
    assert_eq!(first_state.context(), third_state.context());
    let (first_final, first_share) = first_state
        .bind_transaction_bound([(PARTIES[2], third_preprocess.clone())])
        .unwrap()
        .release_bound_signature_share()
        .unwrap();
    let (third_final, third_share) = third_state
        .bind_transaction_bound([(PARTIES[0], first_preprocess.clone())])
        .unwrap()
        .release_bound_signature_share()
        .unwrap();

    let first_transaction =
        first_final.complete_bound([(PARTIES[2], third_share.clone())]).unwrap();
    let third_transaction =
        third_final.complete_bound([(PARTIES[0], first_share.clone())]).unwrap();

    assert_eq!(first_transaction.serialize(), third_transaction.serialize());
    assert!(first_transaction.signature_hash().is_some());
}

#[test]
fn binds_the_exact_unsigned_transaction_before_releasing_shares() {
    let keys = threshold_keys();
    let transaction = signable_transaction(&keys[0]);
    let session = SessionId([49; 32]);
    let (first_state, first_preprocess, third_state, third_preprocess) =
        start_two_bound(&transaction, &keys, session, 47);

    let first_bound = first_state.bind_transaction_bound([(PARTIES[2], third_preprocess)]).unwrap();
    let third_bound = third_state.bind_transaction_bound([(PARTIES[0], first_preprocess)]).unwrap();
    assert_eq!(first_bound.context(), third_bound.context());
    assert_eq!(first_bound.key_images(), third_bound.key_images());
    assert_eq!(first_bound.key_images().len(), 1);
    assert_eq!(
        first_bound.unsigned_transaction().serialize(),
        third_bound.unsigned_transaction().serialize(),
    );
    let unsigned = first_bound.unsigned_transaction().serialize();
    let unsigned_prefix = first_bound.unsigned_transaction().prefix().clone();

    let (first_final, first_share) = first_bound.release_bound_signature_share().unwrap();
    let (third_final, third_share) = third_bound.release_bound_signature_share().unwrap();
    let first_transaction = first_final.complete_bound([(PARTIES[2], third_share)]).unwrap();
    let third_transaction = third_final.complete_bound([(PARTIES[0], first_share)]).unwrap();

    assert_eq!(first_transaction.serialize(), third_transaction.serialize());
    assert_ne!(first_transaction.serialize(), unsigned);
    assert_eq!(first_transaction.prefix(), &unsigned_prefix);
}

#[test]
fn proof_verified_multi_input_preview_is_stable_across_retry_subsets_and_gates_share_release() {
    let keys = threshold_keys();
    let transaction = multi_input_signable_transaction(&keys[0]);
    let eventuality = Eventuality::from(transaction.clone());

    let (first_state, first_preprocess, third_state, third_preprocess) =
        start_bound_pair(&transaction, &keys, [0, 2], SessionId([71; 32]), 72);
    let mut external_preprocess_copy = third_preprocess.message().as_bytes().to_vec();
    let first_bound = first_state.bind_transaction_bound([(PARTIES[2], third_preprocess)]).unwrap();
    let third_bound = third_state.bind_transaction_bound([(PARTIES[0], first_preprocess)]).unwrap();

    // bind_transaction_bound returns only the authorization state. A signature share does not
    // exist at this API boundary; only the explicit consuming release below can create one.
    let first_preview: &ProofVerifiedKeyImagePreview = first_bound.proof_verified_preview();
    let third_preview: &ProofVerifiedKeyImagePreview = third_bound.proof_verified_preview();
    assert_eq!(first_preview.context(), first_bound.context());
    assert_eq!(first_preview.key_images(), third_preview.key_images());
    assert_eq!(first_preview.key_images().len(), 2);
    assert_eq!(first_preview.preprocess_set_digest(), third_preview.preprocess_set_digest());
    assert_eq!(
        first_preview.unsigned_transaction().serialize(),
        third_preview.unsigned_transaction().serialize(),
    );

    let first_attempt_key_images = first_preview.key_images().to_vec();
    let first_attempt_unsigned = first_preview.unsigned_transaction().serialize();
    let first_attempt_prefix = first_preview.unsigned_transaction().prefix().clone();
    let first_attempt_preprocess_digest = first_preview.preprocess_set_digest();

    let actual_sorted_key_images = first_preview
        .unsigned_transaction()
        .prefix()
        .inputs
        .iter()
        .map(|input| match input {
            MoneroInput::ToKey { key_image, .. } => *key_image,
            MoneroInput::Gen(_) => panic!("fixture unexpectedly created a miner input"),
        })
        .collect::<Vec<_>>();
    let mut expected_sorted_key_images = first_attempt_key_images.clone();
    expected_sorted_key_images.sort_by(|left, right| right.cmp(left));
    assert_ne!(
        first_attempt_key_images, expected_sorted_key_images,
        "the deterministic fixture must exercise Monero's input reorder"
    );
    assert_eq!(actual_sorted_key_images, expected_sorted_key_images);

    // A fresh session and a different valid threshold subset derive the same original-order key
    // images and unsigned transaction family, despite distinct nonces and proof-bearing bytes.
    let (retry_first_state, retry_first_preprocess, retry_second_state, retry_second_preprocess) =
        start_bound_pair(&transaction, &keys, [0, 1], SessionId([73; 32]), 74);
    let retry_first_bound =
        retry_first_state.bind_transaction_bound([(PARTIES[1], retry_second_preprocess)]).unwrap();
    let retry_second_bound =
        retry_second_state.bind_transaction_bound([(PARTIES[0], retry_first_preprocess)]).unwrap();
    assert_eq!(retry_first_bound.key_images(), retry_second_bound.key_images());
    assert_eq!(retry_first_bound.key_images(), first_attempt_key_images);
    assert_eq!(retry_first_bound.unsigned_transaction().serialize(), first_attempt_unsigned);
    assert_ne!(
        retry_first_bound.proof_verified_preview().preprocess_set_digest(),
        first_attempt_preprocess_digest,
    );

    // Mutating a caller-owned copy after bind cannot replace the exact parsed preprocess set held
    // by AwaitingAuthorization.
    tamper_preprocess_field(&mut external_preprocess_copy, 2, 0, PreprocessProofField::Response);
    let (first_final, first_share) = first_bound.release_bound_signature_share().unwrap();
    let (third_final, third_share) = third_bound.release_bound_signature_share().unwrap();
    let first_transaction = first_final.complete_bound([(PARTIES[2], third_share)]).unwrap();
    let third_transaction = third_final.complete_bound([(PARTIES[0], first_share)]).unwrap();
    assert_eq!(first_transaction.serialize(), third_transaction.serialize());
    assert_eq!(first_transaction.prefix(), &first_attempt_prefix);
    assert!(eventuality.matches(&first_transaction.clone().into()));
}

#[test]
fn independent_valid_preprocess_equivocations_keep_key_images_but_change_exact_set_digest() {
    let keys = threshold_keys();
    let transaction = multi_input_signable_transaction(&keys[0]);
    let committee = committee();
    let group_key = threshold_group_key(&keys[0]);
    let session = SessionId([109; 32]);
    let signers = [PARTIES[0], PARTIES[2]];

    let start = |key_index: usize, seed: u8| {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        FrostlassSigner::start_in_session(
            transaction.clone(),
            keys[key_index].clone(),
            &committee,
            PARTIES[key_index],
            signers,
            group_key,
            session,
            &mut rng,
        )
        .unwrap()
    };

    // Reconstruct the same local pre-share state twice without ever releasing a share. This is
    // test-only deterministic RNG use, allowing the peer's valid equivocation to be the sole byte
    // difference between the two exact preprocess sets.
    let (first_local, first_local_preprocess) = start(0, 110);
    let (second_local, second_local_preprocess) = start(0, 110);
    assert_eq!(first_local_preprocess, second_local_preprocess);
    let (_, peer_preprocess_a) = start(2, 111);
    let (_, peer_preprocess_b) = start(2, 112);
    assert_ne!(peer_preprocess_a, peer_preprocess_b);
    for input_index in 0..2 {
        assert_eq!(
            preprocess_field_bytes(
                peer_preprocess_a.message().as_bytes(),
                2,
                input_index,
                PreprocessProofField::KeyImageShare,
            ),
            preprocess_field_bytes(
                peer_preprocess_b.message().as_bytes(),
                2,
                input_index,
                PreprocessProofField::KeyImageShare,
            ),
        );
    }

    let first_bound =
        first_local.bind_transaction_bound([(PARTIES[2], peer_preprocess_a)]).unwrap();
    let second_bound =
        second_local.bind_transaction_bound([(PARTIES[2], peer_preprocess_b)]).unwrap();
    assert_eq!(first_bound.key_images(), second_bound.key_images());
    assert_eq!(
        first_bound.unsigned_transaction().serialize(),
        second_bound.unsigned_transaction().serialize(),
    );
    assert_ne!(
        first_bound.proof_verified_preview().preprocess_set_digest(),
        second_bound.proof_verified_preview().preprocess_set_digest(),
        "authorization must certify the exact selected preprocess set, not only aggregate key images",
    );
}

#[test]
fn bind_rejects_arbitrary_key_image_share_and_each_proof_field_before_authorization() {
    let keys = threshold_keys();
    let transaction = multi_input_signable_transaction(&keys[0]);
    let fields = [
        PreprocessProofField::KeyImageShare,
        PreprocessProofField::CommitmentG,
        PreprocessProofField::CommitmentH,
        PreprocessProofField::Response,
    ];

    for (case, field) in fields.into_iter().enumerate() {
        let seed = 80_u8 + u8::try_from(case * 2).unwrap();
        let session = SessionId([seed; 32]);
        let (first_state, _, _, third_preprocess) =
            start_bound_pair(&transaction, &keys, [0, 2], session, seed);
        let mut malicious = third_preprocess.message().as_bytes().to_vec();
        tamper_preprocess_field(&mut malicious, 2, 1, field);
        let malicious = replace_bound_preprocess_bytes(third_preprocess, malicious);
        let result = first_state.bind_transaction_bound([(PARTIES[2], malicious)]);
        assert!(matches!(
            result,
            Err(SigningError::InvalidPreprocess { party }) if party == PARTIES[2]
        ));
    }
}

#[test]
fn malformed_key_image_proof_encodings_are_rejected_before_authorization() {
    let keys = threshold_keys();
    let transaction = multi_input_signable_transaction(&keys[0]);
    let mut noncanonical_point = [0xff; 32];
    // y = p + 1 is a non-canonical encoding of the identity point.
    noncanonical_point[0] = 0xee;
    noncanonical_point[31] = 0x7f;
    let malformed = [
        (PreprocessProofField::CommitmentG, EIGHT_TORSION[1].compress().to_bytes()),
        (PreprocessProofField::CommitmentH, noncanonical_point),
        (PreprocessProofField::Response, NONCANONICAL_SCALAR_ENCODING),
    ];

    for (case, (field, replacement)) in malformed.into_iter().enumerate() {
        let seed = 101_u8 + u8::try_from(case * 2).unwrap();
        let (first_state, _, _, third_preprocess) =
            start_bound_pair(&transaction, &keys, [0, 2], SessionId([seed; 32]), seed);
        let mut malicious = third_preprocess.message().as_bytes().to_vec();
        replace_preprocess_field(&mut malicious, 2, 0, field, replacement);
        let malicious = replace_bound_preprocess_bytes(third_preprocess, malicious);
        let result = first_state.bind_transaction_bound([(PARTIES[2], malicious)]);
        assert!(matches!(
            result,
            Err(SigningError::MalformedMessage {
                party,
                kind: SigningMessageKind::Preprocess,
                ..
            }) if party == PARTIES[2]
        ));
    }
}

#[test]
fn canonical_identity_proof_commitments_are_rejected_before_authorization() {
    let keys = threshold_keys();
    let transaction = multi_input_signable_transaction(&keys[0]);
    let identity = EdwardsPoint::identity().compress().to_bytes();

    for (case, field) in [PreprocessProofField::CommitmentG, PreprocessProofField::CommitmentH]
        .into_iter()
        .enumerate()
    {
        let seed = 121_u8 + u8::try_from(case * 2).unwrap();
        let (first_state, _, _, third_preprocess) =
            start_bound_pair(&transaction, &keys, [0, 2], SessionId([seed; 32]), seed);
        let mut malicious = third_preprocess.message().as_bytes().to_vec();
        replace_preprocess_field(&mut malicious, 2, 0, field, identity);
        let malicious = replace_bound_preprocess_bytes(third_preprocess, malicious);
        let result = first_state.bind_transaction_bound([(PARTIES[2], malicious)]);
        assert!(matches!(
            result,
            Err(SigningError::InvalidPreprocess { party }) if party == PARTIES[2]
        ));
    }
}

#[test]
fn typed_bind_revalidates_proof_context_participant_and_input_order() {
    let keys = threshold_keys();
    let transaction = multi_input_signable_transaction(&keys[0]);
    let reversed_transaction = signable_transaction_with_input_order(&keys[0], 100_000, &[0, 1]);
    let context = [91; 32];
    let peer = Participant::new(3).unwrap();

    let mut tampered_key_image = direct_preprocess_bytes(&transaction, &keys[2], context, 92);
    tamper_preprocess_field(&mut tampered_key_image, 2, 0, PreprocessProofField::KeyImageShare);
    assert_eq!(
        direct_bind_error(&transaction, &keys[0], context, peer, &tampered_key_image, 93),
        FrostError::InvalidPreprocess(peer),
    );

    let wrong_context = direct_preprocess_bytes(&transaction, &keys[2], [94; 32], 95);
    assert_eq!(
        direct_bind_error(&transaction, &keys[0], context, peer, &wrong_context, 96),
        FrostError::InvalidPreprocess(peer),
    );

    let participant_two = Participant::new(2).unwrap();
    let wrong_participant = direct_preprocess_bytes(&transaction, &keys[1], context, 97);
    assert_eq!(
        direct_bind_error(&transaction, &keys[0], context, peer, &wrong_participant, 98),
        FrostError::InvalidPreprocess(peer),
    );
    assert_ne!(participant_two, peer);

    let wrong_input_order = direct_preprocess_bytes(&reversed_transaction, &keys[2], context, 99);
    assert_eq!(
        direct_bind_error(&transaction, &keys[0], context, peer, &wrong_input_order, 100),
        FrostError::InvalidPreprocess(peer),
    );

    // A malformed local secret/public pair creates an invalid local xG/xH proof. The typed binding
    // API must validate it too, rather than checking only received peer preprocesses.
    let malformed_local = malformed_keys(Participant::new(1).unwrap(), true, false);
    let honest_peer = direct_preprocess_bytes(&transaction, &keys[2], context, 107);
    assert_eq!(
        direct_bind_error(&transaction, &malformed_local, context, peer, &honest_peer, 108),
        FrostError::InvalidPreprocess(Participant::new(1).unwrap()),
    );
}

#[test]
fn session_bound_context_commits_to_session_intent_and_signer_set() {
    let committee = committee();
    let keys = threshold_keys();
    let transaction = signable_transaction(&keys[0]);
    let different_transaction = signable_transaction_with_first_payment(&keys[0], 100_001);
    let group_key = threshold_group_key(&keys[0]);
    let first_set =
        CanonicalSignerSet::new(&committee, PARTIES[0], [PARTIES[0], PARTIES[2]]).unwrap();
    let second_set =
        CanonicalSignerSet::new(&committee, PARTIES[0], [PARTIES[0], PARTIES[1]]).unwrap();
    let first_session = SessionId([41; 32]);
    let second_session = SessionId([42; 32]);

    let context =
        signing_context_in_session(&transaction, &committee, &first_set, group_key, first_session);
    assert_ne!(
        context,
        signing_context_in_session(&transaction, &committee, &first_set, group_key, second_session,)
    );
    assert_ne!(
        context,
        signing_context_in_session(
            &different_transaction,
            &committee,
            &first_set,
            group_key,
            first_session,
        )
    );
    assert_ne!(
        context,
        signing_context_in_session(&transaction, &committee, &second_set, group_key, first_session,)
    );
}

#[test]
fn bound_messages_reject_cross_session_replay_and_sign_successfully() {
    let keys = threshold_keys();
    let transaction = signable_transaction(&keys[0]);
    let first_session = SessionId([51; 32]);
    let second_session = SessionId([52; 32]);

    let (first_state, _, _, _) = start_two_bound(&transaction, &keys, first_session, 50);
    let (_, _, _, wrong_preprocess) = start_two_bound(&transaction, &keys, second_session, 52);
    let result = first_state.bind_transaction_bound([(PARTIES[2], wrong_preprocess)]);
    assert!(matches!(
        result,
        Err(SigningError::WrongMessageContext {
            party,
            kind: SigningMessageKind::Preprocess,
        }) if party == PARTIES[2]
    ));

    let (first_state, _, _, _) = start_two_bound(&transaction, &keys, first_session, 54);
    let (_, relabeled_preprocess, _, _) = start_two_bound(&transaction, &keys, first_session, 56);
    let result = first_state.bind_transaction_bound([(PARTIES[2], relabeled_preprocess)]);
    assert!(matches!(
        result,
        Err(SigningError::WrongMessageSender {
            party,
            bound_sender,
            kind: SigningMessageKind::Preprocess,
        }) if party == PARTIES[2] && bound_sender == PARTIES[0]
    ));

    let (first_state, first_preprocess, third_state, third_preprocess) =
        start_two_bound(&transaction, &keys, first_session, 58);
    let (first_final, first_share) = first_state
        .bind_transaction_bound([(PARTIES[2], third_preprocess)])
        .unwrap()
        .release_bound_signature_share()
        .unwrap();
    let (third_final, third_share) = third_state
        .bind_transaction_bound([(PARTIES[0], first_preprocess)])
        .unwrap()
        .release_bound_signature_share()
        .unwrap();
    let first_transaction = first_final.complete_bound([(PARTIES[2], third_share)]).unwrap();
    let third_transaction = third_final.complete_bound([(PARTIES[0], first_share)]).unwrap();
    assert_eq!(first_transaction.serialize(), third_transaction.serialize());

    let (first_state, first_preprocess, third_state, third_preprocess) =
        start_two_bound(&transaction, &keys, first_session, 60);
    let (first_final, relabeled_share) = first_state
        .bind_transaction_bound([(PARTIES[2], third_preprocess)])
        .unwrap()
        .release_bound_signature_share()
        .unwrap();
    let _ = third_state
        .bind_transaction_bound([(PARTIES[0], first_preprocess)])
        .unwrap()
        .release_bound_signature_share()
        .unwrap();
    let result = first_final.complete_bound([(PARTIES[2], relabeled_share)]);
    assert!(matches!(
        result,
        Err(SigningError::WrongMessageSender {
            party,
            bound_sender,
            kind: SigningMessageKind::SignatureShare,
        }) if party == PARTIES[2] && bound_sender == PARTIES[0]
    ));

    let (first_state, _, _, third_preprocess) =
        start_two_bound(&transaction, &keys, first_session, 62);
    let (first_final, _) = first_state
        .bind_transaction_bound([(PARTIES[2], third_preprocess)])
        .unwrap()
        .release_bound_signature_share()
        .unwrap();
    let (_, first_preprocess, third_state, _) =
        start_two_bound(&transaction, &keys, second_session, 64);
    let (_, wrong_share) = third_state
        .bind_transaction_bound([(PARTIES[0], first_preprocess)])
        .unwrap()
        .release_bound_signature_share()
        .unwrap();
    let result = first_final.complete_bound([(PARTIES[2], wrong_share)]);
    assert!(matches!(
        result,
        Err(SigningError::WrongMessageContext {
            party,
            kind: SigningMessageKind::SignatureShare,
        }) if party == PARTIES[2]
    ));

    let different_transaction = signable_transaction_with_first_payment(&keys[0], 100_001);
    let (first_state, _, _, _) = start_two_bound(&transaction, &keys, first_session, 66);
    let (_, _, _, wrong_intent_preprocess) =
        start_two_bound(&different_transaction, &keys, first_session, 68);
    let result = first_state.bind_transaction_bound([(PARTIES[2], wrong_intent_preprocess)]);
    assert!(matches!(
        result,
        Err(SigningError::WrongMessageContext {
            party,
            kind: SigningMessageKind::Preprocess,
        }) if party == PARTIES[2]
    ));
}

#[test]
fn rejects_missing_unexpected_and_malformed_preprocesses() {
    let keys = threshold_keys();
    let transaction = signable_transaction(&keys[0]);

    let (first_state, _, _, _) = start_two_bound(&transaction, &keys, SessionId([20; 32]), 20);
    let missing = first_state.bind_transaction_bound([]);
    assert!(matches!(
        missing,
        Err(SigningError::MissingMessage {
            party,
            kind: SigningMessageKind::Preprocess,
        }) if party == PARTIES[2]
    ));

    let (first_state, _, _, third_preprocess) =
        start_two_bound(&transaction, &keys, SessionId([22; 32]), 22);
    let unexpected = first_state.bind_transaction_bound([(PARTIES[1], third_preprocess)]);
    assert!(matches!(
        unexpected,
        Err(SigningError::UnexpectedMessage {
            party,
            kind: SigningMessageKind::Preprocess,
        }) if party == PARTIES[1]
    ));

    let (first_state, _, _, third_preprocess) =
        start_two_bound(&transaction, &keys, SessionId([24; 32]), 24);
    let mut truncated = third_preprocess.message().as_bytes().to_vec();
    truncated.pop();
    let truncated = replace_bound_preprocess_bytes(third_preprocess, truncated);
    let malformed = first_state.bind_transaction_bound([(PARTIES[2], truncated)]);
    assert!(matches!(
        malformed,
        Err(SigningError::WrongMessageLength {
            party,
            kind: SigningMessageKind::Preprocess,
            ..
        }) if party == PARTIES[2]
    ));

    let (first_state, _, _, third_preprocess) =
        start_two_bound(&transaction, &keys, SessionId([25; 32]), 25);
    let malformed = vec![0; third_preprocess.message().as_bytes().len()];
    let malformed = replace_bound_preprocess_bytes(third_preprocess, malformed);
    let result = first_state.bind_transaction_bound([(PARTIES[2], malformed)]);
    assert!(matches!(
        result,
        Err(SigningError::MalformedMessage {
            party,
            kind: SigningMessageKind::Preprocess,
            ..
        }) if party == PARTIES[2]
    ));

    let (first_state, _, _, third_preprocess) =
        start_two_bound(&transaction, &keys, SessionId([26; 32]), 26);
    let mut trailing = third_preprocess.message().as_bytes().to_vec();
    trailing.push(0);
    let trailing = replace_bound_preprocess_bytes(third_preprocess, trailing);
    let result = first_state.bind_transaction_bound([(PARTIES[2], trailing)]);
    assert!(matches!(
        result,
        Err(SigningError::WrongMessageLength {
            party,
            kind: SigningMessageKind::Preprocess,
            ..
        }) if party == PARTIES[2]
    ));

    let (first_state, _, _, third_preprocess) =
        start_two_bound(&transaction, &keys, SessionId([27; 32]), 27);
    let duplicate = first_state.bind_transaction_bound([
        (PARTIES[2], third_preprocess.clone()),
        (PARTIES[2], third_preprocess),
    ]);
    assert!(matches!(
        duplicate,
        Err(SigningError::DuplicateMessage {
            party,
            kind: SigningMessageKind::Preprocess,
        }) if party == PARTIES[2]
    ));

    let (_, _, _, third_preprocess) = start_two_bound(&transaction, &keys, SessionId([28; 32]), 28);
    let mut oversized = serde_json::to_value(third_preprocess).unwrap();
    oversized["message"] = serde_json::to_value(vec![0; MAX_FROSTLASS_MESSAGE_BYTES + 1]).unwrap();
    assert!(serde_json::from_value::<BoundPreprocessMessage>(oversized).is_err());
}

#[test]
fn rejects_malformed_or_invalid_signature_shares() {
    let keys = threshold_keys();
    let transaction = signable_transaction(&keys[0]);

    let (first_final, third_share) = first_final_and_third_share(&transaction, &keys, 31);
    let mut truncated = third_share.message().as_bytes().to_vec();
    truncated.pop();
    let truncated = replace_bound_share_bytes(third_share, truncated);
    let result = first_final.complete_bound([(PARTIES[2], truncated)]);
    assert!(matches!(
        result,
        Err(SigningError::WrongMessageLength {
            party,
            kind: SigningMessageKind::SignatureShare,
            ..
        }) if party == PARTIES[2]
    ));

    let (first_final, third_share) = first_final_and_third_share(&transaction, &keys, 33);
    let mut trailing = third_share.message().as_bytes().to_vec();
    trailing.push(0);
    let trailing = replace_bound_share_bytes(third_share, trailing);
    let result = first_final.complete_bound([(PARTIES[2], trailing)]);
    assert!(matches!(
        result,
        Err(SigningError::WrongMessageLength {
            party,
            kind: SigningMessageKind::SignatureShare,
            ..
        }) if party == PARTIES[2]
    ));

    let (first_final, third_share) = first_final_and_third_share(&transaction, &keys, 35);
    let malformed = vec![0xff; third_share.message().as_bytes().len()];
    let malformed = replace_bound_share_bytes(third_share, malformed);
    let result = first_final.complete_bound([(PARTIES[2], malformed)]);
    assert!(matches!(
        result,
        Err(SigningError::MalformedMessage {
            party,
            kind: SigningMessageKind::SignatureShare,
            ..
        }) if party == PARTIES[2]
    ));

    let (first_final, third_share) = first_final_and_third_share(&transaction, &keys, 37);
    let invalid = vec![0; third_share.message().as_bytes().len()];
    let invalid = replace_bound_share_bytes(third_share, invalid);
    let result = first_final.complete_bound([(PARTIES[2], invalid)]);
    assert!(matches!(
        result,
        Err(SigningError::InvalidSignatureShare { party }) if party == PARTIES[2]
    ));

    let (first_final, third_share) = first_final_and_third_share(&transaction, &keys, 39);
    let duplicate =
        first_final.complete_bound([(PARTIES[2], third_share.clone()), (PARTIES[2], third_share)]);
    assert!(matches!(
        duplicate,
        Err(SigningError::DuplicateMessage {
            party,
            kind: SigningMessageKind::SignatureShare,
        }) if party == PARTIES[2]
    ));
}
