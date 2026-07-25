use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::{EdwardsPoint, Scalar};
use dkg::Participant;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use threshold_monero::keys::{
    DealerOutput, EpochPublic, EpochShare, EpochShareMaterial, KeyError, PointBytes,
    PolynomialCommitment, ScalarBytes, SecretPolynomial, aggregate_dkg, aggregate_dkg_subset,
    aggregate_proactive_reshare, aggregate_proactive_reshare_from_public, aggregate_reshare,
    aggregate_reshare_from_public, aggregate_zero_share_refresh, lagrange_for_party_at_zero,
    make_dkg_output, make_proactive_reshare_polynomial, make_reshare_polynomial,
    make_zero_share_refresh_polynomial, scalar_for_party,
};

type ReshareCase<'a> = (u16, &'a [u16], &'a [u16], u16, &'a [u16]);
use threshold_monero::{Committee, Member, PartyId, committee::CommitteeError};

fn member(id: u16) -> Member {
    let mut signing_key = [0_u8; 32];
    signing_key[..2].copy_from_slice(&id.to_le_bytes());
    signing_key[31] = 1;
    let mut encryption_key = [0_u8; 32];
    encryption_key[..2].copy_from_slice(&id.to_le_bytes());
    encryption_key[31] = 2;
    Member { id: PartyId(id), signing_key, encryption_key }
}

fn committee(epoch: u64, threshold: u16, ids_in_noncanonical_order: &[u16]) -> Committee {
    let committee = Committee {
        epoch,
        threshold,
        members: ids_in_noncanonical_order.iter().copied().map(member).collect(),
    };
    committee.validate().unwrap();
    committee
}

fn seeded_rng(domain: u8, epoch: u64, party: PartyId) -> ChaCha20Rng {
    let mut seed = [0_u8; 32];
    seed[0] = domain;
    seed[1..9].copy_from_slice(&epoch.to_le_bytes());
    seed[9..11].copy_from_slice(&party.0.to_le_bytes());
    ChaCha20Rng::from_seed(seed)
}

fn dkg_all(committee: &Committee, domain: u8) -> BTreeMap<PartyId, EpochShare> {
    let polynomials = committee
        .members
        .iter()
        .map(|dealer| {
            let mut rng = seeded_rng(domain, committee.epoch, dealer.id);
            (dealer.id, SecretPolynomial::random(committee.threshold, &mut rng).unwrap())
        })
        .collect::<BTreeMap<_, _>>();

    committee
        .members
        .iter()
        .map(|recipient| {
            let outputs = polynomials
                .iter()
                .map(|(dealer, polynomial)| {
                    make_dkg_output(*dealer, polynomial, committee, recipient.id).unwrap()
                })
                .collect();
            (
                recipient.id,
                aggregate_dkg([domain; 32], committee.clone(), recipient.id, outputs).unwrap(),
            )
        })
        .collect()
}

fn reshare_all(
    old: &BTreeMap<PartyId, EpochShare>,
    new_committee: &Committee,
    selected: &[PartyId],
    domain: u8,
) -> BTreeMap<PartyId, EpochShare> {
    let polynomials = selected
        .iter()
        .copied()
        .map(|dealer| {
            let mut rng = seeded_rng(domain, new_committee.epoch, dealer);
            (
                dealer,
                make_reshare_polynomial(
                    &old[&dealer],
                    dealer,
                    selected,
                    new_committee.threshold,
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    new_committee
        .members
        .iter()
        .map(|recipient| {
            let outputs = polynomials
                .iter()
                .map(|(dealer, polynomial)| {
                    make_dkg_output(*dealer, polynomial, new_committee, recipient.id).unwrap()
                })
                .collect();
            (
                recipient.id,
                aggregate_reshare(
                    old.values().next().unwrap(),
                    new_committee.clone(),
                    recipient.id,
                    selected,
                    outputs,
                )
                .unwrap(),
            )
        })
        .collect()
}

fn proactive_reshare_all_with_commitment(
    old: &BTreeMap<PartyId, EpochShare>,
    new_committee: &Committee,
    selected: &[PartyId],
    domain: u8,
) -> (BTreeMap<PartyId, EpochShare>, PolynomialCommitment) {
    let old_public = old.values().next().unwrap().public();
    let polynomials = selected
        .iter()
        .copied()
        .map(|dealer| {
            let mut rng = seeded_rng(domain, new_committee.epoch, dealer);
            (
                dealer,
                make_proactive_reshare_polynomial(
                    &old[&dealer],
                    dealer,
                    new_committee.threshold,
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut coefficients = vec![EdwardsPoint::default(); usize::from(new_committee.threshold)];
    for dealer in selected {
        let lambda = lagrange_for_party_at_zero(&old_public.committee, *dealer, selected).unwrap();
        for (aggregate, coefficient) in
            coefficients.iter_mut().zip(polynomials[dealer].commitment().coefficients)
        {
            *aggregate += coefficient.parse().unwrap() * lambda;
        }
    }
    let commitment = PolynomialCommitment {
        coefficients: coefficients.into_iter().map(PointBytes::from).collect(),
    };

    let shares = new_committee
        .members
        .iter()
        .map(|recipient| {
            let outputs = selected
                .iter()
                .map(|dealer| {
                    make_dkg_output(*dealer, &polynomials[dealer], new_committee, recipient.id)
                        .unwrap()
                })
                .collect();
            (
                recipient.id,
                aggregate_proactive_reshare_from_public(
                    &old_public,
                    new_committee.clone(),
                    recipient.id,
                    selected,
                    outputs,
                )
                .unwrap(),
            )
        })
        .collect();

    (shares, commitment)
}

fn zero_share_refresh_all(
    old: &BTreeMap<PartyId, EpochShare>,
    new_committee: &Committee,
    fault_bound: u16,
    selected: &[PartyId],
    domain: u8,
) -> BTreeMap<PartyId, EpochShare> {
    let polynomials = selected
        .iter()
        .copied()
        .map(|dealer| {
            let mut rng = seeded_rng(domain, new_committee.epoch, dealer);
            (
                dealer,
                make_zero_share_refresh_polynomial(
                    &old[&dealer],
                    dealer,
                    new_committee,
                    fault_bound,
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert!(polynomials.values().all(|polynomial| polynomial.constant() == Scalar::ZERO));

    new_committee
        .members
        .iter()
        .map(|recipient| {
            let outputs = selected
                .iter()
                .map(|dealer| {
                    make_dkg_output(*dealer, &polynomials[dealer], new_committee, recipient.id)
                        .unwrap()
                })
                .collect();
            (
                recipient.id,
                aggregate_zero_share_refresh(
                    &old[&recipient.id],
                    new_committee.clone(),
                    recipient.id,
                    fault_bound,
                    selected,
                    outputs,
                )
                .unwrap(),
            )
        })
        .collect()
}

fn threshold_subsets(parties: &[PartyId], threshold: usize) -> Vec<Vec<PartyId>> {
    assert!(parties.len() < usize::BITS as usize);
    (0_usize..(1_usize << parties.len()))
        .filter(|mask| mask.count_ones() as usize == threshold)
        .map(|mask| {
            parties
                .iter()
                .copied()
                .enumerate()
                .filter_map(|(index, party)| ((mask & (1 << index)) != 0).then_some(party))
                .collect()
        })
        .collect()
}

#[test]
fn sparse_party_ids_become_dense_epoch_local_frost_indices() {
    let committee = committee(7, 3, &[60_000, 90, 4_000, 7]);
    let shares = dkg_all(&committee, 11);
    let expected_group = shares[&PartyId(7)].group_key_bytes();
    let expected_order = [PartyId(7), PartyId(90), PartyId(4_000), PartyId(60_000)];

    for (expected_zero_based, party) in expected_order.iter().copied().enumerate() {
        let share = &shares[&party];
        share.validate().unwrap();
        let keys = share.to_threshold_keys().unwrap();
        let expected_index = u16::try_from(expected_zero_based + 1).unwrap();
        assert_eq!(u16::from(keys.params().i()), expected_index);
        assert_eq!(keys.params().t(), 3);
        assert_eq!(keys.params().n(), 4);
        assert_eq!(keys.group_key().0.compress().to_bytes(), expected_group);

        for (index, mapped_party) in expected_order.iter().copied().enumerate() {
            let participant = Participant::new(u16::try_from(index + 1).unwrap()).unwrap();
            assert_eq!(
                keys.original_verification_share(participant).0.compress().to_bytes(),
                share.verification_share(mapped_party).unwrap().compress().to_bytes(),
            );
        }
    }
}

#[test]
fn reshare_supports_arbitrary_old_and_new_thresholds() {
    let cases: &[ReshareCase<'_>] = &[
        (1, &[71, 13, 400], &[71], 4, &[900, 71, 8, 500, 42]),
        (2, &[99, 3, 55, 21], &[3, 55], 1, &[700, 21]),
        (4, &[81, 5, 65, 25, 45], &[5, 25, 65, 81], 5, &[6, 26, 46, 66, 86, 106]),
        (5, &[101, 1, 81, 21, 61], &[1, 21, 61, 81, 101], 2, &[2, 62, 102]),
    ];

    for (case, (old_threshold, old_ids, selected_ids, new_threshold, new_ids)) in
        cases.iter().enumerate()
    {
        let old_committee = committee(20 + case as u64, *old_threshold, old_ids);
        let old = dkg_all(&old_committee, u8::try_from(20 + case).unwrap());
        let old_group = old.values().next().unwrap().group_key().unwrap();
        let selected = selected_ids.iter().copied().map(PartyId).collect::<Vec<_>>();

        let lambda_sum = selected.iter().try_fold(Scalar::ZERO, |sum, dealer| {
            Ok::<_, KeyError>(sum + lagrange_for_party_at_zero(&old_committee, *dealer, &selected)?)
        });
        assert_eq!(lambda_sum.unwrap(), Scalar::ONE);
        let reconstructed_group = selected
            .iter()
            .map(|dealer| {
                old[dealer].verification_share(*dealer).unwrap()
                    * lagrange_for_party_at_zero(&old_committee, *dealer, &selected).unwrap()
            })
            .sum::<EdwardsPoint>();
        assert_eq!(reconstructed_group, old_group);

        let new_committee = committee(old_committee.epoch + 1, *new_threshold, new_ids);
        let reshared =
            reshare_all(&old, &new_committee, &selected, u8::try_from(80 + case).unwrap());
        let activation_digests = reshared
            .values()
            .map(|share| share.activation_digest().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(activation_digests.len(), 1);
        for share in reshared.values() {
            share.validate().unwrap();
            assert_eq!(share.group_key().unwrap(), old_group);
            assert_eq!(
                share.to_threshold_keys().unwrap().group_key().0.compress().to_bytes(),
                old_group.compress().to_bytes(),
            );
        }

        let new_parties = new_committee.members.iter().map(|member| member.id).collect::<Vec<_>>();
        for subset in threshold_subsets(&new_parties, usize::from(new_committee.threshold)) {
            let participants = subset
                .iter()
                .map(|party| Participant::new(new_committee.frost_index(*party).unwrap()).unwrap())
                .collect::<Vec<_>>();
            for local in &subset {
                let keys = reshared[local].to_threshold_keys().unwrap();
                let view = keys.view(participants.clone()).unwrap();
                let reconstructed = participants
                    .iter()
                    .map(|participant| view.verification_share(*participant))
                    .reduce(|sum, share| sum + share)
                    .unwrap();
                assert_eq!(reconstructed, view.group_key());
                assert_eq!(
                    view.group_key().0.compress().to_bytes(),
                    old_group.compress().to_bytes()
                );
            }
        }
    }
}

#[test]
fn reshare_requires_exactly_old_threshold_distinct_selected_dealers() {
    let old_committee = committee(0, 3, &[50, 10, 40, 20, 30]);
    let old = dkg_all(&old_committee, 31);
    let verifier = old.values().next().unwrap();
    let new_committee = committee(1, 4, &[15, 25, 35, 45, 55, 65]);

    for (selected, expected) in [
        (
            vec![PartyId(10), PartyId(30)],
            KeyError::WrongReshareDealerCount { expected: 3, actual: 2 },
        ),
        (
            vec![PartyId(10), PartyId(20), PartyId(30), PartyId(40)],
            KeyError::WrongReshareDealerCount { expected: 3, actual: 4 },
        ),
        (vec![PartyId(10), PartyId(10), PartyId(30)], KeyError::DuplicateDealer(PartyId(10))),
        (vec![PartyId(30), PartyId(20), PartyId(10)], KeyError::NonCanonicalDealerSet),
        (vec![PartyId(10), PartyId(30), PartyId(999)], KeyError::IneligibleDealer(PartyId(999))),
    ] {
        assert_eq!(
            aggregate_reshare(verifier, new_committee.clone(), PartyId(15), &selected, vec![],)
                .unwrap_err(),
            expected,
        );
    }
}

#[test]
fn reshare_rejects_missing_unselected_invalid_and_unbound_dealer_outputs() {
    let old_committee = committee(0, 3, &[50, 10, 40, 20, 30]);
    let old = dkg_all(&old_committee, 41);
    let old_group = old.values().next().unwrap().group_key_bytes();
    let selected = [PartyId(10), PartyId(30), PartyId(50)];
    let new_committee = committee(1, 4, &[15, 25, 35, 45, 55, 65]);
    let recipient = PartyId(15);

    let polynomials = selected
        .iter()
        .copied()
        .map(|dealer| {
            let mut rng = seeded_rng(42, new_committee.epoch, dealer);
            (
                dealer,
                make_reshare_polynomial(
                    &old[&dealer],
                    dealer,
                    &selected,
                    new_committee.threshold,
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let valid_outputs = || {
        polynomials
            .iter()
            .map(|(dealer, polynomial)| {
                make_dkg_output(*dealer, polynomial, &new_committee, recipient).unwrap()
            })
            .collect::<Vec<_>>()
    };

    let missing =
        valid_outputs().into_iter().filter(|output| output.dealer != PartyId(30)).collect();
    assert_eq!(
        aggregate_reshare(
            old.values().next().unwrap(),
            new_committee.clone(),
            recipient,
            &selected,
            missing,
        )
        .unwrap_err(),
        KeyError::MissingDealer(PartyId(30)),
    );

    let mut unselected = valid_outputs();
    let mut unselected_output = unselected[0].clone();
    unselected_output.dealer = PartyId(20);
    unselected.insert(0, unselected_output);
    assert_eq!(
        aggregate_reshare(
            old.values().next().unwrap(),
            new_committee.clone(),
            recipient,
            &selected,
            unselected,
        )
        .unwrap_err(),
        KeyError::IneligibleDealer(PartyId(20)),
    );

    let mut invalid_share = valid_outputs();
    let bad_dealer = invalid_share[0].dealer;
    let scalar = invalid_share[0].share.parse().unwrap() + Scalar::ONE;
    invalid_share[0].share = ScalarBytes::from(scalar);
    assert_eq!(
        aggregate_reshare(
            old.values().next().unwrap(),
            new_committee.clone(),
            recipient,
            &selected,
            invalid_share,
        )
        .unwrap_err(),
        KeyError::InvalidDealerShare(bad_dealer),
    );

    let unbound_dealer = selected[0];
    let lambda = lagrange_for_party_at_zero(&old_committee, unbound_dealer, &selected).unwrap();
    let wrong_constant = (lambda * old[&unbound_dealer].secret_share()) + Scalar::ONE;
    let mut rng = seeded_rng(43, new_committee.epoch, unbound_dealer);
    let unbound =
        SecretPolynomial::random_with_constant(new_committee.threshold, wrong_constant, &mut rng)
            .unwrap();
    let mut unbound_outputs = valid_outputs();
    *unbound_outputs.iter_mut().find(|output| output.dealer == unbound_dealer).unwrap() =
        make_dkg_output(unbound_dealer, &unbound, &new_committee, recipient).unwrap();
    assert_eq!(
        aggregate_reshare(
            old.values().next().unwrap(),
            new_committee.clone(),
            recipient,
            &selected,
            unbound_outputs,
        )
        .unwrap_err(),
        KeyError::UnboundReshareDealer(unbound_dealer),
    );

    let final_outputs = valid_outputs();
    let valid = aggregate_reshare(
        old.values().next().unwrap(),
        new_committee,
        recipient,
        &selected,
        final_outputs,
    )
    .unwrap();
    assert_eq!(valid.group_key_bytes(), old_group);
}

#[test]
fn material_validation_rejects_secret_public_and_membership_tampering() {
    let committee = committee(9, 2, &[50, 10, 40, 20, 30]);
    let shares = dkg_all(&committee, 51);
    let original = &shares[&PartyId(30)];

    let mut wrong_secret = original.material();
    wrong_secret.secret_share = ScalarBytes::from(original.secret_share() + Scalar::ONE);
    assert_eq!(EpochShare::from_material(wrong_secret).unwrap_err(), KeyError::LocalShareMismatch,);

    let mut wrong_membership = original.material();
    let displaced = wrong_membership.verification_shares.remove(&PartyId(50)).unwrap();
    wrong_membership.verification_shares.insert(PartyId(999), displaced);
    assert_eq!(
        EpochShare::from_material(wrong_membership).unwrap_err(),
        KeyError::InconsistentVerificationShares,
    );

    // Party 50 has dense index 5 and is outside the first-two-share interpolation basis. This
    // specifically exercises the all-public-shares polynomial consistency check.
    let mut inconsistent_public = original.material();
    let changed = inconsistent_public.verification_shares[&PartyId(50)].parse().unwrap()
        + EdwardsPoint::mul_base(&Scalar::ONE);
    inconsistent_public.verification_shares.insert(PartyId(50), PointBytes::from(changed));
    assert_eq!(
        EpochShare::from_material(inconsistent_public).unwrap_err(),
        KeyError::InconsistentVerificationShares,
    );

    let mut wrong_group = original.material();
    wrong_group.group_key =
        PointBytes::from(original.group_key().unwrap() + EdwardsPoint::mul_base(&Scalar::ONE));
    assert_eq!(EpochShare::from_material(wrong_group).unwrap_err(), KeyError::GroupKeyMismatch,);
}

#[test]
fn each_reshare_constant_is_lagrange_bound_and_sums_to_the_old_group_key() {
    let old_committee = committee(3, 4, &[91, 11, 71, 31, 51, 21]);
    let old = dkg_all(&old_committee, 61);
    let selected = [PartyId(11), PartyId(31), PartyId(71), PartyId(91)];
    let old_group = old.values().next().unwrap().group_key().unwrap();
    let mut summed_constants = EdwardsPoint::default();

    for dealer in selected {
        let mut rng = seeded_rng(62, 4, dealer);
        let polynomial =
            make_reshare_polynomial(&old[&dealer], dealer, &selected, 2, &mut rng).unwrap();
        let constant_point = EdwardsPoint::mul_base(&polynomial.constant());
        let lambda = lagrange_for_party_at_zero(&old_committee, dealer, &selected).unwrap();
        assert_eq!(constant_point, old[&dealer].verification_share(dealer).unwrap() * lambda);
        summed_constants += constant_point;
    }

    assert_eq!(summed_constants, old_group);
}

#[test]
fn malformed_scalar_is_rejected_before_material_is_accepted() {
    let committee = committee(0, 2, &[1, 2, 3]);
    let shares = dkg_all(&committee, 71);
    let mut material = shares[&PartyId(1)].material();
    material.secret_share = ScalarBytes([0xff; 32]);
    assert_eq!(EpochShare::from_material(material).unwrap_err(), KeyError::InvalidScalar);
}

#[test]
fn material_rejects_a_lower_effective_degree_than_the_declared_threshold() {
    let committee = committee(12, 3, &[30, 10, 50, 20, 40]);
    let constant = Scalar::from(5_u64);
    let slope = Scalar::from(7_u64);
    let local_party = PartyId(30);
    let verification_shares = committee
        .members
        .iter()
        .map(|member| {
            let x = Scalar::from(u64::from(committee.frost_index(member.id).unwrap()));
            (member.id, PointBytes::from(EdwardsPoint::mul_base(&(constant + (slope * x)))))
        })
        .collect();
    let local_x = Scalar::from(u64::from(committee.frost_index(local_party).unwrap()));
    let material = EpochShareMaterial {
        key_id: [12; 32],
        committee,
        local_party,
        secret_share: ScalarBytes::from(constant + (slope * local_x)),
        verification_shares,
        group_key: PointBytes::from(EdwardsPoint::mul_base(&constant)),
    };

    assert_eq!(
        EpochShare::from_material(material).unwrap_err(),
        KeyError::DegenerateSharingPolynomial,
    );
}

#[test]
fn material_rejects_a_publicly_known_zero_share() {
    let committee = committee(13, 2, &[30, 10, 20]);
    // f(x) = x - 1 has a non-zero group secret and exact degree one, but f(1) = 0 exposes one
    // complete share publicly and lowers the effective corruption threshold.
    let constant = -Scalar::ONE;
    let local_party = PartyId(20);
    let verification_shares = committee
        .members
        .iter()
        .map(|member| {
            let x = Scalar::from(u64::from(committee.frost_index(member.id).unwrap()));
            (member.id, PointBytes::from(EdwardsPoint::mul_base(&(constant + x))))
        })
        .collect();
    let local_x = Scalar::from(u64::from(committee.frost_index(local_party).unwrap()));
    let material = EpochShareMaterial {
        key_id: [13; 32],
        committee,
        local_party,
        secret_share: ScalarBytes::from(constant + local_x),
        verification_shares,
        group_key: PointBytes::from(EdwardsPoint::mul_base(&constant)),
    };

    assert_eq!(
        EpochShare::from_material(material).unwrap_err(),
        KeyError::IdentityVerificationShare(PartyId(10)),
    );
}

#[test]
fn reshare_rejects_stale_skipped_and_exhausted_epochs() {
    let old_committee = committee(8, 2, &[10, 20, 30]);
    let old = dkg_all(&old_committee, 81);
    let selected = [PartyId(10), PartyId(30)];

    for new_epoch in [7, 8, 10] {
        let new_committee = committee(new_epoch, 2, &[40, 50, 60]);
        assert_eq!(
            aggregate_reshare(
                old.values().next().unwrap(),
                new_committee,
                PartyId(40),
                &selected,
                vec![],
            )
            .unwrap_err(),
            KeyError::InvalidEpochTransition { old: 8, new: new_epoch },
        );
    }

    let final_committee = committee(u64::MAX, 1, &[10]);
    let final_share = dkg_all(&final_committee, 82);
    let impossible_successor = committee(0, 1, &[20]);
    assert_eq!(
        aggregate_reshare(
            final_share.values().next().unwrap(),
            impossible_successor,
            PartyId(20),
            &[PartyId(10)],
            vec![],
        )
        .unwrap_err(),
        KeyError::EpochExhausted,
    );
}

#[test]
fn noncanonical_edwards_encodings_are_rejected() {
    let mut modulus_plus_one_identity = [0xff; 32];
    modulus_plus_one_identity[0] = 0xee;
    modulus_plus_one_identity[31] = 0x7f;
    assert_eq!(PointBytes(modulus_plus_one_identity).parse().unwrap_err(), KeyError::InvalidPoint,);

    let mut negative_zero_identity = [0_u8; 32];
    negative_zero_identity[0] = 1;
    negative_zero_identity[31] = 0x80;
    assert_eq!(PointBytes(negative_zero_identity).parse().unwrap_err(), KeyError::InvalidPoint,);
}

#[test]
fn activation_digest_detects_same_key_but_equivocated_new_polynomials() {
    let old_committee = committee(0, 2, &[30, 10, 20]);
    let old = dkg_all(&old_committee, 91);
    let selected = [PartyId(10), PartyId(30)];
    let new_committee = committee(1, 2, &[60, 40, 50]);
    let recipient = PartyId(40);

    let mut first = BTreeMap::new();
    let mut second = BTreeMap::new();
    for dealer in selected {
        let lambda = lagrange_for_party_at_zero(&old_committee, dealer, &selected).unwrap();
        let constant = lambda * old[&dealer].secret_share();
        let mut first_rng = seeded_rng(92, new_committee.epoch, dealer);
        let mut second_rng = seeded_rng(93, new_committee.epoch, dealer);
        first.insert(
            dealer,
            SecretPolynomial::random_with_constant(
                new_committee.threshold,
                constant,
                &mut first_rng,
            )
            .unwrap(),
        );
        second.insert(
            dealer,
            SecretPolynomial::random_with_constant(
                new_committee.threshold,
                constant,
                &mut second_rng,
            )
            .unwrap(),
        );
    }

    let outputs = |polynomials: &BTreeMap<PartyId, SecretPolynomial>| {
        polynomials
            .iter()
            .map(|(dealer, polynomial)| {
                make_dkg_output(*dealer, polynomial, &new_committee, recipient).unwrap()
            })
            .collect()
    };
    let left = aggregate_reshare(
        old.values().next().unwrap(),
        new_committee.clone(),
        recipient,
        &selected,
        outputs(&first),
    )
    .unwrap();
    let second_outputs = outputs(&second);
    let right = aggregate_reshare(
        old.values().next().unwrap(),
        new_committee,
        recipient,
        &selected,
        second_outputs,
    )
    .unwrap();

    assert_eq!(left.group_key_bytes(), right.group_key_bytes());
    assert_ne!(left.activation_digest().unwrap(), right.activation_digest().unwrap());
}

#[test]
fn new_only_recipient_aggregates_from_serialized_old_public_metadata() {
    let old_committee = committee(30, 3, &[50, 10, 40, 20, 30]);
    let old = dkg_all(&old_committee, 101);
    let old_public = old.values().next().unwrap().public();
    let serialized = postcard::to_allocvec(&old_public).unwrap();
    let decoded: EpochPublic = postcard::from_bytes(&serialized).unwrap();
    assert_eq!(old_public, decoded);
    old_public.validate().unwrap();

    let selected = [PartyId(10), PartyId(30), PartyId(50)];
    let new_committee = committee(31, 2, &[100, 70, 90, 80]);
    let polynomials = selected
        .iter()
        .copied()
        .map(|dealer| {
            let mut rng = seeded_rng(102, new_committee.epoch, dealer);
            (
                dealer,
                make_reshare_polynomial(
                    &old[&dealer],
                    dealer,
                    &selected,
                    new_committee.threshold,
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    // None of these recipients is in the old committee. They validate old dealer constants from
    // `EpochPublic` and never receive or reconstruct an old secret share.
    let mut digests = BTreeSet::new();
    for recipient in &new_committee.members {
        let outputs = polynomials
            .iter()
            .map(|(dealer, polynomial)| {
                make_dkg_output(*dealer, polynomial, &new_committee, recipient.id).unwrap()
            })
            .collect();
        let share = aggregate_reshare_from_public(
            &decoded,
            new_committee.clone(),
            recipient.id,
            &selected,
            outputs,
        )
        .unwrap();
        assert_eq!(share.group_key_bytes(), old_public.group_key_bytes());
        share.to_threshold_keys().unwrap();
        digests.insert(share.activation_digest().unwrap());
    }
    assert_eq!(digests.len(), 1);
}

#[test]
fn consensus_dkg_subset_excludes_a_silent_dealer_and_requires_the_exact_set() {
    let committee = committee(0, 2, &[40, 10, 30, 20]);
    // n = 4 has f = 1, so the key layer accepts the consensus QUAL only at n-f = 3.
    let selected = [PartyId(10), PartyId(20), PartyId(30)];
    let polynomials = committee
        .members
        .iter()
        .map(|dealer| {
            let mut rng = seeded_rng(111, committee.epoch, dealer.id);
            (dealer.id, SecretPolynomial::random(committee.threshold, &mut rng).unwrap())
        })
        .collect::<BTreeMap<_, _>>();
    let outputs_for = |recipient| {
        selected
            .iter()
            .map(|dealer| {
                make_dkg_output(*dealer, &polynomials[dealer], &committee, recipient).unwrap()
            })
            .collect::<Vec<_>>()
    };

    // Dealer 40 never completes, but every recipient installs the same agreed three-dealer QUAL.
    let shares = committee
        .members
        .iter()
        .map(|recipient| {
            (
                recipient.id,
                aggregate_dkg_subset(
                    [111; 32],
                    committee.clone(),
                    recipient.id,
                    1,
                    &selected,
                    outputs_for(recipient.id),
                )
                .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        shares
            .values()
            .map(|share| share.activation_digest().unwrap())
            .collect::<BTreeSet<_>>()
            .len(),
        1,
    );

    assert_eq!(
        aggregate_dkg_subset(
            [111; 32],
            committee.clone(),
            PartyId(10),
            1,
            &[PartyId(10), PartyId(20)],
            vec![],
        )
        .unwrap_err(),
        KeyError::InsufficientDkgDealers { minimum: 3, actual: 2 },
    );
    assert_eq!(
        aggregate_dkg_subset(
            [111; 32],
            committee.clone(),
            PartyId(10),
            1,
            &[PartyId(20), PartyId(10), PartyId(30)],
            vec![],
        )
        .unwrap_err(),
        KeyError::NonCanonicalDealerSet,
    );
    assert_eq!(
        aggregate_dkg_subset(
            [111; 32],
            committee.clone(),
            PartyId(10),
            1,
            &[PartyId(10), PartyId(20), PartyId(20)],
            vec![],
        )
        .unwrap_err(),
        KeyError::DuplicateDealer(PartyId(20)),
    );
    assert_eq!(
        aggregate_dkg_subset(
            [111; 32],
            committee.clone(),
            PartyId(10),
            1,
            &[PartyId(10), PartyId(20), PartyId(99)],
            vec![],
        )
        .unwrap_err(),
        KeyError::IneligibleDealer(PartyId(99)),
    );

    let missing = outputs_for(PartyId(10))
        .into_iter()
        .filter(|output| output.dealer != PartyId(30))
        .collect();
    assert_eq!(
        aggregate_dkg_subset([111; 32], committee.clone(), PartyId(10), 1, &selected, missing,)
            .unwrap_err(),
        KeyError::MissingDealer(PartyId(30)),
    );

    let mut extra = outputs_for(PartyId(10));
    extra.push(
        make_dkg_output(PartyId(40), &polynomials[&PartyId(40)], &committee, PartyId(10)).unwrap(),
    );
    assert_eq!(
        aggregate_dkg_subset([111; 32], committee.clone(), PartyId(10), 1, &selected, extra,)
            .unwrap_err(),
        KeyError::IneligibleDealer(PartyId(40)),
    );

    let mut malformed = outputs_for(PartyId(10));
    let malformed_dealer = malformed[0].dealer;
    malformed[0].share = ScalarBytes::from(malformed[0].share.parse().unwrap() + Scalar::ONE);
    assert_eq!(
        aggregate_dkg_subset([111; 32], committee, PartyId(10), 1, &selected, malformed,)
            .unwrap_err(),
        KeyError::InvalidDealerShare(malformed_dealer),
    );
}

#[test]
fn dkg_subset_uses_the_protocol_fault_bound_instead_of_the_committee_maximum() {
    // n=7 permits a maximum f=2, but threshold=4 is intentionally configured for f=1:
    // 1 < 4 <= 7-2. The protocol quorum is therefore six, not the five inferred from n alone.
    let committee = committee(1, 4, &[70, 10, 60, 20, 50, 30, 40]);
    let selected = [PartyId(10), PartyId(20), PartyId(30), PartyId(40), PartyId(50), PartyId(60)];
    let polynomials = selected
        .iter()
        .map(|dealer| {
            let mut rng = seeded_rng(112, committee.epoch, *dealer);
            (*dealer, SecretPolynomial::random(committee.threshold, &mut rng).unwrap())
        })
        .collect::<BTreeMap<_, _>>();
    let outputs = selected
        .iter()
        .map(|dealer| {
            make_dkg_output(*dealer, &polynomials[dealer], &committee, PartyId(10)).unwrap()
        })
        .collect();

    aggregate_dkg_subset([112; 32], committee.clone(), PartyId(10), 1, &selected, outputs)
        .unwrap()
        .validate()
        .unwrap();

    assert_eq!(
        aggregate_dkg_subset([112; 32], committee.clone(), PartyId(10), 1, &selected[..5], vec![],)
            .unwrap_err(),
        KeyError::InsufficientDkgDealers { minimum: 6, actual: 5 },
    );
    assert_eq!(
        aggregate_dkg_subset([112; 32], committee, PartyId(10), 2, &selected, vec![],).unwrap_err(),
        KeyError::Committee(CommitteeError::InvalidFaultBound),
    );
}

#[test]
fn proactive_raw_share_dealing_allows_two_availability_subsets_for_the_same_key() {
    let old_committee = committee(40, 3, &[50, 10, 40, 20, 30]);
    let old = dkg_all(&old_committee, 121);
    let old_public = old.values().next().unwrap().public();
    let old_group = old_public.group_key().unwrap();
    let new_committee = committee(41, 2, &[90, 60, 80, 70]);

    // Every old member deals before QUAL selection. Dealer 50 can subsequently be unavailable
    // without blocking the first exact-threshold subset.
    let polynomials = old
        .iter()
        .map(|(dealer, share)| {
            let mut rng = seeded_rng(122, new_committee.epoch, *dealer);
            (
                *dealer,
                make_proactive_reshare_polynomial(
                    share,
                    *dealer,
                    new_committee.threshold,
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(polynomials.len(), old_committee.members.len());
    for (dealer, polynomial) in &polynomials {
        assert_eq!(
            EdwardsPoint::mul_base(&polynomial.constant()),
            old_public.verification_share(*dealer).unwrap(),
        );
    }

    let subsets =
        [[PartyId(10), PartyId(20), PartyId(30)], [PartyId(20), PartyId(40), PartyId(50)]];
    let mut subset_digests = Vec::new();
    for (subset_index, selected) in subsets.iter().enumerate() {
        let mut recipient_digests = BTreeSet::new();
        for recipient in &new_committee.members {
            let outputs = selected
                .iter()
                .map(|dealer| {
                    make_dkg_output(*dealer, &polynomials[dealer], &new_committee, recipient.id)
                        .unwrap()
                })
                .collect();
            let share = if subset_index == 0 && recipient.id == new_committee.members[0].id {
                aggregate_proactive_reshare(
                    old.values().next().unwrap(),
                    new_committee.clone(),
                    recipient.id,
                    selected,
                    outputs,
                )
            } else {
                aggregate_proactive_reshare_from_public(
                    &old_public,
                    new_committee.clone(),
                    recipient.id,
                    selected,
                    outputs,
                )
            }
            .unwrap();
            assert_eq!(share.group_key().unwrap(), old_group);
            share.to_threshold_keys().unwrap();
            recipient_digests.insert(share.activation_digest().unwrap());
        }
        assert_eq!(recipient_digests.len(), 1);
        subset_digests.push(*recipient_digests.first().unwrap());
    }

    // Both legitimate QUAL choices reconstruct p(0), while their refreshed polynomials differ.
    assert_ne!(subset_digests[0], subset_digests[1]);
}

#[test]
fn independently_randomized_refresh_epochs_do_not_form_one_interpolation_polynomial() {
    let initial_committee = committee(60, 3, &[50, 10, 40, 20, 30]);
    let initial = dkg_all(&initial_committee, 141);
    let selected = [PartyId(10), PartyId(20), PartyId(30)];
    let first_committee = committee(61, 3, &[50, 10, 40, 20, 30]);
    let (first, first_commitment) =
        proactive_reshare_all_with_commitment(&initial, &first_committee, &selected, 142);
    let second_committee = committee(62, 3, &[50, 10, 40, 20, 30]);
    let (second, second_commitment) =
        proactive_reshare_all_with_commitment(&first, &second_committee, &selected, 143);
    let group_key = initial.values().next().unwrap().group_key().unwrap();

    assert_eq!(first_commitment.constant().unwrap(), group_key);
    assert_eq!(second_commitment.constant().unwrap(), group_key);
    assert_eq!(first_commitment.coefficients[0], second_commitment.coefficients[0]);
    assert_ne!(first_commitment.coefficients[1..], second_commitment.coefficients[1..]);

    let parties = first_committee.members.iter().map(|member| member.id).collect::<Vec<_>>();
    let reconstruct = |epoch: &BTreeMap<PartyId, EpochShare>, subset: &[PartyId]| {
        subset
            .iter()
            .map(|party| {
                epoch[party].secret_share()
                    * lagrange_for_party_at_zero(&epoch[party].committee, *party, subset).unwrap()
            })
            .sum::<Scalar>()
    };
    for subset in threshold_subsets(&parties, usize::from(first_committee.threshold)) {
        let first_root = reconstruct(&first, &subset);
        let second_root = reconstruct(&second, &subset);
        assert_eq!(EdwardsPoint::mul_base(&first_root), group_key);
        assert_eq!(EdwardsPoint::mul_base(&second_root), group_key);
    }

    for party in &parties {
        let x = scalar_for_party(&first_committee, *party).unwrap();
        assert_eq!(
            first_commitment.evaluate(x).unwrap(),
            first[party].verification_share(*party).unwrap(),
        );
        assert_eq!(
            second_commitment.evaluate(x).unwrap(),
            second[party].verification_share(*party).unwrap(),
        );
    }

    // This fixed mixed subset is a deterministic regression witness, not a proof that every
    // possible cross-epoch subset must fail: fresh random nonconstant coefficients provide that
    // security argument, while an accidental equality remains negligible but mathematically
    // possible. Here the first point comes from epoch 61 and the other two come from epoch 62.
    let mixed_parties = [PartyId(10), PartyId(20), PartyId(30)];
    let mixed_shares = [
        first[&mixed_parties[0]].secret_share(),
        second[&mixed_parties[1]].secret_share(),
        second[&mixed_parties[2]].secret_share(),
    ];
    let mixed_root = mixed_parties
        .iter()
        .zip(mixed_shares)
        .map(|(party, share)| {
            share * lagrange_for_party_at_zero(&first_committee, *party, &mixed_parties).unwrap()
        })
        .sum::<Scalar>();

    assert_ne!(EdwardsPoint::mul_base(&mixed_root), group_key);
    assert_ne!(
        EdwardsPoint::mul_base(&mixed_shares[0]),
        second[&mixed_parties[0]].verification_share(mixed_parties[0]).unwrap(),
    );
    for (party, share) in mixed_parties[1..].iter().zip(&mixed_shares[1..]) {
        assert_ne!(EdwardsPoint::mul_base(share), first[party].verification_share(*party).unwrap(),);
    }
}

#[test]
fn zero_constant_refresh_tolerates_one_silent_dealer_and_rejects_nonzero_contributions() {
    let old_committee = committee(70, 3, &[50, 10, 40, 20, 30]);
    let old = dkg_all(&old_committee, 151);
    let mut new_committee = committee(71, 3, &[50, 10, 40, 20, 30]);
    // Per-epoch transport keys may rotate, while stable signing identities and Shamir coordinates
    // remain fixed.
    for member in &mut new_committee.members {
        member.encryption_key[30] ^= 0x5a;
    }
    new_committee.validate().unwrap();
    let selected = [PartyId(10), PartyId(20), PartyId(30), PartyId(40)];
    let refreshed = zero_share_refresh_all(&old, &new_committee, 1, &selected, 152);
    let group_key = old.values().next().unwrap().group_key().unwrap();
    let activation_digests =
        refreshed.values().map(|share| share.activation_digest().unwrap()).collect::<BTreeSet<_>>();
    assert_eq!(activation_digests.len(), 1);
    assert!(refreshed.values().all(|share| share.group_key().unwrap() == group_key));
    assert_ne!(
        old.values().next().unwrap().public().verification_shares,
        refreshed.values().next().unwrap().public().verification_shares,
    );

    // Party 50 may be Byzantine or silent and is absent from the exact n-f QUAL. If a selected
    // dealer instead tries to smuggle an old-share/nonzero constant into refresh, local
    // certification fails before QUAL can include it.
    let recipient = PartyId(10);
    let mut rng = seeded_rng(153, new_committee.epoch, PartyId(20));
    let nonzero =
        SecretPolynomial::random_with_constant(new_committee.threshold, Scalar::ONE, &mut rng)
            .unwrap();
    let mut outputs = selected
        .iter()
        .map(|dealer| {
            let mut rng = seeded_rng(154, new_committee.epoch, *dealer);
            let polynomial =
                SecretPolynomial::random_zero_constant(new_committee.threshold, &mut rng).unwrap();
            make_dkg_output(*dealer, &polynomial, &new_committee, recipient).unwrap()
        })
        .collect::<Vec<_>>();
    *outputs.iter_mut().find(|output| output.dealer == PartyId(20)).unwrap() =
        make_dkg_output(PartyId(20), &nonzero, &new_committee, recipient).unwrap();
    assert_eq!(
        aggregate_zero_share_refresh(
            &old[&recipient],
            new_committee.clone(),
            recipient,
            1,
            &selected,
            outputs,
        )
        .unwrap_err(),
        KeyError::NonZeroRefreshConstant(PartyId(20)),
    );

    assert_eq!(
        aggregate_zero_share_refresh(
            &old[&recipient],
            new_committee,
            recipient,
            1,
            &selected[..3],
            Vec::new(),
        )
        .unwrap_err(),
        KeyError::WrongRefreshDealerCount { expected: 4, actual: 3 },
    );
}

#[test]
fn proactive_reshare_rejects_subset_mismatch_and_malformed_raw_outputs() {
    let old_committee = committee(50, 3, &[50, 10, 40, 20, 30]);
    let old = dkg_all(&old_committee, 131);
    let old_public = old.values().next().unwrap().public();
    let selected = [PartyId(10), PartyId(20), PartyId(30)];
    let new_committee = committee(51, 2, &[90, 60, 80, 70]);
    let recipient = PartyId(60);
    let polynomials = old
        .iter()
        .map(|(dealer, share)| {
            let mut rng = seeded_rng(132, new_committee.epoch, *dealer);
            (
                *dealer,
                make_proactive_reshare_polynomial(
                    share,
                    *dealer,
                    new_committee.threshold,
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let outputs_for = |dealers: &[PartyId]| {
        dealers
            .iter()
            .map(|dealer| {
                make_dkg_output(*dealer, &polynomials[dealer], &new_committee, recipient).unwrap()
            })
            .collect::<Vec<_>>()
    };

    assert_eq!(
        aggregate_proactive_reshare_from_public(
            &old_public,
            new_committee.clone(),
            recipient,
            &[PartyId(20), PartyId(10), PartyId(30)],
            vec![],
        )
        .unwrap_err(),
        KeyError::NonCanonicalDealerSet,
    );
    assert_eq!(
        aggregate_proactive_reshare_from_public(
            &old_public,
            new_committee.clone(),
            recipient,
            &[PartyId(10), PartyId(20), PartyId(20)],
            vec![],
        )
        .unwrap_err(),
        KeyError::DuplicateDealer(PartyId(20)),
    );
    assert_eq!(
        aggregate_proactive_reshare_from_public(
            &old_public,
            new_committee.clone(),
            recipient,
            &[PartyId(10), PartyId(20)],
            vec![],
        )
        .unwrap_err(),
        KeyError::WrongReshareDealerCount { expected: 3, actual: 2 },
    );

    let missing =
        outputs_for(&selected).into_iter().filter(|output| output.dealer != PartyId(30)).collect();
    assert_eq!(
        aggregate_proactive_reshare_from_public(
            &old_public,
            new_committee.clone(),
            recipient,
            &selected,
            missing,
        )
        .unwrap_err(),
        KeyError::MissingDealer(PartyId(30)),
    );

    let mismatched = outputs_for(&[PartyId(20), PartyId(40), PartyId(50)]);
    assert_eq!(
        aggregate_proactive_reshare_from_public(
            &old_public,
            new_committee.clone(),
            recipient,
            &selected,
            mismatched,
        )
        .unwrap_err(),
        KeyError::IneligibleDealer(PartyId(40)),
    );

    let mut extra = outputs_for(&selected);
    extra.push(
        make_dkg_output(PartyId(40), &polynomials[&PartyId(40)], &new_committee, recipient)
            .unwrap(),
    );
    assert_eq!(
        aggregate_proactive_reshare_from_public(
            &old_public,
            new_committee.clone(),
            recipient,
            &selected,
            extra,
        )
        .unwrap_err(),
        KeyError::IneligibleDealer(PartyId(40)),
    );

    let mut invalid_share = outputs_for(&selected);
    let invalid_dealer = invalid_share[0].dealer;
    invalid_share[0].share =
        ScalarBytes::from(invalid_share[0].share.parse().unwrap() + Scalar::ONE);
    assert_eq!(
        aggregate_proactive_reshare_from_public(
            &old_public,
            new_committee.clone(),
            recipient,
            &selected,
            invalid_share,
        )
        .unwrap_err(),
        KeyError::InvalidDealerShare(invalid_dealer),
    );

    let unbound_dealer = PartyId(10);
    let mut rng = seeded_rng(133, new_committee.epoch, unbound_dealer);
    let unbound = SecretPolynomial::random_with_constant(
        new_committee.threshold,
        old[&unbound_dealer].secret_share() + Scalar::ONE,
        &mut rng,
    )
    .unwrap();
    let mut unbound_outputs = outputs_for(&selected);
    *unbound_outputs.iter_mut().find(|output| output.dealer == unbound_dealer).unwrap() =
        make_dkg_output(unbound_dealer, &unbound, &new_committee, recipient).unwrap();
    assert_eq!(
        aggregate_proactive_reshare_from_public(
            &old_public,
            new_committee.clone(),
            recipient,
            &selected,
            unbound_outputs,
        )
        .unwrap_err(),
        KeyError::UnboundReshareDealer(unbound_dealer),
    );

    let mut wrong_degree = outputs_for(&selected);
    wrong_degree[0].commitment.coefficients.pop();
    assert_eq!(
        aggregate_proactive_reshare_from_public(
            &old_public,
            new_committee.clone(),
            recipient,
            &selected,
            wrong_degree,
        )
        .unwrap_err(),
        KeyError::WrongDegree,
    );

    // Construct individually valid raw outputs whose weighted top coefficients cancel. The final
    // sharing has degree zero and must not be accepted as a threshold-two epoch.
    let mut degenerate = outputs_for(&selected);
    let target = PartyId(30);
    let weighted_other_slope = selected
        .iter()
        .copied()
        .filter(|dealer| *dealer != target)
        .map(|dealer| {
            let polynomial = &polynomials[&dealer];
            let slope = polynomial.evaluate(Scalar::ONE) - polynomial.constant();
            lagrange_for_party_at_zero(&old_committee, dealer, &selected).unwrap() * slope
        })
        .sum::<Scalar>();
    let target_lambda = lagrange_for_party_at_zero(&old_committee, target, &selected).unwrap();
    let target_slope = -weighted_other_slope * target_lambda.invert();
    let target_constant = polynomials[&target].constant();
    let recipient_x = scalar_for_party(&new_committee, recipient).unwrap();
    *degenerate.iter_mut().find(|output| output.dealer == target).unwrap() = DealerOutput {
        dealer: target,
        share: ScalarBytes::from(target_constant + (target_slope * recipient_x)),
        commitment: PolynomialCommitment {
            coefficients: vec![
                PointBytes::from(EdwardsPoint::mul_base(&target_constant)),
                PointBytes::from(EdwardsPoint::mul_base(&target_slope)),
            ],
        },
    };
    assert_eq!(
        aggregate_proactive_reshare_from_public(
            &old_public,
            new_committee.clone(),
            recipient,
            &selected,
            degenerate,
        )
        .unwrap_err(),
        KeyError::DegenerateSharingPolynomial,
    );

    let wrong_epoch = committee(old_committee.epoch, 2, &[90, 60, 80, 70]);
    assert_eq!(
        aggregate_proactive_reshare_from_public(
            &old_public,
            wrong_epoch,
            recipient,
            &selected,
            vec![],
        )
        .unwrap_err(),
        KeyError::InvalidEpochTransition { old: old_committee.epoch, new: old_committee.epoch },
    );
}
