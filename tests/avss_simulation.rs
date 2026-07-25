use std::collections::{BTreeMap, VecDeque};

use curve25519_dalek::{EdwardsPoint, Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use threshold_monero::avss::{
    AvssConfig, AvssDealer, AvssError, AvssMessage, AvssParty, AvssPayload, PrivateAvssMessage,
};
use threshold_monero::keys::{KeyError, ScalarBytes, scalar_for_party};
use threshold_monero::{Committee, Member, PartyId, SessionId};

#[derive(Clone)]
struct Delivery {
    sender: PartyId,
    private: PrivateAvssMessage,
}

fn member(id: u16) -> Member {
    let mut signing_key = [0_u8; 32];
    signing_key[..2].copy_from_slice(&id.to_le_bytes());
    signing_key[31] = 0x51;
    let mut encryption_key = [0_u8; 32];
    encryption_key[..2].copy_from_slice(&id.to_le_bytes());
    encryption_key[31] = 0xa7;
    Member { id: PartyId(id), signing_key, encryption_key }
}

fn committee(n: u16, threshold: u16) -> Committee {
    Committee { epoch: 9, threshold, members: (1..=n).map(member).collect() }
}

fn config(n: u16, threshold: u16, fault_bound: u16) -> AvssConfig {
    let mut session_material = Vec::with_capacity(4);
    session_material.extend_from_slice(&n.to_le_bytes());
    session_material.extend_from_slice(&threshold.to_le_bytes());
    AvssConfig {
        session: SessionId::derive(b"avss-simulation", &session_material),
        dealer: PartyId(1),
        receivers: committee(n, threshold),
        fault_bound,
    }
}

fn rng(seed_byte: u8) -> ChaCha20Rng {
    let mut seed = [0_u8; 32];
    seed[0] = seed_byte;
    ChaCha20Rng::from_seed(seed)
}

fn machines(config: &AvssConfig, included: &[PartyId]) -> BTreeMap<PartyId, AvssParty> {
    included
        .iter()
        .copied()
        .map(|party| (party, AvssParty::new(config.clone(), party).unwrap()))
        .collect()
}

/// Deliver from the back of the queue and inject exact duplicates at deterministic positions.
/// Newly generated messages therefore routinely overtake older DealerSend/Echo traffic.
#[allow(clippy::manual_is_multiple_of)]
fn drive_reordered(
    machines: &mut BTreeMap<PartyId, AvssParty>,
    initial: Vec<Delivery>,
    duplicate_every: usize,
) {
    let mut queue = VecDeque::from(initial);
    let mut delivered = 0_usize;
    while let Some(delivery) = queue.pop_back() {
        delivered += 1;
        assert!(delivered < 20_000, "simulation failed to quiesce");
        let Some(machine) = machines.get_mut(&delivery.private.recipient) else {
            // Models an offline/Byzantine receiver.
            continue;
        };
        let sender = delivery.private.recipient;
        let step = machine.handle(delivery.sender, delivery.private.message.clone()).unwrap();
        for outbound in step.outbound {
            queue.push_back(Delivery { sender, private: outbound.clone() });
            if duplicate_every != 0 && delivered % duplicate_every == 0 {
                // Put the duplicate on the opposite end to exercise both old and new ordering.
                queue.push_front(Delivery { sender, private: outbound });
            }
        }
        if duplicate_every != 0 && delivered % duplicate_every == 0 {
            queue.push_front(delivery);
        }
    }
}

fn initial_deliveries(dealer: &AvssDealer) -> Vec<Delivery> {
    dealer
        .private_messages()
        .unwrap()
        .into_iter()
        .map(|private| Delivery { sender: PartyId(1), private })
        .collect()
}

fn dealer_message_for(dealer: &AvssDealer, recipient: PartyId) -> AvssMessage {
    dealer
        .private_messages()
        .unwrap()
        .into_iter()
        .find(|private| private.recipient == recipient)
        .unwrap_or_else(|| panic!("dealer has no message for party {recipient}"))
        .message
}

fn echo_messages_from(
    config: &AvssConfig,
    dealer: &AvssDealer,
    sender: PartyId,
) -> Vec<PrivateAvssMessage> {
    let mut source = AvssParty::new(config.clone(), sender).unwrap();
    source.handle(config.dealer, dealer_message_for(dealer, sender)).unwrap().outbound
}

fn cross_message_for(
    config: &AvssConfig,
    dealer: &AvssDealer,
    sender: PartyId,
    recipient: PartyId,
) -> AvssMessage {
    echo_messages_from(config, dealer, sender)
        .into_iter()
        .find(|private| private.recipient == recipient)
        .unwrap_or_else(|| panic!("party {sender} has no Echo for party {recipient}"))
        .message
}

fn as_ready(mut message: AvssMessage) -> AvssMessage {
    let AvssPayload::Echo(values) = message.payload else {
        panic!("expected Echo");
    };
    message.payload = AvssPayload::Ready(values);
    message
}

fn assert_rejected_without_mutation(
    party: &mut AvssParty,
    sender: PartyId,
    message: AvssMessage,
    expected: AvssError,
) {
    let before = postcard::to_allocvec(party).unwrap();
    assert_eq!(party.handle(sender, message).unwrap_err(), expected);
    assert_eq!(postcard::to_allocvec(party).unwrap(), before);
}

fn interpolate_two_at_zero(
    committee: &Committee,
    left: (PartyId, Scalar),
    right: (PartyId, Scalar),
) -> Scalar {
    let x_left = scalar_for_party(committee, left.0).unwrap();
    let x_right = scalar_for_party(committee, right.0).unwrap();
    let lambda_left = -x_right * (x_left - x_right).invert();
    let lambda_right = -x_left * (x_right - x_left).invert();
    left.1 * lambda_left + right.1 * lambda_right
}

#[test]
fn validates_exact_ckls_resilience_region() {
    config(4, 2, 1).validate().unwrap();

    assert_eq!(
        config(3, 2, 1).validate().unwrap_err(),
        AvssError::InvalidFaultBound { n: 3, fault_bound: 1 },
    );
    assert_eq!(
        config(4, 1, 1).validate().unwrap_err(),
        AvssError::InvalidThreshold { n: 4, fault_bound: 1, threshold: 1 },
    );
    assert_eq!(
        config(4, 3, 1).validate().unwrap_err(),
        AvssError::InvalidThreshold { n: 4, fault_bound: 1, threshold: 3 },
    );

    let valid = config(4, 2, 1);
    assert_eq!(valid.echo_threshold(), 3);
    assert_eq!(valid.ready_relay_threshold(), 2);
    assert_eq!(valid.completion_threshold(), 3);
}

#[test]
fn every_valid_small_parameter_set_satisfies_the_quorum_proof_obligations() {
    for n in 1_u16..=24 {
        for fault_bound in 0_u16..=8 {
            for threshold in 1_u16..=n {
                let candidate = config(n, threshold, fault_bound);
                if candidate.validate().is_err() {
                    continue;
                }

                let n = usize::from(n);
                let f = usize::from(fault_bound);
                let k = usize::from(threshold);
                let echoes = candidate.echo_threshold();
                let completion = candidate.completion_threshold();

                assert!(2 * echoes > n + f, "two Echo quorums must overlap honestly");
                assert!(echoes <= n - f, "all honest receivers must form an Echo quorum");
                assert!(k > f, "f faulty Readys cannot bootstrap Ready relay");
                assert_eq!(completion, k + f);
                assert!(completion <= n - f, "all honest receivers must complete");
            }
        }
    }
}

#[test]
fn reordered_duplicate_messages_complete_one_consistent_sharing() {
    let config = config(4, 2, 1);
    let secret = Scalar::from(0xfeed_u64);
    let dealer = AvssDealer::random_with_constant(config.clone(), secret, &mut rng(7)).unwrap();
    let parties = [PartyId(1), PartyId(2), PartyId(3), PartyId(4)];
    let mut parties = machines(&config, &parties);

    drive_reordered(&mut parties, initial_deliveries(&dealer), 3);

    let expected_digest = parties[&PartyId(1)].output().unwrap().commitment_digest;
    for (party, machine) in &parties {
        let output = machine.output().unwrap_or_else(|| panic!("party {party} did not complete"));
        assert_eq!(output.commitment_digest, expected_digest);
        assert!(output.ready_senders.len() >= 3);
        let share = output.share.parse().unwrap();
        let x = scalar_for_party(&config.receivers, *party).unwrap();
        assert!(output.x_axis_commitment.verify_share(x, share).unwrap());
        assert_eq!(output.dealer_output().dealer, PartyId(1));

        // Durable state remains valid after an arbitrary crash/reload boundary.
        let encoded = postcard::to_allocvec(machine).unwrap();
        let restored: AvssParty = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(&restored, machine);
    }

    let left = parties[&PartyId(1)].output().unwrap().share.parse().unwrap();
    let right = parties[&PartyId(4)].output().unwrap().share.parse().unwrap();
    assert_eq!(
        interpolate_two_at_zero(&config.receivers, (PartyId(1), left), (PartyId(4), right),),
        secret,
    );
    assert_eq!(
        parties[&PartyId(2)].output().unwrap().x_axis_commitment.constant().unwrap(),
        EdwardsPoint::mul_base(&secret),
    );
}

#[test]
fn omitted_recipient_recovers_from_echoes_without_dealer_send() {
    let config = config(4, 2, 1);
    let dealer =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(19_u64), &mut rng(19))
            .unwrap();
    let ids = [PartyId(1), PartyId(2), PartyId(3), PartyId(4)];
    let mut parties = machines(&config, &ids);
    let initial = initial_deliveries(&dealer)
        .into_iter()
        .filter(|delivery| delivery.private.recipient != PartyId(4))
        .collect();

    drive_reordered(&mut parties, initial, 2);

    let recovered = &parties[&PartyId(4)];
    assert!(recovered.output().is_some());
    assert_eq!(recovered.echoed_for(), None, "an omitted receiver must not fabricate Echo");
    assert!(recovered.ready_for().is_some());
    for machine in parties.values() {
        assert!(machine.output().is_some());
    }
}

#[test]
fn n4_f1_completes_with_one_completely_silent_receiver() {
    let config = config(4, 2, 1);
    let dealer =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(77_u64), &mut rng(77))
            .unwrap();
    let active = [PartyId(1), PartyId(2), PartyId(3)];
    let mut parties = machines(&config, &active);
    let initial = initial_deliveries(&dealer)
        .into_iter()
        .filter(|delivery| delivery.private.recipient != PartyId(4))
        .collect();

    drive_reordered(&mut parties, initial, 4);

    for machine in parties.values() {
        assert!(machine.output().is_some());
        assert_eq!(machine.output().unwrap().ready_senders.len(), 3);
    }
}

#[test]
fn k_readies_recover_and_relay_before_the_echo_gate() {
    let config = config(4, 2, 1);
    let dealer =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(91_u64), &mut rng(91))
            .unwrap();
    let dealer_messages = dealer.private_messages().unwrap();

    let mut echo_messages = Vec::new();
    let mut sources = BTreeMap::new();
    for party in [PartyId(1), PartyId(2), PartyId(3)] {
        let mut machine = AvssParty::new(config.clone(), party).unwrap();
        let dealer_send = dealer_messages
            .iter()
            .find(|message| message.recipient == party)
            .unwrap()
            .message
            .clone();
        let step = machine.handle(PartyId(1), dealer_send).unwrap();
        echo_messages
            .extend(step.outbound.into_iter().map(|private| Delivery { sender: party, private }));
        sources.insert(party, machine);
    }

    let mut ready_for_four = Vec::new();
    for receiver in [PartyId(1), PartyId(2), PartyId(3)] {
        for delivery in
            echo_messages.iter().filter(|delivery| delivery.private.recipient == receiver)
        {
            let step = sources
                .get_mut(&receiver)
                .unwrap()
                .handle(delivery.sender, delivery.private.message.clone())
                .unwrap();
            ready_for_four.extend(
                step.outbound
                    .into_iter()
                    .filter(|private| private.recipient == PartyId(4))
                    .map(|private| Delivery { sender: receiver, private }),
            );
        }
    }
    assert_eq!(ready_for_four.len(), 3);

    let mut recovered = AvssParty::new(config, PartyId(4)).unwrap();
    for delivery in ready_for_four.iter().take(2) {
        let step = recovered.handle(delivery.sender, delivery.private.message.clone()).unwrap();
        if delivery.sender == PartyId(2) {
            assert_eq!(step.outbound.len(), 4, "k Readys must cause one Ready relay");
        }
    }
    assert_eq!(recovered.echoed_for(), None);
    assert!(recovered.ready_for().is_some());
    assert!(recovered.output().is_none());

    let final_ready = &ready_for_four[2];
    let step = recovered.handle(final_ready.sender, final_ready.private.message.clone()).unwrap();
    assert!(step.completed.is_some());
    assert!(recovered.output().is_some());
}

fn add_one(value: &mut ScalarBytes) {
    *value = ScalarBytes::from(value.parse().unwrap() + Scalar::ONE);
}

#[test]
fn malformed_private_values_are_rejected_without_poisoning_later_delivery() {
    let config = config(4, 2, 1);
    let dealer =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(31_u64), &mut rng(31))
            .unwrap();
    let valid_dealer_send = dealer
        .private_messages()
        .unwrap()
        .into_iter()
        .find(|private| private.recipient == PartyId(1))
        .unwrap();
    let mut malformed_dealer_send = valid_dealer_send.message.clone();
    let AvssPayload::DealerSend(polynomials) = &mut malformed_dealer_send.payload else {
        panic!("expected DealerSend");
    };
    add_one(&mut polynomials.row[0]);

    let mut party_one = AvssParty::new(config.clone(), PartyId(1)).unwrap();
    assert_eq!(
        party_one.handle(PartyId(1), malformed_dealer_send).unwrap_err(),
        AvssError::InvalidDealerPolynomials,
    );
    assert_eq!(party_one.echoed_for(), None);

    let echo_step = party_one.handle(PartyId(1), valid_dealer_send.message).unwrap();
    assert_eq!(echo_step.outbound.len(), 4);
    let valid_echo =
        echo_step.outbound.into_iter().find(|private| private.recipient == PartyId(2)).unwrap();
    let mut malformed_echo = valid_echo.message.clone();
    let AvssPayload::Echo(values) = &mut malformed_echo.payload else {
        panic!("expected Echo");
    };
    add_one(&mut values.sender_recipient);

    let mut party_two = AvssParty::new(config, PartyId(2)).unwrap();
    assert_eq!(
        party_two.handle(PartyId(1), malformed_echo).unwrap_err(),
        AvssError::InvalidCrossValues,
    );
    let accepted = party_two.handle(PartyId(1), valid_echo.message.clone()).unwrap();
    assert!(!accepted.duplicate);
    let duplicate = party_two.handle(PartyId(1), valid_echo.message).unwrap();
    assert!(duplicate.duplicate);
}

#[test]
fn signed_matrix_digest_and_one_echo_rule_detect_dealer_equivocation() {
    let config = config(4, 2, 1);
    let first =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(1_u64), &mut rng(1)).unwrap();
    let second =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(2_u64), &mut rng(2)).unwrap();
    let first_message: AvssMessage = first
        .private_messages()
        .unwrap()
        .into_iter()
        .find(|private| private.recipient == PartyId(3))
        .unwrap()
        .message;
    let second_message = second
        .private_messages()
        .unwrap()
        .into_iter()
        .find(|private| private.recipient == PartyId(3))
        .unwrap()
        .message;

    let mut receiver = AvssParty::new(config, PartyId(3)).unwrap();
    receiver.handle(PartyId(1), first_message).unwrap();
    assert_eq!(
        receiver.handle(PartyId(1), second_message).unwrap_err(),
        AvssError::DealerEquivocation,
    );
}

#[test]
fn n7_f2_completes_with_two_completely_silent_receivers() {
    let config = config(7, 3, 2);
    let dealer =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(0x707_u64), &mut rng(70))
            .unwrap();
    let active = [PartyId(1), PartyId(2), PartyId(3), PartyId(4), PartyId(5)];
    let mut parties = machines(&config, &active);
    let initial = initial_deliveries(&dealer)
        .into_iter()
        .filter(|delivery| active.contains(&delivery.private.recipient))
        .collect();

    drive_reordered(&mut parties, initial, 3);

    let digest = parties[&PartyId(1)].output().unwrap().commitment_digest;
    for (party, machine) in &parties {
        let output = machine.output().unwrap_or_else(|| panic!("party {party} did not complete"));
        assert_eq!(output.commitment_digest, digest);
        assert_eq!(output.ready_senders.len(), 5, "only n-f parties were online");
        assert_eq!(machine.echoed_for(), Some(digest));
        assert_eq!(machine.ready_for(), Some(digest));
    }
}

#[test]
fn four_of_seven_f1_completes_with_one_silent_receiver() {
    let config = config(7, 4, 1);
    let dealer =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(0x471_u64), &mut rng(47))
            .unwrap();
    let active = [PartyId(1), PartyId(2), PartyId(3), PartyId(4), PartyId(5), PartyId(6)];
    let mut parties = machines(&config, &active);
    let initial = initial_deliveries(&dealer)
        .into_iter()
        .filter(|delivery| active.contains(&delivery.private.recipient))
        .collect();

    drive_reordered(&mut parties, initial, 5);

    let digest = parties[&PartyId(1)].output().unwrap().commitment_digest;
    for machine in parties.values() {
        let output = machine.output().unwrap();
        assert_eq!(output.commitment_digest, digest);
        assert!(output.ready_senders.len() >= config.completion_threshold());
    }
}

#[test]
fn silent_faulty_dealer_and_f_ready_senders_cannot_create_an_output() {
    let mut config = config(7, 3, 2);
    config.dealer = PartyId(99);
    let dealer =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(0x515_u64), &mut rng(51))
            .unwrap();
    let honest = [PartyId(3), PartyId(4), PartyId(5), PartyId(6), PartyId(7)];
    let mut parties = machines(&config, &honest);
    let mut adversarial = Vec::new();

    // The external faulty dealer may privately coordinate with f faulty receivers. Giving every
    // honest receiver both valid Ready messages is the strongest coalition traffic that still
    // stays within the receiver fault bound. Exact replays must not increase either threshold.
    for sender in [PartyId(1), PartyId(2)] {
        for mut private in echo_messages_from(&config, &dealer, sender) {
            if honest.contains(&private.recipient) {
                private.message = as_ready(private.message);
                adversarial.push(Delivery { sender, private });
            }
        }
    }

    drive_reordered(&mut parties, adversarial, 2);

    for machine in parties.values() {
        assert_eq!(machine.echoed_for(), None);
        assert_eq!(machine.ready_for(), None, "f Readys must not reach the k=3 relay gate");
        assert!(machine.output().is_none());
    }
}

#[test]
fn equivocal_dealer_still_yields_at_most_one_output_among_honest_parties() {
    let mut config = config(7, 3, 2);
    config.dealer = PartyId(99);
    let secret_a = Scalar::from(0xaaa_u64);
    let secret_b = Scalar::from(0xbbb_u64);
    let dealer_a =
        AvssDealer::random_with_constant(config.clone(), secret_a, &mut rng(0xa1)).unwrap();
    let dealer_b =
        AvssDealer::random_with_constant(config.clone(), secret_b, &mut rng(0xb1)).unwrap();
    let digest_a = dealer_message_for(&dealer_a, PartyId(3)).commitment_digest;
    let digest_b = dealer_message_for(&dealer_b, PartyId(5)).commitment_digest;
    assert_ne!(digest_a, digest_b);

    // The external dealer equivocates while receivers 1 and 2 are Byzantine. It sends A to two
    // honest receivers and B to the other three, while both Byzantine receivers Echo B to every
    // honest receiver. Candidate B can reach q_echo=5. Candidate A cannot, even though two honest
    // parties already Echoed it.
    let honest = [PartyId(3), PartyId(4), PartyId(5), PartyId(6), PartyId(7)];
    let mut parties = machines(&config, &honest);
    let mut queue = Vec::new();
    for party in honest {
        let selected = if party <= PartyId(4) { &dealer_a } else { &dealer_b };
        let step = parties
            .get_mut(&party)
            .unwrap()
            .handle(config.dealer, dealer_message_for(selected, party))
            .unwrap();
        assert_eq!(step.outbound.len(), 7);
        queue.extend(step.outbound.into_iter().map(|private| Delivery { sender: party, private }));
    }
    for sender in [PartyId(1), PartyId(2)] {
        queue.extend(
            echo_messages_from(&config, &dealer_b, sender)
                .into_iter()
                .filter(|private| honest.contains(&private.recipient))
                .map(|private| Delivery { sender, private }),
        );
    }

    drive_reordered(&mut parties, queue, 4);

    for party in honest {
        let machine = &parties[&party];
        assert_eq!(
            machine.echoed_for(),
            Some(if party <= PartyId(4) { digest_a } else { digest_b }),
        );
        assert_eq!(machine.ready_for(), Some(digest_b));
        let output = machine.output().unwrap();
        assert_eq!(output.commitment_digest, digest_b);
        assert_eq!(output.x_axis_commitment.constant().unwrap(), EdwardsPoint::mul_base(&secret_b));
        assert!(
            output
                .x_axis_commitment
                .verify_share(
                    scalar_for_party(&config.receivers, party).unwrap(),
                    output.share.parse().unwrap(),
                )
                .unwrap()
        );
    }
}

#[test]
fn receiver_echo_and_ready_equivocation_are_rejected_atomically() {
    let config = config(7, 3, 2);
    let dealer_a =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(41_u64), &mut rng(41))
            .unwrap();
    let dealer_b =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(42_u64), &mut rng(42))
            .unwrap();
    let sender = PartyId(2);
    let recipient = PartyId(3);
    let echo_a = cross_message_for(&config, &dealer_a, sender, recipient);
    let echo_b = cross_message_for(&config, &dealer_b, sender, recipient);

    let mut echo_receiver = AvssParty::new(config.clone(), recipient).unwrap();
    echo_receiver.handle(sender, echo_a).unwrap();
    assert_rejected_without_mutation(
        &mut echo_receiver,
        sender,
        echo_b,
        AvssError::SenderEquivocation {
            sender,
            kind: threshold_monero::avss::AvssMessageKind::Echo,
        },
    );

    let ready_config = config.clone();
    let mut ready_receiver = AvssParty::new(config, recipient).unwrap();
    ready_receiver
        .handle(sender, as_ready(cross_message_for(&ready_config, &dealer_a, sender, recipient)))
        .unwrap();
    let ready_b = as_ready(cross_message_for(&ready_config, &dealer_b, sender, recipient));
    assert_rejected_without_mutation(
        &mut ready_receiver,
        sender,
        ready_b,
        AvssError::SenderEquivocation {
            sender,
            kind: threshold_monero::avss::AvssMessageKind::Ready,
        },
    );
}

#[test]
fn malformed_matrices_and_scalars_are_rejected_atomically() {
    let config = config(4, 2, 1);
    let dealer =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(66_u64), &mut rng(66))
            .unwrap();
    let valid = dealer_message_for(&dealer, PartyId(2));

    let mut wrong_dimensions_json = serde_json::to_value(&valid).unwrap();
    wrong_dimensions_json["commitment"]["coefficients"].as_array_mut().unwrap().pop();
    let wrong_dimensions: AvssMessage = serde_json::from_value(wrong_dimensions_json).unwrap();
    assert_rejected_without_mutation(
        &mut AvssParty::new(config.clone(), PartyId(2)).unwrap(),
        PartyId(1),
        wrong_dimensions,
        AvssError::WrongMatrixDimensions,
    );

    // Compressed Edwards y=0 is a small-order point. Recomputing the digest models a malicious
    // dealer, rather than an accidental wire corruption caught only by the digest.
    let mut low_order_json = serde_json::to_value(&valid).unwrap();
    low_order_json["commitment"]["coefficients"][0] = serde_json::to_value([0_u8; 32]).unwrap();
    let mut low_order: AvssMessage = serde_json::from_value(low_order_json).unwrap();
    low_order.commitment_digest = low_order.commitment.digest();
    assert_rejected_without_mutation(
        &mut AvssParty::new(config.clone(), PartyId(2)).unwrap(),
        PartyId(1),
        low_order,
        AvssError::Key(KeyError::NonPrimeOrderPoint),
    );

    let mut wrong_digest = valid.clone();
    wrong_digest.commitment_digest.0[0] ^= 1;
    assert_rejected_without_mutation(
        &mut AvssParty::new(config.clone(), PartyId(2)).unwrap(),
        PartyId(1),
        wrong_digest,
        AvssError::WrongCommitmentDigest,
    );

    let mut short_polynomial = valid.clone();
    let AvssPayload::DealerSend(polynomials) = &mut short_polynomial.payload else {
        panic!("expected DealerSend");
    };
    polynomials.column.pop();
    assert_rejected_without_mutation(
        &mut AvssParty::new(config.clone(), PartyId(2)).unwrap(),
        PartyId(1),
        short_polynomial,
        AvssError::WrongPolynomialLength,
    );

    let mut noncanonical_scalar = valid;
    let AvssPayload::DealerSend(polynomials) = &mut noncanonical_scalar.payload else {
        panic!("expected DealerSend");
    };
    polynomials.row[0].0 = [0xff; 32];
    assert_rejected_without_mutation(
        &mut AvssParty::new(config, PartyId(2)).unwrap(),
        PartyId(1),
        noncanonical_scalar,
        AvssError::Key(KeyError::InvalidScalar),
    );
}

#[test]
fn misrouted_or_inconsistently_authenticated_deliveries_do_not_poison_state() {
    let config = config(4, 2, 1);
    let dealer =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(88_u64), &mut rng(88))
            .unwrap();

    let mut party_two = AvssParty::new(config.clone(), PartyId(2)).unwrap();
    assert_rejected_without_mutation(
        &mut party_two,
        PartyId(1),
        dealer_message_for(&dealer, PartyId(1)),
        AvssError::InvalidDealerPolynomials,
    );

    let echo_for_three = cross_message_for(&config, &dealer, PartyId(2), PartyId(3));
    let mut party_four = AvssParty::new(config.clone(), PartyId(4)).unwrap();
    assert_rejected_without_mutation(
        &mut party_four,
        PartyId(2),
        echo_for_three.clone(),
        AvssError::InvalidCrossValues,
    );

    let mut party_three = AvssParty::new(config.clone(), PartyId(3)).unwrap();
    assert_rejected_without_mutation(
        &mut party_three,
        PartyId(4),
        echo_for_three.clone(),
        AvssError::InvalidCrossValues,
    );

    let mut wrong_instance = echo_for_three;
    wrong_instance.instance.session = SessionId::derive(b"wrong-avss-session", b"replay");
    assert_rejected_without_mutation(
        &mut party_three,
        PartyId(2),
        wrong_instance,
        AvssError::WrongInstance,
    );
}

#[test]
fn exact_replays_after_completion_are_idempotent() {
    let config = config(4, 2, 1);
    let dealer =
        AvssDealer::random_with_constant(config.clone(), Scalar::from(99_u64), &mut rng(99))
            .unwrap();
    let dealer_send = dealer_message_for(&dealer, PartyId(1));
    let echo = cross_message_for(&config, &dealer, PartyId(2), PartyId(1));
    let ids = [PartyId(1), PartyId(2), PartyId(3), PartyId(4)];
    let mut parties = machines(&config, &ids);
    drive_reordered(&mut parties, initial_deliveries(&dealer), 3);

    let party = parties.get_mut(&PartyId(1)).unwrap();
    assert!(party.output().is_some());
    for (sender, message) in [(PartyId(1), dealer_send), (PartyId(2), echo)] {
        let before = postcard::to_allocvec(&*party).unwrap();
        let step = party.handle(sender, message).unwrap();
        assert!(step.duplicate);
        assert!(step.outbound.is_empty());
        assert!(step.completed.is_none());
        assert_eq!(postcard::to_allocvec(&*party).unwrap(), before);
    }
}
