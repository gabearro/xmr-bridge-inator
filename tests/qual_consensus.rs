use std::collections::{BTreeMap, BTreeSet, VecDeque};

use threshold_monero::{
    Committee, Member, PartyId, SessionId,
    avss::CommitmentDigest,
    qual::{
        EquivocationKind, ProofOfLockCertificate, QualConfig, QualConsensus, QualEntry, QualError,
        QualMessage, QualMessageBody, QualNewRound, QualProposal, QualRoundChange, QualValue,
        QualVote, RoundChangeCertificate, RoundChangeWitness, VotePhase,
    },
};

type Machines = BTreeMap<PartyId, QualConsensus>;
type Queue = VecDeque<(PartyId, QualMessage)>;

fn committee(epoch: u64) -> Committee {
    Committee {
        epoch,
        threshold: 2,
        members: (1_u16..=4)
            .map(|id| Member {
                id: PartyId(id),
                signing_key: [u8::try_from(id).unwrap(); 32],
                encryption_key: [u8::try_from(id + 10).unwrap(); 32],
            })
            .collect(),
    }
    .canonicalized()
    .unwrap()
}

fn config(label: &[u8]) -> QualConfig {
    QualConfig::dkg(
        SessionId::derive(b"qual-test", label),
        *blake3::hash(label).as_bytes(),
        committee(7),
        1,
    )
    .unwrap()
}

fn entry(id: u16) -> QualEntry {
    QualEntry { dealer: PartyId(id), commitment: CommitmentDigest([u8::try_from(id).unwrap(); 32]) }
}

fn make_machines(config: &QualConfig, certified: &[u16], ids: &[u16]) -> Machines {
    ids.iter()
        .map(|id| {
            let mut machine = QualConsensus::new(config.clone(), PartyId(*id)).unwrap();
            for dealer in certified {
                machine.certify(entry(*dealer)).unwrap();
            }
            (PartyId(*id), machine)
        })
        .collect()
}

fn enqueue(queue: &mut Queue, sender: PartyId, messages: Vec<QualMessage>) {
    queue.extend(messages.into_iter().map(|message| (sender, message)));
}

fn start_all(machines: &mut Machines) -> Queue {
    let mut queue = Queue::new();
    for (id, machine) in machines {
        let step = machine.start().unwrap();
        enqueue(&mut queue, *id, step.broadcast);
    }
    queue
}

fn drain(machines: &mut Machines, mut queue: Queue, silent: &BTreeSet<PartyId>) {
    let mut iterations = 0;
    while let Some((sender, message)) = queue.pop_front() {
        iterations += 1;
        assert!(iterations < 20_000, "QUAL delivery did not quiesce");
        let recipients = machines.keys().copied().collect::<Vec<_>>();
        for recipient in recipients {
            if silent.contains(&recipient) || silent.contains(&sender) {
                continue;
            }
            let step =
                machines.get_mut(&recipient).unwrap().handle(sender, message.clone()).unwrap();
            enqueue(&mut queue, recipient, step.broadcast);
        }
    }
}

fn verify_pol_witnesses(
    config: &QualConfig,
    proof: &ProofOfLockCertificate,
    witnesses: &BTreeMap<PartyId, QualMessage>,
) -> bool {
    let expected = proof.expected_prevote();
    proof.voters.iter().all(|voter| {
        witnesses.get(voter).is_some_and(|message| {
            message.context == config.digest() && message.body == QualMessageBody::Vote(expected)
        })
    })
}

fn drain_with_pol_witnesses(
    machines: &mut Machines,
    mut queue: Queue,
    config: &QualConfig,
    witnesses: &BTreeMap<PartyId, QualMessage>,
) {
    let mut iterations = 0;
    while let Some((sender, message)) = queue.pop_front() {
        iterations += 1;
        assert!(iterations < 20_000, "QUAL POL delivery did not quiesce");
        let recipients = machines.keys().copied().collect::<Vec<_>>();
        for recipient in recipients {
            let carries_pol = matches!(
                &message.body,
                QualMessageBody::Proposal(QualProposal { proof_of_lock: Some(_), .. })
                    | QualMessageBody::RoundChange(QualRoundChange { proof_of_lock: Some(_), .. })
            );
            let step = if carries_pol {
                machines
                    .get_mut(&recipient)
                    .unwrap()
                    .handle_with_proof_of_lock_verifier(sender, message.clone(), |proof| {
                        verify_pol_witnesses(config, proof, witnesses)
                    })
                    .unwrap()
            } else {
                machines.get_mut(&recipient).unwrap().handle(sender, message.clone()).unwrap()
            };
            enqueue(&mut queue, recipient, step.broadcast);
        }
    }
}

fn proposal(config: &QualConfig, entries: &[u16], round: u64) -> QualMessage {
    QualMessage {
        context: config.digest(),
        body: QualMessageBody::Proposal(QualProposal {
            round,
            value: QualValue::new(config, entries.iter().copied().map(entry).collect()).unwrap(),
            proof_of_lock: None,
        }),
    }
}

fn vote(
    config: &QualConfig,
    round: u64,
    phase: VotePhase,
    value: Option<threshold_monero::qual::QualValueDigest>,
) -> QualMessage {
    QualMessage {
        context: config.digest(),
        body: QualMessageBody::Vote(QualVote { round, phase, value }),
    }
}

fn round_change(
    config: &QualConfig,
    round: u64,
    proof_of_lock: Option<ProofOfLockCertificate>,
) -> QualMessage {
    QualMessage {
        context: config.digest(),
        body: QualMessageBody::RoundChange(QualRoundChange { round, proof_of_lock }),
    }
}

fn new_round(config: &QualConfig, round: u64, voters: &[u16], entries: &[u16]) -> QualMessage {
    let certificate = RoundChangeCertificate {
        round,
        witnesses: voters
            .iter()
            .map(|voter| RoundChangeWitness {
                voter: PartyId(*voter),
                change: QualRoundChange { round, proof_of_lock: None },
            })
            .collect(),
    };
    QualMessage {
        context: config.digest(),
        body: QualMessageBody::NewRound(QualNewRound {
            round,
            certificate,
            proposal: QualProposal {
                round,
                value: QualValue::new(config, entries.iter().copied().map(entry).collect())
                    .unwrap(),
                proof_of_lock: None,
            },
        }),
    }
}

#[test]
fn honest_parties_decide_one_certified_dkg_qual() {
    let config = config(b"honest");
    let mut machines = make_machines(&config, &[1, 2, 3, 4], &[1, 2, 3, 4]);
    let queue = start_all(&mut machines);
    drain(&mut machines, queue, &BTreeSet::new());

    let decisions = machines
        .values()
        .map(|machine| machine.decision().unwrap().certificate.value.digest())
        .collect::<BTreeSet<_>>();
    assert_eq!(decisions.len(), 1);
    for machine in machines.values() {
        let decision = machine.decision().unwrap();
        assert_eq!(decision.certificate.voters.len(), 3);
        assert_eq!(decision.certificate.value.entries.len(), 3);
        let encoded = postcard::to_allocvec(machine).unwrap();
        let restored: QualConsensus = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(restored.decision(), machine.decision());
    }
}

#[test]
fn one_silent_party_does_not_prevent_a_quorum() {
    let config = config(b"silent");
    let mut machines = make_machines(&config, &[1, 2, 3], &[1, 2, 3, 4]);
    let queue = start_all(&mut machines);
    drain(&mut machines, queue, &BTreeSet::from([PartyId(4)]));
    for id in 1_u16..=3 {
        assert!(machines[&PartyId(id)].decision().is_some());
    }
}

#[test]
fn refresh_qual_selects_exactly_n_minus_f_and_excludes_one_silent_dealer() {
    let config = QualConfig::refresh(
        SessionId::derive(b"qual-test", b"zero-refresh"),
        *blake3::hash(b"zero-refresh").as_bytes(),
        committee(8),
        1,
    )
    .unwrap();
    let mut machines = make_machines(&config, &[1, 2, 3], &[1, 2, 3, 4]);
    let queue = start_all(&mut machines);
    drain(&mut machines, queue, &BTreeSet::from([PartyId(4)]));
    for party in [PartyId(1), PartyId(2), PartyId(3)] {
        let value = &machines[&party].decision().unwrap().certificate.value;
        assert_eq!(value.entries.len(), 3);
        assert!(value.entries.iter().all(|entry| entry.dealer != PartyId(4)));
    }
    assert!(matches!(
        QualValue::new(&config, vec![entry(1), entry(2)]),
        Err(QualError::InvalidValue("refresh QUAL must contain exactly n-f dealers"))
    ));
    assert!(matches!(
        QualValue::new(&config, vec![entry(1), entry(2), entry(3), entry(4)]),
        Err(QualError::InvalidValue("refresh QUAL must contain exactly n-f dealers"))
    ));
}

#[test]
fn explicit_round_advance_recovers_from_a_silent_leader() {
    let config = config(b"timeout");
    let mut machines = make_machines(&config, &[1, 2, 3], &[2, 3, 4]);
    let queue = start_all(&mut machines);
    assert!(queue.is_empty(), "round-zero leader is absent");

    let mut next = Queue::new();
    for (id, machine) in &mut machines {
        let step = machine.advance_round().unwrap();
        assert_eq!(machine.round(), 0, "a timeout alone cannot phase-shift voting");
        assert_eq!(machine.requested_round(), 1);
        assert_eq!(step.requested_round, Some(1));
        enqueue(&mut next, *id, step.broadcast);
    }
    drain(&mut machines, next, &BTreeSet::new());
    assert!(machines.values().all(|machine| machine.decision().is_some()));
}

#[test]
fn byzantine_leader_equivocation_cannot_create_split_quorums() {
    let config = config(b"equivocating-leader");
    let mut machines = make_machines(&config, &[1, 2, 3, 4], &[2, 3, 4]);
    assert!(start_all(&mut machines).is_empty());

    let left = proposal(&config, &[1, 2, 3], 0);
    let right = proposal(&config, &[2, 3, 4], 0);
    let left_digest = match &left.body {
        QualMessageBody::Proposal(proposal) => proposal.value.digest(),
        _ => unreachable!(),
    };
    let right_digest = match &right.body {
        QualMessageBody::Proposal(proposal) => proposal.value.digest(),
        _ => unreachable!(),
    };

    let mut queue = Queue::new();
    enqueue(
        &mut queue,
        PartyId(2),
        machines.get_mut(&PartyId(2)).unwrap().handle(PartyId(1), left.clone()).unwrap().broadcast,
    );
    for id in [PartyId(3), PartyId(4)] {
        let step = machines.get_mut(&id).unwrap().handle(PartyId(1), right.clone()).unwrap();
        enqueue(&mut queue, id, step.broadcast);
    }
    // Show party 2 both signed proposals: it retains evidence and keeps the first.
    let evidence = machines.get_mut(&PartyId(2)).unwrap().handle(PartyId(1), right).unwrap();
    assert_eq!(evidence.evidence.len(), 1);
    assert_eq!(evidence.evidence[0].kind, EquivocationKind::Proposal);

    // Byzantine votes can help only one side reach n-f.
    queue.push_back((PartyId(1), vote(&config, 0, VotePhase::Prevote, Some(right_digest))));
    drain(&mut machines, queue, &BTreeSet::new());
    let mut post = Queue::new();
    post.push_back((PartyId(1), vote(&config, 0, VotePhase::Precommit, Some(right_digest))));
    drain(&mut machines, post, &BTreeSet::new());

    let decisions = machines
        .values()
        .filter_map(QualConsensus::decision)
        .map(|decision| decision.certificate.value.digest())
        .collect::<BTreeSet<_>>();
    assert!(decisions.len() <= 1);
    assert!(!decisions.contains(&left_digest) || !decisions.contains(&right_digest));
}

#[test]
fn reordered_votes_and_exact_duplicates_are_idempotent() {
    let config = config(b"reordered");
    let mut machines = make_machines(&config, &[1, 2, 3], &[1, 2, 3, 4]);
    let mut initial = start_all(&mut machines);
    let proposal_position = initial
        .iter()
        .position(|(_, message)| matches!(message.body, QualMessageBody::Proposal(_)))
        .unwrap();
    let proposal = initial.remove(proposal_position).unwrap();
    let prevote = initial
        .iter()
        .find(|(_, message)| {
            matches!(
                message.body,
                QualMessageBody::Vote(QualVote { phase: VotePhase::Prevote, .. })
            )
        })
        .cloned()
        .unwrap();

    let first =
        machines.get_mut(&PartyId(2)).unwrap().handle(prevote.0, prevote.1.clone()).unwrap();
    assert!(first.changed);
    let duplicate =
        machines.get_mut(&PartyId(2)).unwrap().handle(prevote.0, prevote.1.clone()).unwrap();
    assert!(duplicate.duplicate);
    assert!(duplicate.evidence.is_empty());
    let after_proposal =
        machines.get_mut(&PartyId(2)).unwrap().handle(proposal.0, proposal.1.clone()).unwrap();
    assert!(
        after_proposal
            .broadcast
            .iter()
            .any(|message| matches!(message.body, QualMessageBody::Vote(_)))
    );

    initial.push_back(proposal);
    drain(&mut machines, initial, &BTreeSet::new());
    assert!(machines.values().all(|machine| machine.decision().is_some()));
}

#[test]
fn conflicting_votes_are_evidence_and_only_first_votes_count() {
    let config = config(b"conflicting-votes");
    let mut machines = make_machines(&config, &[1, 2, 3, 4], &[1, 2, 3, 4]);
    let mut queue = start_all(&mut machines);
    let value = QualValue::new(&config, vec![entry(1), entry(2), entry(3)]).unwrap().digest();
    let other = QualValue::new(&config, vec![entry(2), entry(3), entry(4)]).unwrap().digest();

    let first = vote(&config, 0, VotePhase::Prevote, Some(value));
    let conflict = vote(&config, 0, VotePhase::Prevote, Some(other));
    let target = machines.get_mut(&PartyId(2)).unwrap();
    target.handle(PartyId(4), first).unwrap();
    let step = target.handle(PartyId(4), conflict).unwrap();
    assert_eq!(step.evidence.len(), 1);
    assert_eq!(step.evidence[0].kind, EquivocationKind::Prevote);

    drain(&mut machines, std::mem::take(&mut queue), &BTreeSet::new());
    let decisions = machines
        .values()
        .filter_map(QualConsensus::decision)
        .map(|decision| decision.certificate.value.digest())
        .collect::<BTreeSet<_>>();
    assert!(decisions.len() <= 1, "first-seen votes cannot count for both quorums");
}

#[test]
fn unauthenticated_or_conflicting_pol_cannot_unlock_a_different_value() {
    let config = config(b"proof-of-lock");
    let mut machine = make_machines(&config, &[1, 2, 3, 4], &[3]).remove(&PartyId(3)).unwrap();
    machine.start().unwrap();

    let locked_proposal = proposal(&config, &[1, 2, 3], 0);
    let locked_digest = match &locked_proposal.body {
        QualMessageBody::Proposal(proposal) => proposal.value.digest(),
        _ => unreachable!(),
    };
    machine.handle(PartyId(1), locked_proposal).unwrap();
    for sender in [PartyId(1), PartyId(2)] {
        machine.handle(sender, vote(&config, 0, VotePhase::Prevote, Some(locked_digest))).unwrap();
    }
    assert_eq!(machine.locked().unwrap().value.digest(), locked_digest);
    machine.advance_round().unwrap();

    let conflicting_value = QualValue::new(&config, vec![entry(2), entry(3), entry(4)]).unwrap();
    let conflicting_digest = conflicting_value.digest();
    let forged_proof = ProofOfLockCertificate {
        round: 0,
        value: conflicting_value.clone(),
        voters: vec![PartyId(1), PartyId(2), PartyId(3)],
    };
    let unproved_unlock = QualMessage {
        context: config.digest(),
        body: QualMessageBody::Proposal(QualProposal {
            round: 1,
            value: conflicting_value,
            proof_of_lock: Some(forged_proof),
        }),
    };
    assert_eq!(
        machine.handle(PartyId(2), unproved_unlock.clone()),
        Err(QualError::ProofOfLockAuthenticationRequired),
        "canonical voter IDs are not authenticated PREVOTE witnesses"
    );
    assert_eq!(
        machine.handle_with_proof_of_lock_verifier(PartyId(2), unproved_unlock, |_| true),
        Err(QualError::ConflictingQuorums),
        "two authenticated POLs for different values in one round violate the fault bound"
    );
    assert_eq!(machine.locked().unwrap().value.digest(), locked_digest);
    assert_ne!(machine.locked().unwrap().value.digest(), conflicting_digest);
}

#[test]
fn pol_voters_must_be_an_exact_canonical_quorum() {
    let config = config(b"noncanonical-proof-of-lock");
    let mut machine = make_machines(&config, &[1, 2, 3], &[2]).remove(&PartyId(2)).unwrap();
    machine.start().unwrap();
    machine.advance_round().unwrap();

    let value = QualValue::new(&config, vec![entry(1), entry(2), entry(3)]).unwrap();
    let malformed = ProofOfLockCertificate {
        round: 0,
        value: value.clone(),
        voters: vec![PartyId(2), PartyId(1), PartyId(3)],
    };
    let proposal = QualMessage {
        context: config.digest(),
        body: QualMessageBody::Proposal(QualProposal {
            round: 1,
            value,
            proof_of_lock: Some(malformed),
        }),
    };
    let mut verifier_called = false;
    assert!(matches!(
        machine.handle_with_proof_of_lock_verifier(PartyId(2), proposal, |_| {
            verifier_called = true;
            true
        }),
        Err(QualError::InvalidProofOfLock(_))
    ));
    assert!(!verifier_called, "malformed metadata is rejected before witness verification");
    assert!(machine.locked().is_none());
}

#[test]
fn portable_pol_lets_the_next_proposer_decide_with_a_byzantine_party_silent() {
    let config = config(b"portable-pol-liveness");
    let mut machines = make_machines(&config, &[1, 2, 3, 4], &[2, 3, 4]);
    assert!(start_all(&mut machines).is_empty(), "the Byzantine round-zero leader is absent");

    let round_zero_proposal = proposal(&config, &[1, 2, 3], 0);
    let round_zero_digest = match &round_zero_proposal.body {
        QualMessageBody::Proposal(proposal) => proposal.value.digest(),
        _ => unreachable!(),
    };
    let mut witnesses = BTreeMap::new();
    for id in [PartyId(2), PartyId(3), PartyId(4)] {
        let step =
            machines.get_mut(&id).unwrap().handle(PartyId(1), round_zero_proposal.clone()).unwrap();
        let prevote = step
            .broadcast
            .into_iter()
            .find(|message| {
                message.body
                    == QualMessageBody::Vote(QualVote {
                        round: 0,
                        phase: VotePhase::Prevote,
                        value: Some(round_zero_digest),
                    })
            })
            .unwrap();
        witnesses.insert(id, prevote);
    }
    witnesses.insert(PartyId(1), vote(&config, 0, VotePhase::Prevote, Some(round_zero_digest)));

    // Only the next proposer sees q={1,2,3}; parties 3 and 4 retain no round-zero quorum.
    for sender in [PartyId(3), PartyId(1)] {
        machines.get_mut(&PartyId(2)).unwrap().handle(sender, witnesses[&sender].clone()).unwrap();
    }
    assert_eq!(machines[&PartyId(2)].locked().unwrap().value.digest(), round_zero_digest);
    assert!(machines[&PartyId(3)].locked().is_none());
    assert!(machines[&PartyId(4)].locked().is_none());

    // Party 1 is now silent. Party 2 carries its authenticated round-zero witnesses in its
    // round-change; the round-one leader may enter only after collecting q=3 such requests.
    let mut round_one = Queue::new();
    for (id, machine) in &mut machines {
        let step = machine.advance_round().unwrap();
        enqueue(&mut round_one, *id, step.broadcast);
    }
    let proof = round_one
        .iter()
        .find_map(|(_, message)| match &message.body {
            QualMessageBody::RoundChange(QualRoundChange {
                proof_of_lock: Some(proof), ..
            }) => Some(proof),
            _ => None,
        })
        .unwrap();
    assert_eq!(proof.round, 0);
    assert_eq!(proof.value.digest(), round_zero_digest);
    assert_eq!(proof.voters, vec![PartyId(1), PartyId(2), PartyId(3)]);
    assert!(verify_pol_witnesses(&config, proof, &witnesses));

    drain_with_pol_witnesses(&mut machines, round_one, &config, &witnesses);
    for machine in machines.values() {
        let decision = machine.decision().expect("three honest round-one voters reach q=3");
        assert_eq!(decision.certificate.round, 1);
        assert_eq!(decision.certificate.value.digest(), round_zero_digest);
    }
}

#[test]
fn invalid_or_locally_uncertified_values_are_rejected() {
    let config = config(b"invalid");
    let mut machine = make_machines(&config, &[1, 2, 3], &[2]).remove(&PartyId(2)).unwrap();
    machine.start().unwrap();

    let uncertified = proposal(&config, &[1, 2, 4], 0);
    assert_eq!(
        machine.handle(PartyId(1), uncertified),
        Err(QualError::UncertifiedDealer(PartyId(4)))
    );

    let mut invalid_value = QualValue::new(&config, vec![entry(1), entry(2), entry(3)]).unwrap();
    invalid_value.entries.pop();
    let invalid = QualMessage {
        context: config.digest(),
        body: QualMessageBody::Proposal(QualProposal {
            round: 0,
            value: invalid_value,
            proof_of_lock: None,
        }),
    };
    assert!(matches!(machine.handle(PartyId(1), invalid), Err(QualError::InvalidValue(_))));
}

#[test]
fn reshare_qual_selects_exactly_the_old_threshold() {
    let base = committee(9);
    let config = QualConfig::reshare(
        SessionId::derive(b"qual-test", b"reshare"),
        [7; 32],
        base,
        1,
        2,
        vec![PartyId(10), PartyId(11), PartyId(12)],
    )
    .unwrap();
    let mut machines = config
        .committee()
        .members
        .iter()
        .map(|member| {
            let mut machine = QualConsensus::new(config.clone(), member.id).unwrap();
            for id in [10, 11, 12] {
                machine.certify(entry(id)).unwrap();
            }
            (member.id, machine)
        })
        .collect::<Machines>();
    let queue = start_all(&mut machines);
    drain(&mut machines, queue, &BTreeSet::new());
    for machine in machines.values() {
        assert_eq!(machine.decision().unwrap().certificate.value.entries.len(), 2);
    }
}

#[test]
fn f_plus_one_future_senders_trigger_catch_up_without_phase_shifting() {
    let config = config(b"future-evidence-catch-up");
    let mut machine = make_machines(&config, &[1, 2, 3], &[4]).remove(&PartyId(4)).unwrap();
    machine.start().unwrap();

    let first = machine.handle(PartyId(1), vote(&config, 50, VotePhase::Prevote, None)).unwrap();
    assert!(first.broadcast.is_empty());
    assert_eq!(machine.round(), 0);
    assert_eq!(machine.requested_round(), 0);

    // Two message kinds from one Byzantine sender still count as one authenticated sender.
    let same_sender =
        machine.handle(PartyId(1), vote(&config, 60, VotePhase::Precommit, None)).unwrap();
    assert!(same_sender.broadcast.is_empty());
    assert_eq!(machine.requested_round(), 0);

    let catch_up = machine.handle(PartyId(2), vote(&config, 50, VotePhase::Prevote, None)).unwrap();
    assert_eq!(machine.round(), 0, "f+1 evidence requests but does not enter a round");
    assert_eq!(machine.requested_round(), 50);
    assert_eq!(catch_up.requested_round, Some(50));
    assert!(catch_up.broadcast.iter().any(|message| {
        message.body
            == QualMessageBody::RoundChange(QualRoundChange { round: 50, proof_of_lock: None })
    }));
}

#[test]
fn future_buffer_has_one_latest_slot_per_sender_and_kind() {
    let config = config(b"bounded-future-buffer");
    let mut machine = make_machines(&config, &[1, 2, 3], &[4]).remove(&PartyId(4)).unwrap();
    machine.start().unwrap();

    for round in 1..=512 {
        machine.handle(PartyId(1), vote(&config, round, VotePhase::Prevote, None)).unwrap();
    }
    assert_eq!(machine.buffered_future_messages(), 1);
    assert_eq!(machine.requested_round(), 0, "one sender cannot force catch-up");

    machine.handle(PartyId(1), vote(&config, 700, VotePhase::Precommit, None)).unwrap();
    assert_eq!(machine.buffered_future_messages(), 2);

    let encoded = postcard::to_allocvec(&machine).unwrap();
    let restored: QualConsensus = postcard::from_bytes(&encoded).unwrap();
    assert_eq!(restored.buffered_future_messages(), 2);
    assert_eq!(restored.round(), 0);
    assert_eq!(restored.requested_round(), 0);
}

#[test]
fn new_round_waits_for_every_authenticated_certificate_witness() {
    let config = config(b"new-round-authentication");
    let mut machine = make_machines(&config, &[1, 2, 3], &[3]).remove(&PartyId(3)).unwrap();
    machine.start().unwrap();

    let certificate = new_round(&config, 1, &[1, 2, 3], &[1, 2, 3]);
    let buffered = machine.handle(PartyId(2), certificate).unwrap();
    assert!(buffered.entered_round.is_none());
    assert_eq!(machine.round(), 0);
    assert_eq!(machine.buffered_future_messages(), 1);

    // The buffered leader message plus one independently authenticated sender supplies f+1
    // evidence, so this party relays its own round-change but still cannot enter.
    let first = machine.handle(PartyId(1), round_change(&config, 1, None)).unwrap();
    assert_eq!(first.requested_round, Some(1));
    assert_eq!(machine.round(), 0);

    // The final exact witness authenticates the certificate and atomically enters round one.
    let entered = machine.handle(PartyId(2), round_change(&config, 1, None)).unwrap();
    assert_eq!(entered.entered_round, Some(1));
    assert_eq!(machine.round(), 1);
    assert_eq!(machine.buffered_future_messages(), 0);
}

#[test]
fn a_large_round_offset_converges_and_decides_after_gst() {
    let config = config(b"large-offset-recovery");
    let mut machines = make_machines(&config, &[1, 2, 3], &[2, 3, 4]);
    assert!(start_all(&mut machines).is_empty(), "round-zero leader is Byzantine and silent");

    let mut final_changes = Queue::new();
    for party in [PartyId(2), PartyId(3)] {
        let machine = machines.get_mut(&party).unwrap();
        let mut final_change = None;
        for target in 1..=15 {
            let step = machine.advance_round().unwrap();
            assert_eq!(step.requested_round, Some(target));
            final_change = step
                .broadcast
                .into_iter()
                .find(|message| matches!(message.body, QualMessageBody::RoundChange(_)));
        }
        assert_eq!(machine.round(), 0);
        final_changes.push_back((party, final_change.unwrap()));
    }

    // Party 4 starts with no timeout history. Two independently authenticated round-15 requests
    // are f+1 evidence; as round-15 leader it relays its request, forms q=3, and brings all honest
    // parties directly into one certified round.
    drain(&mut machines, final_changes, &BTreeSet::new());
    assert!(machines.values().all(|machine| machine.round() == 15));
    assert!(machines.values().all(|machine| machine.decision().is_some()));
    let decisions = machines
        .values()
        .map(|machine| machine.decision().unwrap().certificate.value.digest())
        .collect::<BTreeSet<_>>();
    assert_eq!(decisions.len(), 1);
}
