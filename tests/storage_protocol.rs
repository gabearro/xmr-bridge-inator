use std::io;

use rand_core::OsRng;
use threshold_monero::{
    PartyId, SessionId,
    storage::{
        ActivationCertificateKey, ActivationTransitionKey, MAX_SESSION_STATE_BYTES, ProtocolStore,
        SessionStateKey, StoreError,
    },
};

fn session_id(byte: u8) -> SessionId {
    SessionId([byte; 32])
}

#[cfg(unix)]
async fn assert_private_file(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let mode = tokio::fs::metadata(path).await.unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[tokio::test]
async fn session_state_overwrite_reload_enumeration_and_retirement_are_crash_safe() {
    let directory = tempfile::tempdir().unwrap();
    let store = ProtocolStore::new(directory.path(), PartyId(1), &[9; 32]).unwrap();
    let session = session_id(1);
    let context = [2; 32];

    store.save_session_state(session, context, b"first snapshot", &mut OsRng).await.unwrap();
    assert_eq!(
        store.load_session_state(session, context).await.unwrap().as_bytes(),
        b"first snapshot"
    );
    #[cfg(unix)]
    assert_private_file(&store.session_state_path(session, context)).await;

    // A completed but unrenamed temporary file models a crash between fsync and rename. Only the
    // exact documented temporary-file grammar is ignored by enumeration.
    let state_path = store.session_state_path(session, context);
    let filename = state_path.file_name().unwrap().to_str().unwrap();
    let stale_temporary =
        state_path.parent().unwrap().join(format!(".{filename}.{}.tmp", "00".repeat(24)));
    tokio::fs::write(&stale_temporary, b"incomplete replacement").await.unwrap();
    assert_eq!(
        store.session_states().await.unwrap(),
        vec![SessionStateKey { session, context_digest: context }]
    );

    store.save_session_state(session, context, b"second snapshot", &mut OsRng).await.unwrap();
    let reloaded = ProtocolStore::new(directory.path(), PartyId(1), &[9; 32]).unwrap();
    let loaded = reloaded.load_session_state(session, context).await.unwrap();
    assert_eq!(loaded.as_bytes(), b"second snapshot");
    assert!(!format!("{loaded:?}").contains("second snapshot"));

    let unexpected = state_path.parent().unwrap().join(".not-a-documented.tmp");
    tokio::fs::write(&unexpected, b"unexpected").await.unwrap();
    assert!(matches!(
        reloaded.session_states().await,
        Err(StoreError::UnexpectedEntry(path)) if path == unexpected
    ));
    tokio::fs::remove_file(unexpected).await.unwrap();

    let retired = reloaded.retire_session_state(session, context).await.unwrap();
    assert!(tokio::fs::metadata(&retired).await.unwrap().is_file());
    assert!(matches!(
        tokio::fs::metadata(reloaded.session_state_path(session, context)).await,
        Err(error) if error.kind() == io::ErrorKind::NotFound
    ));
    assert!(reloaded.session_states().await.unwrap().is_empty());
    #[cfg(unix)]
    assert_private_file(&retired).await;
}

#[tokio::test]
async fn avss_style_close_keeps_only_tombstone_and_finishes_crash_interrupted_destruction() {
    let directory = tempfile::tempdir().unwrap();
    let store = ProtocolStore::new(directory.path(), PartyId(1), &[9; 32]).unwrap();
    let session = session_id(11);
    let context = [12; 32];
    let purpose = b"test/current-session-closure/v1";
    store
        .save_session_state(session, context, b"secret dealer ciphertext outbox", &mut OsRng)
        .await
        .unwrap();
    let state_path = store.session_state_path(session, context);
    let pre_close_state = tokio::fs::read(&state_path).await.unwrap();

    store.close_session_state(session, context, purpose, &mut OsRng).await.unwrap();
    assert!(!tokio::fs::try_exists(&state_path).await.unwrap());
    assert_eq!(store.load_session_tombstone(session).await.unwrap().purpose(), purpose);
    store.close_session_state(session, context, purpose, &mut OsRng).await.unwrap();

    let filename = state_path.file_name().unwrap().to_str().unwrap();
    let stale_temporary =
        state_path.parent().unwrap().join(format!(".{filename}.{}.tmp", "ab".repeat(24)));
    tokio::fs::write(&stale_temporary, &pre_close_state).await.unwrap();
    store.destroy_tombstoned_session_state(session, context).await.unwrap();
    assert!(!tokio::fs::try_exists(&stale_temporary).await.unwrap());

    // Model a crash which persisted the tombstone but not the later directory deletion. Startup
    // authenticates both records, then finishes removing the secret snapshot instead of moving it
    // into the recoverable quarantine encrypted by the retained master seed.
    tokio::fs::write(&state_path, pre_close_state).await.unwrap();
    let restarted = ProtocolStore::new(directory.path(), PartyId(1), &[9; 32]).unwrap();
    restarted.destroy_tombstoned_session_state(session, context).await.unwrap();
    assert!(!tokio::fs::try_exists(&state_path).await.unwrap());
    assert!(matches!(
        restarted.save_session_state(session, context, b"resurrection", &mut OsRng).await,
        Err(StoreError::SessionTombstoned(found)) if found == session
    ));
}

#[tokio::test]
async fn rejects_tamper_trailing_bytes_wrong_party_seed_and_context() {
    let directory = tempfile::tempdir().unwrap();
    let store = ProtocolStore::new(directory.path(), PartyId(4), &[4; 32]).unwrap();
    let session = session_id(4);
    let context = [5; 32];
    let path = store.session_state_path(session, context);

    store.save_session_state(session, context, b"secret state bytes", &mut OsRng).await.unwrap();
    let original = tokio::fs::read(&path).await.unwrap();
    assert!(
        !original.windows(b"secret state bytes".len()).any(|part| part == b"secret state bytes")
    );

    let mut tampered = original.clone();
    *tampered.last_mut().unwrap() ^= 1;
    tokio::fs::write(&path, tampered).await.unwrap();
    assert!(matches!(
        store.load_session_state(session, context).await,
        Err(StoreError::Authentication)
    ));

    tokio::fs::write(&path, &original).await.unwrap();
    let mut with_trailing = original.clone();
    with_trailing.push(0);
    tokio::fs::write(&path, with_trailing).await.unwrap();
    assert!(matches!(
        store.load_session_state(session, context).await,
        Err(StoreError::TrailingBytes { trailing: 1, .. })
    ));

    tokio::fs::write(&path, &original).await.unwrap();
    let other_context = [6; 32];
    let other_path = store.session_state_path(session, other_context);
    tokio::fs::copy(&path, &other_path).await.unwrap();
    assert!(matches!(
        store.load_session_state(session, other_context).await,
        Err(StoreError::WrongContext)
    ));

    let other_party = ProtocolStore::new(directory.path(), PartyId(5), &[4; 32]).unwrap();
    other_party
        .save_session_state(session, context, b"party-five placeholder", &mut OsRng)
        .await
        .unwrap();
    tokio::fs::copy(&path, other_party.session_state_path(session, context)).await.unwrap();
    assert!(matches!(
        other_party.load_session_state(session, context).await,
        Err(StoreError::WrongContext)
    ));
    let other_seed = ProtocolStore::new(directory.path(), PartyId(4), &[7; 32]).unwrap();
    assert!(matches!(
        other_seed.load_session_state(session, context).await,
        Err(StoreError::Authentication)
    ));

    let mut oversized = vec![0_u8; MAX_SESSION_STATE_BYTES + 1];
    assert!(matches!(
        store.save_session_state(session_id(7), [7; 32], &oversized, &mut OsRng).await,
        Err(StoreError::BlobTooLarge { .. })
    ));
    oversized.resize(MAX_SESSION_STATE_BYTES + 16 + 1024 + 1, 0);
    let oversized_path = store.session_state_path(session_id(9), [9; 32]);
    tokio::fs::write(&oversized_path, oversized).await.unwrap();
    assert!(matches!(
        store.load_session_state(session_id(9), [9; 32]).await,
        Err(StoreError::BlobTooLarge { .. })
    ));
}

#[tokio::test]
async fn tombstones_are_permanent_idempotent_and_block_session_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let store = ProtocolStore::new(directory.path(), PartyId(2), &[2; 32]).unwrap();
    let session = session_id(8);
    let context = [8; 32];
    let purpose = b"frost-sign/transaction-input-0";

    let live_session = session_id(18);
    store.save_session_state(live_session, context, b"nonce journal", &mut OsRng).await.unwrap();
    assert!(matches!(
        store.save_session_tombstone(live_session, purpose, &mut OsRng).await,
        Err(StoreError::LiveSessionState(found)) if found == live_session
    ));
    store.save_session_tombstone(session, purpose, &mut OsRng).await.unwrap();
    store.save_session_tombstone(session, purpose, &mut OsRng).await.unwrap();

    let sealed = tokio::fs::read(store.session_tombstone_path(session)).await.unwrap();
    assert!(!sealed.windows(purpose.len()).any(|part| part == purpose));

    let tombstone = store.load_session_tombstone(session).await.unwrap();
    assert_eq!(tombstone.session(), session);
    assert_eq!(tombstone.purpose(), purpose);
    assert!(!format!("{tombstone:?}").contains("frost-sign"));
    assert_eq!(store.session_tombstones().await.unwrap(), vec![session]);

    assert!(matches!(
        store.save_session_tombstone(session, b"different-purpose", &mut OsRng).await,
        Err(StoreError::TombstoneConflict(found)) if found == session
    ));
    assert!(matches!(
        store.save_session_state(session, context, b"reused", &mut OsRng).await,
        Err(StoreError::SessionTombstoned(found)) if found == session
    ));

    // Generic tombstone creation and live state are mutually exclusive. AVSS uses the dedicated
    // atomic close path tested above when it must tombstone and destroy a live secret snapshot.
    assert!(!tokio::fs::try_exists(store.session_state_path(session, context)).await.unwrap());
    let reloaded = ProtocolStore::new(directory.path(), PartyId(2), &[2; 32]).unwrap();
    assert_eq!(reloaded.load_session_tombstone(session).await.unwrap().purpose(), purpose);
    #[cfg(unix)]
    assert_private_file(&reloaded.session_tombstone_path(session)).await;
}

#[tokio::test]
async fn activation_certificates_are_immutable_reload_and_bind_context() {
    let directory = tempfile::tempdir().unwrap();
    let store = ProtocolStore::new(directory.path(), PartyId(3), &[3; 32]).unwrap();
    let epoch = 11;
    let digest = [0xA1; 32];
    let transition = [0x91; 32];

    store
        .save_indexed_activation_certificate(
            epoch,
            transition,
            digest,
            b"final certificate",
            &mut OsRng,
        )
        .await
        .unwrap();
    store
        .save_indexed_activation_certificate(
            epoch,
            transition,
            digest,
            b"final certificate",
            &mut OsRng,
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .save_indexed_activation_certificate(
                epoch,
                transition,
                digest,
                b"conflicting certificate",
                &mut OsRng,
            )
            .await,
        Err(StoreError::ActivationCertificateConflict { .. })
    ));
    assert_eq!(
        store.load_activation_certificate(epoch, digest).await.unwrap().as_bytes(),
        b"final certificate"
    );
    assert_eq!(
        store.activation_certificates().await.unwrap(),
        vec![ActivationCertificateKey { epoch, activation_digest: digest }]
    );

    let reloaded = ProtocolStore::new(directory.path(), PartyId(3), &[3; 32]).unwrap();
    assert_eq!(
        reloaded.load_activation_certificate(epoch, digest).await.unwrap().as_bytes(),
        b"final certificate"
    );
    let other_digest = [0xB2; 32];
    let source = reloaded.activation_certificate_path(epoch, digest);
    let wrong_context = reloaded.activation_certificate_path(epoch, other_digest);
    tokio::fs::copy(&source, &wrong_context).await.unwrap();
    assert!(matches!(
        reloaded.load_activation_certificate(epoch, other_digest).await,
        Err(StoreError::WrongContext)
    ));
    tokio::fs::remove_file(wrong_context).await.unwrap();

    assert!(matches!(
        reloaded.retire_activation_certificate(epoch, digest).await,
        Err(StoreError::IndexedActivationCertificateRetirement { .. })
    ));
    assert!(tokio::fs::metadata(source).await.unwrap().is_file());
}

#[tokio::test]
async fn activation_transition_index_is_authenticated_idempotent_and_immutable() {
    let directory = tempfile::tempdir().unwrap();
    let store = ProtocolStore::new(directory.path(), PartyId(3), &[0x31; 32]).unwrap();
    let key = ActivationTransitionKey { epoch: 11, transition_digest: [0x41; 32] };
    let activation = [0x51; 32];
    store
        .save_indexed_activation_certificate(
            key.epoch,
            key.transition_digest,
            activation,
            b"certificate-a",
            &mut OsRng,
        )
        .await
        .unwrap();

    let index_path = store.activation_transition_index_path(key);
    let original_index = tokio::fs::read(&index_path).await.unwrap();
    let indexed = store.load_activation_certificate_for_transition(key).await.unwrap().unwrap();
    assert_eq!(
        indexed.key,
        ActivationCertificateKey { epoch: key.epoch, activation_digest: activation }
    );
    assert_eq!(indexed.certificate.as_bytes(), b"certificate-a");

    let other_transition =
        ActivationTransitionKey { epoch: key.epoch, transition_digest: [0x43; 32] };
    assert!(matches!(
        store
            .save_indexed_activation_certificate(
                other_transition.epoch,
                other_transition.transition_digest,
                activation,
                b"different-transition-same-activation",
                &mut OsRng,
            )
            .await,
        Err(StoreError::ActivationCertificateConflict {
            epoch,
            activation_digest,
        }) if epoch == key.epoch && activation_digest == activation
    ));
    assert!(
        !tokio::fs::try_exists(store.activation_transition_index_path(other_transition))
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .load_activation_certificate_for_transition(key)
            .await
            .unwrap()
            .unwrap()
            .certificate
            .as_bytes(),
        b"certificate-a"
    );

    store
        .save_indexed_activation_certificate(
            key.epoch,
            key.transition_digest,
            activation,
            b"certificate-a",
            &mut OsRng,
        )
        .await
        .unwrap();
    assert_eq!(tokio::fs::read(&index_path).await.unwrap(), original_index);

    let conflicting = [0x61; 32];
    assert!(matches!(
        store
            .save_indexed_activation_certificate(
                key.epoch,
                key.transition_digest,
                conflicting,
                b"certificate-b",
                &mut OsRng,
            )
            .await,
        Err(StoreError::ActivationIndexConflict { epoch, transition_digest })
            if epoch == key.epoch && transition_digest == key.transition_digest
    ));
    assert_eq!(tokio::fs::read(&index_path).await.unwrap(), original_index);

    let reloaded = ProtocolStore::new(directory.path(), PartyId(3), &[0x31; 32]).unwrap();
    assert_eq!(
        reloaded
            .load_activation_certificate_for_transition(key)
            .await
            .unwrap()
            .unwrap()
            .certificate
            .as_bytes(),
        b"certificate-a"
    );

    let copied_key = ActivationTransitionKey { epoch: key.epoch, transition_digest: [0x42; 32] };
    let copied_path = reloaded.activation_transition_index_path(copied_key);
    tokio::fs::copy(&index_path, &copied_path).await.unwrap();
    assert!(matches!(
        reloaded.load_activation_certificate_for_transition(copied_key).await,
        Err(StoreError::WrongContext)
    ));
    tokio::fs::remove_file(copied_path).await.unwrap();

    let mut tampered = original_index.clone();
    *tampered.last_mut().unwrap() ^= 1;
    tokio::fs::write(&index_path, tampered).await.unwrap();
    assert!(matches!(
        reloaded.load_activation_certificate_for_transition(key).await,
        Err(StoreError::Authentication)
    ));
    tokio::fs::write(&index_path, original_index).await.unwrap();

    assert!(matches!(
        reloaded.retire_activation_certificate(key.epoch, activation).await,
        Err(StoreError::IndexedActivationCertificateRetirement {
            epoch,
            activation_digest,
        }) if epoch == key.epoch && activation_digest == activation
    ));
}

#[tokio::test]
async fn exact_activation_transition_lookup_never_scans_unrelated_history() {
    let directory = tempfile::tempdir().unwrap();
    let store = ProtocolStore::new(directory.path(), PartyId(4), &[0x32; 32]).unwrap();
    let target = ActivationTransitionKey { epoch: 20, transition_digest: [0x71; 32] };
    let target_activation = [0x72; 32];
    store
        .save_indexed_activation_certificate(
            target.epoch,
            target.transition_digest,
            target_activation,
            b"target-certificate",
            &mut OsRng,
        )
        .await
        .unwrap();

    let unrelated = ActivationTransitionKey { epoch: 21, transition_digest: [0x81; 32] };
    let unrelated_activation = [0x82; 32];
    store
        .save_indexed_activation_certificate(
            unrelated.epoch,
            unrelated.transition_digest,
            unrelated_activation,
            b"unrelated-certificate",
            &mut OsRng,
        )
        .await
        .unwrap();
    let unrelated_certificate =
        store.activation_certificate_path(unrelated.epoch, unrelated_activation);
    let mut corrupt = tokio::fs::read(&unrelated_certificate).await.unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    tokio::fs::write(unrelated_certificate, corrupt).await.unwrap();

    let activation_directory = store.activation_certificate_path(0, [0; 32]);
    let activation_junk = activation_directory.parent().unwrap().join("unexpected-entry");
    tokio::fs::write(&activation_junk, b"junk").await.unwrap();
    let index_directory = store.activation_transition_index_path(target);
    let index_junk = index_directory.parent().unwrap().join("unexpected-entry");
    tokio::fs::write(&index_junk, b"junk").await.unwrap();

    let indexed = store.load_activation_certificate_for_transition(target).await.unwrap().unwrap();
    assert_eq!(indexed.certificate.as_bytes(), b"target-certificate");

    let incomplete = ActivationTransitionKey { epoch: 22, transition_digest: [0x91; 32] };
    store
        .save_indexed_activation_certificate(
            incomplete.epoch,
            incomplete.transition_digest,
            [0x92; 32],
            b"crash-incomplete",
            &mut OsRng,
        )
        .await
        .unwrap();
    tokio::fs::remove_file(store.activation_transition_index_path(incomplete)).await.unwrap();
    assert!(store.load_activation_certificate_for_transition(incomplete).await.unwrap().is_none());
    assert!(
        !tokio::fs::try_exists(store.activation_transition_index_path(incomplete)).await.unwrap()
    );

    match store.activation_certificates_bounded(2).await {
        Err(StoreError::UnexpectedEntry(path)) if path == activation_junk => {}
        Err(StoreError::ProtocolEntryLimit { kind: "activation certificate", maximum: 2 }) => {}
        other => panic!("unexpected bounded activation enumeration result: {other:?}"),
    }
    assert!(matches!(
        store.activation_transition_indexes_bounded(2).await,
        Err(StoreError::UnexpectedEntry(path)) if path == index_junk
    ));
}
