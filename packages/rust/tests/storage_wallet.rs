use std::io;

use rand_core::OsRng;
use threshold_monero::{
    PartyId,
    storage::{
        MAX_WALLET_SNAPSHOT_BYTES, ProtocolStore, StoreError, WalletId, WalletSnapshotStore,
    },
};

fn wallet(byte: u8) -> WalletId {
    WalletId([byte; 32])
}

#[cfg(unix)]
async fn assert_private(path: &std::path::Path, expected_mode: u32) {
    use std::os::unix::fs::PermissionsExt;

    let mode = tokio::fs::metadata(path).await.unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, expected_mode);
}

#[tokio::test]
async fn wallet_snapshots_round_trip_and_survive_a_stale_pre_rename_file() {
    let directory = tempfile::tempdir().unwrap();
    let store = WalletSnapshotStore::new(directory.path(), PartyId(1), &[0x11; 32]).unwrap();
    let wallet_id = wallet(1);

    let first = store
        .save_snapshot(wallet_id, 0, b"canonical postcard deposit state zero", &mut OsRng)
        .await
        .unwrap();
    assert_eq!(first.revision, 0);
    assert_eq!(first.previous_snapshot_hash, [0; 32]);
    let path = store.wallet_snapshot_path(wallet_id);
    assert!(path.starts_with(directory.path().join("wallet-snapshots-v1")));
    assert!(!path.starts_with(directory.path().join("protocol-v1")));
    let protocol = ProtocolStore::new(directory.path(), PartyId(1), &[0x11; 32]).unwrap();
    assert!(protocol.session_states().await.unwrap().is_empty());
    let sealed = tokio::fs::read(&path).await.unwrap();
    assert!(
        !sealed
            .windows(b"canonical postcard deposit state zero".len())
            .any(|part| part == b"canonical postcard deposit state zero")
    );

    // Model a crash after a private temporary file was fsynced but before its rename. The durable
    // destination remains the only authoritative snapshot.
    let filename = path.file_name().unwrap().to_str().unwrap();
    let stale = path.parent().unwrap().join(format!(".{filename}.{}.tmp", "00".repeat(24)));
    tokio::fs::write(&stale, b"uncommitted replacement").await.unwrap();
    let restarted = WalletSnapshotStore::new(directory.path(), PartyId(1), &[0x11; 32]).unwrap();
    assert_eq!(
        restarted.load_snapshot(wallet_id).await.unwrap().state.as_bytes(),
        b"canonical postcard deposit state zero"
    );

    let second = restarted
        .save_snapshot(wallet_id, 1, b"canonical postcard deposit state one", &mut OsRng)
        .await
        .unwrap();
    assert_eq!(second.previous_snapshot_hash, first.snapshot_hash);
    assert_ne!(second.snapshot_hash, first.snapshot_hash);

    // An exact retry after an uncertain response is idempotent and does not reseal the record.
    let committed_bytes = tokio::fs::read(&path).await.unwrap();
    assert_eq!(
        restarted
            .save_snapshot(wallet_id, 1, b"canonical postcard deposit state one", &mut OsRng)
            .await
            .unwrap(),
        second
    );
    assert_eq!(tokio::fs::read(&path).await.unwrap(), committed_bytes);

    #[cfg(unix)]
    {
        assert_private(restarted.wallet_directory(), 0o700).await;
        assert_private(&path, 0o600).await;
    }
}

#[tokio::test]
async fn wallet_snapshot_rejects_tamper_trailing_bytes_and_wrong_context() {
    let directory = tempfile::tempdir().unwrap();
    let store = WalletSnapshotStore::new(directory.path(), PartyId(4), &[0x44; 32]).unwrap();
    let wallet_id = wallet(4);
    store.save_snapshot(wallet_id, 0, b"private wallet state", &mut OsRng).await.unwrap();
    let path = store.wallet_snapshot_path(wallet_id);
    let original = tokio::fs::read(&path).await.unwrap();

    let mut tampered = original.clone();
    *tampered.last_mut().unwrap() ^= 1;
    tokio::fs::write(&path, tampered).await.unwrap();
    let fresh = WalletSnapshotStore::new(directory.path(), PartyId(4), &[0x44; 32]).unwrap();
    assert!(matches!(fresh.load_snapshot(wallet_id).await, Err(StoreError::Authentication)));

    let mut trailing = original.clone();
    trailing.push(0);
    tokio::fs::write(&path, trailing).await.unwrap();
    let fresh = WalletSnapshotStore::new(directory.path(), PartyId(4), &[0x44; 32]).unwrap();
    assert!(matches!(
        fresh.load_snapshot(wallet_id).await,
        Err(StoreError::TrailingBytes { trailing: 1, .. })
    ));
    tokio::fs::write(&path, &original).await.unwrap();

    let wrong_wallet = wallet(5);
    let wrong_wallet_path = store.wallet_snapshot_path(wrong_wallet);
    tokio::fs::copy(&path, &wrong_wallet_path).await.unwrap();
    assert!(matches!(store.load_snapshot(wrong_wallet).await, Err(StoreError::WrongContext)));

    let wrong_seed = WalletSnapshotStore::new(directory.path(), PartyId(4), &[0x45; 32]).unwrap();
    assert!(matches!(wrong_seed.load_snapshot(wallet_id).await, Err(StoreError::Authentication)));

    let other_party = WalletSnapshotStore::new(directory.path(), PartyId(5), &[0x44; 32]).unwrap();
    other_party.save_snapshot(wallet_id, 0, b"party five placeholder", &mut OsRng).await.unwrap();
    tokio::fs::copy(&path, other_party.wallet_snapshot_path(wallet_id)).await.unwrap();
    assert!(matches!(other_party.load_snapshot(wallet_id).await, Err(StoreError::WrongContext)));

    let oversized_plaintext = vec![0_u8; MAX_WALLET_SNAPSHOT_BYTES + 1];
    assert!(matches!(
        store
            .save_snapshot(wallet(0x60), 0, &oversized_plaintext, &mut OsRng)
            .await,
        Err(StoreError::BlobTooLarge {
            kind: "wallet snapshot",
            actual,
            maximum: MAX_WALLET_SNAPSHOT_BYTES,
        }) if actual == MAX_WALLET_SNAPSHOT_BYTES + 1
    ));

    let oversized_wallet = wallet(6);
    let oversized_path = store.wallet_snapshot_path(oversized_wallet);
    let oversized = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&oversized_path)
        .await
        .unwrap();
    oversized
        .set_len(u64::try_from(MAX_WALLET_SNAPSHOT_BYTES + 16 + 1024 + 1).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        store.load_snapshot(oversized_wallet).await,
        Err(StoreError::BlobTooLarge { .. })
    ));
}

#[tokio::test]
async fn wallet_revisions_are_sequential_idempotent_and_rollback_fenced_in_process() {
    let directory = tempfile::tempdir().unwrap();
    let store = WalletSnapshotStore::new(directory.path(), PartyId(7), &[0x77; 32]).unwrap();
    let wallet_id = wallet(7);

    assert!(matches!(
        store.save_snapshot(wallet_id, 1, b"skipped genesis", &mut OsRng).await,
        Err(StoreError::WalletRevisionMustStartAtZero { actual: 1, .. })
    ));
    let zero = store.save_snapshot(wallet_id, 0, b"revision zero", &mut OsRng).await.unwrap();
    let zero_record = tokio::fs::read(store.wallet_snapshot_path(wallet_id)).await.unwrap();

    assert!(matches!(
        store.save_snapshot(wallet_id, 0, b"revision zero fork", &mut OsRng).await,
        Err(StoreError::WalletRevisionConflict { revision: 0, .. })
    ));
    assert!(matches!(
        store.save_snapshot(wallet_id, 2, b"revision two", &mut OsRng).await,
        Err(StoreError::WalletRevisionNotNext { expected: 1, actual: 2, .. })
    ));

    let one = store.save_snapshot(wallet_id, 1, b"revision one", &mut OsRng).await.unwrap();
    assert_eq!(one.previous_snapshot_hash, zero.snapshot_hash);
    let one_record = tokio::fs::read(store.wallet_snapshot_path(wallet_id)).await.unwrap();

    tokio::fs::write(store.wallet_snapshot_path(wallet_id), &zero_record).await.unwrap();
    assert!(matches!(
        store.load_snapshot(wallet_id).await,
        Err(StoreError::WalletRollbackDetected { highest_seen: 1, found: 0, .. })
    ));

    tokio::fs::write(store.wallet_snapshot_path(wallet_id), &one_record).await.unwrap();
    assert_eq!(store.load_snapshot(wallet_id).await.unwrap().metadata, one);
    tokio::fs::remove_file(store.wallet_snapshot_path(wallet_id)).await.unwrap();
    assert!(matches!(
        store.load_snapshot(wallet_id).await,
        Err(StoreError::WalletSnapshotDisappeared { highest_seen: 1, .. })
    ));

    // A fresh process has no trusted high-water mark. An external monotonic/WORM anchor is needed
    // to detect restoration of a whole volume across process restarts.
    tokio::fs::write(store.wallet_snapshot_path(wallet_id), zero_record).await.unwrap();
    let no_external_fence =
        WalletSnapshotStore::new(directory.path(), PartyId(7), &[0x77; 32]).unwrap();
    assert_eq!(no_external_fence.load_snapshot(wallet_id).await.unwrap().metadata, zero);
}

#[tokio::test]
async fn wallet_hash_chain_rejects_discontinuity_and_same_revision_forks() {
    let directory_a = tempfile::tempdir().unwrap();
    let directory_b = tempfile::tempdir().unwrap();
    let directory_c = tempfile::tempdir().unwrap();
    let wallet_id = wallet(9);
    let store_a = WalletSnapshotStore::new(directory_a.path(), PartyId(9), &[0x99; 32]).unwrap();
    let store_b = WalletSnapshotStore::new(directory_b.path(), PartyId(9), &[0x99; 32]).unwrap();
    let store_c = WalletSnapshotStore::new(directory_c.path(), PartyId(9), &[0x99; 32]).unwrap();

    store_a.save_snapshot(wallet_id, 0, b"chain A zero", &mut OsRng).await.unwrap();
    let a_zero_record = tokio::fs::read(store_a.wallet_snapshot_path(wallet_id)).await.unwrap();
    store_b.save_snapshot(wallet_id, 0, b"chain B zero", &mut OsRng).await.unwrap();
    store_b.save_snapshot(wallet_id, 1, b"chain B one", &mut OsRng).await.unwrap();
    tokio::fs::copy(
        store_b.wallet_snapshot_path(wallet_id),
        store_a.wallet_snapshot_path(wallet_id),
    )
    .await
    .unwrap();
    assert!(matches!(
        store_a.load_snapshot(wallet_id).await,
        Err(StoreError::WalletHashChainMismatch { revision: 1, .. })
    ));

    tokio::fs::write(store_a.wallet_snapshot_path(wallet_id), &a_zero_record).await.unwrap();
    let a_one = store_a.save_snapshot(wallet_id, 1, b"chain A one", &mut OsRng).await.unwrap();
    store_c.save_snapshot(wallet_id, 0, b"chain A zero", &mut OsRng).await.unwrap();
    let c_one = store_c.save_snapshot(wallet_id, 1, b"chain A one fork", &mut OsRng).await.unwrap();
    assert_ne!(a_one.snapshot_hash, c_one.snapshot_hash);
    tokio::fs::copy(
        store_c.wallet_snapshot_path(wallet_id),
        store_a.wallet_snapshot_path(wallet_id),
    )
    .await
    .unwrap();
    assert!(matches!(
        store_a.load_snapshot(wallet_id).await,
        Err(StoreError::WalletForkDetected { revision: 1, .. })
    ));

    // Keep the imported `io` meaningful on every target and assert the missing-file API remains a
    // normal I/O error before any high-water mark has been observed.
    let absent = wallet(10);
    assert!(matches!(
        store_a.load_snapshot(absent).await,
        Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound
    ));
}
