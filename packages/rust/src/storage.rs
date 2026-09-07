//! Encrypted, crash-consistent persistence for epoch shares and protocol state.

use std::{
    collections::BTreeMap,
    io,
    ops::Deref,
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    committee::{PartyId, SessionId},
    deposit_wallet::{DepositWalletId, SweepId, derive_sweep_signing_session},
    identity::{EpochEncryptionSecret, Identity, IdentityError, PersistedKeyAdvertisementIdentity},
    key_rotation::{
        KeyRotationCertificate, KeyRotationContext, KeyRotationError, KeyRotationRound,
        MAX_KEY_ROTATION_CERTIFICATE_BYTES, MAX_KEY_ROTATION_ROUND_STATE_BYTES,
    },
    keys::{EpochShare, EpochShareMaterial, KeyError},
};

const SHARE_RECORD_VERSION: u16 = 2;
const PROTOCOL_STORE_VERSION: u16 = 2;
const WALLET_SNAPSHOT_STORE_VERSION: u16 = 1;
const WALLET_ARTIFACT_STORE_VERSION: u16 = 2;
const WALLET_ARTIFACT_RESERVATION_VERSION: u16 = 1;
const PROTOCOL_DIRECTORY: &str = "protocol-v2";
const WALLET_SNAPSHOT_DIRECTORY: &str = "wallet-snapshots-v1";
const WALLET_ARTIFACT_DIRECTORY: &str = "wallet-artifacts-v2";
const PARTY_STATE_LEASE_FILE_PREFIX: &str = ".party-state-";
const PARTY_STATE_LEASE_FILE_SUFFIX: &str = ".lock";
const SESSION_NAMESPACE_LOCK_FILE: &str = ".session-namespace.lock";
const SESSION_STATE_DIRECTORY: &str = "sessions";
const TOMBSTONE_DIRECTORY: &str = "tombstones";
const ACTIVATION_DIRECTORY: &str = "activations";
const ACTIVATION_INDEX_DIRECTORY: &str = "activation-indexes";
const KEY_ROTATION_ROUND_DIRECTORY: &str = "key-rotation-rounds";
const KEY_ROTATION_CERTIFICATE_DIRECTORY: &str = "key-rotation-certificates";
const SWEEP_SIGNING_HIGH_WATER_DIRECTORY: &str = "sweep-signing-high-water";
const DEPOSIT_INDEX_JOURNAL_DIRECTORY: &str = "deposit-index-journals";
const DEPOSIT_SYNC_SPOOL_HEAD_DIRECTORY: &str = "deposit-sync-spool-heads-v1";
const DEPOSIT_STATE_TRANSFER_INTENTS_FILE: &str = "deposit-state-transfer-intents-v1";
const EPOCH_IDENTITY_DIRECTORY: &str = "epoch-identities";
const REFRESH_SCHEDULE_FILE: &str = "proactive-refresh-schedule";
const RETIRED_DIRECTORY: &str = "retired";
const ACTIVATION_INDEX_VERSION: u16 = 1;
const KEY_ROTATION_SNAPSHOT_VERSION: u16 = 2;
const EPOCH_IDENTITY_RECORD_VERSION: u16 = 2;
const SWEEP_SIGNING_HIGH_WATER_VERSION: u16 = 1;
const EPOCH_IDENTITY_CERTIFICATION_VERSION: u16 = 3;
const DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_VERSION: u16 = 1;
const DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_VERSION: u16 = 1;
const AEAD_TAG_BYTES: usize = 16;
const MAX_RECORD_OVERHEAD_BYTES: usize = 1024;
const MAX_SHARE_FILE_BYTES: usize = 16 * 1024 * 1024;
const KEY_ROTATION_SNAPSHOT_HEADER_BYTES: usize = 1 + 2 + 8 + 32 + 32 + 8;
const MAX_KEY_ROTATION_SNAPSHOT_BYTES: usize =
    MAX_KEY_ROTATION_ROUND_STATE_BYTES + KEY_ROTATION_SNAPSHOT_HEADER_BYTES;
const DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_HEADER_BYTES: usize = 2 + 8 + 32 + 32 + 8;
const MAX_DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_BYTES: usize =
    MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES + DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_HEADER_BYTES;
const DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_HEADER_BYTES: usize = 2 + 8 + 32 + 32 + 8;
const MAX_DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_BYTES: usize =
    MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES + DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_HEADER_BYTES;
const MAX_EPOCH_IDENTITY_RECORD_BYTES: usize = 320;
const MAX_SWEEP_SIGNING_HIGH_WATER_BYTES: usize = 256;

/// Hard bound on one decrypted durable state-machine snapshot.
pub const MAX_SESSION_STATE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of uncertified AVSS reducers admitted by the live protocol.
///
/// `server` must use this same exported value for live admission.
pub const MAX_LIVE_AVSS_RUNS: usize = 64;
/// Number of authenticated epoch-history entries retained in the hot suffix.
///
/// `server` must use this same exported value when it constructs the epoch-history reducer.
pub const EPOCH_HISTORY_HOT_ENTRIES: u16 = 64;
/// The current epoch and its in-flight successor can both sit beyond the compact hot suffix.
pub const EPOCH_HISTORY_CURRENT_SUFFIX_RECORDS: usize = 2;
/// Maximum number of certificate-finalized AVSS reducers which may still be draining.
pub const MAX_CURRENT_EPOCH_RECORDS: usize =
    match (EPOCH_HISTORY_HOT_ENTRIES as usize).checked_add(EPOCH_HISTORY_CURRENT_SUFFIX_RECORDS) {
        Some(maximum) => maximum,
        None => panic!("current epoch record bound overflowed"),
    };
/// Fixed opaque records used by the consolidation, consolidation-bootstrap, protocol-fault,
/// driver-latch, and deposit-checkpoint acceptance gates.
pub const MAX_FIXED_SESSION_STATE_RECORDS: usize = 5;
/// Maximum legitimate number of active encrypted records in the session-state directory.
///
/// The three terms are disjoint: uncertified live AVSS reducers, certificate-finalized reducers
/// retained by the bounded hot-history suffix while their outboxes drain, and fixed acceptance
/// records. Checked construction makes additions to any protocol class fail at compile time on
/// overflow instead of silently weakening the traversal bound.
pub const MAX_SESSION_STATE_RECORDS: usize =
    match MAX_LIVE_AVSS_RUNS.checked_add(MAX_CURRENT_EPOCH_RECORDS) {
        Some(maximum) => match maximum.checked_add(MAX_FIXED_SESSION_STATE_RECORDS) {
            Some(maximum) => maximum,
            None => panic!("session state record bound overflowed"),
        },
        None => panic!("session state record bound overflowed"),
    };
/// Hard bound on the purpose attached to a permanent session tombstone.
pub const MAX_SESSION_TOMBSTONE_PURPOSE_BYTES: usize = 1024;
/// Hard bound on one durable epoch-activation certificate.
pub const MAX_ACTIVATION_CERTIFICATE_BYTES: usize = 8 * 1024 * 1024;
/// Hard bound on one authenticated transition-to-activation index entry.
pub const MAX_ACTIVATION_INDEX_BYTES: usize = 128;
/// Hard bound on the authenticated proactive-refresh pacemaker record.
pub const MAX_REFRESH_SCHEDULE_BYTES: usize = 1024;
/// Hard bound on one decrypted wallet/deposit state snapshot.
///
/// This intentionally matches the deposit reducer's maximum canonical postcard encoding.
pub const MAX_WALLET_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
/// Hard bound on one immutable wallet artifact.
///
/// This is a per-object resource bound, not a bound on a wallet's lifetime archive. A wallet may
/// reference any number of independently authenticated artifacts from its compact snapshot head.
pub const MAX_WALLET_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_WALLET_ARTIFACT_RESERVATION_BYTES: usize = 4 * 1024;
const MAX_TEMPORARY_REPLACEMENTS_PER_DESTINATION: usize = 64;
/// Hard bound on one exact staged deposit-index transition journal.
pub const MAX_DEPOSIT_INDEX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;
/// Hard bound on one canonical durable deposit-sync spool head.
///
/// Object plaintext and immutable page metadata live outside this compact CAS record, so this is
/// a per-head bound rather than a lifetime candidate-size limit.
/// The authenticated spool head may carry a worst-case 2 MiB traversal/verifier cursor plus
/// fixed-size committee claims, release intents, and one bounded page journal.
pub const MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES: usize = 3 * 1024 * 1024;
/// Hard bound on the opaque durable QUIC state-transfer intent snapshot.
///
/// The runtime admits at most one exact intent per configured remote recipient. Its own decoder
/// applies that semantic count bound; this storage boundary independently caps ciphertext,
/// decrypted allocation, and authenticated readback.
pub const MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES: usize = 128 * 1024;

/// Stable application-defined identifier for one threshold wallet.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletId(pub [u8; 32]);

/// One of the two independently rooted deposit-index namespaces.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DepositIndexJournalScope {
    Portable,
    LocalSafety,
}

/// Fixed, restart-derivable key for one pending deposit-index successor.
///
/// The expected head digest and revision bind the journal to the exact authoritative old head.
/// A startup path therefore probes at most one key per scope and never enumerates historical
/// journal files.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DepositIndexJournalKey {
    pub wallet_id: WalletId,
    pub scope: DepositIndexJournalScope,
    pub expected_revision: u64,
    pub expected_head_digest: [u8; 32],
}

impl DepositIndexJournalKey {
    pub fn validate(self) -> Result<(), StoreError> {
        if self.wallet_id.0 == [0_u8; 32] || self.expected_head_digest == [0_u8; 32] {
            return Err(StoreError::InvalidDepositIndexJournalKey);
        }
        Ok(())
    }
}

/// Fixed, restart-derivable key for one candidate namespace's non-authoritative spool head.
///
/// The network binding prevents a candidate downloaded under one QUIC trust domain from being
/// opened under another. The caller supplies an exact advertisement-bound namespace, within which
/// there is one derivable record path per `(network_id, wallet_id)` pair. Recovery never derives a
/// filename from peer-controlled bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DepositSyncSpoolHeadKey {
    pub network_id: [u8; 32],
    pub wallet_id: DepositWalletId,
}

impl DepositSyncSpoolHeadKey {
    pub fn validate(self) -> Result<(), StoreError> {
        if self.network_id == [0_u8; 32] || self.wallet_id.0 == [0_u8; 32] {
            return Err(StoreError::InvalidDepositSyncSpoolHeadKey);
        }
        Ok(())
    }
}

/// Authenticated position in one compact spool head's revision/hash chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepositSyncSpoolHeadMetadata {
    pub key: DepositSyncSpoolHeadKey,
    pub revision: u64,
    pub previous_snapshot_hash: [u8; 32],
    pub snapshot_hash: [u8; 32],
}

/// One authenticated opaque deposit-sync spool head and its durable CAS position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositSyncSpoolHeadBlob {
    pub metadata: DepositSyncSpoolHeadMetadata,
    pub state: ProtocolBlob,
}

/// Authenticated position in the fixed network-bound state-transfer intent hash chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepositStateTransferIntentsMetadata {
    pub network_id: [u8; 32],
    pub revision: u64,
    pub previous_snapshot_hash: [u8; 32],
    pub snapshot_hash: [u8; 32],
}

/// One authenticated opaque state-transfer intent snapshot and its durable CAS position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositStateTransferIntentsBlob {
    pub metadata: DepositStateTransferIntentsMetadata,
    pub state: ProtocolBlob,
}

/// Authenticated position in a wallet snapshot's revision/hash chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletSnapshotMetadata {
    pub wallet_id: WalletId,
    pub revision: u64,
    pub previous_snapshot_hash: [u8; 32],
    pub snapshot_hash: [u8; 32],
}

/// Decrypted wallet bytes which zeroize on drop and redact their contents from `Debug`.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct WalletSnapshotBlob(Vec<u8>);

impl WalletSnapshotBlob {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Transfer ownership of the decrypted bytes to the caller.
    ///
    /// The returned `Vec` no longer benefits from this type's zeroize-on-drop behavior.
    #[must_use]
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl AsRef<[u8]> for WalletSnapshotBlob {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Deref for WalletSnapshotBlob {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl std::fmt::Debug for WalletSnapshotBlob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("WalletSnapshotBlob").field("length", &self.len()).finish()
    }
}

/// One authenticated wallet snapshot and its chain position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletSnapshot {
    pub metadata: WalletSnapshotMetadata,
    pub state: WalletSnapshotBlob,
}

/// Stable application-defined kind tag for an immutable wallet artifact.
///
/// Zero is reserved so a default/uninitialized tag cannot become durable protocol context.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletArtifactKind(pub u16);

impl WalletArtifactKind {
    #[must_use]
    pub const fn tag(self) -> u16 {
        self.0
    }
}

/// Portable content address for one immutable encrypted wallet artifact.
///
/// The digest commits to the wallet, kind, exact plaintext length, and exact plaintext bytes. It
/// intentionally excludes the local party so independently persisted replicas derive the same
/// reference while encrypting it under different per-party keys.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct WalletArtifactRef {
    version: u16,
    wallet_id: WalletId,
    kind: WalletArtifactKind,
    plaintext_len: u64,
    digest: [u8; 32],
}

impl WalletArtifactRef {
    /// Derive a portable content address without writing local storage.
    pub fn for_contents(
        wallet_id: WalletId,
        kind: WalletArtifactKind,
        contents: &[u8],
    ) -> Result<Self, StoreError> {
        if kind.0 == 0 || contents.is_empty() {
            return Err(StoreError::InvalidWalletArtifactReference);
        }
        if contents.len() > MAX_WALLET_ARTIFACT_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "wallet artifact",
                actual: contents.len(),
                maximum: MAX_WALLET_ARTIFACT_BYTES,
            });
        }
        let plaintext_len = u64::try_from(contents.len()).map_err(|_| StoreError::Serialization)?;
        Ok(Self {
            version: WALLET_ARTIFACT_STORE_VERSION,
            wallet_id,
            kind,
            plaintext_len,
            digest: wallet_artifact_hash(wallet_id, kind, plaintext_len, contents),
        })
    }

    /// Reconstruct a transferred current-format content address before loading and authenticating
    /// its exact bytes. This does not trust the digest: [`WalletArtifactStore::load_artifact`]
    /// recomputes it after AEAD verification.
    pub fn from_parts(
        wallet_id: WalletId,
        kind: WalletArtifactKind,
        plaintext_len: u64,
        digest: [u8; 32],
    ) -> Result<Self, StoreError> {
        let reference =
            Self { version: WALLET_ARTIFACT_STORE_VERSION, wallet_id, kind, plaintext_len, digest };
        reference.validate()?;
        if wallet_id.0 == [0_u8; 32] || digest == [0_u8; 32] {
            return Err(StoreError::InvalidWalletArtifactReference);
        }
        Ok(reference)
    }

    /// Prove that assembled plaintext bytes exactly match this wallet-bound reference.
    pub fn verify_contents(self, contents: &[u8]) -> Result<(), StoreError> {
        self.validate()?;
        let actual_len = u64::try_from(contents.len()).map_err(|_| StoreError::Serialization)?;
        if actual_len != self.plaintext_len
            || wallet_artifact_hash(self.wallet_id, self.kind, actual_len, contents) != self.digest
        {
            return Err(StoreError::Authentication);
        }
        Ok(())
    }

    #[must_use]
    pub const fn wallet_id(self) -> WalletId {
        self.wallet_id
    }

    #[must_use]
    pub const fn kind(self) -> WalletArtifactKind {
        self.kind
    }

    #[must_use]
    pub const fn plaintext_len(self) -> u64 {
        self.plaintext_len
    }

    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn validate(self) -> Result<(), StoreError> {
        if self.version != WALLET_ARTIFACT_STORE_VERSION
            || self.kind.0 == 0
            || self.plaintext_len == 0
        {
            return Err(StoreError::InvalidWalletArtifactReference);
        }
        Ok(())
    }
}

/// Durable owner identity for one journal-before-write immutable-artifact batch.
///
/// The random identity is serialized into the batch's authenticated journal before the first
/// artifact reservation or write. Artifact cleanup is authorized only by an exact matching
/// reservation, so a failed batch cannot unlink content installed by a pre-existing or racing
/// writer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletArtifactOwner([u8; 32]);

impl WalletArtifactOwner {
    /// Generate a fresh batch owner which must be persisted in the batch journal before use.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let mut owner = [0_u8; 32];
            rng.fill_bytes(&mut owner);
            if owner != [0_u8; 32] {
                return Self(owner);
            }
        }
    }

    pub(crate) fn validate(self) -> Result<(), StoreError> {
        if self.0 == [0_u8; 32] {
            return Err(StoreError::InvalidWalletArtifactOwner);
        }
        Ok(())
    }
}

/// Whether an owner-aware install created/resumed an owned object or found stable pre-existing
/// content which must never be removed by this batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletArtifactOwnership {
    Owned,
    PreExisting,
}

/// Decrypted immutable artifact bytes which zeroize on drop and redact contents from `Debug`.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct WalletArtifactBlob(Vec<u8>);

impl WalletArtifactBlob {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl AsRef<[u8]> for WalletArtifactBlob {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Deref for WalletArtifactBlob {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl std::fmt::Debug for WalletArtifactBlob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("WalletArtifactBlob").field("length", &self.len()).finish()
    }
}

/// One authenticated immutable wallet artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletArtifact {
    pub reference: WalletArtifactRef,
    pub contents: WalletArtifactBlob,
    storage_owner: Option<WalletArtifactOwner>,
}

impl WalletArtifact {
    #[must_use]
    pub(crate) const fn storage_owner(&self) -> Option<WalletArtifactOwner> {
        self.storage_owner
    }
}

/// Process-lifetime exclusive ownership of one party's mutable state directory.
///
/// The lock inode is permanent and scoped by `(state_directory, party)`. Construct this before
/// opening any mutable store, retain it for the complete server lifetime, and never delete its
/// path. Advisory locks are released automatically by the operating system after process death;
/// normal drop explicitly unlocks the still-open inode.
pub struct PartyStateLease {
    path: PathBuf,
    party: PartyId,
    file: std::fs::File,
}

impl PartyStateLease {
    /// Acquire this party's exclusive state-directory writer lease without waiting.
    ///
    /// A second process or independently opened lease fails with
    /// [`StoreError::PartyStateLeaseHeld`]. An existing symlink, directory, or other non-regular
    /// lock target is rejected rather than followed.
    pub async fn acquire(
        state_directory: impl Into<PathBuf>,
        party: PartyId,
    ) -> Result<Self, StoreError> {
        let state_directory = state_directory.into();
        ensure_private_directory(&state_directory).await?;
        let state_directory = tokio::fs::canonicalize(&state_directory).await?;
        require_directory(&state_directory).await?;
        let path = party_state_lease_path(&state_directory, party);
        let open_path = path.clone();
        let (file, created) =
            tokio::task::spawn_blocking(move || -> Result<(std::fs::File, bool), StoreError> {
                let (file, created) = match open_party_state_lease_create_new(&open_path) {
                    Ok(file) => (file, true),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        let link_metadata = std::fs::symlink_metadata(&open_path)?;
                        if !link_metadata.is_file() {
                            return Err(StoreError::NotRegularFile(open_path));
                        }
                        let file =
                            std::fs::OpenOptions::new().read(true).write(true).open(&open_path)?;
                        let opened_metadata = file.metadata()?;
                        let current_link_metadata = std::fs::symlink_metadata(&open_path)?;
                        if !opened_metadata.is_file()
                            || !current_link_metadata.is_file()
                            || !same_file_identity(&opened_metadata, &current_link_metadata)
                        {
                            return Err(StoreError::NotRegularFile(open_path));
                        }
                        (file, false)
                    }
                    Err(error) => return Err(error.into()),
                };
                if created {
                    file.sync_all()?;
                }
                match file.try_lock() {
                    Ok(()) => Ok((file, created)),
                    Err(std::fs::TryLockError::WouldBlock) => {
                        Err(StoreError::PartyStateLeaseHeld { party, path: open_path })
                    }
                    Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
                }
            })
            .await
            .map_err(io::Error::other)??;
        if created {
            sync_directory(&state_directory).await?;
        }
        Ok(Self { path, party, file })
    }

    /// Canonical path of the permanent lock inode.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn party(&self) -> PartyId {
        self.party
    }
}

impl Drop for PartyStateLease {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl std::fmt::Debug for PartyStateLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PartyStateLease")
            .field("path", &self.path)
            .field("party", &self.party)
            .finish_non_exhaustive()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ShareStore {
    #[zeroize(skip)]
    directory: PathBuf,
    #[zeroize(skip)]
    party: PartyId,
    key: [u8; 32],
    #[zeroize(skip)]
    mutation: Mutex<()>,
}

impl std::fmt::Debug for ShareStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareStore")
            .field("directory", &self.directory)
            .field("party", &self.party)
            .finish_non_exhaustive()
    }
}

/// Independently keyed store for crash-recoverable protocol state and certificates.
///
/// The directory is namespaced below the supplied base path. `ProtocolStore` is intentionally a
/// single-writer object within one process; its mutation methods serialize through an internal
/// lock. Atomic file replacement still makes readers and process crashes observe either the old
/// complete record or the new complete record.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProtocolStore {
    #[zeroize(skip)]
    directory: PathBuf,
    #[zeroize(skip)]
    party: PartyId,
    key: [u8; 32],
    #[zeroize(skip)]
    mutation: Mutex<ProtocolMutationState>,
}

#[derive(Default)]
struct ProtocolMutationState {
    /// Highest authenticated key-rotation head observed by this process. This is the same local
    /// rollback fence used by wallet snapshots; complete-volume rollback after restart still
    /// requires an external monotonic anchor.
    key_rotation_heads: BTreeMap<KeyRotationRoundKey, KeyRotationRoundMetadata>,
    /// Highest authenticated per-sweep nonce attempt observed by this process. This detects file
    /// deletion, rollback and same-attempt forks while running; complete-volume rollback after a
    /// restart still requires the deployment's external monotonic anchor.
    sweep_signing_high_waters: BTreeMap<(DepositWalletId, SweepId), SweepSigningHighWater>,
    /// Highest authenticated deposit-sync spool head observed by this process. A successful exact
    /// destruction removes this entry so the same candidate namespace can start a fresh chain.
    deposit_sync_spool_heads: BTreeMap<DepositSyncSpoolHeadKey, DepositSyncSpoolHeadMetadata>,
    /// Highest authenticated fixed state-transfer-intent head observed for each transport trust
    /// domain. Intent snapshots are never deleted, including when their opaque state is empty.
    deposit_state_transfer_intents: BTreeMap<[u8; 32], DepositStateTransferIntentsMetadata>,
    retired_epoch_identities: BTreeMap<u64, EpochIdentityRetirement>,
}

impl std::fmt::Debug for ProtocolStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtocolStore")
            .field("directory", &self.directory)
            .field("party", &self.party)
            .finish_non_exhaustive()
    }
}

/// Independently keyed, crash-consistent storage for wallet/deposit reducer snapshots.
///
/// Wallet files live outside `ProtocolStore`'s session tree and therefore can never be mistaken
/// for AVSS/signing session state. A store instance is a single writer and remembers the highest
/// authenticated revision/hash it has observed. That catches rollback, deletion, and same-revision
/// forks while the process remains alive. Atomic replacement and directory fsync make a crash
/// expose either the previous complete snapshot or the replacement.
///
/// This in-process fence cannot detect restoration of an older *entire volume* after a process
/// restart. Production deployments must anchor `(wallet_id, revision, snapshot_hash)` in an
/// external monotonic counter, transparency log, or WORM store before treating rollback resistance
/// as complete.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WalletSnapshotStore {
    #[zeroize(skip)]
    directory: PathBuf,
    #[zeroize(skip)]
    party: PartyId,
    key: [u8; 32],
    #[zeroize(skip)]
    mutation: Mutex<BTreeMap<WalletId, WalletSnapshotMetadata>>,
}

/// Independently keyed content-addressed storage for an unbounded sequence of wallet artifacts.
///
/// Every object is installed with create-new semantics and fsynced before this API returns. An
/// existing content address is accepted only after authenticated decryption proves exact plaintext
/// equality. Compact snapshot heads may therefore safely reference a returned artifact.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WalletArtifactStore {
    #[zeroize(skip)]
    directory: PathBuf,
    #[zeroize(skip)]
    party: PartyId,
    key: [u8; 32],
    #[zeroize(skip)]
    mutation: Mutex<()>,
}

struct WalletArtifactNamespaceLock(std::fs::File);

impl Drop for WalletArtifactNamespaceLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// Cross-instance serialization for check-then-mutate operations in the session namespace.
///
/// `ProtocolStore`'s Tokio mutex protects one handle. This permanent advisory lock also protects
/// independently constructed handles and processes which correctly use the storage API.
struct SessionNamespaceLock(std::fs::File);

impl Drop for SessionNamespaceLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

impl std::fmt::Debug for WalletArtifactStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WalletArtifactStore")
            .field("directory", &self.directory)
            .field("party", &self.party)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for WalletSnapshotStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WalletSnapshotStore")
            .field("directory", &self.directory)
            .field("party", &self.party)
            .finish_non_exhaustive()
    }
}

/// Stable lookup key for an opaque session-state snapshot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionStateKey {
    pub session: SessionId,
    pub context_digest: [u8; 32],
}

/// One authenticated active session-state snapshot.
///
/// Restoration returns these bytes directly so callers never enumerate, authenticate, discard,
/// and then reopen the same secret-bearing record.
#[derive(Debug, Eq, PartialEq)]
pub struct StoredSessionState {
    pub session: SessionId,
    pub context_digest: [u8; 32],
    pub state: ProtocolBlob,
}

/// Stable lookup key for an epoch activation certificate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActivationCertificateKey {
    pub epoch: u64,
    pub activation_digest: [u8; 32],
}

/// Content-addressed lookup key for one canonical AVSS transition.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActivationTransitionKey {
    pub epoch: u64,
    pub transition_digest: [u8; 32],
}

/// Stable lookup key for one source-to-successor X25519 key-rotation round.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyRotationRoundKey {
    pub target_epoch: u64,
    pub context_digest: [u8; 32],
}

/// Authenticated position in a key-rotation round's revision/hash chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyRotationRoundMetadata {
    pub key: KeyRotationRoundKey,
    pub revision: u64,
    pub previous_snapshot_hash: [u8; 32],
    pub snapshot_hash: [u8; 32],
}

/// One decrypted, semantically validated key-rotation round and its durable CAS position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredKeyRotationRound {
    pub metadata: KeyRotationRoundMetadata,
    pub round: KeyRotationRound,
}

enum OpenKeyRotationRound {
    Active(StoredKeyRotationRound),
    Retired([u8; 32]),
}

/// Permanent, authenticated evidence that one dynamic X25519 epoch secret was retired after an
/// exact certified fresh-key successor or certified removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochIdentityRetirement {
    pub epoch: u64,
    pub public_key: [u8; 32],
    /// Immediate successor epoch.
    pub successor_epoch: u64,
    /// Digest of the exact fresh-key selection certificate.
    pub key_rotation_certificate_digest: [u8; 32],
    /// Domain-separated binding of the party, source/target committees, context, certificate,
    /// source key, and selected fresh target key (or removal).
    pub key_rotation_authorization_digest: [u8; 32],
}

/// One exact authenticated index resolution and its referenced certificate bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct IndexedActivationCertificate {
    pub key: ActivationCertificateKey,
    pub certificate: ProtocolBlob,
}

/// Decrypted protocol bytes which zeroize on drop and redact their contents from `Debug`.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct ProtocolBlob(Vec<u8>);

impl ProtocolBlob {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Transfer ownership of the decrypted bytes to the caller.
    ///
    /// The returned `Vec` no longer benefits from this type's zeroize-on-drop behavior.
    #[must_use]
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl AsRef<[u8]> for ProtocolBlob {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Deref for ProtocolBlob {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl std::fmt::Debug for ProtocolBlob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ProtocolBlob").field("length", &self.len()).finish()
    }
}

/// Permanent evidence that a session identifier has completed or been abandoned.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SessionTombstone {
    #[zeroize(skip)]
    session: SessionId,
    purpose: ProtocolBlob,
}

/// One-use proof that this call created and authenticated a previously absent permanent session
/// tombstone. It is intentionally non-`Clone`: an already-existing tombstone never recreates this
/// capability.
#[derive(Debug)]
pub(crate) struct PersistedSessionTombstoneReceipt {
    session: SessionId,
    purpose_digest: [u8; 32],
}

impl PersistedSessionTombstoneReceipt {
    #[must_use]
    pub(crate) const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub(crate) const fn purpose_digest(&self) -> [u8; 32] {
        self.purpose_digest
    }
}

/// Exact result of claiming the permanent session-tombstone namespace.
#[derive(Debug)]
pub(crate) enum SessionTombstoneClaim {
    Created(PersistedSessionTombstoneReceipt),
    /// The exact authenticated purpose was already durable. No nonce-authorizing receipt exists.
    Existing,
}

/// Authenticated monotonic family fence installed before a deterministic sweep session can mint
/// any nonce. Only the highest attempt is needed: deterministic session derivation makes every
/// lower attempt permanently recognizable after its exact hot-state tombstone is compacted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct SweepSigningHighWater {
    version: u16,
    wallet: DepositWalletId,
    sweep: SweepId,
    attempt: u64,
    session: SessionId,
    intent_digest: [u8; 32],
    tombstone_purpose_digest: [u8; 32],
}

impl SweepSigningHighWater {
    #[must_use]
    pub(crate) const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub(crate) const fn sweep(&self) -> SweepId {
        self.sweep
    }

    #[must_use]
    pub(crate) const fn attempt(&self) -> u64 {
        self.attempt
    }

    #[must_use]
    pub(crate) const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub(crate) const fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }

    #[must_use]
    pub(crate) const fn tombstone_purpose_digest(&self) -> [u8; 32] {
        self.tombstone_purpose_digest
    }
}

/// One-use proof that this call monotonically installed a previously unseen family attempt.
/// Exact retries return [`SweepSigningHighWaterClaim::Existing`] and never recreate this receipt.
#[derive(Debug)]
pub(crate) struct PersistedSweepSigningHighWaterReceipt(SweepSigningHighWater);

impl PersistedSweepSigningHighWaterReceipt {
    #[must_use]
    pub(crate) const fn record(&self) -> SweepSigningHighWater {
        self.0
    }
}

#[derive(Debug)]
enum SweepSigningHighWaterClaim {
    Advanced(PersistedSweepSigningHighWaterReceipt),
    Existing,
}

/// Fused result of crossing both persistent nonce fences. `Fresh` is the only variant carrying
/// the two non-cloneable receipts needed by the signer boundary; a crash/retry can obtain only
/// `Burned`, after storage has also closed the exact session tombstone.
#[derive(Debug)]
pub(crate) enum SweepSigningNonceClaim {
    Fresh { family: PersistedSweepSigningHighWaterReceipt, session: SessionTombstoneClaim },
    Burned,
}

impl SessionTombstone {
    #[must_use]
    pub fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub fn purpose(&self) -> &[u8] {
        self.purpose.as_bytes()
    }
}

impl std::fmt::Debug for SessionTombstone {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionTombstone")
            .field("session", &self.session)
            .field("purpose_length", &self.purpose.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum ProtocolRecordContext {
    SessionState {
        session: SessionId,
        context_digest: [u8; 32],
    },
    SessionTombstone {
        session: SessionId,
    },
    ActivationCertificate {
        epoch: u64,
        activation_digest: [u8; 32],
    },
    // Append new variants: postcard encodes enum discriminants by declaration order, and existing
    // durable records must retain their original associated data.
    ActivationTransitionIndex {
        epoch: u64,
        transition_digest: [u8; 32],
    },
    ProactiveRefreshSchedule {
        network_id: [u8; 32],
    },
    KeyRotationRound {
        target_epoch: u64,
        context_digest: [u8; 32],
    },
    KeyRotationCertificate {
        target_epoch: u64,
        context_digest: [u8; 32],
    },
    EpochIdentity {
        epoch: u64,
        public_key: [u8; 32],
    },
    SweepSigningHighWater {
        wallet: DepositWalletId,
        sweep: SweepId,
    },
    DepositIndexJournal {
        wallet_id: WalletId,
        scope: DepositIndexJournalScope,
        expected_revision: u64,
        expected_head_digest: [u8; 32],
    },
    DepositSyncSpoolHead {
        network_id: [u8; 32],
        wallet_id: DepositWalletId,
    },
    DepositStateTransferIntents {
        network_id: [u8; 32],
    },
}

impl ProtocolRecordContext {
    const fn kind(&self) -> &'static str {
        match self {
            Self::SessionState { .. } => "session state",
            Self::SessionTombstone { .. } => "session tombstone purpose",
            Self::ActivationCertificate { .. } => "activation certificate",
            Self::ActivationTransitionIndex { .. } => "activation transition index",
            Self::ProactiveRefreshSchedule { .. } => "proactive refresh schedule",
            Self::KeyRotationRound { .. } => "key rotation round snapshot",
            Self::KeyRotationCertificate { .. } => "key rotation certificate",
            Self::EpochIdentity { .. } => "epoch identity record",
            Self::SweepSigningHighWater { .. } => "sweep signing high-water",
            Self::DepositIndexJournal { .. } => "deposit index journal",
            Self::DepositSyncSpoolHead { .. } => "deposit sync spool head snapshot",
            Self::DepositStateTransferIntents { .. } => "deposit state-transfer intent snapshot",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ActivationTransitionIndexEntry {
    version: u16,
    activation_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ProtocolRecordHeader {
    version: u16,
    party: PartyId,
    context: ProtocolRecordContext,
    plaintext_len: u64,
}

#[derive(Serialize, Deserialize)]
struct SealedProtocolRecord {
    header: ProtocolRecordHeader,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

enum ExpectedProtocolContext {
    Exact(ProtocolRecordContext),
    Tombstone(SessionId),
    EpochIdentity(u64),
}

impl ExpectedProtocolContext {
    fn matches(&self, actual: &ProtocolRecordContext) -> bool {
        match (self, actual) {
            (Self::Exact(expected), actual) => expected == actual,
            (
                Self::Tombstone(expected_session),
                ProtocolRecordContext::SessionTombstone { session, .. },
            ) => expected_session == session,
            (
                Self::EpochIdentity(expected_epoch),
                ProtocolRecordContext::EpochIdentity { epoch, .. },
            ) => expected_epoch == epoch,
            _ => false,
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::Exact(context) => context.kind(),
            Self::Tombstone(_) => "session tombstone purpose",
            Self::EpochIdentity(_) => "epoch identity record",
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct ActiveEpochIdentitySecret {
    version: u16,
    epoch: u64,
    public_key: [u8; 32],
    secret: [u8; 32],
    /// `None` is valid only for the externally provisioned epoch-zero identity. Every dynamic
    /// candidate is bound to the exact current rotation context before it can be advertised.
    candidate_context: Option<[u8; 32]>,
    certification: Option<EpochIdentityCertification>,
}

/// Encrypted receipt binding an active target-epoch secret to the exact rotation decision which
/// selected it. Candidate records have no receipt and may be promoted only when their exact fresh
/// public key appears in the certified successor. Keeping this inside the AEAD-protected record makes crash retries
/// distinguish a completed promotion from an unrelated target-epoch key.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
struct EpochIdentityCertification {
    version: u16,
    source_epoch: u64,
    target_epoch: u64,
    target_public_key: [u8; 32],
    context_digest: [u8; 32],
    certificate_digest: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
enum EpochIdentityRecord {
    Active(ActiveEpochIdentitySecret),
    Retired(#[zeroize(skip)] EpochIdentityRetirement),
}

/// One active share encrypted under a random, non-derivable data-encryption key. The local store
/// key wraps that DEK so a normal process restart can recover it. Retirement atomically replaces
/// this entire record, including the only live wrapped DEK, with [`SealedShareRetirement`].
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SealedShare {
    version: u16,
    party: PartyId,
    epoch: u64,
    committee_digest: [u8; 32],
    key_nonce: [u8; 24],
    wrapped_key: Vec<u8>,
    share_nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

/// Non-secret authorization metadata retained after an obsolete epoch share is destroyed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ShareRetirement {
    epoch: u64,
    committee_digest: [u8; 32],
    successor_epoch: u64,
    successor_activation_digest: [u8; 32],
}

impl ShareRetirement {
    pub(crate) const fn epoch(self) -> u64 {
        self.epoch
    }

    pub(crate) const fn committee_digest(self) -> [u8; 32] {
        self.committee_digest
    }

    /// Construct storage authorization only at the server boundary which has already verified and
    /// durably persisted the successor activation certificate.
    pub(crate) fn for_certified_successor(
        epoch: u64,
        committee_digest: [u8; 32],
        successor_epoch: u64,
        successor_activation_digest: [u8; 32],
    ) -> Result<Self, StoreError> {
        let retirement =
            Self { epoch, committee_digest, successor_epoch, successor_activation_digest };
        validate_share_retirement(retirement)?;
        Ok(retirement)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SealedShareRetirement {
    version: u16,
    party: PartyId,
    retirement: ShareRetirement,
    nonce: [u8; 24],
    /// XChaCha20-Poly1305's tag for an empty plaintext and retirement-bound AAD.
    authenticator: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum ShareRecord {
    Active(SealedShare),
    Retired(SealedShareRetirement),
}

enum OpenShareRecord {
    Active(EpochShare),
    Retired(ShareRetirement),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WalletSnapshotHeader {
    version: u16,
    party: PartyId,
    wallet_id: WalletId,
    revision: u64,
    previous_snapshot_hash: [u8; 32],
    snapshot_hash: [u8; 32],
    plaintext_len: u64,
}

impl WalletSnapshotHeader {
    const fn metadata(&self) -> WalletSnapshotMetadata {
        WalletSnapshotMetadata {
            wallet_id: self.wallet_id,
            revision: self.revision,
            previous_snapshot_hash: self.previous_snapshot_hash,
            snapshot_hash: self.snapshot_hash,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SealedWalletSnapshot {
    header: WalletSnapshotHeader,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WalletArtifactHeader {
    version: u16,
    party: PartyId,
    reference: WalletArtifactRef,
    /// Local crash-cleanup ownership only. It does not participate in the portable content
    /// address, whose digest remains a commitment to exact plaintext and protocol context.
    owner: Option<WalletArtifactOwner>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SealedWalletArtifact {
    header: WalletArtifactHeader,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WalletArtifactReservationHeader {
    version: u16,
    party: PartyId,
    reference: WalletArtifactRef,
    owner: WalletArtifactOwner,
    artifact_nonce: [u8; 24],
    sealed_len: u64,
    sealed_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SealedWalletArtifactReservation {
    header: WalletArtifactReservationHeader,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("storage serialization failed")]
    Serialization,
    #[error("{kind} has {actual} bytes; maximum is {maximum}")]
    BlobTooLarge { kind: &'static str, actual: usize, maximum: usize },
    #[error("{kind} encoding has {trailing} trailing bytes")]
    TrailingBytes { kind: &'static str, trailing: usize },
    #[error("{kind} encoding is not canonical")]
    NonCanonicalEncoding { kind: &'static str },
    #[error("stored record is for another version, party, or protocol context")]
    WrongContext,
    #[error("stored record authentication or decryption failed")]
    Authentication,
    #[error("party {party:?} mutable state is already leased by another writer at {path:?}")]
    PartyStateLeaseHeld { party: PartyId, path: PathBuf },
    #[error(
        "epoch {epoch} share was permanently retired in favor of certified successor epoch {successor_epoch}"
    )]
    ShareRetired { epoch: u64, successor_epoch: u64 },
    #[error("share retirement authorization is invalid")]
    InvalidShareRetirement,
    #[error("epoch {epoch} is already retired under another successor activation")]
    ShareRetirementConflict { epoch: u64 },
    #[error("persisted share is invalid: {0}")]
    InvalidShare(#[from] KeyError),
    #[error("persisted key-rotation state is invalid: {0}")]
    InvalidKeyRotation(#[from] KeyRotationError),
    #[error("persisted dynamic identity is invalid: {0}")]
    InvalidIdentity(#[from] IdentityError),
    #[error("storage entry is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error("unexpected entry while enumerating durable protocol state: {0}")]
    UnexpectedEntry(PathBuf),
    #[error("{kind} count exceeds the configured maximum of {maximum}")]
    ProtocolEntryLimit { kind: &'static str, maximum: usize },
    #[error("activation transition index is invalid")]
    InvalidActivationIndex,
    #[error(
        "epoch {epoch} activation {activation_digest:?} already has different certificate bytes"
    )]
    ActivationCertificateConflict { epoch: u64, activation_digest: [u8; 32] },
    #[error(
        "epoch {epoch} transition {transition_digest:?} is already indexed to another activation"
    )]
    ActivationIndexConflict { epoch: u64, transition_digest: [u8; 32] },
    #[error(
        "epoch {epoch} activation {activation_digest:?} is permanently indexed and cannot be retired"
    )]
    IndexedActivationCertificateRetirement { epoch: u64, activation_digest: [u8; 32] },
    #[error("a session tombstone purpose must not be empty")]
    EmptyTombstonePurpose,
    #[error("session {0} already has a tombstone for another purpose")]
    TombstoneConflict(SessionId),
    #[error("session {0} is permanently tombstoned")]
    SessionTombstoned(SessionId),
    #[error("session {session} already has live state for another protocol context")]
    SessionContextConflict { session: SessionId },
    #[error("session {0} still has live protocol state")]
    LiveSessionState(SessionId),
    #[error("sweep signing high-water record is invalid")]
    InvalidSweepSigningHighWater,
    #[error("sweep signing attempt rolled back from durable high-water {stored} to {attempted}")]
    SweepSigningHighWaterRollback { stored: u64, attempted: u64 },
    #[error("sweep signing high-water has a same-attempt fork")]
    SweepSigningHighWaterConflict,
    #[error("observed sweep signing high-water disappeared")]
    SweepSigningHighWaterDisappeared,
    #[error("retired artifact conflicts with existing quarantine file: {0}")]
    RetirementConflict(PathBuf),
    #[error("key-rotation round {key:?} must begin at revision zero, not {actual}")]
    KeyRotationRevisionMustStartAtZero { key: KeyRotationRoundKey, actual: u64 },
    #[error(
        "key-rotation round {key:?} revision is not the next durable revision: expected {expected}, got {actual}"
    )]
    KeyRotationRevisionNotNext { key: KeyRotationRoundKey, expected: u64, actual: u64 },
    #[error("key-rotation round {key:?} revision {revision} conflicts with durable state")]
    KeyRotationRevisionConflict { key: KeyRotationRoundKey, revision: u64 },
    #[error("key-rotation round {0:?} revision counter is exhausted")]
    KeyRotationRevisionExhausted(KeyRotationRoundKey),
    #[error(
        "key-rotation round {key:?} rolled back in-process from revision {highest_seen} to {found}"
    )]
    KeyRotationRollbackDetected { key: KeyRotationRoundKey, highest_seen: u64, found: u64 },
    #[error(
        "key-rotation round {key:?} disappeared after revision {highest_seen} was authenticated"
    )]
    KeyRotationSnapshotDisappeared { key: KeyRotationRoundKey, highest_seen: u64 },
    #[error("key-rotation round {key:?} has a same-revision fork at revision {revision}")]
    KeyRotationForkDetected { key: KeyRotationRoundKey, revision: u64 },
    #[error("key-rotation round {key:?} hash chain is discontinuous at revision {revision}")]
    KeyRotationHashChainMismatch { key: KeyRotationRoundKey, revision: u64 },
    #[error("key-rotation certificate for {0:?} conflicts with durable bytes")]
    KeyRotationCertificateConflict(KeyRotationRoundKey),
    #[error("key-rotation round {0:?} has no durable certificate authorizing retirement")]
    KeyRotationCertificateMissing(KeyRotationRoundKey),
    #[error(
        "key-rotation round {0:?} was permanently retired after its certificate became durable"
    )]
    KeyRotationRoundRetired(KeyRotationRoundKey),
    #[error("dynamic epoch identity {epoch} conflicts with the durable public key")]
    EpochIdentityConflict { epoch: u64 },
    #[error("dynamic epoch identity {epoch} belongs to another or missing current rotation policy")]
    EpochIdentityPolicyConflict { epoch: u64 },
    #[error("dynamic epoch identity {epoch} is certified by another key-rotation decision")]
    EpochIdentityCertificationConflict { epoch: u64 },
    #[error(
        "dynamic epoch identity {epoch} was permanently retired in favor of certified epoch {successor_epoch}"
    )]
    EpochIdentityRetired { epoch: u64, successor_epoch: u64 },
    #[error("dynamic epoch identity retirement authorization is invalid")]
    InvalidEpochIdentityRetirement,
    #[error("dynamic epoch identity {epoch} is already retired under another certificate")]
    EpochIdentityRetirementConflict { epoch: u64 },
    #[error("dynamic epoch identity {epoch} rolled back in-process across its retirement marker")]
    EpochIdentityRollbackDetected { epoch: u64 },
    #[error("wallet {wallet_id:?} must begin at revision zero, not {actual}")]
    WalletRevisionMustStartAtZero { wallet_id: WalletId, actual: u64 },
    #[error(
        "wallet {wallet_id:?} revision is not the next durable revision: expected {expected}, got {actual}"
    )]
    WalletRevisionNotNext { wallet_id: WalletId, expected: u64, actual: u64 },
    #[error("wallet {wallet_id:?} revision {revision} conflicts with the durable snapshot")]
    WalletRevisionConflict { wallet_id: WalletId, revision: u64 },
    #[error("wallet {wallet_id:?} revision counter is exhausted")]
    WalletRevisionExhausted { wallet_id: WalletId },
    #[error("wallet {wallet_id:?} rolled back in-process from revision {highest_seen} to {found}")]
    WalletRollbackDetected { wallet_id: WalletId, highest_seen: u64, found: u64 },
    #[error(
        "wallet {wallet_id:?} snapshot disappeared after revision {highest_seen} was authenticated"
    )]
    WalletSnapshotDisappeared { wallet_id: WalletId, highest_seen: u64 },
    #[error("wallet {wallet_id:?} has a same-revision fork at revision {revision}")]
    WalletForkDetected { wallet_id: WalletId, revision: u64 },
    #[error("wallet {wallet_id:?} hash chain is discontinuous at revision {revision}")]
    WalletHashChainMismatch { wallet_id: WalletId, revision: u64 },
    #[error("wallet artifact reference is invalid")]
    InvalidWalletArtifactReference,
    #[error(
        "wallet {wallet_id:?} artifact kind {kind:?} at {digest:?} conflicts with existing bytes"
    )]
    WalletArtifactConflict { wallet_id: WalletId, kind: WalletArtifactKind, digest: [u8; 32] },
    #[error("wallet artifact batch owner is invalid")]
    InvalidWalletArtifactOwner,
    #[error(
        "wallet {wallet_id:?} artifact kind {kind:?} at {digest:?} is reserved by another durable batch"
    )]
    WalletArtifactReservationConflict {
        wallet_id: WalletId,
        kind: WalletArtifactKind,
        digest: [u8; 32],
    },
    #[error("deposit index journal key is invalid")]
    InvalidDepositIndexJournalKey,
    #[error("deposit index journal conflicts with an existing exact-head transition")]
    DepositIndexJournalConflict(DepositIndexJournalKey),
    #[error("deposit sync spool head key is invalid")]
    InvalidDepositSyncSpoolHeadKey,
    #[error("deposit sync spool head {0:?} revision counter is exhausted")]
    DepositSyncSpoolHeadRevisionExhausted(DepositSyncSpoolHeadKey),
    #[error(
        "deposit sync spool head {key:?} durable head does not match expected revision {expected_revision}; found {actual_revision}"
    )]
    DepositSyncSpoolHeadMismatch {
        key: DepositSyncSpoolHeadKey,
        expected_revision: u64,
        actual_revision: u64,
    },
    #[error("deposit sync spool head {key:?} revision {revision} conflicts with durable bytes")]
    DepositSyncSpoolHeadRevisionConflict { key: DepositSyncSpoolHeadKey, revision: u64 },
    #[error(
        "deposit sync spool head {key:?} rolled back in-process from revision {highest_seen} to {found}"
    )]
    DepositSyncSpoolHeadRollbackDetected {
        key: DepositSyncSpoolHeadKey,
        highest_seen: u64,
        found: u64,
    },
    #[error(
        "deposit sync spool head {key:?} disappeared after revision {highest_seen} was authenticated"
    )]
    DepositSyncSpoolHeadDisappeared { key: DepositSyncSpoolHeadKey, highest_seen: u64 },
    #[error("deposit sync spool head {key:?} has a same-revision fork at revision {revision}")]
    DepositSyncSpoolHeadForkDetected { key: DepositSyncSpoolHeadKey, revision: u64 },
    #[error("deposit sync spool head {key:?} hash chain is discontinuous at revision {revision}")]
    DepositSyncSpoolHeadHashChainMismatch { key: DepositSyncSpoolHeadKey, revision: u64 },
    #[error("deposit state-transfer intent network identifier is invalid")]
    InvalidDepositStateTransferIntentsNetwork,
    #[error(
        "deposit state-transfer intent snapshot for network {network_id:?} exhausted its revision counter"
    )]
    DepositStateTransferIntentsRevisionExhausted { network_id: [u8; 32] },
    #[error(
        "deposit state-transfer intent snapshot for network {network_id:?} does not match expected revision {expected_revision}; found {actual_revision}"
    )]
    DepositStateTransferIntentsMismatch {
        network_id: [u8; 32],
        expected_revision: u64,
        actual_revision: u64,
    },
    #[error(
        "deposit state-transfer intent snapshot for network {network_id:?} revision {revision} conflicts with durable bytes"
    )]
    DepositStateTransferIntentsRevisionConflict { network_id: [u8; 32], revision: u64 },
    #[error(
        "deposit state-transfer intent snapshot for network {network_id:?} rolled back in-process from revision {highest_seen} to {found}"
    )]
    DepositStateTransferIntentsRollbackDetected {
        network_id: [u8; 32],
        highest_seen: u64,
        found: u64,
    },
    #[error(
        "deposit state-transfer intent snapshot for network {network_id:?} disappeared after revision {highest_seen} was authenticated"
    )]
    DepositStateTransferIntentsDisappeared { network_id: [u8; 32], highest_seen: u64 },
    #[error(
        "deposit state-transfer intent snapshot for network {network_id:?} has a same-revision fork at revision {revision}"
    )]
    DepositStateTransferIntentsForkDetected { network_id: [u8; 32], revision: u64 },
    #[error(
        "deposit state-transfer intent snapshot for network {network_id:?} has a discontinuous hash chain at revision {revision}"
    )]
    DepositStateTransferIntentsHashChainMismatch { network_id: [u8; 32], revision: u64 },
}

impl ShareStore {
    pub fn new(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
    ) -> Result<Self, StoreError> {
        let hk = Hkdf::<Sha256>::new(Some(b"threshold-monero/share-store/v1"), identity_seed);
        let mut key = [0_u8; 32];
        let mut info = b"party/".to_vec();
        info.extend_from_slice(&party.0.to_le_bytes());
        hk.expand(&info, &mut key).map_err(|_| StoreError::KeyDerivation)?;
        Ok(Self { directory: directory.into(), party, key, mutation: Mutex::new(()) })
    }

    #[must_use]
    pub fn share_path(&self, epoch: u64) -> PathBuf {
        self.directory.join(format!("epoch-{epoch}.share"))
    }

    pub async fn save<R: RngCore + CryptoRng>(
        &self,
        share: &EpochShare,
        rng: &mut R,
    ) -> Result<(), StoreError> {
        let _mutation = self.mutation.lock().await;
        share.validate()?;
        if share.local_party != self.party {
            return Err(StoreError::WrongContext);
        }
        ensure_private_directory(&self.directory).await?;

        let destination = self.share_path(share.committee.epoch);
        if entry_exists_regular(&destination).await? {
            match self.open_share_record(share.committee.epoch, share.committee.digest()).await? {
                OpenShareRecord::Active(existing) => {
                    if existing.material() != share.material() {
                        return Err(StoreError::WrongContext);
                    }
                }
                OpenShareRecord::Retired(retirement) => {
                    return Err(StoreError::ShareRetired {
                        epoch: retirement.epoch,
                        successor_epoch: retirement.successor_epoch,
                    });
                }
            }
        }

        let material = share.material();
        let mut plaintext =
            postcard::to_allocvec(&material).map_err(|_| StoreError::Serialization)?;
        if plaintext.len() > MAX_SHARE_FILE_BYTES {
            let actual = plaintext.len();
            plaintext.zeroize();
            return Err(StoreError::BlobTooLarge {
                kind: "epoch share",
                actual,
                maximum: MAX_SHARE_FILE_BYTES,
            });
        }
        let committee_digest = share.committee.digest();
        let aad = associated_data(self.party, share.committee.epoch, committee_digest);
        let mut data_key = Zeroizing::new([0_u8; 32]);
        rng.fill_bytes(data_key.as_mut());
        let mut share_nonce = [0_u8; 24];
        rng.fill_bytes(&mut share_nonce);
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(data_key.as_ref()))
            .encrypt(XNonce::from_slice(&share_nonce), Payload { msg: &plaintext, aad: &aad })
            .map_err(|_| StoreError::Authentication)?;
        plaintext.zeroize();

        let mut key_nonce = [0_u8; 24];
        rng.fill_bytes(&mut key_nonce);
        let key_aad = share_key_associated_data(
            self.party,
            share.committee.epoch,
            committee_digest,
            share_nonce,
        );
        let wrapped_key = XChaCha20Poly1305::new(Key::from_slice(&self.key))
            .encrypt(
                XNonce::from_slice(&key_nonce),
                Payload { msg: data_key.as_ref(), aad: &key_aad },
            )
            .map_err(|_| StoreError::Authentication)?;
        let sealed = SealedShare {
            version: SHARE_RECORD_VERSION,
            party: self.party,
            epoch: share.committee.epoch,
            committee_digest,
            key_nonce,
            wrapped_key,
            share_nonce,
            ciphertext,
        };
        let encoded = postcard::to_allocvec(&ShareRecord::Active(sealed))
            .map_err(|_| StoreError::Serialization)?;
        if encoded.len() > MAX_SHARE_FILE_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "sealed epoch share",
                actual: encoded.len(),
                maximum: MAX_SHARE_FILE_BYTES,
            });
        }

        atomic_replace(&destination, &encoded, key_nonce).await
    }

    /// Load an active share. An authenticated retirement marker is a permanent, fail-closed
    /// result even if a caller still knows the old committee digest.
    pub async fn load(
        &self,
        epoch: u64,
        expected_committee_digest: [u8; 32],
    ) -> Result<EpochShare, StoreError> {
        match self.open_share_record(epoch, expected_committee_digest).await? {
            OpenShareRecord::Active(share) => Ok(share),
            OpenShareRecord::Retired(retirement) => Err(StoreError::ShareRetired {
                epoch: retirement.epoch,
                successor_epoch: retirement.successor_epoch,
            }),
        }
    }

    /// Load an active share or authenticate that it was retired. This is used only by startup
    /// recovery, where a tombstone is expected and must not make the whole party unavailable.
    pub async fn load_if_active(
        &self,
        epoch: u64,
        expected_committee_digest: [u8; 32],
    ) -> Result<Option<EpochShare>, StoreError> {
        match self.open_share_record(epoch, expected_committee_digest).await? {
            OpenShareRecord::Active(share) => Ok(Some(share)),
            OpenShareRecord::Retired(_) => Ok(None),
        }
    }

    /// Authenticate an epoch's durable share record and return its retirement authorization.
    ///
    /// Absence and a still-active share both return `None`; callers may treat only an exact
    /// returned marker as evidence that a historical retirement already completed. In
    /// particular, a malformed, wrongly bound, or unauthenticated record remains an error rather
    /// than being mistaken for an absent share.
    pub(crate) async fn load_retirement(
        &self,
        epoch: u64,
        expected_committee_digest: [u8; 32],
    ) -> Result<Option<ShareRetirement>, StoreError> {
        require_directory(&self.directory).await?;
        if !entry_exists_regular(&self.share_path(epoch)).await? {
            return Ok(None);
        }
        match self.open_share_record(epoch, expected_committee_digest).await? {
            OpenShareRecord::Active(share) => {
                drop(share);
                Ok(None)
            }
            OpenShareRecord::Retired(retirement) => Ok(Some(retirement)),
        }
    }

    async fn open_share_record(
        &self,
        epoch: u64,
        expected_committee_digest: [u8; 32],
    ) -> Result<OpenShareRecord, StoreError> {
        require_directory(&self.directory).await?;
        let path = self.share_path(epoch);
        let bytes =
            read_capped_regular_file(&path, MAX_SHARE_FILE_BYTES, "sealed epoch share").await?;
        match decode_canonical_exact::<ShareRecord>(&bytes, "sealed epoch share")? {
            ShareRecord::Active(sealed) => {
                self.open_sealed_share(sealed, epoch, expected_committee_digest)
            }
            ShareRecord::Retired(sealed) => {
                let retirement = self.open_share_retirement(sealed)?;
                if retirement.epoch != epoch
                    || retirement.committee_digest != expected_committee_digest
                {
                    return Err(StoreError::WrongContext);
                }
                Ok(OpenShareRecord::Retired(retirement))
            }
        }
    }

    fn open_sealed_share(
        &self,
        sealed: SealedShare,
        epoch: u64,
        expected_committee_digest: [u8; 32],
    ) -> Result<OpenShareRecord, StoreError> {
        if sealed.version != SHARE_RECORD_VERSION
            || sealed.party != self.party
            || sealed.epoch != epoch
            || sealed.committee_digest != expected_committee_digest
        {
            return Err(StoreError::WrongContext);
        }
        if sealed.wrapped_key.len() != 32 + AEAD_TAG_BYTES {
            return Err(StoreError::Authentication);
        }
        let key_aad = share_key_associated_data(
            self.party,
            epoch,
            expected_committee_digest,
            sealed.share_nonce,
        );
        let data_key = XChaCha20Poly1305::new(Key::from_slice(&self.key))
            .decrypt(
                XNonce::from_slice(&sealed.key_nonce),
                Payload { msg: &sealed.wrapped_key, aad: &key_aad },
            )
            .map_err(|_| StoreError::Authentication)?;
        if data_key.len() != 32 {
            return Err(StoreError::Authentication);
        }
        let data_key = Zeroizing::new(data_key);
        let aad = associated_data(self.party, epoch, expected_committee_digest);
        let plaintext = XChaCha20Poly1305::new(Key::from_slice(data_key.as_slice()))
            .decrypt(
                XNonce::from_slice(&sealed.share_nonce),
                Payload { msg: &sealed.ciphertext, aad: &aad },
            )
            .map_err(|_| StoreError::Authentication)?;
        self.decode_open_share(plaintext, expected_committee_digest)
    }

    fn decode_open_share(
        &self,
        mut plaintext: Vec<u8>,
        expected_committee_digest: [u8; 32],
    ) -> Result<OpenShareRecord, StoreError> {
        if plaintext.len() > MAX_SHARE_FILE_BYTES {
            let actual = plaintext.len();
            plaintext.zeroize();
            return Err(StoreError::BlobTooLarge {
                kind: "epoch share",
                actual,
                maximum: MAX_SHARE_FILE_BYTES,
            });
        }
        let material: EpochShareMaterial = match decode_canonical_exact(&plaintext, "epoch share") {
            Ok(material) => material,
            Err(error) => {
                plaintext.zeroize();
                return Err(error);
            }
        };
        plaintext.zeroize();
        let share = EpochShare::from_material(material)?;
        if share.committee.digest() != expected_committee_digest {
            return Err(StoreError::WrongContext);
        }
        Ok(OpenShareRecord::Active(share))
    }

    fn open_share_retirement(
        &self,
        sealed: SealedShareRetirement,
    ) -> Result<ShareRetirement, StoreError> {
        if sealed.version != SHARE_RECORD_VERSION
            || sealed.party != self.party
            || sealed.authenticator.len() != AEAD_TAG_BYTES
        {
            return Err(StoreError::WrongContext);
        }
        validate_share_retirement(sealed.retirement)?;
        let aad = share_retirement_associated_data(self.party, sealed.retirement);
        let plaintext = XChaCha20Poly1305::new(Key::from_slice(&self.key))
            .decrypt(
                XNonce::from_slice(&sealed.nonce),
                Payload { msg: &sealed.authenticator, aad: &aad },
            )
            .map_err(|_| StoreError::Authentication)?;
        if !plaintext.is_empty() {
            return Err(StoreError::Authentication);
        }
        Ok(sealed.retirement)
    }

    /// Authenticate an old epoch share, then atomically replace the active ciphertext and its
    /// wrapped random DEK with a non-secret authenticated retirement marker.
    ///
    /// The temporary marker is fsynced before rename and the containing directory is fsynced
    /// afterwards. Therefore a crash exposes either the complete active share or the complete
    /// tombstone, never a partially rewritten record. Repeating the exact retirement is
    /// idempotent; a different successor authorization is rejected.
    ///
    /// This is the strongest local crypto-erasure claim this store can make. Filesystem/volume
    /// snapshots, copy-on-write media, backups, crash dumps, or a copy of the replaced inode may
    /// retain both ciphertext and wrapped DEK. Because the identity seed remains available, such
    /// a copied DEK can still be unwrapped. Production mobile-adversary forward erasure requires
    /// a non-rollbackable external KMS/HSM (and erasure of retired epoch transport identities).
    pub(crate) async fn retire_share(
        &self,
        retirement: ShareRetirement,
    ) -> Result<PathBuf, StoreError> {
        let _mutation = self.mutation.lock().await;
        validate_share_retirement(retirement)?;
        let active =
            match self.open_share_record(retirement.epoch, retirement.committee_digest).await? {
                OpenShareRecord::Active(share) => {
                    drop(share);
                    true
                }
                OpenShareRecord::Retired(existing) if existing == retirement => false,
                OpenShareRecord::Retired(_) => {
                    return Err(StoreError::ShareRetirementConflict { epoch: retirement.epoch });
                }
            };

        let destination = self.share_path(retirement.epoch);
        if active {
            let mut nonce = [0_u8; 24];
            OsRng.fill_bytes(&mut nonce);
            let aad = share_retirement_associated_data(self.party, retirement);
            let authenticator = XChaCha20Poly1305::new(Key::from_slice(&self.key))
                .encrypt(XNonce::from_slice(&nonce), Payload { msg: &[], aad: &aad })
                .map_err(|_| StoreError::Authentication)?;
            let sealed = SealedShareRetirement {
                version: SHARE_RECORD_VERSION,
                party: self.party,
                retirement,
                nonce,
                authenticator,
            };
            let encoded = postcard::to_allocvec(&ShareRecord::Retired(sealed))
                .map_err(|_| StoreError::Serialization)?;
            atomic_replace(&destination, &encoded, nonce).await?;
        }
        destroy_temporary_replacements(&destination).await?;
        Ok(destination)
    }
}

impl ProtocolStore {
    pub fn new(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
    ) -> Result<Self, StoreError> {
        let hk = Hkdf::<Sha256>::new(Some(b"threshold-monero/protocol-store/v1"), identity_seed);
        let mut key = [0_u8; 32];
        let mut info = b"xchacha20poly1305/party/".to_vec();
        info.extend_from_slice(&party.0.to_le_bytes());
        hk.expand(&info, &mut key).map_err(|_| StoreError::KeyDerivation)?;
        Ok(Self {
            directory: directory.into().join(PROTOCOL_DIRECTORY).join(format!("party-{}", party.0)),
            party,
            key,
            mutation: Mutex::new(ProtocolMutationState::default()),
        })
    }

    #[must_use]
    pub fn protocol_directory(&self) -> &Path {
        &self.directory
    }

    /// Stable local party bound into every authenticated protocol record in this store.
    #[must_use]
    pub const fn party_id(&self) -> PartyId {
        self.party
    }

    #[must_use]
    pub fn session_state_path(&self, session: SessionId, context_digest: [u8; 32]) -> PathBuf {
        self.session_directory()
            .join(session_state_filename(SessionStateKey { session, context_digest }))
    }

    #[must_use]
    pub fn session_tombstone_path(&self, session: SessionId) -> PathBuf {
        self.tombstone_directory().join(session_tombstone_filename(session))
    }

    #[must_use]
    pub fn activation_certificate_path(&self, epoch: u64, activation_digest: [u8; 32]) -> PathBuf {
        self.activation_directory()
            .join(activation_filename(ActivationCertificateKey { epoch, activation_digest }))
    }

    #[must_use]
    pub fn activation_transition_index_path(&self, key: ActivationTransitionKey) -> PathBuf {
        self.activation_index_directory().join(activation_index_filename(key))
    }

    #[must_use]
    pub fn proactive_refresh_schedule_path(&self) -> PathBuf {
        self.directory.join(REFRESH_SCHEDULE_FILE)
    }

    #[must_use]
    pub fn key_rotation_round_path(&self, key: KeyRotationRoundKey) -> PathBuf {
        self.key_rotation_round_directory().join(key_rotation_round_filename(key))
    }

    #[must_use]
    pub fn key_rotation_certificate_path(&self, key: KeyRotationRoundKey) -> PathBuf {
        self.key_rotation_certificate_directory().join(key_rotation_certificate_filename(key))
    }

    #[must_use]
    pub fn deposit_index_journal_path(&self, key: DepositIndexJournalKey) -> PathBuf {
        self.deposit_index_journal_directory().join(deposit_index_journal_filename(key))
    }

    #[must_use]
    pub fn deposit_sync_spool_head_path(&self, key: DepositSyncSpoolHeadKey) -> PathBuf {
        self.deposit_sync_spool_head_directory().join(deposit_sync_spool_head_filename(key))
    }

    #[must_use]
    pub fn deposit_state_transfer_intents_path(&self) -> PathBuf {
        self.directory.join(DEPOSIT_STATE_TRANSFER_INTENTS_FILE)
    }

    #[must_use]
    pub(crate) fn sweep_signing_high_water_path(
        &self,
        wallet: DepositWalletId,
        sweep: SweepId,
    ) -> PathBuf {
        self.sweep_signing_high_water_directory()
            .join(sweep_signing_high_water_filename(wallet, sweep))
    }

    #[must_use]
    pub fn epoch_identity_path(&self, epoch: u64) -> PathBuf {
        self.epoch_identity_directory().join(epoch_identity_filename(epoch))
    }

    /// Create the one exact journal for a successor of an authenticated deposit-index head.
    ///
    /// The journal is fsynced before this method returns. Exact retries are idempotent; another
    /// byte string under the same old-head key is a fork and is rejected.
    pub async fn save_deposit_index_journal<R: RngCore + CryptoRng>(
        &self,
        key: DepositIndexJournalKey,
        journal: &[u8],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        key.validate()?;
        if journal.is_empty() {
            return Err(StoreError::InvalidDepositIndexJournalKey);
        }
        let _mutation = self.mutation.lock().await;
        ensure_private_directory(&self.directory).await?;
        ensure_private_directory(&self.deposit_index_journal_directory()).await?;
        let path = self.deposit_index_journal_path(key);
        let context = deposit_index_journal_context(key);
        if entry_exists_regular(&path).await? {
            let (_, durable) = self
                .open_protocol_record(
                    &path,
                    ExpectedProtocolContext::Exact(context.clone()),
                    MAX_DEPOSIT_INDEX_JOURNAL_BYTES,
                )
                .await?;
            return if durable.as_bytes() == journal {
                Ok(())
            } else {
                Err(StoreError::DepositIndexJournalConflict(key))
            };
        }
        let sealed = self.seal_protocol_record(
            context.clone(),
            journal,
            MAX_DEPOSIT_INDEX_JOURNAL_BYTES,
            rng,
        )?;
        if !atomic_create_new(&path, &sealed.encoded, sealed.nonce).await? {
            let (_, durable) = self
                .open_protocol_record(
                    &path,
                    ExpectedProtocolContext::Exact(context),
                    MAX_DEPOSIT_INDEX_JOURNAL_BYTES,
                )
                .await?;
            if durable.as_bytes() != journal {
                return Err(StoreError::DepositIndexJournalConflict(key));
            }
        }
        Ok(())
    }

    /// Load one exact old-head-bound deposit-index journal without enumerating its directory.
    pub async fn load_deposit_index_journal(
        &self,
        key: DepositIndexJournalKey,
    ) -> Result<Option<ProtocolBlob>, StoreError> {
        key.validate()?;
        if !directory_exists(&self.directory).await?
            || !directory_exists(&self.deposit_index_journal_directory()).await?
        {
            return Ok(None);
        }
        let path = self.deposit_index_journal_path(key);
        if !entry_exists_regular(&path).await? {
            return Ok(None);
        }
        let (_, plaintext) = self
            .open_protocol_record(
                &path,
                ExpectedProtocolContext::Exact(deposit_index_journal_context(key)),
                MAX_DEPOSIT_INDEX_JOURNAL_BYTES,
            )
            .await?;
        Ok(Some(plaintext))
    }

    /// Remove one exact journal after authenticating both its context and canonical plaintext.
    ///
    /// Absence is an idempotent success. Callers can therefore retry a bounded recovery cleanup
    /// without scanning the protocol directory.
    pub async fn destroy_deposit_index_journal(
        &self,
        key: DepositIndexJournalKey,
        expected_journal: &[u8],
    ) -> Result<bool, StoreError> {
        key.validate()?;
        let _mutation = self.mutation.lock().await;
        if !directory_exists(&self.directory).await?
            || !directory_exists(&self.deposit_index_journal_directory()).await?
        {
            return Ok(false);
        }
        let path = self.deposit_index_journal_path(key);
        if !entry_exists_regular(&path).await? {
            return Ok(false);
        }
        let (_, durable) = self
            .open_protocol_record(
                &path,
                ExpectedProtocolContext::Exact(deposit_index_journal_context(key)),
                MAX_DEPOSIT_INDEX_JOURNAL_BYTES,
            )
            .await?;
        if durable.as_bytes() != expected_journal {
            return Err(StoreError::DepositIndexJournalConflict(key));
        }
        destroy_file_and_sync_parent(&path).await?;
        Ok(true)
    }

    /// Persist the immediate successor of one authenticated deposit-sync spool head.
    ///
    /// Passing `None` creates revision zero. Passing `Some(metadata)` is an exact CAS against the
    /// current durable head and writes its immediate hash-chained successor. An uncertain exact
    /// retry is idempotent when the durable successor contains the same state bytes.
    pub async fn save_deposit_sync_spool_head<R: RngCore + CryptoRng>(
        &self,
        key: DepositSyncSpoolHeadKey,
        expected: Option<DepositSyncSpoolHeadMetadata>,
        state: &[u8],
        rng: &mut R,
    ) -> Result<DepositSyncSpoolHeadMetadata, StoreError> {
        key.validate()?;
        if let Some(expected) = expected
            && expected.key != key
        {
            return Err(StoreError::WrongContext);
        }
        if state.len() > MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "deposit sync spool head state",
                actual: state.len(),
                maximum: MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES,
            });
        }

        let mut mutation = self.mutation.lock().await;
        ensure_private_directory(&self.directory).await?;
        ensure_private_directory(&self.deposit_sync_spool_head_directory()).await?;
        let destination = self.deposit_sync_spool_head_path(key);
        let current = if entry_exists_regular(&destination).await? {
            let current = self.open_deposit_sync_spool_head(key).await?;
            Self::observe_deposit_sync_spool_head_snapshot(
                &mut mutation.deposit_sync_spool_heads,
                current.metadata,
            )?;
            Some(current)
        } else {
            if let Some(highest) = mutation.deposit_sync_spool_heads.get(&key) {
                return Err(StoreError::DepositSyncSpoolHeadDisappeared {
                    key,
                    highest_seen: highest.revision,
                });
            }
            None
        };

        let (revision, previous_snapshot_hash) = match (current, expected) {
            (None, None) => (0, [0_u8; 32]),
            (None, Some(expected)) => {
                return Err(StoreError::DepositSyncSpoolHeadDisappeared {
                    key,
                    highest_seen: expected.revision,
                });
            }
            (Some(current), None) => {
                if current.metadata.revision == 0 && current.state.as_bytes() == state {
                    return Ok(current.metadata);
                }
                return Err(StoreError::DepositSyncSpoolHeadRevisionConflict {
                    key,
                    revision: current.metadata.revision,
                });
            }
            (Some(current), Some(expected)) if current.metadata == expected => {
                let revision = expected
                    .revision
                    .checked_add(1)
                    .ok_or(StoreError::DepositSyncSpoolHeadRevisionExhausted(key))?;
                (revision, expected.snapshot_hash)
            }
            (Some(current), Some(expected))
                if expected.revision.checked_add(1) == Some(current.metadata.revision)
                    && current.metadata.previous_snapshot_hash == expected.snapshot_hash =>
            {
                if current.state.as_bytes() == state {
                    return Ok(current.metadata);
                }
                return Err(StoreError::DepositSyncSpoolHeadRevisionConflict {
                    key,
                    revision: current.metadata.revision,
                });
            }
            (Some(current), Some(expected)) if current.metadata.revision == expected.revision => {
                return Err(StoreError::DepositSyncSpoolHeadForkDetected {
                    key,
                    revision: current.metadata.revision,
                });
            }
            (Some(current), Some(expected)) => {
                return Err(StoreError::DepositSyncSpoolHeadMismatch {
                    key,
                    expected_revision: expected.revision,
                    actual_revision: current.metadata.revision,
                });
            }
        };

        let plaintext = Zeroizing::new(encode_deposit_sync_spool_head_snapshot(
            self.party,
            key,
            revision,
            previous_snapshot_hash,
            state,
        )?);
        let (metadata, _) =
            decode_deposit_sync_spool_head_snapshot(self.party, key, plaintext.as_slice())?;
        let context = deposit_sync_spool_head_context(key);
        let sealed = self.seal_protocol_record(
            context.clone(),
            plaintext.as_slice(),
            MAX_DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_BYTES,
            rng,
        )?;
        atomic_replace(&destination, &sealed.encoded, sealed.nonce).await?;

        let durable = self.open_deposit_sync_spool_head(key).await?;
        if durable.metadata != metadata || durable.state.as_bytes() != state {
            return Err(StoreError::DepositSyncSpoolHeadForkDetected { key, revision });
        }
        Self::observe_deposit_sync_spool_head_snapshot(
            &mut mutation.deposit_sync_spool_heads,
            durable.metadata,
        )?;
        Ok(durable.metadata)
    }

    /// Load one exact wallet/network spool head without enumerating protocol storage.
    pub async fn load_deposit_sync_spool_head(
        &self,
        key: DepositSyncSpoolHeadKey,
    ) -> Result<Option<DepositSyncSpoolHeadBlob>, StoreError> {
        key.validate()?;
        let mut mutation = self.mutation.lock().await;
        if !directory_exists(&self.directory).await?
            || !directory_exists(&self.deposit_sync_spool_head_directory()).await?
        {
            if let Some(highest) = mutation.deposit_sync_spool_heads.get(&key) {
                return Err(StoreError::DepositSyncSpoolHeadDisappeared {
                    key,
                    highest_seen: highest.revision,
                });
            }
            return Ok(None);
        }
        let path = self.deposit_sync_spool_head_path(key);
        if !entry_exists_regular(&path).await? {
            if let Some(highest) = mutation.deposit_sync_spool_heads.get(&key) {
                return Err(StoreError::DepositSyncSpoolHeadDisappeared {
                    key,
                    highest_seen: highest.revision,
                });
            }
            return Ok(None);
        }
        let durable = self.open_deposit_sync_spool_head(key).await?;
        Self::observe_deposit_sync_spool_head_snapshot(
            &mut mutation.deposit_sync_spool_heads,
            durable.metadata,
        )?;
        Ok(Some(durable))
    }

    /// Remove one exact spool head after authenticating its CAS position and plaintext.
    ///
    /// An absent head is an idempotent success. Exact destruction resets the in-process fence so a
    /// future exact candidate namespace can start a new revision-zero chain.
    pub async fn destroy_deposit_sync_spool_head(
        &self,
        key: DepositSyncSpoolHeadKey,
        expected: DepositSyncSpoolHeadMetadata,
        expected_state: &[u8],
    ) -> Result<bool, StoreError> {
        key.validate()?;
        if expected.key != key {
            return Err(StoreError::WrongContext);
        }
        let mut mutation = self.mutation.lock().await;
        if !directory_exists(&self.directory).await?
            || !directory_exists(&self.deposit_sync_spool_head_directory()).await?
        {
            if let Some(highest) = mutation.deposit_sync_spool_heads.get(&key) {
                return Err(StoreError::DepositSyncSpoolHeadDisappeared {
                    key,
                    highest_seen: highest.revision,
                });
            }
            return Ok(false);
        }
        let path = self.deposit_sync_spool_head_path(key);
        if !entry_exists_regular(&path).await? {
            if let Some(highest) = mutation.deposit_sync_spool_heads.get(&key) {
                return Err(StoreError::DepositSyncSpoolHeadDisappeared {
                    key,
                    highest_seen: highest.revision,
                });
            }
            return Ok(false);
        }
        let durable = self.open_deposit_sync_spool_head(key).await?;
        Self::observe_deposit_sync_spool_head_snapshot(
            &mut mutation.deposit_sync_spool_heads,
            durable.metadata,
        )?;
        if durable.metadata != expected {
            if durable.metadata.revision == expected.revision {
                return Err(StoreError::DepositSyncSpoolHeadForkDetected {
                    key,
                    revision: durable.metadata.revision,
                });
            }
            return Err(StoreError::DepositSyncSpoolHeadMismatch {
                key,
                expected_revision: expected.revision,
                actual_revision: durable.metadata.revision,
            });
        }
        if durable.state.as_bytes() != expected_state {
            return Err(StoreError::DepositSyncSpoolHeadRevisionConflict {
                key,
                revision: durable.metadata.revision,
            });
        }
        destroy_file_and_sync_parent(&path).await?;
        mutation.deposit_sync_spool_heads.remove(&key);
        Ok(true)
    }

    /// Persist the immediate successor of the fixed network-bound state-transfer intent snapshot.
    ///
    /// Passing `None` creates revision zero. Passing `Some(metadata)` is an exact CAS against the
    /// current authenticated head. Retrying an uncertain create or successor write is idempotent
    /// only when the durable state bytes are identical. An empty state is a valid snapshot and
    /// must be written instead of deleting the record, preserving its monotonic generation and
    /// rollback fence.
    pub async fn save_deposit_state_transfer_intents<R: RngCore + CryptoRng>(
        &self,
        network_id: [u8; 32],
        expected: Option<DepositStateTransferIntentsMetadata>,
        state: &[u8],
        rng: &mut R,
    ) -> Result<DepositStateTransferIntentsMetadata, StoreError> {
        validate_deposit_state_transfer_intents_network(network_id)?;
        if let Some(expected) = expected
            && expected.network_id != network_id
        {
            return Err(StoreError::WrongContext);
        }
        if state.len() > MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "deposit state-transfer intent state",
                actual: state.len(),
                maximum: MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES,
            });
        }

        let mut mutation = self.mutation.lock().await;
        ensure_private_directory(&self.directory).await?;
        let destination = self.deposit_state_transfer_intents_path();
        let current = if entry_exists_regular(&destination).await? {
            let current = self.open_deposit_state_transfer_intents(network_id).await?;
            Self::observe_deposit_state_transfer_intents_snapshot(
                &mut mutation.deposit_state_transfer_intents,
                current.metadata,
            )?;
            Some(current)
        } else {
            if let Some(highest) = mutation.deposit_state_transfer_intents.get(&network_id) {
                return Err(StoreError::DepositStateTransferIntentsDisappeared {
                    network_id,
                    highest_seen: highest.revision,
                });
            }
            None
        };

        let (revision, previous_snapshot_hash) = match (current, expected) {
            (None, None) => (0, [0_u8; 32]),
            (None, Some(expected)) => {
                return Err(StoreError::DepositStateTransferIntentsDisappeared {
                    network_id,
                    highest_seen: expected.revision,
                });
            }
            (Some(current), None) => {
                if current.metadata.revision == 0 && current.state.as_bytes() == state {
                    return Ok(current.metadata);
                }
                return Err(StoreError::DepositStateTransferIntentsRevisionConflict {
                    network_id,
                    revision: current.metadata.revision,
                });
            }
            (Some(current), Some(expected)) if current.metadata == expected => {
                let revision = expected.revision.checked_add(1).ok_or(
                    StoreError::DepositStateTransferIntentsRevisionExhausted { network_id },
                )?;
                (revision, expected.snapshot_hash)
            }
            (Some(current), Some(expected))
                if expected.revision.checked_add(1) == Some(current.metadata.revision)
                    && current.metadata.previous_snapshot_hash == expected.snapshot_hash =>
            {
                if current.state.as_bytes() == state {
                    return Ok(current.metadata);
                }
                return Err(StoreError::DepositStateTransferIntentsRevisionConflict {
                    network_id,
                    revision: current.metadata.revision,
                });
            }
            (Some(current), Some(expected)) if current.metadata.revision == expected.revision => {
                return Err(StoreError::DepositStateTransferIntentsForkDetected {
                    network_id,
                    revision: current.metadata.revision,
                });
            }
            (Some(current), Some(expected)) => {
                return Err(StoreError::DepositStateTransferIntentsMismatch {
                    network_id,
                    expected_revision: expected.revision,
                    actual_revision: current.metadata.revision,
                });
            }
        };

        let plaintext = Zeroizing::new(encode_deposit_state_transfer_intents_snapshot(
            self.party,
            network_id,
            revision,
            previous_snapshot_hash,
            state,
        )?);
        let (metadata, _) = decode_deposit_state_transfer_intents_snapshot(
            self.party,
            network_id,
            plaintext.as_slice(),
        )?;
        let context = ProtocolRecordContext::DepositStateTransferIntents { network_id };
        let sealed = self.seal_protocol_record(
            context,
            plaintext.as_slice(),
            MAX_DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_BYTES,
            rng,
        )?;
        // A reported replacement error is never converted to success from a merely readable
        // destination: the parent-directory fsync may have failed. The caller sends no network
        // request and retries this exact CAS. That retry fsyncs the directory before recognizing
        // the already-installed immediate successor above.
        atomic_replace(&destination, &sealed.encoded, sealed.nonce).await?;

        let durable = self.open_deposit_state_transfer_intents(network_id).await?;
        if durable.metadata != metadata || durable.state.as_bytes() != state {
            return Err(StoreError::DepositStateTransferIntentsForkDetected {
                network_id,
                revision,
            });
        }
        Self::observe_deposit_state_transfer_intents_snapshot(
            &mut mutation.deposit_state_transfer_intents,
            durable.metadata,
        )?;
        Ok(durable.metadata)
    }

    /// Load the fixed state-transfer intent snapshot without enumerating protocol storage.
    pub async fn load_deposit_state_transfer_intents(
        &self,
        network_id: [u8; 32],
    ) -> Result<Option<DepositStateTransferIntentsBlob>, StoreError> {
        validate_deposit_state_transfer_intents_network(network_id)?;
        let mut mutation = self.mutation.lock().await;
        if !directory_exists(&self.directory).await? {
            if let Some(highest) = mutation.deposit_state_transfer_intents.get(&network_id) {
                return Err(StoreError::DepositStateTransferIntentsDisappeared {
                    network_id,
                    highest_seen: highest.revision,
                });
            }
            return Ok(None);
        }
        let path = self.deposit_state_transfer_intents_path();
        if !entry_exists_regular(&path).await? {
            if let Some(highest) = mutation.deposit_state_transfer_intents.get(&network_id) {
                return Err(StoreError::DepositStateTransferIntentsDisappeared {
                    network_id,
                    highest_seen: highest.revision,
                });
            }
            return Ok(None);
        }
        let durable = self.open_deposit_state_transfer_intents(network_id).await?;
        Self::observe_deposit_state_transfer_intents_snapshot(
            &mut mutation.deposit_state_transfer_intents,
            durable.metadata,
        )?;
        Ok(Some(durable))
    }

    /// Atomically replace the authenticated proactive-refresh deadline for this transport trust
    /// domain. The caller owns semantic validation of the canonical schedule bytes.
    pub async fn save_proactive_refresh_schedule<R: RngCore + CryptoRng>(
        &self,
        network_id: [u8; 32],
        schedule: &[u8],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        let _mutation = self.mutation.lock().await;
        ensure_private_directory(&self.directory).await?;
        let context = ProtocolRecordContext::ProactiveRefreshSchedule { network_id };
        let sealed =
            self.seal_protocol_record(context, schedule, MAX_REFRESH_SCHEDULE_BYTES, rng)?;
        atomic_replace(&self.proactive_refresh_schedule_path(), &sealed.encoded, sealed.nonce).await
    }

    /// Load the authenticated proactive-refresh deadline, if one has been armed.
    pub async fn load_proactive_refresh_schedule(
        &self,
        network_id: [u8; 32],
    ) -> Result<Option<ProtocolBlob>, StoreError> {
        if !directory_exists(&self.directory).await?
            || !entry_exists_regular(&self.proactive_refresh_schedule_path()).await?
        {
            return Ok(None);
        }
        let expected = ProtocolRecordContext::ProactiveRefreshSchedule { network_id };
        let (_, plaintext) = self
            .open_protocol_record(
                &self.proactive_refresh_schedule_path(),
                ExpectedProtocolContext::Exact(expected),
                MAX_REFRESH_SCHEDULE_BYTES,
            )
            .await?;
        Ok(Some(plaintext))
    }

    /// Persist a complete key-rotation reducer/outbox snapshot at an exact monotonic revision.
    ///
    /// Revision zero creates the round. A later call must name the immediate successor revision;
    /// retrying the same revision is accepted only for byte-identical canonical state. The
    /// returned metadata is a CAS/hash-chain anchor suitable for an external rollback fence.
    pub async fn save_key_rotation_round<R: RngCore + CryptoRng>(
        &self,
        context: &KeyRotationContext,
        revision: u64,
        round: &KeyRotationRound,
        rng: &mut R,
    ) -> Result<KeyRotationRoundMetadata, StoreError> {
        context.validate()?;
        let state = Zeroizing::new(round.encode()?);
        drop(KeyRotationRound::decode(context, self.party, state.as_slice())?);
        let key = key_rotation_round_key(context);

        let mut mutation = self.mutation.lock().await;
        ensure_private_directory(&self.directory).await?;
        let destination = self.key_rotation_round_path(key);
        let current = if entry_exists_regular(&destination).await? {
            match self.open_key_rotation_round(context).await? {
                OpenKeyRotationRound::Active(current) => {
                    Self::observe_key_rotation_snapshot(
                        &mut mutation.key_rotation_heads,
                        current.metadata,
                    )?;
                    Some(current)
                }
                OpenKeyRotationRound::Retired(_) => {
                    return Err(StoreError::KeyRotationRoundRetired(key));
                }
            }
        } else {
            if let Some(highest) = mutation.key_rotation_heads.get(&key) {
                return Err(StoreError::KeyRotationSnapshotDisappeared {
                    key,
                    highest_seen: highest.revision,
                });
            }
            None
        };

        let previous_snapshot_hash = if let Some(current) = current {
            if revision == current.metadata.revision {
                if current.round == *round {
                    return Ok(current.metadata);
                }
                return Err(StoreError::KeyRotationRevisionConflict { key, revision });
            }
            let expected = current
                .metadata
                .revision
                .checked_add(1)
                .ok_or(StoreError::KeyRotationRevisionExhausted(key))?;
            if revision != expected {
                return Err(StoreError::KeyRotationRevisionNotNext {
                    key,
                    expected,
                    actual: revision,
                });
            }
            current.metadata.snapshot_hash
        } else {
            if revision != 0 {
                return Err(StoreError::KeyRotationRevisionMustStartAtZero {
                    key,
                    actual: revision,
                });
            }
            [0_u8; 32]
        };

        let plaintext = Zeroizing::new(encode_key_rotation_snapshot(
            self.party,
            key,
            revision,
            previous_snapshot_hash,
            state.as_slice(),
        )?);
        let metadata = decode_key_rotation_snapshot_header(self.party, key, &plaintext)?.0;
        let record_context = ProtocolRecordContext::KeyRotationRound {
            target_epoch: key.target_epoch,
            context_digest: key.context_digest,
        };
        let sealed = self.seal_protocol_record(
            record_context,
            &plaintext,
            MAX_KEY_ROTATION_SNAPSHOT_BYTES,
            rng,
        )?;
        atomic_replace(&destination, &sealed.encoded, sealed.nonce).await?;
        mutation.key_rotation_heads.insert(key, metadata);
        Ok(metadata)
    }

    /// Load and semantically validate one round against locally reconstructed context.
    pub async fn load_key_rotation_round(
        &self,
        context: &KeyRotationContext,
    ) -> Result<Option<StoredKeyRotationRound>, StoreError> {
        context.validate()?;
        let key = key_rotation_round_key(context);
        let mut mutation = self.mutation.lock().await;
        let destination = self.key_rotation_round_path(key);
        if !directory_exists(&self.directory).await? || !entry_exists_regular(&destination).await? {
            if let Some(highest) = mutation.key_rotation_heads.get(&key) {
                return Err(StoreError::KeyRotationSnapshotDisappeared {
                    key,
                    highest_seen: highest.revision,
                });
            }
            return Ok(None);
        }
        match self.open_key_rotation_round(context).await? {
            OpenKeyRotationRound::Active(snapshot) => {
                Self::observe_key_rotation_snapshot(
                    &mut mutation.key_rotation_heads,
                    snapshot.metadata,
                )?;
                Ok(Some(snapshot))
            }
            OpenKeyRotationRound::Retired(_) => Err(StoreError::KeyRotationRoundRetired(key)),
        }
    }

    /// List and authenticate active round records while enforcing a traversal bound.
    pub async fn key_rotation_rounds_bounded(
        &self,
        maximum: usize,
    ) -> Result<Vec<KeyRotationRoundKey>, StoreError> {
        if !directory_exists(&self.directory).await? {
            return Ok(Vec::new());
        }
        let keys = enumerate_protocol_directory_bounded(
            &self.key_rotation_round_directory(),
            parse_key_rotation_round_filename,
            maximum,
            "key rotation round",
        )
        .await?;
        for key in &keys {
            let expected = ProtocolRecordContext::KeyRotationRound {
                target_epoch: key.target_epoch,
                context_digest: key.context_digest,
            };
            let (_, plaintext) = self
                .open_protocol_record(
                    &self.key_rotation_round_path(*key),
                    ExpectedProtocolContext::Exact(expected),
                    MAX_KEY_ROTATION_SNAPSHOT_BYTES,
                )
                .await?;
            match plaintext.first().copied() {
                Some(0) => {
                    let _ = decode_key_rotation_snapshot_header(self.party, *key, &plaintext)?;
                }
                Some(1) if plaintext.len() == 33 && plaintext[1..] != [0_u8; 32] => {}
                _ => {
                    return Err(StoreError::NonCanonicalEncoding {
                        kind: "key rotation round snapshot",
                    });
                }
            }
        }
        Ok(keys)
    }

    /// Create an immutable, canonical key-rotation decision certificate.
    ///
    /// The first valid witness-bearing representation remains the local durable artifact.
    /// Byte-distinct quorum subsets proving the same semantic decision are idempotent; a
    /// certificate proving another rotation value for this context is rejected.
    pub async fn save_key_rotation_certificate<R: RngCore + CryptoRng>(
        &self,
        context: &KeyRotationContext,
        certificate: &KeyRotationCertificate,
        rng: &mut R,
    ) -> Result<(), StoreError> {
        context.validate()?;
        let encoded = Zeroizing::new(certificate.encode(context)?);
        let key = key_rotation_round_key(context);
        let _mutation = self.mutation.lock().await;
        ensure_private_directory(&self.directory).await?;
        let destination = self.key_rotation_certificate_path(key);
        if entry_exists_regular(&destination).await? {
            let durable = self.open_key_rotation_certificate(context).await?;
            if durable.proves_same_decision(certificate, context)? {
                return Ok(());
            }
            return Err(StoreError::KeyRotationCertificateConflict(key));
        }
        let record_context = ProtocolRecordContext::KeyRotationCertificate {
            target_epoch: key.target_epoch,
            context_digest: key.context_digest,
        };
        let sealed = self.seal_protocol_record(
            record_context,
            &encoded,
            MAX_KEY_ROTATION_CERTIFICATE_BYTES,
            rng,
        )?;
        if !atomic_create_new(&destination, &sealed.encoded, sealed.nonce).await? {
            let durable = self.open_key_rotation_certificate(context).await?;
            if !durable.proves_same_decision(certificate, context)? {
                return Err(StoreError::KeyRotationCertificateConflict(key));
            }
        }
        Ok(())
    }

    /// Load an immutable decision certificate against trusted local context.
    pub async fn load_key_rotation_certificate(
        &self,
        context: &KeyRotationContext,
    ) -> Result<Option<KeyRotationCertificate>, StoreError> {
        context.validate()?;
        let key = key_rotation_round_key(context);
        if !directory_exists(&self.directory).await?
            || !entry_exists_regular(&self.key_rotation_certificate_path(key)).await?
        {
            return Ok(None);
        }
        Ok(Some(self.open_key_rotation_certificate(context).await?))
    }

    /// Load the node's exact immutable witness artifact and prove that `candidate` certifies the
    /// same rotation decision.
    ///
    /// Honest collectors may retain different PRECOMMIT witness subsets for one value. All
    /// downstream receipts and erasure authorizations must nevertheless use this node's first
    /// durable representation, otherwise the same decision could acquire multiple local digests.
    async fn canonical_key_rotation_certificate(
        &self,
        context: &KeyRotationContext,
        candidate: &KeyRotationCertificate,
    ) -> Result<KeyRotationCertificate, StoreError> {
        let key = key_rotation_round_key(context);
        if !entry_exists_regular(&self.key_rotation_certificate_path(key)).await? {
            return Err(StoreError::KeyRotationCertificateMissing(key));
        }
        let durable = self.open_key_rotation_certificate(context).await?;
        if !durable.proves_same_decision(candidate, context)? {
            return Err(StoreError::KeyRotationCertificateConflict(key));
        }
        Ok(durable)
    }

    /// List immutable certificate keys with a hard traversal bound. Semantic verification still
    /// requires the caller's matching locally reconstructed context.
    pub async fn key_rotation_certificates_bounded(
        &self,
        maximum: usize,
    ) -> Result<Vec<KeyRotationRoundKey>, StoreError> {
        if !directory_exists(&self.directory).await? {
            return Ok(Vec::new());
        }
        let keys = enumerate_protocol_directory_bounded(
            &self.key_rotation_certificate_directory(),
            parse_key_rotation_certificate_filename,
            maximum,
            "key rotation certificate",
        )
        .await?;
        for key in &keys {
            let expected = ProtocolRecordContext::KeyRotationCertificate {
                target_epoch: key.target_epoch,
                context_digest: key.context_digest,
            };
            let (_, plaintext) = self
                .open_protocol_record(
                    &self.key_rotation_certificate_path(*key),
                    ExpectedProtocolContext::Exact(expected),
                    MAX_KEY_ROTATION_CERTIFICATE_BYTES,
                )
                .await?;
            if plaintext.is_empty() {
                return Err(StoreError::Authentication);
            }
        }
        Ok(keys)
    }

    /// Destroy a duplicate current-volume key-rotation certificate after its exact bytes are
    /// authenticated by immutable epoch history. The immutable history object remains the
    /// authoritative certificate used for historical verification.
    pub(crate) async fn destroy_archived_key_rotation_certificate(
        &self,
        context: &KeyRotationContext,
    ) -> Result<(), StoreError> {
        context.validate()?;
        let key = key_rotation_round_key(context);
        let _mutation = self.mutation.lock().await;
        if !directory_exists(&self.directory).await? {
            return Ok(());
        }
        let path = self.key_rotation_certificate_path(key);
        if !entry_exists_regular(&path).await? {
            return Ok(());
        }
        drop(self.open_key_rotation_certificate(context).await?);
        destroy_file_and_sync_parent(&path).await
    }

    /// Permanently replace a terminal round snapshot with a small authenticated marker. The
    /// matching immutable certificate must already be durable, preventing premature reducer and
    /// retry-outbox destruction.
    pub async fn retire_key_rotation_round<R: RngCore + CryptoRng>(
        &self,
        context: &KeyRotationContext,
        certificate: &KeyRotationCertificate,
        rng: &mut R,
    ) -> Result<(), StoreError> {
        context.validate()?;
        let key = key_rotation_round_key(context);
        let _mutation = self.mutation.lock().await;
        let durable = self.canonical_key_rotation_certificate(context, certificate).await?;
        let certificate_bytes = Zeroizing::new(durable.encode(context)?);
        let destination = self.key_rotation_round_path(key);
        let expected_retirement_digest = key_rotation_certificate_digest(key, &certificate_bytes);
        match self.open_key_rotation_round(context).await? {
            OpenKeyRotationRound::Retired(digest) if digest == expected_retirement_digest => {
                return Ok(());
            }
            OpenKeyRotationRound::Retired(_) => {
                return Err(StoreError::KeyRotationCertificateConflict(key));
            }
            OpenKeyRotationRound::Active(snapshot) => {
                let Some(round_certificate) = snapshot.round.certificate() else {
                    return Err(StoreError::KeyRotationCertificateConflict(key));
                };
                if !round_certificate.proves_same_decision(&durable, context)? {
                    return Err(StoreError::KeyRotationCertificateConflict(key));
                }
            }
        }
        let mut retirement = Zeroizing::new(Vec::with_capacity(33));
        retirement.push(1);
        retirement.extend_from_slice(&expected_retirement_digest);
        let record_context = ProtocolRecordContext::KeyRotationRound {
            target_epoch: key.target_epoch,
            context_digest: key.context_digest,
        };
        let sealed = self.seal_protocol_record(
            record_context,
            &retirement,
            MAX_KEY_ROTATION_SNAPSHOT_BYTES,
            rng,
        )?;
        atomic_replace(&destination, &sealed.encoded, sealed.nonce).await?;
        destroy_temporary_replacements(&destination).await
    }

    /// Persist the externally provisioned epoch-zero X25519 secret, or verify an already-existing
    /// dynamic identity exactly. New post-genesis candidates must use
    /// [`Self::save_epoch_identity_candidate_secret`] so their current policy is durable.
    pub async fn save_epoch_identity_secret<R: RngCore + CryptoRng>(
        &self,
        identity: &EpochEncryptionSecret,
        rng: &mut R,
    ) -> Result<(), StoreError> {
        validate_epoch_identity_secret(self.party, identity)?;
        let mutation = self.mutation.lock().await;
        if let Some(retirement) = mutation.retired_epoch_identities.get(&identity.epoch()) {
            return Err(StoreError::EpochIdentityRetired {
                epoch: identity.epoch(),
                successor_epoch: retirement.successor_epoch,
            });
        }
        ensure_private_directory(&self.directory).await?;
        let destination = self.epoch_identity_path(identity.epoch());
        if entry_exists_regular(&destination).await? {
            let (stored_public_key, existing) =
                self.open_epoch_identity_record(identity.epoch()).await?;
            return match &existing {
                EpochIdentityRecord::Active(active)
                    if stored_public_key == identity.public_key()
                        && active.secret.as_slice() == identity.secret_bytes() =>
                {
                    Ok(())
                }
                EpochIdentityRecord::Retired(retirement) => Err(StoreError::EpochIdentityRetired {
                    epoch: identity.epoch(),
                    successor_epoch: retirement.successor_epoch,
                }),
                EpochIdentityRecord::Active(_) => {
                    Err(StoreError::EpochIdentityConflict { epoch: identity.epoch() })
                }
            };
        }
        if identity.epoch() != 0 {
            return Err(StoreError::EpochIdentityPolicyConflict { epoch: identity.epoch() });
        }
        self.save_epoch_identity_secret_locked(identity, None, rng).await
    }

    /// Persist a caller-supplied post-genesis candidate under the exact current rotation policy.
    /// This is primarily useful to restore externally constructed test fixtures; production
    /// candidates are generated by [`Self::load_or_create_epoch_identity_secret`].
    pub async fn save_epoch_identity_candidate_secret<R: RngCore + CryptoRng>(
        &self,
        context: &KeyRotationContext,
        identity: &EpochEncryptionSecret,
        rng: &mut R,
    ) -> Result<(), StoreError> {
        context.validate()?;
        context.target_policy().eligible().member(self.party).map_err(KeyRotationError::from)?;
        validate_epoch_identity_secret(self.party, identity)?;
        if identity.epoch() != context.target_epoch() {
            return Err(StoreError::EpochIdentityPolicyConflict { epoch: identity.epoch() });
        }
        let _mutation = self.mutation.lock().await;
        ensure_private_directory(&self.directory).await?;
        self.save_epoch_identity_secret_locked(identity, Some(context.digest()), rng).await
    }

    /// Create a current-format non-genesis fixture without manufacturing a rotation certificate.
    #[cfg(test)]
    pub(crate) async fn save_epoch_identity_secret_for_test<R: RngCore + CryptoRng>(
        &self,
        identity: &EpochEncryptionSecret,
        candidate_context: [u8; 32],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        if identity.epoch() == 0 || candidate_context == [0_u8; 32] {
            return Err(StoreError::EpochIdentityPolicyConflict { epoch: identity.epoch() });
        }
        let _mutation = self.mutation.lock().await;
        ensure_private_directory(&self.directory).await?;
        self.save_epoch_identity_secret_locked(identity, Some(candidate_context), rng).await
    }

    /// Recover an existing dynamic X25519 secret or generate and durably create one exactly once.
    /// The returned value is safe to use only after this method succeeds.
    pub async fn load_or_create_epoch_identity_secret<R: RngCore + CryptoRng>(
        &self,
        context: &KeyRotationContext,
        rng: &mut R,
    ) -> Result<EpochEncryptionSecret, StoreError> {
        context.validate()?;
        context.target_policy().eligible().member(self.party).map_err(KeyRotationError::from)?;
        let epoch = context.target_epoch();
        let mut mutation = self.mutation.lock().await;
        if let Some(retirement) = mutation.retired_epoch_identities.get(&epoch) {
            return Err(StoreError::EpochIdentityRetired {
                epoch,
                successor_epoch: retirement.successor_epoch,
            });
        }
        ensure_private_directory(&self.directory).await?;
        let destination = self.epoch_identity_path(epoch);
        let generated = if entry_exists_regular(&destination).await? {
            None
        } else {
            let identity = EpochEncryptionSecret::generate(self.party, epoch, rng)?;
            self.save_epoch_identity_secret_locked(&identity, Some(context.digest()), rng).await?;
            Some(identity)
        };

        // Even the create-new path must reopen and authenticate the exact durable record. A
        // successful rename alone is not authority to use an in-memory candidate: this readback
        // resolves create/retry ambiguity and catches a conflicting or retired record before any
        // caller can construct an identity from the returned secret.
        let (stored_public_key, existing) = self.open_epoch_identity_record(epoch).await?;
        match &existing {
            EpochIdentityRecord::Active(active) => {
                if active.candidate_context != Some(context.digest()) {
                    return Err(StoreError::EpochIdentityPolicyConflict { epoch });
                }
                let durable = epoch_identity_from_active(self.party, active)?;
                if stored_public_key != durable.public_key()
                    || generated.as_ref().is_some_and(|candidate| candidate != &durable)
                {
                    return Err(StoreError::EpochIdentityConflict { epoch });
                }
                Ok(durable)
            }
            EpochIdentityRecord::Retired(retirement) => {
                mutation.retired_epoch_identities.insert(epoch, *retirement);
                Err(StoreError::EpochIdentityRetired {
                    epoch,
                    successor_epoch: retirement.successor_epoch,
                })
            }
        }
    }

    /// Generate or recover a target-epoch X25519 candidate and return advertisement authority only
    /// after authenticated canonical readback.
    ///
    /// The stable Ed25519 seed is used solely to reconstruct the signing identity after the
    /// independently random X25519 secret is durable. It never contributes to X25519 generation.
    /// The returned non-serializable capability is the only production input accepted by the
    /// key-rotation advertisement boundary.
    pub async fn load_or_create_epoch_advertisement_identity<R: RngCore + CryptoRng>(
        &self,
        context: &KeyRotationContext,
        signing_seed: &[u8; 32],
        expected_signing_public_key: [u8; 32],
        rng: &mut R,
    ) -> Result<PersistedKeyAdvertisementIdentity, StoreError> {
        validate_signing_seed(signing_seed, expected_signing_public_key)?;
        let secret = self.load_or_create_epoch_identity_secret(context, rng).await?;
        self.load_persisted_key_advertisement_identity(
            &secret,
            Some(context.digest()),
            signing_seed,
            expected_signing_public_key,
            secret.public_key(),
        )
        .await
    }

    /// Persist the externally provisioned genesis X25519 secret and return identity authority only
    /// after reopening and authenticating the exact active record.
    ///
    /// Exact retries are idempotent. A conflicting key, retired epoch, mismatched stable signing
    /// seed, or mismatched configured X25519 public key fails closed.
    pub async fn persist_epoch_advertisement_identity<R: RngCore + CryptoRng>(
        &self,
        secret: &EpochEncryptionSecret,
        signing_seed: &[u8; 32],
        expected_signing_public_key: [u8; 32],
        expected_encryption_public_key: [u8; 32],
        rng: &mut R,
    ) -> Result<PersistedKeyAdvertisementIdentity, StoreError> {
        validate_signing_seed(signing_seed, expected_signing_public_key)?;
        validate_epoch_identity_secret(self.party, secret)?;
        if secret.public_key() != expected_encryption_public_key {
            return Err(StoreError::EpochIdentityConflict { epoch: secret.epoch() });
        }
        self.save_epoch_identity_secret(secret, rng).await?;
        self.load_persisted_key_advertisement_identity(
            secret,
            None,
            signing_seed,
            expected_signing_public_key,
            expected_encryption_public_key,
        )
        .await
    }

    /// Promote the local target-epoch candidate selected by an exact durable key-rotation
    /// certificate.
    ///
    /// The caller passes the candidate it previously loaded or created. If the certificate
    /// includes this party, its exact fresh advertised candidate is retained. An omitted eligible
    /// identity is not a successor member and cannot call this method successfully. No source or
    /// bootstrap secret is accepted as a replacement.
    ///
    /// The immutable certificate must already be present in this store. A retired source or
    /// target identity is never recreated, and a target record certified by any other decision is
    /// rejected.
    pub async fn promote_certified_epoch_identity_secret<R: RngCore + CryptoRng>(
        &self,
        context: &KeyRotationContext,
        certificate: &KeyRotationCertificate,
        candidate: &EpochEncryptionSecret,
        rng: &mut R,
    ) -> Result<EpochEncryptionSecret, StoreError> {
        context.validate()?;
        context.target_policy().eligible().member(self.party).map_err(KeyRotationError::from)?;
        validate_epoch_identity_secret(self.party, candidate)?;
        if candidate.epoch() != context.target_epoch() {
            return Err(StoreError::EpochIdentityConflict { epoch: candidate.epoch() });
        }
        let key = key_rotation_round_key(context);
        let mut mutation = self.mutation.lock().await;
        if let Some(retirement) = mutation.retired_epoch_identities.get(&context.target_epoch()) {
            return Err(StoreError::EpochIdentityRetired {
                epoch: context.target_epoch(),
                successor_epoch: retirement.successor_epoch,
            });
        }
        let durable = self.canonical_key_rotation_certificate(context, certificate).await?;
        let target = durable.verify(context)?;
        let target_member = target.member(self.party).map_err(KeyRotationError::from)?;
        if candidate.public_key() != target_member.encryption_key {
            return Err(StoreError::EpochIdentityConflict { epoch: context.target_epoch() });
        }
        let certificate_bytes = Zeroizing::new(durable.encode(context)?);
        let certification = EpochIdentityCertification {
            version: EPOCH_IDENTITY_CERTIFICATION_VERSION,
            source_epoch: context.source().epoch,
            target_epoch: context.target_epoch(),
            target_public_key: target_member.encryption_key,
            context_digest: context.digest(),
            certificate_digest: key_rotation_certificate_digest(key, &certificate_bytes),
        };

        // A source-committee member must prove continuity with its durable source-epoch identity:
        // the certified decision's authority flowed through that exact key. A joiner promoted into
        // the successor has no source record and is exempt. Active and Retired records both
        // satisfy continuity when the stored key matches the certified source member key; a
        // missing or divergent source record fails closed so a substituted store cannot launder
        // an unrelated identity into the successor epoch.
        if let Ok(source_member) = context.source().member(self.party) {
            let source_epoch = context.source().epoch;
            let source_identity_path = self.epoch_identity_path(source_epoch);
            if !entry_exists_regular(&source_identity_path).await? {
                return Err(StoreError::EpochIdentityConflict { epoch: source_epoch });
            }
            let (stored_source_public_key, _) =
                self.open_epoch_identity_record(source_epoch).await?;
            if stored_source_public_key != source_member.encryption_key {
                return Err(StoreError::EpochIdentityConflict { epoch: source_epoch });
            }
        }

        let target_path = self.epoch_identity_path(context.target_epoch());
        if !entry_exists_regular(&target_path).await? {
            return Err(StoreError::EpochIdentityConflict { epoch: context.target_epoch() });
        }
        let (stored_target_public_key, target_record) =
            self.open_epoch_identity_record(context.target_epoch()).await?;
        let target_active = match &target_record {
            EpochIdentityRecord::Retired(retirement) => {
                mutation.retired_epoch_identities.insert(context.target_epoch(), *retirement);
                return Err(StoreError::EpochIdentityRetired {
                    epoch: context.target_epoch(),
                    successor_epoch: retirement.successor_epoch,
                });
            }
            EpochIdentityRecord::Active(active) => active,
        };
        if target_active.candidate_context != Some(context.digest()) {
            return Err(StoreError::EpochIdentityPolicyConflict { epoch: context.target_epoch() });
        }
        if let Some(existing) = target_active.certification {
            if existing != certification || stored_target_public_key != target_member.encryption_key
            {
                return Err(StoreError::EpochIdentityCertificationConflict {
                    epoch: context.target_epoch(),
                });
            }
            return epoch_identity_from_active(self.party, target_active);
        }

        let current_candidate = epoch_identity_from_active(self.party, target_active)?;
        if current_candidate != *candidate {
            return Err(StoreError::EpochIdentityConflict { epoch: context.target_epoch() });
        }

        let promoted = current_candidate;
        if promoted.public_key() != target_member.encryption_key {
            return Err(StoreError::EpochIdentityConflict { epoch: context.target_epoch() });
        }

        let promoted_record = EpochIdentityRecord::Active(ActiveEpochIdentitySecret {
            version: EPOCH_IDENTITY_RECORD_VERSION,
            epoch: promoted.epoch(),
            public_key: promoted.public_key(),
            secret: *promoted.secret_bytes(),
            candidate_context: Some(context.digest()),
            certification: Some(certification),
        });
        let encoded = Zeroizing::new(
            postcard::to_allocvec(&promoted_record).map_err(|_| StoreError::Serialization)?,
        );
        let record_context = ProtocolRecordContext::EpochIdentity {
            epoch: promoted.epoch(),
            public_key: promoted.public_key(),
        };
        let sealed = self.seal_protocol_record(
            record_context,
            &encoded,
            MAX_EPOCH_IDENTITY_RECORD_BYTES,
            rng,
        )?;
        atomic_replace(&target_path, &sealed.encoded, sealed.nonce).await?;
        destroy_temporary_replacements(&target_path).await?;

        // Promotion authorizes identity construction, so it has the same mandatory durable
        // readback boundary as advertisement creation.
        let (durable_public_key, durable_record) =
            self.open_epoch_identity_record(context.target_epoch()).await?;
        let EpochIdentityRecord::Active(durable_active) = &durable_record else {
            return Err(StoreError::EpochIdentityConflict { epoch: context.target_epoch() });
        };
        if durable_public_key != target_member.encryption_key
            || durable_active.certification != Some(certification)
        {
            return Err(StoreError::EpochIdentityCertificationConflict {
                epoch: context.target_epoch(),
            });
        }
        let durable_promoted = epoch_identity_from_active(self.party, durable_active)?;
        if durable_promoted != promoted {
            return Err(StoreError::EpochIdentityConflict { epoch: context.target_epoch() });
        }
        Ok(durable_promoted)
    }

    /// Permanently erase this party's unselected target candidate after authenticating the exact
    /// terminal rotation certificate.
    ///
    /// The immutable certificate is the deletion authority. A selected candidate, a candidate
    /// created for another context, or an already-certified identity fails closed. Replaying the
    /// same certificate after the file is absent is idempotent, which also makes restart clean up
    /// a rolled-back unselected candidate before it can be advertised again.
    pub async fn destroy_unselected_epoch_identity_secret(
        &self,
        context: &KeyRotationContext,
        certificate: &KeyRotationCertificate,
    ) -> Result<bool, StoreError> {
        context.validate()?;
        context.target_policy().eligible().member(self.party).map_err(KeyRotationError::from)?;
        let _mutation = self.mutation.lock().await;
        let durable = self.canonical_key_rotation_certificate(context, certificate).await?;
        let target = durable.verify(context)?;
        if target.member(self.party).is_ok() {
            return Err(StoreError::EpochIdentityPolicyConflict { epoch: context.target_epoch() });
        }
        let path = self.epoch_identity_path(context.target_epoch());
        if !entry_exists_regular(&path).await? {
            return Ok(false);
        }
        let (_, record) = self.open_epoch_identity_record(context.target_epoch()).await?;
        match &record {
            EpochIdentityRecord::Active(active)
                if active.candidate_context == Some(context.digest())
                    && active.certification.is_none() =>
            {
                drop(epoch_identity_from_active(self.party, active)?);
            }
            _ => {
                return Err(StoreError::EpochIdentityPolicyConflict {
                    epoch: context.target_epoch(),
                });
            }
        }
        destroy_file_and_sync_parent(&path).await?;
        Ok(true)
    }

    /// Load a dynamic epoch identity and exact-bind it to the committee's expected public key.
    pub async fn load_epoch_identity_secret(
        &self,
        epoch: u64,
        expected_public_key: [u8; 32],
    ) -> Result<Option<EpochEncryptionSecret>, StoreError> {
        let mut mutation = self.mutation.lock().await;
        let destination = self.epoch_identity_path(epoch);
        if !directory_exists(&self.directory).await? || !entry_exists_regular(&destination).await? {
            if mutation.retired_epoch_identities.contains_key(&epoch) {
                return Err(StoreError::EpochIdentityRollbackDetected { epoch });
            }
            return Ok(None);
        }
        let (stored_public_key, record) = self.open_epoch_identity_record(epoch).await?;
        if mutation.retired_epoch_identities.contains_key(&epoch)
            && matches!(&record, EpochIdentityRecord::Active(_))
        {
            return Err(StoreError::EpochIdentityRollbackDetected { epoch });
        }
        if stored_public_key != expected_public_key {
            return Err(StoreError::EpochIdentityConflict { epoch });
        }
        match &record {
            EpochIdentityRecord::Active(active) => {
                Ok(Some(epoch_identity_from_active(self.party, active)?))
            }
            EpochIdentityRecord::Retired(retirement) => {
                if let Some(observed) = mutation.retired_epoch_identities.get(&epoch)
                    && observed != retirement
                {
                    return Err(StoreError::EpochIdentityRetirementConflict { epoch });
                }
                mutation.retired_epoch_identities.insert(epoch, *retirement);
                Err(StoreError::EpochIdentityRetired {
                    epoch,
                    successor_epoch: retirement.successor_epoch,
                })
            }
        }
    }

    async fn load_persisted_key_advertisement_identity(
        &self,
        expected_secret: &EpochEncryptionSecret,
        expected_candidate_context: Option<[u8; 32]>,
        signing_seed: &[u8; 32],
        expected_signing_public_key: [u8; 32],
        expected_encryption_public_key: [u8; 32],
    ) -> Result<PersistedKeyAdvertisementIdentity, StoreError> {
        validate_signing_seed(signing_seed, expected_signing_public_key)?;
        validate_epoch_identity_secret(self.party, expected_secret)?;
        let epoch = expected_secret.epoch();
        if expected_secret.public_key() != expected_encryption_public_key {
            return Err(StoreError::EpochIdentityConflict { epoch });
        }

        let mut mutation = self.mutation.lock().await;
        if let Some(retirement) = mutation.retired_epoch_identities.get(&epoch) {
            return Err(StoreError::EpochIdentityRetired {
                epoch,
                successor_epoch: retirement.successor_epoch,
            });
        }
        let destination = self.epoch_identity_path(epoch);
        if !directory_exists(&self.directory).await? || !entry_exists_regular(&destination).await? {
            return Err(StoreError::EpochIdentityConflict { epoch });
        }
        let (stored_public_key, record) = self.open_epoch_identity_record(epoch).await?;
        let active = match &record {
            EpochIdentityRecord::Active(active) => active,
            EpochIdentityRecord::Retired(retirement) => {
                mutation.retired_epoch_identities.insert(epoch, *retirement);
                return Err(StoreError::EpochIdentityRetired {
                    epoch,
                    successor_epoch: retirement.successor_epoch,
                });
            }
        };
        if active.certification.is_some() {
            // A certified record has a different canonical digest from the pre-decision
            // candidate. Reissuing an advertisement capability here could make an honest restart
            // equivocate solely because its persistence receipt changed.
            return Err(StoreError::EpochIdentityCertificationConflict { epoch });
        }
        if active.candidate_context != expected_candidate_context {
            return Err(StoreError::EpochIdentityPolicyConflict { epoch });
        }
        if stored_public_key != expected_encryption_public_key {
            return Err(StoreError::EpochIdentityConflict { epoch });
        }
        let durable_secret = epoch_identity_from_active(self.party, active)?;
        if durable_secret != *expected_secret {
            return Err(StoreError::EpochIdentityConflict { epoch });
        }

        // Construct the usable identity only after the exact active record has passed AEAD,
        // canonical-encoding, metadata, and public-key derivation checks.
        let identity = Identity::from_encryption_secret(
            self.party,
            epoch,
            signing_seed,
            expected_signing_public_key,
            expected_encryption_public_key,
            &durable_secret,
        )?;
        let durable_record_digest = epoch_identity_record_digest(self.party, &record)?;
        Ok(identity.after_durable_encryption_readback(durable_record_digest)?)
    }

    /// Authenticate a permanent retirement marker without recovering any secret bytes.
    pub async fn load_epoch_identity_retirement(
        &self,
        epoch: u64,
        expected_public_key: [u8; 32],
    ) -> Result<Option<EpochIdentityRetirement>, StoreError> {
        let mut mutation = self.mutation.lock().await;
        let destination = self.epoch_identity_path(epoch);
        if !directory_exists(&self.directory).await? || !entry_exists_regular(&destination).await? {
            if mutation.retired_epoch_identities.contains_key(&epoch) {
                return Err(StoreError::EpochIdentityRollbackDetected { epoch });
            }
            return Ok(None);
        }
        let (stored_public_key, record) = self.open_epoch_identity_record(epoch).await?;
        if mutation.retired_epoch_identities.contains_key(&epoch)
            && matches!(&record, EpochIdentityRecord::Active(_))
        {
            return Err(StoreError::EpochIdentityRollbackDetected { epoch });
        }
        if stored_public_key != expected_public_key {
            return Err(StoreError::EpochIdentityConflict { epoch });
        }
        match record {
            EpochIdentityRecord::Active(_) => Ok(None),
            EpochIdentityRecord::Retired(retirement) => {
                if let Some(observed) = mutation.retired_epoch_identities.get(&epoch)
                    && *observed != retirement
                {
                    return Err(StoreError::EpochIdentityRetirementConflict { epoch });
                }
                mutation.retired_epoch_identities.insert(epoch, retirement);
                Ok(Some(retirement))
            }
        }
    }

    /// List and authenticate dynamic epoch-identity records with a hard traversal bound.
    pub async fn epoch_identities_bounded(&self, maximum: usize) -> Result<Vec<u64>, StoreError> {
        if !directory_exists(&self.directory).await? {
            return Ok(Vec::new());
        }
        let epochs = enumerate_protocol_directory_bounded(
            &self.epoch_identity_directory(),
            parse_epoch_identity_filename,
            maximum,
            "epoch identity",
        )
        .await?;
        for epoch in &epochs {
            drop(self.open_epoch_identity_record(*epoch).await?);
        }
        Ok(epochs)
    }

    /// Destroy one source epoch's dynamic X25519 secret after a directly certified fresh-key
    /// successor or certified removal from the successor committee.
    pub async fn retire_epoch_identity_secret<R: RngCore + CryptoRng>(
        &self,
        context: &KeyRotationContext,
        certificate: &KeyRotationCertificate,
        rng: &mut R,
    ) -> Result<EpochIdentityRetirement, StoreError> {
        context.validate()?;
        let mut mutation = self.mutation.lock().await;
        ensure_private_directory(&self.directory).await?;
        let durable = self.canonical_key_rotation_certificate(context, certificate).await?;
        let (retirement, target_certification) =
            epoch_identity_retirement_authorization(self.party, context, &durable)?;

        if let Some((target_public_key, expected_certification)) = target_certification {
            let target_path = self.epoch_identity_path(context.target_epoch());
            if !entry_exists_regular(&target_path).await? {
                return Err(StoreError::EpochIdentityConflict { epoch: context.target_epoch() });
            }
            let (stored_target_public_key, target_record) =
                self.open_epoch_identity_record(context.target_epoch()).await?;
            match &target_record {
                EpochIdentityRecord::Active(target) => {
                    if stored_target_public_key != target_public_key
                        || target.certification != Some(expected_certification)
                    {
                        return Err(StoreError::EpochIdentityCertificationConflict {
                            epoch: context.target_epoch(),
                        });
                    }
                }
                EpochIdentityRecord::Retired(target_retirement) => {
                    // The target identity is no longer Active because it has itself been durably
                    // retired. This is exactly the state a *terminal* replay of this source
                    // handoff observes after later epochs advanced: the successor whose freshly
                    // certified key authorized erasing this source has since been superseded and
                    // erased in turn. Treating the source retirement as already-complete here is
                    // safe ONLY under durable proof that the target was retired to its own
                    // immediate certified successor — never on a merely absent or non-certified
                    // target. The target retirement's `successor_epoch` (always target_epoch + 1
                    // by the strictly-sequential authorization invariant) is that proof; anything
                    // else, or a record inconsistent with a prior in-memory observation, stays
                    // fail-closed so a forged or mis-linked retirement can never manufacture a
                    // source erasure.
                    if stored_target_public_key != target_public_key {
                        return Err(StoreError::EpochIdentityConflict {
                            epoch: context.target_epoch(),
                        });
                    }
                    if let Some(observed) =
                        mutation.retired_epoch_identities.get(&context.target_epoch())
                        && observed != target_retirement
                    {
                        return Err(StoreError::EpochIdentityRetirementConflict {
                            epoch: context.target_epoch(),
                        });
                    }
                    let expected_target_successor = context.target_epoch().checked_add(1).ok_or(
                        StoreError::EpochIdentityConflict { epoch: context.target_epoch() },
                    )?;
                    if target_retirement.successor_epoch != expected_target_successor {
                        return Err(StoreError::EpochIdentityConflict {
                            epoch: context.target_epoch(),
                        });
                    }
                    mutation
                        .retired_epoch_identities
                        .insert(context.target_epoch(), *target_retirement);
                    // Fall through to the source-retirement handling below. That block is already
                    // idempotent: it returns the durable retirement when the source record is
                    // already Retired, or completes the erasure when the source secret still
                    // exists, so on every replay path the source secret cannot outlive the
                    // certified handoff.
                }
            }
        }

        let source_path = self.epoch_identity_path(retirement.epoch);
        if !entry_exists_regular(&source_path).await? {
            return Err(StoreError::EpochIdentityConflict { epoch: retirement.epoch });
        }
        let (source_public_key, source_record) =
            self.open_epoch_identity_record(retirement.epoch).await?;
        if source_public_key != retirement.public_key {
            return Err(StoreError::EpochIdentityConflict { epoch: retirement.epoch });
        }
        match &source_record {
            EpochIdentityRecord::Retired(existing) => {
                if *existing != retirement {
                    return Err(StoreError::EpochIdentityRetirementConflict {
                        epoch: retirement.epoch,
                    });
                }
                mutation.retired_epoch_identities.insert(retirement.epoch, retirement);
                destroy_temporary_replacements(&source_path).await?;
                return Ok(retirement);
            }
            EpochIdentityRecord::Active(source) => {
                drop(epoch_identity_from_active(self.party, source)?);
            }
        }

        let record = EpochIdentityRecord::Retired(retirement);
        let encoded =
            Zeroizing::new(postcard::to_allocvec(&record).map_err(|_| StoreError::Serialization)?);
        let record_context = ProtocolRecordContext::EpochIdentity {
            epoch: retirement.epoch,
            public_key: retirement.public_key,
        };
        let sealed = self.seal_protocol_record(
            record_context,
            &encoded,
            MAX_EPOCH_IDENTITY_RECORD_BYTES,
            rng,
        )?;
        atomic_replace(&source_path, &sealed.encoded, sealed.nonce).await?;
        destroy_temporary_replacements(&source_path).await?;
        mutation.retired_epoch_identities.insert(retirement.epoch, retirement);
        Ok(retirement)
    }

    /// Verify a source-secret retirement against its exact certified fresh-key transition.
    pub fn verify_epoch_identity_retirement(
        &self,
        retirement: EpochIdentityRetirement,
        context: &KeyRotationContext,
        certificate: &KeyRotationCertificate,
    ) -> Result<(), StoreError> {
        let (expected, _) =
            epoch_identity_retirement_authorization(self.party, context, certificate)?;
        if retirement != expected {
            return Err(StoreError::InvalidEpochIdentityRetirement);
        }
        Ok(())
    }

    /// Atomically replace one opaque state snapshot unless the session is permanently tombstoned.
    pub async fn save_session_state<R: RngCore + CryptoRng>(
        &self,
        session: SessionId,
        context_digest: [u8; 32],
        state: &[u8],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        let _mutation = self.mutation.lock().await;
        let _namespace = self.lock_session_namespace().await?;
        if entry_exists_regular(&self.session_tombstone_path(session)).await? {
            return Err(StoreError::SessionTombstoned(session));
        }
        let keys = self.session_state_keys_bounded().await?;
        let mut matching_state = false;
        for key in &keys {
            if key.session != session {
                continue;
            }
            drop(self.load_session_state(key.session, key.context_digest).await?);
            if key.context_digest != context_digest {
                return Err(StoreError::SessionContextConflict { session });
            }
            matching_state = true;
        }
        if !matching_state && keys.len() == MAX_SESSION_STATE_RECORDS {
            return Err(StoreError::ProtocolEntryLimit {
                kind: "session state",
                maximum: MAX_SESSION_STATE_RECORDS,
            });
        }
        let context = ProtocolRecordContext::SessionState { session, context_digest };
        let sealed = self.seal_protocol_record(context, state, MAX_SESSION_STATE_BYTES, rng)?;
        atomic_replace(
            &self.session_state_path(session, context_digest),
            &sealed.encoded,
            sealed.nonce,
        )
        .await
    }

    pub async fn load_session_state(
        &self,
        session: SessionId,
        context_digest: [u8; 32],
    ) -> Result<ProtocolBlob, StoreError> {
        require_directory(&self.directory).await?;
        let expected = ProtocolRecordContext::SessionState { session, context_digest };
        let (_, plaintext) = self
            .open_protocol_record(
                &self.session_state_path(session, context_digest),
                ExpectedProtocolContext::Exact(expected),
                MAX_SESSION_STATE_BYTES,
            )
            .await?;
        Ok(plaintext)
    }

    /// Boundedly list and authenticate every active session-state snapshot.
    ///
    /// Directory traversal rejects record `MAX_SESSION_STATE_RECORDS + 1` before opening any
    /// ciphertext. Every accepted ciphertext is returned from that one authentication pass.
    pub async fn session_states(&self) -> Result<Vec<StoredSessionState>, StoreError> {
        let _mutation = self.mutation.lock().await;
        if !directory_exists(&self.directory).await? {
            return Ok(Vec::new());
        }
        let _namespace = self.lock_session_namespace().await?;
        let keys = self.session_state_keys_bounded().await?;
        self.authenticate_session_states(keys).await
    }

    /// Move an authenticated session snapshot to quarantine; no destructive delete API exists.
    ///
    /// To close a session permanently, durably save its tombstone before calling this method.
    pub async fn retire_session_state(
        &self,
        session: SessionId,
        context_digest: [u8; 32],
    ) -> Result<PathBuf, StoreError> {
        let _mutation = self.mutation.lock().await;
        let _namespace = self.lock_session_namespace().await?;
        require_directory(&self.directory).await?;
        drop(self.load_session_state(session, context_digest).await?);
        self.retire_protocol_file(
            &self.session_state_path(session, context_digest),
            MAX_SESSION_STATE_BYTES + AEAD_TAG_BYTES + MAX_RECORD_OVERHEAD_BYTES,
        )
        .await
    }

    /// Destroy a secret-bearing session snapshot after authenticating both it and the permanent
    /// session tombstone which forbids recreation. This is the AVSS retirement recovery path.
    /// Repeating it after the state file has disappeared is idempotent.
    ///
    /// `remove_file` plus directory fsync prevents this application from reopening the snapshot
    /// on the current filesystem namespace. It cannot erase copy-on-write blocks, volume
    /// snapshots, backups, or crash dumps; the long-lived identity seed also still decrypts any
    /// such recovered protocol-store record.
    pub async fn destroy_tombstoned_session_state(
        &self,
        session: SessionId,
        context_digest: [u8; 32],
    ) -> Result<(), StoreError> {
        let _mutation = self.mutation.lock().await;
        let _namespace = self.lock_session_namespace().await?;
        require_directory(&self.directory).await?;
        drop(self.load_session_tombstone(session).await?);
        let keys = self.session_state_keys_bounded().await?;
        let mut matching_state = false;
        for key in keys {
            if key.session != session {
                continue;
            }
            drop(self.load_session_state(key.session, key.context_digest).await?);
            if key.context_digest != context_digest {
                return Err(StoreError::SessionContextConflict { session });
            }
            matching_state = true;
        }
        let path = self.session_state_path(session, context_digest);
        if matching_state {
            destroy_file_and_sync_parent(&path).await?;
        } else if directory_exists(&self.session_directory()).await? {
            destroy_temporary_replacements(&path).await?;
        }
        Ok(())
    }

    async fn open_sweep_signing_high_water(
        &self,
        wallet: DepositWalletId,
        sweep: SweepId,
    ) -> Result<SweepSigningHighWater, StoreError> {
        let expected = ProtocolRecordContext::SweepSigningHighWater { wallet, sweep };
        let (_, plaintext) = self
            .open_protocol_record(
                &self.sweep_signing_high_water_path(wallet, sweep),
                ExpectedProtocolContext::Exact(expected),
                MAX_SWEEP_SIGNING_HIGH_WATER_BYTES,
            )
            .await?;
        let record = decode_canonical_exact::<SweepSigningHighWater>(
            plaintext.as_bytes(),
            "sweep signing high-water",
        )?;
        validate_sweep_signing_high_water(record)?;
        if record.wallet != wallet || record.sweep != sweep {
            return Err(StoreError::WrongContext);
        }
        Ok(record)
    }

    /// Monotonically claim one deterministic wallet/sweep signing attempt.
    ///
    /// The authenticated record is replaced and read back before a one-use receipt is returned.
    /// An exact retry returns `Existing`; an older attempt is a rollback and a different binding
    /// at the same attempt is a fork. Therefore deleting compacted per-attempt detail cannot turn
    /// an already observed high-water into fresh nonce authority.
    async fn claim_sweep_signing_high_water<R: RngCore + CryptoRng>(
        &self,
        wallet: DepositWalletId,
        sweep: SweepId,
        attempt: u64,
        session: SessionId,
        intent_digest: [u8; 32],
        tombstone_purpose: &[u8],
        rng: &mut R,
    ) -> Result<SweepSigningHighWaterClaim, StoreError> {
        if tombstone_purpose.is_empty() {
            return Err(StoreError::EmptyTombstonePurpose);
        }
        if tombstone_purpose.len() > MAX_SESSION_TOMBSTONE_PURPOSE_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "session tombstone purpose",
                actual: tombstone_purpose.len(),
                maximum: MAX_SESSION_TOMBSTONE_PURPOSE_BYTES,
            });
        }
        let candidate = SweepSigningHighWater {
            version: SWEEP_SIGNING_HIGH_WATER_VERSION,
            wallet,
            sweep,
            attempt,
            session,
            intent_digest,
            tombstone_purpose_digest: session_tombstone_purpose_digest(session, tombstone_purpose),
        };
        validate_sweep_signing_high_water(candidate)?;

        let mut mutation = self.mutation.lock().await;
        ensure_private_directory(&self.directory).await?;
        ensure_private_directory(&self.sweep_signing_high_water_directory()).await?;
        let key = (wallet, sweep);
        let destination = self.sweep_signing_high_water_path(wallet, sweep);
        let existing = if entry_exists_regular(&destination).await? {
            Some(self.open_sweep_signing_high_water(wallet, sweep).await?)
        } else {
            None
        };
        if let Some(observed) = mutation.sweep_signing_high_waters.get(&key) {
            match existing {
                None => return Err(StoreError::SweepSigningHighWaterDisappeared),
                Some(found) if found.attempt < observed.attempt => {
                    return Err(StoreError::SweepSigningHighWaterRollback {
                        stored: observed.attempt,
                        attempted: found.attempt,
                    });
                }
                Some(found) if found.attempt == observed.attempt && found != *observed => {
                    return Err(StoreError::SweepSigningHighWaterConflict);
                }
                Some(_) => {}
            }
        }
        if let Some(existing) = existing {
            if candidate.attempt < existing.attempt {
                return Err(StoreError::SweepSigningHighWaterRollback {
                    stored: existing.attempt,
                    attempted: candidate.attempt,
                });
            }
            if candidate.attempt == existing.attempt {
                if candidate != existing {
                    return Err(StoreError::SweepSigningHighWaterConflict);
                }
                mutation.sweep_signing_high_waters.insert(key, existing);
                return Ok(SweepSigningHighWaterClaim::Existing);
            }
        }

        let plaintext = postcard::to_allocvec(&candidate).map_err(|_| StoreError::Serialization)?;
        let context = ProtocolRecordContext::SweepSigningHighWater { wallet, sweep };
        let sealed = self.seal_protocol_record(
            context,
            &plaintext,
            MAX_SWEEP_SIGNING_HIGH_WATER_BYTES,
            rng,
        )?;
        atomic_replace(&destination, &sealed.encoded, sealed.nonce).await?;
        let readback = self.open_sweep_signing_high_water(wallet, sweep).await?;
        if readback != candidate {
            return Err(StoreError::SweepSigningHighWaterConflict);
        }
        mutation.sweep_signing_high_waters.insert(key, readback);
        Ok(SweepSigningHighWaterClaim::Advanced(PersistedSweepSigningHighWaterReceipt(readback)))
    }

    /// Claim the monotonic wallet/sweep attempt and its exact one-use session namespace as one
    /// typed nonce boundary. The records use separate crash-consistent files, so a crash can land
    /// between them; replay then observes `Existing`, creates/authenticates the missing exact
    /// tombstone, and returns `Burned` without exposing either receipt.
    pub(crate) async fn claim_sweep_signing_nonce_boundary<R: RngCore + CryptoRng>(
        &self,
        wallet: DepositWalletId,
        sweep: SweepId,
        attempt: u64,
        session: SessionId,
        intent_digest: [u8; 32],
        tombstone_purpose: &[u8],
        rng: &mut R,
    ) -> Result<SweepSigningNonceClaim, StoreError> {
        match self
            .claim_sweep_signing_high_water(
                wallet,
                sweep,
                attempt,
                session,
                intent_digest,
                tombstone_purpose,
                rng,
            )
            .await?
        {
            SweepSigningHighWaterClaim::Existing => {
                self.save_session_tombstone(session, tombstone_purpose, rng).await?;
                Ok(SweepSigningNonceClaim::Burned)
            }
            SweepSigningHighWaterClaim::Advanced(family) => {
                match self.claim_session_tombstone(session, tombstone_purpose, rng).await? {
                    SessionTombstoneClaim::Created(receipt) => Ok(SweepSigningNonceClaim::Fresh {
                        family,
                        session: SessionTombstoneClaim::Created(receipt),
                    }),
                    SessionTombstoneClaim::Existing => Ok(SweepSigningNonceClaim::Burned),
                }
            }
        }
    }

    /// Permanently record why a session identifier must never be reused.
    ///
    /// Repeating the same tombstone is idempotent. A different purpose for the same session is a
    /// conflict and the original authenticated tombstone remains authoritative.
    pub async fn save_session_tombstone<R: RngCore + CryptoRng>(
        &self,
        session: SessionId,
        purpose: &[u8],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        drop(self.claim_session_tombstone(session, purpose, rng).await?);
        Ok(())
    }

    /// Claim a previously unused session identifier at the persistent nonce-creation boundary.
    ///
    /// Both outcomes authenticate an exact readback of `purpose`. Only a create-new installation
    /// returns the non-cloneable receipt. An exact idempotent retry returns `Existing`, so a
    /// process restart cannot turn an old tombstone into fresh nonce authority.
    pub(crate) async fn claim_session_tombstone<R: RngCore + CryptoRng>(
        &self,
        session: SessionId,
        purpose: &[u8],
        rng: &mut R,
    ) -> Result<SessionTombstoneClaim, StoreError> {
        if purpose.is_empty() {
            return Err(StoreError::EmptyTombstonePurpose);
        }
        if purpose.len() > MAX_SESSION_TOMBSTONE_PURPOSE_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "session tombstone purpose",
                actual: purpose.len(),
                maximum: MAX_SESSION_TOMBSTONE_PURPOSE_BYTES,
            });
        }

        let _mutation = self.mutation.lock().await;
        let _namespace = self.lock_session_namespace().await?;
        for key in self.session_state_keys_bounded().await? {
            if key.session == session {
                drop(self.load_session_state(key.session, key.context_digest).await?);
                return Err(StoreError::LiveSessionState(session));
            }
        }
        let destination = self.session_tombstone_path(session);
        if entry_exists_regular(&destination).await? {
            self.require_tombstone_purpose(session, purpose).await?;
            return Ok(SessionTombstoneClaim::Existing);
        }

        let context = ProtocolRecordContext::SessionTombstone { session };
        let sealed =
            self.seal_protocol_record(context, purpose, MAX_SESSION_TOMBSTONE_PURPOSE_BYTES, rng)?;
        if atomic_create_new(&destination, &sealed.encoded, sealed.nonce).await? {
            self.require_tombstone_purpose(session, purpose).await?;
            Ok(SessionTombstoneClaim::Created(PersistedSessionTombstoneReceipt {
                session,
                purpose_digest: session_tombstone_purpose_digest(session, purpose),
            }))
        } else {
            self.require_tombstone_purpose(session, purpose).await?;
            Ok(SessionTombstoneClaim::Existing)
        }
    }

    /// Atomically claim the permanent tombstone namespace and destroy the matching live state
    /// under the same in-process storage lock. This is the only valid AVSS close path; generic
    /// tombstone creation rejects every live session so Frost and AVSS cannot win opposite halves
    /// of a check-then-write race. The tombstone is durable before the secret-bearing state is
    /// unlinked, so a crash can only leave a state file which startup must finish destroying.
    pub async fn close_session_state<R: RngCore + CryptoRng>(
        &self,
        session: SessionId,
        context_digest: [u8; 32],
        purpose: &[u8],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        if purpose.is_empty() {
            return Err(StoreError::EmptyTombstonePurpose);
        }
        if purpose.len() > MAX_SESSION_TOMBSTONE_PURPOSE_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "session tombstone purpose",
                actual: purpose.len(),
                maximum: MAX_SESSION_TOMBSTONE_PURPOSE_BYTES,
            });
        }
        let _mutation = self.mutation.lock().await;
        let _namespace = self.lock_session_namespace().await?;
        let mut matching_state = false;
        for key in self.session_state_keys_bounded().await? {
            if key.session != session {
                continue;
            }
            drop(self.load_session_state(key.session, key.context_digest).await?);
            if key.context_digest != context_digest {
                return Err(StoreError::SessionContextConflict { session });
            }
            matching_state = true;
        }
        let destination = self.session_tombstone_path(session);
        if entry_exists_regular(&destination).await? {
            self.require_tombstone_purpose(session, purpose).await?;
        } else {
            let context = ProtocolRecordContext::SessionTombstone { session };
            let sealed = self.seal_protocol_record(
                context,
                purpose,
                MAX_SESSION_TOMBSTONE_PURPOSE_BYTES,
                rng,
            )?;
            if !atomic_create_new(&destination, &sealed.encoded, sealed.nonce).await? {
                self.require_tombstone_purpose(session, purpose).await?;
            }
        }
        if matching_state {
            destroy_file_and_sync_parent(&self.session_state_path(session, context_digest)).await?;
        } else if directory_exists(&self.session_directory()).await? {
            // A public-history catch-up party may never have owned this AVSS reducer. The
            // certificate still authorizes installing its permanent tombstone, but there is no
            // session directory (and therefore no temporary replacement) to scan or erase.
            destroy_temporary_replacements(&self.session_state_path(session, context_digest))
                .await?;
        }
        Ok(())
    }

    pub async fn load_session_tombstone(
        &self,
        session: SessionId,
    ) -> Result<SessionTombstone, StoreError> {
        require_directory(&self.directory).await?;
        let (context, purpose) = self
            .open_protocol_record(
                &self.session_tombstone_path(session),
                ExpectedProtocolContext::Tombstone(session),
                MAX_SESSION_TOMBSTONE_PURPOSE_BYTES,
            )
            .await?;
        let ProtocolRecordContext::SessionTombstone { .. } = context else {
            return Err(StoreError::WrongContext);
        };
        if purpose.is_empty() {
            return Err(StoreError::WrongContext);
        }
        Ok(SessionTombstone { session, purpose })
    }

    /// Persist a certificate before immutably publishing its exact transition lookup.
    ///
    /// A crash may leave a certificate without its index. Repeating this exact operation repairs
    /// that in-flight write, while startup rejects the incomplete store. An index is never created
    /// before its referenced certificate.
    pub async fn save_indexed_activation_certificate<R: RngCore + CryptoRng>(
        &self,
        epoch: u64,
        transition_digest: [u8; 32],
        activation_digest: [u8; 32],
        certificate: &[u8],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        let _mutation = self.mutation.lock().await;
        ensure_private_directory(&self.directory).await?;
        let transition = ActivationTransitionKey { epoch, transition_digest };
        let index_path = self.activation_transition_index_path(transition);
        if entry_exists_regular(&index_path).await? {
            let existing = self.load_activation_transition_index_entry(transition).await?;
            if existing.activation_digest != activation_digest {
                return Err(StoreError::ActivationIndexConflict { epoch, transition_digest });
            }
            // Index-first or dangling state cannot result from the supported write ordering.
            // Refuse to use a new certificate write as an implicit corruption repair.
            drop(self.load_activation_certificate(epoch, activation_digest).await?);
        }
        self.create_activation_certificate_locked(epoch, activation_digest, certificate, rng)
            .await?;
        self.install_activation_transition_index_locked(transition, activation_digest, rng).await?;
        let indexed = self
            .load_activation_certificate_for_transition(transition)
            .await?
            .ok_or(StoreError::InvalidActivationIndex)?;
        if indexed.key.activation_digest != activation_digest {
            return Err(StoreError::InvalidActivationIndex);
        }
        Ok(())
    }

    async fn create_activation_certificate_locked<R: RngCore + CryptoRng>(
        &self,
        epoch: u64,
        activation_digest: [u8; 32],
        certificate: &[u8],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        let destination = self.activation_certificate_path(epoch, activation_digest);
        if entry_exists_regular(&destination).await? {
            let existing = self.load_activation_certificate(epoch, activation_digest).await?;
            return if existing.as_bytes() == certificate {
                Ok(())
            } else {
                Err(StoreError::ActivationCertificateConflict { epoch, activation_digest })
            };
        }
        let context = ProtocolRecordContext::ActivationCertificate { epoch, activation_digest };
        let sealed =
            self.seal_protocol_record(context, certificate, MAX_ACTIVATION_CERTIFICATE_BYTES, rng)?;
        if !atomic_create_new(&destination, &sealed.encoded, sealed.nonce).await? {
            let existing = self.load_activation_certificate(epoch, activation_digest).await?;
            if existing.as_bytes() != certificate {
                return Err(StoreError::ActivationCertificateConflict { epoch, activation_digest });
            }
        }
        Ok(())
    }

    /// Rebuild one missing current-format transition index after the caller has authenticated and
    /// semantically verified its current-format activation certificate. Existing malformed or
    /// conflicting records are never overwritten.
    pub async fn ensure_activation_transition_index<R: RngCore + CryptoRng>(
        &self,
        key: ActivationTransitionKey,
        activation_digest: [u8; 32],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        let _mutation = self.mutation.lock().await;
        ensure_private_directory(&self.directory).await?;
        self.install_activation_transition_index_locked(key, activation_digest, rng).await
    }

    async fn install_activation_transition_index_locked<R: RngCore + CryptoRng>(
        &self,
        key: ActivationTransitionKey,
        activation_digest: [u8; 32],
        rng: &mut R,
    ) -> Result<(), StoreError> {
        drop(self.load_activation_certificate(key.epoch, activation_digest).await?);
        let destination = self.activation_transition_index_path(key);
        if entry_exists_regular(&destination).await? {
            let existing = self.load_activation_transition_index_entry(key).await?;
            return if existing.activation_digest == activation_digest {
                Ok(())
            } else {
                Err(StoreError::ActivationIndexConflict {
                    epoch: key.epoch,
                    transition_digest: key.transition_digest,
                })
            };
        }
        let entry =
            ActivationTransitionIndexEntry { version: ACTIVATION_INDEX_VERSION, activation_digest };
        let encoded = postcard::to_allocvec(&entry).map_err(|_| StoreError::Serialization)?;
        let context = ProtocolRecordContext::ActivationTransitionIndex {
            epoch: key.epoch,
            transition_digest: key.transition_digest,
        };
        let sealed =
            self.seal_protocol_record(context, &encoded, MAX_ACTIVATION_INDEX_BYTES, rng)?;
        if !atomic_create_new(&destination, &sealed.encoded, sealed.nonce).await? {
            let existing = self.load_activation_transition_index_entry(key).await?;
            if existing.activation_digest != activation_digest {
                return Err(StoreError::ActivationIndexConflict {
                    epoch: key.epoch,
                    transition_digest: key.transition_digest,
                });
            }
        }
        Ok(())
    }

    pub async fn load_activation_certificate(
        &self,
        epoch: u64,
        activation_digest: [u8; 32],
    ) -> Result<ProtocolBlob, StoreError> {
        require_directory(&self.directory).await?;
        let expected = ProtocolRecordContext::ActivationCertificate { epoch, activation_digest };
        let (_, plaintext) = self
            .open_protocol_record(
                &self.activation_certificate_path(epoch, activation_digest),
                ExpectedProtocolContext::Exact(expected),
                MAX_ACTIVATION_CERTIFICATE_BYTES,
            )
            .await?;
        Ok(plaintext)
    }

    async fn load_activation_transition_index_entry(
        &self,
        key: ActivationTransitionKey,
    ) -> Result<ActivationTransitionIndexEntry, StoreError> {
        require_directory(&self.directory).await?;
        let expected = ProtocolRecordContext::ActivationTransitionIndex {
            epoch: key.epoch,
            transition_digest: key.transition_digest,
        };
        let (_, plaintext) = self
            .open_protocol_record(
                &self.activation_transition_index_path(key),
                ExpectedProtocolContext::Exact(expected),
                MAX_ACTIVATION_INDEX_BYTES,
            )
            .await?;
        let entry: ActivationTransitionIndexEntry =
            decode_canonical_exact(&plaintext, "activation transition index")?;
        if entry.version != ACTIVATION_INDEX_VERSION {
            return Err(StoreError::InvalidActivationIndex);
        }
        Ok(entry)
    }

    /// Resolve one transition with two exact authenticated reads and no directory enumeration.
    pub async fn load_activation_certificate_for_transition(
        &self,
        key: ActivationTransitionKey,
    ) -> Result<Option<IndexedActivationCertificate>, StoreError> {
        if !directory_exists(&self.directory).await?
            || !directory_exists(&self.activation_index_directory()).await?
            || !entry_exists_regular(&self.activation_transition_index_path(key)).await?
        {
            return Ok(None);
        }
        let index = self.load_activation_transition_index_entry(key).await?;
        let certificate_key = ActivationCertificateKey {
            epoch: key.epoch,
            activation_digest: index.activation_digest,
        };
        let certificate = self
            .load_activation_certificate(certificate_key.epoch, certificate_key.activation_digest)
            .await?;
        Ok(Some(IndexedActivationCertificate { key: certificate_key, certificate }))
    }

    /// List and authenticate all active epoch-activation certificates.
    pub async fn activation_certificates(
        &self,
    ) -> Result<Vec<ActivationCertificateKey>, StoreError> {
        self.activation_certificates_bounded(usize::MAX).await
    }

    /// List and authenticate activation certificates while enforcing the bound during traversal.
    pub async fn activation_certificates_bounded(
        &self,
        maximum: usize,
    ) -> Result<Vec<ActivationCertificateKey>, StoreError> {
        if !directory_exists(&self.directory).await? {
            return Ok(Vec::new());
        }
        let keys = enumerate_protocol_directory_bounded(
            &self.activation_directory(),
            parse_activation_filename,
            maximum,
            "activation certificate",
        )
        .await?;
        for key in &keys {
            drop(self.load_activation_certificate(key.epoch, key.activation_digest).await?);
        }
        Ok(keys)
    }

    /// List and authenticate transition indexes for startup audit.
    pub async fn activation_transition_indexes_bounded(
        &self,
        maximum: usize,
    ) -> Result<Vec<(ActivationTransitionKey, [u8; 32])>, StoreError> {
        if !directory_exists(&self.directory).await? {
            return Ok(Vec::new());
        }
        let keys = enumerate_protocol_directory_bounded(
            &self.activation_index_directory(),
            parse_activation_index_filename,
            maximum,
            "activation transition index",
        )
        .await?;
        let mut entries = Vec::with_capacity(keys.len());
        for key in keys {
            let entry = self.load_activation_transition_index_entry(key).await?;
            entries.push((key, entry.activation_digest));
        }
        Ok(entries)
    }

    /// Destroy the duplicate current-volume activation certificate and transition index after the
    /// caller has installed and authenticated the exact certificate in immutable epoch history.
    ///
    /// The index is removed first. A crash between the two deletions therefore leaves an
    /// unindexed certificate which is safe to authenticate and delete on retry; it can never
    /// leave an index pointing at a missing certificate. Absence of both records is idempotent.
    pub(crate) async fn destroy_archived_activation_records(
        &self,
        transition: ActivationTransitionKey,
        activation_digest: [u8; 32],
    ) -> Result<(), StoreError> {
        let _mutation = self.mutation.lock().await;
        require_directory(&self.directory).await?;
        let index_path = self.activation_transition_index_path(transition);
        let certificate_path =
            self.activation_certificate_path(transition.epoch, activation_digest);
        let index_exists = entry_exists_regular(&index_path).await?;
        let certificate_exists = entry_exists_regular(&certificate_path).await?;

        if index_exists {
            if !certificate_exists {
                return Err(StoreError::InvalidActivationIndex);
            }
            let index = self.load_activation_transition_index_entry(transition).await?;
            if index.activation_digest != activation_digest {
                return Err(StoreError::ActivationIndexConflict {
                    epoch: transition.epoch,
                    transition_digest: transition.transition_digest,
                });
            }
            drop(self.load_activation_certificate(transition.epoch, activation_digest).await?);
            destroy_file_and_sync_parent(&index_path).await?;
        }
        if certificate_exists {
            drop(self.load_activation_certificate(transition.epoch, activation_digest).await?);
            destroy_file_and_sync_parent(&certificate_path).await?;
        }
        Ok(())
    }

    /// Move an authenticated activation certificate to quarantine.
    pub async fn retire_activation_certificate(
        &self,
        epoch: u64,
        activation_digest: [u8; 32],
    ) -> Result<PathBuf, StoreError> {
        let _mutation = self.mutation.lock().await;
        require_directory(&self.directory).await?;
        drop(self.load_activation_certificate(epoch, activation_digest).await?);
        for (transition, indexed_digest) in
            self.activation_transition_indexes_bounded(usize::MAX).await?
        {
            if transition.epoch == epoch && indexed_digest == activation_digest {
                return Err(StoreError::IndexedActivationCertificateRetirement {
                    epoch,
                    activation_digest,
                });
            }
        }
        self.retire_protocol_file(
            &self.activation_certificate_path(epoch, activation_digest),
            MAX_ACTIVATION_CERTIFICATE_BYTES + AEAD_TAG_BYTES + MAX_RECORD_OVERHEAD_BYTES,
        )
        .await
    }

    async fn open_deposit_sync_spool_head(
        &self,
        key: DepositSyncSpoolHeadKey,
    ) -> Result<DepositSyncSpoolHeadBlob, StoreError> {
        let (_, plaintext) = self
            .open_protocol_record(
                &self.deposit_sync_spool_head_path(key),
                ExpectedProtocolContext::Exact(deposit_sync_spool_head_context(key)),
                MAX_DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_BYTES,
            )
            .await?;
        let (metadata, state) =
            decode_deposit_sync_spool_head_snapshot(self.party, key, plaintext.as_bytes())?;
        Ok(DepositSyncSpoolHeadBlob { metadata, state: ProtocolBlob(state.to_vec()) })
    }

    async fn open_deposit_state_transfer_intents(
        &self,
        network_id: [u8; 32],
    ) -> Result<DepositStateTransferIntentsBlob, StoreError> {
        let (_, plaintext) = self
            .open_protocol_record(
                &self.deposit_state_transfer_intents_path(),
                ExpectedProtocolContext::Exact(
                    ProtocolRecordContext::DepositStateTransferIntents { network_id },
                ),
                MAX_DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_BYTES,
            )
            .await?;
        let (metadata, state) = decode_deposit_state_transfer_intents_snapshot(
            self.party,
            network_id,
            plaintext.as_bytes(),
        )?;
        Ok(DepositStateTransferIntentsBlob { metadata, state: ProtocolBlob(state.to_vec()) })
    }

    async fn open_key_rotation_round(
        &self,
        context: &KeyRotationContext,
    ) -> Result<OpenKeyRotationRound, StoreError> {
        let key = key_rotation_round_key(context);
        let expected = ProtocolRecordContext::KeyRotationRound {
            target_epoch: key.target_epoch,
            context_digest: key.context_digest,
        };
        let (_, plaintext) = self
            .open_protocol_record(
                &self.key_rotation_round_path(key),
                ExpectedProtocolContext::Exact(expected),
                MAX_KEY_ROTATION_SNAPSHOT_BYTES,
            )
            .await?;
        let Some(tag) = plaintext.first().copied() else {
            return Err(StoreError::Serialization);
        };
        match tag {
            0 => {
                let (metadata, state) =
                    decode_key_rotation_snapshot_header(self.party, key, &plaintext)?;
                let round = KeyRotationRound::decode(context, self.party, state)?;
                Ok(OpenKeyRotationRound::Active(StoredKeyRotationRound { metadata, round }))
            }
            1 if plaintext.len() == 33 => {
                let mut digest = [0_u8; 32];
                digest.copy_from_slice(&plaintext[1..]);
                if digest == [0_u8; 32] {
                    return Err(StoreError::Authentication);
                }
                Ok(OpenKeyRotationRound::Retired(digest))
            }
            _ => Err(StoreError::NonCanonicalEncoding { kind: "key rotation round snapshot" }),
        }
    }

    async fn open_key_rotation_certificate(
        &self,
        context: &KeyRotationContext,
    ) -> Result<KeyRotationCertificate, StoreError> {
        let key = key_rotation_round_key(context);
        let expected = ProtocolRecordContext::KeyRotationCertificate {
            target_epoch: key.target_epoch,
            context_digest: key.context_digest,
        };
        let (_, plaintext) = self
            .open_protocol_record(
                &self.key_rotation_certificate_path(key),
                ExpectedProtocolContext::Exact(expected),
                MAX_KEY_ROTATION_CERTIFICATE_BYTES,
            )
            .await?;
        Ok(KeyRotationCertificate::decode(context, &plaintext)?)
    }

    async fn save_epoch_identity_secret_locked<R: RngCore + CryptoRng>(
        &self,
        identity: &EpochEncryptionSecret,
        candidate_context: Option<[u8; 32]>,
        rng: &mut R,
    ) -> Result<(), StoreError> {
        validate_epoch_identity_secret(self.party, identity)?;
        let epoch = identity.epoch();
        let public_key = identity.public_key();
        let destination = self.epoch_identity_path(epoch);
        if entry_exists_regular(&destination).await? {
            let (stored_public_key, existing) = self.open_epoch_identity_record(epoch).await?;
            return match &existing {
                EpochIdentityRecord::Active(active)
                    if stored_public_key == public_key
                        && active.secret.as_slice() == identity.secret_bytes()
                        && active.candidate_context == candidate_context =>
                {
                    Ok(())
                }
                EpochIdentityRecord::Retired(retirement) => Err(StoreError::EpochIdentityRetired {
                    epoch,
                    successor_epoch: retirement.successor_epoch,
                }),
                EpochIdentityRecord::Active(_) => Err(StoreError::EpochIdentityConflict { epoch }),
            };
        }
        let record = EpochIdentityRecord::Active(ActiveEpochIdentitySecret {
            version: EPOCH_IDENTITY_RECORD_VERSION,
            epoch,
            public_key,
            secret: *identity.secret_bytes(),
            candidate_context,
            certification: None,
        });
        let encoded =
            Zeroizing::new(postcard::to_allocvec(&record).map_err(|_| StoreError::Serialization)?);
        let record_context = ProtocolRecordContext::EpochIdentity { epoch, public_key };
        let sealed = self.seal_protocol_record(
            record_context,
            &encoded,
            MAX_EPOCH_IDENTITY_RECORD_BYTES,
            rng,
        )?;
        if !atomic_create_new(&destination, &sealed.encoded, sealed.nonce).await? {
            let (stored_public_key, existing) = self.open_epoch_identity_record(epoch).await?;
            match &existing {
                EpochIdentityRecord::Active(active)
                    if stored_public_key == public_key
                        && active.secret.as_slice() == identity.secret_bytes()
                        && active.candidate_context == candidate_context => {}
                EpochIdentityRecord::Retired(retirement) => {
                    return Err(StoreError::EpochIdentityRetired {
                        epoch,
                        successor_epoch: retirement.successor_epoch,
                    });
                }
                EpochIdentityRecord::Active(_) => {
                    return Err(StoreError::EpochIdentityConflict { epoch });
                }
            }
        }
        Ok(())
    }

    async fn open_epoch_identity_record(
        &self,
        epoch: u64,
    ) -> Result<([u8; 32], EpochIdentityRecord), StoreError> {
        let (record_context, plaintext) = self
            .open_protocol_record(
                &self.epoch_identity_path(epoch),
                ExpectedProtocolContext::EpochIdentity(epoch),
                MAX_EPOCH_IDENTITY_RECORD_BYTES,
            )
            .await?;
        let ProtocolRecordContext::EpochIdentity { public_key, .. } = record_context else {
            return Err(StoreError::WrongContext);
        };
        let record: EpochIdentityRecord =
            decode_canonical_exact(&plaintext, "epoch identity record")?;
        let canonical =
            Zeroizing::new(postcard::to_allocvec(&record).map_err(|_| StoreError::Serialization)?);
        if canonical.as_slice() != plaintext.as_bytes() {
            return Err(StoreError::NonCanonicalEncoding { kind: "epoch identity record" });
        }
        match &record {
            EpochIdentityRecord::Active(active) => {
                if active.version != EPOCH_IDENTITY_RECORD_VERSION
                    || active.epoch != epoch
                    || active.public_key != public_key
                    || X25519PublicKey::from(&StaticSecret::from(active.secret)).to_bytes()
                        != public_key
                    || (epoch == 0 && active.candidate_context.is_some())
                    || (epoch > 0
                        && active.candidate_context.is_none_or(|digest| digest == [0_u8; 32]))
                {
                    return Err(StoreError::WrongContext);
                }
                if let Some(certification) = active.certification
                    && (certification.version != EPOCH_IDENTITY_CERTIFICATION_VERSION
                        || certification.source_epoch.checked_add(1)
                            != Some(certification.target_epoch)
                        || certification.target_epoch != epoch
                        || certification.target_public_key != public_key
                        || active.candidate_context != Some(certification.context_digest)
                        || certification.context_digest == [0_u8; 32]
                        || certification.certificate_digest == [0_u8; 32])
                {
                    return Err(StoreError::WrongContext);
                }
            }
            EpochIdentityRecord::Retired(retirement) => {
                validate_epoch_identity_retirement(*retirement)?;
                if retirement.epoch != epoch || retirement.public_key != public_key {
                    return Err(StoreError::WrongContext);
                }
            }
        }
        Ok((public_key, record))
    }

    fn observe_key_rotation_snapshot(
        observed: &mut BTreeMap<KeyRotationRoundKey, KeyRotationRoundMetadata>,
        found: KeyRotationRoundMetadata,
    ) -> Result<(), StoreError> {
        let Some(highest) = observed.get(&found.key).copied() else {
            observed.insert(found.key, found);
            return Ok(());
        };
        if found.revision < highest.revision {
            return Err(StoreError::KeyRotationRollbackDetected {
                key: found.key,
                highest_seen: highest.revision,
                found: found.revision,
            });
        }
        if found.revision == highest.revision {
            if found != highest {
                return Err(StoreError::KeyRotationForkDetected {
                    key: found.key,
                    revision: found.revision,
                });
            }
            return Ok(());
        }
        let expected = highest
            .revision
            .checked_add(1)
            .ok_or(StoreError::KeyRotationRevisionExhausted(found.key))?;
        if found.revision != expected {
            return Err(StoreError::KeyRotationRevisionNotNext {
                key: found.key,
                expected,
                actual: found.revision,
            });
        }
        if found.previous_snapshot_hash != highest.snapshot_hash {
            return Err(StoreError::KeyRotationHashChainMismatch {
                key: found.key,
                revision: found.revision,
            });
        }
        observed.insert(found.key, found);
        Ok(())
    }

    fn observe_deposit_sync_spool_head_snapshot(
        observed: &mut BTreeMap<DepositSyncSpoolHeadKey, DepositSyncSpoolHeadMetadata>,
        found: DepositSyncSpoolHeadMetadata,
    ) -> Result<(), StoreError> {
        let Some(highest) = observed.get(&found.key).copied() else {
            observed.insert(found.key, found);
            return Ok(());
        };
        if found.revision < highest.revision {
            return Err(StoreError::DepositSyncSpoolHeadRollbackDetected {
                key: found.key,
                highest_seen: highest.revision,
                found: found.revision,
            });
        }
        if found.revision == highest.revision {
            if found != highest {
                return Err(StoreError::DepositSyncSpoolHeadForkDetected {
                    key: found.key,
                    revision: found.revision,
                });
            }
            return Ok(());
        }
        let expected = highest
            .revision
            .checked_add(1)
            .ok_or(StoreError::DepositSyncSpoolHeadRevisionExhausted(found.key))?;
        if found.revision != expected {
            return Err(StoreError::DepositSyncSpoolHeadMismatch {
                key: found.key,
                expected_revision: expected,
                actual_revision: found.revision,
            });
        }
        if found.previous_snapshot_hash != highest.snapshot_hash {
            return Err(StoreError::DepositSyncSpoolHeadHashChainMismatch {
                key: found.key,
                revision: found.revision,
            });
        }
        observed.insert(found.key, found);
        Ok(())
    }

    fn observe_deposit_state_transfer_intents_snapshot(
        observed: &mut BTreeMap<[u8; 32], DepositStateTransferIntentsMetadata>,
        found: DepositStateTransferIntentsMetadata,
    ) -> Result<(), StoreError> {
        let network_id = found.network_id;
        let Some(highest) = observed.get(&network_id).copied() else {
            observed.insert(network_id, found);
            return Ok(());
        };
        if found.revision < highest.revision {
            return Err(StoreError::DepositStateTransferIntentsRollbackDetected {
                network_id,
                highest_seen: highest.revision,
                found: found.revision,
            });
        }
        if found.revision == highest.revision {
            if found != highest {
                return Err(StoreError::DepositStateTransferIntentsForkDetected {
                    network_id,
                    revision: found.revision,
                });
            }
            return Ok(());
        }
        let expected = highest
            .revision
            .checked_add(1)
            .ok_or(StoreError::DepositStateTransferIntentsRevisionExhausted { network_id })?;
        if found.revision != expected {
            return Err(StoreError::DepositStateTransferIntentsMismatch {
                network_id,
                expected_revision: expected,
                actual_revision: found.revision,
            });
        }
        if found.previous_snapshot_hash != highest.snapshot_hash {
            return Err(StoreError::DepositStateTransferIntentsHashChainMismatch {
                network_id,
                revision: found.revision,
            });
        }
        observed.insert(network_id, found);
        Ok(())
    }

    fn session_directory(&self) -> PathBuf {
        self.directory.join(SESSION_STATE_DIRECTORY)
    }

    fn session_namespace_lock_path(&self) -> PathBuf {
        self.directory.join(SESSION_NAMESPACE_LOCK_FILE)
    }

    async fn lock_session_namespace(&self) -> Result<SessionNamespaceLock, StoreError> {
        ensure_private_directory(&self.directory).await?;
        let path = self.session_namespace_lock_path();
        let open_path = path.clone();
        let (file, created) =
            tokio::task::spawn_blocking(move || -> Result<(std::fs::File, bool), StoreError> {
                let (file, created) = {
                    let mut options = std::fs::OpenOptions::new();
                    options.read(true).write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;

                        options.mode(0o600);
                    }
                    match options.open(&open_path) {
                        Ok(file) => (file, true),
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                            let link_metadata = std::fs::symlink_metadata(&open_path)?;
                            if !link_metadata.is_file() {
                                return Err(StoreError::NotRegularFile(open_path));
                            }
                            let file = std::fs::OpenOptions::new()
                                .read(true)
                                .write(true)
                                .open(&open_path)?;
                            let opened_metadata = file.metadata()?;
                            let current_link_metadata = std::fs::symlink_metadata(&open_path)?;
                            if !opened_metadata.is_file()
                                || !current_link_metadata.is_file()
                                || !same_file_identity(&opened_metadata, &current_link_metadata)
                            {
                                return Err(StoreError::NotRegularFile(open_path));
                            }
                            (file, false)
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                if created {
                    file.sync_all()?;
                }
                file.lock()?;
                Ok((file, created))
            })
            .await
            .map_err(io::Error::other)??;
        if created {
            sync_directory(&self.directory).await?;
        }
        Ok(SessionNamespaceLock(file))
    }

    async fn session_state_keys_bounded(&self) -> Result<Vec<SessionStateKey>, StoreError> {
        enumerate_protocol_directory_bounded(
            &self.session_directory(),
            parse_session_state_filename,
            MAX_SESSION_STATE_RECORDS,
            "session state",
        )
        .await
    }

    async fn authenticate_session_states(
        &self,
        keys: Vec<SessionStateKey>,
    ) -> Result<Vec<StoredSessionState>, StoreError> {
        let mut contexts = BTreeMap::new();
        let mut states = Vec::with_capacity(keys.len());
        for key in keys {
            let state = self.load_session_state(key.session, key.context_digest).await?;
            if let Some(existing) = contexts.insert(key.session, key.context_digest)
                && existing != key.context_digest
            {
                return Err(StoreError::SessionContextConflict { session: key.session });
            }
            states.push(StoredSessionState {
                session: key.session,
                context_digest: key.context_digest,
                state,
            });
        }
        Ok(states)
    }

    fn tombstone_directory(&self) -> PathBuf {
        self.directory.join(TOMBSTONE_DIRECTORY)
    }

    fn activation_directory(&self) -> PathBuf {
        self.directory.join(ACTIVATION_DIRECTORY)
    }

    fn activation_index_directory(&self) -> PathBuf {
        self.directory.join(ACTIVATION_INDEX_DIRECTORY)
    }

    fn key_rotation_round_directory(&self) -> PathBuf {
        self.directory.join(KEY_ROTATION_ROUND_DIRECTORY)
    }

    fn key_rotation_certificate_directory(&self) -> PathBuf {
        self.directory.join(KEY_ROTATION_CERTIFICATE_DIRECTORY)
    }

    fn sweep_signing_high_water_directory(&self) -> PathBuf {
        self.directory.join(SWEEP_SIGNING_HIGH_WATER_DIRECTORY)
    }

    fn deposit_index_journal_directory(&self) -> PathBuf {
        self.directory.join(DEPOSIT_INDEX_JOURNAL_DIRECTORY)
    }

    fn deposit_sync_spool_head_directory(&self) -> PathBuf {
        self.directory.join(DEPOSIT_SYNC_SPOOL_HEAD_DIRECTORY)
    }

    fn epoch_identity_directory(&self) -> PathBuf {
        self.directory.join(EPOCH_IDENTITY_DIRECTORY)
    }

    fn retired_directory(&self) -> PathBuf {
        self.directory.join(RETIRED_DIRECTORY)
    }

    fn seal_protocol_record<R: RngCore + CryptoRng>(
        &self,
        context: ProtocolRecordContext,
        plaintext: &[u8],
        maximum: usize,
        rng: &mut R,
    ) -> Result<SealedRecordBytes, StoreError> {
        if plaintext.len() > maximum {
            return Err(StoreError::BlobTooLarge {
                kind: context.kind(),
                actual: plaintext.len(),
                maximum,
            });
        }
        let plaintext_len =
            u64::try_from(plaintext.len()).map_err(|_| StoreError::Serialization)?;
        let header = ProtocolRecordHeader {
            version: PROTOCOL_STORE_VERSION,
            party: self.party,
            context,
            plaintext_len,
        };
        let aad = protocol_associated_data(&header)?;
        let mut nonce = [0_u8; 24];
        rng.fill_bytes(&mut nonce);
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(&self.key))
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| StoreError::Authentication)?;
        let encoded = postcard::to_allocvec(&SealedProtocolRecord { header, nonce, ciphertext })
            .map_err(|_| StoreError::Serialization)?;
        let maximum_encoded = maximum
            .checked_add(AEAD_TAG_BYTES + MAX_RECORD_OVERHEAD_BYTES)
            .ok_or(StoreError::Serialization)?;
        if encoded.len() > maximum_encoded {
            return Err(StoreError::BlobTooLarge {
                kind: "sealed protocol record",
                actual: encoded.len(),
                maximum: maximum_encoded,
            });
        }
        Ok(SealedRecordBytes { encoded, nonce })
    }

    async fn open_protocol_record(
        &self,
        path: &Path,
        expected: ExpectedProtocolContext,
        maximum: usize,
    ) -> Result<(ProtocolRecordContext, ProtocolBlob), StoreError> {
        let parent =
            path.parent().ok_or_else(|| StoreError::UnexpectedEntry(path.to_path_buf()))?;
        require_directory(parent).await?;
        let maximum_encoded = maximum
            .checked_add(AEAD_TAG_BYTES + MAX_RECORD_OVERHEAD_BYTES)
            .ok_or(StoreError::Serialization)?;
        let bytes =
            read_capped_regular_file(path, maximum_encoded, "sealed protocol record").await?;
        let sealed: SealedProtocolRecord =
            decode_canonical_exact(&bytes, "sealed protocol record")?;
        if sealed.header.version != PROTOCOL_STORE_VERSION
            || sealed.header.party != self.party
            || !expected.matches(&sealed.header.context)
        {
            return Err(StoreError::WrongContext);
        }
        let plaintext_len =
            usize::try_from(sealed.header.plaintext_len).map_err(|_| StoreError::Serialization)?;
        if plaintext_len > maximum {
            return Err(StoreError::BlobTooLarge {
                kind: expected.kind(),
                actual: plaintext_len,
                maximum,
            });
        }
        let expected_ciphertext_len =
            plaintext_len.checked_add(AEAD_TAG_BYTES).ok_or(StoreError::Serialization)?;
        if sealed.ciphertext.len() != expected_ciphertext_len {
            return Err(StoreError::Authentication);
        }
        let aad = protocol_associated_data(&sealed.header)?;
        let mut plaintext = XChaCha20Poly1305::new(Key::from_slice(&self.key))
            .decrypt(
                XNonce::from_slice(&sealed.nonce),
                Payload { msg: &sealed.ciphertext, aad: &aad },
            )
            .map_err(|_| StoreError::Authentication)?;
        if plaintext.len() != plaintext_len {
            plaintext.zeroize();
            return Err(StoreError::Authentication);
        }
        Ok((sealed.header.context, ProtocolBlob(plaintext)))
    }

    async fn require_tombstone_purpose(
        &self,
        session: SessionId,
        expected_purpose: &[u8],
    ) -> Result<(), StoreError> {
        let tombstone = self.load_session_tombstone(session).await?;
        if tombstone.purpose() == expected_purpose {
            Ok(())
        } else {
            Err(StoreError::TombstoneConflict(session))
        }
    }

    async fn retire_protocol_file(
        &self,
        source: &Path,
        maximum_encoded: usize,
    ) -> Result<PathBuf, StoreError> {
        let bytes =
            read_capped_regular_file(source, maximum_encoded, "sealed protocol record").await?;
        let source_name = source
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| StoreError::UnexpectedEntry(source.to_path_buf()))?;
        let retired_directory = self.retired_directory();
        ensure_private_directory(&retired_directory).await?;
        let destination = retired_directory.join(format!(
            "{source_name}.{}.retired",
            hex::encode(blake3::hash(&bytes).as_bytes())
        ));
        ensure_destination_absent(&destination).await?;
        tokio::fs::rename(source, &destination).await?;
        sync_directory(&retired_directory).await?;
        sync_directory(
            source.parent().ok_or_else(|| StoreError::UnexpectedEntry(source.to_path_buf()))?,
        )
        .await?;
        Ok(destination)
    }
}

impl WalletSnapshotStore {
    /// Construct a wallet store with key material and paths independent from both share and
    /// protocol-session storage.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::KeyDerivation`] if the storage key cannot be derived.
    pub fn new(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
    ) -> Result<Self, StoreError> {
        let hk = Hkdf::<Sha256>::new(
            Some(b"threshold-monero/wallet-snapshot-store/root/v1"),
            identity_seed,
        );
        let mut key = [0_u8; 32];
        let mut info = b"xchacha20poly1305/party/".to_vec();
        info.extend_from_slice(&party.0.to_le_bytes());
        hk.expand(&info, &mut key).map_err(|_| StoreError::KeyDerivation)?;
        Ok(Self {
            directory: directory
                .into()
                .join(WALLET_SNAPSHOT_DIRECTORY)
                .join(format!("party-{}", party.0)),
            party,
            key,
            mutation: Mutex::new(BTreeMap::new()),
        })
    }

    #[must_use]
    pub fn wallet_directory(&self) -> &Path {
        &self.directory
    }

    #[must_use]
    pub fn wallet_snapshot_path(&self, wallet_id: WalletId) -> PathBuf {
        self.directory.join(format!("{}.wallet", hex::encode(wallet_id.0)))
    }

    /// Save an exact reducer snapshot at the next revision.
    ///
    /// Revision zero initializes a wallet. Every subsequent write must be the exact successor of
    /// the authenticated durable revision. Repeating a write after an uncertain response is
    /// idempotent only when both revision and plaintext bytes are identical.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized state, an unauthentic or context-mismatched durable
    /// record, a revision fork/gap/rollback, or a storage I/O failure.
    pub async fn save_snapshot<R: RngCore + CryptoRng>(
        &self,
        wallet_id: WalletId,
        revision: u64,
        state: &[u8],
        rng: &mut R,
    ) -> Result<WalletSnapshotMetadata, StoreError> {
        if state.len() > MAX_WALLET_SNAPSHOT_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "wallet snapshot",
                actual: state.len(),
                maximum: MAX_WALLET_SNAPSHOT_BYTES,
            });
        }

        let mut observed = self.mutation.lock().await;
        self.ensure_wallet_directory().await?;
        let destination = self.wallet_snapshot_path(wallet_id);
        let current = if entry_exists_regular(&destination).await? {
            let snapshot = self.open_wallet_snapshot(&destination, wallet_id).await?;
            Self::observe_snapshot(&mut observed, snapshot.metadata)?;
            Some(snapshot)
        } else {
            if let Some(highest) = observed.get(&wallet_id) {
                return Err(StoreError::WalletSnapshotDisappeared {
                    wallet_id,
                    highest_seen: highest.revision,
                });
            }
            None
        };

        let previous_snapshot_hash = if let Some(current) = current {
            if revision == current.metadata.revision {
                if current.state.as_bytes() == state {
                    return Ok(current.metadata);
                }
                return Err(StoreError::WalletRevisionConflict { wallet_id, revision });
            }
            let expected = current
                .metadata
                .revision
                .checked_add(1)
                .ok_or(StoreError::WalletRevisionExhausted { wallet_id })?;
            if revision != expected {
                return Err(StoreError::WalletRevisionNotNext {
                    wallet_id,
                    expected,
                    actual: revision,
                });
            }
            current.metadata.snapshot_hash
        } else {
            if revision != 0 {
                return Err(StoreError::WalletRevisionMustStartAtZero {
                    wallet_id,
                    actual: revision,
                });
            }
            [0_u8; 32]
        };

        let sealed =
            self.seal_wallet_snapshot(wallet_id, revision, previous_snapshot_hash, state, rng)?;
        let metadata = sealed.header.metadata();
        let encoded = postcard::to_allocvec(&sealed).map_err(|_| StoreError::Serialization)?;
        let maximum_encoded = wallet_maximum_encoded_bytes()?;
        if encoded.len() > maximum_encoded {
            return Err(StoreError::BlobTooLarge {
                kind: "sealed wallet snapshot",
                actual: encoded.len(),
                maximum: maximum_encoded,
            });
        }
        atomic_replace(&destination, &encoded, sealed.nonce).await?;
        observed.insert(wallet_id, metadata);
        Ok(metadata)
    }

    /// Load and authenticate the current wallet snapshot.
    ///
    /// Storage authenticates the exact byte string; the owning current-format reducer remains
    /// responsible for semantic and canonical validation against its expected protocol context.
    ///
    /// # Errors
    ///
    /// Returns an error if the file is absent/malformed/oversized, authentication or context
    /// binding fails, an in-process rollback/fork is found, or an I/O operation fails.
    pub async fn load_snapshot(&self, wallet_id: WalletId) -> Result<WalletSnapshot, StoreError> {
        let mut observed = self.mutation.lock().await;
        let path = self.wallet_snapshot_path(wallet_id);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Err(StoreError::NotRegularFile(path)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if let Some(highest) = observed.get(&wallet_id) {
                    return Err(StoreError::WalletSnapshotDisappeared {
                        wallet_id,
                        highest_seen: highest.revision,
                    });
                }
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        }
        let snapshot = self.open_wallet_snapshot(&path, wallet_id).await?;
        Self::observe_snapshot(&mut observed, snapshot.metadata)?;
        Ok(snapshot)
    }

    fn seal_wallet_snapshot<R: RngCore + CryptoRng>(
        &self,
        wallet_id: WalletId,
        revision: u64,
        previous_snapshot_hash: [u8; 32],
        state: &[u8],
        rng: &mut R,
    ) -> Result<SealedWalletSnapshot, StoreError> {
        let plaintext_len = u64::try_from(state.len()).map_err(|_| StoreError::Serialization)?;
        let snapshot_hash = wallet_snapshot_hash(
            self.party,
            wallet_id,
            revision,
            previous_snapshot_hash,
            plaintext_len,
            state,
        );
        let header = WalletSnapshotHeader {
            version: WALLET_SNAPSHOT_STORE_VERSION,
            party: self.party,
            wallet_id,
            revision,
            previous_snapshot_hash,
            snapshot_hash,
            plaintext_len,
        };
        let aad = wallet_associated_data(&header)?;
        let mut nonce = [0_u8; 24];
        rng.fill_bytes(&mut nonce);
        let key = self.wallet_key(wallet_id)?;
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: state, aad: &aad })
            .map_err(|_| StoreError::Authentication)?;
        Ok(SealedWalletSnapshot { header, nonce, ciphertext })
    }

    async fn open_wallet_snapshot(
        &self,
        path: &Path,
        expected_wallet_id: WalletId,
    ) -> Result<WalletSnapshot, StoreError> {
        let maximum_encoded = wallet_maximum_encoded_bytes()?;
        let bytes =
            read_capped_regular_file(path, maximum_encoded, "sealed wallet snapshot").await?;
        let sealed: SealedWalletSnapshot =
            decode_canonical_exact(&bytes, "sealed wallet snapshot")?;
        if sealed.header.version != WALLET_SNAPSHOT_STORE_VERSION
            || sealed.header.party != self.party
            || sealed.header.wallet_id != expected_wallet_id
        {
            return Err(StoreError::WrongContext);
        }
        let plaintext_len =
            usize::try_from(sealed.header.plaintext_len).map_err(|_| StoreError::Serialization)?;
        if plaintext_len > MAX_WALLET_SNAPSHOT_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "wallet snapshot",
                actual: plaintext_len,
                maximum: MAX_WALLET_SNAPSHOT_BYTES,
            });
        }
        let expected_ciphertext_len =
            plaintext_len.checked_add(AEAD_TAG_BYTES).ok_or(StoreError::Serialization)?;
        if sealed.ciphertext.len() != expected_ciphertext_len {
            return Err(StoreError::Authentication);
        }
        let aad = wallet_associated_data(&sealed.header)?;
        let key = self.wallet_key(expected_wallet_id)?;
        let mut plaintext = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
            .decrypt(
                XNonce::from_slice(&sealed.nonce),
                Payload { msg: &sealed.ciphertext, aad: &aad },
            )
            .map_err(|_| StoreError::Authentication)?;
        if plaintext.len() != plaintext_len {
            plaintext.zeroize();
            return Err(StoreError::Authentication);
        }
        let computed_hash = wallet_snapshot_hash(
            self.party,
            expected_wallet_id,
            sealed.header.revision,
            sealed.header.previous_snapshot_hash,
            sealed.header.plaintext_len,
            &plaintext,
        );
        if computed_hash != sealed.header.snapshot_hash {
            plaintext.zeroize();
            return Err(StoreError::Authentication);
        }
        if sealed.header.revision == 0 && sealed.header.previous_snapshot_hash != [0_u8; 32] {
            plaintext.zeroize();
            return Err(StoreError::WalletHashChainMismatch {
                wallet_id: expected_wallet_id,
                revision: sealed.header.revision,
            });
        }
        Ok(WalletSnapshot {
            metadata: sealed.header.metadata(),
            state: WalletSnapshotBlob(plaintext),
        })
    }

    fn wallet_key(&self, wallet_id: WalletId) -> Result<Zeroizing<[u8; 32]>, StoreError> {
        let hk = Hkdf::<Sha256>::new(
            Some(b"threshold-monero/wallet-snapshot-store/per-wallet-key/v1"),
            &self.key,
        );
        let mut key = Zeroizing::new([0_u8; 32]);
        let mut info = b"xchacha20poly1305/wallet/".to_vec();
        info.extend_from_slice(&wallet_id.0);
        hk.expand(&info, key.as_mut()).map_err(|_| StoreError::KeyDerivation)?;
        Ok(key)
    }

    async fn ensure_wallet_directory(&self) -> Result<(), StoreError> {
        let namespace = self
            .directory
            .parent()
            .ok_or_else(|| StoreError::UnexpectedEntry(self.directory.clone()))?;
        ensure_private_directory(namespace).await?;
        ensure_private_directory(&self.directory).await
    }

    fn observe_snapshot(
        observed: &mut BTreeMap<WalletId, WalletSnapshotMetadata>,
        found: WalletSnapshotMetadata,
    ) -> Result<(), StoreError> {
        let Some(highest) = observed.get(&found.wallet_id).copied() else {
            observed.insert(found.wallet_id, found);
            return Ok(());
        };
        if found.revision < highest.revision {
            return Err(StoreError::WalletRollbackDetected {
                wallet_id: found.wallet_id,
                highest_seen: highest.revision,
                found: found.revision,
            });
        }
        if found.revision == highest.revision {
            if found != highest {
                return Err(StoreError::WalletForkDetected {
                    wallet_id: found.wallet_id,
                    revision: found.revision,
                });
            }
            return Ok(());
        }
        let expected = highest
            .revision
            .checked_add(1)
            .ok_or(StoreError::WalletRevisionExhausted { wallet_id: found.wallet_id })?;
        if found.revision != expected {
            return Err(StoreError::WalletRevisionNotNext {
                wallet_id: found.wallet_id,
                expected,
                actual: found.revision,
            });
        }
        if found.previous_snapshot_hash != highest.snapshot_hash {
            return Err(StoreError::WalletHashChainMismatch {
                wallet_id: found.wallet_id,
                revision: found.revision,
            });
        }
        observed.insert(found.wallet_id, found);
        Ok(())
    }
}

impl WalletArtifactStore {
    /// Construct an immutable artifact store with a key and namespace independent from mutable
    /// wallet snapshots and protocol-session records.
    pub fn new(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
    ) -> Result<Self, StoreError> {
        let hk = Hkdf::<Sha256>::new(
            Some(b"threshold-monero/wallet-artifact-store/root/v2"),
            identity_seed,
        );
        let mut key = [0_u8; 32];
        let mut info = b"xchacha20poly1305/party/".to_vec();
        info.extend_from_slice(&party.0.to_le_bytes());
        hk.expand(&info, &mut key).map_err(|_| StoreError::KeyDerivation)?;
        Ok(Self {
            directory: directory
                .into()
                .join(WALLET_ARTIFACT_DIRECTORY)
                .join(format!("party-{}", party.0)),
            party,
            key,
            mutation: Mutex::new(()),
        })
    }

    /// Derive a secret subkey for authenticated metadata colocated with wallet artifacts.
    ///
    /// The artifact-store root key is never exposed. Callers must use a permanent,
    /// protocol-specific domain label; the local party is already bound into the root key.
    pub(crate) fn derive_subkey(
        &self,
        domain: &'static [u8],
    ) -> Result<Zeroizing<[u8; 32]>, StoreError> {
        if domain.is_empty() {
            return Err(StoreError::KeyDerivation);
        }
        let hk = Hkdf::<Sha256>::new(
            Some(b"threshold-monero/wallet-artifact-store/subkey/v1"),
            &self.key,
        );
        let mut key = Zeroizing::new([0_u8; 32]);
        hk.expand(domain, key.as_mut()).map_err(|_| StoreError::KeyDerivation)?;
        if key.as_ref() == &[0_u8; 32] {
            return Err(StoreError::KeyDerivation);
        }
        Ok(key)
    }

    #[must_use]
    pub fn artifact_root(&self) -> &Path {
        &self.directory
    }

    /// Resolve the deterministic local path for a content address.
    #[must_use]
    pub fn artifact_path(&self, reference: WalletArtifactRef) -> PathBuf {
        self.directory
            .join(hex::encode(reference.wallet_id.0))
            .join(format!("kind-{:04x}", reference.kind.0))
            .join(format!("{}.artifact", hex::encode(reference.digest)))
    }

    fn artifact_reservation_path(&self, reference: WalletArtifactRef) -> PathBuf {
        self.directory
            .join(hex::encode(reference.wallet_id.0))
            .join(format!("kind-{:04x}", reference.kind.0))
            .join(format!("{}.reservation", hex::encode(reference.digest)))
    }

    /// Install one immutable object and authenticate an exact readback before returning its
    /// portable content address.
    ///
    /// A retry derives the same destination and succeeds only when the existing record decrypts
    /// under the expected wallet/kind/length/digest context and contains the exact same bytes.
    pub async fn create_artifact<R: RngCore + CryptoRng>(
        &self,
        wallet_id: WalletId,
        kind: WalletArtifactKind,
        contents: &[u8],
        rng: &mut R,
    ) -> Result<WalletArtifactRef, StoreError> {
        Ok(self.create_artifact_tracked(wallet_id, kind, contents, rng).await?.0)
    }

    /// Install one unowned immutable object and report whether this call created its durable
    /// inode. General imports and transfers use this API; journaled batches use
    /// [`Self::create_artifact_owned`] instead.
    pub async fn create_artifact_tracked<R: RngCore + CryptoRng>(
        &self,
        wallet_id: WalletId,
        kind: WalletArtifactKind,
        contents: &[u8],
        rng: &mut R,
    ) -> Result<(WalletArtifactRef, bool), StoreError> {
        if kind.0 == 0 || contents.is_empty() {
            return Err(StoreError::InvalidWalletArtifactReference);
        }
        if contents.len() > MAX_WALLET_ARTIFACT_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "wallet artifact",
                actual: contents.len(),
                maximum: MAX_WALLET_ARTIFACT_BYTES,
            });
        }
        let reference = WalletArtifactRef::for_contents(wallet_id, kind, contents)?;
        reference.validate()?;

        let _mutation = self.mutation.lock().await;
        let _namespace = self.lock_artifact_namespace(wallet_id).await?;
        self.ensure_artifact_directory(wallet_id, kind).await?;
        let destination = self.artifact_path(reference);
        if self.load_artifact_reservation(reference).await?.is_some() {
            return Err(artifact_reservation_conflict(reference));
        }
        if entry_exists_regular(&destination).await? {
            let reference = self.require_exact_artifact(&destination, reference, contents).await?;
            return Ok((reference, false));
        }

        let mut nonce = [0_u8; 24];
        rng.fill_bytes(&mut nonce);
        let sealed = self.seal_wallet_artifact(reference, None, contents, nonce)?;
        let encoded = postcard::to_allocvec(&sealed).map_err(|_| StoreError::Serialization)?;
        let maximum_encoded = wallet_artifact_maximum_encoded_bytes(contents.len())?;
        if encoded.len() > maximum_encoded {
            return Err(StoreError::BlobTooLarge {
                kind: "sealed wallet artifact",
                actual: encoded.len(),
                maximum: maximum_encoded,
            });
        }
        let installed = atomic_create_new(&destination, &encoded, nonce).await?;
        // A journal owner which won the reservation race must be allowed to finish or abort
        // before an unowned writer treats its object as stable. If this call won the artifact
        // create race, the owner will observe pre-existing exact content and relinquish its
        // reservation instead of claiming cleanup authority.
        if !installed && self.load_artifact_reservation(reference).await?.is_some() {
            return Err(artifact_reservation_conflict(reference));
        }
        let reference = self.require_exact_artifact(&destination, reference, contents).await?;
        Ok((reference, installed))
    }

    /// Install or resume one artifact owned by an already durable batch journal.
    ///
    /// The permanent namespace lock plus the authenticated reservation file are the
    /// cross-instance/process ownership proof. The reservation is installed with create-new
    /// semantics before checking or creating the artifact and remains until the caller commits or
    /// aborts the journal. Exact content which predated a newly installed reservation is returned
    /// as [`WalletArtifactOwnership::PreExisting`] after relinquishing the reservation and must
    /// never be deleted by this batch.
    pub async fn create_artifact_owned<R: RngCore + CryptoRng>(
        &self,
        owner: WalletArtifactOwner,
        wallet_id: WalletId,
        kind: WalletArtifactKind,
        contents: &[u8],
        rng: &mut R,
    ) -> Result<(WalletArtifactRef, WalletArtifactOwnership), StoreError> {
        owner.validate()?;
        if kind.0 == 0 || contents.is_empty() {
            return Err(StoreError::InvalidWalletArtifactReference);
        }
        if contents.len() > MAX_WALLET_ARTIFACT_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "wallet artifact",
                actual: contents.len(),
                maximum: MAX_WALLET_ARTIFACT_BYTES,
            });
        }
        let reference = WalletArtifactRef::for_contents(wallet_id, kind, contents)?;
        reference.validate()?;

        let _mutation = self.mutation.lock().await;
        let _namespace = self.lock_artifact_namespace(wallet_id).await?;
        self.ensure_artifact_directory(wallet_id, kind).await?;
        let destination = self.artifact_path(reference);
        self.destroy_artifact_temporaries(reference).await?;
        let reservation_path = self.artifact_reservation_path(reference);
        let (reservation, planned) = match self.load_artifact_reservation(reference).await? {
            Some(found) if found.owner == owner => {
                let planned =
                    self.encode_owned_artifact(reference, owner, contents, found.artifact_nonce)?;
                validate_artifact_reservation_plan(&found, &planned)?;
                (found, planned)
            }
            Some(_) => return Err(artifact_reservation_conflict(reference)),
            None => {
                let mut artifact_nonce = [0_u8; 24];
                rng.fill_bytes(&mut artifact_nonce);
                let planned =
                    self.encode_owned_artifact(reference, owner, contents, artifact_nonce)?;
                let header = WalletArtifactReservationHeader {
                    version: WALLET_ARTIFACT_RESERVATION_VERSION,
                    party: self.party,
                    reference,
                    owner,
                    artifact_nonce,
                    sealed_len: u64::try_from(planned.len())
                        .map_err(|_| StoreError::Serialization)?,
                    sealed_digest: wallet_artifact_sealed_bytes_hash(reference, owner, &planned),
                };
                let mut reservation_nonce = [0_u8; 24];
                rng.fill_bytes(&mut reservation_nonce);
                let sealed = self.seal_artifact_reservation(header.clone(), reservation_nonce)?;
                let encoded =
                    postcard::to_allocvec(&sealed).map_err(|_| StoreError::Serialization)?;
                if encoded.len() > MAX_WALLET_ARTIFACT_RESERVATION_BYTES {
                    return Err(StoreError::BlobTooLarge {
                        kind: "wallet artifact reservation",
                        actual: encoded.len(),
                        maximum: MAX_WALLET_ARTIFACT_RESERVATION_BYTES,
                    });
                }
                if atomic_create_new(&reservation_path, &encoded, reservation_nonce).await? {
                    (header, planned)
                } else {
                    let found = self
                        .load_artifact_reservation(reference)
                        .await?
                        .ok_or(StoreError::Authentication)?;
                    if found.owner != owner {
                        return Err(artifact_reservation_conflict(reference));
                    }
                    let planned = self.encode_owned_artifact(
                        reference,
                        owner,
                        contents,
                        found.artifact_nonce,
                    )?;
                    validate_artifact_reservation_plan(&found, &planned)?;
                    (found, planned)
                }
            }
        };
        validate_artifact_reservation_plan(&reservation, &planned)?;

        if !entry_exists_regular(&destination).await? {
            let mut create_token = [0_u8; 24];
            rng.fill_bytes(&mut create_token);
            let _installed = atomic_create_new(&destination, &planned, create_token).await?;
        }
        let durable = self.read_wallet_artifact_bytes(&destination, reference).await?;
        if durable != planned {
            let existing = self.open_wallet_artifact_bytes(&durable, reference)?;
            if existing.contents.as_bytes() != contents {
                return Err(StoreError::WalletArtifactConflict {
                    wallet_id: reference.wallet_id,
                    kind: reference.kind,
                    digest: reference.digest,
                });
            }
            self.release_artifact_reservation(reference, owner).await?;
            return Ok((reference, WalletArtifactOwnership::PreExisting));
        }
        let installed = self.open_wallet_artifact_bytes(&durable, reference)?;
        if installed.contents.as_bytes() != contents || installed.storage_owner() != Some(owner) {
            return Err(StoreError::Authentication);
        }
        Ok((reference, WalletArtifactOwnership::Owned))
    }

    /// Load and authenticate one stable content address.
    ///
    /// An active batch reservation makes ordinary reads fail closed: otherwise another reducer
    /// could publish a head referencing an object which the reserving batch is still entitled to
    /// delete on abort.
    pub async fn load_artifact(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<WalletArtifact, StoreError> {
        reference.validate()?;
        let plaintext_len =
            usize::try_from(reference.plaintext_len).map_err(|_| StoreError::Serialization)?;
        if plaintext_len > MAX_WALLET_ARTIFACT_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "wallet artifact",
                actual: plaintext_len,
                maximum: MAX_WALLET_ARTIFACT_BYTES,
            });
        }
        let _mutation = self.mutation.lock().await;
        let _namespace = self.lock_artifact_namespace(reference.wallet_id).await?;
        if self.load_artifact_reservation(reference).await?.is_some() {
            return Err(artifact_reservation_conflict(reference));
        }
        self.open_wallet_artifact(&self.artifact_path(reference), reference).await
    }

    /// Load an artifact while recovering or verifying the exact journal which owns its
    /// reservation. A missing reservation is accepted as an idempotent committed/pre-existing
    /// state; a reservation for another owner always fails closed.
    pub async fn load_artifact_owned(
        &self,
        reference: WalletArtifactRef,
        owner: WalletArtifactOwner,
    ) -> Result<WalletArtifact, StoreError> {
        reference.validate()?;
        owner.validate()?;
        let plaintext_len =
            usize::try_from(reference.plaintext_len).map_err(|_| StoreError::Serialization)?;
        if plaintext_len > MAX_WALLET_ARTIFACT_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "wallet artifact",
                actual: plaintext_len,
                maximum: MAX_WALLET_ARTIFACT_BYTES,
            });
        }
        let _mutation = self.mutation.lock().await;
        let _namespace = self.lock_artifact_namespace(reference.wallet_id).await?;
        match self.load_artifact_reservation(reference).await? {
            Some(found) if found.owner != owner => Err(artifact_reservation_conflict(reference)),
            Some(found) => {
                let path = self.artifact_path(reference);
                let durable = self.read_wallet_artifact_bytes(&path, reference).await?;
                let length = u64::try_from(durable.len()).map_err(|_| StoreError::Serialization)?;
                if found.sealed_len != length
                    || found.sealed_digest
                        != wallet_artifact_sealed_bytes_hash(reference, owner, &durable)
                {
                    return Err(StoreError::Authentication);
                }
                let artifact = self.open_wallet_artifact_bytes(&durable, reference)?;
                if artifact.storage_owner() != Some(owner) {
                    return Err(StoreError::Authentication);
                }
                Ok(artifact)
            }
            None => self.open_wallet_artifact(&self.artifact_path(reference), reference).await,
        }
    }

    /// Remove one exact immutable artifact after authenticating its complete storage context.
    ///
    /// Cleanup callers must already have proved that no installed head or active journal can
    /// reference `reference`. A missing artifact is an idempotent success so crash recovery may
    /// replay an exact cleanup list without enumerating the artifact directory. Existing bytes are
    /// decrypted and authenticated before unlinking; a symlink, wrong-context record, or corrupt
    /// artifact therefore fails closed instead of deleting an unexpected path.
    pub async fn remove_artifact(&self, reference: WalletArtifactRef) -> Result<bool, StoreError> {
        reference.validate()?;
        let _mutation = self.mutation.lock().await;
        let _namespace = self.lock_artifact_namespace(reference.wallet_id).await?;
        if self.load_artifact_reservation(reference).await?.is_some() {
            return Err(artifact_reservation_conflict(reference));
        }
        self.remove_artifact_unreserved(reference).await
    }

    /// Delete an artifact only when the exact durable batch still owns its reservation.
    ///
    /// A missing reservation is an idempotent, preserve-content result. This is the only deletion
    /// primitive an old-head journal abort may use.
    pub async fn remove_artifact_if_owned(
        &self,
        reference: WalletArtifactRef,
        owner: WalletArtifactOwner,
    ) -> Result<bool, StoreError> {
        reference.validate()?;
        owner.validate()?;
        let _mutation = self.mutation.lock().await;
        let _namespace = self.lock_artifact_namespace(reference.wallet_id).await?;
        self.destroy_artifact_temporaries(reference).await?;
        match self.load_artifact_reservation(reference).await? {
            None => Ok(false),
            Some(found) if found.owner != owner => Err(artifact_reservation_conflict(reference)),
            Some(found) => {
                validate_artifact_reservation_header(&found)?;
                let path = self.artifact_path(reference);
                let removed = match tokio::fs::symlink_metadata(&path).await {
                    Ok(metadata) if metadata.is_file() => {
                        let durable = self.read_wallet_artifact_bytes(&path, reference).await?;
                        let length =
                            u64::try_from(durable.len()).map_err(|_| StoreError::Serialization)?;
                        if found.sealed_len == length
                            && found.sealed_digest
                                == wallet_artifact_sealed_bytes_hash(reference, owner, &durable)
                        {
                            let artifact = self.open_wallet_artifact_bytes(&durable, reference)?;
                            if artifact.storage_owner() != Some(owner) {
                                return Err(StoreError::Authentication);
                            }
                            destroy_file_and_sync_parent(&path).await?;
                            true
                        } else {
                            false
                        }
                    }
                    Ok(_) => return Err(StoreError::NotRegularFile(path)),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                    Err(error) => return Err(error.into()),
                };
                self.release_artifact_reservation(reference, owner).await?;
                Ok(removed)
            }
        }
    }

    /// Relinquish exact cleanup ownership after the target snapshot became authoritative.
    ///
    /// Missing is an idempotent success for a crash after marker removal but before journal
    /// deletion. This never removes the artifact itself.
    pub async fn release_artifact_ownership(
        &self,
        reference: WalletArtifactRef,
        owner: WalletArtifactOwner,
    ) -> Result<bool, StoreError> {
        reference.validate()?;
        owner.validate()?;
        let _mutation = self.mutation.lock().await;
        let _namespace = self.lock_artifact_namespace(reference.wallet_id).await?;
        self.destroy_artifact_temporaries(reference).await?;
        match self.load_artifact_reservation(reference).await? {
            None => Ok(false),
            Some(found) if found.owner != owner => Err(artifact_reservation_conflict(reference)),
            Some(_) => {
                self.release_artifact_reservation(reference, owner).await?;
                Ok(true)
            }
        }
    }

    async fn require_exact_artifact(
        &self,
        path: &Path,
        reference: WalletArtifactRef,
        expected: &[u8],
    ) -> Result<WalletArtifactRef, StoreError> {
        let existing = self.open_wallet_artifact(path, reference).await?;
        if existing.contents.as_bytes() != expected {
            return Err(StoreError::WalletArtifactConflict {
                wallet_id: reference.wallet_id,
                kind: reference.kind,
                digest: reference.digest,
            });
        }
        Ok(reference)
    }

    async fn load_artifact_reservation(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<Option<WalletArtifactReservationHeader>, StoreError> {
        let path = self.artifact_reservation_path(reference);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Err(StoreError::NotRegularFile(path)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        self.open_artifact_reservation(&path, reference).await.map(Some)
    }

    fn seal_artifact_reservation(
        &self,
        header: WalletArtifactReservationHeader,
        nonce: [u8; 24],
    ) -> Result<SealedWalletArtifactReservation, StoreError> {
        header.reference.validate()?;
        header.owner.validate()?;
        validate_artifact_reservation_header(&header)?;
        let aad = wallet_artifact_reservation_associated_data(&header)?;
        let key = self.wallet_key(header.reference.wallet_id)?;
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &[], aad: &aad })
            .map_err(|_| StoreError::Authentication)?;
        Ok(SealedWalletArtifactReservation { header, nonce, ciphertext })
    }

    async fn open_artifact_reservation(
        &self,
        path: &Path,
        expected: WalletArtifactRef,
    ) -> Result<WalletArtifactReservationHeader, StoreError> {
        expected.validate()?;
        let bytes = read_capped_regular_file(
            path,
            MAX_WALLET_ARTIFACT_RESERVATION_BYTES,
            "wallet artifact reservation",
        )
        .await?;
        let sealed: SealedWalletArtifactReservation =
            decode_canonical_exact(&bytes, "wallet artifact reservation")?;
        if sealed.header.version != WALLET_ARTIFACT_RESERVATION_VERSION
            || sealed.header.party != self.party
            || sealed.header.reference != expected
        {
            return Err(StoreError::WrongContext);
        }
        sealed.header.owner.validate()?;
        validate_artifact_reservation_header(&sealed.header)?;
        if sealed.ciphertext.len() != AEAD_TAG_BYTES {
            return Err(StoreError::Authentication);
        }
        let aad = wallet_artifact_reservation_associated_data(&sealed.header)?;
        let key = self.wallet_key(expected.wallet_id)?;
        let plaintext = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
            .decrypt(
                XNonce::from_slice(&sealed.nonce),
                Payload { msg: &sealed.ciphertext, aad: &aad },
            )
            .map_err(|_| StoreError::Authentication)?;
        if !plaintext.is_empty() {
            return Err(StoreError::Authentication);
        }
        Ok(sealed.header)
    }

    async fn release_artifact_reservation(
        &self,
        reference: WalletArtifactRef,
        owner: WalletArtifactOwner,
    ) -> Result<(), StoreError> {
        let path = self.artifact_reservation_path(reference);
        let found = self.open_artifact_reservation(&path, reference).await?;
        if found.owner != owner {
            return Err(artifact_reservation_conflict(reference));
        }
        destroy_file_and_sync_parent(&path).await
    }

    async fn remove_artifact_unreserved(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<bool, StoreError> {
        let path = self.artifact_path(reference);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Err(StoreError::NotRegularFile(path)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        let _authenticated = self.open_wallet_artifact(&path, reference).await?;
        destroy_file_and_sync_parent(&path).await?;
        Ok(true)
    }

    fn seal_wallet_artifact(
        &self,
        reference: WalletArtifactRef,
        owner: Option<WalletArtifactOwner>,
        contents: &[u8],
        nonce: [u8; 24],
    ) -> Result<SealedWalletArtifact, StoreError> {
        if let Some(owner) = owner {
            owner.validate()?;
        }
        let header = WalletArtifactHeader {
            version: WALLET_ARTIFACT_STORE_VERSION,
            party: self.party,
            reference,
            owner,
        };
        let aad = wallet_artifact_associated_data(&header)?;
        let key = self.wallet_key(reference.wallet_id)?;
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: contents, aad: &aad })
            .map_err(|_| StoreError::Authentication)?;
        Ok(SealedWalletArtifact { header, nonce, ciphertext })
    }

    fn encode_owned_artifact(
        &self,
        reference: WalletArtifactRef,
        owner: WalletArtifactOwner,
        contents: &[u8],
        nonce: [u8; 24],
    ) -> Result<Vec<u8>, StoreError> {
        reference.verify_contents(contents)?;
        owner.validate()?;
        let sealed = self.seal_wallet_artifact(reference, Some(owner), contents, nonce)?;
        let encoded = postcard::to_allocvec(&sealed).map_err(|_| StoreError::Serialization)?;
        let maximum_encoded = wallet_artifact_maximum_encoded_bytes(contents.len())?;
        if encoded.len() > maximum_encoded {
            return Err(StoreError::BlobTooLarge {
                kind: "sealed wallet artifact",
                actual: encoded.len(),
                maximum: maximum_encoded,
            });
        }
        Ok(encoded)
    }

    async fn read_wallet_artifact_bytes(
        &self,
        path: &Path,
        expected: WalletArtifactRef,
    ) -> Result<Vec<u8>, StoreError> {
        expected.validate()?;
        let plaintext_len =
            usize::try_from(expected.plaintext_len).map_err(|_| StoreError::Serialization)?;
        if plaintext_len > MAX_WALLET_ARTIFACT_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "wallet artifact",
                actual: plaintext_len,
                maximum: MAX_WALLET_ARTIFACT_BYTES,
            });
        }
        let maximum_encoded = wallet_artifact_maximum_encoded_bytes(plaintext_len)?;
        read_capped_regular_file(path, maximum_encoded, "sealed wallet artifact").await
    }

    fn open_wallet_artifact_bytes(
        &self,
        bytes: &[u8],
        expected: WalletArtifactRef,
    ) -> Result<WalletArtifact, StoreError> {
        expected.validate()?;
        let plaintext_len =
            usize::try_from(expected.plaintext_len).map_err(|_| StoreError::Serialization)?;
        if plaintext_len > MAX_WALLET_ARTIFACT_BYTES {
            return Err(StoreError::BlobTooLarge {
                kind: "wallet artifact",
                actual: plaintext_len,
                maximum: MAX_WALLET_ARTIFACT_BYTES,
            });
        }
        let maximum_encoded = wallet_artifact_maximum_encoded_bytes(plaintext_len)?;
        if bytes.len() > maximum_encoded {
            return Err(StoreError::BlobTooLarge {
                kind: "sealed wallet artifact",
                actual: bytes.len(),
                maximum: maximum_encoded,
            });
        }
        let sealed: SealedWalletArtifact = decode_canonical_exact(bytes, "sealed wallet artifact")?;
        if sealed.header.version != WALLET_ARTIFACT_STORE_VERSION
            || sealed.header.party != self.party
            || sealed.header.reference != expected
        {
            return Err(StoreError::WrongContext);
        }
        if let Some(owner) = sealed.header.owner {
            owner.validate()?;
        }
        let expected_ciphertext_len =
            plaintext_len.checked_add(AEAD_TAG_BYTES).ok_or(StoreError::Serialization)?;
        if sealed.ciphertext.len() != expected_ciphertext_len {
            return Err(StoreError::Authentication);
        }
        let aad = wallet_artifact_associated_data(&sealed.header)?;
        let key = self.wallet_key(expected.wallet_id)?;
        let mut plaintext = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
            .decrypt(
                XNonce::from_slice(&sealed.nonce),
                Payload { msg: &sealed.ciphertext, aad: &aad },
            )
            .map_err(|_| StoreError::Authentication)?;
        if plaintext.len() != plaintext_len
            || wallet_artifact_hash(
                expected.wallet_id,
                expected.kind,
                expected.plaintext_len,
                &plaintext,
            ) != expected.digest
        {
            plaintext.zeroize();
            return Err(StoreError::Authentication);
        }
        Ok(WalletArtifact {
            reference: expected,
            contents: WalletArtifactBlob(plaintext),
            storage_owner: sealed.header.owner,
        })
    }

    async fn open_wallet_artifact(
        &self,
        path: &Path,
        expected: WalletArtifactRef,
    ) -> Result<WalletArtifact, StoreError> {
        let bytes = self.read_wallet_artifact_bytes(path, expected).await?;
        self.open_wallet_artifact_bytes(&bytes, expected)
    }

    fn wallet_key(&self, wallet_id: WalletId) -> Result<Zeroizing<[u8; 32]>, StoreError> {
        let hk = Hkdf::<Sha256>::new(
            Some(b"threshold-monero/wallet-artifact-store/per-wallet-key/v2"),
            &self.key,
        );
        let mut key = Zeroizing::new([0_u8; 32]);
        let mut info = b"xchacha20poly1305/wallet/".to_vec();
        info.extend_from_slice(&wallet_id.0);
        hk.expand(&info, key.as_mut()).map_err(|_| StoreError::KeyDerivation)?;
        Ok(key)
    }

    async fn ensure_artifact_directory(
        &self,
        wallet_id: WalletId,
        kind: WalletArtifactKind,
    ) -> Result<(), StoreError> {
        let namespace = self
            .directory
            .parent()
            .ok_or_else(|| StoreError::UnexpectedEntry(self.directory.clone()))?;
        ensure_private_directory(namespace).await?;
        ensure_private_directory(&self.directory).await?;
        let wallet_directory = self.directory.join(hex::encode(wallet_id.0));
        ensure_private_directory(&wallet_directory).await?;
        ensure_private_directory(&wallet_directory.join(format!("kind-{:04x}", kind.0))).await
    }

    async fn destroy_artifact_temporaries(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<(), StoreError> {
        for destination in
            [self.artifact_path(reference), self.artifact_reservation_path(reference)]
        {
            let parent = destination
                .parent()
                .ok_or_else(|| StoreError::UnexpectedEntry(destination.clone()))?;
            if directory_exists(parent).await? {
                destroy_temporary_replacements(&destination).await?;
            }
        }
        Ok(())
    }

    async fn lock_artifact_namespace(
        &self,
        wallet_id: WalletId,
    ) -> Result<WalletArtifactNamespaceLock, StoreError> {
        let namespace = self
            .directory
            .parent()
            .ok_or_else(|| StoreError::UnexpectedEntry(self.directory.clone()))?;
        ensure_private_directory(namespace).await?;
        ensure_private_directory(&self.directory).await?;
        let wallet_directory = self.directory.join(hex::encode(wallet_id.0));
        ensure_private_directory(&wallet_directory).await?;
        let path = wallet_directory.join(".namespace.lock");
        let file = tokio::task::spawn_blocking(move || -> io::Result<std::fs::File> {
            let file = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let metadata = std::fs::symlink_metadata(&path)?;
                    if !metadata.is_file() {
                        return Err(io::Error::other(format!(
                            "artifact namespace lock is not a regular file: {}",
                            path.display()
                        )));
                    }
                    std::fs::OpenOptions::new().read(true).write(true).open(&path)?
                }
                Err(error) => return Err(error),
            };
            file.lock()?;
            Ok(file)
        })
        .await
        .map_err(io::Error::other)??;
        Ok(WalletArtifactNamespaceLock(file))
    }
}

struct SealedRecordBytes {
    encoded: Vec<u8>,
    nonce: [u8; 24],
}

fn wallet_maximum_encoded_bytes() -> Result<usize, StoreError> {
    MAX_WALLET_SNAPSHOT_BYTES
        .checked_add(AEAD_TAG_BYTES + MAX_RECORD_OVERHEAD_BYTES)
        .ok_or(StoreError::Serialization)
}

fn wallet_artifact_maximum_encoded_bytes(plaintext_len: usize) -> Result<usize, StoreError> {
    plaintext_len
        .checked_add(AEAD_TAG_BYTES + MAX_RECORD_OVERHEAD_BYTES)
        .ok_or(StoreError::Serialization)
}

fn wallet_artifact_hash(
    wallet_id: WalletId,
    kind: WalletArtifactKind,
    plaintext_len: u64,
    contents: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/wallet-artifact-content/v2");
    hasher.update(&WALLET_ARTIFACT_STORE_VERSION.to_le_bytes());
    hasher.update(&wallet_id.0);
    hasher.update(&kind.0.to_le_bytes());
    hasher.update(&plaintext_len.to_le_bytes());
    hasher.update(contents);
    *hasher.finalize().as_bytes()
}

fn wallet_artifact_sealed_bytes_hash(
    reference: WalletArtifactRef,
    owner: WalletArtifactOwner,
    encoded: &[u8],
) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/wallet-artifact-sealed-ownership/v1");
    hasher.update(&WALLET_ARTIFACT_RESERVATION_VERSION.to_le_bytes());
    hasher.update(&reference.version.to_le_bytes());
    hasher.update(&reference.wallet_id.0);
    hasher.update(&reference.kind.0.to_le_bytes());
    hasher.update(&reference.plaintext_len.to_le_bytes());
    hasher.update(&reference.digest);
    hasher.update(&owner.0);
    hasher.update(&(encoded.len() as u64).to_le_bytes());
    hasher.update(encoded);
    *hasher.finalize().as_bytes()
}

fn validate_artifact_reservation_header(
    header: &WalletArtifactReservationHeader,
) -> Result<(), StoreError> {
    header.reference.validate()?;
    header.owner.validate()?;
    let plaintext_len =
        usize::try_from(header.reference.plaintext_len).map_err(|_| StoreError::Serialization)?;
    let maximum = wallet_artifact_maximum_encoded_bytes(plaintext_len)?;
    let sealed_len = usize::try_from(header.sealed_len).map_err(|_| StoreError::Serialization)?;
    if header.version != WALLET_ARTIFACT_RESERVATION_VERSION
        || header.party == PartyId(0)
        || sealed_len == 0
        || sealed_len > maximum
        || header.sealed_digest == [0_u8; 32]
    {
        return Err(StoreError::Authentication);
    }
    Ok(())
}

fn validate_artifact_reservation_plan(
    header: &WalletArtifactReservationHeader,
    encoded: &[u8],
) -> Result<(), StoreError> {
    validate_artifact_reservation_header(header)?;
    let length = u64::try_from(encoded.len()).map_err(|_| StoreError::Serialization)?;
    if header.sealed_len != length
        || header.sealed_digest
            != wallet_artifact_sealed_bytes_hash(header.reference, header.owner, encoded)
    {
        return Err(StoreError::Authentication);
    }
    Ok(())
}

fn wallet_artifact_associated_data(header: &WalletArtifactHeader) -> Result<Vec<u8>, StoreError> {
    let encoded = postcard::to_allocvec(header).map_err(|_| StoreError::Serialization)?;
    let mut aad = b"threshold-monero/sealed-wallet-artifact/v2".to_vec();
    aad.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
    aad.extend_from_slice(&encoded);
    Ok(aad)
}

fn wallet_artifact_reservation_associated_data(
    header: &WalletArtifactReservationHeader,
) -> Result<Vec<u8>, StoreError> {
    let encoded = postcard::to_allocvec(header).map_err(|_| StoreError::Serialization)?;
    let mut aad = b"threshold-monero/wallet-artifact-reservation/v1".to_vec();
    aad.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
    aad.extend_from_slice(&encoded);
    Ok(aad)
}

fn artifact_reservation_conflict(reference: WalletArtifactRef) -> StoreError {
    StoreError::WalletArtifactReservationConflict {
        wallet_id: reference.wallet_id,
        kind: reference.kind,
        digest: reference.digest,
    }
}

fn wallet_snapshot_hash(
    party: PartyId,
    wallet_id: WalletId,
    revision: u64,
    previous_snapshot_hash: [u8; 32],
    plaintext_len: u64,
    state: &[u8],
) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/wallet-snapshot-hash-chain/v1");
    hasher.update(&WALLET_SNAPSHOT_STORE_VERSION.to_le_bytes());
    hasher.update(&party.0.to_le_bytes());
    hasher.update(&wallet_id.0);
    hasher.update(&revision.to_le_bytes());
    hasher.update(&previous_snapshot_hash);
    hasher.update(&plaintext_len.to_le_bytes());
    hasher.update(state);
    *hasher.finalize().as_bytes()
}

fn wallet_associated_data(header: &WalletSnapshotHeader) -> Result<Vec<u8>, StoreError> {
    let encoded = postcard::to_allocvec(header).map_err(|_| StoreError::Serialization)?;
    let mut aad = b"threshold-monero/sealed-wallet-snapshot/v1".to_vec();
    aad.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
    aad.extend_from_slice(&encoded);
    Ok(aad)
}

fn protocol_associated_data(header: &ProtocolRecordHeader) -> Result<Vec<u8>, StoreError> {
    let encoded = postcard::to_allocvec(header).map_err(|_| StoreError::Serialization)?;
    let mut aad = b"threshold-monero/sealed-protocol-record/v1".to_vec();
    aad.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
    aad.extend_from_slice(&encoded);
    Ok(aad)
}

fn deposit_sync_spool_head_snapshot_hash(
    party: PartyId,
    key: DepositSyncSpoolHeadKey,
    revision: u64,
    previous_snapshot_hash: [u8; 32],
    state: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/deposit-sync-spool-head/v1");
    hasher.update(&DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_VERSION.to_le_bytes());
    hasher.update(&party.0.to_le_bytes());
    hasher.update(&key.network_id);
    hasher.update(&key.wallet_id.0);
    hasher.update(&revision.to_le_bytes());
    hasher.update(&previous_snapshot_hash);
    hasher.update(&(state.len() as u64).to_le_bytes());
    hasher.update(state);
    *hasher.finalize().as_bytes()
}

fn encode_deposit_sync_spool_head_snapshot(
    party: PartyId,
    key: DepositSyncSpoolHeadKey,
    revision: u64,
    previous_snapshot_hash: [u8; 32],
    state: &[u8],
) -> Result<Vec<u8>, StoreError> {
    key.validate()?;
    if state.len() > MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES {
        return Err(StoreError::BlobTooLarge {
            kind: "deposit sync spool head state",
            actual: state.len(),
            maximum: MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES,
        });
    }
    if (revision == 0) != (previous_snapshot_hash == [0_u8; 32]) {
        return Err(StoreError::DepositSyncSpoolHeadHashChainMismatch { key, revision });
    }
    let state_len = u64::try_from(state.len()).map_err(|_| StoreError::Serialization)?;
    let snapshot_hash =
        deposit_sync_spool_head_snapshot_hash(party, key, revision, previous_snapshot_hash, state);
    let mut encoded =
        Vec::with_capacity(DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_HEADER_BYTES + state.len());
    encoded.extend_from_slice(&DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_VERSION.to_le_bytes());
    encoded.extend_from_slice(&revision.to_le_bytes());
    encoded.extend_from_slice(&previous_snapshot_hash);
    encoded.extend_from_slice(&snapshot_hash);
    encoded.extend_from_slice(&state_len.to_le_bytes());
    encoded.extend_from_slice(state);
    Ok(encoded)
}

fn decode_deposit_sync_spool_head_snapshot<'a>(
    party: PartyId,
    key: DepositSyncSpoolHeadKey,
    encoded: &'a [u8],
) -> Result<(DepositSyncSpoolHeadMetadata, &'a [u8]), StoreError> {
    key.validate()?;
    if encoded.len() < DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_HEADER_BYTES {
        return Err(StoreError::NonCanonicalEncoding { kind: "deposit sync spool head snapshot" });
    }
    let version =
        u16::from_le_bytes(encoded[..2].try_into().map_err(|_| StoreError::Serialization)?);
    if version != DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_VERSION {
        return Err(StoreError::WrongContext);
    }
    let revision =
        u64::from_le_bytes(encoded[2..10].try_into().map_err(|_| StoreError::Serialization)?);
    let mut previous_snapshot_hash = [0_u8; 32];
    previous_snapshot_hash.copy_from_slice(&encoded[10..42]);
    let mut snapshot_hash = [0_u8; 32];
    snapshot_hash.copy_from_slice(&encoded[42..74]);
    let state_len =
        u64::from_le_bytes(encoded[74..82].try_into().map_err(|_| StoreError::Serialization)?);
    let state_len = usize::try_from(state_len).map_err(|_| StoreError::Serialization)?;
    if state_len > MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES {
        return Err(StoreError::BlobTooLarge {
            kind: "deposit sync spool head state",
            actual: state_len,
            maximum: MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES,
        });
    }
    if encoded.len() != DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_HEADER_BYTES + state_len {
        return Err(StoreError::NonCanonicalEncoding { kind: "deposit sync spool head snapshot" });
    }
    let state = &encoded[DEPOSIT_SYNC_SPOOL_HEAD_SNAPSHOT_HEADER_BYTES..];
    if snapshot_hash
        != deposit_sync_spool_head_snapshot_hash(
            party,
            key,
            revision,
            previous_snapshot_hash,
            state,
        )
    {
        return Err(StoreError::Authentication);
    }
    if snapshot_hash == [0_u8; 32] || (revision == 0) != (previous_snapshot_hash == [0_u8; 32]) {
        return Err(StoreError::DepositSyncSpoolHeadHashChainMismatch { key, revision });
    }
    Ok((
        DepositSyncSpoolHeadMetadata { key, revision, previous_snapshot_hash, snapshot_hash },
        state,
    ))
}

fn validate_deposit_state_transfer_intents_network(network_id: [u8; 32]) -> Result<(), StoreError> {
    if network_id == [0_u8; 32] {
        return Err(StoreError::InvalidDepositStateTransferIntentsNetwork);
    }
    Ok(())
}

fn deposit_state_transfer_intents_snapshot_hash(
    party: PartyId,
    network_id: [u8; 32],
    revision: u64,
    previous_snapshot_hash: [u8; 32],
    state: &[u8],
) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/deposit-state-transfer-intents/v1");
    hasher.update(&DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_VERSION.to_le_bytes());
    hasher.update(&party.0.to_le_bytes());
    hasher.update(&network_id);
    hasher.update(&revision.to_le_bytes());
    hasher.update(&previous_snapshot_hash);
    hasher.update(&(state.len() as u64).to_le_bytes());
    hasher.update(state);
    *hasher.finalize().as_bytes()
}

fn encode_deposit_state_transfer_intents_snapshot(
    party: PartyId,
    network_id: [u8; 32],
    revision: u64,
    previous_snapshot_hash: [u8; 32],
    state: &[u8],
) -> Result<Vec<u8>, StoreError> {
    validate_deposit_state_transfer_intents_network(network_id)?;
    if state.len() > MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES {
        return Err(StoreError::BlobTooLarge {
            kind: "deposit state-transfer intent state",
            actual: state.len(),
            maximum: MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES,
        });
    }
    if (revision == 0) != (previous_snapshot_hash == [0_u8; 32]) {
        return Err(StoreError::DepositStateTransferIntentsHashChainMismatch {
            network_id,
            revision,
        });
    }
    let state_len = u64::try_from(state.len()).map_err(|_| StoreError::Serialization)?;
    let snapshot_hash = deposit_state_transfer_intents_snapshot_hash(
        party,
        network_id,
        revision,
        previous_snapshot_hash,
        state,
    );
    let mut encoded =
        Vec::with_capacity(DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_HEADER_BYTES + state.len());
    encoded.extend_from_slice(&DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_VERSION.to_le_bytes());
    encoded.extend_from_slice(&revision.to_le_bytes());
    encoded.extend_from_slice(&previous_snapshot_hash);
    encoded.extend_from_slice(&snapshot_hash);
    encoded.extend_from_slice(&state_len.to_le_bytes());
    encoded.extend_from_slice(state);
    Ok(encoded)
}

fn decode_deposit_state_transfer_intents_snapshot<'a>(
    party: PartyId,
    network_id: [u8; 32],
    encoded: &'a [u8],
) -> Result<(DepositStateTransferIntentsMetadata, &'a [u8]), StoreError> {
    validate_deposit_state_transfer_intents_network(network_id)?;
    if encoded.len() < DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_HEADER_BYTES {
        return Err(StoreError::NonCanonicalEncoding {
            kind: "deposit state-transfer intent snapshot",
        });
    }
    let version =
        u16::from_le_bytes(encoded[..2].try_into().map_err(|_| StoreError::Serialization)?);
    if version != DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_VERSION {
        return Err(StoreError::WrongContext);
    }
    let revision =
        u64::from_le_bytes(encoded[2..10].try_into().map_err(|_| StoreError::Serialization)?);
    let mut previous_snapshot_hash = [0_u8; 32];
    previous_snapshot_hash.copy_from_slice(&encoded[10..42]);
    let mut snapshot_hash = [0_u8; 32];
    snapshot_hash.copy_from_slice(&encoded[42..74]);
    let state_len =
        u64::from_le_bytes(encoded[74..82].try_into().map_err(|_| StoreError::Serialization)?);
    let state_len = usize::try_from(state_len).map_err(|_| StoreError::Serialization)?;
    if state_len > MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES {
        return Err(StoreError::BlobTooLarge {
            kind: "deposit state-transfer intent state",
            actual: state_len,
            maximum: MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES,
        });
    }
    if encoded.len() != DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_HEADER_BYTES + state_len {
        return Err(StoreError::NonCanonicalEncoding {
            kind: "deposit state-transfer intent snapshot",
        });
    }
    let state = &encoded[DEPOSIT_STATE_TRANSFER_INTENTS_SNAPSHOT_HEADER_BYTES..];
    if snapshot_hash
        != deposit_state_transfer_intents_snapshot_hash(
            party,
            network_id,
            revision,
            previous_snapshot_hash,
            state,
        )
    {
        return Err(StoreError::Authentication);
    }
    if snapshot_hash == [0_u8; 32] || (revision == 0) != (previous_snapshot_hash == [0_u8; 32]) {
        return Err(StoreError::DepositStateTransferIntentsHashChainMismatch {
            network_id,
            revision,
        });
    }
    Ok((
        DepositStateTransferIntentsMetadata {
            network_id,
            revision,
            previous_snapshot_hash,
            snapshot_hash,
        },
        state,
    ))
}

fn key_rotation_round_key(context: &KeyRotationContext) -> KeyRotationRoundKey {
    KeyRotationRoundKey { target_epoch: context.target_epoch(), context_digest: context.digest() }
}

fn key_rotation_snapshot_hash(
    party: PartyId,
    key: KeyRotationRoundKey,
    revision: u64,
    previous_snapshot_hash: [u8; 32],
    state: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/key-rotation-snapshot/v2");
    hasher.update(&party.0.to_le_bytes());
    hasher.update(&key.target_epoch.to_le_bytes());
    hasher.update(&key.context_digest);
    hasher.update(&revision.to_le_bytes());
    hasher.update(&previous_snapshot_hash);
    hasher.update(&(state.len() as u64).to_le_bytes());
    hasher.update(state);
    *hasher.finalize().as_bytes()
}

fn encode_key_rotation_snapshot(
    party: PartyId,
    key: KeyRotationRoundKey,
    revision: u64,
    previous_snapshot_hash: [u8; 32],
    state: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if state.len() > MAX_KEY_ROTATION_ROUND_STATE_BYTES {
        return Err(StoreError::BlobTooLarge {
            kind: "key rotation round state",
            actual: state.len(),
            maximum: MAX_KEY_ROTATION_ROUND_STATE_BYTES,
        });
    }
    if revision == 0 && previous_snapshot_hash != [0_u8; 32] {
        return Err(StoreError::KeyRotationHashChainMismatch { key, revision });
    }
    let state_len = u64::try_from(state.len()).map_err(|_| StoreError::Serialization)?;
    let snapshot_hash =
        key_rotation_snapshot_hash(party, key, revision, previous_snapshot_hash, state);
    let mut encoded = Vec::with_capacity(KEY_ROTATION_SNAPSHOT_HEADER_BYTES + state.len());
    encoded.push(0);
    encoded.extend_from_slice(&KEY_ROTATION_SNAPSHOT_VERSION.to_le_bytes());
    encoded.extend_from_slice(&revision.to_le_bytes());
    encoded.extend_from_slice(&previous_snapshot_hash);
    encoded.extend_from_slice(&snapshot_hash);
    encoded.extend_from_slice(&state_len.to_le_bytes());
    encoded.extend_from_slice(state);
    Ok(encoded)
}

fn decode_key_rotation_snapshot_header<'a>(
    party: PartyId,
    key: KeyRotationRoundKey,
    encoded: &'a [u8],
) -> Result<(KeyRotationRoundMetadata, &'a [u8]), StoreError> {
    if encoded.len() < KEY_ROTATION_SNAPSHOT_HEADER_BYTES || encoded[0] != 0 {
        return Err(StoreError::NonCanonicalEncoding { kind: "key rotation round snapshot" });
    }
    let version =
        u16::from_le_bytes(encoded[1..3].try_into().map_err(|_| StoreError::Serialization)?);
    if version != KEY_ROTATION_SNAPSHOT_VERSION {
        return Err(StoreError::WrongContext);
    }
    let revision =
        u64::from_le_bytes(encoded[3..11].try_into().map_err(|_| StoreError::Serialization)?);
    let mut previous_snapshot_hash = [0_u8; 32];
    previous_snapshot_hash.copy_from_slice(&encoded[11..43]);
    let mut snapshot_hash = [0_u8; 32];
    snapshot_hash.copy_from_slice(&encoded[43..75]);
    let state_len =
        u64::from_le_bytes(encoded[75..83].try_into().map_err(|_| StoreError::Serialization)?);
    let state_len = usize::try_from(state_len).map_err(|_| StoreError::Serialization)?;
    if state_len > MAX_KEY_ROTATION_ROUND_STATE_BYTES {
        return Err(StoreError::BlobTooLarge {
            kind: "key rotation round state",
            actual: state_len,
            maximum: MAX_KEY_ROTATION_ROUND_STATE_BYTES,
        });
    }
    if encoded.len() != KEY_ROTATION_SNAPSHOT_HEADER_BYTES + state_len {
        return Err(StoreError::NonCanonicalEncoding { kind: "key rotation round snapshot" });
    }
    let state = &encoded[KEY_ROTATION_SNAPSHOT_HEADER_BYTES..];
    if snapshot_hash
        != key_rotation_snapshot_hash(party, key, revision, previous_snapshot_hash, state)
    {
        return Err(StoreError::Authentication);
    }
    if revision == 0 && previous_snapshot_hash != [0_u8; 32] {
        return Err(StoreError::KeyRotationHashChainMismatch { key, revision });
    }
    Ok((KeyRotationRoundMetadata { key, revision, previous_snapshot_hash, snapshot_hash }, state))
}

fn key_rotation_certificate_digest(key: KeyRotationRoundKey, encoded: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/key-rotation-certificate/v2");
    hasher.update(&key.target_epoch.to_le_bytes());
    hasher.update(&key.context_digest);
    hasher.update(&(encoded.len() as u64).to_le_bytes());
    hasher.update(encoded);
    *hasher.finalize().as_bytes()
}

fn epoch_identity_retirement_authorization(
    party: PartyId,
    context: &KeyRotationContext,
    certificate: &KeyRotationCertificate,
) -> Result<(EpochIdentityRetirement, Option<([u8; 32], EpochIdentityCertification)>), StoreError> {
    context.validate()?;
    let target = certificate.verify(context)?;
    let source_member = context.source().member(party).map_err(KeyRotationError::from)?;
    let target_member = target.member(party).ok();
    if target_member.is_some_and(|member| member.encryption_key == source_member.encryption_key)
        || context.source().epoch.checked_add(1) != Some(context.target_epoch())
    {
        return Err(StoreError::InvalidEpochIdentityRetirement);
    }
    let certificate_bytes = Zeroizing::new(certificate.encode(context)?);
    let key = key_rotation_round_key(context);
    let certificate_digest = key_rotation_certificate_digest(key, &certificate_bytes);
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/epoch-identity-retirement/v2");
    hasher.update(&party.0.to_le_bytes());
    hasher.update(&context.source().epoch.to_le_bytes());
    hasher.update(&context.target_epoch().to_le_bytes());
    hasher.update(&context.digest());
    hasher.update(&certificate_digest);
    hasher.update(&target.digest());
    hasher.update(&source_member.encryption_key);
    match target_member {
        Some(member) => {
            hasher.update(&[1]);
            hasher.update(&member.encryption_key);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    let authorization_digest = *hasher.finalize().as_bytes();
    let retirement = EpochIdentityRetirement {
        epoch: context.source().epoch,
        public_key: source_member.encryption_key,
        successor_epoch: context.target_epoch(),
        key_rotation_certificate_digest: certificate_digest,
        key_rotation_authorization_digest: authorization_digest,
    };
    validate_epoch_identity_retirement(retirement)?;
    let certification = target_member.map(|member| {
        (
            member.encryption_key,
            EpochIdentityCertification {
                version: EPOCH_IDENTITY_CERTIFICATION_VERSION,
                source_epoch: context.source().epoch,
                target_epoch: context.target_epoch(),
                target_public_key: member.encryption_key,
                context_digest: context.digest(),
                certificate_digest,
            },
        )
    });
    Ok((retirement, certification))
}

fn validate_epoch_identity_secret(
    expected_party: PartyId,
    identity: &EpochEncryptionSecret,
) -> Result<(), StoreError> {
    if identity.party() != expected_party
        || X25519PublicKey::from(&StaticSecret::from(*identity.secret_bytes())).to_bytes()
            != identity.public_key()
    {
        return Err(StoreError::EpochIdentityConflict { epoch: identity.epoch() });
    }
    Ok(())
}

fn validate_signing_seed(
    signing_seed: &[u8; 32],
    expected_signing_public_key: [u8; 32],
) -> Result<(), StoreError> {
    if Identity::signing_public_key_from_seed(signing_seed)? != expected_signing_public_key {
        return Err(StoreError::InvalidIdentity(IdentityError::WrongSigningPublicKey));
    }
    Ok(())
}

fn epoch_identity_record_digest(
    party: PartyId,
    record: &EpochIdentityRecord,
) -> Result<[u8; 32], StoreError> {
    // `open_epoch_identity_record` has already required exact canonical bytes. Re-encoding that
    // validated value gives a stable logical record digest across restart without binding the
    // protocol transcript to randomized local AEAD nonces.
    let canonical =
        Zeroizing::new(postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?);
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/epoch-identity-durable-readback/v1");
    hasher.update(&party.0.to_le_bytes());
    hasher.update(&(canonical.len() as u64).to_le_bytes());
    hasher.update(&canonical);
    Ok(*hasher.finalize().as_bytes())
}

fn epoch_identity_from_active(
    party: PartyId,
    active: &ActiveEpochIdentitySecret,
) -> Result<EpochEncryptionSecret, StoreError> {
    let identity = EpochEncryptionSecret::from_decrypted(
        party,
        active.epoch,
        active.public_key,
        Zeroizing::new(active.secret),
    )?;
    validate_epoch_identity_secret(party, &identity)?;
    Ok(identity)
}

fn validate_epoch_identity_retirement(
    retirement: EpochIdentityRetirement,
) -> Result<(), StoreError> {
    if retirement.successor_epoch <= retirement.epoch
        || retirement.public_key == [0_u8; 32]
        || retirement.key_rotation_certificate_digest == [0_u8; 32]
        || retirement.key_rotation_authorization_digest == [0_u8; 32]
    {
        return Err(StoreError::InvalidEpochIdentityRetirement);
    }
    Ok(())
}

fn session_tombstone_purpose_digest(session: SessionId, purpose: &[u8]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/session-tombstone-purpose/v1");
    hasher.update(&session.0);
    hasher.update(&(purpose.len() as u64).to_le_bytes());
    hasher.update(purpose);
    *hasher.finalize().as_bytes()
}

fn validate_sweep_signing_high_water(record: SweepSigningHighWater) -> Result<(), StoreError> {
    if record.version != SWEEP_SIGNING_HIGH_WATER_VERSION
        || record.wallet.0 == [0_u8; 32]
        || record.sweep.0 == [0_u8; 32]
        || record.attempt == 0
        || record.intent_digest == [0_u8; 32]
        || record.tombstone_purpose_digest == [0_u8; 32]
        || derive_sweep_signing_session(record.wallet, record.sweep, record.attempt)
            != Some(record.session)
    {
        return Err(StoreError::InvalidSweepSigningHighWater);
    }
    Ok(())
}

fn session_state_filename(key: SessionStateKey) -> String {
    format!("{}.{}.state", key.session, hex::encode(key.context_digest))
}

fn session_tombstone_filename(session: SessionId) -> String {
    format!("{session}.tombstone")
}

fn activation_filename(key: ActivationCertificateKey) -> String {
    format!("{}.{}.activation", key.epoch, hex::encode(key.activation_digest))
}

fn activation_index_filename(key: ActivationTransitionKey) -> String {
    format!("{}.{}.activation-index", key.epoch, hex::encode(key.transition_digest))
}

fn key_rotation_round_filename(key: KeyRotationRoundKey) -> String {
    format!("{}.{}.rotation", key.target_epoch, hex::encode(key.context_digest))
}

fn key_rotation_certificate_filename(key: KeyRotationRoundKey) -> String {
    format!("{}.{}.rotation-certificate", key.target_epoch, hex::encode(key.context_digest))
}

fn deposit_index_journal_filename(key: DepositIndexJournalKey) -> String {
    let scope = match key.scope {
        DepositIndexJournalScope::Portable => "portable",
        DepositIndexJournalScope::LocalSafety => "local",
    };
    format!(
        "{}.{scope}.{}.{}.deposit-index-journal",
        hex::encode(key.wallet_id.0),
        key.expected_revision,
        hex::encode(key.expected_head_digest)
    )
}

fn deposit_index_journal_context(key: DepositIndexJournalKey) -> ProtocolRecordContext {
    ProtocolRecordContext::DepositIndexJournal {
        wallet_id: key.wallet_id,
        scope: key.scope,
        expected_revision: key.expected_revision,
        expected_head_digest: key.expected_head_digest,
    }
}

fn deposit_sync_spool_head_filename(key: DepositSyncSpoolHeadKey) -> String {
    format!(
        "{}.{}.deposit-sync-spool-head",
        hex::encode(key.network_id),
        hex::encode(key.wallet_id.0)
    )
}

fn deposit_sync_spool_head_context(key: DepositSyncSpoolHeadKey) -> ProtocolRecordContext {
    ProtocolRecordContext::DepositSyncSpoolHead {
        network_id: key.network_id,
        wallet_id: key.wallet_id,
    }
}

fn sweep_signing_high_water_filename(wallet: DepositWalletId, sweep: SweepId) -> String {
    format!("{}.{}.sweep-high-water", hex::encode(wallet.0), hex::encode(sweep.0))
}

fn epoch_identity_filename(epoch: u64) -> String {
    format!("{epoch}.epoch-identity")
}

fn parse_session_state_filename(filename: &str) -> Option<SessionStateKey> {
    let stem = filename.strip_suffix(".state")?;
    let (session, context_digest) = stem.split_once('.')?;
    if context_digest.contains('.') {
        return None;
    }
    Some(SessionStateKey {
        session: SessionId(decode_canonical_hex(session)?),
        context_digest: decode_canonical_hex(context_digest)?,
    })
}

fn parse_activation_filename(filename: &str) -> Option<ActivationCertificateKey> {
    let stem = filename.strip_suffix(".activation")?;
    let (epoch_text, activation_digest) = stem.split_once('.')?;
    if activation_digest.contains('.') {
        return None;
    }
    let epoch = epoch_text.parse::<u64>().ok()?;
    if epoch.to_string() != epoch_text {
        return None;
    }
    Some(ActivationCertificateKey {
        epoch,
        activation_digest: decode_canonical_hex(activation_digest)?,
    })
}

fn parse_activation_index_filename(filename: &str) -> Option<ActivationTransitionKey> {
    let stem = filename.strip_suffix(".activation-index")?;
    let (epoch_text, transition_digest) = stem.split_once('.')?;
    if transition_digest.contains('.') {
        return None;
    }
    let epoch = epoch_text.parse::<u64>().ok()?;
    if epoch.to_string() != epoch_text {
        return None;
    }
    Some(ActivationTransitionKey {
        epoch,
        transition_digest: decode_canonical_hex(transition_digest)?,
    })
}

fn parse_key_rotation_round_filename(filename: &str) -> Option<KeyRotationRoundKey> {
    parse_key_rotation_filename(filename, ".rotation")
}

fn parse_key_rotation_certificate_filename(filename: &str) -> Option<KeyRotationRoundKey> {
    parse_key_rotation_filename(filename, ".rotation-certificate")
}

fn parse_key_rotation_filename(filename: &str, suffix: &str) -> Option<KeyRotationRoundKey> {
    let stem = filename.strip_suffix(suffix)?;
    let (target_epoch_text, context_digest) = stem.split_once('.')?;
    if context_digest.contains('.') {
        return None;
    }
    let target_epoch = target_epoch_text.parse::<u64>().ok()?;
    if target_epoch.to_string() != target_epoch_text {
        return None;
    }
    Some(KeyRotationRoundKey {
        target_epoch,
        context_digest: decode_canonical_hex(context_digest)?,
    })
}

fn parse_epoch_identity_filename(filename: &str) -> Option<u64> {
    let epoch_text = filename.strip_suffix(".epoch-identity")?;
    let epoch = epoch_text.parse::<u64>().ok()?;
    (epoch.to_string() == epoch_text).then_some(epoch)
}

fn decode_canonical_hex<const N: usize>(encoded: &str) -> Option<[u8; N]> {
    if encoded.len() != N.checked_mul(2)? {
        return None;
    }
    let mut bytes = [0_u8; N];
    hex::decode_to_slice(encoded, &mut bytes).ok()?;
    (hex::encode(bytes) == encoded).then_some(bytes)
}

fn documented_temporary_file<T>(filename: &str, parser: fn(&str) -> Option<T>) -> bool {
    let Some(stem) = filename.strip_prefix('.').and_then(|name| name.strip_suffix(".tmp")) else {
        return false;
    };
    let Some((destination, token)) = stem.rsplit_once('.') else {
        return false;
    };
    parser(destination).is_some() && decode_canonical_hex::<24>(token).is_some()
}

async fn enumerate_protocol_directory_bounded<T: Ord>(
    directory: &Path,
    parser: fn(&str) -> Option<T>,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<T>, StoreError> {
    match tokio::fs::symlink_metadata(directory).await {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(StoreError::UnexpectedEntry(directory.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    }

    let mut entries = tokio::fs::read_dir(directory).await?;
    let mut records = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if !entry.file_type().await?.is_file() {
            return Err(StoreError::UnexpectedEntry(path));
        }
        let filename = entry
            .file_name()
            .into_string()
            .map_err(|_| StoreError::UnexpectedEntry(path.clone()))?;
        if let Some(record) = parser(&filename) {
            if records.len() == maximum {
                return Err(StoreError::ProtocolEntryLimit { kind, maximum });
            }
            records.push(record);
        } else if !documented_temporary_file(&filename, parser) {
            return Err(StoreError::UnexpectedEntry(path));
        }
    }
    records.sort();
    Ok(records)
}

fn decode_exact<T>(bytes: &[u8], kind: &'static str) -> Result<T, StoreError>
where
    T: for<'de> Deserialize<'de>,
{
    let (decoded, remaining) =
        postcard::take_from_bytes(bytes).map_err(|_| StoreError::Serialization)?;
    if !remaining.is_empty() {
        return Err(StoreError::TrailingBytes { kind, trailing: remaining.len() });
    }
    Ok(decoded)
}

fn decode_canonical_exact<T>(bytes: &[u8], kind: &'static str) -> Result<T, StoreError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let decoded = decode_exact(bytes, kind)?;
    let canonical = postcard::to_allocvec(&decoded).map_err(|_| StoreError::Serialization)?;
    if canonical != bytes {
        return Err(StoreError::NonCanonicalEncoding { kind });
    }
    Ok(decoded)
}

async fn read_capped_regular_file(
    path: &Path,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<u8>, StoreError> {
    let link_metadata = tokio::fs::symlink_metadata(path).await?;
    if !link_metadata.is_file() {
        return Err(StoreError::NotRegularFile(path.to_path_buf()));
    }
    let file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() {
        return Err(StoreError::NotRegularFile(path.to_path_buf()));
    }
    let metadata_len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if metadata_len > maximum {
        return Err(StoreError::BlobTooLarge { kind, actual: metadata_len, maximum });
    }
    let read_limit = u64::try_from(maximum)
        .map_err(|_| StoreError::Serialization)?
        .checked_add(1)
        .ok_or(StoreError::Serialization)?;
    let mut reader = file.take(read_limit);
    let mut bytes = Vec::with_capacity(metadata_len);
    reader.read_to_end(&mut bytes).await?;
    if bytes.len() > maximum {
        return Err(StoreError::BlobTooLarge { kind, actual: bytes.len(), maximum });
    }
    Ok(bytes)
}

fn party_state_lease_path(state_directory: &Path, party: PartyId) -> PathBuf {
    state_directory
        .join(format!("{PARTY_STATE_LEASE_FILE_PREFIX}{}{PARTY_STATE_LEASE_FILE_SUFFIX}", party.0))
}

fn open_party_state_lease_create_new(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(unix)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    true
}

async fn ensure_private_directory(path: &Path) -> Result<(), StoreError> {
    let existing = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_dir() => Some(metadata),
        Ok(_) => return Err(StoreError::UnexpectedEntry(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    tokio::fs::create_dir_all(path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Even chmod(0700) on an already-private directory dirties its inode. Artifact reads
        // use this helper too; avoid forcing a fresh journal commit on every authenticated read.
        if existing.as_ref().is_none_or(|metadata| metadata.permissions().mode() & 0o7777 != 0o700)
        {
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
        }
    }
    sync_directory(path).await?;
    if existing.is_none()
        && let Some(parent) = path.parent()
    {
        sync_directory(parent).await?;
    }
    Ok(())
}

async fn entry_exists_regular(path: &Path) -> Result<bool, StoreError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(StoreError::NotRegularFile(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn require_directory(path: &Path) -> Result<(), StoreError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(StoreError::UnexpectedEntry(path.to_path_buf())),
        Err(error) => Err(error.into()),
    }
}

async fn directory_exists(path: &Path) -> Result<bool, StoreError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(StoreError::UnexpectedEntry(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn ensure_destination_absent(path: &Path) -> Result<(), StoreError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Err(StoreError::RetirementConflict(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn temporary_path(destination: &Path, token: [u8; 24]) -> Result<PathBuf, StoreError> {
    let parent = destination
        .parent()
        .ok_or_else(|| StoreError::UnexpectedEntry(destination.to_path_buf()))?;
    let filename = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| StoreError::UnexpectedEntry(destination.to_path_buf()))?;
    Ok(parent.join(format!(".{filename}.{}.tmp", hex::encode(token))))
}

/// Replace one mutable record while the caller holds its store mutation lock and the process-wide
/// [`PartyStateLease`]. A retry first removes only bounded, canonical crash temporaries for this
/// exact destination and makes those removals durable before creating the next temporary.
async fn atomic_replace(
    destination: &Path,
    bytes: &[u8],
    token: [u8; 24],
) -> Result<(), StoreError> {
    let parent = destination
        .parent()
        .ok_or_else(|| StoreError::UnexpectedEntry(destination.to_path_buf()))?;
    ensure_private_directory(parent).await?;
    let _destination_exists = entry_exists_regular(destination).await?;
    destroy_temporary_replacements(destination).await?;
    let temporary = temporary_path(destination, token)?;
    write_private_file(&temporary, bytes).await?;
    tokio::fs::rename(&temporary, destination).await?;
    sync_directory(parent).await?;
    Ok(())
}

async fn destroy_file_and_sync_parent(path: &Path) -> Result<(), StoreError> {
    let parent = path.parent().ok_or_else(|| StoreError::UnexpectedEntry(path.to_path_buf()))?;
    destroy_temporary_replacements(path).await?;
    tokio::fs::remove_file(path).await?;
    sync_directory(parent).await?;
    Ok(())
}

/// Remove only temporary replacements for this exact destination. These files are never
/// authoritative, but a crash after `write_private_file` and before rename can leave a complete
/// secret-bearing record behind. Callers hold the corresponding store mutation/namespace lock and
/// have already authenticated the durable operation whose retry makes the temporary unreachable.
/// The complete candidate set is validated and bounded before any candidate is removed.
async fn destroy_temporary_replacements(destination: &Path) -> Result<(), StoreError> {
    let parent = destination
        .parent()
        .ok_or_else(|| StoreError::UnexpectedEntry(destination.to_path_buf()))?;
    let filename = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| StoreError::UnexpectedEntry(destination.to_path_buf()))?;
    let prefix = format!(".{filename}.");
    let mut entries = tokio::fs::read_dir(parent).await?;
    let mut candidates = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let candidate_path = entry.path();
        let Some(candidate) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(token) =
            candidate.strip_prefix(&prefix).and_then(|rest| rest.strip_suffix(".tmp"))
        else {
            continue;
        };
        if decode_canonical_hex::<24>(token).is_none() {
            continue;
        }
        if !entry.file_type().await?.is_file() {
            return Err(StoreError::NotRegularFile(candidate_path));
        }
        if candidates.len() == MAX_TEMPORARY_REPLACEMENTS_PER_DESTINATION {
            return Err(StoreError::ProtocolEntryLimit {
                kind: "temporary replacements for one destination",
                maximum: MAX_TEMPORARY_REPLACEMENTS_PER_DESTINATION,
            });
        }
        candidates.push(candidate_path);
    }
    for candidate in &candidates {
        if !tokio::fs::symlink_metadata(candidate).await?.is_file() {
            return Err(StoreError::NotRegularFile(candidate.clone()));
        }
    }
    for candidate in &candidates {
        tokio::fs::remove_file(candidate).await?;
    }
    if !candidates.is_empty() {
        sync_directory(parent).await?;
    }
    Ok(())
}

/// Install an immutable artifact without ever replacing an existing destination.
async fn atomic_create_new(
    destination: &Path,
    bytes: &[u8],
    token: [u8; 24],
) -> Result<bool, StoreError> {
    let parent = destination
        .parent()
        .ok_or_else(|| StoreError::UnexpectedEntry(destination.to_path_buf()))?;
    ensure_private_directory(parent).await?;
    let temporary = temporary_path(destination, token)?;
    write_private_file(&temporary, bytes).await?;
    let installed = match tokio::fs::hard_link(&temporary, destination).await {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    tokio::fs::remove_file(&temporary).await?;
    sync_directory(parent).await?;
    Ok(installed)
}

fn associated_data(party: PartyId, epoch: u64, committee_digest: [u8; 32]) -> Vec<u8> {
    let mut aad = b"threshold-monero/sealed-share/v1".to_vec();
    aad.extend_from_slice(&party.0.to_le_bytes());
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(&committee_digest);
    aad
}

fn share_key_associated_data(
    party: PartyId,
    epoch: u64,
    committee_digest: [u8; 32],
    share_nonce: [u8; 24],
) -> Vec<u8> {
    let mut aad = b"threshold-monero/sealed-share/wrapped-dek/v2".to_vec();
    aad.extend_from_slice(&party.0.to_le_bytes());
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(&committee_digest);
    aad.extend_from_slice(&share_nonce);
    aad
}

fn validate_share_retirement(retirement: ShareRetirement) -> Result<(), StoreError> {
    if retirement.successor_epoch <= retirement.epoch
        || retirement.successor_activation_digest == [0_u8; 32]
    {
        return Err(StoreError::InvalidShareRetirement);
    }
    Ok(())
}

fn share_retirement_associated_data(party: PartyId, retirement: ShareRetirement) -> Vec<u8> {
    let mut aad = b"threshold-monero/share-retirement/v2".to_vec();
    aad.extend_from_slice(&party.0.to_le_bytes());
    aad.extend_from_slice(&retirement.epoch.to_le_bytes());
    aad.extend_from_slice(&retirement.committee_digest);
    aad.extend_from_slice(&retirement.successor_epoch.to_le_bytes());
    aad.extend_from_slice(&retirement.successor_activation_digest);
    aad
}

async fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(path).await?;
    file.write_all(bytes).await?;
    file.flush().await?;
    file.sync_all().await
}

async fn sync_directory(path: &Path) -> io::Result<()> {
    let directory = tokio::fs::File::open(path).await?;
    directory.sync_all().await
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use curve25519_dalek::Scalar;
    use rand_core::OsRng;

    use super::*;
    use crate::{
        committee::{Committee, Member},
        deposit_consensus::{
            CommitCertificate, ConsensusMessageBody, Vote, sign_consensus_message,
        },
        deposit_wallet::{DepositWalletId, SweepId},
        identity::{Identity, PersistedKeyAdvertisementIdentity},
        key_rotation::{
            KeyRotationContext, KeyRotationError, KeyRotationRound, KeyRotationTargetPolicy,
            KeyRotationWire, sign_key_advertisement,
        },
        keys::{SecretPolynomial, aggregate_dkg, make_dkg_output},
        receiver_key_accumulator::ReceiverKeyAccumulatorStore,
    };

    fn explicit_test_identity(
        party: PartyId,
        epoch: u64,
        signing_seed: [u8; 32],
        x25519_secret: [u8; 32],
    ) -> Identity {
        assert_ne!(
            signing_seed, x25519_secret,
            "tests must model independently provisioned signing and encryption material"
        );
        Identity::from_test_secrets(party, epoch, &signing_seed, x25519_secret).unwrap()
    }

    fn share() -> EpochShare {
        let identities = (1_u16..=3)
            .map(|id| {
                let party = PartyId(id);
                (
                    party,
                    explicit_test_identity(
                        party,
                        0,
                        [u8::try_from(id).unwrap(); 32],
                        [u8::try_from(id).unwrap().wrapping_add(0x60); 32],
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let committee = Committee {
            epoch: 0,
            threshold: 2,
            members: identities
                .iter()
                .map(|(id, identity)| Member {
                    id: *id,
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        };
        let polynomials = (1_u16..=3)
            .map(|id| {
                let polynomial =
                    SecretPolynomial::random_with_constant(2, Scalar::from(id), &mut OsRng)
                        .unwrap();
                (PartyId(id), polynomial)
            })
            .collect::<BTreeMap<_, _>>();
        let outputs = polynomials
            .iter()
            .map(|(dealer, polynomial)| {
                make_dkg_output(*dealer, polynomial, &committee, PartyId(1)).unwrap()
            })
            .collect();
        aggregate_dkg([4; 32], committee, PartyId(1), outputs).unwrap()
    }

    fn retirement(committee_digest: [u8; 32]) -> ShareRetirement {
        ShareRetirement {
            epoch: 0,
            committee_digest,
            successor_epoch: 1,
            successor_activation_digest: [7; 32],
        }
    }

    struct RotationFixture {
        context: KeyRotationContext,
        receiver_keys: ReceiverKeyAccumulatorStore,
        source: Vec<Identity>,
        target: Vec<Identity>,
    }

    fn rotation_signing_seed(party: PartyId) -> [u8; 32] {
        let mut seed = [u8::try_from(party.0).unwrap().wrapping_mul(29); 32];
        seed[..2].copy_from_slice(&party.0.to_le_bytes());
        seed
    }

    fn rotation_encryption_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut material = Vec::with_capacity(10);
        material.extend_from_slice(&party.0.to_le_bytes());
        material.extend_from_slice(&epoch.to_le_bytes());
        blake3::derive_key("threshold-monero/storage-test-x25519/v1", &material)
    }

    fn rotation_identity(party: PartyId, epoch: u64) -> Identity {
        explicit_test_identity(
            party,
            epoch,
            rotation_signing_seed(party),
            rotation_encryption_secret(party, epoch),
        )
    }

    fn rotation_bootstrap_identity(party: PartyId, epoch: u64) -> Identity {
        let mut material = Vec::with_capacity(10);
        material.extend_from_slice(&party.0.to_le_bytes());
        material.extend_from_slice(&epoch.to_le_bytes());
        explicit_test_identity(
            party,
            epoch,
            rotation_signing_seed(party),
            blake3::derive_key("threshold-monero/storage-test-bootstrap-x25519/v1", &material),
        )
    }

    fn rotation_committee(epoch: u64, identities: &[Identity]) -> Committee {
        Committee {
            epoch,
            threshold: 2,
            members: identities
                .iter()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        }
    }

    fn rotation_receiver_key_store(
        network: [u8; 32],
        source: &Committee,
        eligible: &Committee,
    ) -> ReceiverKeyAccumulatorStore {
        let entries = source
            .members
            .iter()
            .chain(&eligible.members)
            .map(|member| (member.id, member.encryption_key))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        ReceiverKeyAccumulatorStore::from_entries_at_epoch(network, source.epoch, &entries).unwrap()
    }

    fn rotation_identity_from_secret(secret: &EpochEncryptionSecret) -> Identity {
        explicit_test_identity(
            secret.party(),
            secret.epoch(),
            rotation_signing_seed(secret.party()),
            *secret.secret_bytes(),
        )
    }

    fn rotation_advertisement_capability(identity: &Identity) -> PersistedKeyAdvertisementIdentity {
        let secret = identity.export_encryption_secret();
        let reconstructed = rotation_identity_from_secret(&secret);
        let mut material = Vec::with_capacity(42);
        material.extend_from_slice(&identity.party().0.to_le_bytes());
        material.extend_from_slice(&identity.encryption_epoch().to_le_bytes());
        material.extend_from_slice(&identity.encryption_public_key());
        let digest =
            blake3::derive_key("threshold-monero/storage-test-durable-readback/v1", &material);
        reconstructed.after_durable_encryption_readback(digest).unwrap()
    }

    fn rotation_fixture() -> RotationFixture {
        let source_epoch = 7;
        let target_epoch = 8;
        let source = (1_u16..=4)
            .map(|id| {
                let party = PartyId(id);
                rotation_identity(party, source_epoch)
            })
            .collect::<Vec<_>>();
        let target = (1_u16..=4)
            .map(|id| {
                let party = PartyId(id);
                rotation_identity(party, target_epoch)
            })
            .collect::<Vec<_>>();
        let committee = rotation_committee(source_epoch, &source);
        // Async-security selection requires a certified target of n=4 (n >= 3f+1 with f=1) and an
        // eligible pool floor of desired_n + f = 5, so extend the pool with a single joiner
        // spare that is eligible but never advertised and therefore never selected.
        let spare = rotation_bootstrap_identity(PartyId(5), target_epoch);
        let mut eligible = committee.clone();
        eligible.epoch = target_epoch;
        eligible.members.push(Member {
            id: PartyId(5),
            signing_key: spare.signing_public_key(),
            encryption_key: spare.encryption_public_key(),
        });
        let network = [0x31; 32];
        let receiver_keys = rotation_receiver_key_store(network, &committee, &eligible);
        let target_policy = KeyRotationTargetPolicy::new(
            &committee,
            1,
            eligible.clone(),
            4,
            1,
            receiver_keys.commitment(),
            10_000,
        )
        .unwrap();
        let context =
            KeyRotationContext::new(network, committee, [0x41; 32], 1, target_policy).unwrap();
        RotationFixture { context, receiver_keys, source, target }
    }

    fn committed_rotation_rounds(fixture: &RotationFixture) -> Vec<KeyRotationRound> {
        committed_rotation_rounds_for(
            &fixture.context,
            &fixture.receiver_keys,
            &fixture.source,
            &fixture.target,
            4,
        )
    }

    fn committed_rotation_rounds_for(
        context: &KeyRotationContext,
        receiver_keys: &ReceiverKeyAccumulatorStore,
        source: &[Identity],
        target: &[Identity],
        advertiser_count: usize,
    ) -> Vec<KeyRotationRound> {
        let advertisers =
            target.iter().take(advertiser_count).map(Identity::party).collect::<Vec<_>>();
        committed_rotation_rounds_for_advertisers(
            context,
            receiver_keys,
            source,
            target,
            &advertisers,
        )
    }

    fn committed_rotation_rounds_for_advertisers(
        context: &KeyRotationContext,
        receiver_keys: &ReceiverKeyAccumulatorStore,
        source: &[Identity],
        target: &[Identity],
        advertisers: &[PartyId],
    ) -> Vec<KeyRotationRound> {
        let mut rounds = source
            .iter()
            .map(|identity| KeyRotationRound::new(context.clone(), identity.party()).unwrap())
            .collect::<Vec<_>>();
        for advertiser in advertisers {
            let identity = target.iter().find(|identity| identity.party() == *advertiser).unwrap();
            let capability = rotation_advertisement_capability(identity);
            let advertisement = sign_key_advertisement(context, &capability).unwrap();
            for (round, local_identity) in rounds.iter_mut().zip(source) {
                round
                    .handle_wire(
                        *advertiser,
                        KeyRotationWire::Advertisement(advertisement.clone()),
                        local_identity,
                        receiver_keys,
                    )
                    .unwrap();
            }
        }
        let retained_source =
            advertisers.iter().filter(|party| context.source().member(**party).is_ok()).count();
        if retained_source < context.primary_source_overlap() {
            let votes = source
                .iter()
                .map(|identity| {
                    crate::key_rotation::sign_selection_fallback_vote(context, identity).unwrap()
                })
                .collect::<Vec<_>>();
            for (round, identity) in rounds.iter_mut().zip(source) {
                round.authorize_fallback(identity, receiver_keys).unwrap();
                for vote in &votes {
                    if vote.from != identity.party() {
                        round
                            .handle_wire(
                                vote.from,
                                KeyRotationWire::FallbackVote(vote.clone()),
                                identity,
                                receiver_keys,
                            )
                            .unwrap();
                    }
                }
            }
        }
        for _ in 0..512 {
            if rounds[..context.source_quorum()].iter().all(|round| round.certificate().is_some()) {
                return rounds;
            }
            let mut progressed = false;
            for sender_index in (0..source.len()).rev() {
                let sender = source[sender_index].party();
                for pending in rounds[sender_index].pending_messages(usize::MAX) {
                    let Some(recipient_index) =
                        source.iter().position(|identity| identity.party() == pending.id.recipient)
                    else {
                        // Target-only joiners receive immutable certificate catch-up in the real
                        // runtime but do not participate in the source committee's consensus.
                        continue;
                    };
                    if recipient_index >= context.source_quorum() {
                        continue;
                    }
                    match rounds[recipient_index].handle_wire(
                        sender,
                        pending.wire,
                        &source[recipient_index],
                        receiver_keys,
                    ) {
                        Ok(_) => {
                            assert_eq!(rounds[sender_index].acknowledge(&[pending.id]).unwrap(), 1);
                            progressed = true;
                        }
                        Err(KeyRotationError::ConsensusNotReady) => {}
                        Err(error) => panic!("key-rotation delivery failed: {error}"),
                    }
                }
            }
            assert!(progressed, "key-rotation fixture stopped making progress");
        }
        panic!("key-rotation fixture did not commit")
    }

    #[tokio::test]
    async fn party_state_lease_fences_cloned_server_until_last_owner_drops() {
        use std::sync::Arc;

        let directory = tempfile::tempdir().unwrap();
        let party = PartyId(41);
        let first = Arc::new(PartyStateLease::acquire(directory.path(), party).await.unwrap());
        let lock_path = first.path().to_path_buf();
        assert!(tokio::fs::symlink_metadata(&lock_path).await.unwrap().is_file());

        let retained_by_server_clone = Arc::clone(&first);
        drop(first);
        assert!(matches!(
            PartyStateLease::acquire(directory.path(), party).await,
            Err(StoreError::PartyStateLeaseHeld {
                party: held_party,
                path,
            }) if held_party == party && path == lock_path
        ));

        // A different party has an independent permanent writer inode.
        let other_party = PartyStateLease::acquire(directory.path(), PartyId(42)).await.unwrap();
        drop(other_party);

        drop(retained_by_server_clone);
        let restarted = PartyStateLease::acquire(directory.path(), party).await.unwrap();
        assert_eq!(restarted.path(), lock_path);
        drop(restarted);
        assert!(
            tokio::fs::symlink_metadata(&lock_path).await.unwrap().is_file(),
            "normal drop must unlock but never delete the permanent inode"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn private_directory_rechecks_do_not_dirty_an_already_private_inode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private");
        ensure_private_directory(&path).await.unwrap();
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).await.unwrap();
        ensure_private_directory(&path).await.unwrap();
        let before = tokio::fs::symlink_metadata(&path).await.unwrap();
        assert_eq!(before.permissions().mode() & 0o7777, 0o700);
        ensure_private_directory(&path).await.unwrap();
        let after = tokio::fs::symlink_metadata(&path).await.unwrap();
        assert_eq!((after.ctime(), after.ctime_nsec()), (before.ctime(), before.ctime_nsec()));
        assert_eq!(after.permissions().mode() & 0o7777, 0o700);

        let link = root.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            ensure_private_directory(&link).await,
            Err(StoreError::UnexpectedEntry(_))
        ));
    }

    #[tokio::test]
    async fn party_state_lease_rejects_a_non_regular_lock_target() {
        let directory = tempfile::tempdir().unwrap();
        ensure_private_directory(directory.path()).await.unwrap();
        let canonical = tokio::fs::canonicalize(directory.path()).await.unwrap();
        let lock_path = party_state_lease_path(&canonical, PartyId(43));
        tokio::fs::create_dir(&lock_path).await.unwrap();
        assert!(matches!(
            PartyStateLease::acquire(directory.path(), PartyId(43)).await,
            Err(StoreError::NotRegularFile(path)) if path == lock_path
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn party_state_lease_rejects_a_symlink_lock_target() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        ensure_private_directory(directory.path()).await.unwrap();
        let canonical = tokio::fs::canonicalize(directory.path()).await.unwrap();
        let target = canonical.join("foreign-lock-target");
        tokio::fs::write(&target, b"not the permanent lease inode").await.unwrap();
        let lock_path = party_state_lease_path(&canonical, PartyId(44));
        symlink(&target, &lock_path).unwrap();
        assert!(matches!(
            PartyStateLease::acquire(directory.path(), PartyId(44)).await,
            Err(StoreError::NotRegularFile(path)) if path == lock_path
        ));
    }

    #[tokio::test]
    async fn atomic_replace_sweeps_only_exact_canonical_crash_temporaries() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("mutable.record");
        atomic_replace(&destination, b"old authoritative bytes", [0x11; 24]).await.unwrap();

        // Model a crash after the next replacement was fsynced but before rename.
        let crash_temporary = temporary_path(&destination, [0x12; 24]).unwrap();
        write_private_file(&crash_temporary, b"uncommitted replacement").await.unwrap();
        let near_miss = directory.path().join(".mutable.record.not-canonical.tmp");
        write_private_file(&near_miss, b"unrelated").await.unwrap();
        let other_destination = directory.path().join("other.record");
        let other_temporary = temporary_path(&other_destination, [0x13; 24]).unwrap();
        write_private_file(&other_temporary, b"other destination").await.unwrap();

        atomic_replace(&destination, b"new authoritative bytes", [0x14; 24]).await.unwrap();
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"new authoritative bytes");
        assert!(!tokio::fs::try_exists(crash_temporary).await.unwrap());
        assert!(tokio::fs::try_exists(near_miss).await.unwrap());
        assert!(tokio::fs::try_exists(other_temporary).await.unwrap());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn atomic_replace_rejects_a_canonical_symlink_before_creating_the_next_temp() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("mutable.record");
        atomic_replace(&destination, b"authoritative bytes", [0x21; 24]).await.unwrap();
        let poisoned = temporary_path(&destination, [0x22; 24]).unwrap();
        symlink(&destination, &poisoned).unwrap();
        let next = temporary_path(&destination, [0x23; 24]).unwrap();

        assert!(matches!(
            atomic_replace(&destination, b"must not install", [0x23; 24]).await,
            Err(StoreError::NotRegularFile(path)) if path == poisoned
        ));
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"authoritative bytes");
        assert!(!tokio::fs::try_exists(next).await.unwrap());
    }

    #[tokio::test]
    async fn atomic_replace_temp_sweep_is_bounded_and_all_or_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("bounded.record");
        atomic_replace(&destination, b"authoritative bytes", [0x31; 24]).await.unwrap();
        let mut leftovers = Vec::new();
        for index in 0..=MAX_TEMPORARY_REPLACEMENTS_PER_DESTINATION {
            let mut token = [0_u8; 24];
            token[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
            let path = temporary_path(&destination, token).unwrap();
            tokio::fs::write(&path, b"crash leftover").await.unwrap();
            leftovers.push(path);
        }

        assert!(matches!(
            atomic_replace(&destination, b"must not install", [0xFF; 24]).await,
            Err(StoreError::ProtocolEntryLimit {
                kind: "temporary replacements for one destination",
                maximum: MAX_TEMPORARY_REPLACEMENTS_PER_DESTINATION,
            })
        ));
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"authoritative bytes");
        for path in leftovers {
            assert!(
                tokio::fs::try_exists(path).await.unwrap(),
                "over-limit cleanup must fail before partially deleting the set"
            );
        }
        assert!(
            !tokio::fs::try_exists(temporary_path(&destination, [0xFF; 24]).unwrap())
                .await
                .unwrap()
        );
    }

    fn bounded_session_state_fixture(index: usize) -> (SessionId, [u8; 32], [u8; 8]) {
        let index = u64::try_from(index).unwrap();
        let mut session = [0xA5; 32];
        session[..8].copy_from_slice(&index.to_be_bytes());
        let mut context = [0x5A; 32];
        context[..8].copy_from_slice(&index.to_be_bytes());
        (SessionId(session), context, index.to_be_bytes())
    }

    #[tokio::test]
    async fn session_state_restore_rejects_cap_plus_one_before_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProtocolStore::new(directory.path(), PartyId(1), &[0x41; 32]).unwrap();
        ensure_private_directory(&store.session_directory()).await.unwrap();

        // Every entry is deliberately unauthenticated. The cap must be established by bounded
        // filename traversal before restoration opens even the first ciphertext.
        for index in 0..=MAX_SESSION_STATE_RECORDS {
            let (session, context, _) = bounded_session_state_fixture(index);
            tokio::fs::write(
                store.session_state_path(session, context),
                b"deliberately unauthenticated",
            )
            .await
            .unwrap();
        }

        assert!(matches!(
            store.session_states().await,
            Err(StoreError::ProtocolEntryLimit {
                kind: "session state",
                maximum: MAX_SESSION_STATE_RECORDS,
            })
        ));
    }

    #[tokio::test]
    async fn session_state_restore_accepts_exact_protocol_maximum_and_returns_blobs() {
        let directory = tempfile::tempdir().unwrap();
        let identity_seed = [0x42; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();

        for index in 0..MAX_SESSION_STATE_RECORDS {
            let (session, context, state) = bounded_session_state_fixture(index);
            store.save_session_state(session, context, &state, &mut OsRng).await.unwrap();
        }
        let (overflow_session, overflow_context, overflow_state) =
            bounded_session_state_fixture(MAX_SESSION_STATE_RECORDS);
        assert!(matches!(
            store
                .save_session_state(
                    overflow_session,
                    overflow_context,
                    &overflow_state,
                    &mut OsRng,
                )
                .await,
            Err(StoreError::ProtocolEntryLimit {
                kind: "session state",
                maximum: MAX_SESSION_STATE_RECORDS,
            })
        ));

        let restarted = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let restored = restarted.session_states().await.unwrap();
        assert_eq!(restored.len(), MAX_SESSION_STATE_RECORDS);
        for (index, restored) in restored.into_iter().enumerate() {
            let (session, context, state) = bounded_session_state_fixture(index);
            assert_eq!(restored.session, session);
            assert_eq!(restored.context_digest, context);
            assert_eq!(restored.state.as_bytes(), state);
        }
    }

    #[tokio::test]
    async fn session_context_claim_is_serialized_across_store_handles() {
        let directory = tempfile::tempdir().unwrap();
        let first = ProtocolStore::new(directory.path(), PartyId(1), &[0x43; 32]).unwrap();
        let second = ProtocolStore::new(directory.path(), PartyId(1), &[0x43; 32]).unwrap();
        let session = SessionId([0x44; 32]);
        let mut first_rng = OsRng;
        let mut second_rng = OsRng;
        let (first_result, second_result) = tokio::join!(
            first.save_session_state(session, [0x45; 32], b"first", &mut first_rng),
            second.save_session_state(session, [0x46; 32], b"second", &mut second_rng),
        );

        assert_eq!(usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()), 1);
        let rejected = if first_result.is_err() { first_result } else { second_result };
        assert!(matches!(
            rejected,
            Err(StoreError::SessionContextConflict { session: found }) if found == session
        ));
        let restored = first.session_states().await.unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].session, session);
    }

    #[tokio::test]
    async fn encrypted_store_round_trip_and_tamper_rejection() {
        let directory = tempfile::tempdir().unwrap();
        let store = ShareStore::new(directory.path(), PartyId(1), &[1; 32]).unwrap();
        let share = share();
        store.save(&share, &mut OsRng).await.unwrap();
        let loaded = store.load(0, share.committee.digest()).await.unwrap();
        assert_eq!(loaded.group_key_bytes(), share.group_key_bytes());

        let path = store.share_path(0);
        let mut bytes = tokio::fs::read(&path).await.unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        tokio::fs::write(&path, bytes).await.unwrap();
        assert!(store.load(0, share.committee.digest()).await.is_err());
    }

    #[tokio::test]
    async fn removed_direct_encryption_share_format_is_rejected_without_fallback() {
        #[derive(Serialize)]
        struct RemovedDirectShareRecord {
            version: u16,
            party: PartyId,
            epoch: u64,
            committee_digest: [u8; 32],
            nonce: [u8; 24],
            ciphertext: Vec<u8>,
        }

        let directory = tempfile::tempdir().unwrap();
        let store = ShareStore::new(directory.path(), PartyId(1), &[1; 32]).unwrap();
        let share = share();
        let committee_digest = share.committee.digest();
        let mut plaintext = postcard::to_allocvec(&share.material()).unwrap();
        let nonce = [0x91; 24];
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(&store.key))
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &associated_data(store.party, 0, committee_digest),
                },
            )
            .unwrap();
        plaintext.zeroize();
        let removed = RemovedDirectShareRecord {
            version: 1,
            party: store.party,
            epoch: 0,
            committee_digest,
            nonce,
            ciphertext,
        };
        tokio::fs::write(store.share_path(0), postcard::to_allocvec(&removed).unwrap())
            .await
            .unwrap();

        assert!(store.load(0, committee_digest).await.is_err());
        assert!(store.save(&share, &mut OsRng).await.is_err());
    }

    #[tokio::test]
    async fn share_retirement_atomically_replaces_secret_and_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let store = ShareStore::new(directory.path(), PartyId(1), &[1; 32]).unwrap();
        let share = share();
        let committee_digest = share.committee.digest();
        store.save(&share, &mut OsRng).await.unwrap();
        let active_record = tokio::fs::read(store.share_path(0)).await.unwrap();
        let stale_active_temporary = temporary_path(&store.share_path(0), [0x44; 24]).unwrap();
        tokio::fs::write(&stale_active_temporary, &active_record).await.unwrap();
        let near_miss = directory.path().join(".epoch-0.share.not-canonical-hex.tmp");
        tokio::fs::write(&near_miss, &active_record).await.unwrap();

        assert!(matches!(
            store.retire_share(retirement([0xFF; 32])).await,
            Err(StoreError::WrongContext)
        ));
        assert_eq!(tokio::fs::read(store.share_path(0)).await.unwrap(), active_record);
        assert!(tokio::fs::metadata(store.share_path(0)).await.unwrap().is_file());

        let authorization = retirement(committee_digest);
        let retired = store.retire_share(authorization).await.unwrap();
        assert_eq!(retired, store.share_path(0));
        assert!(!tokio::fs::try_exists(&stale_active_temporary).await.unwrap());
        assert!(tokio::fs::try_exists(&near_miss).await.unwrap());
        tokio::fs::remove_file(near_miss).await.unwrap();
        assert!(tokio::fs::metadata(&retired).await.unwrap().is_file());
        assert!(matches!(
            store.load(0, committee_digest).await,
            Err(StoreError::ShareRetired { epoch: 0, successor_epoch: 1 })
        ));
        assert!(store.load_if_active(0, committee_digest).await.unwrap().is_none());
        assert_eq!(store.load_retirement(0, committee_digest).await.unwrap(), Some(authorization));
        let restarted = ShareStore::new(directory.path(), PartyId(1), &[1; 32]).unwrap();
        assert_eq!(
            restarted.load_retirement(0, committee_digest).await.unwrap(),
            Some(authorization),
            "a fresh process must authenticate the exact retirement authorization"
        );
        let crash_leftover = temporary_path(&store.share_path(0), [0x45; 24]).unwrap();
        tokio::fs::write(&crash_leftover, &active_record).await.unwrap();
        assert_eq!(store.retire_share(authorization).await.unwrap(), retired);
        assert!(!tokio::fs::try_exists(crash_leftover).await.unwrap());
        assert!(matches!(
            store.save(&share, &mut OsRng).await,
            Err(StoreError::ShareRetired { epoch: 0, successor_epoch: 1 })
        ));

        let conflicting = ShareRetirement {
            successor_epoch: 2,
            successor_activation_digest: [8; 32],
            ..authorization
        };
        assert!(matches!(
            store.retire_share(conflicting).await,
            Err(StoreError::ShareRetirementConflict { epoch: 0 })
        ));

        let marker = tokio::fs::read(&retired).await.unwrap();
        let mut tampered = marker.clone();
        *tampered.last_mut().unwrap() ^= 1;
        tokio::fs::write(&retired, tampered).await.unwrap();
        assert!(matches!(store.load(0, committee_digest).await, Err(StoreError::Authentication)));
        tokio::fs::write(&retired, marker).await.unwrap();

        let retired_directory = directory.path().join(RETIRED_DIRECTORY);
        assert!(!tokio::fs::try_exists(retired_directory).await.unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = tokio::fs::metadata(retired).await.unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[tokio::test]
    async fn retirement_crash_boundary_exposes_complete_active_or_complete_tombstone() {
        let directory = tempfile::tempdir().unwrap();
        let store = ShareStore::new(directory.path(), PartyId(1), &[1; 32]).unwrap();
        let share = share();
        let committee_digest = share.committee.digest();
        store.save(&share, &mut OsRng).await.unwrap();
        let active_record = tokio::fs::read(store.share_path(0)).await.unwrap();
        store.retire_share(retirement(committee_digest)).await.unwrap();
        let tombstone_record = tokio::fs::read(store.share_path(0)).await.unwrap();

        // Model a crash after the replacement file was fsynced but before rename: the old active
        // record remains authoritative and the documented temporary file is ignored.
        tokio::fs::write(store.share_path(0), &active_record).await.unwrap();
        let temporary = temporary_path(&store.share_path(0), [9; 24]).unwrap();
        tokio::fs::write(&temporary, &tombstone_record).await.unwrap();
        let restarted = ShareStore::new(directory.path(), PartyId(1), &[1; 32]).unwrap();
        assert!(restarted.load(0, committee_digest).await.is_ok());

        // Model the post-rename state. A fresh process authenticates the marker and can neither
        // load nor overwrite the retired share.
        tokio::fs::rename(&temporary, restarted.share_path(0)).await.unwrap();
        let restarted = ShareStore::new(directory.path(), PartyId(1), &[1; 32]).unwrap();
        assert!(matches!(
            restarted.load(0, committee_digest).await,
            Err(StoreError::ShareRetired { epoch: 0, successor_epoch: 1 })
        ));
        assert!(matches!(
            restarted.save(&share, &mut OsRng).await,
            Err(StoreError::ShareRetired { .. })
        ));
    }

    #[tokio::test]
    async fn whole_volume_rollback_is_explicitly_outside_local_erasure_claim() {
        let directory = tempfile::tempdir().unwrap();
        let store = ShareStore::new(directory.path(), PartyId(1), &[1; 32]).unwrap();
        let share = share();
        let committee_digest = share.committee.digest();
        store.save(&share, &mut OsRng).await.unwrap();
        let copied_pre_retirement_record = tokio::fs::read(store.share_path(0)).await.unwrap();
        store.retire_share(retirement(committee_digest)).await.unwrap();

        // A CoW snapshot/backup can restore both the wrapped random DEK and ciphertext while the
        // retained identity seed recreates the wrapping key. Only an external monotonic/KMS
        // erasure boundary can reject this complete-volume rollback after restart.
        tokio::fs::write(store.share_path(0), copied_pre_retirement_record).await.unwrap();
        let rolled_back = ShareStore::new(directory.path(), PartyId(1), &[1; 32]).unwrap();
        assert!(rolled_back.load(0, committee_digest).await.is_ok());
    }

    #[tokio::test]
    async fn restarted_tombstone_claim_authenticates_but_never_remints_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let session = SessionId([0x61; 32]);
        let purpose = b"consolidation/frostlass/intent-digest";
        let store = ProtocolStore::new(directory.path(), PartyId(1), &[0x62; 32]).unwrap();

        let SessionTombstoneClaim::Created(receipt) =
            store.claim_session_tombstone(session, purpose, &mut OsRng).await.unwrap()
        else {
            panic!("the first exact create-new claim must mint one receipt");
        };
        assert_eq!(receipt.session(), session);
        assert_eq!(receipt.purpose_digest(), session_tombstone_purpose_digest(session, purpose));
        drop(receipt);

        // Model an adversarial restart whose in-memory nonce authorization was lost. Even after
        // authenticating the exact same durable purpose, storage exposes no fresh capability.
        let restarted = ProtocolStore::new(directory.path(), PartyId(1), &[0x62; 32]).unwrap();
        assert!(matches!(
            restarted.claim_session_tombstone(session, purpose, &mut OsRng).await.unwrap(),
            SessionTombstoneClaim::Existing
        ));
        assert!(matches!(
            restarted
                .claim_session_tombstone(session, b"different-intent", &mut OsRng)
                .await,
            Err(StoreError::TombstoneConflict(found)) if found == session
        ));
    }

    #[tokio::test]
    async fn sweep_signing_high_water_is_monotonic_and_never_remints_a_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let identity_seed = [0x63; 32];
        let wallet = DepositWalletId([0x64; 32]);
        let sweep = SweepId([0x65; 32]);
        let first_session = derive_sweep_signing_session(wallet, sweep, 1).unwrap();
        let first_intent = [0x66; 32];
        let first_purpose = b"consolidation/frostlass/wallet-sweep/attempt-1";
        let store = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();

        let SweepSigningHighWaterClaim::Advanced(receipt) = store
            .claim_sweep_signing_high_water(
                wallet,
                sweep,
                1,
                first_session,
                first_intent,
                first_purpose,
                &mut OsRng,
            )
            .await
            .unwrap()
        else {
            panic!("the first family attempt must mint one receipt");
        };
        let first = receipt.record();
        assert_eq!(first.wallet(), wallet);
        assert_eq!(first.sweep(), sweep);
        assert_eq!(first.attempt(), 1);
        assert_eq!(first.session(), first_session);
        assert_eq!(first.intent_digest(), first_intent);
        assert_eq!(
            first.tombstone_purpose_digest(),
            session_tombstone_purpose_digest(first_session, first_purpose)
        );
        drop(receipt);

        // A restart may authenticate the exact durable head, but it cannot recreate the one-use
        // authority which lets a FROST machine mint nonces.
        let restarted = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert!(matches!(
            restarted
                .claim_sweep_signing_high_water(
                    wallet,
                    sweep,
                    1,
                    first_session,
                    first_intent,
                    first_purpose,
                    &mut OsRng,
                )
                .await
                .unwrap(),
            SweepSigningHighWaterClaim::Existing
        ));
        assert!(matches!(
            restarted
                .claim_sweep_signing_high_water(
                    wallet,
                    sweep,
                    1,
                    first_session,
                    [0x67; 32],
                    first_purpose,
                    &mut OsRng,
                )
                .await,
            Err(StoreError::SweepSigningHighWaterConflict)
        ));

        let second_session = derive_sweep_signing_session(wallet, sweep, 2).unwrap();
        assert!(matches!(
            restarted
                .claim_sweep_signing_high_water(
                    wallet,
                    sweep,
                    2,
                    second_session,
                    [0x68; 32],
                    b"consolidation/frostlass/wallet-sweep/attempt-2",
                    &mut OsRng,
                )
                .await
                .unwrap(),
            SweepSigningHighWaterClaim::Advanced(_)
        ));
        assert!(matches!(
            restarted
                .claim_sweep_signing_high_water(
                    wallet,
                    sweep,
                    1,
                    first_session,
                    first_intent,
                    first_purpose,
                    &mut OsRng,
                )
                .await,
            Err(StoreError::SweepSigningHighWaterRollback { stored: 2, attempted: 1 })
        ));

        // In-process deletion is fail-closed after the authenticated head has been observed.
        tokio::fs::remove_file(restarted.sweep_signing_high_water_path(wallet, sweep))
            .await
            .unwrap();
        assert!(matches!(
            restarted
                .claim_sweep_signing_high_water(
                    wallet,
                    sweep,
                    3,
                    derive_sweep_signing_session(wallet, sweep, 3).unwrap(),
                    [0x69; 32],
                    b"consolidation/frostlass/wallet-sweep/attempt-3",
                    &mut OsRng,
                )
                .await,
            Err(StoreError::SweepSigningHighWaterDisappeared)
        ));

        // Model the exact two-file crash window: the family fence reached stable storage, while
        // the process died before it could create the session tombstone or any FROST state.
        let crash_wallet = DepositWalletId([0x6A; 32]);
        let crash_sweep = SweepId([0x6B; 32]);
        let crash_session = derive_sweep_signing_session(crash_wallet, crash_sweep, 1).unwrap();
        let crash_intent = [0x6C; 32];
        let crash_purpose = b"consolidation/frostlass/crash-before-session-tombstone";
        let pre_crash = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert!(matches!(
            pre_crash
                .claim_sweep_signing_high_water(
                    crash_wallet,
                    crash_sweep,
                    1,
                    crash_session,
                    crash_intent,
                    crash_purpose,
                    &mut OsRng,
                )
                .await
                .unwrap(),
            SweepSigningHighWaterClaim::Advanced(_)
        ));
        assert!(
            !tokio::fs::try_exists(pre_crash.session_tombstone_path(crash_session)).await.unwrap()
        );
        drop(pre_crash);

        let crash_replay =
            ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert!(matches!(
            crash_replay
                .claim_sweep_signing_nonce_boundary(
                    crash_wallet,
                    crash_sweep,
                    1,
                    crash_session,
                    crash_intent,
                    crash_purpose,
                    &mut OsRng,
                )
                .await
                .unwrap(),
            SweepSigningNonceClaim::Burned
        ));
        assert_eq!(
            crash_replay.load_session_tombstone(crash_session).await.unwrap().purpose(),
            crash_purpose
        );

        let successor_session = derive_sweep_signing_session(crash_wallet, crash_sweep, 2).unwrap();
        let SweepSigningNonceClaim::Fresh { family, session } = crash_replay
            .claim_sweep_signing_nonce_boundary(
                crash_wallet,
                crash_sweep,
                2,
                successor_session,
                [0x6D; 32],
                b"consolidation/frostlass/successor-attempt",
                &mut OsRng,
            )
            .await
            .unwrap()
        else {
            panic!("a fresh successor attempt must cross both persistent fences");
        };
        assert_eq!(family.record().attempt(), 2);
        assert!(matches!(session, SessionTombstoneClaim::Created(_)));
    }

    #[tokio::test]
    async fn proactive_refresh_schedule_round_trips_replaces_and_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let network_id = [0x81; 32];
        let identity_seed = [0x82; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();

        assert!(store.load_proactive_refresh_schedule(network_id).await.unwrap().is_none());

        let first = b"canonical-schedule/epoch-4/deadline-100";
        store.save_proactive_refresh_schedule(network_id, first, &mut OsRng).await.unwrap();
        assert_eq!(
            store.load_proactive_refresh_schedule(network_id).await.unwrap().unwrap().as_bytes(),
            first
        );

        let replacement = b"canonical-schedule/epoch-5/deadline-200";
        store.save_proactive_refresh_schedule(network_id, replacement, &mut OsRng).await.unwrap();

        let restarted = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert_eq!(
            restarted
                .load_proactive_refresh_schedule(network_id)
                .await
                .unwrap()
                .unwrap()
                .as_bytes(),
            replacement
        );
        assert!(matches!(
            restarted.load_proactive_refresh_schedule([0x83; 32]).await,
            Err(StoreError::WrongContext)
        ));
    }

    #[tokio::test]
    async fn proactive_refresh_schedule_rejects_tamper_and_non_exact_record_encoding() {
        let directory = tempfile::tempdir().unwrap();
        let network_id = [0x84; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(1), &[0x85; 32]).unwrap();
        store
            .save_proactive_refresh_schedule(network_id, b"authenticated schedule", &mut OsRng)
            .await
            .unwrap();

        let path = store.proactive_refresh_schedule_path();
        let canonical = tokio::fs::read(&path).await.unwrap();
        let mut tampered = canonical.clone();
        *tampered.last_mut().unwrap() ^= 1;
        tokio::fs::write(&path, tampered).await.unwrap();
        assert!(matches!(
            store.load_proactive_refresh_schedule(network_id).await,
            Err(StoreError::Authentication)
        ));

        let mut trailing = canonical;
        trailing.push(0);
        tokio::fs::write(&path, trailing).await.unwrap();
        assert!(matches!(
            store.load_proactive_refresh_schedule(network_id).await,
            Err(StoreError::TrailingBytes { kind: "sealed protocol record", trailing: 1 })
        ));
    }

    #[tokio::test]
    async fn proactive_refresh_schedule_enforces_canonical_size_before_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let network_id = [0x86; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(1), &[0x87; 32]).unwrap();
        let maximum = vec![0x88; MAX_REFRESH_SCHEDULE_BYTES];
        store.save_proactive_refresh_schedule(network_id, &maximum, &mut OsRng).await.unwrap();
        assert_eq!(
            store.load_proactive_refresh_schedule(network_id).await.unwrap().unwrap().as_bytes(),
            maximum
        );

        let oversized = vec![0x89; MAX_REFRESH_SCHEDULE_BYTES + 1];
        assert!(matches!(
            store
                .save_proactive_refresh_schedule(network_id, &oversized, &mut OsRng)
                .await,
            Err(StoreError::BlobTooLarge {
                kind: "proactive refresh schedule",
                actual,
                maximum
            }) if actual == MAX_REFRESH_SCHEDULE_BYTES + 1
                && maximum == MAX_REFRESH_SCHEDULE_BYTES
        ));
        assert_eq!(
            store.load_proactive_refresh_schedule(network_id).await.unwrap().unwrap().as_bytes(),
            maximum,
            "an oversized update must not replace the last authenticated deadline"
        );
    }

    #[tokio::test]
    async fn deposit_state_transfer_intents_create_replace_clear_restart_and_exact_retry() {
        let directory = tempfile::tempdir().unwrap();
        let identity_seed = [0x31; 32];
        let network_id = [0x32; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert!(store.load_deposit_state_transfer_intents(network_id).await.unwrap().is_none());

        let empty = store
            .save_deposit_state_transfer_intents(network_id, None, b"", &mut OsRng)
            .await
            .unwrap();
        assert_eq!(empty.revision, 0);
        assert_eq!(empty.previous_snapshot_hash, [0_u8; 32]);
        assert_eq!(
            store
                .save_deposit_state_transfer_intents(network_id, None, b"", &mut OsRng)
                .await
                .unwrap(),
            empty,
            "an uncertain revision-zero response must be exactly retryable"
        );

        let populated_state = b"recipient=2/request=deterministic/scope=export-seal";
        let populated = store
            .save_deposit_state_transfer_intents(
                network_id,
                Some(empty),
                populated_state,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert_eq!(populated.revision, 1);
        assert_eq!(populated.previous_snapshot_hash, empty.snapshot_hash);
        assert_eq!(
            store
                .save_deposit_state_transfer_intents(
                    network_id,
                    Some(empty),
                    populated_state,
                    &mut OsRng,
                )
                .await
                .unwrap(),
            populated,
            "an uncertain successor response must return the authenticated successor"
        );

        let cleared = store
            .save_deposit_state_transfer_intents(network_id, Some(populated), b"", &mut OsRng)
            .await
            .unwrap();
        assert_eq!(cleared.revision, 2);
        assert_eq!(cleared.previous_snapshot_hash, populated.snapshot_hash);
        assert!(
            tokio::fs::symlink_metadata(store.deposit_state_transfer_intents_path())
                .await
                .unwrap()
                .is_file(),
            "clearing intents must persist an empty head rather than delete the rollback fence"
        );

        let restarted = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let loaded =
            restarted.load_deposit_state_transfer_intents(network_id).await.unwrap().unwrap();
        assert_eq!(loaded.metadata, cleared);
        assert!(loaded.state.is_empty());
    }

    #[tokio::test]
    async fn deposit_state_transfer_intents_enforce_network_and_plaintext_bounds() {
        let directory = tempfile::tempdir().unwrap();
        let network_id = [0x33; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(1), &[0x34; 32]).unwrap();
        assert!(matches!(
            store.save_deposit_state_transfer_intents([0_u8; 32], None, b"", &mut OsRng).await,
            Err(StoreError::InvalidDepositStateTransferIntentsNetwork)
        ));
        assert!(matches!(
            store.load_deposit_state_transfer_intents([0_u8; 32]).await,
            Err(StoreError::InvalidDepositStateTransferIntentsNetwork)
        ));

        let maximum = vec![0x35; MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES];
        let head = store
            .save_deposit_state_transfer_intents(network_id, None, &maximum, &mut OsRng)
            .await
            .unwrap();
        let oversized = vec![0x36; MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES + 1];
        assert!(matches!(
            store
                .save_deposit_state_transfer_intents(
                    network_id,
                    Some(head),
                    &oversized,
                    &mut OsRng,
                )
                .await,
            Err(StoreError::BlobTooLarge {
                kind: "deposit state-transfer intent state",
                actual,
                maximum: MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES,
            }) if actual == MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES + 1
        ));
        assert_eq!(
            store
                .load_deposit_state_transfer_intents(network_id)
                .await
                .unwrap()
                .unwrap()
                .state
                .as_bytes(),
            maximum,
            "an oversized successor must not replace the authenticated head"
        );
    }

    #[tokio::test]
    async fn deposit_state_transfer_intents_reject_forks_wrong_context_and_wrong_key() {
        let directory = tempfile::tempdir().unwrap();
        let identity_seed = [0x37; 32];
        let network_id = [0x38; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(2), &identity_seed).unwrap();
        let first = store
            .save_deposit_state_transfer_intents(network_id, None, b"first", &mut OsRng)
            .await
            .unwrap();
        let second = store
            .save_deposit_state_transfer_intents(network_id, Some(first), b"second", &mut OsRng)
            .await
            .unwrap();

        assert!(matches!(
            store
                .save_deposit_state_transfer_intents(
                    network_id,
                    Some(first),
                    b"competing-second",
                    &mut OsRng,
                )
                .await,
            Err(StoreError::DepositStateTransferIntentsRevisionConflict {
                network_id: found,
                revision: 1,
            }) if found == network_id
        ));
        let forged = DepositStateTransferIntentsMetadata { snapshot_hash: [0x39; 32], ..second };
        assert!(matches!(
            store
                .save_deposit_state_transfer_intents(
                    network_id,
                    Some(forged),
                    b"third",
                    &mut OsRng,
                )
                .await,
            Err(StoreError::DepositStateTransferIntentsForkDetected {
                network_id: found,
                revision: 1,
            }) if found == network_id
        ));
        assert_eq!(
            store
                .load_deposit_state_transfer_intents(network_id)
                .await
                .unwrap()
                .unwrap()
                .state
                .as_bytes(),
            b"second"
        );

        assert!(matches!(
            store.load_deposit_state_transfer_intents([0x3A; 32]).await,
            Err(StoreError::WrongContext)
        ));
        let wrong_key_store =
            ProtocolStore::new(directory.path(), PartyId(2), &[0x3B; 32]).unwrap();
        assert!(matches!(
            wrong_key_store.load_deposit_state_transfer_intents(network_id).await,
            Err(StoreError::Authentication)
        ));
    }

    #[tokio::test]
    async fn deposit_state_transfer_intents_detect_rollback_and_disappearance_in_process() {
        let directory = tempfile::tempdir().unwrap();
        let network_id = [0x3C; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(3), &[0x3D; 32]).unwrap();
        let first = store
            .save_deposit_state_transfer_intents(network_id, None, b"first", &mut OsRng)
            .await
            .unwrap();
        let path = store.deposit_state_transfer_intents_path();
        let first_record = tokio::fs::read(&path).await.unwrap();
        let second = store
            .save_deposit_state_transfer_intents(network_id, Some(first), b"second", &mut OsRng)
            .await
            .unwrap();
        let second_record = tokio::fs::read(&path).await.unwrap();

        tokio::fs::write(&path, &first_record).await.unwrap();
        assert!(matches!(
            store.load_deposit_state_transfer_intents(network_id).await,
            Err(StoreError::DepositStateTransferIntentsRollbackDetected {
                network_id: found,
                highest_seen: 1,
                found: 0,
            }) if found == network_id
        ));

        tokio::fs::write(&path, &second_record).await.unwrap();
        assert_eq!(
            store.load_deposit_state_transfer_intents(network_id).await.unwrap().unwrap().metadata,
            second
        );
        tokio::fs::remove_file(&path).await.unwrap();
        assert!(matches!(
            store.load_deposit_state_transfer_intents(network_id).await,
            Err(StoreError::DepositStateTransferIntentsDisappeared {
                network_id: found,
                highest_seen: 1,
            }) if found == network_id
        ));
    }

    #[tokio::test]
    async fn deposit_state_transfer_intents_reject_tampered_and_noncanonical_sealed_records() {
        let directory = tempfile::tempdir().unwrap();
        let network_id = [0x3E; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(4), &[0x3F; 32]).unwrap();
        store
            .save_deposit_state_transfer_intents(network_id, None, b"intent", &mut OsRng)
            .await
            .unwrap();
        let path = store.deposit_state_transfer_intents_path();
        let original = tokio::fs::read(&path).await.unwrap();

        let mut tampered = original.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        tokio::fs::write(&path, tampered).await.unwrap();
        assert!(matches!(
            store.load_deposit_state_transfer_intents(network_id).await,
            Err(StoreError::Authentication)
                | Err(StoreError::NonCanonicalEncoding { kind: "sealed protocol record" })
        ));

        let mut trailing = original;
        trailing.push(0);
        tokio::fs::write(&path, trailing).await.unwrap();
        assert!(matches!(
            store.load_deposit_state_transfer_intents(network_id).await,
            Err(StoreError::TrailingBytes { kind: "sealed protocol record", trailing: 1 })
        ));
    }

    #[test]
    fn deposit_state_transfer_intents_inner_snapshot_is_canonical_bounded_and_hash_chained() {
        let party = PartyId(5);
        let network_id = [0x40; 32];
        let encoded =
            encode_deposit_state_transfer_intents_snapshot(party, network_id, 0, [0; 32], b"")
                .unwrap();
        let (metadata, state) =
            decode_deposit_state_transfer_intents_snapshot(party, network_id, &encoded).unwrap();
        assert_eq!(metadata.revision, 0);
        assert!(state.is_empty());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_deposit_state_transfer_intents_snapshot(party, network_id, &trailing),
            Err(StoreError::NonCanonicalEncoding {
                kind: "deposit state-transfer intent snapshot",
            })
        ));

        let mut wrong_version = encoded.clone();
        wrong_version[..2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(matches!(
            decode_deposit_state_transfer_intents_snapshot(party, network_id, &wrong_version,),
            Err(StoreError::WrongContext)
        ));

        let mut oversized_claim = encoded.clone();
        oversized_claim[74..82].copy_from_slice(
            &u64::try_from(MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES + 1).unwrap().to_le_bytes(),
        );
        assert!(matches!(
            decode_deposit_state_transfer_intents_snapshot(
                party,
                network_id,
                &oversized_claim,
            ),
            Err(StoreError::BlobTooLarge {
                kind: "deposit state-transfer intent state",
                actual,
                maximum: MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES,
            }) if actual == MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES + 1
        ));

        let mut invalid_chain = encoded;
        let previous = [0x41; 32];
        invalid_chain[10..42].copy_from_slice(&previous);
        let hash =
            deposit_state_transfer_intents_snapshot_hash(party, network_id, 0, previous, b"");
        invalid_chain[42..74].copy_from_slice(&hash);
        assert!(matches!(
            decode_deposit_state_transfer_intents_snapshot(
                party,
                network_id,
                &invalid_chain,
            ),
            Err(StoreError::DepositStateTransferIntentsHashChainMismatch {
                network_id: found,
                revision: 0,
            }) if found == network_id
        ));

        assert!(matches!(
            encode_deposit_state_transfer_intents_snapshot(
                party,
                network_id,
                1,
                [0; 32],
                b"intent",
            ),
            Err(StoreError::DepositStateTransferIntentsHashChainMismatch {
                network_id: found,
                revision: 1,
            }) if found == network_id
        ));
        let oversized = vec![0x42; MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES + 1];
        assert!(matches!(
            encode_deposit_state_transfer_intents_snapshot(
                party,
                network_id,
                0,
                [0; 32],
                &oversized,
            ),
            Err(StoreError::BlobTooLarge {
                kind: "deposit state-transfer intent state",
                actual,
                maximum: MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES,
            }) if actual == MAX_DEPOSIT_STATE_TRANSFER_INTENTS_BYTES + 1
        ));
    }

    #[tokio::test]
    async fn deposit_sync_spool_head_create_successor_restart_and_exact_retry_are_durable() {
        let directory = tempfile::tempdir().unwrap();
        let identity_seed = [0x8A; 32];
        let key = DepositSyncSpoolHeadKey {
            network_id: [0x8B; 32],
            wallet_id: DepositWalletId([0x8C; 32]),
        };
        let store = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert!(store.load_deposit_sync_spool_head(key).await.unwrap().is_none());

        let first_state = b"deposit-sync-spool-head/revision-0";
        let first =
            store.save_deposit_sync_spool_head(key, None, first_state, &mut OsRng).await.unwrap();
        assert_eq!(first.revision, 0);
        assert_eq!(first.previous_snapshot_hash, [0_u8; 32]);
        assert_eq!(
            store.save_deposit_sync_spool_head(key, None, first_state, &mut OsRng).await.unwrap(),
            first,
            "an uncertain revision-zero response must be exactly retryable"
        );

        let second_state = b"deposit-sync-spool-head/revision-1";
        let second = store
            .save_deposit_sync_spool_head(key, Some(first), second_state, &mut OsRng)
            .await
            .unwrap();
        assert_eq!(second.revision, 1);
        assert_eq!(second.previous_snapshot_hash, first.snapshot_hash);
        assert_eq!(
            store
                .save_deposit_sync_spool_head(key, Some(first), second_state, &mut OsRng)
                .await
                .unwrap(),
            second,
            "an uncertain successor response must authenticate and return the durable successor"
        );

        let restarted = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let loaded = restarted.load_deposit_sync_spool_head(key).await.unwrap().unwrap();
        assert_eq!(loaded.metadata, second);
        assert_eq!(loaded.state.as_bytes(), second_state);
    }

    #[tokio::test]
    async fn deposit_sync_spool_head_rejects_oversized_state_without_creating_a_record() {
        let directory = tempfile::tempdir().unwrap();
        let key = DepositSyncSpoolHeadKey {
            network_id: [0x8D; 32],
            wallet_id: DepositWalletId([0x8E; 32]),
        };
        let store = ProtocolStore::new(directory.path(), PartyId(1), &[0x8C; 32]).unwrap();
        let oversized = vec![0x8F; MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES + 1];

        assert!(matches!(
            store
                .save_deposit_sync_spool_head(key, None, &oversized, &mut OsRng)
                .await,
            Err(StoreError::BlobTooLarge {
                kind: "deposit sync spool head state",
                actual,
                maximum: MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES,
            }) if actual == MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES + 1
        ));
        assert!(
            store.load_deposit_sync_spool_head(key).await.unwrap().is_none(),
            "an oversized candidate must not create a spool-head record"
        );
    }

    #[tokio::test]
    async fn deposit_sync_spool_head_rejects_successor_forks_and_wrong_storage_key() {
        let directory = tempfile::tempdir().unwrap();
        let identity_seed = [0x8D; 32];
        let key = DepositSyncSpoolHeadKey {
            network_id: [0x8E; 32],
            wallet_id: DepositWalletId([0x8F; 32]),
        };
        let store = ProtocolStore::new(directory.path(), PartyId(2), &identity_seed).unwrap();
        let first =
            store.save_deposit_sync_spool_head(key, None, b"first", &mut OsRng).await.unwrap();
        let second = store
            .save_deposit_sync_spool_head(key, Some(first), b"second", &mut OsRng)
            .await
            .unwrap();

        assert!(matches!(
            store
                .save_deposit_sync_spool_head(key, Some(first), b"competing-second", &mut OsRng)
                .await,
            Err(StoreError::DepositSyncSpoolHeadRevisionConflict {
                key: found_key,
                revision: 1
            }) if found_key == key
        ));
        let forged = DepositSyncSpoolHeadMetadata { snapshot_hash: [0x90; 32], ..second };
        assert!(matches!(
            store
                .save_deposit_sync_spool_head(key, Some(forged), b"third", &mut OsRng)
                .await,
            Err(StoreError::DepositSyncSpoolHeadForkDetected {
                key: found_key,
                revision: 1
            }) if found_key == key
        ));
        assert_eq!(
            store.load_deposit_sync_spool_head(key).await.unwrap().unwrap().state.as_bytes(),
            b"second",
            "a rejected fork must not replace the durable head"
        );

        let wrong_context_key =
            DepositSyncSpoolHeadKey { network_id: [0x90; 32], wallet_id: key.wallet_id };
        tokio::fs::copy(
            store.deposit_sync_spool_head_path(key),
            store.deposit_sync_spool_head_path(wrong_context_key),
        )
        .await
        .unwrap();
        assert!(matches!(
            store.load_deposit_sync_spool_head(wrong_context_key).await,
            Err(StoreError::WrongContext)
        ));

        let wrong_key_store =
            ProtocolStore::new(directory.path(), PartyId(2), &[0x91; 32]).unwrap();
        assert!(matches!(
            wrong_key_store.load_deposit_sync_spool_head(key).await,
            Err(StoreError::Authentication)
        ));
    }

    #[tokio::test]
    async fn deposit_sync_spool_head_destroy_requires_exact_head_and_bytes_then_resets_chain() {
        let directory = tempfile::tempdir().unwrap();
        let key = DepositSyncSpoolHeadKey {
            network_id: [0x92; 32],
            wallet_id: DepositWalletId([0x93; 32]),
        };
        let store = ProtocolStore::new(directory.path(), PartyId(3), &[0x94; 32]).unwrap();
        let state = b"ready-to-delete-spool-head";
        let head = store.save_deposit_sync_spool_head(key, None, state, &mut OsRng).await.unwrap();

        assert!(matches!(
            store.destroy_deposit_sync_spool_head(key, head, b"other-spool-head").await,
            Err(StoreError::DepositSyncSpoolHeadRevisionConflict {
                key: found_key,
                revision: 0
            }) if found_key == key
        ));
        let forged = DepositSyncSpoolHeadMetadata { snapshot_hash: [0x95; 32], ..head };
        assert!(matches!(
            store.destroy_deposit_sync_spool_head(key, forged, state).await,
            Err(StoreError::DepositSyncSpoolHeadForkDetected {
                key: found_key,
                revision: 0
            }) if found_key == key
        ));
        assert!(store.destroy_deposit_sync_spool_head(key, head, state).await.unwrap());
        assert!(!store.destroy_deposit_sync_spool_head(key, head, state).await.unwrap());
        assert!(store.load_deposit_sync_spool_head(key).await.unwrap().is_none());

        let fresh = store
            .save_deposit_sync_spool_head(key, None, b"fresh-spool-head", &mut OsRng)
            .await
            .unwrap();
        assert_eq!(fresh.revision, 0);
        assert_ne!(fresh.snapshot_hash, head.snapshot_hash);
    }

    #[tokio::test]
    async fn key_rotation_round_snapshot_is_monotonic_canonical_and_rollback_fenced() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = rotation_fixture();
        let identity_seed = [0x91; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let initial = KeyRotationRound::new(fixture.context.clone(), PartyId(1)).unwrap();

        let first =
            store.save_key_rotation_round(&fixture.context, 0, &initial, &mut OsRng).await.unwrap();
        assert_eq!(first.revision, 0);
        assert_eq!(first.previous_snapshot_hash, [0_u8; 32]);
        assert_eq!(
            store.save_key_rotation_round(&fixture.context, 0, &initial, &mut OsRng).await.unwrap(),
            first,
            "an uncertain exact CAS response must be safely retryable"
        );
        let first_record = tokio::fs::read(store.key_rotation_round_path(first.key)).await.unwrap();

        let mut advertised = initial.clone();
        let capability = rotation_advertisement_capability(&fixture.target[0]);
        advertised.advertise(&capability, &fixture.receiver_keys).unwrap();

        // Model process termination after a complete revision-one replacement was fsynced under
        // the canonical temporary-file name but before its atomic rename. The candidate is a
        // fully authenticated key-rotation record, not arbitrary placeholder bytes.
        let pending_plaintext = encode_key_rotation_snapshot(
            PartyId(1),
            first.key,
            1,
            first.snapshot_hash,
            &advertised.encode().unwrap(),
        )
        .unwrap();
        let pending_context = ProtocolRecordContext::KeyRotationRound {
            target_epoch: first.key.target_epoch,
            context_digest: first.key.context_digest,
        };
        let pending = store
            .seal_protocol_record(
                pending_context.clone(),
                &pending_plaintext,
                MAX_KEY_ROTATION_SNAPSHOT_BYTES,
                &mut OsRng,
            )
            .unwrap();
        let crash_temporary =
            temporary_path(&store.key_rotation_round_path(first.key), pending.nonce).unwrap();
        write_private_file(&crash_temporary, &pending.encoded).await.unwrap();
        let (_, opened_pending) = store
            .open_protocol_record(
                &crash_temporary,
                ExpectedProtocolContext::Exact(pending_context),
                MAX_KEY_ROTATION_SNAPSHOT_BYTES,
            )
            .await
            .unwrap();
        assert_eq!(opened_pending.as_bytes(), pending_plaintext);
        drop(store);

        let store = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let restored_first =
            store.load_key_rotation_round(&fixture.context).await.unwrap().unwrap();
        assert_eq!(restored_first.metadata, first);
        assert_eq!(
            restored_first.round, initial,
            "an unrenamed successor became authoritative after restart"
        );
        assert_eq!(
            store.key_rotation_rounds_bounded(1).await.unwrap(),
            vec![first.key],
            "the canonical crash temporary changed startup enumeration"
        );
        assert!(
            tokio::fs::try_exists(&crash_temporary).await.unwrap(),
            "restart unexpectedly treated an unrenamed replacement as committed"
        );

        let second = store
            .save_key_rotation_round(&fixture.context, 1, &advertised, &mut OsRng)
            .await
            .unwrap();
        assert!(
            !tokio::fs::try_exists(&crash_temporary).await.unwrap(),
            "exact successor replay did not sweep its pre-rename crash temporary"
        );
        assert_eq!(second.previous_snapshot_hash, first.snapshot_hash);
        assert_eq!(
            store.load_key_rotation_round(&fixture.context).await.unwrap().unwrap().round,
            advertised
        );
        assert!(matches!(
            store.save_key_rotation_round(&fixture.context, 1, &initial, &mut OsRng).await,
            Err(StoreError::KeyRotationRevisionConflict { revision: 1, .. })
        ));
        assert!(matches!(
            store.save_key_rotation_round(&fixture.context, 3, &advertised, &mut OsRng).await,
            Err(StoreError::KeyRotationRevisionNotNext { expected: 2, actual: 3, .. })
        ));
        assert_eq!(store.key_rotation_rounds_bounded(1).await.unwrap(), vec![first.key]);
        assert!(matches!(
            store.key_rotation_rounds_bounded(0).await,
            Err(StoreError::ProtocolEntryLimit { kind: "key rotation round", maximum: 0 })
        ));

        let second_record =
            tokio::fs::read(store.key_rotation_round_path(first.key)).await.unwrap();
        tokio::fs::write(store.key_rotation_round_path(first.key), first_record).await.unwrap();
        assert!(matches!(
            store.load_key_rotation_round(&fixture.context).await,
            Err(StoreError::KeyRotationRollbackDetected { highest_seen: 1, found: 0, .. })
        ));
        tokio::fs::write(store.key_rotation_round_path(first.key), second_record).await.unwrap();

        let restarted = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert_eq!(
            restarted.load_key_rotation_round(&fixture.context).await.unwrap().unwrap().metadata,
            second,
            "restart must authenticate the complete hash-chain head"
        );
    }

    #[tokio::test]
    async fn dynamic_epoch_identity_is_encrypted_create_once_and_context_bound() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = rotation_fixture();
        let identity_seed = [0x92; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let secret = fixture.target[0].export_encryption_secret();
        assert!(matches!(
            store.save_epoch_identity_secret(&secret, &mut OsRng).await,
            Err(StoreError::EpochIdentityPolicyConflict { .. })
        ));
        store
            .save_epoch_identity_candidate_secret(&fixture.context, &secret, &mut OsRng)
            .await
            .unwrap();
        store
            .save_epoch_identity_candidate_secret(&fixture.context, &secret, &mut OsRng)
            .await
            .unwrap();

        let loaded = store
            .load_epoch_identity_secret(secret.epoch(), secret.public_key())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded, secret);
        assert_eq!(store.epoch_identities_bounded(1).await.unwrap(), vec![secret.epoch()]);
        assert!(matches!(
            store.epoch_identities_bounded(0).await,
            Err(StoreError::ProtocolEntryLimit { kind: "epoch identity", maximum: 0 })
        ));
        assert!(matches!(
            store.load_epoch_identity_secret(secret.epoch(), [0x93; 32]).await,
            Err(StoreError::EpochIdentityConflict { .. })
        ));

        let sealed = tokio::fs::read(store.epoch_identity_path(secret.epoch())).await.unwrap();
        assert!(
            !sealed.windows(32).any(|window| window == secret.secret_bytes()),
            "the plaintext X25519 secret must never appear in the durable record"
        );
        let rendered = format!("{loaded:?}");
        assert!(!rendered.contains(&hex::encode(secret.secret_bytes())));

        let signing_seed = rotation_signing_seed(PartyId(1));
        let signing_public_key = fixture.target[0].signing_public_key();
        let advertisable = store
            .load_persisted_key_advertisement_identity(
                &secret,
                Some(fixture.context.digest()),
                &signing_seed,
                signing_public_key,
                secret.public_key(),
            )
            .await
            .unwrap();
        assert_eq!(advertisable.identity().party(), PartyId(1));
        assert_eq!(advertisable.identity().encryption_epoch(), secret.epoch());
        assert_eq!(advertisable.identity().signing_public_key(), signing_public_key);
        assert_eq!(advertisable.identity().encryption_public_key(), secret.public_key());
        assert_ne!(advertisable.durable_record_digest(), [0_u8; 32]);
        let first_readback_digest = advertisable.durable_record_digest();
        assert_eq!(
            store
                .load_persisted_key_advertisement_identity(
                    &secret,
                    Some(fixture.context.digest()),
                    &signing_seed,
                    signing_public_key,
                    secret.public_key(),
                )
                .await
                .unwrap()
                .durable_record_digest(),
            first_readback_digest,
            "an exact retry must bind the same canonical durable record"
        );
        assert!(matches!(
            store
                .load_persisted_key_advertisement_identity(
                    &secret,
                    Some(fixture.context.digest()),
                    &[0xEE; 32],
                    signing_public_key,
                    secret.public_key(),
                )
                .await,
            Err(StoreError::InvalidIdentity(IdentityError::WrongSigningPublicKey))
        ));
        assert!(matches!(
            store
                .load_persisted_key_advertisement_identity(
                    &secret,
                    Some(fixture.context.digest()),
                    &signing_seed,
                    signing_public_key,
                    [0xEF; 32],
                )
                .await,
            Err(StoreError::EpochIdentityConflict { .. })
        ));

        let conflicting =
            explicit_test_identity(PartyId(1), secret.epoch(), [0x94; 32], [0xD4; 32])
                .export_encryption_secret();
        assert!(matches!(
            store.save_epoch_identity_secret(&conflicting, &mut OsRng).await,
            Err(StoreError::EpochIdentityConflict { .. })
        ));
        let wrong_party =
            explicit_test_identity(PartyId(2), secret.epoch(), [0x95; 32], [0xD5; 32])
                .export_encryption_secret();
        assert!(matches!(
            store.save_epoch_identity_secret(&wrong_party, &mut OsRng).await,
            Err(StoreError::EpochIdentityConflict { .. })
        ));

        let generated =
            store.load_or_create_epoch_identity_secret(&fixture.context, &mut OsRng).await.unwrap();
        assert_eq!(generated.party(), PartyId(1));
        assert_eq!(
            store.load_or_create_epoch_identity_secret(&fixture.context, &mut OsRng).await.unwrap(),
            generated
        );

        let generated_capability = store
            .load_or_create_epoch_advertisement_identity(
                &fixture.context,
                &signing_seed,
                signing_public_key,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert_eq!(
            generated_capability.identity().encryption_epoch(),
            fixture.context.target_epoch()
        );
        assert_eq!(generated_capability.identity().signing_public_key(), signing_public_key);
        assert_ne!(generated_capability.durable_record_digest(), [0_u8; 32]);
        let generated_public_key = generated_capability.identity().encryption_public_key();
        let generated_digest = generated_capability.durable_record_digest();
        let retried_capability = store
            .load_or_create_epoch_advertisement_identity(
                &fixture.context,
                &signing_seed,
                signing_public_key,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert_eq!(retried_capability.identity().encryption_public_key(), generated_public_key);
        assert_eq!(retried_capability.durable_record_digest(), generated_digest);
    }

    #[tokio::test]
    async fn target_only_joiner_requires_its_exact_selected_fresh_advertisement() {
        let source_epoch = 12;
        let target_epoch = 13;
        let source =
            (1_u16..=4).map(|id| rotation_identity(PartyId(id), source_epoch)).collect::<Vec<_>>();
        let target =
            (1_u16..=5).map(|id| rotation_identity(PartyId(id), target_epoch)).collect::<Vec<_>>();
        let source_committee = rotation_committee(source_epoch, &source);
        let bootstrap = rotation_bootstrap_identity(PartyId(5), target_epoch);
        let mut eligible = source_committee.clone();
        eligible.epoch = target_epoch;
        eligible.members.push(Member {
            id: PartyId(5),
            signing_key: bootstrap.signing_public_key(),
            encryption_key: bootstrap.encryption_public_key(),
        });
        let network = [0x51; 32];
        let receiver_keys = rotation_receiver_key_store(network, &source_committee, &eligible);
        let target_policy = KeyRotationTargetPolicy::new(
            &source_committee,
            1,
            eligible.clone(),
            4,
            1,
            receiver_keys.commitment(),
            10_000,
        )
        .unwrap();
        let context =
            KeyRotationContext::new(network, source_committee, [0x52; 32], 1, target_policy)
                .unwrap();

        let selected_certificate = committed_rotation_rounds_for_advertisers(
            &context,
            &receiver_keys,
            &source,
            &target,
            &[PartyId(1), PartyId(2), PartyId(3), PartyId(5)],
        )[0]
        .certificate()
        .unwrap();
        let selected_target = selected_certificate.verify(&context).unwrap();
        let candidate = target[4].export_encryption_secret();
        assert_eq!(
            selected_target.member(PartyId(5)).unwrap().encryption_key,
            candidate.public_key()
        );
        let selected_directory = tempfile::tempdir().unwrap();
        let selected_store =
            ProtocolStore::new(selected_directory.path(), PartyId(5), &[0x53; 32]).unwrap();
        selected_store
            .save_epoch_identity_candidate_secret(&context, &candidate, &mut OsRng)
            .await
            .unwrap();
        selected_store
            .save_key_rotation_certificate(&context, &selected_certificate, &mut OsRng)
            .await
            .unwrap();
        let selected = selected_store
            .promote_certified_epoch_identity_secret(
                &context,
                &selected_certificate,
                &candidate,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert_eq!(selected, candidate, "a selected joiner retains its fresh candidate");

        let omitted_certificate = committed_rotation_rounds_for_advertisers(
            &context,
            &receiver_keys,
            &source,
            &target,
            &[PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
        )[0]
        .certificate()
        .unwrap();
        let omitted_target = omitted_certificate.verify(&context).unwrap();
        assert!(omitted_target.member(PartyId(5)).is_err());
        let omitted_directory = tempfile::tempdir().unwrap();
        let omitted_store =
            ProtocolStore::new(omitted_directory.path(), PartyId(5), &[0x54; 32]).unwrap();
        omitted_store
            .save_epoch_identity_candidate_secret(&context, &candidate, &mut OsRng)
            .await
            .unwrap();
        omitted_store
            .save_key_rotation_certificate(&context, &omitted_certificate, &mut OsRng)
            .await
            .unwrap();
        assert!(
            omitted_store
                .promote_certified_epoch_identity_secret(
                    &context,
                    &omitted_certificate,
                    &candidate,
                    &mut OsRng,
                )
                .await
                .is_err()
        );
        assert!(
            omitted_store
                .destroy_unselected_epoch_identity_secret(&context, &omitted_certificate)
                .await
                .unwrap(),
            "the certificate must authorize erasure of the omitted candidate"
        );
        assert!(
            !tokio::fs::try_exists(omitted_store.epoch_identity_path(target_epoch)).await.unwrap(),
            "an omitted candidate secret must not survive the terminal certificate"
        );
        let restarted =
            ProtocolStore::new(omitted_directory.path(), PartyId(5), &[0x54; 32]).unwrap();
        assert!(
            !restarted
                .destroy_unselected_epoch_identity_secret(&context, &omitted_certificate)
                .await
                .unwrap(),
            "restart cleanup is idempotent once the omitted secret is absent"
        );
    }

    #[tokio::test]
    async fn source_only_removed_member_retires_without_a_target_identity_record() {
        let source_epoch = 20;
        let target_epoch = 21;
        let source =
            (1_u16..=5).map(|id| rotation_identity(PartyId(id), source_epoch)).collect::<Vec<_>>();
        let target =
            (1_u16..=4).map(|id| rotation_identity(PartyId(id), target_epoch)).collect::<Vec<_>>();
        let source_committee = rotation_committee(source_epoch, &source);
        // The eligible pool must satisfy the desired_n + f floor (4 + 1 = 5), so all five source
        // members remain eligible. Party 5 is simply never advertised and therefore never selected
        // into the certified target of desired_n=4, which is what leaves it without a successor.
        let mut eligible = rotation_committee(target_epoch, &source);
        for (baseline_member, source_member) in
            eligible.members.iter_mut().zip(&source_committee.members)
        {
            baseline_member.encryption_key = source_member.encryption_key;
        }
        let network = [0x61; 32];
        let receiver_keys = rotation_receiver_key_store(network, &source_committee, &eligible);
        let target_policy = KeyRotationTargetPolicy::new(
            &source_committee,
            1,
            eligible.clone(),
            4,
            1,
            receiver_keys.commitment(),
            10_000,
        )
        .unwrap();
        let context =
            KeyRotationContext::new(network, source_committee, [0x62; 32], 1, target_policy)
                .unwrap();
        let certificate = committed_rotation_rounds_for_advertisers(
            &context,
            &receiver_keys,
            &source,
            &target,
            &[PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
        )[0]
        .certificate()
        .unwrap();
        assert!(certificate.verify(&context).unwrap().member(PartyId(5)).is_err());

        let directory = tempfile::tempdir().unwrap();
        let store = ProtocolStore::new(directory.path(), PartyId(5), &[0x63; 32]).unwrap();
        let source_secret = source[4].export_encryption_secret();
        store
            .save_epoch_identity_secret_for_test(
                &source_secret,
                context.source_activation(),
                &mut OsRng,
            )
            .await
            .unwrap();
        store.save_key_rotation_certificate(&context, &certificate, &mut OsRng).await.unwrap();
        let retirement =
            store.retire_epoch_identity_secret(&context, &certificate, &mut OsRng).await.unwrap();
        assert_eq!(retirement.epoch, source_epoch);
        assert_eq!(retirement.successor_epoch, target_epoch);
        assert_eq!(retirement.public_key, source_secret.public_key());
        store.verify_epoch_identity_retirement(retirement, &context, &certificate).unwrap();
        assert_eq!(
            store.retire_epoch_identity_secret(&context, &certificate, &mut OsRng).await.unwrap(),
            retirement
        );
        assert!(matches!(
            store.load_epoch_identity_secret(source_epoch, source_secret.public_key()).await,
            Err(StoreError::EpochIdentityRetired { successor_epoch, .. })
                if successor_epoch == target_epoch
        ));
        assert!(
            !tokio::fs::try_exists(store.epoch_identity_path(target_epoch)).await.unwrap(),
            "a removed source member must not manufacture a target identity record"
        );
    }

    #[tokio::test]
    async fn certified_epoch_identity_promotion_keeps_the_selected_candidate() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = rotation_fixture();
        let certificate = committed_rotation_rounds(&fixture)[0].certificate().unwrap();
        let store = ProtocolStore::new(directory.path(), PartyId(1), &[0xA0; 32]).unwrap();
        let source = fixture.source[0].export_encryption_secret();
        let candidate = fixture.target[0].export_encryption_secret();
        store
            .save_epoch_identity_secret_for_test(
                &source,
                fixture.context.source_activation(),
                &mut OsRng,
            )
            .await
            .unwrap();
        store
            .save_epoch_identity_candidate_secret(&fixture.context, &candidate, &mut OsRng)
            .await
            .unwrap();
        store
            .save_key_rotation_certificate(&fixture.context, &certificate, &mut OsRng)
            .await
            .unwrap();

        let promoted = store
            .promote_certified_epoch_identity_secret(
                &fixture.context,
                &certificate,
                &candidate,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert_eq!(promoted, candidate, "a selected advertisement must keep its exact secret");
        assert!(matches!(
            store
                .load_or_create_epoch_advertisement_identity(
                    &fixture.context,
                    &rotation_signing_seed(PartyId(1)),
                    fixture.target[0].signing_public_key(),
                    &mut OsRng,
                )
                .await,
            Err(StoreError::EpochIdentityCertificationConflict { epoch })
                if epoch == candidate.epoch()
        ));
        assert_eq!(
            store
                .load_epoch_identity_secret(candidate.epoch(), candidate.public_key())
                .await
                .unwrap(),
            Some(candidate.clone())
        );

        let retirement = store
            .retire_epoch_identity_secret(&fixture.context, &certificate, &mut OsRng)
            .await
            .unwrap();
        assert!(matches!(
            store.load_epoch_identity_secret(source.epoch(), source.public_key()).await,
            Err(StoreError::EpochIdentityRetired { .. })
        ));
        assert_eq!(retirement.epoch, source.epoch());
        assert_eq!(
            store
                .promote_certified_epoch_identity_secret(
                    &fixture.context,
                    &certificate,
                    &candidate,
                    &mut OsRng,
                )
                .await
                .unwrap(),
            candidate,
            "an exact retry must not require or resurrect the retired source record"
        );
    }

    #[tokio::test]
    async fn certified_epoch_identity_promotion_repairs_pre_replace_crash_and_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = rotation_fixture();
        let certificate = committed_rotation_rounds(&fixture)[0].certificate().unwrap();
        let party = PartyId(4);
        let identity_seed = [0xA2; 32];
        let source = fixture.source[3].export_encryption_secret();
        let candidate = fixture.target[3].export_encryption_secret();
        let store = ProtocolStore::new(directory.path(), party, &identity_seed).unwrap();
        store
            .save_epoch_identity_secret_for_test(
                &source,
                fixture.context.source_activation(),
                &mut OsRng,
            )
            .await
            .unwrap();
        store
            .save_epoch_identity_candidate_secret(&fixture.context, &candidate, &mut OsRng)
            .await
            .unwrap();
        store
            .save_key_rotation_certificate(&fixture.context, &certificate, &mut OsRng)
            .await
            .unwrap();
        drop(store);

        // A restart which sees the old complete candidate record represents the pre-rename side
        // of an interrupted atomic replacement.
        let restarted = ProtocolStore::new(directory.path(), party, &identity_seed).unwrap();
        let promoted = restarted
            .promote_certified_epoch_identity_secret(
                &fixture.context,
                &certificate,
                &candidate,
                &mut OsRng,
            )
            .await
            .unwrap();
        let certified_bytes =
            tokio::fs::read(restarted.epoch_identity_path(promoted.epoch())).await.unwrap();
        drop(restarted);

        // A second restart with a stale pre-promotion handle sees the encrypted receipt and must
        // return the same key without rewriting the durable record.
        let restarted = ProtocolStore::new(directory.path(), party, &identity_seed).unwrap();
        assert_eq!(
            restarted
                .promote_certified_epoch_identity_secret(
                    &fixture.context,
                    &certificate,
                    &candidate,
                    &mut OsRng,
                )
                .await
                .unwrap(),
            promoted
        );
        assert_eq!(
            tokio::fs::read(restarted.epoch_identity_path(promoted.epoch())).await.unwrap(),
            certified_bytes,
            "an exact retry must not reseal or mutate an already-certified target key"
        );
    }

    #[tokio::test]
    async fn certified_epoch_identity_promotion_rejects_unrelated_and_conflicting_keys() {
        let fixture = rotation_fixture();
        let certificate = committed_rotation_rounds(&fixture)[0].certificate().unwrap();
        let source = fixture.source[0].export_encryption_secret();
        let selected = fixture.target[0].export_encryption_secret();
        let missing_certificate_directory = tempfile::tempdir().unwrap();
        let missing_certificate =
            ProtocolStore::new(missing_certificate_directory.path(), PartyId(1), &[0xA3; 32])
                .unwrap();
        missing_certificate
            .save_epoch_identity_secret_for_test(
                &source,
                fixture.context.source_activation(),
                &mut OsRng,
            )
            .await
            .unwrap();
        missing_certificate
            .save_epoch_identity_candidate_secret(&fixture.context, &selected, &mut OsRng)
            .await
            .unwrap();
        assert!(matches!(
            missing_certificate
                .promote_certified_epoch_identity_secret(
                    &fixture.context,
                    &certificate,
                    &selected,
                    &mut OsRng,
                )
                .await,
            Err(StoreError::KeyRotationCertificateMissing(_))
        ));

        let wrong_source_directory = tempfile::tempdir().unwrap();
        let wrong_source =
            ProtocolStore::new(wrong_source_directory.path(), PartyId(1), &[0xA4; 32]).unwrap();
        let unrelated_source =
            explicit_test_identity(PartyId(1), source.epoch(), [0xA5; 32], [0xD5; 32])
                .export_encryption_secret();
        wrong_source
            .save_epoch_identity_secret_for_test(
                &unrelated_source,
                fixture.context.source_activation(),
                &mut OsRng,
            )
            .await
            .unwrap();
        wrong_source
            .save_epoch_identity_candidate_secret(&fixture.context, &selected, &mut OsRng)
            .await
            .unwrap();
        wrong_source
            .save_key_rotation_certificate(&fixture.context, &certificate, &mut OsRng)
            .await
            .unwrap();
        assert!(matches!(
            wrong_source
                .promote_certified_epoch_identity_secret(
                    &fixture.context,
                    &certificate,
                    &selected,
                    &mut OsRng,
                )
                .await,
            Err(StoreError::EpochIdentityConflict { epoch }) if epoch == source.epoch()
        ));

        let wrong_target_directory = tempfile::tempdir().unwrap();
        let wrong_target =
            ProtocolStore::new(wrong_target_directory.path(), PartyId(1), &[0xA6; 32]).unwrap();
        let unrelated_target =
            explicit_test_identity(PartyId(1), selected.epoch(), [0xA7; 32], [0xD7; 32])
                .export_encryption_secret();
        wrong_target
            .save_epoch_identity_secret_for_test(
                &source,
                fixture.context.source_activation(),
                &mut OsRng,
            )
            .await
            .unwrap();
        wrong_target
            .save_epoch_identity_candidate_secret(&fixture.context, &unrelated_target, &mut OsRng)
            .await
            .unwrap();
        wrong_target
            .save_key_rotation_certificate(&fixture.context, &certificate, &mut OsRng)
            .await
            .unwrap();
        assert!(matches!(
            wrong_target
                .promote_certified_epoch_identity_secret(
                    &fixture.context,
                    &certificate,
                    &unrelated_target,
                    &mut OsRng,
                )
                .await,
            Err(StoreError::EpochIdentityConflict { epoch }) if epoch == selected.epoch()
        ));

        let conflicting_directory = tempfile::tempdir().unwrap();
        let conflicting =
            ProtocolStore::new(conflicting_directory.path(), PartyId(1), &[0xA8; 32]).unwrap();
        conflicting
            .save_epoch_identity_secret_for_test(
                &source,
                fixture.context.source_activation(),
                &mut OsRng,
            )
            .await
            .unwrap();
        conflicting
            .save_epoch_identity_candidate_secret(&fixture.context, &selected, &mut OsRng)
            .await
            .unwrap();
        conflicting
            .save_key_rotation_certificate(&fixture.context, &certificate, &mut OsRng)
            .await
            .unwrap();
        conflicting
            .promote_certified_epoch_identity_secret(
                &fixture.context,
                &certificate,
                &selected,
                &mut OsRng,
            )
            .await
            .unwrap();

        let alternate_base = rotation_fixture();
        let alternate_context = KeyRotationContext::new(
            alternate_base.context.network(),
            alternate_base.context.source().clone(),
            [0x42; 32],
            alternate_base.context.source_fault_bound(),
            alternate_base.context.target_policy().clone(),
        )
        .unwrap();
        let alternate = RotationFixture {
            context: alternate_context,
            receiver_keys: alternate_base.receiver_keys,
            source: alternate_base.source,
            target: alternate_base.target,
        };
        let alternate_certificate = committed_rotation_rounds(&alternate)[0].certificate().unwrap();
        conflicting
            .save_key_rotation_certificate(&alternate.context, &alternate_certificate, &mut OsRng)
            .await
            .unwrap();
        assert!(matches!(
            conflicting
                .promote_certified_epoch_identity_secret(
                    &alternate.context,
                    &alternate_certificate,
                    &selected,
                    &mut OsRng,
                )
                .await,
            Err(StoreError::EpochIdentityPolicyConflict { epoch })
                if epoch == selected.epoch()
        ));
    }

    #[tokio::test]
    async fn equivalent_rotation_witness_subsets_normalize_every_durable_side_effect() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = rotation_fixture();
        let mut rounds = committed_rotation_rounds(&fixture);
        let canonical = rounds.remove(0).certificate().unwrap();
        let consensus = fixture.context.consensus_context().unwrap();
        let value = canonical.commit_certificate().value().clone();
        let view = canonical.commit_certificate().view();
        let canonical_signers = canonical
            .commit_certificate()
            .witnesses()
            .iter()
            .map(|witness| witness.from)
            .collect::<BTreeSet<_>>();
        let alternate_indices: &[usize] =
            if canonical_signers == BTreeSet::from([PartyId(1), PartyId(2), PartyId(3)]) {
                &[1, 2, 3]
            } else {
                &[0, 1, 2]
            };
        let alternate_witnesses = alternate_indices
            .iter()
            .map(|index| {
                sign_consensus_message(
                    &consensus,
                    &fixture.source[*index],
                    ConsensusMessageBody::Precommit(Vote { view, value: value.digest() }),
                )
                .unwrap()
            })
            .collect();
        let alternate_commit =
            CommitCertificate::from_witnesses(&consensus, view, value, alternate_witnesses)
                .unwrap();
        let alternate =
            KeyRotationCertificate::from_commit(&fixture.context, alternate_commit).unwrap();
        assert_ne!(alternate, canonical);
        assert!(alternate.proves_same_decision(&canonical, &fixture.context).unwrap());

        let identity_seed = [0x95; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let mut alternate_round =
            KeyRotationRound::new(fixture.context.clone(), PartyId(1)).unwrap();
        alternate_round
            .handle_wire(
                PartyId(2),
                KeyRotationWire::Certificate(alternate.clone()),
                &fixture.source[0],
                &fixture.receiver_keys,
            )
            .unwrap();
        assert_eq!(alternate_round.certificate(), Some(alternate.clone()));
        store
            .save_key_rotation_round(&fixture.context, 0, &alternate_round, &mut OsRng)
            .await
            .unwrap();

        let source_secret = fixture.source[0].export_encryption_secret();
        let target_secret = fixture.target[0].export_encryption_secret();
        store
            .save_epoch_identity_secret_for_test(
                &source_secret,
                fixture.context.source_activation(),
                &mut OsRng,
            )
            .await
            .unwrap();
        store
            .save_epoch_identity_candidate_secret(&fixture.context, &target_secret, &mut OsRng)
            .await
            .unwrap();
        store
            .save_key_rotation_certificate(&fixture.context, &canonical, &mut OsRng)
            .await
            .unwrap();
        store
            .save_key_rotation_certificate(&fixture.context, &alternate, &mut OsRng)
            .await
            .unwrap();
        assert_eq!(
            store.load_key_rotation_certificate(&fixture.context).await.unwrap(),
            Some(canonical.clone()),
            "semantic retry replaced the node's exact durable witness artifact"
        );

        assert_eq!(
            store
                .promote_certified_epoch_identity_secret(
                    &fixture.context,
                    &alternate,
                    &target_secret,
                    &mut OsRng,
                )
                .await
                .unwrap(),
            target_secret,
            "promotion must derive its receipt from the first durable certificate"
        );
        let retirement = store
            .retire_epoch_identity_secret(&fixture.context, &alternate, &mut OsRng)
            .await
            .unwrap();
        store.verify_epoch_identity_retirement(retirement, &fixture.context, &canonical).unwrap();
        store.retire_key_rotation_round(&fixture.context, &alternate, &mut OsRng).await.unwrap();
        assert!(matches!(
            store.load_key_rotation_round(&fixture.context).await,
            Err(StoreError::KeyRotationRoundRetired(_))
        ));

        let omitted_directory = tempfile::tempdir().unwrap();
        let omitted_store =
            ProtocolStore::new(omitted_directory.path(), PartyId(5), &[0x96; 32]).unwrap();
        let omitted_candidate = rotation_identity(PartyId(5), fixture.context.target_epoch())
            .export_encryption_secret();
        omitted_store
            .save_epoch_identity_candidate_secret(&fixture.context, &omitted_candidate, &mut OsRng)
            .await
            .unwrap();
        omitted_store
            .save_key_rotation_certificate(&fixture.context, &canonical, &mut OsRng)
            .await
            .unwrap();
        assert!(
            omitted_store
                .destroy_unselected_epoch_identity_secret(&fixture.context, &alternate)
                .await
                .unwrap(),
            "unselected cleanup must accept an equivalent witness subset"
        );
        assert!(
            !omitted_store
                .destroy_unselected_epoch_identity_secret(&fixture.context, &alternate)
                .await
                .unwrap()
        );

        let restarted = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert_eq!(
            restarted.load_key_rotation_certificate(&fixture.context).await.unwrap(),
            Some(canonical)
        );
    }

    #[tokio::test]
    async fn rotation_certificate_gates_round_and_epoch_secret_retirement() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = rotation_fixture();
        let mut rounds = committed_rotation_rounds(&fixture);
        let round = rounds.remove(0);
        let certificate = round.certificate().unwrap();
        let identity_seed = [0x96; 32];
        let store = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let metadata =
            store.save_key_rotation_round(&fixture.context, 0, &round, &mut OsRng).await.unwrap();
        let source_secret = fixture.source[0].export_encryption_secret();
        store
            .save_epoch_identity_secret_for_test(
                &source_secret,
                fixture.context.source_activation(),
                &mut OsRng,
            )
            .await
            .unwrap();
        let active_identity_record =
            tokio::fs::read(store.epoch_identity_path(source_secret.epoch())).await.unwrap();

        assert!(matches!(
            store.retire_key_rotation_round(&fixture.context, &certificate, &mut OsRng).await,
            Err(StoreError::KeyRotationCertificateMissing(_))
        ));
        assert!(matches!(
            store.retire_epoch_identity_secret(&fixture.context, &certificate, &mut OsRng).await,
            Err(StoreError::KeyRotationCertificateMissing(_))
        ));
        store
            .save_key_rotation_certificate(&fixture.context, &certificate, &mut OsRng)
            .await
            .unwrap();
        store
            .save_key_rotation_certificate(&fixture.context, &certificate, &mut OsRng)
            .await
            .unwrap();
        assert_eq!(
            store.load_key_rotation_certificate(&fixture.context).await.unwrap(),
            Some(certificate.clone())
        );
        assert_eq!(store.key_rotation_certificates_bounded(1).await.unwrap(), vec![metadata.key]);

        // Source retirement requires the durable certified successor identity: persist and
        // promote the advertised target candidate exactly as the live handoff does.
        let target_secret = fixture.target[0].export_encryption_secret();
        store
            .save_epoch_identity_candidate_secret(&fixture.context, &target_secret, &mut OsRng)
            .await
            .unwrap();
        store
            .promote_certified_epoch_identity_secret(
                &fixture.context,
                &certificate,
                &target_secret,
                &mut OsRng,
            )
            .await
            .unwrap();

        let retirement = store
            .retire_epoch_identity_secret(&fixture.context, &certificate, &mut OsRng)
            .await
            .unwrap();
        let retired_identity_record =
            tokio::fs::read(store.epoch_identity_path(source_secret.epoch())).await.unwrap();
        tokio::fs::write(store.epoch_identity_path(source_secret.epoch()), &active_identity_record)
            .await
            .unwrap();
        assert!(matches!(
            store
                .load_epoch_identity_secret(source_secret.epoch(), source_secret.public_key())
                .await,
            Err(StoreError::EpochIdentityRollbackDetected { .. })
        ));
        tokio::fs::write(store.epoch_identity_path(source_secret.epoch()), retired_identity_record)
            .await
            .unwrap();
        assert_eq!(retirement.epoch, fixture.context.source().epoch);
        assert_eq!(retirement.successor_epoch, fixture.context.target_epoch());
        assert_eq!(
            store
                .retire_epoch_identity_secret(&fixture.context, &certificate, &mut OsRng)
                .await
                .unwrap(),
            retirement
        );
        assert!(matches!(
            store.load_epoch_identity_secret(retirement.epoch, retirement.public_key).await,
            Err(StoreError::EpochIdentityRetired { .. })
        ));
        assert_eq!(
            store
                .load_epoch_identity_retirement(retirement.epoch, retirement.public_key)
                .await
                .unwrap(),
            Some(retirement)
        );

        store.retire_key_rotation_round(&fixture.context, &certificate, &mut OsRng).await.unwrap();
        store.retire_key_rotation_round(&fixture.context, &certificate, &mut OsRng).await.unwrap();
        assert!(matches!(
            store.load_key_rotation_round(&fixture.context).await,
            Err(StoreError::KeyRotationRoundRetired(_))
        ));
        assert!(matches!(
            store.save_key_rotation_round(&fixture.context, 1, &round, &mut OsRng).await,
            Err(StoreError::KeyRotationRoundRetired(_))
        ));

        let restarted = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert_eq!(
            restarted.load_key_rotation_certificate(&fixture.context).await.unwrap(),
            Some(certificate)
        );
        assert_eq!(
            restarted
                .load_epoch_identity_retirement(retirement.epoch, retirement.public_key)
                .await
                .unwrap(),
            Some(retirement),
            "a fresh process must authenticate the permanent erasure authorization"
        );
    }

    #[tokio::test]
    async fn wallet_artifacts_bind_all_context_and_retry_only_after_exact_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let wallet = WalletId([0x71; 32]);
        let kind = WalletArtifactKind(7);
        let bytes = b"exact immutable deposit certificate";
        let store = WalletArtifactStore::new(directory.path(), PartyId(1), &[0x72; 32]).unwrap();

        let reference = store.create_artifact(wallet, kind, bytes, &mut OsRng).await.unwrap();
        assert_eq!(
            store.create_artifact(wallet, kind, bytes, &mut OsRng).await.unwrap(),
            reference
        );
        assert_eq!(store.load_artifact(reference).await.unwrap().contents.as_bytes(), bytes);
        assert_ne!(
            WalletArtifactRef::for_contents(WalletId([0x73; 32]), kind, bytes).unwrap(),
            reference
        );
        assert_ne!(
            WalletArtifactRef::for_contents(wallet, WalletArtifactKind(8), bytes).unwrap(),
            reference
        );
        assert_ne!(
            WalletArtifactRef::for_contents(wallet, kind, b"exact immutable deposit certificate\0")
                .unwrap(),
            reference
        );

        let wrong_key =
            WalletArtifactStore::new(directory.path(), PartyId(1), &[0x74; 32]).unwrap();
        assert!(matches!(
            wrong_key.load_artifact(reference).await,
            Err(StoreError::Authentication)
        ));

        let path = store.artifact_path(reference);
        let mut sealed = tokio::fs::read(&path).await.unwrap();
        *sealed.last_mut().unwrap() ^= 1;
        tokio::fs::write(path, sealed).await.unwrap();
        assert!(store.create_artifact(wallet, kind, bytes, &mut OsRng).await.is_err());
    }

    async fn install_owned_crash_cut(
        store: &WalletArtifactStore,
        reference: WalletArtifactRef,
        owner: WalletArtifactOwner,
        contents: &[u8],
        cut: usize,
    ) {
        if cut == 0 {
            return;
        }
        let _mutation = store.mutation.lock().await;
        let _namespace = store.lock_artifact_namespace(reference.wallet_id()).await.unwrap();
        store.ensure_artifact_directory(reference.wallet_id(), reference.kind()).await.unwrap();
        let artifact_nonce = [0x81; 24];
        let planned =
            store.encode_owned_artifact(reference, owner, contents, artifact_nonce).unwrap();
        let header = WalletArtifactReservationHeader {
            version: WALLET_ARTIFACT_RESERVATION_VERSION,
            party: store.party,
            reference,
            owner,
            artifact_nonce,
            sealed_len: u64::try_from(planned.len()).unwrap(),
            sealed_digest: wallet_artifact_sealed_bytes_hash(reference, owner, &planned),
        };
        let reservation_nonce = [0x82; 24];
        let reservation = store.seal_artifact_reservation(header, reservation_nonce).unwrap();
        let reservation_bytes = postcard::to_allocvec(&reservation).unwrap();
        let reservation_path = store.artifact_reservation_path(reference);
        let reservation_temporary = temporary_path(&reservation_path, [0x84; 24]).unwrap();
        write_private_file(&reservation_temporary, &reservation_bytes).await.unwrap();
        if cut == 1 {
            return;
        }
        tokio::fs::hard_link(&reservation_temporary, &reservation_path).await.unwrap();
        sync_directory(reservation_path.parent().unwrap()).await.unwrap();
        tokio::fs::remove_file(&reservation_temporary).await.unwrap();
        sync_directory(reservation_path.parent().unwrap()).await.unwrap();
        if cut == 2 {
            return;
        }

        let artifact_path = store.artifact_path(reference);
        let artifact_temporary = temporary_path(&artifact_path, [0x83; 24]).unwrap();
        write_private_file(&artifact_temporary, &planned).await.unwrap();
        if cut == 3 {
            return;
        }
        tokio::fs::hard_link(&artifact_temporary, &artifact_path).await.unwrap();
        sync_directory(artifact_path.parent().unwrap()).await.unwrap();
        if cut == 4 {
            return;
        }
        tokio::fs::remove_file(&artifact_temporary).await.unwrap();
        sync_directory(artifact_path.parent().unwrap()).await.unwrap();
        let raw = store.read_wallet_artifact_bytes(&artifact_path, reference).await.unwrap();
        let artifact = store.open_wallet_artifact_bytes(&raw, reference).unwrap();
        assert_eq!(artifact.contents.as_bytes(), contents);
        assert_eq!(artifact.storage_owner(), Some(owner));
    }

    #[tokio::test]
    async fn owned_artifact_recovery_is_exact_at_every_write_cut() {
        let wallet = WalletId([0x91; 32]);
        let kind = WalletArtifactKind(17);
        let contents = b"journal-owned immutable object";
        let reference = WalletArtifactRef::for_contents(wallet, kind, contents).unwrap();
        let owner = WalletArtifactOwner([0x92; 32]);
        for cut in 0..=5 {
            let directory = tempfile::tempdir().unwrap();
            let store =
                WalletArtifactStore::new(directory.path(), PartyId(1), &[0x93; 32]).unwrap();
            install_owned_crash_cut(&store, reference, owner, contents, cut).await;
            drop(store);

            let restarted =
                WalletArtifactStore::new(directory.path(), PartyId(1), &[0x93; 32]).unwrap();
            assert_eq!(
                restarted.remove_artifact_if_owned(reference, owner).await.unwrap(),
                cut >= 4
            );
            assert!(!restarted.artifact_reservation_path(reference).exists());
            assert!(!restarted.artifact_path(reference).exists());
            assert!(
                !temporary_path(&restarted.artifact_reservation_path(reference), [0x84; 24])
                    .unwrap()
                    .exists()
            );
            assert!(
                !temporary_path(&restarted.artifact_path(reference), [0x83; 24]).unwrap().exists()
            );
        }
    }

    #[tokio::test]
    async fn preexisting_or_foreign_sealed_bytes_are_never_claimed_or_deleted() {
        let directory = tempfile::tempdir().unwrap();
        let wallet = WalletId([0x94; 32]);
        let kind = WalletArtifactKind(18);
        let contents = b"stable pre-existing object";
        let first = WalletArtifactStore::new(directory.path(), PartyId(1), &[0x95; 32]).unwrap();
        let second = WalletArtifactStore::new(directory.path(), PartyId(1), &[0x95; 32]).unwrap();
        let reference = first.create_artifact(wallet, kind, contents, &mut OsRng).await.unwrap();
        let owner = WalletArtifactOwner([0x96; 32]);

        assert_eq!(
            second.create_artifact_owned(owner, wallet, kind, contents, &mut OsRng).await.unwrap(),
            (reference, WalletArtifactOwnership::PreExisting)
        );
        assert!(!second.remove_artifact_if_owned(reference, owner).await.unwrap());
        assert_eq!(first.load_artifact(reference).await.unwrap().contents.as_bytes(), contents);

        // Even a matching content reference with different valid sealed bytes is not owned.
        let active_owner = WalletArtifactOwner([0x97; 32]);
        assert_eq!(
            first
                .create_artifact_owned(active_owner, wallet, kind, contents, &mut OsRng)
                .await
                .unwrap()
                .1,
            WalletArtifactOwnership::PreExisting
        );
        assert!(!first.remove_artifact_if_owned(reference, active_owner).await.unwrap());
        assert!(first.artifact_path(reference).exists());
    }

    #[tokio::test]
    async fn active_owner_blocks_foreign_reads_and_abort_cannot_feed_a_missing_head() {
        let directory = tempfile::tempdir().unwrap();
        let wallet = WalletId([0x98; 32]);
        let kind = WalletArtifactKind(19);
        let contents = b"owned until exact snapshot CAS";
        let owner = WalletArtifactOwner([0x99; 32]);
        let owner_store =
            WalletArtifactStore::new(directory.path(), PartyId(1), &[0x9A; 32]).unwrap();
        let reader_store =
            WalletArtifactStore::new(directory.path(), PartyId(1), &[0x9A; 32]).unwrap();
        let (reference, ownership) = owner_store
            .create_artifact_owned(owner, wallet, kind, contents, &mut OsRng)
            .await
            .unwrap();
        assert_eq!(ownership, WalletArtifactOwnership::Owned);
        assert!(matches!(
            reader_store.load_artifact(reference).await,
            Err(StoreError::WalletArtifactReservationConflict { .. })
        ));
        assert_eq!(
            owner_store.load_artifact_owned(reference, owner).await.unwrap().contents.as_bytes(),
            contents
        );
        assert!(owner_store.remove_artifact_if_owned(reference, owner).await.unwrap());
        assert!(reader_store.load_artifact(reference).await.is_err());
    }

    #[tokio::test]
    async fn independent_store_instances_share_the_namespace_lock() {
        use std::{sync::Arc, time::Duration};

        let directory = tempfile::tempdir().unwrap();
        let wallet = WalletId([0x9B; 32]);
        let kind = WalletArtifactKind(20);
        let contents = b"cross-process lock linearization".to_vec();
        let first =
            Arc::new(WalletArtifactStore::new(directory.path(), PartyId(1), &[0x9C; 32]).unwrap());
        let second =
            Arc::new(WalletArtifactStore::new(directory.path(), PartyId(1), &[0x9C; 32]).unwrap());
        let held = first.lock_artifact_namespace(wallet).await.unwrap();
        let contender = Arc::clone(&second);
        let mut task = tokio::spawn(async move {
            contender.create_artifact(wallet, kind, &contents, &mut OsRng).await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut task).await.is_err(),
            "a distinct store instance bypassed the permanent namespace lock inode"
        );
        drop(held);
        let reference = task.await.unwrap().unwrap();
        assert_eq!(
            first.load_artifact(reference).await.unwrap().contents.as_bytes(),
            b"cross-process lock linearization"
        );
    }
}
