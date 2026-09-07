//! Authenticated, restart-safe endorser progress for deposit prefix support.
//!
//! A prefix-support request can require walking an old archive while the live archive continues
//! to advance. This store gives every authenticated requester one bounded durable slot. The slot
//! binds the exact full request, its attempt digest, and an immutable local archive anchor. Each
//! read-only archive step is journaled as `InFlight` before it begins and replaced atomically by
//! its result afterwards, so a crash can only cause the same bounded step to be replayed.
//!
//! Serialized state is deliberately not authority. Callers must supply the current verified
//! registry target, the transport-authenticated requester, and the independently verified exact
//! terminal checkpoint on every start, continuation, or recovery. In particular,
//! [`VerifiedDepositArchivePrefix`] is never serialized. A terminal included slot retains the
//! pre-terminal cursor and recreates that capability by repeating the final authenticated,
//! read-only archive step.

use std::{
    fmt,
    fs::OpenOptions,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as DeError, SeqAccess, Visitor},
};
use thiserror::Error;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::{
    committee::{CommitteeError, MAX_COMMITTEE_MEMBERS, PartyId},
    deposit_archive::{
        DEPOSIT_ARCHIVE_EVENT_ARTIFACT, DepositArchiveError, DepositArchiveHead,
        DepositArchivePrefixCursor, DepositArchivePrefixStep, DepositArchiveStore,
        MAX_DEPOSIT_ARCHIVE_PREFIX_CURSOR_BYTES, VerifiedDepositArchivePrefix,
    },
    deposit_index_checkpoint::VerifiedDepositIndexCheckpoint,
    deposit_service::AuthenticatedLocalDepositArchiveHead,
    deposit_sync_support::{
        DepositSyncPrefixSupportAttempt, DepositSyncPrefixSupportContinue,
        DepositSyncPrefixSupportStart, DepositSyncSupportError, DepositSyncSupportRequest,
        MAX_DEPOSIT_SYNC_PREFIX_SUPPORT_START_BYTES,
    },
    deposit_sync_wire::DepositSyncContext,
    identity::Identity,
    key_rotation::VerifiedRegistryHandoffTarget,
    storage::{StoreError, WalletArtifactRef, WalletArtifactStore, WalletId},
};

const PREFIX_SCAN_STORE_VERSION: u16 = 1;
const PREFIX_SCAN_DIRECTORY: &str = "deposit-prefix-scan-v1";
const PREFIX_SCAN_DATABASE_FILE: &str = "prefix-scans.redb";
const PREFIX_SCAN_SUBKEY_DOMAIN: &[u8] = b"threshold-monero/deposit-prefix-scan/value-key/v1";
const PREFIX_SCAN_VALUE_KEY_DOMAIN: &str =
    "threshold-monero/deposit-prefix-scan/derived-value-key/v1";
const PREFIX_SCAN_AEAD_DOMAIN: &[u8] = b"threshold-monero/deposit-prefix-scan/slot-aead/v1";
const PREFIX_SCAN_SLOT_LABEL: &[u8] = b"requester-slot";
const PREFIX_SCAN_DATABASE_CACHE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PREFIX_SCAN_SLOT_PLAINTEXT_BYTES: usize = MAX_DEPOSIT_SYNC_PREFIX_SUPPORT_START_BYTES
    + MAX_DEPOSIT_ARCHIVE_PREFIX_CURSOR_BYTES
    + 16 * 1024;
const MAX_PREFIX_SCAN_SEALED_SLOT_BYTES: usize = MAX_PREFIX_SCAN_SLOT_PLAINTEXT_BYTES + 4096;

const PREFIX_SCAN_SLOT_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-prefix-scan-slots-v1");

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DurableScanInput {
    Start,
    Continue { revision: u64 },
}

impl DurableScanInput {
    fn next_revision(self) -> Result<u64, DepositPrefixScanStoreError> {
        match self {
            Self::Start => Ok(1),
            Self::Continue { revision } => {
                revision.checked_add(1).ok_or(DepositPrefixScanStoreError::RevisionExhausted)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DurableScanPhase {
    /// The exact cursor/input pair is persisted before the archive is touched.
    InFlight {
        input: DurableScanInput,
        #[serde(deserialize_with = "deserialize_cursor_bytes")]
        cursor: Vec<u8>,
    },
    /// `last_input` produced this cursor and `next_revision`.
    Pending {
        last_input: DurableScanInput,
        next_revision: u64,
        #[serde(deserialize_with = "deserialize_cursor_bytes")]
        cursor: Vec<u8>,
    },
    /// Re-run `replay_cursor` to reconstruct the deliberately non-serializable proof.
    Included {
        last_input: DurableScanInput,
        #[serde(deserialize_with = "deserialize_cursor_bytes")]
        replay_cursor: Vec<u8>,
        local_terminal_event: WalletArtifactRef,
    },
    /// A bounded terminal tombstone. Only an exact explicit replacement evicts it.
    NotIncluded { last_input: DurableScanInput },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurablePrefixScanSlot {
    version: u16,
    requester: PartyId,
    attempt: DepositSyncPrefixSupportAttempt,
    #[serde(deserialize_with = "deserialize_start_bytes")]
    start: Vec<u8>,
    anchor: DepositArchiveHead,
    phase: DurableScanPhase,
}

impl DurablePrefixScanSlot {
    fn start_message(&self) -> Result<DepositSyncPrefixSupportStart, DepositPrefixScanStoreError> {
        Ok(DepositSyncPrefixSupportStart::from_bytes(&self.start)?)
    }

    fn parsed_request(&self) -> Result<DepositSyncSupportRequest, DepositPrefixScanStoreError> {
        Ok(self.start_message()?.request().clone())
    }

    fn validate(
        &self,
        local_party: PartyId,
        expected_context: DepositSyncContext,
    ) -> Result<(), DepositPrefixScanStoreError> {
        if self.version != PREFIX_SCAN_STORE_VERSION
            || self.requester == PartyId(0)
            || local_party == PartyId(0)
            || expected_context.network() == [0; 32]
        {
            return Err(DepositPrefixScanStoreError::InvalidDurableState);
        }
        self.anchor.validate()?;
        let start = self.start_message()?;
        let request = start.request();
        let attempt = start.attempt()?;
        if attempt != self.attempt
            || request.statement().requester() != self.requester
            || request.statement().context() != expected_context
            || self.anchor.wallet_id() != request.statement().context().wallet()
        {
            return Err(DepositPrefixScanStoreError::InvalidDurableState);
        }
        let target = request.statement().prefix_target()?;
        match &self.phase {
            DurableScanPhase::InFlight { input, cursor } => {
                validate_input(*input)?;
                validate_cursor(cursor, self.anchor, &target)?;
            }
            DurableScanPhase::Pending { last_input, next_revision, cursor } => {
                validate_input(*last_input)?;
                if last_input.next_revision()? != *next_revision {
                    return Err(DepositPrefixScanStoreError::InvalidDurableState);
                }
                validate_cursor(cursor, self.anchor, &target)?;
            }
            DurableScanPhase::Included { last_input, replay_cursor, local_terminal_event } => {
                validate_input(*last_input)?;
                validate_cursor(replay_cursor, self.anchor, &target)?;
                local_terminal_event.validate()?;
                if local_terminal_event.wallet_id() != WalletId(self.anchor.wallet_id().0)
                    || local_terminal_event.kind() != DEPOSIT_ARCHIVE_EVENT_ARTIFACT
                {
                    return Err(DepositPrefixScanStoreError::InvalidDurableState);
                }
            }
            DurableScanPhase::NotIncluded { last_input } => validate_input(*last_input)?,
        }
        Ok(())
    }
}

fn validate_input(input: DurableScanInput) -> Result<(), DepositPrefixScanStoreError> {
    if matches!(input, DurableScanInput::Continue { revision: 0 | u64::MAX }) {
        return Err(DepositPrefixScanStoreError::InvalidDurableState);
    }
    Ok(())
}

fn validate_cursor(
    bytes: &[u8],
    anchor: DepositArchiveHead,
    target: &crate::deposit_archive::DepositArchivePrefixTarget,
) -> Result<(), DepositPrefixScanStoreError> {
    let cursor = DepositArchivePrefixCursor::from_bytes(bytes)?;
    if cursor.anchor() != anchor || cursor.target() != target {
        return Err(DepositPrefixScanStoreError::InvalidDurableState);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SealedPrefixScanSlot {
    version: u16,
    nonce: [u8; 24],
    #[serde(deserialize_with = "deserialize_sealed_slot_bytes")]
    ciphertext: Vec<u8>,
}

struct PrefixScanDatabase {
    database: Database,
    local_party: PartyId,
    context: DepositSyncContext,
    value_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for PrefixScanDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrefixScanDatabase")
            .field("local_party", &self.local_party)
            .field("context_digest", &hex::encode(self.context.digest()))
            .finish_non_exhaustive()
    }
}

/// Authenticated, encrypted one-slot-per-requester prefix scan journal.
pub struct DepositPrefixScanStore {
    inner: Arc<PrefixScanDatabase>,
    mutation: Mutex<()>,
}

impl fmt::Debug for DepositPrefixScanStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DepositPrefixScanStore")
            .field("local_party", &self.inner.local_party)
            .finish_non_exhaustive()
    }
}

/// Non-serializable reconstruction of an included prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDepositPrefixScan {
    attempt: DepositSyncPrefixSupportAttempt,
    request: DepositSyncSupportRequest,
    prefix: VerifiedDepositArchivePrefix,
}

impl VerifiedDepositPrefixScan {
    #[must_use]
    pub const fn attempt(&self) -> DepositSyncPrefixSupportAttempt {
        self.attempt
    }

    #[must_use]
    pub const fn request(&self) -> &DepositSyncSupportRequest {
        &self.request
    }

    #[must_use]
    pub const fn prefix(&self) -> &VerifiedDepositArchivePrefix {
        &self.prefix
    }
}

/// Result of one exact start, continuation, or crash recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DepositPrefixScanOutcome {
    Pending { attempt: DepositSyncPrefixSupportAttempt, next_revision: u64 },
    Included(VerifiedDepositPrefixScan),
    NotIncluded { attempt: DepositSyncPrefixSupportAttempt },
}

impl DepositPrefixScanOutcome {
    #[must_use]
    pub const fn attempt(&self) -> DepositSyncPrefixSupportAttempt {
        match self {
            Self::Pending { attempt, .. }
            | Self::NotIncluded { attempt }
            | Self::Included(VerifiedDepositPrefixScan { attempt, .. }) => *attempt,
        }
    }

    #[must_use]
    pub const fn next_revision(&self) -> Option<u64> {
        match self {
            Self::Pending { next_revision, .. } => Some(*next_revision),
            Self::Included(_) | Self::NotIncluded { .. } => None,
        }
    }
}

#[derive(Clone, Debug)]
enum PreparedScanAction {
    Execute {
        expected: DurablePrefixScanSlot,
        input: DurableScanInput,
        cursor: DepositArchivePrefixCursor,
    },
    Replay(StoredScanOutcome),
}

#[derive(Clone, Debug)]
enum StoredScanOutcome {
    Pending {
        attempt: DepositSyncPrefixSupportAttempt,
        next_revision: u64,
    },
    Included {
        attempt: DepositSyncPrefixSupportAttempt,
        request: DepositSyncSupportRequest,
        replay_cursor: DepositArchivePrefixCursor,
        local_terminal_event: WalletArtifactRef,
    },
    NotIncluded {
        attempt: DepositSyncPrefixSupportAttempt,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartDisposition {
    New,
    Replay,
    Replace,
}

fn classify_start(
    existing: Option<DepositSyncPrefixSupportAttempt>,
    incoming: DepositSyncPrefixSupportAttempt,
    replaces: Option<DepositSyncPrefixSupportAttempt>,
) -> Result<StartDisposition, DepositPrefixScanStoreError> {
    match existing {
        Some(current) if current == incoming => Ok(StartDisposition::Replay),
        Some(current) if replaces == Some(current) => Ok(StartDisposition::Replace),
        Some(_) | None if replaces.is_some() => {
            Err(DepositPrefixScanStoreError::ReplacementMismatch)
        }
        None => Ok(StartDisposition::New),
        Some(_) => Err(DepositPrefixScanStoreError::ReplacementMismatch),
    }
}

fn ensure_new_slot_capacity(count: usize) -> Result<(), DepositPrefixScanStoreError> {
    if count >= MAX_COMMITTEE_MEMBERS {
        return Err(DepositPrefixScanStoreError::RequesterQuota);
    }
    Ok(())
}

impl DepositPrefixScanStore {
    /// Open the current-format database. There are no migrations or legacy paths.
    pub async fn open(
        directory: impl Into<PathBuf>,
        expected_context: DepositSyncContext,
        local_identity: &Identity,
        identity_seed: &[u8; 32],
    ) -> Result<Self, DepositPrefixScanStoreError> {
        let directory = directory.into();
        let local_party = local_identity.party();
        let canonical_context =
            DepositSyncContext::new(expected_context.network(), expected_context.wallet())?;
        if local_party == PartyId(0)
            || canonical_context != expected_context
            || local_identity.signing_public_key() == [0; 32]
            || identity_seed == &[0; 32]
        {
            return Err(DepositPrefixScanStoreError::InvalidIdentity);
        }
        let artifacts = WalletArtifactStore::new(&directory, local_party, identity_seed)?;
        let path = artifacts
            .artifact_root()
            .join(PREFIX_SCAN_DIRECTORY)
            .join(hex::encode(expected_context.digest()))
            .join(PREFIX_SCAN_DATABASE_FILE);
        let root_key = artifacts.derive_subkey(PREFIX_SCAN_SUBKEY_DOMAIN)?;
        let value_key = derive_value_key(&root_key, local_party, expected_context.digest())?;
        let inner = tokio::task::spawn_blocking(move || {
            open_prefix_scan_database(&path, local_party, expected_context, value_key)
        })
        .await
        .map_err(|error| DepositPrefixScanStoreError::BlockingTask(error.to_string()))??;
        Ok(Self { inner: Arc::new(inner), mutation: Mutex::new(()) })
    }

    /// Install or replay an exact full start request and perform at most one bounded archive step.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn process_start(
        &self,
        authenticated_requester: PartyId,
        start: &DepositSyncPrefixSupportStart,
        fixed_local_anchor: &AuthenticatedLocalDepositArchiveHead,
        verified_terminal: &VerifiedDepositIndexCheckpoint,
        active: &VerifiedRegistryHandoffTarget,
        local_identity: &Identity,
        archive: &DepositArchiveStore,
    ) -> Result<DepositPrefixScanOutcome, DepositPrefixScanStoreError> {
        let (attempt, start_bytes) = self.authorize_start(
            authenticated_requester,
            start,
            verified_terminal,
            active,
            local_identity,
        )?;
        let fixed_local_anchor = fixed_local_anchor.head();
        let action = {
            let _mutation = self.mutation.lock().await;
            let inner = Arc::clone(&self.inner);
            tokio::task::spawn_blocking(move || {
                prepare_start_blocking(
                    &inner,
                    authenticated_requester,
                    attempt,
                    start_bytes,
                    fixed_local_anchor,
                )
            })
            .await
            .map_err(|error| DepositPrefixScanStoreError::BlockingTask(error.to_string()))??
        };
        self.complete_action(
            authenticated_requester,
            action,
            verified_terminal,
            active,
            local_identity,
            archive,
        )
        .await
    }

    /// Advance or replay one exact attempt/revision.
    pub async fn process_continue(
        &self,
        authenticated_requester: PartyId,
        continuation: DepositSyncPrefixSupportContinue,
        verified_terminal: &VerifiedDepositIndexCheckpoint,
        active: &VerifiedRegistryHandoffTarget,
        local_identity: &Identity,
        archive: &DepositArchiveStore,
    ) -> Result<DepositPrefixScanOutcome, DepositPrefixScanStoreError> {
        let _ = continuation.to_bytes()?;
        let action = {
            let _mutation = self.mutation.lock().await;
            let slot = self.load_slot(authenticated_requester).await?;
            self.authorize_slot(
                authenticated_requester,
                &slot,
                verified_terminal,
                active,
                local_identity,
            )?;
            let inner = Arc::clone(&self.inner);
            tokio::task::spawn_blocking(move || {
                prepare_continue_blocking(&inner, &slot, continuation)
            })
            .await
            .map_err(|error| DepositPrefixScanStoreError::BlockingTask(error.to_string()))??
        };
        self.complete_action(
            authenticated_requester,
            action,
            verified_terminal,
            active,
            local_identity,
            archive,
        )
        .await
    }

    /// Load the exact durable request needed to authenticate a small continuation.
    ///
    /// This is deliberately not an authority-bearing result. The caller must independently
    /// verify the returned request's complete terminal checkpoint and pass that non-serializable
    /// capability back to [`Self::process_continue`]. The latter re-reads the slot and repeats all
    /// requester, attempt, registry, identity, and terminal-capability checks, closing the race
    /// with an explicit same-requester replacement.
    pub async fn request_for_attempt(
        &self,
        authenticated_requester: PartyId,
        attempt: DepositSyncPrefixSupportAttempt,
        active: &VerifiedRegistryHandoffTarget,
        local_identity: &Identity,
    ) -> Result<DepositSyncSupportRequest, DepositPrefixScanStoreError> {
        let slot = self.load_slot(authenticated_requester).await?;
        slot.validate(self.inner.local_party, self.inner.context)?;
        if slot.attempt != attempt {
            return Err(DepositPrefixScanStoreError::WrongAttempt);
        }
        let request = slot.parsed_request()?;
        if request.statement().requester() != authenticated_requester {
            return Err(DepositPrefixScanStoreError::UnauthenticatedRequester);
        }
        request.statement().validate_against(active)?;
        self.authorize_local_identity(local_identity, active)?;
        active.committee().member(authenticated_requester)?;
        Ok(request)
    }

    /// Recover one exact slot after restart without implicitly advancing a completed pending step.
    ///
    /// `InFlight` repeats its exact read-only archive step. `Pending` returns the same next
    /// revision, and terminal states replay their exact result.
    pub async fn resume(
        &self,
        authenticated_requester: PartyId,
        attempt: DepositSyncPrefixSupportAttempt,
        verified_terminal: &VerifiedDepositIndexCheckpoint,
        active: &VerifiedRegistryHandoffTarget,
        local_identity: &Identity,
        archive: &DepositArchiveStore,
    ) -> Result<DepositPrefixScanOutcome, DepositPrefixScanStoreError> {
        let action = {
            let _mutation = self.mutation.lock().await;
            let slot = self.load_slot(authenticated_requester).await?;
            if slot.attempt != attempt {
                return Err(DepositPrefixScanStoreError::WrongAttempt);
            }
            self.authorize_slot(
                authenticated_requester,
                &slot,
                verified_terminal,
                active,
                local_identity,
            )?;
            action_for_existing(&slot)?
        };
        self.complete_action(
            authenticated_requester,
            action,
            verified_terminal,
            active,
            local_identity,
            archive,
        )
        .await
    }

    /// Remove slots belonging to requesters which are absent from the supplied current committee.
    ///
    /// Same-requester replacement still always requires the incoming `Start.replaces` to name the
    /// exact current attempt. This maintenance hook only prevents a disjoint retired committee
    /// from consuming the next committee's global bounded requester quota.
    pub async fn retire_inactive_requesters(
        &self,
        local_identity: &Identity,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<usize, DepositPrefixScanStoreError> {
        self.authorize_local_identity(local_identity, active)?;
        let current = active.committee().members.iter().map(|member| member.id).collect::<Vec<_>>();
        let _mutation = self.mutation.lock().await;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || retire_inactive_blocking(&inner, &current))
            .await
            .map_err(|error| DepositPrefixScanStoreError::BlockingTask(error.to_string()))?
    }

    fn authorize_start(
        &self,
        authenticated_requester: PartyId,
        start: &DepositSyncPrefixSupportStart,
        verified_terminal: &VerifiedDepositIndexCheckpoint,
        active: &VerifiedRegistryHandoffTarget,
        local_identity: &Identity,
    ) -> Result<(DepositSyncPrefixSupportAttempt, Vec<u8>), DepositPrefixScanStoreError> {
        let start_bytes = start.to_bytes()?;
        self.authorize_request(
            authenticated_requester,
            start.request(),
            verified_terminal,
            active,
            local_identity,
        )?;
        Ok((start.attempt()?, start_bytes))
    }

    fn authorize_slot(
        &self,
        authenticated_requester: PartyId,
        slot: &DurablePrefixScanSlot,
        verified_terminal: &VerifiedDepositIndexCheckpoint,
        active: &VerifiedRegistryHandoffTarget,
        local_identity: &Identity,
    ) -> Result<(), DepositPrefixScanStoreError> {
        slot.validate(self.inner.local_party, self.inner.context)?;
        let request = slot.parsed_request()?;
        self.authorize_request(
            authenticated_requester,
            &request,
            verified_terminal,
            active,
            local_identity,
        )
    }

    fn authorize_request(
        &self,
        authenticated_requester: PartyId,
        request: &DepositSyncSupportRequest,
        verified_terminal: &VerifiedDepositIndexCheckpoint,
        active: &VerifiedRegistryHandoffTarget,
        local_identity: &Identity,
    ) -> Result<(), DepositPrefixScanStoreError> {
        if authenticated_requester == PartyId(0)
            || request.statement().requester() != authenticated_requester
            || request.statement().context() != self.inner.context
        {
            return Err(DepositPrefixScanStoreError::UnauthenticatedRequester);
        }
        request.statement().validate_against(active)?;
        request.verify_terminal_capability(verified_terminal)?;
        self.authorize_local_identity(local_identity, active)?;
        active.committee().member(authenticated_requester)?;
        Ok(())
    }

    fn authorize_local_identity(
        &self,
        local_identity: &Identity,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositPrefixScanStoreError> {
        if local_identity.party() != self.inner.local_party {
            return Err(DepositPrefixScanStoreError::InvalidIdentity);
        }
        let member = active.committee().member(self.inner.local_party)?;
        if local_identity.encryption_epoch() != active.committee().epoch
            || member.signing_key != local_identity.signing_public_key()
            || member.encryption_key != local_identity.encryption_public_key()
        {
            return Err(DepositPrefixScanStoreError::InvalidIdentity);
        }
        Ok(())
    }

    async fn load_slot(
        &self,
        requester: PartyId,
    ) -> Result<DurablePrefixScanSlot, DepositPrefixScanStoreError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            load_slot_blocking(&inner, requester)?
                .ok_or(DepositPrefixScanStoreError::UnknownRequester)
        })
        .await
        .map_err(|error| DepositPrefixScanStoreError::BlockingTask(error.to_string()))?
    }

    async fn complete_action(
        &self,
        authenticated_requester: PartyId,
        action: PreparedScanAction,
        verified_terminal: &VerifiedDepositIndexCheckpoint,
        active: &VerifiedRegistryHandoffTarget,
        local_identity: &Identity,
        archive: &DepositArchiveStore,
    ) -> Result<DepositPrefixScanOutcome, DepositPrefixScanStoreError> {
        match action {
            PreparedScanAction::Replay(stored) => {
                self.reconstruct_outcome(
                    authenticated_requester,
                    stored,
                    verified_terminal,
                    active,
                    local_identity,
                    archive,
                )
                .await
            }
            PreparedScanAction::Execute { expected, input, cursor } => {
                let replay_cursor = cursor.clone();
                let step = archive.verify_anchored_prefix_step(cursor).await?;
                let inner = Arc::clone(&self.inner);
                let stored = tokio::task::spawn_blocking(move || {
                    finalize_step_blocking(&inner, &expected, input, replay_cursor, step)
                })
                .await
                .map_err(|error| DepositPrefixScanStoreError::BlockingTask(error.to_string()))??;
                self.reconstruct_outcome(
                    authenticated_requester,
                    stored,
                    verified_terminal,
                    active,
                    local_identity,
                    archive,
                )
                .await
            }
        }
    }

    async fn reconstruct_outcome(
        &self,
        authenticated_requester: PartyId,
        stored: StoredScanOutcome,
        verified_terminal: &VerifiedDepositIndexCheckpoint,
        active: &VerifiedRegistryHandoffTarget,
        local_identity: &Identity,
        archive: &DepositArchiveStore,
    ) -> Result<DepositPrefixScanOutcome, DepositPrefixScanStoreError> {
        match stored {
            StoredScanOutcome::Pending { attempt, next_revision } => {
                Ok(DepositPrefixScanOutcome::Pending { attempt, next_revision })
            }
            StoredScanOutcome::NotIncluded { attempt } => {
                Ok(DepositPrefixScanOutcome::NotIncluded { attempt })
            }
            StoredScanOutcome::Included {
                attempt,
                request,
                replay_cursor,
                local_terminal_event,
            } => {
                // Recheck caller-supplied authority immediately before returning the reconstructed
                // non-serializable capability.
                self.authorize_request(
                    authenticated_requester,
                    &request,
                    verified_terminal,
                    active,
                    local_identity,
                )?;
                let DepositArchivePrefixStep::Included(prefix) =
                    archive.verify_anchored_prefix_step(replay_cursor).await?
                else {
                    return Err(DepositPrefixScanStoreError::TerminalReplayMismatch);
                };
                if prefix.local_terminal_event() != local_terminal_event
                    || prefix.target() != &request.statement().prefix_target()?
                {
                    return Err(DepositPrefixScanStoreError::TerminalReplayMismatch);
                }
                Ok(DepositPrefixScanOutcome::Included(VerifiedDepositPrefixScan {
                    attempt,
                    request,
                    prefix,
                }))
            }
        }
    }
}

fn action_for_existing(
    slot: &DurablePrefixScanSlot,
) -> Result<PreparedScanAction, DepositPrefixScanStoreError> {
    Ok(match &slot.phase {
        DurableScanPhase::InFlight { input, cursor } => PreparedScanAction::Execute {
            expected: slot.clone(),
            input: *input,
            cursor: DepositArchivePrefixCursor::from_bytes(cursor)?,
        },
        _ => PreparedScanAction::Replay(stored_outcome(slot)?),
    })
}

fn prepare_start_blocking(
    inner: &PrefixScanDatabase,
    requester: PartyId,
    attempt: DepositSyncPrefixSupportAttempt,
    start: Vec<u8>,
    anchor: DepositArchiveHead,
) -> Result<PreparedScanAction, DepositPrefixScanStoreError> {
    let parsed_start = DepositSyncPrefixSupportStart::from_bytes(&start)?;
    if parsed_start.attempt()? != attempt
        || parsed_start.request().statement().requester() != requester
    {
        return Err(DepositPrefixScanStoreError::InvalidDurableState);
    }
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let existing = load_slot_in_transaction(&transaction, inner, requester)?;
    let disposition = classify_start(
        existing.as_ref().map(|slot| slot.attempt),
        attempt,
        parsed_start.replaces(),
    )?;
    let action = match (disposition, existing) {
        (StartDisposition::Replay, Some(existing)) => {
            // The local live head may have advanced since the first delivery. An exact Start
            // replay must retain the already journaled anchor instead of comparing it with the
            // caller's newly sampled head.
            if existing.start != start {
                return Err(DepositPrefixScanStoreError::StartConflict);
            }
            action_for_existing(&existing)?
        }
        (StartDisposition::Replace, Some(_existing)) => {
            let cursor = DepositArchivePrefixCursor::start(
                anchor,
                parsed_start.request().statement().prefix_target()?,
            )?;
            let candidate = DurablePrefixScanSlot {
                version: PREFIX_SCAN_STORE_VERSION,
                requester,
                attempt,
                start,
                anchor,
                phase: DurableScanPhase::InFlight {
                    input: DurableScanInput::Start,
                    cursor: cursor.to_bytes()?,
                },
            };
            candidate.validate(inner.local_party, inner.context)?;
            store_slot(&transaction, inner, &candidate)?;
            PreparedScanAction::Execute {
                expected: candidate,
                input: DurableScanInput::Start,
                cursor,
            }
        }
        (StartDisposition::New, None) => {
            ensure_new_slot_capacity(slot_count(&transaction)?)?;
            let cursor = DepositArchivePrefixCursor::start(
                anchor,
                parsed_start.request().statement().prefix_target()?,
            )?;
            let candidate = DurablePrefixScanSlot {
                version: PREFIX_SCAN_STORE_VERSION,
                requester,
                attempt,
                start,
                anchor,
                phase: DurableScanPhase::InFlight {
                    input: DurableScanInput::Start,
                    cursor: cursor.to_bytes()?,
                },
            };
            candidate.validate(inner.local_party, inner.context)?;
            store_slot(&transaction, inner, &candidate)?;
            PreparedScanAction::Execute {
                expected: candidate,
                input: DurableScanInput::Start,
                cursor,
            }
        }
        _ => return Err(DepositPrefixScanStoreError::InvalidDurableState),
    };
    transaction.commit().map_database()?;
    Ok(action)
}

fn prepare_continue_blocking(
    inner: &PrefixScanDatabase,
    expected_slot: &DurablePrefixScanSlot,
    continuation: DepositSyncPrefixSupportContinue,
) -> Result<PreparedScanAction, DepositPrefixScanStoreError> {
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut slot = load_slot_in_transaction(&transaction, inner, expected_slot.requester)?
        .ok_or(DepositPrefixScanStoreError::UnknownRequester)?;
    if &slot != expected_slot {
        return Err(DepositPrefixScanStoreError::ConcurrentMutation);
    }
    if continuation.attempt() != slot.attempt {
        return Err(DepositPrefixScanStoreError::WrongAttempt);
    }
    let requested_revision = continuation.revision();
    let phase = slot.phase.clone();
    let action = match phase {
        DurableScanPhase::Pending { next_revision, cursor, .. }
            if requested_revision == next_revision =>
        {
            let cursor = DepositArchivePrefixCursor::from_bytes(&cursor)?;
            let input = DurableScanInput::Continue { revision: requested_revision };
            let _ = input.next_revision()?;
            slot.phase = DurableScanPhase::InFlight { input, cursor: cursor.to_bytes()? };
            slot.validate(inner.local_party, inner.context)?;
            store_slot(&transaction, inner, &slot)?;
            PreparedScanAction::Execute { expected: slot, input, cursor }
        }
        DurableScanPhase::Pending { last_input, next_revision, .. }
            if last_input == (DurableScanInput::Continue { revision: requested_revision }) =>
        {
            PreparedScanAction::Replay(StoredScanOutcome::Pending {
                attempt: slot.attempt,
                next_revision,
            })
        }
        DurableScanPhase::InFlight { input, cursor }
            if input == (DurableScanInput::Continue { revision: requested_revision }) =>
        {
            PreparedScanAction::Execute {
                expected: slot.clone(),
                input,
                cursor: DepositArchivePrefixCursor::from_bytes(&cursor)?,
            }
        }
        DurableScanPhase::Included { last_input, .. }
        | DurableScanPhase::NotIncluded { last_input }
            if last_input == (DurableScanInput::Continue { revision: requested_revision }) =>
        {
            PreparedScanAction::Replay(stored_outcome(&slot)?)
        }
        _ => return Err(DepositPrefixScanStoreError::RevisionMismatch),
    };
    transaction.commit().map_database()?;
    Ok(action)
}

fn finalize_step_blocking(
    inner: &PrefixScanDatabase,
    expected: &DurablePrefixScanSlot,
    input: DurableScanInput,
    replay_cursor: DepositArchivePrefixCursor,
    step: DepositArchivePrefixStep,
) -> Result<StoredScanOutcome, DepositPrefixScanStoreError> {
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let Some(mut slot) = load_slot_in_transaction(&transaction, inner, expected.requester)? else {
        return Err(DepositPrefixScanStoreError::ConcurrentMutation);
    };
    if &slot != expected {
        if slot.attempt == expected.attempt {
            if let Ok(completed) = stored_outcome_for_input(&slot, input) {
                transaction.commit().map_database()?;
                return Ok(completed);
            }
        }
        return Err(DepositPrefixScanStoreError::ConcurrentMutation);
    }
    match step {
        DepositArchivePrefixStep::Pending(cursor) => {
            let next_revision = input.next_revision()?;
            slot.phase = DurableScanPhase::Pending {
                last_input: input,
                next_revision,
                cursor: cursor.to_bytes()?,
            };
        }
        DepositArchivePrefixStep::Included(prefix) => {
            if prefix.anchor() != replay_cursor.anchor()
                || prefix.target() != replay_cursor.target()
            {
                return Err(DepositPrefixScanStoreError::TerminalReplayMismatch);
            }
            slot.phase = DurableScanPhase::Included {
                last_input: input,
                replay_cursor: replay_cursor.to_bytes()?,
                local_terminal_event: prefix.local_terminal_event(),
            };
        }
        DepositArchivePrefixStep::NotIncluded => {
            slot.phase = DurableScanPhase::NotIncluded { last_input: input };
        }
    }
    slot.validate(inner.local_party, inner.context)?;
    store_slot(&transaction, inner, &slot)?;
    let outcome = stored_outcome(&slot)?;
    transaction.commit().map_database()?;
    Ok(outcome)
}

fn stored_outcome_for_input(
    slot: &DurablePrefixScanSlot,
    input: DurableScanInput,
) -> Result<StoredScanOutcome, DepositPrefixScanStoreError> {
    let matches = match &slot.phase {
        DurableScanPhase::Pending { last_input, .. }
        | DurableScanPhase::Included { last_input, .. }
        | DurableScanPhase::NotIncluded { last_input } => *last_input == input,
        DurableScanPhase::InFlight { .. } => false,
    };
    if !matches {
        return Err(DepositPrefixScanStoreError::ConcurrentMutation);
    }
    stored_outcome(slot)
}

fn stored_outcome(
    slot: &DurablePrefixScanSlot,
) -> Result<StoredScanOutcome, DepositPrefixScanStoreError> {
    Ok(match &slot.phase {
        DurableScanPhase::Pending { next_revision, .. } => {
            StoredScanOutcome::Pending { attempt: slot.attempt, next_revision: *next_revision }
        }
        DurableScanPhase::Included { replay_cursor, local_terminal_event, .. } => {
            StoredScanOutcome::Included {
                attempt: slot.attempt,
                request: slot.parsed_request()?,
                replay_cursor: DepositArchivePrefixCursor::from_bytes(replay_cursor)?,
                local_terminal_event: *local_terminal_event,
            }
        }
        DurableScanPhase::NotIncluded { .. } => {
            StoredScanOutcome::NotIncluded { attempt: slot.attempt }
        }
        DurableScanPhase::InFlight { .. } => {
            return Err(DepositPrefixScanStoreError::InvalidDurableState);
        }
    })
}

fn open_prefix_scan_database(
    path: &Path,
    local_party: PartyId,
    context: DepositSyncContext,
    value_key: Zeroizing<[u8; 32]>,
) -> Result<PrefixScanDatabase, DepositPrefixScanStoreError> {
    if local_party == PartyId(0) || context.network() == [0; 32] || *value_key == [0; 32] {
        return Err(DepositPrefixScanStoreError::InvalidIdentity);
    }
    let parent = path.parent().ok_or(DepositPrefixScanStoreError::StorageConflict)?;
    std::fs::create_dir_all(parent).map_database()?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_database()?;
    if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(DepositPrefixScanStoreError::StorageConflict);
    }
    #[cfg(unix)]
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_database()?;
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && (!metadata.file_type().is_file() || metadata.file_type().is_symlink())
    {
        return Err(DepositPrefixScanStoreError::StorageConflict);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).map_database()?;
    let opened = file.metadata().map_database()?;
    let current = std::fs::symlink_metadata(path).map_database()?;
    if !opened.is_file() || !current.is_file() || !same_file_identity(&opened, &current) {
        return Err(DepositPrefixScanStoreError::StorageConflict);
    }
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600)).map_database()?;
    let mut builder = Database::builder();
    builder.set_cache_size(PREFIX_SCAN_DATABASE_CACHE_BYTES);
    let database = builder.create_file(file).map_database()?;
    let inner = PrefixScanDatabase { database, local_party, context, value_key };
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    drop(transaction.open_table(PREFIX_SCAN_SLOT_TABLE).map_database()?);
    transaction.commit().map_database()?;
    validate_database_shape(&inner)?;
    #[cfg(unix)]
    std::fs::File::open(parent).and_then(|directory| directory.sync_all()).map_database()?;
    Ok(inner)
}

fn validate_database_shape(inner: &PrefixScanDatabase) -> Result<(), DepositPrefixScanStoreError> {
    let transaction = inner.database.begin_read().map_database()?;
    let table = transaction.open_table(PREFIX_SCAN_SLOT_TABLE).map_database()?;
    if usize::try_from(table.len().map_database()?)
        .map_err(|_| DepositPrefixScanStoreError::RequesterQuota)?
        > MAX_COMMITTEE_MEMBERS
    {
        return Err(DepositPrefixScanStoreError::RequesterQuota);
    }
    for entry in table.iter().map_database()? {
        let (key, value) = entry.map_database()?;
        let requester = requester_from_key(key.value())?;
        let slot = open_slot(inner, requester, value.value())?;
        if slot.requester != requester {
            return Err(DepositPrefixScanStoreError::InvalidDurableState);
        }
    }
    Ok(())
}

fn load_slot_blocking(
    inner: &PrefixScanDatabase,
    requester: PartyId,
) -> Result<Option<DurablePrefixScanSlot>, DepositPrefixScanStoreError> {
    if requester == PartyId(0) {
        return Err(DepositPrefixScanStoreError::UnauthenticatedRequester);
    }
    let transaction = inner.database.begin_read().map_database()?;
    let table = transaction.open_table(PREFIX_SCAN_SLOT_TABLE).map_database()?;
    let key = requester_key(requester);
    let Some(value) = table.get(key.as_slice()).map_database()? else {
        return Ok(None);
    };
    Ok(Some(open_slot(inner, requester, value.value())?))
}

fn load_slot_in_transaction(
    transaction: &redb::WriteTransaction,
    inner: &PrefixScanDatabase,
    requester: PartyId,
) -> Result<Option<DurablePrefixScanSlot>, DepositPrefixScanStoreError> {
    let table = transaction.open_table(PREFIX_SCAN_SLOT_TABLE).map_database()?;
    let key = requester_key(requester);
    let Some(value) = table.get(key.as_slice()).map_database()? else {
        return Ok(None);
    };
    Ok(Some(open_slot(inner, requester, value.value())?))
}

fn store_slot(
    transaction: &redb::WriteTransaction,
    inner: &PrefixScanDatabase,
    slot: &DurablePrefixScanSlot,
) -> Result<(), DepositPrefixScanStoreError> {
    slot.validate(inner.local_party, inner.context)?;
    let key = requester_key(slot.requester);
    let encoded = seal_slot(inner, slot.requester, slot)?;
    let mut table = transaction.open_table(PREFIX_SCAN_SLOT_TABLE).map_database()?;
    table.insert(key.as_slice(), encoded.as_slice()).map_database()?;
    Ok(())
}

fn slot_count(transaction: &redb::WriteTransaction) -> Result<usize, DepositPrefixScanStoreError> {
    let table = transaction.open_table(PREFIX_SCAN_SLOT_TABLE).map_database()?;
    usize::try_from(table.len().map_database()?)
        .map_err(|_| DepositPrefixScanStoreError::RequesterQuota)
}

fn retire_inactive_blocking(
    inner: &PrefixScanDatabase,
    current: &[PartyId],
) -> Result<usize, DepositPrefixScanStoreError> {
    if current.is_empty() || current.len() > MAX_COMMITTEE_MEMBERS {
        return Err(DepositPrefixScanStoreError::InvalidDurableState);
    }
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let stale = {
        let table = transaction.open_table(PREFIX_SCAN_SLOT_TABLE).map_database()?;
        let mut stale = Vec::new();
        for entry in table.iter().map_database()? {
            let (key, value) = entry.map_database()?;
            let requester = requester_from_key(key.value())?;
            let slot = open_slot(inner, requester, value.value())?;
            if !current.contains(&requester) {
                stale.push((requester, slot.attempt));
            }
        }
        stale
    };
    {
        let mut table = transaction.open_table(PREFIX_SCAN_SLOT_TABLE).map_database()?;
        for (requester, _) in &stale {
            let key = requester_key(*requester);
            table.remove(key.as_slice()).map_database()?;
        }
    }
    transaction.commit().map_database()?;
    Ok(stale.len())
}

fn seal_slot(
    inner: &PrefixScanDatabase,
    requester: PartyId,
    slot: &DurablePrefixScanSlot,
) -> Result<Vec<u8>, DepositPrefixScanStoreError> {
    let plaintext = Zeroizing::new(encode_canonical(slot, MAX_PREFIX_SCAN_SLOT_PLAINTEXT_BYTES)?);
    let aad = slot_aad(inner.local_party, inner.context.digest(), requester);
    seal_slot_plaintext(&inner.value_key, &aad, plaintext.as_slice())
}

fn open_slot(
    inner: &PrefixScanDatabase,
    requester: PartyId,
    encoded: &[u8],
) -> Result<DurablePrefixScanSlot, DepositPrefixScanStoreError> {
    let aad = slot_aad(inner.local_party, inner.context.digest(), requester);
    let plaintext = open_slot_plaintext(&inner.value_key, &aad, encoded)?;
    let slot: DurablePrefixScanSlot =
        decode_canonical(plaintext.as_slice(), MAX_PREFIX_SCAN_SLOT_PLAINTEXT_BYTES)?;
    slot.validate(inner.local_party, inner.context)?;
    if slot.requester != requester {
        return Err(DepositPrefixScanStoreError::StorageAuthentication);
    }
    Ok(slot)
}

fn seal_slot_plaintext(
    value_key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, DepositPrefixScanStoreError> {
    if plaintext.is_empty() || plaintext.len() > MAX_PREFIX_SCAN_SLOT_PLAINTEXT_BYTES {
        return Err(DepositPrefixScanStoreError::StorageValueTooLarge);
    }
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new(Key::from_slice(value_key))
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| DepositPrefixScanStoreError::StorageAuthentication)?;
    encode_canonical(
        &SealedPrefixScanSlot { version: PREFIX_SCAN_STORE_VERSION, nonce, ciphertext },
        MAX_PREFIX_SCAN_SEALED_SLOT_BYTES,
    )
}

fn open_slot_plaintext(
    value_key: &[u8; 32],
    aad: &[u8],
    encoded: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DepositPrefixScanStoreError> {
    let sealed: SealedPrefixScanSlot =
        decode_canonical(encoded, MAX_PREFIX_SCAN_SEALED_SLOT_BYTES)?;
    if sealed.version != PREFIX_SCAN_STORE_VERSION {
        return Err(DepositPrefixScanStoreError::StorageAuthentication);
    }
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new(Key::from_slice(value_key))
            .decrypt(XNonce::from_slice(&sealed.nonce), Payload { msg: &sealed.ciphertext, aad })
            .map_err(|_| DepositPrefixScanStoreError::StorageAuthentication)?,
    );
    if plaintext.is_empty() || plaintext.len() > MAX_PREFIX_SCAN_SLOT_PLAINTEXT_BYTES {
        return Err(DepositPrefixScanStoreError::StorageValueTooLarge);
    }
    Ok(plaintext)
}

fn derive_value_key(
    root_key: &[u8; 32],
    local_party: PartyId,
    context_digest: [u8; 32],
) -> Result<Zeroizing<[u8; 32]>, DepositPrefixScanStoreError> {
    if context_digest == [0; 32] {
        return Err(DepositPrefixScanStoreError::KeyDerivation);
    }
    let mut hasher = blake3::Hasher::new_keyed(root_key);
    hasher.update(PREFIX_SCAN_VALUE_KEY_DOMAIN.as_bytes());
    hasher.update(&local_party.0.to_le_bytes());
    hasher.update(&context_digest);
    let key = Zeroizing::new(*hasher.finalize().as_bytes());
    if *key == [0; 32] {
        return Err(DepositPrefixScanStoreError::KeyDerivation);
    }
    Ok(key)
}

fn slot_aad(local_party: PartyId, context_digest: [u8; 32], requester: PartyId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PREFIX_SCAN_AEAD_DOMAIN.len() + 36 + 8);
    aad.extend_from_slice(PREFIX_SCAN_AEAD_DOMAIN);
    aad.extend_from_slice(&(PREFIX_SCAN_SLOT_LABEL.len() as u64).to_le_bytes());
    aad.extend_from_slice(PREFIX_SCAN_SLOT_LABEL);
    aad.extend_from_slice(&local_party.0.to_le_bytes());
    aad.extend_from_slice(&context_digest);
    aad.extend_from_slice(&requester.0.to_le_bytes());
    aad
}

fn requester_key(requester: PartyId) -> [u8; 2] {
    requester.0.to_be_bytes()
}

fn requester_from_key(bytes: &[u8]) -> Result<PartyId, DepositPrefixScanStoreError> {
    let raw: [u8; 2] =
        bytes.try_into().map_err(|_| DepositPrefixScanStoreError::InvalidDurableState)?;
    let requester = PartyId(u16::from_be_bytes(raw));
    if requester == PartyId(0) {
        return Err(DepositPrefixScanStoreError::InvalidDurableState);
    }
    Ok(requester)
}

fn deserialize_start_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes(
        deserializer,
        MAX_DEPOSIT_SYNC_PREFIX_SUPPORT_START_BYTES,
        "prefix scan start exceeds its allocation bound",
    )
}

fn deserialize_cursor_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes(
        deserializer,
        MAX_DEPOSIT_ARCHIVE_PREFIX_CURSOR_BYTES,
        "prefix scan cursor exceeds its allocation bound",
    )
}

fn deserialize_sealed_slot_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes(
        deserializer,
        MAX_PREFIX_SCAN_SLOT_PLAINTEXT_BYTES + 16,
        "sealed prefix scan slot exceeds its allocation bound",
    )
}

fn deserialize_bounded_bytes<'de, D>(
    deserializer: D,
    maximum: usize,
    expectation: &'static str,
) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedBytesVisitor {
        maximum: usize,
        expectation: &'static str,
    }

    impl<'de> Visitor<'de> for BoundedBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.expectation)
        }

        fn visit_bytes<E: DeError>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            if bytes.len() > self.maximum {
                return Err(E::custom(self.expectation));
            }
            Ok(bytes.to_vec())
        }

        fn visit_borrowed_bytes<E: DeError>(self, bytes: &'de [u8]) -> Result<Self::Value, E> {
            self.visit_bytes(bytes)
        }

        fn visit_byte_buf<E: DeError>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            if bytes.len() > self.maximum {
                return Err(E::custom(self.expectation));
            }
            Ok(bytes)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|length| length > self.maximum) {
                return Err(A::Error::custom(self.expectation));
            }
            let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == self.maximum {
                    return Err(A::Error::custom(self.expectation));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_byte_buf(BoundedBytesVisitor { maximum, expectation })
}

fn encode_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, DepositPrefixScanStoreError> {
    let bytes =
        postcard::to_allocvec(value).map_err(|_| DepositPrefixScanStoreError::Serialization)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositPrefixScanStoreError::StorageValueTooLarge);
    }
    Ok(bytes)
}

fn decode_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, DepositPrefixScanStoreError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositPrefixScanStoreError::StorageValueTooLarge);
    }
    let (value, trailing) = postcard::take_from_bytes::<T>(bytes)
        .map_err(|_| DepositPrefixScanStoreError::Serialization)?;
    if !trailing.is_empty() || encode_canonical(&value, maximum)? != bytes {
        return Err(DepositPrefixScanStoreError::NonCanonicalEncoding);
    }
    Ok(value)
}

fn configure_write(transaction: &mut redb::WriteTransaction) {
    transaction.set_two_phase_commit(true);
    transaction.set_quick_repair(true);
}

#[cfg(unix)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    true
}

trait DatabaseResultExt<T> {
    fn map_database(self) -> Result<T, DepositPrefixScanStoreError>;
}

impl<T, E: fmt::Display> DatabaseResultExt<T> for Result<T, E> {
    fn map_database(self) -> Result<T, DepositPrefixScanStoreError> {
        self.map_err(|error| DepositPrefixScanStoreError::Database(error.to_string()))
    }
}

#[derive(Debug, Error)]
pub enum DepositPrefixScanStoreError {
    #[error("deposit archive rejected prefix scan state: {0}")]
    Archive(#[from] DepositArchiveError),
    #[error("deposit prefix-support request was rejected: {0}")]
    Support(#[from] DepositSyncSupportError),
    #[error("deposit sync wire rejected prefix scan context: {0}")]
    Wire(#[from] crate::deposit_sync_wire::DepositSyncWireError),
    #[error("committee rejected prefix scan authorization: {0}")]
    Committee(#[from] CommitteeError),
    #[error("wallet storage rejected prefix scan state: {0}")]
    Storage(#[from] StoreError),
    #[error("prefix scan database failed: {0}")]
    Database(String),
    #[error("prefix scan blocking task failed: {0}")]
    BlockingTask(String),
    #[error("prefix scan storage serialization failed")]
    Serialization,
    #[error("prefix scan storage encoding was non-canonical")]
    NonCanonicalEncoding,
    #[error("prefix scan storage value exceeded its fixed bound")]
    StorageValueTooLarge,
    #[error("prefix scan storage record authentication failed")]
    StorageAuthentication,
    #[error("prefix scan storage path conflicts with a private regular database")]
    StorageConflict,
    #[error("prefix scan key derivation failed")]
    KeyDerivation,
    #[error("prefix scan caller identity is not the configured current identity")]
    InvalidIdentity,
    #[error("prefix scan requester did not match the transport-authenticated peer")]
    UnauthenticatedRequester,
    #[error("prefix scan requester does not have a durable slot")]
    UnknownRequester,
    #[error("prefix scan request does not name the slot's exact attempt")]
    WrongAttempt,
    #[error("prefix scan continuation does not name the exact accepted revision")]
    RevisionMismatch,
    #[error("prefix scan revision counter is exhausted")]
    RevisionExhausted,
    #[error("prefix scan replacement does not name the exact current attempt")]
    ReplacementMismatch,
    #[error("prefix scan start conflicts with the exact existing attempt")]
    StartConflict,
    #[error("prefix scan requester quota is full")]
    RequesterQuota,
    #[error("prefix scan durable state is malformed")]
    InvalidDurableState,
    #[error("prefix scan state changed through another writer")]
    ConcurrentMutation,
    #[error("prefix scan terminal replay no longer reconstructs its exact authenticated result")]
    TerminalReplayMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(byte: u8) -> DepositSyncPrefixSupportAttempt {
        DepositSyncPrefixSupportAttempt::from_bytes([byte; 32]).unwrap()
    }

    #[test]
    fn revisions_are_exact_and_replayable() {
        assert_eq!(DurableScanInput::Start.next_revision().unwrap(), 1);
        assert_eq!(DurableScanInput::Continue { revision: 7 }.next_revision().unwrap(), 8);
        assert!(matches!(
            DurableScanInput::Continue { revision: u64::MAX }.next_revision(),
            Err(DepositPrefixScanStoreError::RevisionExhausted)
        ));
        assert!(matches!(
            validate_input(DurableScanInput::Continue { revision: 0 }),
            Err(DepositPrefixScanStoreError::InvalidDurableState)
        ));
        assert!(matches!(
            validate_input(DurableScanInput::Continue { revision: u64::MAX }),
            Err(DepositPrefixScanStoreError::InvalidDurableState)
        ));

        let slot = DurablePrefixScanSlot {
            version: PREFIX_SCAN_STORE_VERSION,
            requester: PartyId(2),
            attempt: attempt(0x21),
            // `action_for_existing` does not parse the request for a completed Pending replay.
            // Full durable loads validate exact request bytes before reaching this classifier.
            start: vec![0x01],
            anchor: DepositArchiveHead::empty(crate::deposit_wallet::DepositWalletId([0x22; 32]))
                .unwrap(),
            phase: DurableScanPhase::Pending {
                last_input: DurableScanInput::Continue { revision: 6 },
                next_revision: 7,
                cursor: vec![0x02],
            },
        };
        let PreparedScanAction::Replay(StoredScanOutcome::Pending { attempt, next_revision }) =
            action_for_existing(&slot).unwrap()
        else {
            panic!("a completed pending transition must replay without another archive step");
        };
        assert_eq!(attempt, slot.attempt);
        assert_eq!(next_revision, 7);
        assert!(matches!(
            action_for_existing(&slot).unwrap(),
            PreparedScanAction::Replay(StoredScanOutcome::Pending { next_revision: 7, .. })
        ));
    }

    #[test]
    fn replacement_requires_the_exact_current_attempt() {
        let current = attempt(0x31);
        let incoming = attempt(0x32);
        assert_eq!(classify_start(Some(current), current, None).unwrap(), StartDisposition::Replay);
        assert_eq!(
            classify_start(Some(current), incoming, Some(current)).unwrap(),
            StartDisposition::Replace
        );
        assert!(matches!(
            classify_start(Some(current), incoming, None),
            Err(DepositPrefixScanStoreError::ReplacementMismatch)
        ));
        assert!(matches!(
            classify_start(Some(current), incoming, Some(attempt(0x33))),
            Err(DepositPrefixScanStoreError::ReplacementMismatch)
        ));
        assert!(matches!(
            classify_start(None, incoming, Some(current)),
            Err(DepositPrefixScanStoreError::ReplacementMismatch)
        ));
        assert_eq!(classify_start(None, incoming, None).unwrap(), StartDisposition::New);
    }

    #[test]
    fn requester_keys_are_canonical_and_bounded() {
        assert!(ensure_new_slot_capacity(MAX_COMMITTEE_MEMBERS - 1).is_ok());
        assert!(matches!(
            ensure_new_slot_capacity(MAX_COMMITTEE_MEMBERS),
            Err(DepositPrefixScanStoreError::RequesterQuota)
        ));
        for raw in 1..=u16::try_from(MAX_COMMITTEE_MEMBERS).unwrap() {
            let requester = PartyId(raw);
            assert_eq!(requester_from_key(&requester_key(requester)).unwrap(), requester);
        }
        assert!(matches!(
            requester_from_key(&[]),
            Err(DepositPrefixScanStoreError::InvalidDurableState)
        ));
        assert!(matches!(
            requester_from_key(&[0, 0]),
            Err(DepositPrefixScanStoreError::InvalidDurableState)
        ));
    }

    #[test]
    fn sealed_values_are_canonical_and_detect_tampering() {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        struct TestRecord {
            version: u16,
            attempt: DepositSyncPrefixSupportAttempt,
        }

        let record = TestRecord { version: PREFIX_SCAN_STORE_VERSION, attempt: attempt(0x41) };
        let bytes = encode_canonical(&record, 1024).unwrap();
        assert_eq!(decode_canonical::<TestRecord>(&bytes, 1024).unwrap(), record);
        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            decode_canonical::<TestRecord>(&trailing, 1024),
            Err(DepositPrefixScanStoreError::NonCanonicalEncoding)
        ));

        let key = [0x42; 32];
        let network = [0x43; 32];
        let aad = slot_aad(PartyId(1), network, PartyId(2));
        let plaintext = b"restart-stable private prefix cursor";
        let sealed = seal_slot_plaintext(&key, &aad, plaintext).unwrap();
        assert_ne!(
            sealed.windows(plaintext.len()).find(|window| *window == plaintext),
            Some(plaintext.as_slice())
        );
        assert_eq!(open_slot_plaintext(&key, &aad, &sealed).unwrap().as_slice(), plaintext);

        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open_slot_plaintext(&key, &aad, &tampered).is_err());
        assert!(matches!(
            open_slot_plaintext(&key, &slot_aad(PartyId(1), network, PartyId(3)), &sealed),
            Err(DepositPrefixScanStoreError::StorageAuthentication)
        ));
        assert!(matches!(
            open_slot_plaintext(&key, &slot_aad(PartyId(1), [0x44; 32], PartyId(2)), &sealed),
            Err(DepositPrefixScanStoreError::StorageAuthentication)
        ));
    }

    #[test]
    fn restart_phase_preserves_inflight_cursor_and_terminal_tombstones() {
        let in_flight = DurableScanPhase::InFlight {
            input: DurableScanInput::Continue { revision: 9 },
            cursor: vec![1, 2, 3],
        };
        let encoded = encode_canonical(&in_flight, 1024).unwrap();
        assert_eq!(decode_canonical::<DurableScanPhase>(&encoded, 1024).unwrap(), in_flight);

        let not_included = DurableScanPhase::NotIncluded {
            last_input: DurableScanInput::Continue { revision: 9 },
        };
        let encoded = encode_canonical(&not_included, 1024).unwrap();
        assert_eq!(decode_canonical::<DurableScanPhase>(&encoded, 1024).unwrap(), not_included);
    }
}
