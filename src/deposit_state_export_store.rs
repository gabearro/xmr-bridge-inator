//! Crash-safe post-handoff export-seal voting and certification.
//!
//! A retiring committee can continue signing an exact source export after its transport
//! encryption keys have been erased.  This reducer therefore binds only the predecessor member's
//! stable signing key and accepts the deliberately narrow
//! [`crate::identity::EnvelopeSignerScope::HandoffOnly`] capability.  It never serializes signing
//! authority.
//!
//! Each `(network, wallet, local predecessor, source registry, semantic transition, serving
//! source)` tuple has one synthetic [`WalletSnapshotStore`] record.  The exact statement and every
//! vote are committed to that record before a signature or certificate can leave this module.
//! Retrying an exact request replays the authenticated bytes; presenting another exact statement
//! for the same vote slot is a permanent equivocation, including after restart.
//!
//! Durable bytes are evidence, never signing authority. Signing requires fresh
//! [`DepositStateExportSealAuthority`]. After import finality, [`DepositStateExportSealReplay`]
//! reauthenticates already signed messages without reopening reclaimed graph/signing gates.

use std::{collections::BTreeSet, fmt, io, path::PathBuf, sync::Arc};

use rand_core::OsRng;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as DeError, SeqAccess, Visitor},
};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    committee::{MAX_COMMITTEE_MEMBERS, PartyId},
    compact_epoch_registry::{CompactEpochRegistry, RegistryHandoffCertificate, RegistryId},
    deposit_index_retention::{PreparedExportCandidatePin, RetentionError, StoredExportPin},
    deposit_index_store::{DepositIndexStoreError, VerifiedRemoteExportSealVoteGate},
    deposit_state_export::{
        DepositPostHandoffExportSealCertificate, DepositPostHandoffExportSealStatement,
        DepositStateExportError, MAX_POST_HANDOFF_EXPORT_SEAL_BYTES,
        VerifiedDepositPostHandoffExportCandidate, VerifiedDepositPostHandoffExportSeal,
    },
    deposit_state_import::{
        DepositStateImportError, VerifiedStateImportCandidateTransitionBinding,
        VerifiedStateImportTransitionBinding, VerifiedStateImportedCertificate,
    },
    deposit_state_transfer_wire::{
        DepositPostHandoffExportCandidateEvidence, DepositPostHandoffExportSealCertificateAck,
        DepositPostHandoffExportSealCertificateDelivery, DepositPostHandoffExportSealRequest,
        DepositPostHandoffExportSealVote, DepositPostHandoffExportSealVoteAck,
        DepositStateTransferWireError, MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_BYTES,
        MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES,
    },
    deposit_wallet::DepositWalletId,
    identity::{EnvelopeSigner, EnvelopeSignerScope, Identity, SignedEnvelope},
    key_rotation::VerifiedRegistryHandoffTarget,
    storage::{
        MAX_WALLET_SNAPSHOT_BYTES, StoreError, WalletId, WalletSnapshotMetadata,
        WalletSnapshotStore,
    },
};

const EXPORT_SEAL_STORE_VERSION: u16 = 2;
const EXPORT_SEAL_STORE_DOMAIN: [u8; 16] = *b"tm-xseal-jrnl002";
const EXPORT_SEAL_WALLET_ID_DOMAIN: &str =
    "threshold-monero/deposit-state-export-seal-store/synthetic-wallet/v2";
const EXPORT_SEAL_WORK_LOCATOR_DOMAIN: &str =
    "threshold-monero/deposit-state-export-seal-store/work-locator/v2";
const MAX_EXPORT_SEAL_CERTIFICATE_RECIPIENTS: usize = MAX_COMMITTEE_MEMBERS * 2;

const MAX_EXPORT_SEAL_STORE_SNAPSHOT_BYTES: usize = MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_BYTES
    + (MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES + 512) * MAX_COMMITTEE_MEMBERS
    + MAX_POST_HANDOFF_EXPORT_SEAL_BYTES
    + 128 * 1024;

const _: () = assert!(MAX_EXPORT_SEAL_STORE_SNAPSHOT_BYTES <= MAX_WALLET_SNAPSHOT_BYTES);

/// Live authority for one exact predecessor export-seal slot.
///
/// This type borrows every non-serializable capability needed by signing and recovery.  In
/// particular, a structurally valid statement restored from storage can never mint this value.
pub(crate) struct DepositStateExportSealAuthority<'a> {
    candidate: &'a VerifiedDepositPostHandoffExportCandidate,
    source: &'a CompactEpochRegistry,
    handoff: &'a RegistryHandoffCertificate,
    signer: &'a dyn EnvelopeSigner,
    signing_gate: DepositStateExportSealSigningGate<'a>,
    binding: DurableExportSealBinding,
}

enum DepositStateExportSealSigningGate<'a> {
    Source(&'a PreparedExportCandidatePin),
    Remote(&'a VerifiedRemoteExportSealVoteGate),
}

/// Replay scope for an already finalized import. This carries no graph/signing gate and can
/// only reopen signed journal messages or commit their exact transport receipts.
pub(crate) struct DepositStateExportSealReplay<'a> {
    pub(crate) source: &'a CompactEpochRegistry,
    pub(crate) handoff: &'a RegistryHandoffCertificate,
    pub(crate) target: &'a VerifiedRegistryHandoffTarget,
    pub(crate) imported: &'a VerifiedStateImportedCertificate,
    pub(crate) signer: &'a dyn EnvelopeSigner,
}

impl DepositStateExportSealReplay<'_> {
    fn snapshot_id(
        &self,
        store: &DepositStateExportSealStore,
        source_party: PartyId,
    ) -> Result<WalletId, DepositStateExportStoreError> {
        let member = self
            .source
            .active()
            .committee()
            .member(store.local_party)
            .map_err(|_| DepositStateExportStoreError::WrongAuthority)?;
        if self.imported.network() != store.network
            || self.imported.wallet() != store.wallet
            || self.source.wallet() != store.wallet
            || self.target.wallet() != store.wallet
            || self.signer.party() != store.local_party
            || self.signer.signing_public_key() != member.signing_key
            || !matches!(
                self.signer.scope(),
                EnvelopeSignerScope::Full | EnvelopeSignerScope::HandoffOnly
            )
            || self.source.active().committee().member(source_party).is_err()
            || self.handoff.statement().source() != self.source.id()
            || self.imported.handoff_statement_digest() != self.handoff.statement().digest()
            || self.imported.target_epoch() != self.target.committee().epoch
            || self.source.active_epoch().checked_add(1) != Some(self.imported.target_epoch())
            || self.imported.target_committee_digest() != self.target.committee().digest()
            || self.imported.target_activation() != self.target.activation()
            || self.imported.target_certified_activation_root()
                != self.target.certified_activation_root()
        {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        export_seal_slot_id(
            store.network,
            store.wallet,
            store.local_party,
            self.source.id(),
            source_party,
            self.imported.target_epoch(),
            self.imported.semantic_transition_digest(),
            self.imported.transition_binding(),
            crate::deposit_state_export::export_seal_vote_slot_digest(
                self.imported.semantic_transition_digest(),
                source_party,
                self.imported.target_epoch(),
            ),
        )
    }

    fn validate_binding(
        &self,
        binding: &DurableExportSealBinding,
    ) -> Result<(), DepositStateExportStoreError> {
        if binding.network != self.imported.network()
            || binding.wallet != self.imported.wallet()
            || binding.local_party != self.signer.party()
            || binding.local_signing_key != self.signer.signing_public_key()
            || binding.source != self.source.id()
            || binding.source_registry != self.source.digest()
            || binding.source_committee != self.source.active().committee().digest()
            || binding.source_fault_bound != self.source.active().fault_bound()
            || binding.source_certified_activation_root
                != self.source.active().certified_activation_root()
            || binding.handoff_statement != self.handoff.statement().digest()
            || binding.handoff_certificate
                != self
                    .handoff
                    .digest()
                    .map_err(|_| DepositStateExportStoreError::WrongAuthority)?
            || binding.target_epoch != self.imported.target_epoch()
            || binding.semantic_transition != self.imported.semantic_transition_digest()
            || binding.transition_binding != self.imported.transition_binding()
        {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        Ok(())
    }

    fn certificate(
        &self,
        snapshot: &DurableExportSealSnapshot,
    ) -> Result<VerifiedDepositPostHandoffExportSeal, DepositStateExportStoreError> {
        if snapshot.binding.source_party != self.signer.party() || !snapshot.pin_certified {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        let stored = snapshot
            .certificate
            .as_ref()
            .ok_or(DepositStateExportStoreError::CertificateIncomplete)?;
        let seal = DepositPostHandoffExportSealCertificate::from_bytes(&stored.bytes)?
            .verify(self.source, self.handoff)?;
        seal.validate_target(self.target)?;
        validate_stored_certificate(snapshot, &seal)?;
        let transition = VerifiedStateImportTransitionBinding::from_verified_export_seal(&seal)?;
        let binding = DurableExportSealBinding::from_statement(
            seal.statement(),
            self.source,
            self.handoff,
            self.signer,
            transition.transition_binding(),
        )?;
        if binding != snapshot.binding {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        Ok(seal)
    }
}

impl fmt::Debug for DepositStateExportSealAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DepositStateExportSealAuthority")
            .field("local_party", &self.signer.party())
            .field("source", &self.binding.source)
            .field("semantic_transition", &hex::encode(self.binding.semantic_transition))
            .field("statement", &hex::encode(self.binding.statement))
            .finish_non_exhaustive()
    }
}

impl<'a> DepositStateExportSealAuthority<'a> {
    /// Reconstruct serving-source authority after its exact export graph pin is durable.
    pub(crate) fn new_source(
        candidate: &'a VerifiedDepositPostHandoffExportCandidate,
        source: &'a CompactEpochRegistry,
        handoff: &'a RegistryHandoffCertificate,
        prepared_pin: &'a PreparedExportCandidatePin,
        signer: &'a dyn EnvelopeSigner,
    ) -> Result<Self, DepositStateExportStoreError> {
        let binding = DurableExportSealBinding::from_live(candidate, source, handoff, signer)?;
        prepared_pin.authorizes(candidate)?;
        if signer.party() != candidate.statement().source_party() {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        let authority = Self {
            candidate,
            source,
            handoff,
            signer,
            signing_gate: DepositStateExportSealSigningGate::Source(prepared_pin),
            binding,
        };
        authority.validate_live()?;
        Ok(authority)
    }

    /// Reconstruct a non-serving predecessor's authority from a settled, fully reauthenticated
    /// local portable state.
    pub(crate) fn new_remote(
        candidate: &'a VerifiedDepositPostHandoffExportCandidate,
        source: &'a CompactEpochRegistry,
        handoff: &'a RegistryHandoffCertificate,
        remote_gate: &'a VerifiedRemoteExportSealVoteGate,
        signer: &'a dyn EnvelopeSigner,
    ) -> Result<Self, DepositStateExportStoreError> {
        let binding = DurableExportSealBinding::from_live(candidate, source, handoff, signer)?;
        remote_gate.authorize(candidate, signer.party())?;
        let authority = Self {
            candidate,
            source,
            handoff,
            signer,
            signing_gate: DepositStateExportSealSigningGate::Remote(remote_gate),
            binding,
        };
        authority.validate_live()?;
        Ok(authority)
    }

    #[must_use]
    pub(crate) const fn local_party(&self) -> PartyId {
        self.binding.local_party
    }

    #[must_use]
    pub(crate) const fn source_party(&self) -> PartyId {
        self.binding.source_party
    }

    #[must_use]
    pub(crate) const fn semantic_transition_digest(&self) -> [u8; 32] {
        self.binding.semantic_transition
    }

    #[must_use]
    pub(crate) fn statement(&self) -> &DepositPostHandoffExportSealStatement {
        self.candidate.statement()
    }

    fn validate_live(&self) -> Result<(), DepositStateExportStoreError> {
        let reconstructed = DurableExportSealBinding::from_live(
            self.candidate,
            self.source,
            self.handoff,
            self.signer,
        )?;
        if reconstructed != self.binding {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        match self.signing_gate {
            DepositStateExportSealSigningGate::Source(prepared_pin) => {
                prepared_pin.authorizes(self.candidate)?;
                if self.signer.party() != self.candidate.statement().source_party() {
                    return Err(DepositStateExportStoreError::WrongAuthority);
                }
            }
            DepositStateExportSealSigningGate::Remote(remote_gate) => {
                remote_gate.authorize(self.candidate, self.signer.party())?;
                if self.signer.party() == self.candidate.statement().source_party() {
                    return Err(DepositStateExportStoreError::WrongAuthority);
                }
            }
        }
        Ok(())
    }

    fn sign_exact_envelope(
        &self,
    ) -> Result<crate::identity::SignedEnvelope, DepositStateExportStoreError> {
        self.validate_live()?;
        match self.signing_gate {
            DepositStateExportSealSigningGate::Source(prepared_pin) => {
                Ok(self.candidate.sign_as_source(self.signer, self.source, prepared_pin)?)
            }
            DepositStateExportSealSigningGate::Remote(remote_gate) => {
                Ok(self.candidate.sign_as_remote(self.signer, self.source, remote_gate)?)
            }
        }
    }

    fn is_source_authority(&self) -> bool {
        matches!(self.signing_gate, DepositStateExportSealSigningGate::Source(_))
    }

    fn required_votes(&self) -> Result<u16, DepositStateExportStoreError> {
        self.source
            .active()
            .committee()
            .n()
            .checked_sub(self.source.active().fault_bound())
            .ok_or(DepositStateExportStoreError::WrongAuthority)
    }
}

/// Re-authorized state of one durable export-seal slot.
#[derive(Clone, Debug)]
pub(crate) enum DepositStateExportSealStatus {
    Vacant,
    Collecting {
        votes: u16,
        required: u16,
        locally_signed: bool,
    },
    CertificateInstalled {
        seal: VerifiedDepositPostHandoffExportSeal,
        pin_certified: bool,
        terminal: bool,
    },
}

impl DepositStateExportSealStatus {
    #[must_use]
    pub(crate) const fn pin_certified(&self) -> bool {
        matches!(self, Self::CertificateInstalled { pin_certified: true, .. })
    }

    #[must_use]
    pub(crate) const fn seal(&self) -> Option<&VerifiedDepositPostHandoffExportSeal> {
        match self {
            Self::CertificateInstalled { seal, .. } => Some(seal),
            Self::Vacant | Self::Collecting { .. } => None,
        }
    }
}

/// Stable route for one exact, durably reconstructible export-seal transmission.
///
/// A locator deliberately carries no candidate evidence and is not an authorization capability.
/// The owning service first uses its projections to recover the corresponding live predecessor
/// history, then supplies fresh signing authority or finalized-import replay scope. `binding`
/// detects accidental or adversarial field splicing before a locator is used as a storage key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct DepositStateExportSealWorkLocator {
    kind: DepositStateExportSealWorkKind,
    snapshot: WalletId,
    network: [u8; 32],
    wallet: DepositWalletId,
    local_party: PartyId,
    source_party: PartyId,
    peer: PartyId,
    target_epoch: u64,
    semantic_transition: [u8; 32],
    statement: [u8; 32],
    primary: [u8; 32],
    secondary: [u8; 32],
    binding: [u8; 32],
}

/// Semantic work lane selected by an export-seal locator.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum DepositStateExportSealWorkKind {
    SourceRequest,
    LocalVote,
    CertificateDelivery,
}

impl DepositStateExportSealWorkKind {
    const fn tag(self) -> u8 {
        match self {
            Self::SourceRequest => 1,
            Self::LocalVote => 2,
            Self::CertificateDelivery => 3,
        }
    }
}

impl DepositStateExportSealWorkLocator {
    fn new(
        binding: &DurableExportSealBinding,
        kind: DepositStateExportSealWorkKind,
        peer: PartyId,
        primary: [u8; 32],
        secondary: [u8; 32],
    ) -> Result<Self, DepositStateExportStoreError> {
        binding.validate_static()?;
        let snapshot = export_seal_snapshot_id(binding)?;
        let mut locator = Self {
            kind,
            snapshot,
            network: binding.network,
            wallet: binding.wallet,
            local_party: binding.local_party,
            source_party: binding.source_party,
            peer,
            target_epoch: binding.target_epoch,
            semantic_transition: binding.semantic_transition,
            statement: binding.statement,
            primary,
            secondary,
            binding: [0; 32],
        };
        locator.validate_shape()?;
        locator.binding = locator.expected_binding();
        if locator.binding == [0; 32] {
            return Err(DepositStateExportStoreError::KeyDerivation);
        }
        Ok(locator)
    }

    fn expected_binding(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(EXPORT_SEAL_WORK_LOCATOR_DOMAIN);
        hasher.update(&[self.kind.tag()]);
        hasher.update(&self.snapshot.0);
        hasher.update(&self.network);
        hasher.update(&self.wallet.0);
        hasher.update(&self.local_party.0.to_le_bytes());
        hasher.update(&self.source_party.0.to_le_bytes());
        hasher.update(&self.peer.0.to_le_bytes());
        hasher.update(&self.target_epoch.to_le_bytes());
        hasher.update(&self.semantic_transition);
        hasher.update(&self.statement);
        hasher.update(&self.primary);
        hasher.update(&self.secondary);
        *hasher.finalize().as_bytes()
    }

    fn validate_shape(&self) -> Result<(), DepositStateExportStoreError> {
        if self.snapshot.0 == [0; 32]
            || self.network == [0; 32]
            || self.wallet.0 == [0; 32]
            || self.local_party == PartyId(0)
            || self.source_party == PartyId(0)
            || self.peer == PartyId(0)
            || self.target_epoch == 0
            || self.semantic_transition == [0; 32]
            || self.statement == [0; 32]
            || self.primary == [0; 32]
            || match self.kind {
                DepositStateExportSealWorkKind::SourceRequest => {
                    self.local_party != self.source_party
                        || self.peer == self.source_party
                        || self.secondary != [0; 32]
                }
                DepositStateExportSealWorkKind::LocalVote => {
                    self.local_party == self.source_party
                        || self.peer != self.local_party
                        || self.secondary == [0; 32]
                }
                DepositStateExportSealWorkKind::CertificateDelivery => {
                    self.local_party != self.source_party || self.secondary == [0; 32]
                }
            }
        {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        Ok(())
    }

    fn validate(
        &self,
        store: &DepositStateExportSealStore,
        binding: &DurableExportSealBinding,
    ) -> Result<(), DepositStateExportStoreError> {
        self.validate_shape()?;
        if self.binding == [0; 32]
            || self.binding != self.expected_binding()
            || self.snapshot != export_seal_snapshot_id(binding)?
            || self.network != store.network
            || self.network != binding.network
            || self.wallet != store.wallet
            || self.wallet != binding.wallet
            || self.local_party != store.local_party
            || self.local_party != binding.local_party
            || self.source_party != binding.source_party
            || self.target_epoch != binding.target_epoch
            || self.semantic_transition != binding.semantic_transition
            || self.statement != binding.statement
        {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        Ok(())
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> DepositStateExportSealWorkKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn network(&self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub(crate) const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub(crate) const fn local_party(&self) -> PartyId {
        self.local_party
    }

    #[must_use]
    pub(crate) const fn source_party(&self) -> PartyId {
        self.source_party
    }

    #[must_use]
    pub(crate) const fn peer(&self) -> PartyId {
        self.peer
    }

    #[must_use]
    pub(crate) const fn target_epoch(&self) -> u64 {
        self.target_epoch
    }

    #[must_use]
    pub(crate) const fn semantic_transition_digest(&self) -> [u8; 32] {
        self.semantic_transition
    }

    #[must_use]
    pub(crate) const fn statement_digest(&self) -> [u8; 32] {
        self.statement
    }

    #[must_use]
    pub(crate) const fn primary_digest(&self) -> [u8; 32] {
        self.primary
    }

    #[must_use]
    pub(crate) const fn secondary_digest(&self) -> [u8; 32] {
        self.secondary
    }
}

/// One encrypted, authenticated CAS journal per exact semantic export slot.
///
/// The owning service must keep exactly one cached handle for a party while holding that party's
/// process-wide [`crate::storage::PartyStateLease`]. The in-memory mutation lock serializes tasks
/// inside that fenced writer; opening an unfenced second process with the same signing key and
/// state directory is outside the protocol invariant.
pub(crate) struct DepositStateExportSealStore {
    snapshots: Arc<WalletSnapshotStore>,
    network: [u8; 32],
    wallet: DepositWalletId,
    local_party: PartyId,
    mutation: Mutex<()>,
}

impl fmt::Debug for DepositStateExportSealStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DepositStateExportSealStore")
            .field("wallet", &self.wallet)
            .field("local_party", &self.local_party)
            .finish_non_exhaustive()
    }
}

impl DepositStateExportSealStore {
    /// Open the clean-v7 namespace.  There are no legacy decoders or migrations.
    pub(crate) fn open(
        directory: impl Into<PathBuf>,
        network: [u8; 32],
        wallet: DepositWalletId,
        local_party: PartyId,
        identity_seed: &[u8; 32],
    ) -> Result<Self, DepositStateExportStoreError> {
        if network == [0; 32]
            || wallet.0 == [0; 32]
            || local_party == PartyId(0)
            || identity_seed == &[0; 32]
        {
            return Err(DepositStateExportStoreError::InvalidContext);
        }
        Ok(Self {
            snapshots: Arc::new(WalletSnapshotStore::new(directory, local_party, identity_seed)?),
            network,
            wallet,
            local_party,
            mutation: Mutex::new(()),
        })
    }

    /// Journal and sign the serving source's mandatory self-vote.
    ///
    /// The common multi-megabyte candidate evidence is committed once in this slot before the
    /// source envelope can escape. Callers use the returned envelope to build every voter-specific
    /// request; those requests never cause another durable copy of the evidence.
    pub(crate) async fn sign_or_replay_source_vote(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        evidence: &DepositPostHandoffExportCandidateEvidence,
    ) -> Result<SignedEnvelope, DepositStateExportStoreError> {
        self.ensure_source_aggregator(authority)?;
        evidence.validate_for_candidate(authority.candidate)?;
        let durable_evidence = DurableExportCandidateEvidence::from_live(authority, evidence)?;
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let mut loaded = self.load_optional(snapshot_id).await?;
        let mut snapshot = match loaded.as_ref() {
            Some(loaded) => {
                loaded.snapshot.validate_with_authority(authority)?;
                loaded.snapshot.clone()
            }
            None => DurableExportSealSnapshot::new(&authority.binding),
        };
        if snapshot.terminal {
            return Err(DepositStateExportStoreError::WorkAlreadyComplete);
        }
        snapshot.install_common_evidence(durable_evidence, None, authority)?;
        if let Some(stored) = snapshot.source_self_vote.as_ref() {
            return stored.reconstruct(authority);
        }

        let envelope = authority.sign_exact_envelope()?;
        let stored = DurableSourceSelfVote::from_live(authority, envelope)?;
        snapshot.source_self_vote = Some(stored);
        snapshot.install_source_request_work(authority)?;
        snapshot.install_certificate_if_ready(authority)?;
        self.persist(&mut loaded, snapshot_id, &snapshot).await?;
        snapshot
            .source_self_vote
            .as_ref()
            .ok_or(DepositStateExportStoreError::InvalidDurableState)?
            .reconstruct(authority)
    }

    /// Sign or replay this non-serving predecessor member's exact vote.
    ///
    /// The newly created signed envelope is inserted into the encrypted snapshot and its CAS is
    /// durable before this function returns it.  An exact retry returns the stored, reverified
    /// vote.  Another statement in the same vote slot is rejected permanently.
    pub(crate) async fn sign_or_replay_vote(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        request: &DepositPostHandoffExportSealRequest,
    ) -> Result<DepositPostHandoffExportSealVote, DepositStateExportStoreError> {
        self.ensure_authority(authority)?;
        if authority.is_source_authority() || self.local_party == authority.source_party() {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        validate_request(authority, request, self.local_party)?;
        let durable_evidence =
            DurableExportCandidateEvidence::from_live(authority, request.evidence())?;
        let source_self_vote =
            DurableSourceSelfVote::from_live(authority, request.source_self_vote().clone())?;
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let mut loaded = self.load_optional(snapshot_id).await?;
        let mut snapshot = match loaded.as_ref() {
            Some(loaded) => {
                loaded.snapshot.validate_with_authority(authority)?;
                loaded.snapshot.clone()
            }
            None => DurableExportSealSnapshot::new(&authority.binding),
        };
        if snapshot.terminal {
            return Err(DepositStateExportStoreError::WorkAlreadyComplete);
        }
        snapshot.install_common_evidence(durable_evidence, Some(source_self_vote), authority)?;

        if let Some(stored) = snapshot.local_vote.as_ref() {
            if stored.request_digest != request.digest() {
                return Err(DepositStateExportStoreError::PermanentEquivocation);
            }
            return stored.reconstruct(authority, &snapshot);
        }

        let envelope = authority.sign_exact_envelope()?;
        let vote = DepositPostHandoffExportSealVote::new(request, envelope)?;
        let stored = DurableExportSealVote::from_wire(request, &vote)?;
        stored.verify_live(authority, &snapshot)?;
        snapshot.local_vote = Some(stored);
        snapshot.install_certificate_if_ready(authority)?;
        self.persist(&mut loaded, snapshot_id, &snapshot).await?;

        snapshot
            .local_vote
            .as_ref()
            .ok_or(DepositStateExportStoreError::InvalidDurableState)?
            .reconstruct(authority, &snapshot)
    }

    /// Persist one transport-authenticated predecessor vote.
    ///
    /// Only the source named by the exact statement aggregates votes.  Votes are retained in
    /// canonical party order and a deterministic `n-f` witness subset (which always includes the
    /// serving source) is certified in the same CAS as the completing vote.
    pub(crate) async fn record_vote(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        request: &DepositPostHandoffExportSealRequest,
        authenticated_voter: PartyId,
        vote: &DepositPostHandoffExportSealVote,
    ) -> Result<DepositStateExportSealStatus, DepositStateExportStoreError> {
        self.ensure_source_aggregator(authority)?;
        if authenticated_voter == PartyId(0) || authenticated_voter == authority.source_party() {
            return Err(DepositStateExportStoreError::WrongVote);
        }
        validate_request(authority, request, authenticated_voter)?;
        let incoming = DurableExportSealVote::from_wire(request, vote)?;
        if incoming.voter != authenticated_voter {
            return Err(DepositStateExportStoreError::WrongVote);
        }
        let durable_evidence =
            DurableExportCandidateEvidence::from_live(authority, request.evidence())?;
        let source_self_vote =
            DurableSourceSelfVote::from_live(authority, request.source_self_vote().clone())?;

        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let mut loaded = self
            .load_optional(snapshot_id)
            .await?
            .ok_or(DepositStateExportStoreError::UnjournaledLocalVote)?;
        loaded.snapshot.validate_with_authority(authority)?;
        let mut snapshot = loaded.snapshot.clone();
        if snapshot.terminal {
            return snapshot.status(authority);
        }
        snapshot.install_common_evidence(durable_evidence, Some(source_self_vote), authority)?;
        if snapshot.source_self_vote.is_none() {
            return Err(DepositStateExportStoreError::UnjournaledLocalVote);
        }
        incoming.verify_live(authority, &snapshot)?;

        let changed = match snapshot
            .remote_votes
            .binary_search_by_key(&authenticated_voter, |stored| stored.voter)
        {
            Ok(index) if snapshot.remote_votes[index] == incoming => false,
            Ok(_) => return Err(DepositStateExportStoreError::ConflictingVote),
            Err(index) => {
                if snapshot.total_votes() >= MAX_COMMITTEE_MEMBERS {
                    return Err(DepositStateExportStoreError::TooManyVotes);
                }
                snapshot.remote_votes.insert(index, incoming);
                true
            }
        };

        let installed = snapshot.install_certificate_if_ready(authority)?;
        if changed || installed {
            self.persist_existing(&mut loaded, snapshot_id, &snapshot).await?;
        }
        snapshot.status(authority)
    }

    /// Install an independently delivered, fully verified old-quorum seal.
    ///
    /// This supports predecessor members which did not participate in the selected `n-f` witness
    /// subset.  Once one exact canonical certificate is installed, a different witness-set
    /// encoding for the same statement is rejected rather than silently changing restart state.
    pub(crate) async fn install_certificate(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<DepositStateExportSealStatus, DepositStateExportStoreError> {
        self.ensure_authority(authority)?;
        validate_verified_seal(authority, seal)?;
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let mut loaded = self.load_optional(snapshot_id).await?;
        let mut snapshot = match loaded.as_ref() {
            Some(loaded) => {
                loaded.snapshot.validate_with_authority(authority)?;
                loaded.snapshot.clone()
            }
            None => DurableExportSealSnapshot::new(&authority.binding),
        };
        if snapshot.certificate.is_none()
            && authority.is_source_authority()
            && (snapshot.source_self_vote.is_none() || snapshot.evidence.is_none())
        {
            return Err(DepositStateExportStoreError::UnjournaledLocalVote);
        }
        let canonical = DurableExportSealCertificate::from_verified(seal)?;
        match snapshot.certificate.as_ref() {
            Some(existing) if existing == &canonical => {}
            Some(_) => return Err(DepositStateExportStoreError::ConflictingCertificate),
            None => {
                snapshot.certificate = Some(canonical);
                self.persist(&mut loaded, snapshot_id, &snapshot).await?;
            }
        }
        snapshot.status(authority)
    }

    /// Retain a verified certificate without signing or substituting local archive witnesses.
    /// Existing votes are preserved. A serving source can only replay its already certified pin.
    pub(crate) async fn retain_certificate(
        &self,
        seal: &VerifiedDepositPostHandoffExportSeal,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        signer: &dyn EnvelopeSigner,
    ) -> Result<(), DepositStateExportStoreError> {
        let verified = seal.certificate().verify(source, handoff)?;
        if verified.canonical_certificate_bytes() != seal.canonical_certificate_bytes() {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        let transition =
            VerifiedStateImportTransitionBinding::from_verified_export_seal(&verified)?;
        let binding = DurableExportSealBinding::from_statement(
            verified.statement(),
            source,
            handoff,
            signer,
            transition.transition_binding(),
        )?;
        if binding.network != self.network
            || binding.wallet != self.wallet
            || binding.local_party != self.local_party
        {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        let id = export_seal_snapshot_id(&binding)?;
        let _guard = self.mutation.lock().await;
        let mut loaded = self.load_optional(id).await?;
        let mut snapshot = match &loaded {
            Some(loaded) if loaded.snapshot.binding == binding => loaded.snapshot.clone(),
            Some(_) => return Err(DepositStateExportStoreError::WrongAuthority),
            None => DurableExportSealSnapshot::new(&binding),
        };
        let certificate = DurableExportSealCertificate::from_verified(&verified)?;
        if binding.source_party == self.local_party
            && (!snapshot.pin_certified || snapshot.certificate.as_ref() != Some(&certificate))
        {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        match &snapshot.certificate {
            Some(existing) if existing == &certificate => return Ok(()),
            Some(_) => return Err(DepositStateExportStoreError::ConflictingCertificate),
            None => snapshot.certificate = Some(certificate),
        }
        self.persist(&mut loaded, id, &snapshot).await
    }

    /// Reconstruct the exact certificate only under fresh predecessor authority.
    pub(crate) async fn certificate(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<Option<VerifiedDepositPostHandoffExportSeal>, DepositStateExportStoreError> {
        self.ensure_authority(authority)?;
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let Some(loaded) = self.load_optional(snapshot_id).await? else {
            return Ok(None);
        };
        loaded.snapshot.validate_with_authority(authority)?;
        loaded
            .snapshot
            .certificate
            .as_ref()
            .map(|certificate| certificate.reconstruct(authority))
            .transpose()
    }

    /// Recover bounded per-source journal work after graph reclamation, including a crash
    /// between certificate persistence and fanout initialization.
    pub(crate) async fn pending_finalized_replay(
        &self,
        replay: &DepositStateExportSealReplay<'_>,
    ) -> Result<Vec<DepositStateExportSealWorkLocator>, DepositStateExportStoreError> {
        let _guard = self.mutation.lock().await;
        let mut pending = Vec::new();
        for member in &replay.source.active().committee().members {
            let id = replay.snapshot_id(self, member.id)?;
            let Some(mut loaded) = self.load_optional(id).await? else { continue };
            replay.validate_binding(&loaded.snapshot.binding)?;
            if member.id == self.local_party {
                if loaded.snapshot.certificate.is_none() {
                    continue;
                }
                let seal = replay.certificate(&loaded.snapshot)?;
                let expected = certificate_recipients(replay.source, &seal, replay.target)?;
                let mut changed = false;
                if loaded.snapshot.certificate_recipients.is_empty() {
                    loaded.snapshot.certificate_recipients = expected;
                    changed = true;
                } else {
                    validate_exact_fanout(&loaded.snapshot.certificate_recipients, &expected)?;
                }
                if !loaded.snapshot.terminal
                    && loaded
                        .snapshot
                        .certificate_recipients
                        .iter()
                        .all(|r| r.acknowledgement.is_some())
                {
                    loaded.snapshot.clear_terminal_voting_evidence();
                    changed = true;
                }
                if changed {
                    let snapshot = loaded.snapshot.clone();
                    self.persist_existing(&mut loaded, id, &snapshot).await?;
                }
                pending.extend(pending_certificate_locators(&loaded.snapshot)?);
            } else if let Some(locator) = loaded.snapshot.local_vote_locator()? {
                pending.push(locator);
            }
        }
        pending.sort_unstable();
        Ok(pending)
    }

    /// Reauthenticate an existing signed message; optionally persist its exact peer receipt.
    /// No signing capability is constructed, and no current export graph is reopened.
    pub(crate) async fn finalized_replay(
        &self,
        replay: &DepositStateExportSealReplay<'_>,
        locator: DepositStateExportSealWorkLocator,
        receipt: Option<(PartyId, &[u8])>,
    ) -> Result<Vec<u8>, DepositStateExportStoreError> {
        let id = replay.snapshot_id(self, locator.source_party)?;
        if id != locator.snapshot {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        let _guard = self.mutation.lock().await;
        let mut loaded =
            self.load_optional(id).await?.ok_or(DepositStateExportStoreError::UnknownSealSlot)?;
        replay.validate_binding(&loaded.snapshot.binding)?;
        locator.validate(self, &loaded.snapshot.binding)?;
        let snapshot = &mut loaded.snapshot;
        let mut changed = false;
        let body = match locator.kind {
            DepositStateExportSealWorkKind::SourceRequest => {
                return Err(DepositStateExportStoreError::WorkAlreadyComplete);
            }
            DepositStateExportSealWorkKind::LocalVote => {
                if locator.source_party == self.local_party || locator.peer != self.local_party {
                    return Err(DepositStateExportStoreError::InvalidWorkLocator);
                }
                if receipt.is_none() && snapshot.local_vote_locator()? != Some(locator) {
                    return Err(DepositStateExportStoreError::WorkAlreadyComplete);
                }
                let stored = snapshot
                    .evidence
                    .as_ref()
                    .ok_or(DepositStateExportStoreError::WorkAlreadyComplete)?;
                let (evidence, candidate) =
                    DepositPostHandoffExportCandidateEvidence::from_bytes_verified(
                        &stored.bytes,
                        self.network,
                        locator.source_party,
                        replay.source,
                        replay.handoff,
                        replay.target,
                    )?;
                let binding = DurableExportSealBinding::from_live(
                    &candidate,
                    replay.source,
                    replay.handoff,
                    replay.signer,
                )?;
                if binding != snapshot.binding || evidence.digest() != stored.digest {
                    return Err(DepositStateExportStoreError::InvalidDurableState);
                }
                let source_vote = snapshot
                    .source_self_vote
                    .as_ref()
                    .ok_or(DepositStateExportStoreError::InvalidDurableState)?;
                let request = DepositPostHandoffExportSealRequest::new(
                    &candidate,
                    self.local_party,
                    evidence,
                    source_vote.envelope.clone(),
                )?;
                request.verify_and_reconstruct_candidate(
                    self.network,
                    replay.source,
                    replay.handoff,
                    replay.target,
                )?;
                let stored_vote = snapshot
                    .local_vote
                    .as_ref()
                    .ok_or(DepositStateExportStoreError::WorkAlreadyComplete)?;
                let vote = DepositPostHandoffExportSealVote::from_bytes(
                    &request,
                    self.local_party,
                    &stored_vote.vote,
                )?;
                let committee = replay.source.active().committee();
                Identity::verify_envelope(committee, self.local_party, vote.envelope())
                    .map_err(|_| DepositStateExportStoreError::WrongVote)?;
                let expected = DepositStateExportSealWorkLocator::new(
                    &binding,
                    DepositStateExportSealWorkKind::LocalVote,
                    self.local_party,
                    request.digest(),
                    vote.digest(),
                )?;
                if locator != expected
                    || stored_vote.request_digest != request.digest()
                    || stored_vote.vote_digest != vote.digest()
                    || stored_vote.voter != self.local_party
                {
                    return Err(DepositStateExportStoreError::InvalidWorkLocator);
                }
                if let Some((peer, bytes)) = receipt {
                    if peer != locator.source_party {
                        return Err(DepositStateExportStoreError::WrongAcknowledgementPeer);
                    }
                    let ack =
                        DepositPostHandoffExportSealVoteAck::from_bytes(&request, &vote, bytes)?;
                    let durable = DurableExportSealVoteAck::from_live(&request, &vote, ack)?;
                    if snapshot.local_vote_ack.is_some_and(|existing| existing != durable) {
                        return Err(DepositStateExportStoreError::ConflictingAcknowledgement);
                    }
                    changed = snapshot.local_vote_ack.is_none();
                    snapshot.local_vote_ack = Some(durable);
                }
                vote.to_bytes(&request)?
            }
            DepositStateExportSealWorkKind::CertificateDelivery => {
                if locator.source_party != self.local_party || !snapshot.pin_certified {
                    return Err(DepositStateExportStoreError::WrongAuthority);
                }
                let seal = replay.certificate(snapshot)?;
                let expected = certificate_recipients(replay.source, &seal, replay.target)?;
                validate_exact_fanout(&snapshot.certificate_recipients, &expected)?;
                let recipient = *find_certificate_recipient(snapshot, locator.peer)?;
                if snapshot.certificate_delivery_locator(&recipient)? != locator {
                    return Err(DepositStateExportStoreError::InvalidWorkLocator);
                }
                if receipt.is_none() && (snapshot.terminal || recipient.acknowledgement.is_some()) {
                    return Err(DepositStateExportStoreError::WorkAlreadyComplete);
                }
                let delivery = recipient.delivery(&seal)?;
                if let Some((peer, bytes)) = receipt {
                    if peer != locator.peer {
                        return Err(DepositStateExportStoreError::WrongAcknowledgementPeer);
                    }
                    let ack =
                        DepositPostHandoffExportSealCertificateAck::from_bytes(&delivery, bytes)?;
                    if recipient.acknowledgement.is_some_and(|existing| existing != ack) {
                        return Err(DepositStateExportStoreError::ConflictingAcknowledgement);
                    }
                    let index = snapshot
                        .certificate_recipients
                        .binary_search_by_key(&peer, |r| r.recipient)
                        .map_err(|_| DepositStateExportStoreError::InvalidWorkLocator)?;
                    changed = recipient.acknowledgement.is_none();
                    snapshot.certificate_recipients[index].acknowledgement = Some(ack);
                    if snapshot.certificate_recipients.iter().all(|r| r.acknowledgement.is_some()) {
                        snapshot.clear_terminal_voting_evidence();
                    }
                }
                delivery.to_bytes()?
            }
        };
        if changed {
            let snapshot = loaded.snapshot.clone();
            self.persist_existing(&mut loaded, id, &snapshot).await?;
        }
        Ok(body)
    }

    /// Recover the exact source evidence from the witness-independent vote slot. The lookup
    /// candidate identifies only the slot; it does not authorize the stored export bytes.
    pub(crate) async fn recover_remote_request(
        &self,
        lookup_candidate: &VerifiedDepositPostHandoffExportCandidate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target: &VerifiedRegistryHandoffTarget,
        signer: &dyn EnvelopeSigner,
        pending_only: bool,
    ) -> Result<Option<DepositPostHandoffExportSealRequest>, DepositStateExportStoreError> {
        let lookup =
            DurableExportSealBinding::from_live(lookup_candidate, source, handoff, signer)?;
        if lookup.network != self.network
            || lookup.wallet != self.wallet
            || lookup.local_party != self.local_party
            || lookup.source_party == self.local_party
        {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        let snapshot_id = export_seal_snapshot_id(&lookup)?;
        let _guard = self.mutation.lock().await;
        let Some(loaded) = self.load_optional(snapshot_id).await? else {
            return Ok(None);
        };
        if !loaded.snapshot.binding.same_slot(&lookup) {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        if loaded.snapshot.terminal || loaded.snapshot.local_vote.is_none() {
            return Ok(None);
        }
        if pending_only && loaded.snapshot.local_vote_locator()?.is_none() {
            return Ok(None);
        }
        let stored = loaded
            .snapshot
            .evidence
            .as_ref()
            .ok_or(DepositStateExportStoreError::InvalidDurableState)?;
        let (evidence, candidate) = DepositPostHandoffExportCandidateEvidence::from_bytes_verified(
            &stored.bytes,
            self.network,
            lookup.source_party,
            source,
            handoff,
            target,
        )?;
        let binding = DurableExportSealBinding::from_live(&candidate, source, handoff, signer)?;
        if binding != loaded.snapshot.binding || evidence.digest() != stored.digest {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        let source_vote = loaded
            .snapshot
            .source_self_vote
            .as_ref()
            .ok_or(DepositStateExportStoreError::InvalidDurableState)?;
        let request = DepositPostHandoffExportSealRequest::new(
            &candidate,
            self.local_party,
            evidence,
            source_vote.envelope.clone(),
        )?;
        request.verify_and_reconstruct_candidate(self.network, source, handoff, target)?;
        Ok(Some(request))
    }

    /// Re-open the non-source member's exact durably journaled outbound request/vote pair.
    ///
    /// The transport pacemaker calls this after restart and retransmits the same bytes until the
    /// source acknowledges them. No new signature is produced on this recovery path.
    pub(crate) async fn local_vote(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<
        Option<(DepositPostHandoffExportSealRequest, DepositPostHandoffExportSealVote)>,
        DepositStateExportStoreError,
    > {
        self.ensure_authority(authority)?;
        if authority.is_source_authority() || self.local_party == authority.source_party() {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let Some(loaded) = self.load_optional(snapshot_id).await? else {
            return Ok(None);
        };
        loaded.snapshot.validate_with_authority(authority)?;
        if loaded.snapshot.local_vote_locator()?.is_none() {
            return Ok(None);
        }
        let Some(stored) = loaded.snapshot.local_vote.as_ref() else {
            return Ok(None);
        };
        let request = loaded.snapshot.reconstruct_request(authority, self.local_party)?;
        let vote = stored.reconstruct(authority, &loaded.snapshot)?;
        Ok(Some((request, vote)))
    }

    /// Journal that the exact certified seal has been attached to the permanent source pin.
    ///
    /// `StoredExportPin` cannot be constructed by wire or snapshot bytes and is returned only by
    /// the retention store.  Requiring it prevents a crash-recovery marker from claiming that the
    /// graph is certified before the independent retention transaction commits.
    pub(crate) async fn mark_pin_certified(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        seal: &VerifiedDepositPostHandoffExportSeal,
        certified_pin: &StoredExportPin,
    ) -> Result<DepositStateExportSealStatus, DepositStateExportStoreError> {
        self.ensure_source_aggregator(authority)?;
        validate_verified_seal(authority, seal)?;
        validate_certified_pin(authority, seal, certified_pin)?;
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let mut loaded = self
            .load_optional(snapshot_id)
            .await?
            .ok_or(DepositStateExportStoreError::UnknownSealSlot)?;
        loaded.snapshot.validate_with_authority(authority)?;
        let stored = loaded
            .snapshot
            .certificate
            .as_ref()
            .ok_or(DepositStateExportStoreError::CertificateIncomplete)?;
        if stored.certificate_digest != seal.certificate_digest()
            || stored.statement != seal.statement_digest()
            || stored.bytes.as_slice() != seal.canonical_certificate_bytes()
        {
            return Err(DepositStateExportStoreError::ConflictingCertificate);
        }
        if !loaded.snapshot.pin_certified {
            loaded.snapshot.pin_certified = true;
            let snapshot = loaded.snapshot.clone();
            self.persist_existing(&mut loaded, snapshot_id, &snapshot).await?;
        }
        loaded.snapshot.status(authority)
    }

    /// Re-open and fully re-authenticate durable state after a restart.
    pub(crate) async fn recover(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<DepositStateExportSealStatus, DepositStateExportStoreError> {
        self.ensure_authority(authority)?;
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let Some(loaded) = self.load_optional(snapshot_id).await? else {
            return Ok(DepositStateExportSealStatus::Vacant);
        };
        loaded.snapshot.validate_with_authority(authority)?;
        loaded.snapshot.status(authority)
    }

    /// Reconstruct one voter-specific request from the source's already durable common evidence
    /// and mandatory self-vote.
    ///
    /// This is the restart path for a persistent sender: callers do not need to retain or rebuild
    /// the multi-megabyte evidence body in memory after `sign_or_replay_source_vote` commits it.
    pub(crate) async fn source_request(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        voter: PartyId,
    ) -> Result<DepositPostHandoffExportSealRequest, DepositStateExportStoreError> {
        self.ensure_source_aggregator(authority)?;
        if voter == authority.source_party()
            || authority.source.active().committee().member(voter).is_err()
        {
            return Err(DepositStateExportStoreError::WrongRequest);
        }
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let loaded = self
            .load_optional(snapshot_id)
            .await?
            .ok_or(DepositStateExportStoreError::UnknownSealSlot)?;
        loaded.snapshot.validate_with_authority(authority)?;
        loaded.snapshot.reconstruct_request(authority, voter)
    }

    /// Enumerate the source's bounded, restart-safe request work.
    ///
    /// A voter remains pending until its exact vote is durable. A request acknowledgement alone
    /// cannot suppress this work, and certification terminally suppresses all remaining
    /// solicitations.
    pub(crate) async fn pending_source_requests(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<Vec<DepositStateExportSealWorkLocator>, DepositStateExportStoreError> {
        self.ensure_source_aggregator(authority)?;
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let loaded = self
            .load_optional(snapshot_id)
            .await?
            .ok_or(DepositStateExportStoreError::UnknownSealSlot)?;
        loaded.snapshot.validate_work_index_with_authority(authority)?;
        if loaded.snapshot.terminal || loaded.snapshot.certificate.is_some() {
            return Ok(Vec::new());
        }
        let mut pending = Vec::with_capacity(loaded.snapshot.source_requests.len());
        for work in &loaded.snapshot.source_requests {
            if loaded
                .snapshot
                .remote_votes
                .binary_search_by_key(&work.voter, |stored| stored.voter)
                .is_err()
            {
                pending.push(loaded.snapshot.source_request_locator(work.voter)?);
            }
        }
        Ok(pending)
    }

    /// Reconstruct the exact source request named by a locator under fresh live authority.
    pub(crate) async fn source_request_for_locator(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        locator: DepositStateExportSealWorkLocator,
    ) -> Result<DepositPostHandoffExportSealRequest, DepositStateExportStoreError> {
        self.ensure_source_aggregator(authority)?;
        locator.validate(self, &authority.binding)?;
        if locator.kind != DepositStateExportSealWorkKind::SourceRequest {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        let _guard = self.mutation.lock().await;
        let loaded = self
            .load_optional(locator.snapshot)
            .await?
            .ok_or(DepositStateExportStoreError::UnknownSealSlot)?;
        loaded.snapshot.validate_work_index_with_authority(authority)?;
        if loaded.snapshot.terminal || loaded.snapshot.certificate.is_some() {
            return Err(DepositStateExportStoreError::WorkAlreadyComplete);
        }
        if loaded
            .snapshot
            .remote_votes
            .binary_search_by_key(&locator.peer, |stored| stored.voter)
            .is_ok()
        {
            return Err(DepositStateExportStoreError::WorkAlreadyComplete);
        }
        let expected = loaded.snapshot.source_request_locator(locator.peer)?;
        if locator != expected {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        loaded.snapshot.reconstruct_request(authority, locator.peer)
    }

    /// Locate this non-source member's one unacknowledged durable request/vote pair.
    pub(crate) async fn local_vote_locator(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<Option<DepositStateExportSealWorkLocator>, DepositStateExportStoreError> {
        self.ensure_remote_voter(authority)?;
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let Some(loaded) = self.load_optional(snapshot_id).await? else {
            return Ok(None);
        };
        loaded.snapshot.validate_work_index_with_authority(authority)?;
        loaded.snapshot.local_vote_locator()
    }

    /// Reconstruct the exact request/vote pair named by a locator.
    ///
    /// The locator itself is untrusted route material. Reconstructing the multi-megabyte request
    /// always reauthenticates its one durable evidence copy against `authority`.
    pub(crate) async fn local_vote_for_locator(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        locator: DepositStateExportSealWorkLocator,
    ) -> Result<
        (DepositPostHandoffExportSealRequest, DepositPostHandoffExportSealVote),
        DepositStateExportStoreError,
    > {
        self.ensure_remote_voter(authority)?;
        locator.validate(self, &authority.binding)?;
        if locator.kind != DepositStateExportSealWorkKind::LocalVote {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        let _guard = self.mutation.lock().await;
        let loaded = self
            .load_optional(locator.snapshot)
            .await?
            .ok_or(DepositStateExportStoreError::UnknownSealSlot)?;
        loaded.snapshot.validate_with_authority(authority)?;
        let expected = loaded
            .snapshot
            .local_vote_locator()?
            .ok_or(DepositStateExportStoreError::WorkAlreadyComplete)?;
        if locator != expected {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        let stored = loaded
            .snapshot
            .local_vote
            .as_ref()
            .ok_or(DepositStateExportStoreError::InvalidDurableState)?;
        let request = loaded.snapshot.reconstruct_request(authority, self.local_party)?;
        let vote = stored.reconstruct(authority, &loaded.snapshot)?;
        Ok((request, vote))
    }

    /// Persist the source's exact receipt for this member's durable vote.
    ///
    /// The receipt is a tombstone: exact replay is idempotent and a different receipt can never
    /// replace it. It stops retransmission only after the receipt CAS commits.
    pub(crate) async fn acknowledge_local_vote(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        authenticated_source: PartyId,
        locator: DepositStateExportSealWorkLocator,
        acknowledgement: DepositPostHandoffExportSealVoteAck,
    ) -> Result<(), DepositStateExportStoreError> {
        self.ensure_remote_voter(authority)?;
        if authenticated_source != authority.source_party() {
            return Err(DepositStateExportStoreError::WrongAcknowledgementPeer);
        }
        locator.validate(self, &authority.binding)?;
        if locator.kind != DepositStateExportSealWorkKind::LocalVote {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        let _guard = self.mutation.lock().await;
        let mut loaded = self
            .load_optional(locator.snapshot)
            .await?
            .ok_or(DepositStateExportStoreError::UnknownSealSlot)?;
        loaded.snapshot.validate_with_authority(authority)?;
        if let Some(existing) = loaded.snapshot.local_vote_ack {
            let expected = DepositStateExportSealWorkLocator::new(
                &loaded.snapshot.binding,
                DepositStateExportSealWorkKind::LocalVote,
                loaded.snapshot.binding.local_party,
                existing.request_digest,
                existing.vote_digest,
            )?;
            if locator != expected || existing.acknowledgement != acknowledgement {
                return Err(DepositStateExportStoreError::ConflictingAcknowledgement);
            }
            return Ok(());
        }
        let stored = loaded
            .snapshot
            .local_vote
            .as_ref()
            .ok_or(DepositStateExportStoreError::WorkAlreadyComplete)?;
        let request = loaded.snapshot.reconstruct_request(authority, self.local_party)?;
        let vote = stored.reconstruct(authority, &loaded.snapshot)?;
        let expected = DepositStateExportSealWorkLocator::new(
            &loaded.snapshot.binding,
            DepositStateExportSealWorkKind::LocalVote,
            self.local_party,
            request.digest(),
            vote.digest(),
        )?;
        if locator != expected {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        loaded.snapshot.local_vote_ack =
            Some(DurableExportSealVoteAck::from_live(&request, &vote, acknowledgement)?);
        let snapshot = loaded.snapshot.clone();
        self.persist_existing(&mut loaded, locator.snapshot, &snapshot).await
    }

    /// Initialize and enumerate exact old∪target certificate fanout.
    ///
    /// The local party is intentionally retained in the recipient set. If it overlaps the target
    /// committee, its delivery must remain pending until the service durably seeds the target's
    /// pre-`ExportHead` intent and then records the ordinary exact delivery acknowledgement.
    pub(crate) async fn prepare_certificate_fanout(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        seal: &VerifiedDepositPostHandoffExportSeal,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Vec<DepositStateExportSealWorkLocator>, DepositStateExportStoreError> {
        self.ensure_source_aggregator(authority)?;
        validate_verified_seal(authority, seal)?;
        validate_fanout_target(authority, target)?;
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let mut loaded = self
            .load_optional(snapshot_id)
            .await?
            .ok_or(DepositStateExportStoreError::UnknownSealSlot)?;
        loaded.snapshot.validate_with_authority(authority)?;
        validate_stored_certificate(&loaded.snapshot, seal)?;
        if !loaded.snapshot.pin_certified {
            return Err(DepositStateExportStoreError::FanoutNotReady);
        }
        let expected = certificate_fanout_recipients(authority, seal, target)?;
        if loaded.snapshot.certificate_recipients.is_empty() {
            loaded.snapshot.certificate_recipients = expected;
            let snapshot = loaded.snapshot.clone();
            self.persist_existing(&mut loaded, snapshot_id, &snapshot).await?;
        } else {
            validate_exact_fanout(&loaded.snapshot.certificate_recipients, &expected)?;
        }
        pending_certificate_locators(&loaded.snapshot)
    }

    /// Re-enumerate the exact unacknowledged certificate fanout after restart.
    pub(crate) async fn pending_certificate_recipients(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        seal: &VerifiedDepositPostHandoffExportSeal,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Vec<DepositStateExportSealWorkLocator>, DepositStateExportStoreError> {
        self.ensure_source_aggregator(authority)?;
        validate_verified_seal(authority, seal)?;
        validate_fanout_target(authority, target)?;
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let loaded = self
            .load_optional(snapshot_id)
            .await?
            .ok_or(DepositStateExportStoreError::UnknownSealSlot)?;
        loaded.snapshot.validate_with_authority(authority)?;
        validate_stored_certificate(&loaded.snapshot, seal)?;
        let expected = certificate_fanout_recipients(authority, seal, target)?;
        if loaded.snapshot.certificate_recipients.is_empty() {
            return Err(DepositStateExportStoreError::FanoutNotReady);
        }
        validate_exact_fanout(&loaded.snapshot.certificate_recipients, &expected)?;
        pending_certificate_locators(&loaded.snapshot)
    }

    /// Reconstruct one exact certificate delivery from its durable locator.
    pub(crate) async fn certificate_delivery_for_locator(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        seal: &VerifiedDepositPostHandoffExportSeal,
        target: &VerifiedRegistryHandoffTarget,
        locator: DepositStateExportSealWorkLocator,
    ) -> Result<DepositPostHandoffExportSealCertificateDelivery, DepositStateExportStoreError> {
        self.ensure_source_aggregator(authority)?;
        validate_verified_seal(authority, seal)?;
        validate_fanout_target(authority, target)?;
        locator.validate(self, &authority.binding)?;
        if locator.kind != DepositStateExportSealWorkKind::CertificateDelivery {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        let _guard = self.mutation.lock().await;
        let loaded = self
            .load_optional(locator.snapshot)
            .await?
            .ok_or(DepositStateExportStoreError::UnknownSealSlot)?;
        loaded.snapshot.validate_with_authority(authority)?;
        validate_stored_certificate(&loaded.snapshot, seal)?;
        let expected = certificate_fanout_recipients(authority, seal, target)?;
        validate_exact_fanout(&loaded.snapshot.certificate_recipients, &expected)?;
        let recipient = find_certificate_recipient(&loaded.snapshot, locator.peer)?;
        if recipient.acknowledgement.is_some() {
            return Err(DepositStateExportStoreError::WorkAlreadyComplete);
        }
        if loaded.snapshot.certificate_delivery_locator(recipient)? != locator {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        recipient.delivery(seal)
    }

    /// Persist one exact certificate-delivery acknowledgement.
    pub(crate) async fn acknowledge_certificate_delivery(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        seal: &VerifiedDepositPostHandoffExportSeal,
        target: &VerifiedRegistryHandoffTarget,
        authenticated_recipient: PartyId,
        locator: DepositStateExportSealWorkLocator,
        acknowledgement: DepositPostHandoffExportSealCertificateAck,
    ) -> Result<(), DepositStateExportStoreError> {
        self.ensure_source_aggregator(authority)?;
        validate_verified_seal(authority, seal)?;
        validate_fanout_target(authority, target)?;
        locator.validate(self, &authority.binding)?;
        if locator.kind != DepositStateExportSealWorkKind::CertificateDelivery {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        if authenticated_recipient != locator.peer {
            return Err(DepositStateExportStoreError::WrongAcknowledgementPeer);
        }
        let _guard = self.mutation.lock().await;
        let mut loaded = self
            .load_optional(locator.snapshot)
            .await?
            .ok_or(DepositStateExportStoreError::UnknownSealSlot)?;
        loaded.snapshot.validate_with_authority(authority)?;
        validate_stored_certificate(&loaded.snapshot, seal)?;
        let expected = certificate_fanout_recipients(authority, seal, target)?;
        validate_exact_fanout(&loaded.snapshot.certificate_recipients, &expected)?;
        let index = loaded
            .snapshot
            .certificate_recipients
            .binary_search_by_key(&locator.peer, |recipient| recipient.recipient)
            .map_err(|_| DepositStateExportStoreError::InvalidWorkLocator)?;
        let recipient = loaded.snapshot.certificate_recipients[index];
        if loaded.snapshot.certificate_delivery_locator(&recipient)? != locator {
            return Err(DepositStateExportStoreError::InvalidWorkLocator);
        }
        let delivery = recipient.delivery(seal)?;
        acknowledgement.to_bytes(&delivery)?;
        match recipient.acknowledgement {
            Some(existing) if existing == acknowledgement => return Ok(()),
            Some(_) => return Err(DepositStateExportStoreError::ConflictingAcknowledgement),
            None => {}
        }
        loaded.snapshot.certificate_recipients[index].acknowledgement = Some(acknowledgement);
        let snapshot = loaded.snapshot.clone();
        self.persist_existing(&mut loaded, locator.snapshot, &snapshot).await
    }

    /// Terminalize a completely acknowledged source fanout and discard bulky voting evidence.
    pub(crate) async fn terminalize_certificate_fanout(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        seal: &VerifiedDepositPostHandoffExportSeal,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<DepositStateExportSealStatus, DepositStateExportStoreError> {
        self.ensure_source_aggregator(authority)?;
        validate_verified_seal(authority, seal)?;
        validate_fanout_target(authority, target)?;
        let snapshot_id = export_seal_snapshot_id(&authority.binding)?;
        let _guard = self.mutation.lock().await;
        let mut loaded = self
            .load_optional(snapshot_id)
            .await?
            .ok_or(DepositStateExportStoreError::UnknownSealSlot)?;
        loaded.snapshot.validate_with_authority(authority)?;
        validate_stored_certificate(&loaded.snapshot, seal)?;
        let expected = certificate_fanout_recipients(authority, seal, target)?;
        validate_exact_fanout(&loaded.snapshot.certificate_recipients, &expected)?;
        if !loaded.snapshot.pin_certified
            || loaded.snapshot.certificate_recipients.is_empty()
            || loaded
                .snapshot
                .certificate_recipients
                .iter()
                .any(|recipient| recipient.acknowledgement.is_none())
        {
            return Err(DepositStateExportStoreError::FanoutIncomplete);
        }
        if !loaded.snapshot.terminal {
            loaded.snapshot.clear_terminal_voting_evidence();
            let snapshot = loaded.snapshot.clone();
            self.persist_existing(&mut loaded, snapshot_id, &snapshot).await?;
        }
        loaded.snapshot.status(authority)
    }

    fn ensure_authority(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<(), DepositStateExportStoreError> {
        authority.validate_live()?;
        if authority.binding.network != self.network
            || authority.binding.wallet != self.wallet
            || authority.binding.local_party != self.local_party
        {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        Ok(())
    }

    fn ensure_remote_voter(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<(), DepositStateExportStoreError> {
        self.ensure_authority(authority)?;
        if authority.is_source_authority() || self.local_party == authority.source_party() {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        Ok(())
    }

    fn ensure_source_aggregator(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<(), DepositStateExportStoreError> {
        self.ensure_authority(authority)?;
        if self.local_party != authority.binding.source_party || !authority.is_source_authority() {
            return Err(DepositStateExportStoreError::NotSourceAggregator);
        }
        Ok(())
    }

    async fn load_optional(
        &self,
        snapshot_id: WalletId,
    ) -> Result<Option<LoadedExportSealSnapshot>, DepositStateExportStoreError> {
        let path = self.snapshots.wallet_snapshot_path(snapshot_id);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Err(DepositStateExportStoreError::StorageConflict(path)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let loaded = self.snapshots.load_snapshot(snapshot_id).await?;
        let snapshot = decode_canonical::<DurableExportSealSnapshot>(
            loaded.state.as_bytes(),
            MAX_EXPORT_SEAL_STORE_SNAPSHOT_BYTES,
        )?;
        snapshot.validate_static(self.network, self.wallet, self.local_party, snapshot_id)?;
        Ok(Some(LoadedExportSealSnapshot { metadata: loaded.metadata, snapshot }))
    }

    async fn persist(
        &self,
        loaded: &mut Option<LoadedExportSealSnapshot>,
        snapshot_id: WalletId,
        snapshot: &DurableExportSealSnapshot,
    ) -> Result<(), DepositStateExportStoreError> {
        snapshot.validate_static(self.network, self.wallet, self.local_party, snapshot_id)?;
        let bytes = encode_canonical(snapshot, MAX_EXPORT_SEAL_STORE_SNAPSHOT_BYTES)?;
        let revision = match loaded.as_ref() {
            Some(loaded) => loaded
                .metadata
                .revision
                .checked_add(1)
                .ok_or(DepositStateExportStoreError::RevisionExhausted)?,
            None => 0,
        };
        let metadata =
            self.snapshots.save_snapshot(snapshot_id, revision, &bytes, &mut OsRng).await?;
        *loaded = Some(LoadedExportSealSnapshot { metadata, snapshot: snapshot.clone() });
        Ok(())
    }

    async fn persist_existing(
        &self,
        loaded: &mut LoadedExportSealSnapshot,
        snapshot_id: WalletId,
        snapshot: &DurableExportSealSnapshot,
    ) -> Result<(), DepositStateExportStoreError> {
        snapshot.validate_static(self.network, self.wallet, self.local_party, snapshot_id)?;
        let bytes = encode_canonical(snapshot, MAX_EXPORT_SEAL_STORE_SNAPSHOT_BYTES)?;
        let revision = loaded
            .metadata
            .revision
            .checked_add(1)
            .ok_or(DepositStateExportStoreError::RevisionExhausted)?;
        let metadata =
            self.snapshots.save_snapshot(snapshot_id, revision, &bytes, &mut OsRng).await?;
        loaded.metadata = metadata;
        loaded.snapshot = snapshot.clone();
        Ok(())
    }
}

fn validate_fanout_target(
    authority: &DepositStateExportSealAuthority<'_>,
    target: &VerifiedRegistryHandoffTarget,
) -> Result<(), DepositStateExportStoreError> {
    authority.validate_live()?;
    let statement = authority.statement();
    target
        .committee()
        .validate_async_security_with_faults(target.fault_bound())
        .map_err(|_| DepositStateExportStoreError::WrongFanoutTarget)?;
    if target.wallet() != authority.binding.wallet
        || target.committee().epoch != authority.binding.target_epoch
        || target.committee().digest() != statement.target_committee()
        || target.fault_bound() != statement.target_fault_bound()
        || target.key_id() != statement.target_key_id()
        || target.group_key() != statement.target_group_key()
        || target.activation() != statement.target_activation()
        || target.certified_activation_root() != statement.target_certified_activation_root()
    {
        return Err(DepositStateExportStoreError::WrongFanoutTarget);
    }
    Ok(())
}

fn validate_stored_certificate(
    snapshot: &DurableExportSealSnapshot,
    seal: &VerifiedDepositPostHandoffExportSeal,
) -> Result<(), DepositStateExportStoreError> {
    let stored =
        snapshot.certificate.as_ref().ok_or(DepositStateExportStoreError::CertificateIncomplete)?;
    if stored.statement != seal.statement_digest()
        || stored.certificate_digest != seal.certificate_digest()
        || stored.bytes.as_slice() != seal.canonical_certificate_bytes()
    {
        return Err(DepositStateExportStoreError::ConflictingCertificate);
    }
    Ok(())
}

fn certificate_fanout_recipients(
    authority: &DepositStateExportSealAuthority<'_>,
    seal: &VerifiedDepositPostHandoffExportSeal,
    target: &VerifiedRegistryHandoffTarget,
) -> Result<Vec<DurableExportSealCertificateRecipient>, DepositStateExportStoreError> {
    validate_verified_seal(authority, seal)?;
    validate_fanout_target(authority, target)?;
    certificate_recipients(authority.source, seal, target)
}

fn certificate_recipients(
    source: &CompactEpochRegistry,
    seal: &VerifiedDepositPostHandoffExportSeal,
    target: &VerifiedRegistryHandoffTarget,
) -> Result<Vec<DurableExportSealCertificateRecipient>, DepositStateExportStoreError> {
    let recipients = source
        .active()
        .committee()
        .members
        .iter()
        .chain(target.committee().members.iter())
        .map(|member| member.id)
        .collect::<BTreeSet<_>>();
    if recipients.is_empty() || recipients.len() > MAX_EXPORT_SEAL_CERTIFICATE_RECIPIENTS {
        return Err(DepositStateExportStoreError::InvalidDurableState);
    }
    recipients
        .into_iter()
        .map(|recipient| DurableExportSealCertificateRecipient::new(seal, recipient))
        .collect()
}

fn validate_exact_fanout(
    actual: &[DurableExportSealCertificateRecipient],
    expected: &[DurableExportSealCertificateRecipient],
) -> Result<(), DepositStateExportStoreError> {
    if actual.len() != expected.len()
        || actual.iter().zip(expected).any(|(actual, expected)| {
            actual.recipient != expected.recipient
                || actual.certificate_digest != expected.certificate_digest
                || actual.delivery_digest != expected.delivery_digest
        })
    {
        return Err(DepositStateExportStoreError::ConflictingCertificateFanout);
    }
    Ok(())
}

fn pending_certificate_locators(
    snapshot: &DurableExportSealSnapshot,
) -> Result<Vec<DepositStateExportSealWorkLocator>, DepositStateExportStoreError> {
    if snapshot.terminal {
        return Ok(Vec::new());
    }
    snapshot
        .certificate_recipients
        .iter()
        .filter(|recipient| recipient.acknowledgement.is_none())
        .map(|recipient| snapshot.certificate_delivery_locator(recipient))
        .collect()
}

fn find_certificate_recipient(
    snapshot: &DurableExportSealSnapshot,
    recipient: PartyId,
) -> Result<&DurableExportSealCertificateRecipient, DepositStateExportStoreError> {
    let index = snapshot
        .certificate_recipients
        .binary_search_by_key(&recipient, |entry| entry.recipient)
        .map_err(|_| DepositStateExportStoreError::InvalidWorkLocator)?;
    Ok(&snapshot.certificate_recipients[index])
}

#[derive(Clone, Debug)]
struct LoadedExportSealSnapshot {
    metadata: WalletSnapshotMetadata,
    snapshot: DurableExportSealSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableExportSealBinding {
    network: [u8; 32],
    wallet: DepositWalletId,
    local_party: PartyId,
    local_signing_key: [u8; 32],
    source: RegistryId,
    source_registry: [u8; 32],
    source_committee: [u8; 32],
    source_fault_bound: u16,
    source_certified_activation_root: [u8; 32],
    handoff_statement: [u8; 32],
    handoff_certificate: [u8; 32],
    source_party: PartyId,
    target_epoch: u64,
    semantic_transition: [u8; 32],
    transition_binding: [u8; 32],
    vote_slot: [u8; 32],
    statement: [u8; 32],
    advertisement: [u8; 32],
    export_binding: [u8; 32],
}

impl DurableExportSealBinding {
    fn from_live(
        candidate: &VerifiedDepositPostHandoffExportCandidate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        signer: &dyn EnvelopeSigner,
    ) -> Result<Self, DepositStateExportStoreError> {
        let transition =
            VerifiedStateImportCandidateTransitionBinding::from_verified_export_candidate(
                candidate,
            )?;
        Self::from_statement(
            candidate.statement(),
            source,
            handoff,
            signer,
            transition.transition_binding(),
        )
    }

    fn from_statement(
        statement: &DepositPostHandoffExportSealStatement,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        signer: &dyn EnvelopeSigner,
        transition_binding: [u8; 32],
    ) -> Result<Self, DepositStateExportStoreError> {
        statement.validate_against(source, handoff)?;
        if !matches!(signer.scope(), EnvelopeSignerScope::Full | EnvelopeSignerScope::HandoffOnly) {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        let member = source
            .active()
            .committee()
            .member(signer.party())
            .map_err(|_| DepositStateExportStoreError::WrongAuthority)?;
        if member.signing_key != signer.signing_public_key() {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        let final_export = statement.final_export();
        let binding = Self {
            network: statement.network(),
            wallet: statement.source().wallet(),
            local_party: signer.party(),
            local_signing_key: signer.signing_public_key(),
            source: source.id(),
            source_registry: source.digest(),
            source_committee: source.active().committee().digest(),
            source_fault_bound: source.active().fault_bound(),
            source_certified_activation_root: source.active().certified_activation_root(),
            handoff_statement: statement.handoff_statement_digest(),
            handoff_certificate: handoff
                .digest()
                .map_err(|_| DepositStateExportStoreError::WrongAuthority)?,
            source_party: statement.source_party(),
            target_epoch: statement.target_epoch(),
            semantic_transition: statement.semantic_transition_digest(),
            transition_binding,
            vote_slot: statement.vote_slot_digest(),
            statement: statement.digest(),
            advertisement: final_export.advertisement_digest(),
            export_binding: final_export.digest()?,
        };
        binding.validate_static()?;
        binding.validate_statement(statement)?;
        Ok(binding)
    }

    fn validate_static(&self) -> Result<(), DepositStateExportStoreError> {
        self.source.validate().map_err(|_| DepositStateExportStoreError::InvalidDurableState)?;
        if self.network == [0; 32]
            || self.wallet.0 == [0; 32]
            || self.local_party == PartyId(0)
            || self.local_signing_key == [0; 32]
            || self.source.wallet() != self.wallet
            || self.source_registry == [0; 32]
            || self.source_registry != self.source.digest()
            || self.source_committee == [0; 32]
            || self.source_certified_activation_root == [0; 32]
            || self.handoff_statement == [0; 32]
            || self.handoff_certificate == [0; 32]
            || self.source_party == PartyId(0)
            || self.source.active_epoch().checked_add(1) != Some(self.target_epoch)
            || self.semantic_transition == [0; 32]
            || self.transition_binding == [0; 32]
            || self.vote_slot == [0; 32]
            || self.statement == [0; 32]
            || self.advertisement == [0; 32]
            || self.export_binding == [0; 32]
        {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        Ok(())
    }

    fn validate_statement(
        &self,
        statement: &DepositPostHandoffExportSealStatement,
    ) -> Result<(), DepositStateExportStoreError> {
        let export = statement.final_export();
        if statement.network() != self.network
            || statement.source().wallet() != self.wallet
            || statement.source() != self.source
            || statement.source_committee() != self.source_committee
            || statement.source_fault_bound() != self.source_fault_bound
            || statement.source_certified_activation_root() != self.source_certified_activation_root
            || statement.handoff_statement_digest() != self.handoff_statement
            || statement.handoff_certificate_digest() != self.handoff_certificate
            || statement.source_party() != self.source_party
            || statement.target_epoch() != self.target_epoch
            || statement.semantic_transition_digest() != self.semantic_transition
            || statement.vote_slot_digest() != self.vote_slot
            || statement.digest() != self.statement
            || export.advertisement_digest() != self.advertisement
            || export.digest()? != self.export_binding
        {
            return Err(DepositStateExportStoreError::PermanentEquivocation);
        }
        Ok(())
    }

    fn same_slot(&self, other: &Self) -> bool {
        self.network == other.network
            && self.wallet == other.wallet
            && self.local_party == other.local_party
            && self.source == other.source
            && self.source_party == other.source_party
            && self.target_epoch == other.target_epoch
            && self.semantic_transition == other.semantic_transition
            && self.transition_binding == other.transition_binding
            && self.vote_slot == other.vote_slot
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableExportCandidateEvidence {
    digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_candidate_evidence_bytes")]
    bytes: Vec<u8>,
}

impl DurableExportCandidateEvidence {
    fn from_live(
        authority: &DepositStateExportSealAuthority<'_>,
        evidence: &DepositPostHandoffExportCandidateEvidence,
    ) -> Result<Self, DepositStateExportStoreError> {
        evidence.validate_for_candidate(authority.candidate)?;
        let durable =
            Self { digest: evidence.digest(), bytes: evidence.to_bytes(authority.candidate)? };
        durable.reconstruct(authority)?;
        Ok(durable)
    }

    fn validate_static(&self) -> Result<(), DepositStateExportStoreError> {
        if self.digest == [0; 32]
            || self.bytes.is_empty()
            || self.bytes.len() > MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_BYTES
        {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        Ok(())
    }

    fn reconstruct(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<DepositPostHandoffExportCandidateEvidence, DepositStateExportStoreError> {
        self.validate_static()?;
        let evidence = DepositPostHandoffExportCandidateEvidence::from_bytes(
            authority.candidate,
            &self.bytes,
        )?;
        if evidence.digest() != self.digest {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        Ok(evidence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableSourceSelfVote {
    envelope: SignedEnvelope,
}

impl DurableSourceSelfVote {
    fn from_live(
        authority: &DepositStateExportSealAuthority<'_>,
        envelope: SignedEnvelope,
    ) -> Result<Self, DepositStateExportStoreError> {
        let vote = Self { envelope };
        vote.verify_live(authority)?;
        Ok(vote)
    }

    fn verify_live(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<(), DepositStateExportStoreError> {
        let statement = authority.statement();
        if self.envelope.from != authority.source_party()
            || self.envelope.to.is_some()
            || self.envelope.session != statement.session()
            || self.envelope.sequence != statement.final_export().terminal_checkpoint().sequence()
            || self.envelope.payload != statement.signing_payload()
        {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        let verifier = authority
            .source
            .active()
            .committee()
            .members
            .first()
            .ok_or(DepositStateExportStoreError::WrongAuthority)?
            .id;
        Identity::verify_envelope(authority.source.active().committee(), verifier, &self.envelope)
            .map_err(|_| DepositStateExportStoreError::WrongVote)
    }

    fn reconstruct(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<SignedEnvelope, DepositStateExportStoreError> {
        self.verify_live(authority)?;
        Ok(self.envelope.clone())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableSourceRequestWork {
    voter: PartyId,
    request_digest: [u8; 32],
}

impl DurableSourceRequestWork {
    fn validate_static(&self) -> Result<(), DepositStateExportStoreError> {
        if self.voter == PartyId(0) || self.request_digest == [0; 32] {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableExportSealVote {
    voter: PartyId,
    request_digest: [u8; 32],
    vote_digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_seal_vote_bytes")]
    vote: Vec<u8>,
}

impl DurableExportSealVote {
    fn from_wire(
        request: &DepositPostHandoffExportSealRequest,
        vote: &DepositPostHandoffExportSealVote,
    ) -> Result<Self, DepositStateExportStoreError> {
        let stored = Self {
            voter: vote.voter(),
            request_digest: request.digest(),
            vote_digest: vote.digest(),
            vote: vote.to_bytes(request)?,
        };
        stored.validate_static()?;
        Ok(stored)
    }

    fn validate_static(&self) -> Result<(), DepositStateExportStoreError> {
        if self.voter == PartyId(0)
            || self.request_digest == [0; 32]
            || self.vote_digest == [0; 32]
            || self.vote.is_empty()
            || self.vote.len() > MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES
        {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        Ok(())
    }

    fn verify_live(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        snapshot: &DurableExportSealSnapshot,
    ) -> Result<(), DepositStateExportStoreError> {
        self.validate_static()?;
        let request = snapshot.reconstruct_request(authority, self.voter)?;
        if request.digest() != self.request_digest {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        validate_request(authority, &request, self.voter)?;
        let vote = DepositPostHandoffExportSealVote::from_bytes(&request, self.voter, &self.vote)?;
        if vote.digest() != self.vote_digest || vote.voter() != self.voter {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        verify_vote_signature(authority, &vote)
    }

    fn reconstruct(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        snapshot: &DurableExportSealSnapshot,
    ) -> Result<DepositPostHandoffExportSealVote, DepositStateExportStoreError> {
        self.verify_live(authority, snapshot)?;
        let request = snapshot.reconstruct_request(authority, self.voter)?;
        Ok(DepositPostHandoffExportSealVote::from_bytes(&request, self.voter, &self.vote)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableExportSealCertificate {
    statement: [u8; 32],
    certificate_digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_seal_certificate_bytes")]
    bytes: Vec<u8>,
}

impl DurableExportSealCertificate {
    fn from_verified(
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<Self, DepositStateExportStoreError> {
        let certificate = Self {
            statement: seal.statement_digest(),
            certificate_digest: seal.certificate_digest(),
            bytes: seal.canonical_certificate_bytes().to_vec(),
        };
        certificate.validate_static(None)?;
        Ok(certificate)
    }

    fn validate_static(
        &self,
        binding: Option<&DurableExportSealBinding>,
    ) -> Result<(), DepositStateExportStoreError> {
        if self.statement == [0; 32]
            || self.certificate_digest == [0; 32]
            || self.bytes.is_empty()
            || self.bytes.len() > MAX_POST_HANDOFF_EXPORT_SEAL_BYTES
        {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        let certificate = DepositPostHandoffExportSealCertificate::from_bytes(&self.bytes)?;
        if certificate.statement().digest() != self.statement
            || certificate.digest()? != self.certificate_digest
        {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        if let Some(binding) = binding {
            binding.validate_statement(certificate.statement())?;
        }
        Ok(())
    }

    fn reconstruct(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<VerifiedDepositPostHandoffExportSeal, DepositStateExportStoreError> {
        self.validate_static(Some(&authority.binding))?;
        let seal = DepositPostHandoffExportSealCertificate::from_bytes(&self.bytes)?
            .verify(authority.source, authority.handoff)?;
        validate_verified_seal(authority, &seal)?;
        if seal.statement_digest() != self.statement
            || seal.certificate_digest() != self.certificate_digest
            || seal.canonical_certificate_bytes() != self.bytes
        {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        Ok(seal)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableExportSealVoteAck {
    request_digest: [u8; 32],
    vote_digest: [u8; 32],
    acknowledgement: DepositPostHandoffExportSealVoteAck,
}

impl DurableExportSealVoteAck {
    fn from_live(
        request: &DepositPostHandoffExportSealRequest,
        vote: &DepositPostHandoffExportSealVote,
        acknowledgement: DepositPostHandoffExportSealVoteAck,
    ) -> Result<Self, DepositStateExportStoreError> {
        acknowledgement.to_bytes(request, vote)?;
        let durable =
            Self { request_digest: request.digest(), vote_digest: vote.digest(), acknowledgement };
        durable.validate_static()?;
        Ok(durable)
    }

    fn validate_static(&self) -> Result<(), DepositStateExportStoreError> {
        if self.request_digest == [0; 32] || self.vote_digest == [0; 32] {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        Ok(())
    }

    fn verify_live(
        &self,
        request: &DepositPostHandoffExportSealRequest,
        vote: &DepositPostHandoffExportSealVote,
    ) -> Result<(), DepositStateExportStoreError> {
        self.validate_static()?;
        if self.request_digest != request.digest() || self.vote_digest != vote.digest() {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        self.acknowledgement.to_bytes(request, vote)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableExportSealCertificateRecipient {
    recipient: PartyId,
    certificate_digest: [u8; 32],
    delivery_digest: [u8; 32],
    acknowledgement: Option<DepositPostHandoffExportSealCertificateAck>,
}

impl DurableExportSealCertificateRecipient {
    fn new(
        seal: &VerifiedDepositPostHandoffExportSeal,
        recipient: PartyId,
    ) -> Result<Self, DepositStateExportStoreError> {
        let delivery =
            DepositPostHandoffExportSealCertificateDelivery::from_verified(seal, recipient)?;
        let durable = Self {
            recipient,
            certificate_digest: seal.certificate_digest(),
            delivery_digest: delivery.digest(),
            acknowledgement: None,
        };
        durable.validate_static()?;
        Ok(durable)
    }

    fn validate_static(&self) -> Result<(), DepositStateExportStoreError> {
        if self.recipient == PartyId(0)
            || self.certificate_digest == [0; 32]
            || self.delivery_digest == [0; 32]
        {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        Ok(())
    }

    fn delivery(
        &self,
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<DepositPostHandoffExportSealCertificateDelivery, DepositStateExportStoreError> {
        self.validate_static()?;
        let delivery =
            DepositPostHandoffExportSealCertificateDelivery::from_verified(seal, self.recipient)?;
        if self.certificate_digest != seal.certificate_digest()
            || self.delivery_digest != delivery.digest()
        {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        if let Some(acknowledgement) = self.acknowledgement {
            acknowledgement.to_bytes(&delivery)?;
        }
        Ok(delivery)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableExportSealSnapshot {
    version: u16,
    domain: [u8; 16],
    binding: DurableExportSealBinding,
    evidence: Option<DurableExportCandidateEvidence>,
    source_self_vote: Option<DurableSourceSelfVote>,
    #[serde(deserialize_with = "deserialize_source_request_work")]
    source_requests: Vec<DurableSourceRequestWork>,
    local_vote: Option<DurableExportSealVote>,
    #[serde(deserialize_with = "deserialize_remote_votes")]
    remote_votes: Vec<DurableExportSealVote>,
    certificate: Option<DurableExportSealCertificate>,
    local_vote_ack: Option<DurableExportSealVoteAck>,
    #[serde(deserialize_with = "deserialize_certificate_recipients")]
    certificate_recipients: Vec<DurableExportSealCertificateRecipient>,
    pin_certified: bool,
    terminal: bool,
}

impl DurableExportSealSnapshot {
    /// Called only after exact source fanout verification and durable receipt completion.
    fn clear_terminal_voting_evidence(&mut self) {
        self.evidence = None;
        self.source_self_vote = None;
        self.source_requests.clear();
        self.local_vote = None;
        self.remote_votes.clear();
        self.terminal = true;
    }

    fn new(binding: &DurableExportSealBinding) -> Self {
        Self {
            version: EXPORT_SEAL_STORE_VERSION,
            domain: EXPORT_SEAL_STORE_DOMAIN,
            binding: binding.clone(),
            evidence: None,
            source_self_vote: None,
            source_requests: Vec::new(),
            local_vote: None,
            remote_votes: Vec::new(),
            certificate: None,
            local_vote_ack: None,
            certificate_recipients: Vec::new(),
            pin_certified: false,
            terminal: false,
        }
    }

    fn total_votes(&self) -> usize {
        self.source_self_vote.is_some() as usize
            + self.local_vote.is_some() as usize
            + self.remote_votes.len()
    }

    fn source_request_locator(
        &self,
        voter: PartyId,
    ) -> Result<DepositStateExportSealWorkLocator, DepositStateExportStoreError> {
        let index = self
            .source_requests
            .binary_search_by_key(&voter, |work| work.voter)
            .map_err(|_| DepositStateExportStoreError::InvalidDurableState)?;
        DepositStateExportSealWorkLocator::new(
            &self.binding,
            DepositStateExportSealWorkKind::SourceRequest,
            voter,
            self.source_requests[index].request_digest,
            [0; 32],
        )
    }

    fn local_vote_locator(
        &self,
    ) -> Result<Option<DepositStateExportSealWorkLocator>, DepositStateExportStoreError> {
        if self.terminal
            || self.certificate.is_some()
            || self.local_vote_ack.is_some()
            || self.local_vote.is_none()
        {
            return Ok(None);
        }
        let vote =
            self.local_vote.as_ref().ok_or(DepositStateExportStoreError::InvalidDurableState)?;
        Ok(Some(DepositStateExportSealWorkLocator::new(
            &self.binding,
            DepositStateExportSealWorkKind::LocalVote,
            self.binding.local_party,
            vote.request_digest,
            vote.vote_digest,
        )?))
    }

    fn certificate_delivery_locator(
        &self,
        recipient: &DurableExportSealCertificateRecipient,
    ) -> Result<DepositStateExportSealWorkLocator, DepositStateExportStoreError> {
        DepositStateExportSealWorkLocator::new(
            &self.binding,
            DepositStateExportSealWorkKind::CertificateDelivery,
            recipient.recipient,
            recipient.certificate_digest,
            recipient.delivery_digest,
        )
    }

    fn install_common_evidence(
        &mut self,
        evidence: DurableExportCandidateEvidence,
        source_self_vote: Option<DurableSourceSelfVote>,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<(), DepositStateExportStoreError> {
        evidence.reconstruct(authority)?;
        match self.evidence.as_ref() {
            Some(existing) if existing != &evidence => {
                return Err(DepositStateExportStoreError::PermanentEquivocation);
            }
            Some(_) => {}
            None => self.evidence = Some(evidence),
        }
        if let Some(source_self_vote) = source_self_vote {
            source_self_vote.verify_live(authority)?;
            match self.source_self_vote.as_ref() {
                Some(existing) if existing != &source_self_vote => {
                    return Err(DepositStateExportStoreError::PermanentEquivocation);
                }
                Some(_) => {}
                None => self.source_self_vote = Some(source_self_vote),
            }
        }
        Ok(())
    }

    fn install_source_request_work(
        &mut self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<(), DepositStateExportStoreError> {
        if authority.local_party() != authority.source_party()
            || self.evidence.is_none()
            || self.source_self_vote.is_none()
        {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        let mut expected = authority
            .source
            .active()
            .committee()
            .members
            .iter()
            .map(|member| member.id)
            .filter(|voter| *voter != authority.source_party())
            .map(|voter| {
                Ok(DurableSourceRequestWork {
                    voter,
                    request_digest: self.reconstruct_request(authority, voter)?.digest(),
                })
            })
            .collect::<Result<Vec<_>, DepositStateExportStoreError>>()?;
        expected.sort_by_key(|work| work.voter);
        if self.source_requests.is_empty() {
            self.source_requests = expected;
        } else if self.source_requests != expected {
            return Err(DepositStateExportStoreError::PermanentEquivocation);
        }
        Ok(())
    }

    fn reconstruct_request(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
        voter: PartyId,
    ) -> Result<DepositPostHandoffExportSealRequest, DepositStateExportStoreError> {
        let evidence = self
            .evidence
            .as_ref()
            .ok_or(DepositStateExportStoreError::InvalidDurableState)?
            .reconstruct(authority)?;
        let source_self_vote = self
            .source_self_vote
            .as_ref()
            .ok_or(DepositStateExportStoreError::InvalidDurableState)?
            .reconstruct(authority)?;
        Ok(DepositPostHandoffExportSealRequest::new(
            authority.candidate,
            voter,
            evidence,
            source_self_vote,
        )?)
    }

    fn validate_static(
        &self,
        network: [u8; 32],
        wallet: DepositWalletId,
        local_party: PartyId,
        snapshot_id: WalletId,
    ) -> Result<(), DepositStateExportStoreError> {
        self.binding.validate_static()?;
        validate_pin_certification_role(
            self.pin_certified,
            self.certificate.is_some(),
            self.binding.local_party,
            self.binding.source_party,
        )?;
        if self.version != EXPORT_SEAL_STORE_VERSION
            || self.domain != EXPORT_SEAL_STORE_DOMAIN
            || self.binding.network != network
            || self.binding.wallet != wallet
            || self.binding.local_party != local_party
            || export_seal_snapshot_id(&self.binding)? != snapshot_id
            || self.total_votes() > MAX_COMMITTEE_MEMBERS
            || self.source_requests.len() > MAX_COMMITTEE_MEMBERS.saturating_sub(1)
            || self.evidence.is_some() != self.source_self_vote.is_some()
            || (self.local_vote.is_some() || !self.remote_votes.is_empty())
                && (self.evidence.is_none() || self.source_self_vote.is_none())
            || self.binding.local_party == self.binding.source_party && self.local_vote.is_some()
            || self.binding.local_party != self.binding.source_party
                && !self.remote_votes.is_empty()
            || self.binding.local_party != self.binding.source_party
                && !self.source_requests.is_empty()
            || !self.source_requests.is_empty()
                && (self.evidence.is_none() || self.source_self_vote.is_none())
            || self.binding.local_party == self.binding.source_party
                && self.certificate.is_some()
                && self.source_self_vote.is_none()
                && !self.terminal
            || self.local_vote_ack.is_some()
                && (self.binding.local_party == self.binding.source_party
                    || self.local_vote.is_none() && !self.terminal)
            || !self.certificate_recipients.is_empty()
                && (self.binding.local_party != self.binding.source_party
                    || self.certificate.is_none()
                    || !self.pin_certified)
            || self.certificate_recipients.len() > MAX_EXPORT_SEAL_CERTIFICATE_RECIPIENTS
            || self.terminal
                && (self.certificate.is_none()
                    || self.evidence.is_some()
                    || self.source_self_vote.is_some()
                    || !self.source_requests.is_empty()
                    || self.local_vote.is_some()
                    || !self.remote_votes.is_empty())
            || self.terminal
                && self.binding.local_party == self.binding.source_party
                && (!self.pin_certified
                    || self.certificate_recipients.is_empty()
                    || self
                        .certificate_recipients
                        .iter()
                        .any(|recipient| recipient.acknowledgement.is_none()))
            || self.source_self_vote.is_none()
                && self.local_vote.is_none()
                && self.remote_votes.is_empty()
                && self.certificate.is_none()
        {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        if let Some(evidence) = self.evidence.as_ref() {
            evidence.validate_static()?;
        }
        if let Some(source_self_vote) = self.source_self_vote.as_ref() {
            if source_self_vote.envelope.from != self.binding.source_party
                || source_self_vote.envelope.to.is_some()
                || source_self_vote.envelope.payload.as_slice() != self.binding.statement.as_slice()
            {
                return Err(DepositStateExportStoreError::InvalidDurableState);
            }
        }
        let mut previous_request_voter = None;
        for request in &self.source_requests {
            request.validate_static()?;
            if request.voter == self.binding.source_party
                || previous_request_voter.is_some_and(|previous| previous >= request.voter)
            {
                return Err(DepositStateExportStoreError::InvalidDurableState);
            }
            previous_request_voter = Some(request.voter);
        }
        if let Some(local) = self.local_vote.as_ref() {
            if local.voter != local_party {
                return Err(DepositStateExportStoreError::InvalidDurableState);
            }
            local.validate_static()?;
        }
        let mut previous = None;
        for remote in &self.remote_votes {
            if remote.voter == self.binding.source_party
                || remote.voter == local_party
                || previous.is_some_and(|party| party >= remote.voter)
            {
                return Err(DepositStateExportStoreError::InvalidDurableState);
            }
            remote.validate_static()?;
            previous = Some(remote.voter);
        }
        if let Some(certificate) = self.certificate.as_ref() {
            certificate.validate_static(Some(&self.binding))?;
        }
        if let Some(acknowledgement) = self.local_vote_ack.as_ref() {
            acknowledgement.validate_static()?;
        }
        let mut previous_recipient = None;
        for recipient in &self.certificate_recipients {
            recipient.validate_static()?;
            if previous_recipient.is_some_and(|previous| previous >= recipient.recipient) {
                return Err(DepositStateExportStoreError::InvalidDurableState);
            }
            previous_recipient = Some(recipient.recipient);
        }
        Ok(())
    }

    fn validate_work_index_with_authority(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<(), DepositStateExportStoreError> {
        authority.validate_live()?;
        if self.binding.local_signing_key != authority.binding.local_signing_key {
            return Err(DepositStateExportStoreError::WrongAuthority);
        }
        if self.binding != authority.binding {
            return if self.binding.same_slot(&authority.binding) {
                Err(DepositStateExportStoreError::PermanentEquivocation)
            } else {
                Err(DepositStateExportStoreError::InvalidDurableState)
            };
        }
        let expected_voters = if authority.local_party() == authority.source_party()
            && self.source_self_vote.is_some()
            && !self.terminal
        {
            let mut voters = authority
                .source
                .active()
                .committee()
                .members
                .iter()
                .map(|member| member.id)
                .filter(|voter| *voter != authority.source_party())
                .collect::<Vec<_>>();
            voters.sort_unstable();
            voters
        } else {
            Vec::new()
        };
        if self.source_requests.iter().map(|request| request.voter).collect::<Vec<_>>()
            != expected_voters
        {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        Ok(())
    }

    fn validate_with_authority(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<(), DepositStateExportStoreError> {
        self.validate_work_index_with_authority(authority)?;
        let committee = authority.source.active().committee();
        if self.total_votes() > usize::from(committee.n()) {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        if let Some(evidence) = self.evidence.as_ref() {
            evidence.reconstruct(authority)?;
        }
        if let Some(source_self_vote) = self.source_self_vote.as_ref() {
            source_self_vote.verify_live(authority)?;
        }
        if let Some(local) = self.local_vote.as_ref() {
            local.verify_live(authority, self)?;
            if let Some(acknowledgement) = self.local_vote_ack.as_ref() {
                let request = self.reconstruct_request(authority, local.voter)?;
                let vote = local.reconstruct(authority, self)?;
                acknowledgement.verify_live(&request, &vote)?;
            }
        } else if self.local_vote_ack.is_some() && !self.terminal {
            return Err(DepositStateExportStoreError::InvalidDurableState);
        }
        for remote in &self.remote_votes {
            remote.verify_live(authority, self)?;
        }
        if let Some(certificate) = self.certificate.as_ref() {
            let seal = certificate.reconstruct(authority)?;
            for recipient in &self.certificate_recipients {
                recipient.delivery(&seal)?;
            }
        }
        Ok(())
    }

    fn install_certificate_if_ready(
        &mut self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<bool, DepositStateExportStoreError> {
        if self.certificate.is_some() || authority.local_party() != authority.source_party() {
            return Ok(false);
        }
        let required = usize::from(authority.required_votes()?);
        if self.total_votes() < required || self.source_self_vote.is_none() {
            return Ok(false);
        }
        let mut envelopes = Vec::with_capacity(self.total_votes());
        envelopes.push(
            self.source_self_vote
                .as_ref()
                .ok_or(DepositStateExportStoreError::CertificateIncomplete)?
                .reconstruct(authority)?,
        );
        if let Some(local) = self.local_vote.as_ref() {
            envelopes.push(local.reconstruct(authority, self)?.envelope().clone());
        }
        for remote in &self.remote_votes {
            envelopes.push(remote.reconstruct(authority, self)?.envelope().clone());
        }
        let envelopes = select_witnesses(envelopes, authority.source_party(), required)?;
        let certificate =
            DepositPostHandoffExportSealCertificate::new(authority.statement().clone(), envelopes)?;
        let seal = certificate.verify(authority.source, authority.handoff)?;
        validate_verified_seal(authority, &seal)?;
        self.certificate = Some(DurableExportSealCertificate::from_verified(&seal)?);
        Ok(true)
    }

    fn status(
        &self,
        authority: &DepositStateExportSealAuthority<'_>,
    ) -> Result<DepositStateExportSealStatus, DepositStateExportStoreError> {
        self.validate_with_authority(authority)?;
        if let Some(certificate) = self.certificate.as_ref() {
            return Ok(DepositStateExportSealStatus::CertificateInstalled {
                seal: certificate.reconstruct(authority)?,
                pin_certified: self.pin_certified,
                terminal: self.terminal,
            });
        }
        Ok(DepositStateExportSealStatus::Collecting {
            votes: u16::try_from(self.total_votes())
                .map_err(|_| DepositStateExportStoreError::InvalidDurableState)?,
            required: authority.required_votes()?,
            locally_signed: if authority.local_party() == authority.source_party() {
                self.source_self_vote.is_some()
            } else {
                self.local_vote.is_some()
            },
        })
    }
}

fn validate_pin_certification_role(
    pin_certified: bool,
    certificate_installed: bool,
    local_party: PartyId,
    source_party: PartyId,
) -> Result<(), DepositStateExportStoreError> {
    if pin_certified && (!certificate_installed || local_party != source_party) {
        return Err(DepositStateExportStoreError::InvalidDurableState);
    }
    Ok(())
}

fn validate_request(
    authority: &DepositStateExportSealAuthority<'_>,
    request: &DepositPostHandoffExportSealRequest,
    voter: PartyId,
) -> Result<(), DepositStateExportStoreError> {
    authority.validate_live()?;
    request.validate_verified_candidate(authority.candidate, authority.source)?;
    let expected = DepositPostHandoffExportSealRequest::new(
        authority.candidate,
        voter,
        request.evidence().clone(),
        request.source_self_vote().clone(),
    )?;
    if request != &expected
        || request.requester() != authority.source_party()
        || request.voter() != voter
    {
        return Err(DepositStateExportStoreError::WrongRequest);
    }
    authority
        .source
        .active()
        .committee()
        .member(voter)
        .map_err(|_| DepositStateExportStoreError::WrongRequest)?;
    Ok(())
}

fn verify_vote_signature(
    authority: &DepositStateExportSealAuthority<'_>,
    vote: &DepositPostHandoffExportSealVote,
) -> Result<(), DepositStateExportStoreError> {
    let committee = authority.source.active().committee();
    let verifier =
        committee.members.first().ok_or(DepositStateExportStoreError::WrongAuthority)?.id;
    Identity::verify_envelope(committee, verifier, vote.envelope())
        .map_err(|_| DepositStateExportStoreError::WrongVote)
}

fn validate_verified_seal(
    authority: &DepositStateExportSealAuthority<'_>,
    seal: &VerifiedDepositPostHandoffExportSeal,
) -> Result<(), DepositStateExportStoreError> {
    authority.validate_live()?;
    let reverified = seal.certificate().verify(authority.source, authority.handoff)?;
    if seal.statement() != authority.statement()
        || seal.statement_digest() != authority.binding.statement
        || seal.certificate_digest() != reverified.certificate_digest()
        || seal.canonical_certificate_bytes() != reverified.canonical_certificate_bytes()
    {
        return Err(DepositStateExportStoreError::WrongCertificate);
    }
    Ok(())
}

fn validate_certified_pin(
    authority: &DepositStateExportSealAuthority<'_>,
    seal: &VerifiedDepositPostHandoffExportSeal,
    pin: &StoredExportPin,
) -> Result<(), DepositStateExportStoreError> {
    let statement = authority.statement();
    let export = statement.final_export();
    let transition = VerifiedStateImportCandidateTransitionBinding::from_verified_export_candidate(
        authority.candidate,
    )?;
    if pin.semantic_transition_digest() != statement.semantic_transition_digest()
        || pin.transition_binding() != transition.transition_binding()
        || pin.source() != statement.source_party()
        || pin.advertisement_digest() != export.advertisement_digest()
        || pin.seal_statement_digest() != seal.statement_digest()
        || pin.seal_certificate_digest() != Some(seal.certificate_digest())
        || pin.seal_certificate_bytes() != Some(seal.canonical_certificate_bytes())
        || pin.export_binding_digest() != export.digest()?
        || export.resulting_portable_head().root() != Some(pin.root())
    {
        return Err(DepositStateExportStoreError::WrongCertifiedPin);
    }
    Ok(())
}

fn select_witnesses(
    mut votes: Vec<SignedEnvelope>,
    required_source: PartyId,
    required: usize,
) -> Result<Vec<SignedEnvelope>, DepositStateExportStoreError> {
    if required == 0 || required > MAX_COMMITTEE_MEMBERS || votes.len() < required {
        return Err(DepositStateExportStoreError::CertificateIncomplete);
    }
    votes.sort_by_key(|vote| vote.from);
    if votes.windows(2).any(|pair| pair[0].from == pair[1].from) {
        return Err(DepositStateExportStoreError::ConflictingVote);
    }
    let source_index = votes
        .binary_search_by_key(&required_source, |vote| vote.from)
        .map_err(|_| DepositStateExportStoreError::CertificateIncomplete)?;
    let mut selected: Vec<_> = votes.iter().take(required).cloned().collect();
    if !selected.iter().any(|vote| vote.from == required_source) {
        selected[required - 1] = votes[source_index].clone();
        selected.sort_by_key(|vote| vote.from);
    }
    Ok(selected)
}

fn export_seal_snapshot_id(
    binding: &DurableExportSealBinding,
) -> Result<WalletId, DepositStateExportStoreError> {
    binding.validate_static()?;
    export_seal_slot_id(
        binding.network,
        binding.wallet,
        binding.local_party,
        binding.source,
        binding.source_party,
        binding.target_epoch,
        binding.semantic_transition,
        binding.transition_binding,
        binding.vote_slot,
    )
}

#[allow(clippy::too_many_arguments)]
fn export_seal_slot_id(
    network: [u8; 32],
    wallet: DepositWalletId,
    local_party: PartyId,
    source: RegistryId,
    source_party: PartyId,
    target_epoch: u64,
    semantic_transition: [u8; 32],
    transition_binding: [u8; 32],
    vote_slot: [u8; 32],
) -> Result<WalletId, DepositStateExportStoreError> {
    let mut hasher = blake3::Hasher::new_derive_key(EXPORT_SEAL_WALLET_ID_DOMAIN);
    hasher.update(&network);
    hasher.update(&wallet.0);
    hasher.update(&local_party.0.to_le_bytes());
    hasher.update(&source.digest());
    hasher.update(&source_party.0.to_le_bytes());
    hasher.update(&target_epoch.to_le_bytes());
    hasher.update(&semantic_transition);
    hasher.update(&transition_binding);
    hasher.update(&vote_slot);
    let id = *hasher.finalize().as_bytes();
    if id == [0; 32] {
        return Err(DepositStateExportStoreError::KeyDerivation);
    }
    Ok(WalletId(id))
}

fn encode_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, DepositStateExportStoreError> {
    let bytes =
        postcard::to_allocvec(value).map_err(|_| DepositStateExportStoreError::Serialization)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositStateExportStoreError::StorageValueTooLarge);
    }
    Ok(bytes)
}

fn decode_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, DepositStateExportStoreError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositStateExportStoreError::StorageValueTooLarge);
    }
    let (value, trailing) = postcard::take_from_bytes::<T>(bytes)
        .map_err(|_| DepositStateExportStoreError::Serialization)?;
    if !trailing.is_empty() || encode_canonical(&value, maximum)? != bytes {
        return Err(DepositStateExportStoreError::NonCanonicalEncoding);
    }
    Ok(value)
}

fn deserialize_candidate_evidence_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    deserialize_bounded_bytes(
        deserializer,
        MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_BYTES,
        "post-handoff export candidate evidence exceeds its journal bound",
    )
}

fn deserialize_seal_vote_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    deserialize_bounded_bytes(
        deserializer,
        MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES,
        "post-handoff export seal vote exceeds its journal bound",
    )
}

fn deserialize_seal_certificate_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    deserialize_bounded_bytes(
        deserializer,
        MAX_POST_HANDOFF_EXPORT_SEAL_BYTES,
        "post-handoff export seal certificate exceeds its journal bound",
    )
}

fn deserialize_remote_votes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DurableExportSealVote>, D::Error> {
    deserialize_bounded_sequence(
        deserializer,
        MAX_COMMITTEE_MEMBERS.saturating_sub(1),
        "too many post-handoff export seal votes",
    )
}

fn deserialize_source_request_work<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DurableSourceRequestWork>, D::Error> {
    deserialize_bounded_sequence(
        deserializer,
        MAX_COMMITTEE_MEMBERS.saturating_sub(1),
        "too many post-handoff export source request locators",
    )
}

fn deserialize_certificate_recipients<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DurableExportSealCertificateRecipient>, D::Error> {
    deserialize_bounded_sequence(
        deserializer,
        MAX_EXPORT_SEAL_CERTIFICATE_RECIPIENTS,
        "too many post-handoff export seal certificate recipients",
    )
}

fn deserialize_bounded_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
    maximum: usize,
    expectation: &'static str,
) -> Result<Vec<u8>, D::Error> {
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
            if sequence.size_hint().is_some_and(|hint| hint > self.maximum) {
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

fn deserialize_bounded_sequence<'de, D, T>(
    deserializer: D,
    maximum: usize,
    expectation: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedSequenceVisitor<T> {
        maximum: usize,
        expectation: &'static str,
        marker: std::marker::PhantomData<T>,
    }

    impl<'de, T: Deserialize<'de>> Visitor<'de> for BoundedSequenceVisitor<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.expectation)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|hint| hint > self.maximum) {
                return Err(A::Error::custom(self.expectation));
            }
            let mut values =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
            while let Some(value) = sequence.next_element()? {
                if values.len() == self.maximum {
                    return Err(A::Error::custom(self.expectation));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedSequenceVisitor {
        maximum,
        expectation,
        marker: std::marker::PhantomData,
    })
}

#[derive(Debug, Error)]
pub(crate) enum DepositStateExportStoreError {
    #[error("post-handoff export store context is invalid")]
    InvalidContext,
    #[error("post-handoff export live authority is invalid or does not match durable state")]
    WrongAuthority,
    #[error("post-handoff export request is not the exact authorized request")]
    WrongRequest,
    #[error("post-handoff export vote is invalid or has the wrong authenticated voter")]
    WrongVote,
    #[error("post-handoff export source must journal its own signature before recording it")]
    UnjournaledLocalVote,
    #[error("post-handoff export source received conflicting votes from one predecessor")]
    ConflictingVote,
    #[error("post-handoff export vote slot has a permanent conflicting exact statement")]
    PermanentEquivocation,
    #[error("only the source named by the export statement may aggregate its seal")]
    NotSourceAggregator,
    #[error("post-handoff export seal vote bound was exceeded")]
    TooManyVotes,
    #[error("post-handoff export seal certificate is not complete")]
    CertificateIncomplete,
    #[error("post-handoff export seal certificate does not match the exact live candidate")]
    WrongCertificate,
    #[error("another canonical certificate is already installed for this exact seal")]
    ConflictingCertificate,
    #[error("certified export pin does not match the exact installed seal")]
    WrongCertifiedPin,
    #[error("post-handoff export seal slot does not exist")]
    UnknownSealSlot,
    #[error("post-handoff export work locator is malformed or does not name this exact slot")]
    InvalidWorkLocator,
    #[error("post-handoff export work is already durably complete")]
    WorkAlreadyComplete,
    #[error("post-handoff export acknowledgement conflicts with the durable exact receipt")]
    ConflictingAcknowledgement,
    #[error("post-handoff export acknowledgement came from the wrong authenticated QUIC peer")]
    WrongAcknowledgementPeer,
    #[error("post-handoff export certificate target is not the exact verified handoff target")]
    WrongFanoutTarget,
    #[error("post-handoff export certificate fanout is not ready")]
    FanoutNotReady,
    #[error("post-handoff export certificate fanout conflicts with the exact old/target union")]
    ConflictingCertificateFanout,
    #[error("post-handoff export certificate fanout still has unacknowledged recipients")]
    FanoutIncomplete,
    #[error("post-handoff export durable state is malformed")]
    InvalidDurableState,
    #[error("post-handoff export durable revision is exhausted")]
    RevisionExhausted,
    #[error("post-handoff export journal serialization failed")]
    Serialization,
    #[error("post-handoff export journal encoding is not canonical")]
    NonCanonicalEncoding,
    #[error("post-handoff export journal exceeds its allocation bound")]
    StorageValueTooLarge,
    #[error("post-handoff export synthetic storage key derivation failed")]
    KeyDerivation,
    #[error("post-handoff export snapshot path is not a private regular file: {0}")]
    StorageConflict(PathBuf),
    #[error("post-handoff export state validation failed: {0}")]
    Export(#[from] DepositStateExportError),
    #[error("post-handoff export transition validation failed: {0}")]
    Import(#[from] DepositStateImportError),
    #[error("post-handoff export transfer wire validation failed: {0}")]
    Wire(#[from] DepositStateTransferWireError),
    #[error("post-handoff export retention validation failed: {0}")]
    Retention(#[from] RetentionError),
    #[error("post-handoff export local settled-state validation failed: {0}")]
    IndexStore(#[from] DepositIndexStoreError),
    #[error("post-handoff export snapshot storage failed: {0}")]
    Storage(#[from] StoreError),
    #[error("post-handoff export snapshot I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        committee::SessionId, compact_epoch_registry::RegistryId,
        deposit_state_transfer_wire::tests::export_evidence_fixture,
    };

    fn vote(voter: u16) -> SignedEnvelope {
        SignedEnvelope {
            version: 1,
            committee: [1; 32],
            epoch: 1,
            session: SessionId([2; 32]),
            from: PartyId(voter),
            to: None,
            sequence: 1,
            payload: vec![3],
            signature: [4; 64],
        }
    }

    #[test]
    fn witness_selection_is_sorted_deterministic_and_keeps_source() {
        let votes = [vote(1), vote(2), vote(3), vote(4)];
        let selected =
            select_witnesses(votes.iter().rev().cloned().collect(), PartyId(4), 3).unwrap();
        assert_eq!(
            selected.iter().map(|vote| vote.from).collect::<Vec<_>>(),
            vec![PartyId(1), PartyId(2), PartyId(4)]
        );
    }

    #[test]
    fn witness_selection_rejects_duplicate_or_missing_source() {
        let first = vote(1);
        let duplicate = vote(1);
        let second = vote(2);
        assert!(matches!(
            select_witnesses(vec![first.clone(), duplicate, second.clone()], PartyId(1), 2),
            Err(DepositStateExportStoreError::ConflictingVote)
        ));
        assert!(matches!(
            select_witnesses(vec![first, second], PartyId(3), 2),
            Err(DepositStateExportStoreError::CertificateIncomplete)
        ));
    }

    #[test]
    fn only_the_serving_source_may_persist_a_certified_pin_marker() {
        assert!(validate_pin_certification_role(false, false, PartyId(2), PartyId(1)).is_ok());
        assert!(validate_pin_certification_role(true, true, PartyId(1), PartyId(1)).is_ok());
        assert!(matches!(
            validate_pin_certification_role(true, false, PartyId(1), PartyId(1)),
            Err(DepositStateExportStoreError::InvalidDurableState)
        ));
        assert!(matches!(
            validate_pin_certification_role(true, true, PartyId(2), PartyId(1)),
            Err(DepositStateExportStoreError::InvalidDurableState)
        ));
    }

    #[test]
    fn snapshot_layout_stores_candidate_evidence_once_for_all_votes() {
        let wallet = DepositWalletId([0x21; 32]);
        let source = RegistryId::new(wallet, 7, [0x22; 32], [0x23; 32]).unwrap();
        let binding = DurableExportSealBinding {
            network: [0x24; 32],
            wallet,
            local_party: PartyId(1),
            local_signing_key: [0x25; 32],
            source,
            source_registry: source.digest(),
            source_committee: [0x26; 32],
            source_fault_bound: 1,
            source_certified_activation_root: [0x27; 32],
            handoff_statement: [0x28; 32],
            handoff_certificate: [0x29; 32],
            source_party: PartyId(1),
            target_epoch: 8,
            semantic_transition: [0x2a; 32],
            transition_binding: [0x2b; 32],
            vote_slot: [0x2c; 32],
            statement: [0x2d; 32],
            advertisement: [0x2e; 32],
            export_binding: [0x2f; 32],
        };
        let marker = (0_u8..=127).collect::<Vec<_>>();
        let evidence = DurableExportCandidateEvidence { digest: [0x31; 32], bytes: marker.clone() };
        let source_self_vote = DurableSourceSelfVote {
            envelope: SignedEnvelope {
                version: 1,
                committee: binding.source_committee,
                epoch: binding.source.active_epoch(),
                session: SessionId([0x30; 32]),
                from: binding.source_party,
                to: None,
                sequence: 1,
                payload: binding.statement.to_vec(),
                signature: [0x38; 64],
            },
        };
        let snapshot = DurableExportSealSnapshot {
            version: EXPORT_SEAL_STORE_VERSION,
            domain: EXPORT_SEAL_STORE_DOMAIN,
            binding,
            evidence: Some(evidence.clone()),
            source_self_vote: Some(source_self_vote),
            source_requests: Vec::new(),
            local_vote: None,
            remote_votes: vec![
                DurableExportSealVote {
                    voter: PartyId(2),
                    request_digest: [0x32; 32],
                    vote_digest: [0x33; 32],
                    vote: vec![0x34; 64],
                },
                DurableExportSealVote {
                    voter: PartyId(3),
                    request_digest: [0x35; 32],
                    vote_digest: [0x36; 32],
                    vote: vec![0x37; 64],
                },
            ],
            certificate: None,
            local_vote_ack: None,
            certificate_recipients: Vec::new(),
            pin_certified: false,
            terminal: false,
        };

        let snapshot_id = export_seal_snapshot_id(&snapshot.binding).unwrap();
        snapshot
            .validate_static(
                snapshot.binding.network,
                snapshot.binding.wallet,
                snapshot.binding.local_party,
                snapshot_id,
            )
            .unwrap();
        let bytes = encode_canonical(&snapshot, MAX_EXPORT_SEAL_STORE_SNAPSHOT_BYTES).unwrap();
        assert_eq!(
            bytes.windows(marker.len()).filter(|window| *window == marker.as_slice()).count(),
            1
        );
        let decoded = decode_canonical::<DurableExportSealSnapshot>(
            &bytes,
            MAX_EXPORT_SEAL_STORE_SNAPSHOT_BYTES,
        )
        .unwrap();
        assert_eq!(decoded.evidence, Some(evidence));
        assert_eq!(decoded.remote_votes.len(), 2);

        let mut missing_evidence = decoded.clone();
        missing_evidence.evidence = None;
        assert!(matches!(
            missing_evidence.validate_static(
                missing_evidence.binding.network,
                missing_evidence.binding.wallet,
                missing_evidence.binding.local_party,
                snapshot_id,
            ),
            Err(DepositStateExportStoreError::InvalidDurableState)
        ));

        let mut missing_source_vote = decoded;
        missing_source_vote.source_self_vote = None;
        assert!(matches!(
            missing_source_vote.validate_static(
                missing_source_vote.binding.network,
                missing_source_vote.binding.wallet,
                missing_source_vote.binding.local_party,
                snapshot_id,
            ),
            Err(DepositStateExportStoreError::InvalidDurableState)
        ));
    }

    #[test]
    fn work_locator_binds_every_route_projection() {
        let wallet = DepositWalletId([0x41; 32]);
        let source = RegistryId::new(wallet, 7, [0x42; 32], [0x43; 32]).unwrap();
        let binding = DurableExportSealBinding {
            network: [0x44; 32],
            wallet,
            local_party: PartyId(1),
            local_signing_key: [0x45; 32],
            source,
            source_registry: source.digest(),
            source_committee: [0x46; 32],
            source_fault_bound: 1,
            source_certified_activation_root: [0x47; 32],
            handoff_statement: [0x48; 32],
            handoff_certificate: [0x49; 32],
            source_party: PartyId(1),
            target_epoch: 8,
            semantic_transition: [0x4a; 32],
            transition_binding: [0x4b; 32],
            vote_slot: [0x4c; 32],
            statement: [0x4d; 32],
            advertisement: [0x4e; 32],
            export_binding: [0x4f; 32],
        };
        let locator = DepositStateExportSealWorkLocator::new(
            &binding,
            DepositStateExportSealWorkKind::SourceRequest,
            PartyId(2),
            [0x50; 32],
            [0; 32],
        )
        .unwrap();
        assert_eq!(locator.network(), binding.network);
        assert_eq!(locator.wallet(), binding.wallet);
        assert_eq!(locator.local_party(), binding.local_party);
        assert_eq!(locator.source_party(), binding.source_party);
        assert_eq!(locator.target_epoch(), binding.target_epoch);
        assert_eq!(locator.semantic_transition_digest(), binding.semantic_transition);
        assert_eq!(locator.statement_digest(), binding.statement);
        assert_eq!(locator.primary_digest(), [0x50; 32]);
        assert_eq!(locator.secondary_digest(), [0; 32]);
        assert_eq!(locator.binding, locator.expected_binding());

        let mut spliced = locator;
        spliced.peer = PartyId(3);
        assert_ne!(spliced.binding, spliced.expected_binding());
    }

    #[tokio::test]
    async fn source_requests_reconstruct_byte_exactly_after_restart() {
        let fixture = export_evidence_fixture().await;
        let source_party = fixture.candidate.statement().source_party();
        let pin = PreparedExportCandidatePin::from_verified_candidate_for_test(&fixture.candidate)
            .unwrap();
        let authority = DepositStateExportSealAuthority::new_source(
            &fixture.candidate,
            &fixture.source,
            &fixture.handoff,
            &pin,
            &fixture.source_identity,
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x7a; 32];
        let store = DepositStateExportSealStore::open(
            directory.path(),
            fixture.network,
            fixture.source.wallet(),
            source_party,
            &seed,
        )
        .unwrap();

        let source_vote =
            store.sign_or_replay_source_vote(&authority, &fixture.evidence).await.unwrap();
        assert_eq!(source_vote, fixture.source_self_vote);
        let voter_two = store.source_request(&authority, PartyId(2)).await.unwrap();
        let voter_three = store.source_request(&authority, PartyId(3)).await.unwrap();
        assert_eq!(voter_two.evidence(), voter_three.evidence());
        assert_eq!(voter_two.source_self_vote(), voter_three.source_self_vote());
        assert_ne!(voter_two.digest(), voter_three.digest());
        let expected_bytes = voter_two.to_bytes().unwrap();

        drop(store);
        let reopened = DepositStateExportSealStore::open(
            directory.path(),
            fixture.network,
            fixture.source.wallet(),
            source_party,
            &seed,
        )
        .unwrap();
        let pending = reopened.pending_source_requests(&authority).await.unwrap();
        assert_eq!(pending.len(), usize::from(fixture.source.active().committee().n()) - 1);
        assert!(
            pending
                .iter()
                .all(|locator| locator.kind() == DepositStateExportSealWorkKind::SourceRequest)
        );
        let voter_two_locator =
            pending.iter().copied().find(|locator| locator.peer() == PartyId(2)).unwrap();
        let recovered =
            reopened.source_request_for_locator(&authority, voter_two_locator).await.unwrap();
        assert_eq!(recovered.to_bytes().unwrap(), expected_bytes);
    }

    #[tokio::test]
    async fn remote_request_recovery_authenticates_persisted_source_evidence() {
        let fixture = export_evidence_fixture().await;
        let alternate = crate::deposit_state_transfer_wire::tests::export_evidence_fixture_with_alternate_witnesses(true).await;
        assert_eq!(
            fixture.candidate.statement().vote_slot_digest(),
            alternate.candidate.statement().vote_slot_digest()
        );
        assert_ne!(
            fixture.candidate.statement().digest(),
            alternate.candidate.statement().digest()
        );
        assert_eq!(
            fixture.evidence.advertisement().unwrap().portable_index(),
            alternate.evidence.advertisement().unwrap().portable_index()
        );
        let party = PartyId(2);
        let mut secret = [0x58; 32];
        secret[1..9].copy_from_slice(&0_u64.to_le_bytes());
        secret[9..11].copy_from_slice(&party.0.to_le_bytes());
        let signer = Identity::from_test_secrets(party, 0, &[2; 32], secret).unwrap();
        let request = DepositPostHandoffExportSealRequest::new(
            &fixture.candidate,
            party,
            fixture.evidence.clone(),
            fixture.source_self_vote.clone(),
        )
        .unwrap();
        let statement = fixture.candidate.statement();
        let envelope = signer
            .sign_envelope(
                fixture.source.active().committee(),
                statement.session(),
                None,
                statement.final_export().terminal_checkpoint().sequence(),
                statement.signing_payload(),
            )
            .unwrap();
        let vote = DepositPostHandoffExportSealVote::new(&request, envelope).unwrap();
        let binding = DurableExportSealBinding::from_live(
            &fixture.candidate,
            &fixture.source,
            &fixture.handoff,
            &signer,
        )
        .unwrap();
        let mut snapshot = DurableExportSealSnapshot::new(&binding);
        snapshot.evidence = Some(DurableExportCandidateEvidence {
            digest: fixture.evidence.digest(),
            bytes: fixture.evidence.to_bytes(&fixture.candidate).unwrap(),
        });
        snapshot.source_self_vote =
            Some(DurableSourceSelfVote { envelope: fixture.source_self_vote.clone() });
        snapshot.local_vote = Some(DurableExportSealVote::from_wire(&request, &vote).unwrap());
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x71; 32];
        let store = DepositStateExportSealStore::open(
            directory.path(),
            fixture.network,
            fixture.source.wallet(),
            party,
            &seed,
        )
        .unwrap();
        let id = export_seal_snapshot_id(&binding).unwrap();
        store.persist(&mut None, id, &snapshot).await.unwrap();
        drop(store);
        let reopened = DepositStateExportSealStore::open(
            directory.path(),
            fixture.network,
            fixture.source.wallet(),
            party,
            &seed,
        )
        .unwrap();
        let recovered = reopened
            .recover_remote_request(
                &alternate.candidate,
                &fixture.source,
                &fixture.handoff,
                &fixture.target,
                &signer,
                true,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.to_bytes().unwrap(), request.to_bytes().unwrap());
        let seal = crate::deposit_state_transfer_wire::tests::seal_certificate_for(
            &fixture,
            &[PartyId(1), PartyId(2), PartyId(3)],
        )
        .verify(&fixture.source, &fixture.handoff)
        .unwrap();
        let completed_import = crate::deposit_state_import::VerifiedDepositStateImport::from_verified_export_seal_for_test(
            fixture.network, &fixture.source, &fixture.handoff, &fixture.target, &seal,
        ).unwrap();
        let target_identities = crate::deposit_state_transfer_wire::tests::test_identities(1);
        let acknowledgements = fixture
            .target
            .committee()
            .members
            .iter()
            .take(3)
            .map(|member| {
                crate::deposit_state_import::DepositStateImportedAck::sign(
                    &completed_import,
                    &target_identities[&member.id],
                )
                .unwrap()
            })
            .collect();
        let imported =
            crate::deposit_state_import::DepositStateImportedCertificate::from_completed_import(
                &completed_import,
                acknowledgements,
                &fixture.target,
            )
            .unwrap()
            .verify_completed_import(&completed_import, &fixture.target)
            .unwrap();
        let replay = DepositStateExportSealReplay {
            source: &fixture.source,
            handoff: &fixture.handoff,
            target: &fixture.target,
            imported: &imported,
            signer: &signer,
        };
        // Finality reclaims graph authority, not a signed vote still owed to a lagging source.
        let pending = reopened.pending_finalized_replay(&replay).await.unwrap();
        assert_eq!(pending, vec![snapshot.local_vote_locator().unwrap().unwrap()]);
        let locator = pending[0];
        assert_eq!(
            reopened.finalized_replay(&replay, locator, None).await.unwrap(),
            vote.to_bytes(&request).unwrap()
        );
        let ack = DepositPostHandoffExportSealVoteAck::issue(&request, &vote).unwrap();
        let ack_bytes = ack.to_bytes(&request, &vote).unwrap();
        assert!(
            reopened
                .finalized_replay(&replay, locator, Some((PartyId(3), &ack_bytes)))
                .await
                .is_err()
        );
        reopened.finalized_replay(&replay, locator, Some((PartyId(1), &ack_bytes))).await.unwrap();
        reopened.finalized_replay(&replay, locator, Some((PartyId(1), &ack_bytes))).await.unwrap();
        assert!(reopened.pending_finalized_replay(&replay).await.unwrap().is_empty());
        let acknowledged = reopened.load_optional(id).await.unwrap().unwrap();
        assert_eq!(acknowledged.snapshot.local_vote_ack.unwrap().acknowledgement, ack);
        assert_eq!(
            acknowledged.metadata.revision, 1,
            "duplicate receipts must not rewrite the journal"
        );
        let wrong_network = DepositStateExportSealStore::open(
            directory.path(),
            [0x62; 32],
            fixture.source.wallet(),
            party,
            &seed,
        )
        .unwrap();
        assert!(wrong_network.pending_finalized_replay(&replay).await.is_err());

        // Source certificate fanout has the same post-finality replay obligation, including
        // its self receipt. No prepared graph pin is passed to any replay operation.
        let source_binding = DurableExportSealBinding::from_live(
            &fixture.candidate,
            &fixture.source,
            &fixture.handoff,
            &fixture.source_identity,
        )
        .unwrap();
        let source_store = DepositStateExportSealStore::open(
            directory.path(),
            fixture.network,
            fixture.source.wallet(),
            PartyId(1),
            &seed,
        )
        .unwrap();
        let source_id = export_seal_snapshot_id(&source_binding).unwrap();
        let mut source_snapshot = DurableExportSealSnapshot::new(&source_binding);
        source_snapshot.evidence = snapshot.evidence.clone();
        source_snapshot.source_self_vote = snapshot.source_self_vote.clone();
        source_snapshot.certificate =
            Some(DurableExportSealCertificate::from_verified(&seal).unwrap());
        source_snapshot.pin_certified = true;
        // Model the earlier crash cut too: the certificate and pin committed, fanout did not.
        source_store.persist(&mut None, source_id, &source_snapshot).await.unwrap();
        let source_replay =
            DepositStateExportSealReplay { signer: &fixture.source_identity, ..replay };
        let deliveries = source_store.pending_finalized_replay(&source_replay).await.unwrap();
        assert_eq!(
            deliveries.len(),
            certificate_recipients(&fixture.source, &seal, &fixture.target).unwrap().len()
        );
        assert_eq!(
            source_store.pending_finalized_replay(&source_replay).await.unwrap(),
            deliveries
        );
        for locator in deliveries {
            let delivery = DepositPostHandoffExportSealCertificateDelivery::from_verified(
                &seal,
                locator.peer(),
            )
            .unwrap();
            assert_eq!(
                source_store.finalized_replay(&source_replay, locator, None).await.unwrap(),
                delivery.to_bytes().unwrap()
            );
            let ack = DepositPostHandoffExportSealCertificateAck::issue(&delivery).unwrap();
            let bytes = ack.to_bytes(&delivery).unwrap();
            assert!(
                source_store
                    .finalized_replay(&source_replay, locator, Some((PartyId(99), &bytes)))
                    .await
                    .is_err()
            );
            source_store
                .finalized_replay(&source_replay, locator, Some((locator.peer(), &bytes)))
                .await
                .unwrap();
        }
        assert!(source_store.pending_finalized_replay(&source_replay).await.unwrap().is_empty());
        let terminal = source_store.load_optional(source_id).await.unwrap().unwrap();
        assert!(terminal.snapshot.terminal);
        assert!(terminal.snapshot.evidence.is_none());
        source_store
            .retain_certificate(&seal, &fixture.source, &fixture.handoff, &fixture.source_identity)
            .await
            .unwrap();

        // Restore the unacknowledged cut for the independent certificate/evidence checks below.
        let mut loaded = reopened.load_optional(id).await.unwrap();
        reopened.persist(&mut loaded, id, &snapshot).await.unwrap();
        reopened
            .retain_certificate(&seal, &fixture.source, &fixture.handoff, &signer)
            .await
            .unwrap();
        assert_eq!(
            reopened.load_optional(id).await.unwrap().unwrap().snapshot.local_vote,
            snapshot.local_vote
        );
        assert!(
            reopened
                .recover_remote_request(
                    &alternate.candidate,
                    &fixture.source,
                    &fixture.handoff,
                    &fixture.target,
                    &signer,
                    true,
                )
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            reopened
                .recover_remote_request(
                    &alternate.candidate,
                    &fixture.source,
                    &fixture.handoff,
                    &fixture.target,
                    &signer,
                    false,
                )
                .await
                .unwrap()
                .unwrap()
                .to_bytes()
                .unwrap(),
            request.to_bytes().unwrap()
        );
        // Authenticated storage is not cryptographic authority: a validly encrypted journal
        // containing a damaged source signature must still fail recovery.
        let mut loaded = reopened.load_optional(id).await.unwrap();
        snapshot.source_self_vote.as_mut().unwrap().envelope.signature[0] ^= 1;
        reopened.persist(&mut loaded, id, &snapshot).await.unwrap();
        assert!(reopened.finalized_replay(&replay, locator, None).await.is_err());
        assert!(
            reopened
                .recover_remote_request(
                    &fixture.candidate,
                    &fixture.source,
                    &fixture.handoff,
                    &fixture.target,
                    &signer,
                    false,
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn nonvoter_retains_certificate_without_minting_vote_or_pin() {
        use crate::deposit_state_transfer_wire::tests::{seal_certificate_for, test_identities};
        let fixture = export_evidence_fixture().await;
        let identities = test_identities(0);
        let signer = &identities[&PartyId(4)];
        let seal = seal_certificate_for(&fixture, &[PartyId(1), PartyId(2), PartyId(3)])
            .verify(&fixture.source, &fixture.handoff)
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = DepositStateExportSealStore::open(
            directory.path(),
            fixture.network,
            fixture.source.wallet(),
            PartyId(4),
            &[0x72; 32],
        )
        .unwrap();
        store.retain_certificate(&seal, &fixture.source, &fixture.handoff, signer).await.unwrap();
        drop(store);
        let reopened = DepositStateExportSealStore::open(
            directory.path(),
            fixture.network,
            fixture.source.wallet(),
            PartyId(4),
            &[0x72; 32],
        )
        .unwrap();
        reopened
            .retain_certificate(&seal, &fixture.source, &fixture.handoff, signer)
            .await
            .unwrap();
        let binding = DurableExportSealBinding::from_live(
            &fixture.candidate,
            &fixture.source,
            &fixture.handoff,
            signer,
        )
        .unwrap();
        let loaded = reopened
            .load_optional(export_seal_snapshot_id(&binding).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(loaded.snapshot.certificate.is_some());
        assert!(loaded.snapshot.local_vote.is_none());
        assert!(loaded.snapshot.source_self_vote.is_none());
        assert!(!loaded.snapshot.pin_certified);
        assert!(
            reopened
                .recover_remote_request(
                    &fixture.candidate,
                    &fixture.source,
                    &fixture.handoff,
                    &fixture.target,
                    signer,
                    false,
                )
                .await
                .unwrap()
                .is_none()
        );
        let alternate = seal_certificate_for(&fixture, &[PartyId(1), PartyId(2), PartyId(4)])
            .verify(&fixture.source, &fixture.handoff)
            .unwrap();
        assert!(matches!(
            reopened
                .retain_certificate(&alternate, &fixture.source, &fixture.handoff, signer)
                .await,
            Err(DepositStateExportStoreError::ConflictingCertificate)
        ));
    }
}
