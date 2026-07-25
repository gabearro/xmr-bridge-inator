//! Fresh-format, bounded QUIC catch-up payloads for the deposit protocol.
//!
//! A joining party starts from one [`DepositSyncAdvertisement`], verifies its quorum-authenticated
//! portable index checkpoint, and follows only content references reached from the advertised
//! compact-registry and portable-index roots. Peers are availability providers: an object is not
//! authoritative merely because a peer returned it. The caller must feed registry objects through
//! [`crate::compact_registry_archive`] and index objects through [`crate::deposit_index`] while
//! walking those authenticated roots.
//!
//! This protocol never lists a storage directory and never requests a lifetime ledger prefix.
//! Requests carry a finite reference frontier, responses are hard bounded by both object count and
//! plaintext bytes, and every continuation cursor is bound to the exact request and advertised
//! roots. Exact ledger, observation, and checkpoint certificates are content-addressed leaves in
//! that same authenticated finite frontier.

use std::{collections::BTreeSet, fmt};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as _, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::{
    compact_epoch_registry::RegistryId,
    compact_registry_archive::{
        CompactRegistryArchiveHead, CompactRegistryObjectRef, MAX_COMPACT_REGISTRY_HEAD_BYTES,
        verify_compact_registry_object,
    },
    compact_registry_store::CompactRegistryStoreCheckpoint,
    deposit_archive::{
        CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT, CERTIFIED_LEDGER_ENTRY_ARTIFACT,
        DEPOSIT_ARCHIVE_EVENT_ARTIFACT, DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT,
        DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT, DepositArchiveEvent, DepositArchiveHead,
        DepositArchiveOperation, DepositArchiveSegment,
        MAX_CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT_BYTES, MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES,
        MAX_DEPOSIT_ARCHIVE_EVENT_BYTES, MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES,
        MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES,
    },
    deposit_index::{
        DepositIndexHead, DepositIndexObjectId, MAX_DEPOSIT_INDEX_OBJECT_BYTES,
        verify_portable_index_object,
    },
    deposit_index_checkpoint::{
        DepositIndexCheckpointCertificate, DepositIndexCheckpointOperation,
        DepositIndexCheckpointStatement, PortableDepositIndexHead,
    },
    deposit_index_store::DepositIndexStoreCheckpoint,
    deposit_ledger::{CertifiedDepositObservation, CertifiedLedgerEntry},
    deposit_wallet::DepositWalletId,
    identity::SignedEnvelope,
    storage::{WalletArtifactRef, WalletId},
};

/// Fixed operation-domain tag. It makes dispatching a payload under another QUIC operation fail.
pub const DEPOSIT_SYNC_WIRE_DOMAIN: [u8; 16] = *b"tm-deposit-sync1";
pub const DEPOSIT_SYNC_WIRE_VERSION: u16 = 2;

/// The authenticated QUIC transport's body ceiling.
pub const MAX_DEPOSIT_SYNC_WIRE_BYTES: usize = 8 * 1024 * 1024;
/// A caller may ask for at most this many exact references in one finite frontier.
pub const MAX_DEPOSIT_SYNC_REQUEST_OBJECTS: usize = 256;
/// A response may carry at most this many objects even if they are individually tiny.
pub const MAX_DEPOSIT_SYNC_PAGE_OBJECTS: usize = 64;
/// Leaves one MiB below the QUIC ceiling for references and canonical framing.
pub const MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES: usize = 7 * 1024 * 1024;
/// Complete connected manifests are verified before any of their plaintext is returned.
pub const MAX_DEPOSIT_SYNC_MANIFEST_PLAINTEXT_BYTES: usize = 32 * 1024 * 1024;
const MAX_HEAD_REQUEST_BYTES: usize = 256;
const MAX_ADVERTISEMENT_BYTES: usize = MAX_COMPACT_REGISTRY_HEAD_BYTES + 256 * 1024;
const MAX_OBJECT_REQUEST_BYTES: usize = 128 * 1024;
const MAX_INDEX_CHECKPOINT_ATTEST_WIRE_BYTES: usize = 16 * 1024;
const MAX_INDEX_CHECKPOINT_CERTIFICATE_WIRE_BYTES: usize = 2 * 1024 * 1024;

const CONTEXT_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync/context/v1";
const ADVERTISEMENT_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync/advertisement/v1";
const CERTIFICATE_ARCHIVE_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-sync/certificate-archive/v1";
const OBJECT_MANIFEST_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync/object-manifest/v1";

/// Deployment and wallet binding repeated by every fresh catch-up message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncContext {
    version: u16,
    domain: [u8; 16],
    network: [u8; 32],
    wallet: DepositWalletId,
}

impl DepositSyncContext {
    pub fn new(network: [u8; 32], wallet: DepositWalletId) -> Result<Self, DepositSyncWireError> {
        let context = Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            domain: DEPOSIT_SYNC_WIRE_DOMAIN,
            network,
            wallet,
        };
        context.validate()?;
        Ok(context)
    }

    fn validate(self) -> Result<(), DepositSyncWireError> {
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.domain != DEPOSIT_SYNC_WIRE_DOMAIN
            || self.network == [0; 32]
            || self.wallet.0 == [0; 32]
        {
            return Err(DepositSyncWireError::InvalidContext);
        }
        Ok(())
    }

    #[must_use]
    pub const fn network(self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn wallet(self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(&self).expect("fixed sync context serializes");
        length_prefixed_hash(CONTEXT_DIGEST_DOMAIN, &bytes)
    }
}

/// Exact certified-ledger authority to which an index-checkpoint round is pinned.
///
/// The content reference is an availability/audit commitment to the sender's exact certificate
/// witness set. Honest replicas may retain different exact n-f witness subsets and therefore
/// different references. A receiver matches the wallet, sequence, and witness-independent ledger
/// decision against its independently verified local certificate; reference equality is neither
/// required nor part of the signed checkpoint statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositIndexCheckpointLedgerBinding {
    version: u16,
    context: DepositSyncContext,
    checkpoint_sequence: u64,
    ledger_sequence: u64,
    decision: [u8; 32],
    certificate: WalletArtifactRef,
}

impl DepositIndexCheckpointLedgerBinding {
    pub fn new(
        context: DepositSyncContext,
        checkpoint_sequence: u64,
        certificate: WalletArtifactRef,
        ledger: &CertifiedLedgerEntry,
    ) -> Result<Self, DepositSyncWireError> {
        let bytes =
            ledger.to_bytes().map_err(|_| DepositSyncWireError::InvalidCheckpointBinding)?;
        certificate
            .verify_contents(&bytes)
            .map_err(|_| DepositSyncWireError::InvalidCheckpointBinding)?;
        let binding = Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            context,
            checkpoint_sequence,
            ledger_sequence: ledger.statement.sequence,
            decision: ledger.statement.digest(),
            certificate,
        };
        binding.validate_static()?;
        Ok(binding)
    }

    fn validate_static(self) -> Result<(), DepositSyncWireError> {
        self.context.validate()?;
        validate_certified_reference(self.certificate, self.context.wallet)?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.checkpoint_sequence == 0
            || self.ledger_sequence == 0
            || self.decision == [0; 32]
        {
            return Err(DepositSyncWireError::InvalidCheckpointBinding);
        }
        Ok(())
    }

    /// Authenticate the sender's exact retained certificate bytes against this wire binding. This
    /// optional audit helper does not replace issuer-window verification and is not used to demand
    /// reference equality with another replica's independently certified witness subset.
    pub fn verify_ledger(self, ledger: &CertifiedLedgerEntry) -> Result<(), DepositSyncWireError> {
        self.validate_static()?;
        let bytes =
            ledger.to_bytes().map_err(|_| DepositSyncWireError::InvalidCheckpointBinding)?;
        self.certificate
            .verify_contents(&bytes)
            .map_err(|_| DepositSyncWireError::InvalidCheckpointBinding)?;
        if ledger.statement.wallet != self.context.wallet
            || ledger.statement.sequence != self.ledger_sequence
            || ledger.statement.digest() != self.decision
        {
            return Err(DepositSyncWireError::InvalidCheckpointBinding);
        }
        Ok(())
    }

    fn validate_statement(
        self,
        statement: &DepositIndexCheckpointStatement,
    ) -> Result<(), DepositSyncWireError> {
        self.validate_static()?;
        if statement.context().wallet_id() != self.context.wallet
            || statement.context().network() != self.context.network
            || statement.sequence() != self.checkpoint_sequence
            || statement.operation()
                != (DepositIndexCheckpointOperation::Ledger { statement: self.decision })
            || statement.ledger_sequence() != self.ledger_sequence
            || statement.ledger_decision() != self.decision
        {
            return Err(DepositSyncWireError::InvalidCheckpointBinding);
        }
        Ok(())
    }

    #[must_use]
    pub const fn context(self) -> DepositSyncContext {
        self.context
    }

    #[must_use]
    pub const fn checkpoint_sequence(self) -> u64 {
        self.checkpoint_sequence
    }

    #[must_use]
    pub const fn ledger_sequence(self) -> u64 {
        self.ledger_sequence
    }

    #[must_use]
    pub const fn decision(self) -> [u8; 32] {
        self.decision
    }

    #[must_use]
    pub const fn certificate(self) -> WalletArtifactRef {
        self.certificate
    }
}

/// Exact confirmed-output observation authority for an observation-only checkpoint round.
///
/// The allocation sequence is metadata of the observation certificate, not a ledger cursor and
/// never substitutes for the independently monotonic checkpoint sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositIndexCheckpointObservationBinding {
    version: u16,
    context: DepositSyncContext,
    checkpoint_sequence: u64,
    allocation_sequence: u64,
    statement: [u8; 32],
    certificate: WalletArtifactRef,
}

impl DepositIndexCheckpointObservationBinding {
    pub fn new(
        context: DepositSyncContext,
        checkpoint_sequence: u64,
        certificate: WalletArtifactRef,
        observation: &CertifiedDepositObservation,
    ) -> Result<Self, DepositSyncWireError> {
        let bytes =
            observation.to_bytes().map_err(|_| DepositSyncWireError::InvalidCheckpointBinding)?;
        certificate
            .verify_contents(&bytes)
            .map_err(|_| DepositSyncWireError::InvalidCheckpointBinding)?;
        let binding = Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            context,
            checkpoint_sequence,
            allocation_sequence: observation.statement.allocation_sequence(),
            statement: observation.statement.digest(),
            certificate,
        };
        binding.validate_static()?;
        binding.verify_observation(observation)?;
        Ok(binding)
    }

    fn validate_static(self) -> Result<(), DepositSyncWireError> {
        self.context.validate()?;
        validate_observation_reference(self.certificate, self.context.wallet)
            .map_err(|_| DepositSyncWireError::InvalidCheckpointBinding)?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.checkpoint_sequence == 0
            || self.allocation_sequence == 0
            || self.statement == [0; 32]
        {
            return Err(DepositSyncWireError::InvalidCheckpointBinding);
        }
        Ok(())
    }

    /// Authenticate exact retained observation-certificate bytes against this binding.
    pub fn verify_observation(
        self,
        observation: &CertifiedDepositObservation,
    ) -> Result<(), DepositSyncWireError> {
        self.validate_static()?;
        let bytes =
            observation.to_bytes().map_err(|_| DepositSyncWireError::InvalidCheckpointBinding)?;
        self.certificate
            .verify_contents(&bytes)
            .map_err(|_| DepositSyncWireError::InvalidCheckpointBinding)?;
        if observation.statement.wallet_id() != self.context.wallet
            || observation.statement.allocation_sequence() != self.allocation_sequence
            || observation.statement.digest() != self.statement
        {
            return Err(DepositSyncWireError::InvalidCheckpointBinding);
        }
        Ok(())
    }

    fn validate_statement(
        self,
        statement: &DepositIndexCheckpointStatement,
    ) -> Result<(), DepositSyncWireError> {
        self.validate_static()?;
        if statement.context().wallet_id() != self.context.wallet
            || statement.context().network() != self.context.network
            || statement.sequence() != self.checkpoint_sequence
            || statement.operation()
                != (DepositIndexCheckpointOperation::DepositObservation {
                    statement: self.statement,
                })
        {
            return Err(DepositSyncWireError::InvalidCheckpointBinding);
        }
        Ok(())
    }

    #[must_use]
    pub const fn context(self) -> DepositSyncContext {
        self.context
    }

    #[must_use]
    pub const fn checkpoint_sequence(self) -> u64 {
        self.checkpoint_sequence
    }

    #[must_use]
    pub const fn allocation_sequence(self) -> u64 {
        self.allocation_sequence
    }

    #[must_use]
    pub const fn statement_digest(self) -> [u8; 32] {
        self.statement
    }

    #[must_use]
    pub const fn certificate(self) -> WalletArtifactRef {
        self.certificate
    }
}

/// One independently reconstructed deterministic checkpoint statement and one party witness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositIndexCheckpointAttestWire {
    version: u16,
    binding: DepositIndexCheckpointLedgerBinding,
    statement: DepositIndexCheckpointStatement,
    witness: SignedEnvelope,
}

impl DepositIndexCheckpointAttestWire {
    pub fn new(
        binding: DepositIndexCheckpointLedgerBinding,
        statement: DepositIndexCheckpointStatement,
        witness: SignedEnvelope,
    ) -> Result<Self, DepositSyncWireError> {
        let wire = Self { version: DEPOSIT_SYNC_WIRE_VERSION, binding, statement, witness };
        wire.validate()?;
        Ok(wire)
    }

    fn validate(&self) -> Result<(), DepositSyncWireError> {
        self.binding
            .validate_statement(&self.statement)
            .map_err(|_| DepositSyncWireError::InvalidCheckpointAttestation)?;
        let statement = self
            .statement
            .to_bytes()
            .map_err(|_| DepositSyncWireError::InvalidCheckpointAttestation)?;
        let checkpoint_context = self.statement.context();
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.witness.committee != checkpoint_context.committee_digest()
            || self.witness.epoch != checkpoint_context.epoch()
            || self.witness.to.is_some()
            || self.witness.session != self.statement.slot_session()
            || self.witness.sequence != self.statement.sequence()
            || self.witness.payload != statement
        {
            return Err(DepositSyncWireError::InvalidCheckpointAttestation);
        }
        Ok(())
    }

    #[must_use]
    pub const fn binding(&self) -> DepositIndexCheckpointLedgerBinding {
        self.binding
    }

    #[must_use]
    pub const fn context(&self) -> DepositSyncContext {
        self.binding.context
    }

    #[must_use]
    pub const fn statement(&self) -> &DepositIndexCheckpointStatement {
        &self.statement
    }

    #[must_use]
    pub const fn witness(&self) -> &SignedEnvelope {
        &self.witness
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate()?;
        encode_canonical(self, MAX_INDEX_CHECKPOINT_ATTEST_WIRE_BYTES)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositSyncWireError> {
        let wire = decode_canonical::<Self>(bytes, MAX_INDEX_CHECKPOINT_ATTEST_WIRE_BYTES)?;
        wire.validate()?;
        require_canonical(&wire, bytes, MAX_INDEX_CHECKPOINT_ATTEST_WIRE_BYTES)?;
        Ok(wire)
    }
}

/// Exact quorum checkpoint certificate disseminated with its certified-ledger authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositIndexCheckpointCertificateWire {
    version: u16,
    binding: DepositIndexCheckpointLedgerBinding,
    certificate: DepositIndexCheckpointCertificate,
}

impl DepositIndexCheckpointCertificateWire {
    pub fn new(
        binding: DepositIndexCheckpointLedgerBinding,
        certificate: DepositIndexCheckpointCertificate,
    ) -> Result<Self, DepositSyncWireError> {
        let wire = Self { version: DEPOSIT_SYNC_WIRE_VERSION, binding, certificate };
        wire.validate()?;
        Ok(wire)
    }

    fn validate(&self) -> Result<(), DepositSyncWireError> {
        self.binding
            .validate_statement(self.certificate.statement())
            .map_err(|_| DepositSyncWireError::InvalidCheckpointCertificate)?;
        self.certificate
            .to_bytes()
            .map_err(|_| DepositSyncWireError::InvalidCheckpointCertificate)?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION {
            return Err(DepositSyncWireError::InvalidCheckpointCertificate);
        }
        Ok(())
    }

    #[must_use]
    pub const fn binding(&self) -> DepositIndexCheckpointLedgerBinding {
        self.binding
    }

    #[must_use]
    pub const fn context(&self) -> DepositSyncContext {
        self.binding.context
    }

    #[must_use]
    pub const fn certificate(&self) -> &DepositIndexCheckpointCertificate {
        &self.certificate
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate()?;
        encode_canonical(self, MAX_INDEX_CHECKPOINT_CERTIFICATE_WIRE_BYTES)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositSyncWireError> {
        let wire = decode_canonical::<Self>(bytes, MAX_INDEX_CHECKPOINT_CERTIFICATE_WIRE_BYTES)?;
        wire.validate()?;
        require_canonical(&wire, bytes, MAX_INDEX_CHECKPOINT_CERTIFICATE_WIRE_BYTES)?;
        Ok(wire)
    }
}

/// One observation-checkpoint witness, inseparably bound to the exact observation artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositObservationIndexCheckpointAttestWire {
    version: u16,
    binding: DepositIndexCheckpointObservationBinding,
    statement: DepositIndexCheckpointStatement,
    witness: SignedEnvelope,
}

impl DepositObservationIndexCheckpointAttestWire {
    pub fn new(
        binding: DepositIndexCheckpointObservationBinding,
        statement: DepositIndexCheckpointStatement,
        witness: SignedEnvelope,
    ) -> Result<Self, DepositSyncWireError> {
        let wire = Self { version: DEPOSIT_SYNC_WIRE_VERSION, binding, statement, witness };
        wire.validate()?;
        Ok(wire)
    }

    fn validate(&self) -> Result<(), DepositSyncWireError> {
        self.binding
            .validate_statement(&self.statement)
            .map_err(|_| DepositSyncWireError::InvalidCheckpointAttestation)?;
        let statement = self
            .statement
            .to_bytes()
            .map_err(|_| DepositSyncWireError::InvalidCheckpointAttestation)?;
        let checkpoint_context = self.statement.context();
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.witness.committee != checkpoint_context.committee_digest()
            || self.witness.epoch != checkpoint_context.epoch()
            || self.witness.to.is_some()
            || self.witness.session != self.statement.slot_session()
            || self.witness.sequence != self.statement.sequence()
            || self.witness.payload != statement
        {
            return Err(DepositSyncWireError::InvalidCheckpointAttestation);
        }
        Ok(())
    }

    #[must_use]
    pub const fn binding(&self) -> DepositIndexCheckpointObservationBinding {
        self.binding
    }

    #[must_use]
    pub const fn context(&self) -> DepositSyncContext {
        self.binding.context
    }

    #[must_use]
    pub const fn statement(&self) -> &DepositIndexCheckpointStatement {
        &self.statement
    }

    #[must_use]
    pub const fn witness(&self) -> &SignedEnvelope {
        &self.witness
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate()?;
        encode_canonical(self, MAX_INDEX_CHECKPOINT_ATTEST_WIRE_BYTES)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositSyncWireError> {
        let wire = decode_canonical::<Self>(bytes, MAX_INDEX_CHECKPOINT_ATTEST_WIRE_BYTES)?;
        wire.validate()?;
        require_canonical(&wire, bytes, MAX_INDEX_CHECKPOINT_ATTEST_WIRE_BYTES)?;
        Ok(wire)
    }
}

/// Exact observation-checkpoint quorum certificate plus its certified-observation authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositObservationIndexCheckpointCertificateWire {
    version: u16,
    binding: DepositIndexCheckpointObservationBinding,
    certificate: DepositIndexCheckpointCertificate,
}

impl DepositObservationIndexCheckpointCertificateWire {
    pub fn new(
        binding: DepositIndexCheckpointObservationBinding,
        certificate: DepositIndexCheckpointCertificate,
    ) -> Result<Self, DepositSyncWireError> {
        let wire = Self { version: DEPOSIT_SYNC_WIRE_VERSION, binding, certificate };
        wire.validate()?;
        Ok(wire)
    }

    fn validate(&self) -> Result<(), DepositSyncWireError> {
        self.binding
            .validate_statement(self.certificate.statement())
            .map_err(|_| DepositSyncWireError::InvalidCheckpointCertificate)?;
        self.certificate
            .to_bytes()
            .map_err(|_| DepositSyncWireError::InvalidCheckpointCertificate)?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION {
            return Err(DepositSyncWireError::InvalidCheckpointCertificate);
        }
        Ok(())
    }

    #[must_use]
    pub const fn binding(&self) -> DepositIndexCheckpointObservationBinding {
        self.binding
    }

    #[must_use]
    pub const fn context(&self) -> DepositSyncContext {
        self.binding.context
    }

    #[must_use]
    pub const fn certificate(&self) -> &DepositIndexCheckpointCertificate {
        &self.certificate
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate()?;
        encode_canonical(self, MAX_INDEX_CHECKPOINT_CERTIFICATE_WIRE_BYTES)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositSyncWireError> {
        let wire = decode_canonical::<Self>(bytes, MAX_INDEX_CHECKPOINT_CERTIFICATE_WIRE_BYTES)?;
        wire.validate()?;
        require_canonical(&wire, bytes, MAX_INDEX_CHECKPOINT_CERTIFICATE_WIRE_BYTES)?;
        Ok(wire)
    }
}

/// Request for the current compact catch-up roots.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncHeadRequest {
    version: u16,
    context: DepositSyncContext,
}

impl DepositSyncHeadRequest {
    pub fn new(context: DepositSyncContext) -> Result<Self, DepositSyncWireError> {
        let request = Self { version: DEPOSIT_SYNC_WIRE_VERSION, context };
        request.validate()?;
        Ok(request)
    }

    fn validate(self) -> Result<(), DepositSyncWireError> {
        self.context.validate()?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION {
            return Err(DepositSyncWireError::UnsupportedVersion);
        }
        Ok(())
    }

    #[must_use]
    pub const fn context(self) -> DepositSyncContext {
        self.context
    }

    pub fn to_bytes(self) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate()?;
        encode_canonical(&self, MAX_HEAD_REQUEST_BYTES)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositSyncWireError> {
        let request = decode_canonical::<Self>(bytes, MAX_HEAD_REQUEST_BYTES)?;
        request.validate()?;
        require_canonical(&request, bytes, MAX_HEAD_REQUEST_BYTES)?;
        Ok(request)
    }
}

/// Current authoritative roots advertised by one authenticated peer.
///
/// `registry_checkpoint` names that peer's exact settled compact-registry archive layout. Its
/// witness references can differ across honest replicas. `registry_id` and
/// `portable_index.digest()` are the witness-independent consensus identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncAdvertisement {
    version: u16,
    context: DepositSyncContext,
    registry_checkpoint: [u8; 32],
    registry_id: RegistryId,
    registry_archive: CompactRegistryArchiveHead,
    certificate_archive: DepositArchiveHead,
    portable_index: PortableDepositIndexHead,
    checkpoint_certificate: Option<DepositIndexCheckpointCertificate>,
}

impl DepositSyncAdvertisement {
    /// Project only settled snapshot authorities into a portable advertisement.
    ///
    /// A non-genesis portable head requires the latest exact n-f checkpoint certificate.
    /// Cryptographic verification remains a caller responsibility because it also requires the
    /// operation-specific certificate and bounded registry issuer window fetched from these roots.
    pub fn from_checkpoints(
        context: DepositSyncContext,
        registry: &CompactRegistryStoreCheckpoint,
        certificate_archive: DepositArchiveHead,
        index: &DepositIndexStoreCheckpoint,
        checkpoint_certificate: Option<DepositIndexCheckpointCertificate>,
    ) -> Result<Self, DepositSyncWireError> {
        context.validate()?;
        if registry.wallet() != context.wallet
            || index.wallet() != context.wallet
            || registry.has_recovery_journal()
            || index.has_recovery_journal()
        {
            return Err(DepositSyncWireError::UnsettledCheckpoint);
        }
        let registry_archive =
            registry.head().cloned().ok_or(DepositSyncWireError::MissingRegistryHead)?;
        let portable_index = PortableDepositIndexHead::from_head(index.portable_head())
            .map_err(|_| DepositSyncWireError::InvalidAdvertisement)?;
        let advertisement = Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            context,
            registry_checkpoint: registry.digest(),
            registry_id: registry_archive.registry_id(),
            registry_archive,
            certificate_archive,
            portable_index,
            checkpoint_certificate,
        };
        advertisement.validate()?;
        Ok(advertisement)
    }

    fn validate(&self) -> Result<(), DepositSyncWireError> {
        self.context.validate()?;
        self.registry_archive
            .validate_shape()
            .map_err(|_| DepositSyncWireError::InvalidAdvertisement)?;
        self.certificate_archive
            .validate()
            .map_err(|_| DepositSyncWireError::InvalidAdvertisement)?;
        self.registry_id.validate().map_err(|_| DepositSyncWireError::InvalidAdvertisement)?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.registry_checkpoint == [0; 32]
            || self.registry_archive.wallet() != self.context.wallet
            || self.registry_id != self.registry_archive.registry_id()
            || self.registry_id.wallet() != self.context.wallet
            || self.certificate_archive.wallet_id() != self.context.wallet
            || self.portable_index.wallet_id() != self.context.wallet
        {
            return Err(DepositSyncWireError::InvalidAdvertisement);
        }

        let reconstructed = CompactRegistryStoreCheckpoint::settled(
            self.context.wallet,
            self.registry_archive.clone(),
        )
        .map_err(|_| DepositSyncWireError::InvalidAdvertisement)?;
        if reconstructed.digest() != self.registry_checkpoint {
            return Err(DepositSyncWireError::InvalidAdvertisement);
        }

        let active = self.registry_archive.registry().active();
        let boundary = active
            .start_sequence()
            .checked_sub(1)
            .ok_or(DepositSyncWireError::InvalidAdvertisement)?;
        if self.portable_index.through_sequence() < boundary {
            return Err(DepositSyncWireError::InvalidAdvertisement);
        }
        if self.portable_index.through_sequence() == boundary
            && (self.portable_index.digest() != active.portable_index_checkpoint()
                || self.portable_index.ledger_head() != active.predecessor_ledger_head()
                || self.portable_index.next_index() != active.first_index())
        {
            return Err(DepositSyncWireError::InvalidAdvertisement);
        }

        match (&self.checkpoint_certificate, self.certificate_archive.len()) {
            (None, 0) if self.portable_index.through_sequence() == 0 => {
                let empty = DepositIndexHead::empty_portable(
                    self.context.wallet,
                    self.portable_index.next_index(),
                )
                .map_err(|_| DepositSyncWireError::InvalidAdvertisement)?;
                let expected = PortableDepositIndexHead::from_head(&empty)
                    .map_err(|_| DepositSyncWireError::InvalidAdvertisement)?;
                if expected != self.portable_index {
                    return Err(DepositSyncWireError::InvalidAdvertisement);
                }
            }
            (Some(certificate), checkpoint_sequence) if checkpoint_sequence != 0 => {
                if self.certificate_archive.event_reference().is_none()
                    || self.certificate_archive.segment_reference().is_none()
                {
                    return Err(DepositSyncWireError::InvalidAdvertisement);
                }
                certificate.to_bytes().map_err(|_| DepositSyncWireError::InvalidAdvertisement)?;
                let statement = certificate.statement();
                if statement.sequence() != checkpoint_sequence
                    || statement.ledger_sequence() != self.portable_index.through_sequence()
                    || statement.ledger_decision() != self.portable_index.ledger_head()
                    || statement.resulting_head() != &self.portable_index
                    || statement.context().wallet_id() != self.context.wallet
                    || statement.context().network() != self.context.network
                {
                    return Err(DepositSyncWireError::InvalidAdvertisement);
                }
            }
            _ => return Err(DepositSyncWireError::InvalidAdvertisement),
        }
        Ok(())
    }

    #[must_use]
    pub const fn context(&self) -> DepositSyncContext {
        self.context
    }

    #[must_use]
    pub const fn registry_checkpoint_digest(&self) -> [u8; 32] {
        self.registry_checkpoint
    }

    #[must_use]
    pub const fn registry_id(&self) -> RegistryId {
        self.registry_id
    }

    #[must_use]
    pub const fn registry_archive(&self) -> &CompactRegistryArchiveHead {
        &self.registry_archive
    }

    #[must_use]
    pub const fn certificate_archive(&self) -> DepositArchiveHead {
        self.certificate_archive
    }

    #[must_use]
    pub const fn portable_index(&self) -> &PortableDepositIndexHead {
        &self.portable_index
    }

    #[must_use]
    pub const fn checkpoint_certificate(&self) -> Option<&DepositIndexCheckpointCertificate> {
        self.checkpoint_certificate.as_ref()
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate()?;
        encode_canonical(self, MAX_ADVERTISEMENT_BYTES)
    }

    pub fn to_bytes(
        &self,
        request: DepositSyncHeadRequest,
    ) -> Result<Vec<u8>, DepositSyncWireError> {
        request.validate()?;
        self.validate()?;
        if self.context != request.context {
            return Err(DepositSyncWireError::InvalidAdvertisement);
        }
        self.canonical_bytes()
    }

    pub fn from_bytes(
        request: DepositSyncHeadRequest,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncWireError> {
        request.validate()?;
        let advertisement = decode_canonical::<Self>(bytes, MAX_ADVERTISEMENT_BYTES)?;
        advertisement.validate()?;
        if advertisement.context != request.context {
            return Err(DepositSyncWireError::InvalidAdvertisement);
        }
        require_canonical(&advertisement, bytes, MAX_ADVERTISEMENT_BYTES)?;
        Ok(advertisement)
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = self.canonical_bytes().expect("validated advertisement serializes canonically");
        length_prefixed_hash(ADVERTISEMENT_DIGEST_DOMAIN, &bytes)
    }

    #[must_use]
    pub fn object_anchor(&self) -> DepositSyncObjectAnchor {
        DepositSyncObjectAnchor::from_advertisement(self)
    }
}

/// Exact advertised roots to which every finite object frontier is pinned.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncObjectAnchor {
    version: u16,
    context: [u8; 32],
    wallet: DepositWalletId,
    advertisement: [u8; 32],
    registry_checkpoint: [u8; 32],
    registry_id: [u8; 32],
    registry_root: CompactRegistryObjectRef,
    portable_index: [u8; 32],
    portable_root: Option<DepositIndexObjectId>,
    certificate_archive: [u8; 32],
    certificate_event_root: Option<WalletArtifactRef>,
    certificate_segment_root: Option<WalletArtifactRef>,
    ledger_sequence: u64,
    checkpoint_sequence: u64,
}

impl DepositSyncObjectAnchor {
    fn from_advertisement(advertisement: &DepositSyncAdvertisement) -> Self {
        Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            context: advertisement.context.digest(),
            wallet: advertisement.context.wallet,
            advertisement: advertisement.digest(),
            registry_checkpoint: advertisement.registry_checkpoint,
            registry_id: advertisement.registry_id.digest(),
            registry_root: advertisement.registry_archive.index_root_reference(),
            portable_index: advertisement.portable_index.digest(),
            portable_root: advertisement.portable_index.root(),
            certificate_archive: certificate_archive_digest(advertisement.certificate_archive),
            certificate_event_root: advertisement.certificate_archive.event_reference(),
            certificate_segment_root: advertisement.certificate_archive.segment_reference(),
            ledger_sequence: advertisement.portable_index.through_sequence(),
            checkpoint_sequence: advertisement.certificate_archive.len(),
        }
    }

    fn validate_for(
        self,
        context: DepositSyncContext,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<(), DepositSyncWireError> {
        context.validate()?;
        advertisement.validate()?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.wallet != context.wallet
            || self.context != context.digest()
            || context != advertisement.context
            || self != Self::from_advertisement(advertisement)
        {
            return Err(DepositSyncWireError::WrongAdvertisement);
        }
        Ok(())
    }

    #[must_use]
    pub const fn advertisement_digest(self) -> [u8; 32] {
        self.advertisement
    }

    #[must_use]
    pub const fn registry_root(self) -> CompactRegistryObjectRef {
        self.registry_root
    }

    #[must_use]
    pub const fn portable_root(self) -> Option<DepositIndexObjectId> {
        self.portable_root
    }

    #[must_use]
    pub const fn registry_id_digest(self) -> [u8; 32] {
        self.registry_id
    }

    #[must_use]
    pub const fn portable_index_digest(self) -> [u8; 32] {
        self.portable_index
    }

    #[must_use]
    pub const fn certificate_archive_digest(self) -> [u8; 32] {
        self.certificate_archive
    }

    #[must_use]
    pub const fn ledger_sequence(self) -> u64 {
        self.ledger_sequence
    }

    #[must_use]
    pub const fn checkpoint_sequence(self) -> u64 {
        self.checkpoint_sequence
    }

    #[must_use]
    pub const fn certificate_event_root(self) -> Option<WalletArtifactRef> {
        self.certificate_event_root
    }

    #[must_use]
    pub const fn certificate_segment_root(self) -> Option<WalletArtifactRef> {
        self.certificate_segment_root
    }
}

/// One exact immutable object address from an advertised authenticated traversal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DepositSyncObjectRef {
    Registry(CompactRegistryObjectRef),
    Index(DepositIndexObjectId),
    CertificateArchive(WalletArtifactRef),
}

impl DepositSyncObjectRef {
    fn validate_for(self, wallet: DepositWalletId) -> Result<(), DepositSyncWireError> {
        match self {
            Self::Registry(reference) => {
                reference
                    .storage_reference()
                    .map_err(|_| DepositSyncWireError::InvalidObjectReference)?;
                if reference.wallet() != wallet {
                    return Err(DepositSyncWireError::InvalidObjectReference);
                }
            }
            Self::Index(id) => {
                if id.wallet_id() != wallet
                    || DepositIndexObjectId::from_storage_reference(id.storage_reference())
                        .map_err(|_| DepositSyncWireError::InvalidObjectReference)?
                        != id
                {
                    return Err(DepositSyncWireError::InvalidObjectReference);
                }
            }
            Self::CertificateArchive(reference) => {
                validate_certificate_archive_reference(reference, wallet)?;
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn wallet(self) -> DepositWalletId {
        match self {
            Self::Registry(reference) => reference.wallet(),
            Self::Index(id) => id.wallet_id(),
            Self::CertificateArchive(reference) => DepositWalletId(reference.wallet_id().0),
        }
    }

    #[must_use]
    pub const fn plaintext_len(self) -> u64 {
        match self {
            Self::Registry(reference) => reference.plaintext_len(),
            Self::Index(id) => id.plaintext_len(),
            Self::CertificateArchive(reference) => reference.plaintext_len(),
        }
    }

    pub fn storage_reference(self) -> Result<WalletArtifactRef, DepositSyncWireError> {
        match self {
            Self::Registry(reference) => reference
                .storage_reference()
                .map_err(|_| DepositSyncWireError::InvalidObjectReference),
            Self::Index(id) => Ok(id.storage_reference()),
            Self::CertificateArchive(reference) => {
                validate_certificate_archive_reference(reference, self.wallet())?;
                Ok(reference)
            }
        }
    }
}

/// A content-addressed plaintext object. Reachability remains authenticated by the caller's
/// traversal from [`DepositSyncObjectAnchor`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncObject {
    reference: DepositSyncObjectRef,
    bytes: Vec<u8>,
}

impl DepositSyncObject {
    pub fn new(
        reference: DepositSyncObjectRef,
        bytes: Vec<u8>,
    ) -> Result<Self, DepositSyncWireError> {
        let object = Self { reference, bytes };
        object.validate_for(reference.wallet())?;
        Ok(object)
    }

    fn validate_for(&self, wallet: DepositWalletId) -> Result<(), DepositSyncWireError> {
        self.reference.validate_for(wallet)?;
        if self.bytes.is_empty()
            || self.bytes.len()
                > match self.reference {
                    DepositSyncObjectRef::Registry(reference) => {
                        usize::try_from(reference.plaintext_len())
                            .map_err(|_| DepositSyncWireError::InvalidObjectReference)?
                    }
                    DepositSyncObjectRef::Index(_) => MAX_DEPOSIT_INDEX_OBJECT_BYTES,
                    DepositSyncObjectRef::CertificateArchive(reference) => {
                        certificate_archive_reference_maximum(reference)?
                    }
                }
            || usize::try_from(self.reference.plaintext_len())
                .ok()
                .is_none_or(|length| length != self.bytes.len())
        {
            return Err(DepositSyncWireError::InvalidObject);
        }
        match self.reference {
            DepositSyncObjectRef::Registry(reference) => {
                reference
                    .verify_contents(&self.bytes)
                    .map_err(|_| DepositSyncWireError::ObjectAuthentication)?;
                verify_compact_registry_object(reference, &self.bytes)
                    .map_err(|_| DepositSyncWireError::InvalidObject)?;
            }
            DepositSyncObjectRef::Index(id) => {
                id.storage_reference()
                    .verify_contents(&self.bytes)
                    .map_err(|_| DepositSyncWireError::ObjectAuthentication)?;
                verify_portable_index_object(wallet, id, &self.bytes)
                    .map_err(|_| DepositSyncWireError::InvalidObject)?;
            }
            DepositSyncObjectRef::CertificateArchive(reference) => {
                reference
                    .verify_contents(&self.bytes)
                    .map_err(|_| DepositSyncWireError::ObjectAuthentication)?;
                match reference.kind() {
                    DEPOSIT_ARCHIVE_EVENT_ARTIFACT => {
                        let event = DepositArchiveEvent::from_bytes(&self.bytes)
                            .map_err(|_| DepositSyncWireError::InvalidObject)?;
                        if event.wallet_id() != wallet {
                            return Err(DepositSyncWireError::InvalidObject);
                        }
                    }
                    DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT => {
                        let segment = DepositArchiveSegment::from_bytes(&self.bytes)
                            .map_err(|_| DepositSyncWireError::InvalidObject)?;
                        if segment.wallet_id() != wallet {
                            return Err(DepositSyncWireError::InvalidObject);
                        }
                    }
                    CERTIFIED_LEDGER_ENTRY_ARTIFACT => {
                        let entry = CertifiedLedgerEntry::from_bytes(&self.bytes)
                            .map_err(|_| DepositSyncWireError::InvalidObject)?;
                        if entry.statement.wallet != wallet {
                            return Err(DepositSyncWireError::InvalidObject);
                        }
                    }
                    CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT => {
                        let observation = CertifiedDepositObservation::from_bytes(&self.bytes)
                            .map_err(|_| DepositSyncWireError::InvalidObject)?;
                        if observation.statement.wallet_id() != wallet {
                            return Err(DepositSyncWireError::InvalidObject);
                        }
                    }
                    DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT => {
                        let checkpoint = DepositIndexCheckpointCertificate::from_bytes(&self.bytes)
                            .map_err(|_| DepositSyncWireError::InvalidObject)?;
                        if checkpoint.statement().context().wallet_id() != wallet {
                            return Err(DepositSyncWireError::InvalidObject);
                        }
                    }
                    _ => return Err(DepositSyncWireError::InvalidObjectReference),
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn reference(&self) -> DepositSyncObjectRef {
        self.reference
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn children(&self) -> Result<Vec<DepositSyncObjectRef>, DepositSyncWireError> {
        match self.reference {
            DepositSyncObjectRef::Registry(reference) => {
                let verified = verify_compact_registry_object(reference, &self.bytes)
                    .map_err(|_| DepositSyncWireError::InvalidObject)?;
                Ok(verified
                    .children()
                    .iter()
                    .copied()
                    .map(DepositSyncObjectRef::Registry)
                    .collect())
            }
            DepositSyncObjectRef::Index(id) => {
                let verified =
                    verify_portable_index_object(self.reference.wallet(), id, &self.bytes)
                        .map_err(|_| DepositSyncWireError::InvalidObject)?;
                Ok(verified.children().iter().copied().map(DepositSyncObjectRef::Index).collect())
            }
            DepositSyncObjectRef::CertificateArchive(reference) => match reference.kind() {
                DEPOSIT_ARCHIVE_EVENT_ARTIFACT => {
                    let event = DepositArchiveEvent::from_bytes(&self.bytes)
                        .map_err(|_| DepositSyncWireError::InvalidObject)?;
                    let mut children = Vec::with_capacity(3);
                    children.extend(event.previous().map(DepositSyncObjectRef::CertificateArchive));
                    children.push(DepositSyncObjectRef::CertificateArchive(
                        event.operation_reference(),
                    ));
                    children.push(DepositSyncObjectRef::CertificateArchive(
                        event.checkpoint_reference(),
                    ));
                    Ok(children)
                }
                DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT => {
                    let segment = DepositArchiveSegment::from_bytes(&self.bytes)
                        .map_err(|_| DepositSyncWireError::InvalidObject)?;
                    let mut children = Vec::with_capacity(
                        segment.event_references().len()
                            + usize::from(segment.previous().is_some()),
                    );
                    children
                        .extend(segment.previous().map(DepositSyncObjectRef::CertificateArchive));
                    children.extend(
                        segment
                            .event_references()
                            .iter()
                            .copied()
                            .map(DepositSyncObjectRef::CertificateArchive),
                    );
                    Ok(children)
                }
                CERTIFIED_LEDGER_ENTRY_ARTIFACT
                | CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT
                | DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT => Ok(Vec::new()),
                _ => Err(DepositSyncWireError::InvalidObjectReference),
            },
        }
    }
}

/// Cursor bound to one exact finite object manifest and advertisement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncObjectCursor {
    version: u16,
    domain: [u8; 16],
    wallet: DepositWalletId,
    advertisement: [u8; 32],
    manifest: [u8; 32],
    position: u16,
}

impl DepositSyncObjectCursor {
    fn new(
        context: DepositSyncContext,
        anchor: DepositSyncObjectAnchor,
        manifest: [u8; 32],
        position: usize,
    ) -> Result<Self, DepositSyncWireError> {
        let cursor = Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            domain: DEPOSIT_SYNC_WIRE_DOMAIN,
            wallet: context.wallet,
            advertisement: anchor.advertisement,
            manifest,
            position: u16::try_from(position).map_err(|_| DepositSyncWireError::InvalidCursor)?,
        };
        cursor.validate(context, anchor, manifest, MAX_DEPOSIT_SYNC_REQUEST_OBJECTS)?;
        Ok(cursor)
    }

    fn validate(
        self,
        context: DepositSyncContext,
        anchor: DepositSyncObjectAnchor,
        manifest: [u8; 32],
        reference_count: usize,
    ) -> Result<(), DepositSyncWireError> {
        let position = usize::from(self.position);
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.domain != DEPOSIT_SYNC_WIRE_DOMAIN
            || self.wallet != context.wallet
            || self.advertisement != anchor.advertisement
            || self.manifest != manifest
            || position >= reference_count
        {
            return Err(DepositSyncWireError::InvalidCursor);
        }
        Ok(())
    }

    #[must_use]
    pub const fn position(self) -> u16 {
        self.position
    }
}

/// One finite, root-pinned object frontier with deterministic pagination limits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncObjectPageRequest {
    version: u16,
    context: DepositSyncContext,
    anchor: DepositSyncObjectAnchor,
    #[serde(deserialize_with = "deserialize_object_references")]
    references: Vec<DepositSyncObjectRef>,
    maximum_objects: u16,
    maximum_plaintext_bytes: u32,
    cursor: DepositSyncObjectCursor,
}

impl DepositSyncObjectPageRequest {
    pub fn new(
        advertisement: &DepositSyncAdvertisement,
        references: Vec<DepositSyncObjectRef>,
        maximum_objects: u16,
        maximum_plaintext_bytes: u32,
    ) -> Result<Self, DepositSyncWireError> {
        advertisement.validate()?;
        let context = advertisement.context;
        let anchor = advertisement.object_anchor();
        let manifest = object_manifest_digest(
            context,
            anchor,
            &references,
            maximum_objects,
            maximum_plaintext_bytes,
        )?;
        let cursor = DepositSyncObjectCursor::new(context, anchor, manifest, 0)?;
        let request = Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            context,
            anchor,
            references,
            maximum_objects,
            maximum_plaintext_bytes,
            cursor,
        };
        request.validate_for(advertisement)?;
        Ok(request)
    }

    pub fn with_cursor(
        &self,
        advertisement: &DepositSyncAdvertisement,
        cursor: DepositSyncObjectCursor,
    ) -> Result<Self, DepositSyncWireError> {
        let mut request = self.clone();
        request.cursor = cursor;
        request.validate_for(advertisement)?;
        Ok(request)
    }

    pub fn validate_for(
        &self,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<(), DepositSyncWireError> {
        self.context.validate()?;
        self.anchor.validate_for(self.context, advertisement)?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.references.is_empty()
            || self.references.len() > MAX_DEPOSIT_SYNC_REQUEST_OBJECTS
            || self.maximum_objects == 0
            || usize::from(self.maximum_objects) > MAX_DEPOSIT_SYNC_PAGE_OBJECTS
            || self.maximum_plaintext_bytes == 0
            || usize::try_from(self.maximum_plaintext_bytes)
                .map_err(|_| DepositSyncWireError::InvalidObjectRequest)?
                > MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES
        {
            return Err(DepositSyncWireError::InvalidObjectRequest);
        }
        let first = self.references[0];
        let starts_at_advertised_root = first
            == DepositSyncObjectRef::Registry(self.anchor.registry_root)
            || self
                .anchor
                .portable_root
                .is_some_and(|root| first == DepositSyncObjectRef::Index(root))
            || self
                .anchor
                .certificate_event_root
                .is_some_and(|root| first == DepositSyncObjectRef::CertificateArchive(root))
            || self
                .anchor
                .certificate_segment_root
                .is_some_and(|root| first == DepositSyncObjectRef::CertificateArchive(root));
        if !starts_at_advertised_root {
            return Err(DepositSyncWireError::InvalidObjectRequest);
        }
        let mut unique = BTreeSet::new();
        let mut manifest_bytes = 0_usize;
        for reference in &self.references {
            reference.validate_for(self.context.wallet)?;
            if !unique.insert(*reference) {
                return Err(DepositSyncWireError::InvalidObjectRequest);
            }
            manifest_bytes = manifest_bytes
                .checked_add(
                    usize::try_from(reference.plaintext_len())
                        .map_err(|_| DepositSyncWireError::InvalidObjectRequest)?,
                )
                .ok_or(DepositSyncWireError::InvalidObjectRequest)?;
        }
        if manifest_bytes > MAX_DEPOSIT_SYNC_MANIFEST_PLAINTEXT_BYTES {
            return Err(DepositSyncWireError::InvalidObjectRequest);
        }
        let manifest = object_manifest_digest(
            self.context,
            self.anchor,
            &self.references,
            self.maximum_objects,
            self.maximum_plaintext_bytes,
        )?;
        self.cursor.validate(self.context, self.anchor, manifest, self.references.len())
    }

    #[must_use]
    pub const fn context(&self) -> DepositSyncContext {
        self.context
    }

    #[must_use]
    pub const fn anchor(&self) -> DepositSyncObjectAnchor {
        self.anchor
    }

    #[must_use]
    pub fn references(&self) -> &[DepositSyncObjectRef] {
        &self.references
    }

    #[must_use]
    pub const fn cursor(&self) -> DepositSyncObjectCursor {
        self.cursor
    }

    #[must_use]
    pub const fn maximum_objects(&self) -> u16 {
        self.maximum_objects
    }

    #[must_use]
    pub const fn maximum_plaintext_bytes(&self) -> u32 {
        self.maximum_plaintext_bytes
    }

    pub fn to_bytes(
        &self,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate_for(advertisement)?;
        encode_canonical(self, MAX_OBJECT_REQUEST_BYTES)
    }

    pub fn from_bytes(
        advertisement: &DepositSyncAdvertisement,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncWireError> {
        let request = decode_canonical::<Self>(bytes, MAX_OBJECT_REQUEST_BYTES)?;
        request.validate_for(advertisement)?;
        require_canonical(&request, bytes, MAX_OBJECT_REQUEST_BYTES)?;
        Ok(request)
    }

    /// Decode only enough bounded canonical structure to select the local wallet authority.
    ///
    /// The returned context does not authenticate the request's advertisement anchor. A handler
    /// must immediately load its exact local advertisement and call [`Self::from_bytes`] again.
    pub fn context_from_bytes(bytes: &[u8]) -> Result<DepositSyncContext, DepositSyncWireError> {
        let request = decode_canonical::<Self>(bytes, MAX_OBJECT_REQUEST_BYTES)?;
        request.context.validate()?;
        if request.version != DEPOSIT_SYNC_WIRE_VERSION {
            return Err(DepositSyncWireError::UnsupportedVersion);
        }
        require_canonical(&request, bytes, MAX_OBJECT_REQUEST_BYTES)?;
        Ok(request.context)
    }

    fn manifest_digest(&self) -> Result<[u8; 32], DepositSyncWireError> {
        object_manifest_digest(
            self.context,
            self.anchor,
            &self.references,
            self.maximum_objects,
            self.maximum_plaintext_bytes,
        )
    }

    /// Authenticate the complete ordered frontier before any of its plaintext may be returned.
    ///
    /// Every reference must be either an exact advertised root or a child edge decoded from an
    /// earlier authenticated object. The callback is therefore never invoked for a detached
    /// reference. Portable-index decoding also rejects the party-local safety namespace.
    pub fn verify_reachable_manifest<F>(
        &self,
        advertisement: &DepositSyncAdvertisement,
        mut load: F,
    ) -> Result<VerifiedDepositSyncObjectManifest, DepositSyncWireError>
    where
        F: FnMut(DepositSyncObjectRef) -> Result<Option<Vec<u8>>, DepositSyncWireError>,
    {
        self.validate_for(advertisement)?;
        let mut reachable = BTreeSet::new();
        reachable.insert(DepositSyncObjectRef::Registry(self.anchor.registry_root));
        if let Some(root) = self.anchor.portable_root {
            reachable.insert(DepositSyncObjectRef::Index(root));
        }
        if let Some(root) = self.anchor.certificate_event_root {
            reachable.insert(DepositSyncObjectRef::CertificateArchive(root));
        }
        if let Some(root) = self.anchor.certificate_segment_root {
            reachable.insert(DepositSyncObjectRef::CertificateArchive(root));
        }

        let mut objects = Vec::with_capacity(self.references.len());
        for reference in self.references.iter().copied() {
            if !reachable.remove(&reference) {
                return Err(DepositSyncWireError::UnreachableObjectReference);
            }
            let bytes = load(reference)?.ok_or(DepositSyncWireError::ObjectUnavailable)?;
            let object = DepositSyncObject::new(reference, bytes)?;
            if self
                .anchor
                .portable_root
                .is_some_and(|root| reference == DepositSyncObjectRef::Index(root))
            {
                let DepositSyncObjectRef::Index(id) = reference else {
                    return Err(DepositSyncWireError::InvalidObject);
                };
                let verified =
                    verify_portable_index_object(self.context.wallet, id, object.bytes())
                        .map_err(|_| DepositSyncWireError::InvalidObject)?;
                if !verified.is_node() {
                    return Err(DepositSyncWireError::InvalidObject);
                }
            }
            for child in object.children()? {
                child.validate_for(self.context.wallet)?;
                reachable.insert(child);
            }
            objects.push(object);
        }
        let verified = VerifiedDepositSyncObjectManifest {
            context: self.context,
            advertisement: self.anchor.advertisement,
            manifest: self.manifest_digest()?,
            objects,
        };
        verified.validate_for(self, advertisement)?;
        Ok(verified)
    }
}

/// Non-deserializable proof that one complete finite object manifest is connected to advertised
/// roots and contains no party-local index values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDepositSyncObjectManifest {
    context: DepositSyncContext,
    advertisement: [u8; 32],
    manifest: [u8; 32],
    objects: Vec<DepositSyncObject>,
}

impl VerifiedDepositSyncObjectManifest {
    fn validate_for(
        &self,
        request: &DepositSyncObjectPageRequest,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<(), DepositSyncWireError> {
        request.validate_for(advertisement)?;
        if self.context != request.context
            || self.advertisement != request.anchor.advertisement
            || self.manifest != request.manifest_digest()?
            || self.objects.len() != request.references.len()
            || self
                .objects
                .iter()
                .zip(&request.references)
                .any(|(object, reference)| object.reference != *reference)
        {
            return Err(DepositSyncWireError::InvalidObjectManifest);
        }
        for object in &self.objects {
            object.validate_for(request.context.wallet)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn objects(&self) -> &[DepositSyncObject] {
        &self.objects
    }

    /// Derive both exact operation and checkpoint-certificate references from the directly
    /// advertised latest archive event. No caller-supplied payload reference is accepted.
    pub fn checkpoint_artifacts(
        &self,
        request: &DepositSyncObjectPageRequest,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<VerifiedDepositCheckpointArtifacts, DepositSyncWireError> {
        self.validate_for(request, advertisement)?;
        let head = advertisement.certificate_archive;
        let event_reference =
            head.event_reference().ok_or(DepositSyncWireError::InvalidCertifiedArtifact)?;
        let expected = DepositSyncObjectRef::CertificateArchive(event_reference);
        let object = self
            .objects
            .iter()
            .find(|object| object.reference == expected)
            .ok_or(DepositSyncWireError::InvalidCertifiedArtifact)?;
        VerifiedDepositCheckpointArtifacts::from_checkpoint_event(advertisement, object.bytes())
    }
}

/// Deterministic, hard-bounded page for one exact object manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncObjectPage {
    version: u16,
    context: DepositSyncContext,
    anchor: DepositSyncObjectAnchor,
    manifest: [u8; 32],
    start: u16,
    #[serde(deserialize_with = "deserialize_objects")]
    objects: Vec<DepositSyncObject>,
    next: Option<DepositSyncObjectCursor>,
}

impl DepositSyncObjectPage {
    /// Build one deterministic page only from a previously verified connected manifest.
    pub fn build(
        request: &DepositSyncObjectPageRequest,
        advertisement: &DepositSyncAdvertisement,
        verified: &VerifiedDepositSyncObjectManifest,
    ) -> Result<Self, DepositSyncWireError> {
        request.validate_for(advertisement)?;
        verified.validate_for(request, advertisement)?;
        let start = usize::from(request.cursor.position);
        let end = deterministic_page_end(request)?;
        let objects = verified.objects[start..end].to_vec();
        let manifest = request.manifest_digest()?;
        let next = if end < request.references.len() {
            Some(DepositSyncObjectCursor::new(request.context, request.anchor, manifest, end)?)
        } else {
            None
        };
        let page = Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            context: request.context,
            anchor: request.anchor,
            manifest,
            start: u16::try_from(start).map_err(|_| DepositSyncWireError::InvalidCursor)?,
            objects,
            next,
        };
        page.validate_for(request, advertisement)?;
        Ok(page)
    }

    pub fn validate_for(
        &self,
        request: &DepositSyncObjectPageRequest,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<(), DepositSyncWireError> {
        request.validate_for(advertisement)?;
        self.context.validate()?;
        let manifest = request.manifest_digest()?;
        let start = usize::from(self.start);
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.context != request.context
            || self.anchor != request.anchor
            || self.manifest != manifest
            || start != usize::from(request.cursor.position)
            || self.objects.is_empty()
            || self.objects.len() > usize::from(request.maximum_objects)
            || self.objects.len() > MAX_DEPOSIT_SYNC_PAGE_OBJECTS
            || start
                .checked_add(self.objects.len())
                .is_none_or(|end| end > request.references.len())
        {
            return Err(DepositSyncWireError::InvalidObjectPage);
        }
        let mut plaintext_bytes = 0_usize;
        for (offset, object) in self.objects.iter().enumerate() {
            if object.reference
                != request.references
                    [start.checked_add(offset).ok_or(DepositSyncWireError::InvalidObjectPage)?]
            {
                return Err(DepositSyncWireError::InvalidObjectPage);
            }
            object.validate_for(request.context.wallet)?;
            plaintext_bytes = plaintext_bytes
                .checked_add(object.bytes.len())
                .ok_or(DepositSyncWireError::InvalidObjectPage)?;
        }
        if plaintext_bytes
            > usize::try_from(request.maximum_plaintext_bytes)
                .map_err(|_| DepositSyncWireError::InvalidObjectPage)?
            || plaintext_bytes > MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES
        {
            return Err(DepositSyncWireError::InvalidObjectPage);
        }
        let end = start + self.objects.len();
        if end != deterministic_page_end(request)? {
            return Err(DepositSyncWireError::InvalidObjectPage);
        }
        match (self.next, end == request.references.len()) {
            (None, true) => {}
            (Some(cursor), false) => cursor.validate(
                request.context,
                request.anchor,
                manifest,
                request.references.len(),
            )?,
            _ => return Err(DepositSyncWireError::InvalidObjectPage),
        }
        if self.next.is_some_and(|cursor| usize::from(cursor.position) != end) {
            return Err(DepositSyncWireError::InvalidObjectPage);
        }
        Ok(())
    }

    #[must_use]
    pub fn objects(&self) -> &[DepositSyncObject] {
        &self.objects
    }

    #[must_use]
    pub const fn next_cursor(&self) -> Option<DepositSyncObjectCursor> {
        self.next
    }

    pub fn to_bytes(
        &self,
        request: &DepositSyncObjectPageRequest,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate_for(request, advertisement)?;
        encode_canonical(self, MAX_DEPOSIT_SYNC_WIRE_BYTES)
    }

    pub fn from_bytes(
        request: &DepositSyncObjectPageRequest,
        advertisement: &DepositSyncAdvertisement,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncWireError> {
        let page = decode_canonical::<Self>(bytes, MAX_DEPOSIT_SYNC_WIRE_BYTES)?;
        page.validate_for(request, advertisement)?;
        require_canonical(&page, bytes, MAX_DEPOSIT_SYNC_WIRE_BYTES)?;
        Ok(page)
    }
}

/// Non-deserializable authority for both exact artifacts named by the advertised latest event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedDepositCheckpointArtifacts {
    context: [u8; 32],
    advertisement: [u8; 32],
    checkpoint_sequence: u64,
    operation: DepositArchiveOperation,
    operation_reference: WalletArtifactRef,
    checkpoint_reference: WalletArtifactRef,
}

impl VerifiedDepositCheckpointArtifacts {
    /// Authenticate the directly advertised event and derive its typed operation and checkpoint
    /// references. An observation tip cannot be projected into a ledger artifact.
    pub fn from_checkpoint_event(
        advertisement: &DepositSyncAdvertisement,
        event_bytes: &[u8],
    ) -> Result<Self, DepositSyncWireError> {
        advertisement.validate()?;
        let head = advertisement.certificate_archive;
        let event_reference =
            head.event_reference().ok_or(DepositSyncWireError::InvalidCertifiedArtifact)?;
        event_reference
            .verify_contents(event_bytes)
            .map_err(|_| DepositSyncWireError::InvalidCertifiedArtifact)?;
        let event = DepositArchiveEvent::from_bytes(event_bytes)
            .map_err(|_| DepositSyncWireError::InvalidCertifiedArtifact)?;
        let expected_ordinal =
            head.len().checked_sub(1).ok_or(DepositSyncWireError::InvalidCertifiedArtifact)?;
        let checkpoint_sequence = expected_ordinal
            .checked_add(1)
            .ok_or(DepositSyncWireError::InvalidCertifiedArtifact)?;
        if event.wallet_id() != advertisement.context.wallet
            || event.ordinal() != expected_ordinal
            || checkpoint_sequence != head.len()
        {
            return Err(DepositSyncWireError::InvalidCertifiedArtifact);
        }
        let operation = event.operation();
        let operation_reference = event.operation_reference();
        match operation {
            DepositArchiveOperation::Ledger => {
                validate_certified_reference(operation_reference, advertisement.context.wallet)?;
            }
            DepositArchiveOperation::DepositObservation => {
                validate_observation_reference(operation_reference, advertisement.context.wallet)?;
            }
        }
        let checkpoint_reference = event.checkpoint_reference();
        validate_checkpoint_certificate_reference(
            checkpoint_reference,
            advertisement.context.wallet,
        )?;
        Ok(Self {
            context: advertisement.context.digest(),
            advertisement: advertisement.digest(),
            checkpoint_sequence,
            operation,
            operation_reference,
            checkpoint_reference,
        })
    }

    fn validate_for(
        self,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<(), DepositSyncWireError> {
        advertisement.validate()?;
        if self.context != advertisement.context.digest()
            || self.advertisement != advertisement.digest()
            || self.checkpoint_sequence != advertisement.certificate_archive.len()
        {
            return Err(DepositSyncWireError::InvalidCertifiedArtifact);
        }
        match self.operation {
            DepositArchiveOperation::Ledger => {
                validate_certified_reference(
                    self.operation_reference,
                    advertisement.context.wallet,
                )?;
            }
            DepositArchiveOperation::DepositObservation => {
                validate_observation_reference(
                    self.operation_reference,
                    advertisement.context.wallet,
                )?;
            }
        }
        validate_checkpoint_certificate_reference(
            self.checkpoint_reference,
            advertisement.context.wallet,
        )
    }

    #[must_use]
    pub const fn operation(self) -> DepositArchiveOperation {
        self.operation
    }

    #[must_use]
    pub const fn checkpoint_sequence(self) -> u64 {
        self.checkpoint_sequence
    }

    /// Return the exact content-addressed ledger leaf only for a ledger checkpoint.
    pub fn ledger_reference(
        self,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<WalletArtifactRef, DepositSyncWireError> {
        self.validate_for(advertisement)?;
        if self.operation != DepositArchiveOperation::Ledger {
            return Err(DepositSyncWireError::InvalidCertifiedArtifact);
        }
        Ok(self.operation_reference)
    }

    pub fn observation_artifact(
        self,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<VerifiedCertifiedDepositObservationArtifact, DepositSyncWireError> {
        self.validate_for(advertisement)?;
        if self.operation != DepositArchiveOperation::DepositObservation {
            return Err(DepositSyncWireError::InvalidCertifiedArtifact);
        }
        Ok(VerifiedCertifiedDepositObservationArtifact {
            context: self.context,
            advertisement: self.advertisement,
            reference: self.operation_reference,
        })
    }

    pub fn checkpoint_artifact(
        self,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<VerifiedDepositIndexCheckpointArtifact, DepositSyncWireError> {
        self.validate_for(advertisement)?;
        Ok(VerifiedDepositIndexCheckpointArtifact {
            context: self.context,
            advertisement: self.advertisement,
            checkpoint_sequence: self.checkpoint_sequence,
            operation: self.operation,
            reference: self.checkpoint_reference,
        })
    }
}

/// Non-deserializable authority for the exact observation certificate named by an observation tip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedCertifiedDepositObservationArtifact {
    context: [u8; 32],
    advertisement: [u8; 32],
    reference: WalletArtifactRef,
}

impl VerifiedCertifiedDepositObservationArtifact {
    fn validate_for(
        self,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<(), DepositSyncWireError> {
        advertisement.validate()?;
        validate_observation_reference(self.reference, advertisement.context.wallet)?;
        if self.context != advertisement.context.digest()
            || self.advertisement != advertisement.digest()
        {
            return Err(DepositSyncWireError::InvalidCertifiedArtifact);
        }
        Ok(())
    }

    #[must_use]
    pub const fn reference(self) -> WalletArtifactRef {
        self.reference
    }
}

/// Non-deserializable authority for the exact checkpoint certificate named by the latest event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedDepositIndexCheckpointArtifact {
    context: [u8; 32],
    advertisement: [u8; 32],
    checkpoint_sequence: u64,
    operation: DepositArchiveOperation,
    reference: WalletArtifactRef,
}

impl VerifiedDepositIndexCheckpointArtifact {
    fn validate_for(
        self,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<(), DepositSyncWireError> {
        advertisement.validate()?;
        validate_checkpoint_certificate_reference(self.reference, advertisement.context.wallet)?;
        if self.context != advertisement.context.digest()
            || self.advertisement != advertisement.digest()
            || self.checkpoint_sequence != advertisement.certificate_archive.len()
        {
            return Err(DepositSyncWireError::InvalidCertifiedArtifact);
        }
        Ok(())
    }

    #[must_use]
    pub const fn reference(self) -> WalletArtifactRef {
        self.reference
    }

    #[must_use]
    pub const fn checkpoint_sequence(self) -> u64 {
        self.checkpoint_sequence
    }

    #[must_use]
    pub const fn operation(self) -> DepositArchiveOperation {
        self.operation
    }
}

/// Content-authenticate and canonically decode the exact latest observation certificate.
pub fn decode_certified_deposit_observation_artifact(
    advertisement: &DepositSyncAdvertisement,
    artifact: VerifiedCertifiedDepositObservationArtifact,
    bytes: &[u8],
) -> Result<CertifiedDepositObservation, DepositSyncWireError> {
    artifact.validate_for(advertisement)?;
    artifact
        .reference
        .verify_contents(bytes)
        .map_err(|_| DepositSyncWireError::InvalidCertifiedArtifact)?;
    let observation = CertifiedDepositObservation::from_bytes(bytes)
        .map_err(|_| DepositSyncWireError::InvalidCertifiedArtifact)?;
    if observation.statement.wallet_id() != advertisement.context.wallet {
        return Err(DepositSyncWireError::InvalidCertifiedArtifact);
    }
    Ok(observation)
}

/// Content-authenticate and canonically decode the exact latest index-checkpoint certificate.
pub fn decode_deposit_index_checkpoint_artifact(
    advertisement: &DepositSyncAdvertisement,
    artifact: VerifiedDepositIndexCheckpointArtifact,
    bytes: &[u8],
) -> Result<DepositIndexCheckpointCertificate, DepositSyncWireError> {
    artifact.validate_for(advertisement)?;
    artifact
        .reference
        .verify_contents(bytes)
        .map_err(|_| DepositSyncWireError::InvalidCertifiedArtifact)?;
    let checkpoint = DepositIndexCheckpointCertificate::from_bytes(bytes)
        .map_err(|_| DepositSyncWireError::InvalidCertifiedArtifact)?;
    let statement = checkpoint.statement();
    let expected_operation = match artifact.operation {
        DepositArchiveOperation::Ledger => DepositArchiveOperation::Ledger,
        DepositArchiveOperation::DepositObservation => DepositArchiveOperation::DepositObservation,
    };
    let actual_operation = match statement.operation() {
        DepositIndexCheckpointOperation::Ledger { .. } => DepositArchiveOperation::Ledger,
        DepositIndexCheckpointOperation::DepositObservation { .. } => {
            DepositArchiveOperation::DepositObservation
        }
    };
    if statement.context().wallet_id() != advertisement.context.wallet
        || statement.context().network() != advertisement.context.network
        || statement.sequence() != artifact.checkpoint_sequence
        || actual_operation != expected_operation
        || statement.resulting_head() != &advertisement.portable_index
        || advertisement.checkpoint_certificate.as_ref() != Some(&checkpoint)
    {
        return Err(DepositSyncWireError::InvalidCertifiedArtifact);
    }
    Ok(checkpoint)
}

fn validate_certified_reference(
    reference: WalletArtifactRef,
    wallet: DepositWalletId,
) -> Result<(), DepositSyncWireError> {
    let canonical = WalletArtifactRef::from_parts(
        WalletId(wallet.0),
        CERTIFIED_LEDGER_ENTRY_ARTIFACT,
        reference.plaintext_len(),
        reference.digest(),
    )
    .map_err(|_| DepositSyncWireError::InvalidCertifiedArtifact)?;
    let length = usize::try_from(reference.plaintext_len())
        .map_err(|_| DepositSyncWireError::InvalidCertifiedArtifact)?;
    if reference != canonical
        || reference.wallet_id() != WalletId(wallet.0)
        || reference.kind() != CERTIFIED_LEDGER_ENTRY_ARTIFACT
        || length == 0
        || length > MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES
    {
        return Err(DepositSyncWireError::InvalidCertifiedArtifact);
    }
    Ok(())
}

fn validate_observation_reference(
    reference: WalletArtifactRef,
    wallet: DepositWalletId,
) -> Result<(), DepositSyncWireError> {
    validate_archive_payload_reference(
        reference,
        wallet,
        CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT,
        MAX_CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT_BYTES,
    )
}

fn validate_checkpoint_certificate_reference(
    reference: WalletArtifactRef,
    wallet: DepositWalletId,
) -> Result<(), DepositSyncWireError> {
    validate_archive_payload_reference(
        reference,
        wallet,
        DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
        MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES,
    )
}

fn validate_archive_payload_reference(
    reference: WalletArtifactRef,
    wallet: DepositWalletId,
    kind: crate::storage::WalletArtifactKind,
    maximum: usize,
) -> Result<(), DepositSyncWireError> {
    let canonical = WalletArtifactRef::from_parts(
        WalletId(wallet.0),
        kind,
        reference.plaintext_len(),
        reference.digest(),
    )
    .map_err(|_| DepositSyncWireError::InvalidCertifiedArtifact)?;
    let length = usize::try_from(reference.plaintext_len())
        .map_err(|_| DepositSyncWireError::InvalidCertifiedArtifact)?;
    if reference != canonical
        || reference.wallet_id() != WalletId(wallet.0)
        || reference.kind() != kind
        || length == 0
        || length > maximum
    {
        return Err(DepositSyncWireError::InvalidCertifiedArtifact);
    }
    Ok(())
}

fn certificate_archive_reference_maximum(
    reference: WalletArtifactRef,
) -> Result<usize, DepositSyncWireError> {
    match reference.kind() {
        DEPOSIT_ARCHIVE_EVENT_ARTIFACT => Ok(MAX_DEPOSIT_ARCHIVE_EVENT_BYTES),
        DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT => Ok(MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES),
        CERTIFIED_LEDGER_ENTRY_ARTIFACT => Ok(MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES),
        CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT => {
            Ok(MAX_CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT_BYTES)
        }
        DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT => {
            Ok(MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES)
        }
        _ => Err(DepositSyncWireError::InvalidObjectReference),
    }
}

fn validate_certificate_archive_reference(
    reference: WalletArtifactRef,
    wallet: DepositWalletId,
) -> Result<(), DepositSyncWireError> {
    let maximum = certificate_archive_reference_maximum(reference)?;
    let canonical = WalletArtifactRef::from_parts(
        WalletId(wallet.0),
        reference.kind(),
        reference.plaintext_len(),
        reference.digest(),
    )
    .map_err(|_| DepositSyncWireError::InvalidObjectReference)?;
    let length = usize::try_from(reference.plaintext_len())
        .map_err(|_| DepositSyncWireError::InvalidObjectReference)?;
    if reference != canonical
        || reference.wallet_id() != WalletId(wallet.0)
        || length == 0
        || length > maximum
    {
        return Err(DepositSyncWireError::InvalidObjectReference);
    }
    Ok(())
}

fn object_manifest_digest(
    context: DepositSyncContext,
    anchor: DepositSyncObjectAnchor,
    references: &[DepositSyncObjectRef],
    maximum_objects: u16,
    maximum_plaintext_bytes: u32,
) -> Result<[u8; 32], DepositSyncWireError> {
    #[derive(Serialize)]
    struct Manifest<'a> {
        version: u16,
        context: DepositSyncContext,
        anchor: DepositSyncObjectAnchor,
        references: &'a [DepositSyncObjectRef],
        maximum_objects: u16,
        maximum_plaintext_bytes: u32,
    }
    let bytes = postcard::to_allocvec(&Manifest {
        version: DEPOSIT_SYNC_WIRE_VERSION,
        context,
        anchor,
        references,
        maximum_objects,
        maximum_plaintext_bytes,
    })
    .map_err(|_| DepositSyncWireError::Serialization)?;
    Ok(length_prefixed_hash(OBJECT_MANIFEST_DIGEST_DOMAIN, &bytes))
}

fn deterministic_page_end(
    request: &DepositSyncObjectPageRequest,
) -> Result<usize, DepositSyncWireError> {
    let start = usize::from(request.cursor.position);
    let count_limit = usize::from(request.maximum_objects);
    let byte_limit = usize::try_from(request.maximum_plaintext_bytes)
        .map_err(|_| DepositSyncWireError::InvalidObjectRequest)?;
    let mut count = 0_usize;
    let mut plaintext_bytes = 0_usize;
    for reference in request.references.iter().copied().skip(start) {
        if count == count_limit {
            break;
        }
        let expected = usize::try_from(reference.plaintext_len())
            .map_err(|_| DepositSyncWireError::InvalidObjectReference)?;
        let next_total = plaintext_bytes
            .checked_add(expected)
            .ok_or(DepositSyncWireError::InvalidObjectRequest)?;
        if next_total > byte_limit {
            if count == 0 {
                return Err(DepositSyncWireError::PageLimitTooSmall);
            }
            break;
        }
        plaintext_bytes = next_total;
        count += 1;
    }
    if count == 0 {
        return Err(DepositSyncWireError::InvalidObjectPage);
    }
    start.checked_add(count).ok_or(DepositSyncWireError::InvalidObjectPage)
}

fn certificate_archive_digest(head: DepositArchiveHead) -> [u8; 32] {
    let bytes =
        postcard::to_allocvec(&head).expect("validated certificate archive head serializes");
    length_prefixed_hash(CERTIFICATE_ARCHIVE_DIGEST_DOMAIN, &bytes)
}

fn length_prefixed_hash(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn encode_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, DepositSyncWireError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| DepositSyncWireError::Serialization)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositSyncWireError::WireTooLarge { actual: bytes.len(), maximum });
    }
    Ok(bytes)
}

fn decode_canonical<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, DepositSyncWireError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositSyncWireError::WireTooLarge { actual: bytes.len(), maximum });
    }
    let (value, trailing) =
        postcard::take_from_bytes::<T>(bytes).map_err(|_| DepositSyncWireError::Serialization)?;
    if !trailing.is_empty() {
        return Err(DepositSyncWireError::TrailingBytes);
    }
    Ok(value)
}

fn require_canonical<T: Serialize>(
    value: &T,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), DepositSyncWireError> {
    if encode_canonical(value, maximum)? != bytes {
        return Err(DepositSyncWireError::NonCanonicalEncoding);
    }
    Ok(())
}

fn deserialize_object_references<'de, D>(
    deserializer: D,
) -> Result<Vec<DepositSyncObjectRef>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ReferencesVisitor;

    impl<'de> Visitor<'de> for ReferencesVisitor {
        type Value = Vec<DepositSyncObjectRef>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_DEPOSIT_SYNC_REQUEST_OBJECTS} deposit object references"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|hint| hint > MAX_DEPOSIT_SYNC_REQUEST_OBJECTS) {
                return Err(A::Error::custom("too many deposit object references"));
            }
            let mut references = Vec::with_capacity(
                sequence.size_hint().unwrap_or(0).min(MAX_DEPOSIT_SYNC_REQUEST_OBJECTS),
            );
            while let Some(reference) = sequence.next_element()? {
                if references.len() == MAX_DEPOSIT_SYNC_REQUEST_OBJECTS {
                    return Err(A::Error::custom("too many deposit object references"));
                }
                references.push(reference);
            }
            Ok(references)
        }
    }

    deserializer.deserialize_seq(ReferencesVisitor)
}

fn deserialize_objects<'de, D>(deserializer: D) -> Result<Vec<DepositSyncObject>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ObjectsVisitor;

    impl<'de> Visitor<'de> for ObjectsVisitor {
        type Value = Vec<DepositSyncObject>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_DEPOSIT_SYNC_PAGE_OBJECTS} deposit objects")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|hint| hint > MAX_DEPOSIT_SYNC_PAGE_OBJECTS) {
                return Err(A::Error::custom("too many deposit objects"));
            }
            let mut objects = Vec::with_capacity(
                sequence.size_hint().unwrap_or(0).min(MAX_DEPOSIT_SYNC_PAGE_OBJECTS),
            );
            while let Some(object) = sequence.next_element()? {
                if objects.len() == MAX_DEPOSIT_SYNC_PAGE_OBJECTS {
                    return Err(A::Error::custom("too many deposit objects"));
                }
                objects.push(object);
            }
            Ok(objects)
        }
    }

    deserializer.deserialize_seq(ObjectsVisitor)
}

#[derive(Debug, Error)]
pub enum DepositSyncWireError {
    #[error("deposit sync context has a wrong version, domain, network, or wallet")]
    InvalidContext,
    #[error("deposit sync wire version is unsupported")]
    UnsupportedVersion,
    #[error("only settled compact checkpoints may be advertised")]
    UnsettledCheckpoint,
    #[error("the compact registry has no active head")]
    MissingRegistryHead,
    #[error("the compact catch-up advertisement is malformed or internally inconsistent")]
    InvalidAdvertisement,
    #[error("the request is not bound to the supplied advertised roots")]
    WrongAdvertisement,
    #[error("the finite object request is malformed or exceeds its limits")]
    InvalidObjectRequest,
    #[error("the object cursor is malformed or belongs to another request")]
    InvalidCursor,
    #[error("a content-addressed object reference is malformed or wallet-mismatched")]
    InvalidObjectReference,
    #[error("an object reference is not an advertised root or child of an earlier object")]
    UnreachableObjectReference,
    #[error("a returned content-addressed object is malformed")]
    InvalidObject,
    #[error("returned object bytes do not authenticate to their exact reference")]
    ObjectAuthentication,
    #[error("a requested immutable object is unavailable")]
    ObjectUnavailable,
    #[error("the requested byte limit cannot hold the next exact object")]
    PageLimitTooSmall,
    #[error("the returned object page is malformed or does not match the request")]
    InvalidObjectPage,
    #[error("the finite object manifest has not been authenticated from advertised roots")]
    InvalidObjectManifest,
    #[error("the certified archive artifact is malformed")]
    InvalidCertifiedArtifact,
    #[error("the index checkpoint is not bound to one exact certified ledger decision")]
    InvalidCheckpointBinding,
    #[error("the index checkpoint attestation wire is malformed or inconsistently bound")]
    InvalidCheckpointAttestation,
    #[error("the index checkpoint certificate wire is malformed or inconsistently bound")]
    InvalidCheckpointCertificate,
    #[error("deposit sync payload is {actual} bytes; maximum is {maximum}")]
    WireTooLarge { actual: usize, maximum: usize },
    #[error("deposit sync serialization failed")]
    Serialization,
    #[error("deposit sync payload has trailing bytes")]
    TrailingBytes,
    #[error("deposit sync payload is not encoded canonically")]
    NonCanonicalEncoding,
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        collections::{BTreeMap, VecDeque},
    };

    use crate::{
        committee::{Committee, Member, PartyId},
        compact_registry_archive::{CompactRegistryObjectKind, prepare_compact_registry_genesis},
        deposit_index::DEPOSIT_INDEX_ARTIFACT_KIND,
        deposit_ledger::DepositObservationStatement,
        deposit_wallet::{ChainPoint, DepositSubaddressIndex, WalletOutputId},
        key_rotation::VerifiedRegistryHandoffTarget,
        storage::{WalletArtifactKind, WalletArtifactRef},
    };

    use super::*;

    struct Fixture {
        advertisement: DepositSyncAdvertisement,
        objects: BTreeMap<DepositSyncObjectRef, Vec<u8>>,
    }

    fn fixture(tag: u8) -> Fixture {
        let wallet = DepositWalletId([tag; 32]);
        let network = [tag.wrapping_add(64); 32];
        let context = DepositSyncContext::new(network, wallet).unwrap();
        let first_index = DepositSubaddressIndex::new(0, 1).unwrap();
        let index = DepositIndexStoreCheckpoint::empty(wallet, PartyId(1), first_index).unwrap();
        let portable = PortableDepositIndexHead::from_head(index.portable_head()).unwrap();
        let committee = Committee {
            epoch: 0,
            threshold: 1,
            members: vec![Member {
                id: PartyId(1),
                signing_key: [tag.wrapping_add(1); 32],
                encryption_key: [tag.wrapping_add(2); 32],
            }],
        };
        let target = VerifiedRegistryHandoffTarget::for_test(
            committee,
            0,
            [tag.wrapping_add(3); 32],
            [tag.wrapping_add(4); 32],
            wallet,
            [tag.wrapping_add(5); 32],
            [tag.wrapping_add(6); 32],
        )
        .unwrap();
        let pending =
            prepare_compact_registry_genesis(&target, first_index, portable.digest()).unwrap();
        let registry =
            CompactRegistryStoreCheckpoint::settled(wallet, pending.proposed_head().clone())
                .unwrap();
        let certificate_archive = DepositArchiveHead::empty(wallet).unwrap();
        let advertisement = DepositSyncAdvertisement::from_checkpoints(
            context,
            &registry,
            certificate_archive,
            &index,
            None,
        )
        .unwrap();
        let objects = pending
            .staged_objects()
            .iter()
            .map(|object| {
                (DepositSyncObjectRef::Registry(object.reference()), object.contents().to_vec())
            })
            .collect();
        Fixture { advertisement, objects }
    }

    fn connected_registry_references(
        fixture: &Fixture,
        maximum: usize,
    ) -> Vec<DepositSyncObjectRef> {
        let root =
            DepositSyncObjectRef::Registry(fixture.advertisement.object_anchor().registry_root());
        let mut pending = VecDeque::from([root]);
        let mut references = Vec::new();
        while let Some(reference) = pending.pop_front() {
            if references.len() == maximum {
                break;
            }
            if references.contains(&reference) {
                continue;
            }
            let DepositSyncObjectRef::Registry(registry_reference) = reference else {
                unreachable!("genesis registry traversal contains only registry objects");
            };
            let bytes = &fixture.objects[&reference];
            let verified = verify_compact_registry_object(registry_reference, bytes).unwrap();
            pending.extend(verified.children().iter().copied().map(DepositSyncObjectRef::Registry));
            references.push(reference);
        }
        references
    }

    fn raw_encode<T: Serialize>(value: &T) -> Vec<u8> {
        postcard::to_allocvec(value).unwrap()
    }

    fn observation_certificate(
        wallet: DepositWalletId,
        output_byte: u8,
    ) -> CertifiedDepositObservation {
        #[derive(Serialize)]
        struct ObservationStatementEncoding {
            version: u16,
            wallet: DepositWalletId,
            issuer_epoch: u64,
            issuer_committee: [u8; 32],
            issuer_activation: [u8; 32],
            allocation_sequence: u64,
            allocation_statement: [u8; 32],
            index: DepositSubaddressIndex,
            output: WalletOutputId,
            output_key: [u8; 32],
            index_on_blockchain: u64,
            amount_atomic_units: u64,
            observed_block: ChainPoint,
            block_timestamp: u64,
            confirmation_horizon: ChainPoint,
            confirmation_depth: u32,
        }
        let encoding = ObservationStatementEncoding {
            version: 1,
            wallet,
            issuer_epoch: 3,
            issuer_committee: [0x31; 32],
            issuer_activation: [0x32; 32],
            allocation_sequence: 4,
            allocation_statement: [0x33; 32],
            index: DepositSubaddressIndex::new(0, 1).unwrap(),
            output: WalletOutputId {
                transaction: [output_byte; 32],
                index_in_transaction: u64::from(output_byte),
            },
            output_key: [output_byte.wrapping_add(1); 32],
            index_on_blockchain: 9,
            amount_atomic_units: 10,
            observed_block: ChainPoint::new(20, [0x34; 32]).unwrap(),
            block_timestamp: 100,
            confirmation_horizon: ChainPoint::new(29, [0x35; 32]).unwrap(),
            confirmation_depth: 10,
        };
        let statement: DepositObservationStatement =
            postcard::from_bytes(&postcard::to_allocvec(&encoding).unwrap()).unwrap();
        CertifiedDepositObservation { statement, attestations: Vec::new() }
    }

    #[test]
    fn head_and_advertisement_are_canonical_and_bound() {
        let fixture = fixture(7);
        let request = DepositSyncHeadRequest::new(fixture.advertisement.context()).unwrap();
        let bytes = request.to_bytes().unwrap();
        assert_eq!(DepositSyncHeadRequest::from_bytes(&bytes).unwrap(), request);

        let advertisement_bytes = fixture.advertisement.to_bytes(request).unwrap();
        assert_eq!(
            DepositSyncAdvertisement::from_bytes(request, &advertisement_bytes).unwrap(),
            fixture.advertisement
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            DepositSyncHeadRequest::from_bytes(&trailing),
            Err(DepositSyncWireError::TrailingBytes)
        ));

        // Postcard's unsigned varint decoder must not let an overlong representation become a
        // second encoding of the current version.
        let mut overlong = bytes;
        overlong.splice(0..1, [0x81, 0x00]);
        assert!(DepositSyncHeadRequest::from_bytes(&overlong).is_err());
    }

    #[test]
    fn observation_binding_separates_checkpoint_ordinal_from_allocation_sequence() {
        let wallet = DepositWalletId([0x28; 32]);
        let context = DepositSyncContext::new([0x29; 32], wallet).unwrap();
        let observation = observation_certificate(wallet, 0x41);
        let bytes = observation.to_bytes().unwrap();
        let reference = WalletArtifactRef::for_contents(
            WalletId(wallet.0),
            CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT,
            &bytes,
        )
        .unwrap();
        let binding =
            DepositIndexCheckpointObservationBinding::new(context, 17, reference, &observation)
                .unwrap();
        assert_eq!(binding.checkpoint_sequence(), 17);
        assert_eq!(binding.allocation_sequence(), observation.statement.allocation_sequence());
        assert_ne!(binding.checkpoint_sequence(), binding.allocation_sequence());
        assert_eq!(binding.statement_digest(), observation.statement.digest());
        binding.verify_observation(&observation).unwrap();

        let other = observation_certificate(wallet, 0x42);
        assert!(matches!(
            binding.verify_observation(&other),
            Err(DepositSyncWireError::InvalidCheckpointBinding)
        ));
        let wrong_kind = WalletArtifactRef::for_contents(
            WalletId(wallet.0),
            CERTIFIED_LEDGER_ENTRY_ARTIFACT,
            &bytes,
        )
        .unwrap();
        assert!(matches!(
            DepositIndexCheckpointObservationBinding::new(context, 17, wrong_kind, &observation,),
            Err(DepositSyncWireError::InvalidCheckpointBinding)
        ));

        let object =
            DepositSyncObject::new(DepositSyncObjectRef::CertificateArchive(reference), bytes)
                .unwrap();
        assert!(object.children().unwrap().is_empty());
    }

    #[test]
    fn wrong_domain_wallet_and_version_fail_closed() {
        let fixture = fixture(9);
        let request = DepositSyncHeadRequest::new(fixture.advertisement.context()).unwrap();

        let mut wrong_version = request;
        wrong_version.version = DEPOSIT_SYNC_WIRE_VERSION + 1;
        assert!(DepositSyncHeadRequest::from_bytes(&raw_encode(&wrong_version)).is_err());

        let mut wrong_domain = request;
        wrong_domain.context.domain[0] ^= 1;
        assert!(DepositSyncHeadRequest::from_bytes(&raw_encode(&wrong_domain)).is_err());

        let mut wrong_wallet = fixture.advertisement.clone();
        wrong_wallet.context.wallet = DepositWalletId([0x44; 32]);
        assert!(DepositSyncAdvertisement::from_bytes(request, &raw_encode(&wrong_wallet)).is_err());
    }

    #[test]
    fn request_and_reply_vector_bounds_are_enforced_during_decode() {
        let fixture = fixture(11);
        let root =
            DepositSyncObjectRef::Registry(fixture.advertisement.object_anchor().registry_root());
        let request =
            DepositSyncObjectPageRequest::new(&fixture.advertisement, vec![root], 1, 1024 * 1024)
                .unwrap();

        let mut oversized = request.clone();
        oversized.references = vec![root; MAX_DEPOSIT_SYNC_REQUEST_OBJECTS + 1];
        let bytes = raw_encode(&oversized);
        assert!(DepositSyncObjectPageRequest::from_bytes(&fixture.advertisement, &bytes).is_err());

        assert!(
            DepositSyncObjectPageRequest::new(&fixture.advertisement, vec![root], 0, 1024,)
                .is_err()
        );
        assert!(
            DepositSyncObjectPageRequest::new(
                &fixture.advertisement,
                vec![root],
                1,
                u32::try_from(MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES + 1).unwrap(),
            )
            .is_err()
        );

        let verified = request
            .verify_reachable_manifest(&fixture.advertisement, |reference| {
                Ok(fixture.objects.get(&reference).cloned())
            })
            .unwrap();
        let page =
            DepositSyncObjectPage::build(&request, &fixture.advertisement, &verified).unwrap();
        let mut oversized_page = page.clone();
        oversized_page.objects = vec![page.objects()[0].clone(); MAX_DEPOSIT_SYNC_PAGE_OBJECTS + 1];
        assert!(
            DepositSyncObjectPage::from_bytes(
                &request,
                &fixture.advertisement,
                &raw_encode(&oversized_page),
            )
            .is_err()
        );
    }

    #[test]
    fn object_authentication_and_root_binding_fail_closed() {
        let current = fixture(13);
        let other = fixture(14);
        let root =
            DepositSyncObjectRef::Registry(current.advertisement.object_anchor().registry_root());
        let mut bad = current.objects[&root].clone();
        bad[0] ^= 1;
        assert!(matches!(
            DepositSyncObject::new(root, bad),
            Err(DepositSyncWireError::ObjectAuthentication)
        ));

        let detached_bytes = b"content-addressed but not rooted".to_vec();
        let detached_ref = CompactRegistryObjectRef::for_contents(
            current.advertisement.context().wallet(),
            CompactRegistryObjectKind::Link,
            &detached_bytes,
        )
        .unwrap();
        assert!(
            DepositSyncObjectPageRequest::new(
                &current.advertisement,
                vec![DepositSyncObjectRef::Registry(detached_ref)],
                1,
                1024,
            )
            .is_err()
        );

        let request =
            DepositSyncObjectPageRequest::new(&current.advertisement, vec![root], 1, 1024 * 1024)
                .unwrap();
        assert!(request.validate_for(&other.advertisement).is_err());

        // A same-wallet local-safety artifact cannot be smuggled behind an authentic root. The
        // reachability verifier rejects it before invoking the plaintext loader for that ref.
        let local_bytes = b"party-local-safety-object".to_vec();
        let local_storage = WalletArtifactRef::for_contents(
            WalletId(current.advertisement.context().wallet().0),
            DEPOSIT_INDEX_ARTIFACT_KIND,
            &local_bytes,
        )
        .unwrap();
        let local_id = DepositIndexObjectId::from_storage_reference(local_storage).unwrap();
        let local_ref = DepositSyncObjectRef::Index(local_id);
        let exfiltration_request = DepositSyncObjectPageRequest::new(
            &current.advertisement,
            vec![root, local_ref],
            2,
            1024 * 1024,
        )
        .unwrap();
        let local_was_loaded = Cell::new(false);
        assert!(matches!(
            exfiltration_request.verify_reachable_manifest(&current.advertisement, |reference| {
                if reference == local_ref {
                    local_was_loaded.set(true);
                    return Ok(Some(local_bytes.clone()));
                }
                Ok(current.objects.get(&reference).cloned())
            },),
            Err(DepositSyncWireError::UnreachableObjectReference)
        ));
        assert!(!local_was_loaded.get());
    }

    #[test]
    fn pagination_is_deterministic_and_cursor_is_manifest_bound() {
        let fixture = fixture(17);
        let references = connected_registry_references(&fixture, 5);
        assert_eq!(references.len(), 5);
        let request =
            DepositSyncObjectPageRequest::new(&fixture.advertisement, references, 2, 1024 * 1024)
                .unwrap();
        let verified = request
            .verify_reachable_manifest(&fixture.advertisement, |reference| {
                Ok(fixture.objects.get(&reference).cloned())
            })
            .unwrap();
        let build = |request: &DepositSyncObjectPageRequest| {
            DepositSyncObjectPage::build(request, &fixture.advertisement, &verified).unwrap()
        };
        let first = build(&request);
        assert_eq!(first, build(&request));
        assert_eq!(first.objects().len(), 2);
        let first_bytes = first.to_bytes(&request, &fixture.advertisement).unwrap();
        assert_eq!(
            DepositSyncObjectPage::from_bytes(&request, &fixture.advertisement, &first_bytes,)
                .unwrap(),
            first
        );

        let second_request =
            request.with_cursor(&fixture.advertisement, first.next_cursor().unwrap()).unwrap();
        let second = build(&second_request);
        assert_eq!(second.objects().len(), 2);
        let third_request =
            request.with_cursor(&fixture.advertisement, second.next_cursor().unwrap()).unwrap();
        let third = build(&third_request);
        assert_eq!(third.objects().len(), 1);
        assert!(third.next_cursor().is_none());

        let mut changed = request.clone();
        changed.maximum_objects = 3;
        assert!(changed.with_cursor(&fixture.advertisement, first.next_cursor().unwrap()).is_err());
    }

    #[test]
    fn index_objects_use_exact_wallet_kind_length_and_digest() {
        let fixture = fixture(19);
        let bytes = b"an exact index object".to_vec();
        let storage = WalletArtifactRef::for_contents(
            WalletId(fixture.advertisement.context().wallet().0),
            DEPOSIT_INDEX_ARTIFACT_KIND,
            &bytes,
        )
        .unwrap();
        let id = DepositIndexObjectId::from_storage_reference(storage).unwrap();
        assert!(DepositSyncObject::new(DepositSyncObjectRef::Index(id), bytes.clone()).is_err());

        let wrong_kind = WalletArtifactRef::for_contents(
            WalletId(fixture.advertisement.context().wallet().0),
            WalletArtifactKind(DEPOSIT_INDEX_ARTIFACT_KIND.0 + 1),
            &bytes,
        )
        .unwrap();
        assert!(DepositIndexObjectId::from_storage_reference(wrong_kind).is_err());
    }
}
