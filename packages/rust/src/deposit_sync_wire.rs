//! Fresh-format, bounded QUIC catch-up payloads for the deposit protocol.
//!
//! A joining party starts from one [`DepositSyncAdvertisement`]. Advertised roots can be requested
//! directly. After returning an authenticated object, a source grants opaque, source-local
//! [`DepositSyncObjectCapability`] values for that object's authenticated children. A subsequent
//! request for a non-root object must return the exact capability for that parent-child edge.
//! Capability admission prevents detached storage probing; it does not make returned objects
//! authoritative. The caller must still validate every decoded parent-child edge and independently
//! verify the quorum-authenticated registry, archive, and portable-index state.
//!
//! This protocol never lists a storage directory and never requests a lifetime ledger prefix.
//! Each cursorless request and response is one hard-bounded page. Exact ledger, observation, and
//! checkpoint certificates are content-addressed leaves in the same capability-authorized graph.

use std::{collections::BTreeSet, fmt};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as _, SeqAccess, Visitor},
};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

use crate::{
    committee::PartyId,
    compact_epoch_registry::{COMPACT_REGISTRY_INDEX_DEPTH, RegistryId},
    compact_registry_archive::{
        CompactRegistryArchiveHead, CompactRegistryObjectRef, CompactRegistryTraversalTarget,
        MAX_COMPACT_REGISTRY_HEAD_BYTES, verify_compact_registry_object,
        verify_compact_registry_traversal_object,
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
        DepositIndexHead, DepositIndexObjectId, MAX_DEPOSIT_INDEX_OBJECT_BYTES, MAX_HAMT_DEPTH,
        PortableIndexTraversalTarget, verify_portable_index_object,
        verify_portable_index_traversal_object,
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
pub const DEPOSIT_SYNC_WIRE_DOMAIN: [u8; 16] = *b"tm-deposit-sync4";
pub const DEPOSIT_SYNC_WIRE_VERSION: u16 = 4;

/// The authenticated QUIC transport's body ceiling.
pub const MAX_DEPOSIT_SYNC_WIRE_BYTES: usize = 8 * 1024 * 1024;
/// A caller may ask for at most this many exact references in one page.
pub const MAX_DEPOSIT_SYNC_REQUEST_OBJECTS: usize = MAX_DEPOSIT_SYNC_PAGE_OBJECTS;
/// A response may carry at most this many objects even if they are individually tiny.
pub const MAX_DEPOSIT_SYNC_PAGE_OBJECTS: usize = 64;
/// Leaves one MiB below the QUIC ceiling for references and canonical framing.
pub const MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES: usize = 7 * 1024 * 1024;
/// A page may issue enough child capabilities for 64 full archive segments.
pub const MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES: usize = MAX_DEPOSIT_SYNC_PAGE_OBJECTS
    * (crate::deposit_archive::MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS + 1);
/// Maximum canonical body accepted by the `SyncHead` QUIC route.
pub const MAX_DEPOSIT_SYNC_HEAD_REQUEST_BYTES: usize = 256;
const MAX_ADVERTISEMENT_BYTES: usize = MAX_COMPACT_REGISTRY_HEAD_BYTES + 256 * 1024;
const MAX_HEAD_RESPONSE_BYTES: usize = MAX_ADVERTISEMENT_BYTES + 2 * 1024;
/// Maximum canonical request body accepted by the `SyncObjects` QUIC route.
pub const MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES: usize = 128 * 1024;
/// Maximum canonical body for releasing one exact source-side historical-root pin.
pub const MAX_DEPOSIT_SYNC_RELEASE_REQUEST_BYTES: usize = 2 * 1024;
/// Maximum canonical typed acknowledgement for one exact release request.
pub const MAX_DEPOSIT_SYNC_RELEASE_ACK_BYTES: usize = 512;
const MAX_INDEX_CHECKPOINT_ATTEST_WIRE_BYTES: usize = 16 * 1024;
const MAX_INDEX_CHECKPOINT_CERTIFICATE_WIRE_BYTES: usize = 2 * 1024 * 1024;

const CONTEXT_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync/context/v1";
const ADVERTISEMENT_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync/advertisement/v1";
const CERTIFICATE_ARCHIVE_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-sync/certificate-archive/v1";
const HEAD_REQUEST_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync/head-request/v4";
const ANCHOR_LEASE_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync/anchor-lease/v4";
const ANCHOR_LEASE_MAC_DOMAIN: &[u8] = b"threshold-monero/deposit-sync/anchor-lease-mac/v4";
const RELEASE_REQUEST_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync/release-request/v4";
const OBJECT_REQUEST_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync/object-request/v4";
const OBJECT_RESPONSE_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync/object-response/v4";
const OBJECT_CAPABILITY_MAC_DOMAIN: &[u8] = b"threshold-monero/deposit-sync/object-capability/v4";

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
    source: PartyId,
    requester: PartyId,
}

impl DepositSyncHeadRequest {
    pub fn new(
        context: DepositSyncContext,
        source: PartyId,
        requester: PartyId,
    ) -> Result<Self, DepositSyncWireError> {
        let request = Self { version: DEPOSIT_SYNC_WIRE_VERSION, context, source, requester };
        request.validate()?;
        Ok(request)
    }

    fn validate(self) -> Result<(), DepositSyncWireError> {
        self.context.validate()?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION || self.source.0 == 0 || self.requester.0 == 0
        {
            return Err(DepositSyncWireError::UnsupportedVersion);
        }
        Ok(())
    }

    #[must_use]
    pub const fn context(self) -> DepositSyncContext {
        self.context
    }

    #[must_use]
    pub const fn source(self) -> PartyId {
        self.source
    }

    #[must_use]
    pub const fn requester(self) -> PartyId {
        self.requester
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(&self).expect("validated head request serializes");
        length_prefixed_hash(HEAD_REQUEST_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(self) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate()?;
        encode_canonical(&self, MAX_DEPOSIT_SYNC_HEAD_REQUEST_BYTES)
    }

    pub fn from_bytes(
        source: PartyId,
        requester: PartyId,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncWireError> {
        let request = decode_canonical::<Self>(bytes, MAX_DEPOSIT_SYNC_HEAD_REQUEST_BYTES)?;
        request.validate()?;
        if request.source != source || request.requester != requester {
            return Err(DepositSyncWireError::InvalidHeadLease);
        }
        require_canonical(&request, bytes, MAX_DEPOSIT_SYNC_HEAD_REQUEST_BYTES)?;
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
        self.portable_index
            .maximum_reachable_objects()
            .map_err(|_| DepositSyncWireError::InvalidAdvertisement)?;
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
        let boundary_fields_match = self.portable_index.ledger_head()
            == active.predecessor_ledger_head()
            && self.portable_index.next_index() == active.first_index();
        let epoch_zero_checkpoint_matches = (active.epoch() == 0)
            .then(|| self.portable_index.digest() == active.portable_index_checkpoint());
        // Epoch zero directly commits its empty boundary head. A successor cannot do so without
        // a hash cycle: its registry link commits the preterminal source head, while the exported
        // boundary head includes the handoff statement digest. Full sync/export verification
        // authenticates that transition against the exact handoff witness.
        if !portable_index_respects_registry_boundary(
            self.portable_index.through_sequence(),
            boundary,
            boundary_fields_match,
            epoch_zero_checkpoint_matches,
        ) {
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

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate()?;
        encode_canonical(self, MAX_ADVERTISEMENT_BYTES)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositSyncWireError> {
        let advertisement = decode_canonical::<Self>(bytes, MAX_ADVERTISEMENT_BYTES)?;
        advertisement.validate()?;
        require_canonical(&advertisement, bytes, MAX_ADVERTISEMENT_BYTES)?;
        Ok(advertisement)
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = self.to_bytes().expect("validated advertisement serializes canonically");
        length_prefixed_hash(ADVERTISEMENT_DIGEST_DOMAIN, &bytes)
    }

    #[must_use]
    pub fn object_anchor(&self) -> DepositSyncObjectAnchor {
        DepositSyncObjectAnchor::from_advertisement(self)
    }
}

fn portable_index_respects_registry_boundary(
    through_sequence: u64,
    boundary: u64,
    boundary_fields_match: bool,
    epoch_zero_checkpoint_matches: Option<bool>,
) -> bool {
    through_sequence > boundary
        || (through_sequence == boundary
            && boundary_fields_match
            && epoch_zero_checkpoint_matches.unwrap_or(true))
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
    registry_semantic_root: [u8; 32],
    registry_active_epoch: u64,
    portable_index: [u8; 32],
    portable_root: Option<DepositIndexObjectId>,
    portable_entries: u64,
    portable_maximum_objects: u64,
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
            registry_semantic_root: advertisement.registry_id.index_root(),
            registry_active_epoch: advertisement.registry_id.active_epoch(),
            portable_index: advertisement.portable_index.digest(),
            portable_root: advertisement.portable_index.root(),
            portable_entries: advertisement.portable_index.entry_count(),
            portable_maximum_objects: advertisement
                .portable_index
                .maximum_reachable_objects()
                .expect("validated portable head has a bounded object count"),
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
        self.validate(context)?;
        advertisement.validate()?;
        if context != advertisement.context || self != Self::from_advertisement(advertisement) {
            return Err(DepositSyncWireError::WrongAdvertisement);
        }
        Ok(())
    }

    fn validate(self, context: DepositSyncContext) -> Result<(), DepositSyncWireError> {
        context.validate()?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.wallet != context.wallet
            || self.context != context.digest()
            || self.advertisement == [0; 32]
            || self.registry_checkpoint == [0; 32]
            || self.registry_id == [0; 32]
            || self.registry_semantic_root == [0; 32]
            || self.portable_index == [0; 32]
            || (self.portable_entries == 0) != self.portable_root.is_none()
            || (self.portable_entries == 0) != (self.portable_maximum_objects == 0)
            || self.certificate_archive == [0; 32]
            || (self.checkpoint_sequence == 0)
                != (self.certificate_event_root.is_none()
                    && self.certificate_segment_root.is_none())
            || self.certificate_event_root.is_none() != self.certificate_segment_root.is_none()
        {
            return Err(DepositSyncWireError::InvalidHeadLease);
        }
        DepositSyncObjectRef::Registry(self.registry_root).validate_for(self.wallet)?;
        if let Some(root) = self.portable_root {
            DepositSyncObjectRef::Index(root).validate_for(self.wallet)?;
        }
        if let Some(root) = self.certificate_event_root {
            if root.kind() != DEPOSIT_ARCHIVE_EVENT_ARTIFACT {
                return Err(DepositSyncWireError::InvalidHeadLease);
            }
            DepositSyncObjectRef::CertificateArchive(root).validate_for(self.wallet)?;
        }
        if let Some(root) = self.certificate_segment_root {
            if root.kind() != DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT {
                return Err(DepositSyncWireError::InvalidHeadLease);
            }
            DepositSyncObjectRef::CertificateArchive(root).validate_for(self.wallet)?;
        }
        Ok(())
    }

    /// Revalidate a deserialized anchor when it is embedded by another crate-internal protocol.
    pub(crate) fn validate_context(
        self,
        context: DepositSyncContext,
    ) -> Result<(), DepositSyncWireError> {
        self.validate(context)
    }

    #[must_use]
    pub const fn wallet(self) -> DepositWalletId {
        self.wallet
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
    pub const fn registry_semantic_root(self) -> [u8; 32] {
        self.registry_semantic_root
    }

    #[must_use]
    pub const fn registry_active_epoch(self) -> u64 {
        self.registry_active_epoch
    }

    #[must_use]
    pub const fn portable_root(self) -> Option<DepositIndexObjectId> {
        self.portable_root
    }

    #[must_use]
    pub const fn portable_entries(self) -> u64 {
        self.portable_entries
    }

    #[must_use]
    pub const fn portable_maximum_objects(self) -> u64 {
        self.portable_maximum_objects
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

    #[must_use]
    pub fn is_advertised_root(self, reference: DepositSyncObjectRef) -> bool {
        reference == DepositSyncObjectRef::Registry(self.registry_root)
            || self.portable_root.is_some_and(|root| reference == DepositSyncObjectRef::Index(root))
            || self
                .certificate_segment_root
                .is_some_and(|root| reference == DepositSyncObjectRef::CertificateArchive(root))
    }
}

/// Restart-stable authority for one exact source-pinned advertised object graph.
///
/// The requester persists this small lease beside the fully validated advertisement. Subsequent
/// object requests carry only the lease; the source authenticates it with a stable key derived
/// from its identity seed. The source durably retains the corresponding historical portable-index
/// root until the requester sends an exact authenticated [`DepositSyncReleaseRequest`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncAnchorLease {
    version: u16,
    domain: [u8; 16],
    context: DepositSyncContext,
    anchor: DepositSyncObjectAnchor,
    source: PartyId,
    requester: PartyId,
    tag: [u8; 32],
}

impl DepositSyncAnchorLease {
    fn issue(
        mac_key: &[u8; 32],
        request: DepositSyncHeadRequest,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<Self, DepositSyncWireError> {
        reject_zero_mac_key(mac_key)?;
        request.validate()?;
        advertisement.validate()?;
        if advertisement.context != request.context {
            return Err(DepositSyncWireError::InvalidAdvertisement);
        }
        let mut lease = Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            domain: DEPOSIT_SYNC_WIRE_DOMAIN,
            context: request.context,
            anchor: advertisement.object_anchor(),
            source: request.source,
            requester: request.requester,
            tag: [0; 32],
        };
        lease.validate_for_advertisement(request, advertisement)?;
        lease.tag = anchor_lease_mac(mac_key, &lease)?;
        Ok(lease)
    }

    fn validate(&self) -> Result<(), DepositSyncWireError> {
        self.context.validate()?;
        self.anchor.validate(self.context)?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.domain != DEPOSIT_SYNC_WIRE_DOMAIN
            || self.source.0 == 0
            || self.requester.0 == 0
        {
            return Err(DepositSyncWireError::InvalidHeadLease);
        }
        Ok(())
    }

    pub fn validate_for_advertisement(
        &self,
        request: DepositSyncHeadRequest,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<(), DepositSyncWireError> {
        self.validate()?;
        request.validate()?;
        advertisement.validate()?;
        if self.context != request.context
            || self.source != request.source
            || self.requester != request.requester
            || advertisement.context != request.context
            || self.anchor != advertisement.object_anchor()
        {
            return Err(DepositSyncWireError::InvalidHeadLease);
        }
        Ok(())
    }

    /// Authenticate this exact historical anchor for the transport-authenticated parties.
    pub fn authenticate_for(
        &self,
        mac_key: &[u8; 32],
        source: PartyId,
        requester: PartyId,
    ) -> Result<(), DepositSyncWireError> {
        reject_zero_mac_key(mac_key)?;
        self.validate()?;
        if self.source != source || self.requester != requester {
            return Err(DepositSyncWireError::InvalidHeadLease);
        }
        let expected = anchor_lease_mac(mac_key, self)?;
        if !bool::from(self.tag.ct_eq(&expected)) {
            return Err(DepositSyncWireError::InvalidHeadLease);
        }
        Ok(())
    }

    #[must_use]
    pub const fn context(self) -> DepositSyncContext {
        self.context
    }

    #[must_use]
    pub const fn anchor(self) -> DepositSyncObjectAnchor {
        self.anchor
    }

    #[must_use]
    pub const fn advertisement_digest(self) -> [u8; 32] {
        self.anchor.advertisement
    }

    #[must_use]
    pub const fn source(self) -> PartyId {
        self.source
    }

    #[must_use]
    pub const fn requester(self) -> PartyId {
        self.requester
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(&self).expect("validated anchor lease serializes");
        length_prefixed_hash(ANCHOR_LEASE_DIGEST_DOMAIN, &bytes)
    }
}

/// Fully validated advertisement plus its durable historical-serving lease.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncHeadResponse {
    version: u16,
    request: [u8; 32],
    advertisement: DepositSyncAdvertisement,
    lease: DepositSyncAnchorLease,
}

impl DepositSyncHeadResponse {
    pub fn issue(
        request: DepositSyncHeadRequest,
        advertisement: DepositSyncAdvertisement,
        mac_key: &[u8; 32],
    ) -> Result<Self, DepositSyncWireError> {
        request.validate()?;
        advertisement.validate()?;
        let lease = DepositSyncAnchorLease::issue(mac_key, request, &advertisement)?;
        let response = Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            request: request.digest(),
            advertisement,
            lease,
        };
        response.validate_for(request)?;
        Ok(response)
    }

    fn validate_for(&self, request: DepositSyncHeadRequest) -> Result<(), DepositSyncWireError> {
        request.validate()?;
        self.advertisement.validate()?;
        self.lease.validate_for_advertisement(request, &self.advertisement)?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION || self.request != request.digest() {
            return Err(DepositSyncWireError::InvalidHeadLease);
        }
        Ok(())
    }

    #[must_use]
    pub const fn advertisement(&self) -> &DepositSyncAdvertisement {
        &self.advertisement
    }

    #[must_use]
    pub const fn lease(&self) -> DepositSyncAnchorLease {
        self.lease
    }

    pub fn to_bytes(
        &self,
        request: DepositSyncHeadRequest,
    ) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate_for(request)?;
        encode_canonical(self, MAX_HEAD_RESPONSE_BYTES)
    }

    pub fn from_bytes(
        request: DepositSyncHeadRequest,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncWireError> {
        let response = decode_canonical::<Self>(bytes, MAX_HEAD_RESPONSE_BYTES)?;
        response.validate_for(request)?;
        require_canonical(&response, bytes, MAX_HEAD_RESPONSE_BYTES)?;
        Ok(response)
    }
}

/// Authenticated request to release one exact source-side historical-root pin.
///
/// The lease itself is carried rather than only its digest so the source can re-authenticate the
/// original source/requester/context binding after a process restart. A requester must retain and
/// retransmit this exact body until it receives a matching [`DepositSyncReleaseAck`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncReleaseRequest {
    version: u16,
    lease: DepositSyncAnchorLease,
}

impl DepositSyncReleaseRequest {
    pub fn new(lease: DepositSyncAnchorLease) -> Result<Self, DepositSyncWireError> {
        let request = Self { version: DEPOSIT_SYNC_WIRE_VERSION, lease };
        request.validate()?;
        Ok(request)
    }

    fn validate(self) -> Result<(), DepositSyncWireError> {
        self.lease.validate()?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION {
            return Err(DepositSyncWireError::InvalidRelease);
        }
        Ok(())
    }

    /// Authenticate the original lease under the source's stable local capability key.
    pub fn authenticate_for(
        self,
        mac_key: &[u8; 32],
        source: PartyId,
        requester: PartyId,
    ) -> Result<(), DepositSyncWireError> {
        self.validate()?;
        self.lease.authenticate_for(mac_key, source, requester)
    }

    #[must_use]
    pub const fn lease(self) -> DepositSyncAnchorLease {
        self.lease
    }

    #[must_use]
    pub const fn context(self) -> DepositSyncContext {
        self.lease.context()
    }

    #[must_use]
    pub const fn source(self) -> PartyId {
        self.lease.source()
    }

    #[must_use]
    pub const fn requester(self) -> PartyId {
        self.lease.requester()
    }

    #[must_use]
    pub fn lease_digest(self) -> [u8; 32] {
        self.lease.digest()
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(&self).expect("validated release request serializes");
        length_prefixed_hash(RELEASE_REQUEST_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(self) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate()?;
        encode_canonical(&self, MAX_DEPOSIT_SYNC_RELEASE_REQUEST_BYTES)
    }

    pub fn from_bytes(
        source: PartyId,
        requester: PartyId,
        mac_key: &[u8; 32],
        bytes: &[u8],
    ) -> Result<Self, DepositSyncWireError> {
        let request = decode_canonical::<Self>(bytes, MAX_DEPOSIT_SYNC_RELEASE_REQUEST_BYTES)?;
        request.authenticate_for(mac_key, source, requester)?;
        require_canonical(&request, bytes, MAX_DEPOSIT_SYNC_RELEASE_REQUEST_BYTES)?;
        Ok(request)
    }

    /// Extract the deployment/wallet binding under the same strict canonical bound before the
    /// source derives its stable MAC key. This grants no release authority by itself; callers
    /// must immediately pass the bytes through [`Self::from_bytes`].
    pub fn context_from_bytes(bytes: &[u8]) -> Result<DepositSyncContext, DepositSyncWireError> {
        let request = decode_canonical::<Self>(bytes, MAX_DEPOSIT_SYNC_RELEASE_REQUEST_BYTES)?;
        request.validate()?;
        require_canonical(&request, bytes, MAX_DEPOSIT_SYNC_RELEASE_REQUEST_BYTES)?;
        Ok(request.context())
    }
}

/// Typed acknowledgement for one exact durable release request.
///
/// An absent slot is an idempotent success only when no different lease currently occupies the
/// same requester slot. The source-side store enforces that rule before issuing this response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncReleaseAck {
    version: u16,
    context: DepositSyncContext,
    source: PartyId,
    requester: PartyId,
    request: [u8; 32],
}

impl DepositSyncReleaseAck {
    pub fn issue(request: DepositSyncReleaseRequest) -> Result<Self, DepositSyncWireError> {
        request.validate()?;
        let acknowledgement = Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            context: request.context(),
            source: request.source(),
            requester: request.requester(),
            request: request.digest(),
        };
        acknowledgement.validate_for(request)?;
        Ok(acknowledgement)
    }

    fn validate_for(self, request: DepositSyncReleaseRequest) -> Result<(), DepositSyncWireError> {
        request.validate()?;
        self.context.validate()?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.context != request.context()
            || self.source != request.source()
            || self.requester != request.requester()
            || self.request != request.digest()
        {
            return Err(DepositSyncWireError::InvalidRelease);
        }
        Ok(())
    }

    #[must_use]
    pub const fn context(self) -> DepositSyncContext {
        self.context
    }

    #[must_use]
    pub const fn source(self) -> PartyId {
        self.source
    }

    #[must_use]
    pub const fn requester(self) -> PartyId {
        self.requester
    }

    #[must_use]
    pub const fn request_digest(self) -> [u8; 32] {
        self.request
    }

    pub fn to_bytes(
        self,
        request: DepositSyncReleaseRequest,
    ) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate_for(request)?;
        encode_canonical(&self, MAX_DEPOSIT_SYNC_RELEASE_ACK_BYTES)
    }

    pub fn from_bytes(
        request: DepositSyncReleaseRequest,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncWireError> {
        let acknowledgement = decode_canonical::<Self>(bytes, MAX_DEPOSIT_SYNC_RELEASE_ACK_BYTES)?;
        acknowledgement.validate_for(request)?;
        require_canonical(&acknowledgement, bytes, MAX_DEPOSIT_SYNC_RELEASE_ACK_BYTES)?;
        Ok(acknowledgement)
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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DepositSyncArchiveLeafKind {
    CertifiedLedger,
    CertifiedObservation,
    LedgerCheckpoint,
    ObservationCheckpoint,
}

/// Canonical, restart-persistable semantic position for one object in the leased graph.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DepositSyncTraversalTarget {
    Registry(CompactRegistryTraversalTarget),
    PortableIndex(PortableIndexTraversalTarget),
    ArchiveSegment {
        reference: WalletArtifactRef,
        expected_end_ordinal: u64,
        expected_last_event: Option<WalletArtifactRef>,
    },
    ArchiveEvent {
        reference: WalletArtifactRef,
        expected_ordinal: u64,
    },
    ArchiveLeaf {
        reference: WalletArtifactRef,
        checkpoint_sequence: u64,
        kind: DepositSyncArchiveLeafKind,
    },
}

impl DepositSyncTraversalTarget {
    #[must_use]
    pub const fn reference(self) -> DepositSyncObjectRef {
        match self {
            Self::Registry(target) => DepositSyncObjectRef::Registry(target.reference()),
            Self::PortableIndex(target) => DepositSyncObjectRef::Index(target.id()),
            Self::ArchiveSegment { reference, .. }
            | Self::ArchiveEvent { reference, .. }
            | Self::ArchiveLeaf { reference, .. } => {
                DepositSyncObjectRef::CertificateArchive(reference)
            }
        }
    }

    fn validate_for(self, lease: DepositSyncAnchorLease) -> Result<(), DepositSyncWireError> {
        lease.validate()?;
        self.reference().validate_for(lease.context.wallet)?;
        let anchor = lease.anchor;
        match self {
            Self::Registry(CompactRegistryTraversalTarget::Index {
                depth, semantic_hash, ..
            }) => {
                if depth > COMPACT_REGISTRY_INDEX_DEPTH || semantic_hash == [0; 32] {
                    return Err(DepositSyncWireError::InvalidTraversalTarget);
                }
            }
            Self::Registry(CompactRegistryTraversalTarget::Link { epoch, chain_root, .. }) => {
                if epoch > anchor.registry_active_epoch || chain_root == [0; 32] {
                    return Err(DepositSyncWireError::InvalidTraversalTarget);
                }
            }
            Self::Registry(CompactRegistryTraversalTarget::HandoffWitness {
                target_epoch, ..
            }) => {
                if target_epoch == 0 || target_epoch > anchor.registry_active_epoch {
                    return Err(DepositSyncWireError::InvalidTraversalTarget);
                }
            }
            Self::PortableIndex(PortableIndexTraversalTarget::Node {
                depth,
                expected_entries,
                ..
            }) => {
                if depth > MAX_HAMT_DEPTH || expected_entries == Some(0) {
                    return Err(DepositSyncWireError::InvalidTraversalTarget);
                }
            }
            Self::PortableIndex(PortableIndexTraversalTarget::Value { .. }) => {}
            Self::ArchiveSegment { reference, expected_end_ordinal, expected_last_event } => {
                if reference.kind() != DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT
                    || expected_end_ordinal == 0
                    || expected_end_ordinal > anchor.checkpoint_sequence
                    || expected_last_event.is_some_and(|event| {
                        event.kind() != DEPOSIT_ARCHIVE_EVENT_ARTIFACT
                            || event.wallet_id() != WalletId(anchor.wallet.0)
                    })
                {
                    return Err(DepositSyncWireError::InvalidTraversalTarget);
                }
            }
            Self::ArchiveEvent { reference, expected_ordinal } => {
                if reference.kind() != DEPOSIT_ARCHIVE_EVENT_ARTIFACT
                    || expected_ordinal >= anchor.checkpoint_sequence
                {
                    return Err(DepositSyncWireError::InvalidTraversalTarget);
                }
            }
            Self::ArchiveLeaf { reference, checkpoint_sequence, kind } => {
                let expected_kind = match kind {
                    DepositSyncArchiveLeafKind::CertifiedLedger => CERTIFIED_LEDGER_ENTRY_ARTIFACT,
                    DepositSyncArchiveLeafKind::CertifiedObservation => {
                        CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT
                    }
                    DepositSyncArchiveLeafKind::LedgerCheckpoint
                    | DepositSyncArchiveLeafKind::ObservationCheckpoint => {
                        DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT
                    }
                };
                if reference.kind() != expected_kind
                    || checkpoint_sequence == 0
                    || checkpoint_sequence > anchor.checkpoint_sequence
                {
                    return Err(DepositSyncWireError::InvalidTraversalTarget);
                }
            }
        }
        Ok(())
    }
}

impl DepositSyncAnchorLease {
    pub fn root_targets(self) -> Result<Vec<DepositSyncTraversalTarget>, DepositSyncWireError> {
        self.validate()?;
        let mut roots = Vec::with_capacity(3);
        roots.push(DepositSyncTraversalTarget::Registry(CompactRegistryTraversalTarget::Index {
            reference: self.anchor.registry_root,
            depth: 0,
            semantic_hash: self.anchor.registry_semantic_root,
        }));
        if let Some(id) = self.anchor.portable_root {
            roots.push(DepositSyncTraversalTarget::PortableIndex(
                PortableIndexTraversalTarget::Node {
                    id,
                    depth: 0,
                    expected_entries: Some(self.anchor.portable_entries),
                },
            ));
        }
        if let Some(reference) = self.anchor.certificate_segment_root {
            roots.push(DepositSyncTraversalTarget::ArchiveSegment {
                reference,
                expected_end_ordinal: self.anchor.checkpoint_sequence,
                expected_last_event: self.anchor.certificate_event_root,
            });
        }
        Ok(roots)
    }

    #[must_use]
    pub fn is_root_target(self, target: DepositSyncTraversalTarget) -> bool {
        self.root_targets().is_ok_and(|roots| roots.contains(&target))
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

    /// Authenticate this object at an exact semantic position and derive its successor positions.
    pub fn authenticated_semantic_children(
        &self,
        target: DepositSyncTraversalTarget,
    ) -> Result<Vec<DepositSyncTraversalTarget>, DepositSyncWireError> {
        if target.reference() != self.reference {
            return Err(DepositSyncWireError::InvalidTraversalTarget);
        }
        match target {
            DepositSyncTraversalTarget::Registry(target) => {
                Ok(verify_compact_registry_traversal_object(target, &self.bytes)
                    .map_err(|_| DepositSyncWireError::InvalidTraversalTarget)?
                    .into_iter()
                    .map(DepositSyncTraversalTarget::Registry)
                    .collect())
            }
            DepositSyncTraversalTarget::PortableIndex(target) => {
                Ok(verify_portable_index_traversal_object(
                    self.reference.wallet(),
                    target,
                    &self.bytes,
                )
                .map_err(|_| DepositSyncWireError::InvalidTraversalTarget)?
                .into_iter()
                .map(DepositSyncTraversalTarget::PortableIndex)
                .collect())
            }
            DepositSyncTraversalTarget::ArchiveSegment {
                expected_end_ordinal,
                expected_last_event,
                ..
            } => {
                let segment = DepositArchiveSegment::from_bytes(&self.bytes)
                    .map_err(|_| DepositSyncWireError::InvalidTraversalTarget)?;
                if segment.wallet_id() != self.reference.wallet()
                    || segment
                        .end_ordinal()
                        .map_err(|_| DepositSyncWireError::InvalidTraversalTarget)?
                        != expected_end_ordinal
                    || expected_last_event.is_some_and(|expected| {
                        segment.event_references().last().copied() != Some(expected)
                    })
                {
                    return Err(DepositSyncWireError::InvalidTraversalTarget);
                }
                let mut children = Vec::with_capacity(
                    segment.event_references().len() + usize::from(segment.previous().is_some()),
                );
                children.extend(segment.previous().map(|reference| {
                    DepositSyncTraversalTarget::ArchiveSegment {
                        reference,
                        expected_end_ordinal: segment.start_ordinal(),
                        expected_last_event: None,
                    }
                }));
                for (offset, reference) in segment.event_references().iter().copied().enumerate() {
                    let expected_ordinal = segment
                        .start_ordinal()
                        .checked_add(
                            u64::try_from(offset)
                                .map_err(|_| DepositSyncWireError::InvalidTraversalTarget)?,
                        )
                        .ok_or(DepositSyncWireError::InvalidTraversalTarget)?;
                    children.push(DepositSyncTraversalTarget::ArchiveEvent {
                        reference,
                        expected_ordinal,
                    });
                }
                Ok(children)
            }
            DepositSyncTraversalTarget::ArchiveEvent { expected_ordinal, .. } => {
                let event = DepositArchiveEvent::from_bytes(&self.bytes)
                    .map_err(|_| DepositSyncWireError::InvalidTraversalTarget)?;
                if event.wallet_id() != self.reference.wallet()
                    || event.ordinal() != expected_ordinal
                {
                    return Err(DepositSyncWireError::InvalidTraversalTarget);
                }
                let checkpoint_sequence = expected_ordinal
                    .checked_add(1)
                    .ok_or(DepositSyncWireError::InvalidTraversalTarget)?;
                let (operation_kind, checkpoint_kind) = match event.operation() {
                    DepositArchiveOperation::Ledger => (
                        DepositSyncArchiveLeafKind::CertifiedLedger,
                        DepositSyncArchiveLeafKind::LedgerCheckpoint,
                    ),
                    DepositArchiveOperation::DepositObservation => (
                        DepositSyncArchiveLeafKind::CertifiedObservation,
                        DepositSyncArchiveLeafKind::ObservationCheckpoint,
                    ),
                };
                Ok(vec![
                    DepositSyncTraversalTarget::ArchiveLeaf {
                        reference: event.operation_reference(),
                        checkpoint_sequence,
                        kind: operation_kind,
                    },
                    DepositSyncTraversalTarget::ArchiveLeaf {
                        reference: event.checkpoint_reference(),
                        checkpoint_sequence,
                        kind: checkpoint_kind,
                    },
                ])
            }
            DepositSyncTraversalTarget::ArchiveLeaf { checkpoint_sequence, kind, .. } => {
                match kind {
                    DepositSyncArchiveLeafKind::CertifiedLedger => {
                        let ledger = CertifiedLedgerEntry::from_bytes(&self.bytes)
                            .map_err(|_| DepositSyncWireError::InvalidTraversalTarget)?;
                        if ledger.statement.wallet != self.reference.wallet() {
                            return Err(DepositSyncWireError::InvalidTraversalTarget);
                        }
                    }
                    DepositSyncArchiveLeafKind::CertifiedObservation => {
                        let observation = CertifiedDepositObservation::from_bytes(&self.bytes)
                            .map_err(|_| DepositSyncWireError::InvalidTraversalTarget)?;
                        if observation.statement.wallet_id() != self.reference.wallet() {
                            return Err(DepositSyncWireError::InvalidTraversalTarget);
                        }
                    }
                    DepositSyncArchiveLeafKind::LedgerCheckpoint
                    | DepositSyncArchiveLeafKind::ObservationCheckpoint => {
                        let checkpoint = DepositIndexCheckpointCertificate::from_bytes(&self.bytes)
                            .map_err(|_| DepositSyncWireError::InvalidTraversalTarget)?;
                        let statement = checkpoint.statement();
                        let operation_matches = matches!(
                            (kind, statement.operation()),
                            (
                                DepositSyncArchiveLeafKind::LedgerCheckpoint,
                                DepositIndexCheckpointOperation::Ledger { .. }
                            ) | (
                                DepositSyncArchiveLeafKind::ObservationCheckpoint,
                                DepositIndexCheckpointOperation::DepositObservation { .. }
                            )
                        );
                        if statement.context().wallet_id() != self.reference.wallet()
                            || statement.sequence() != checkpoint_sequence
                            || !operation_matches
                        {
                            return Err(DepositSyncWireError::InvalidTraversalTarget);
                        }
                    }
                }
                Ok(Vec::new())
            }
        }
    }
}

/// Opaque source-issued authority for one exact authenticated parent-child edge.
///
/// The tag is source-local and may only be checked with that source's 32-byte MAC key. All
/// security-relevant bindings remain in the authenticated material so a token cannot be replayed
/// across versions, deployments, wallets, advertisements, sources, requesters, or graph edges.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncObjectCapability {
    version: u16,
    domain: [u8; 16],
    context: DepositSyncContext,
    advertisement: [u8; 32],
    lease: [u8; 32],
    source: PartyId,
    requester: PartyId,
    parent: DepositSyncTraversalTarget,
    child: DepositSyncTraversalTarget,
    tag: [u8; 32],
}

impl DepositSyncObjectCapability {
    pub fn issue(
        mac_key: &[u8; 32],
        lease: DepositSyncAnchorLease,
        parent: DepositSyncTraversalTarget,
        child: DepositSyncTraversalTarget,
    ) -> Result<Self, DepositSyncWireError> {
        reject_zero_mac_key(mac_key)?;
        lease.authenticate_for(mac_key, lease.source, lease.requester)?;
        let mut capability = Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            domain: DEPOSIT_SYNC_WIRE_DOMAIN,
            context: lease.context,
            advertisement: lease.anchor.advertisement,
            lease: lease.digest(),
            source: lease.source,
            requester: lease.requester,
            parent,
            child,
            tag: [0; 32],
        };
        capability.validate_binding(lease, parent, child)?;
        capability.tag = capability_mac(mac_key, &capability)?;
        Ok(capability)
    }

    fn validate_binding(
        &self,
        lease: DepositSyncAnchorLease,
        parent: DepositSyncTraversalTarget,
        child: DepositSyncTraversalTarget,
    ) -> Result<(), DepositSyncWireError> {
        lease.validate()?;
        self.context.validate()?;
        self.parent.validate_for(lease)?;
        self.child.validate_for(lease)?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.domain != DEPOSIT_SYNC_WIRE_DOMAIN
            || self.context != lease.context
            || self.advertisement != lease.anchor.advertisement
            || self.lease != lease.digest()
            || self.source != lease.source
            || self.requester != lease.requester
            || self.parent != parent
            || self.child != child
            || self.parent == self.child
        {
            return Err(DepositSyncWireError::InvalidObjectCapability);
        }
        Ok(())
    }

    /// Verify all exact bindings and compare the keyed BLAKE3 tag in constant time.
    pub fn authenticate_for(
        &self,
        mac_key: &[u8; 32],
        lease: DepositSyncAnchorLease,
        parent: DepositSyncTraversalTarget,
        child: DepositSyncTraversalTarget,
    ) -> Result<(), DepositSyncWireError> {
        reject_zero_mac_key(mac_key)?;
        self.validate_binding(lease, parent, child)?;
        let expected = capability_mac(mac_key, self)?;
        if !bool::from(self.tag.ct_eq(&expected)) {
            return Err(DepositSyncWireError::InvalidObjectCapability);
        }
        Ok(())
    }

    #[must_use]
    pub const fn source(self) -> PartyId {
        self.source
    }

    #[must_use]
    pub const fn requester(self) -> PartyId {
        self.requester
    }

    #[must_use]
    pub const fn parent(self) -> DepositSyncTraversalTarget {
        self.parent
    }

    #[must_use]
    pub const fn child(self) -> DepositSyncTraversalTarget {
        self.child
    }
}

/// One exact object request. Advertised roots carry no capability; every other object carries the
/// exact source-issued parent-child capability returned by an earlier page.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncObjectRequestEntry {
    target: DepositSyncTraversalTarget,
    capability: Option<DepositSyncObjectCapability>,
}

impl DepositSyncObjectRequestEntry {
    pub fn advertised_root(
        lease: DepositSyncAnchorLease,
        target: DepositSyncTraversalTarget,
    ) -> Result<Self, DepositSyncWireError> {
        lease.validate()?;
        target.validate_for(lease)?;
        if !lease.is_root_target(target) {
            return Err(DepositSyncWireError::InvalidObjectRequest);
        }
        Ok(Self { target, capability: None })
    }

    #[must_use]
    pub const fn authorized(capability: DepositSyncObjectCapability) -> Self {
        Self { target: capability.child, capability: Some(capability) }
    }

    #[must_use]
    pub const fn target(self) -> DepositSyncTraversalTarget {
        self.target
    }

    #[must_use]
    pub const fn reference(self) -> DepositSyncObjectRef {
        self.target.reference()
    }

    #[must_use]
    pub const fn capability(self) -> Option<DepositSyncObjectCapability> {
        self.capability
    }
}

/// One cursorless, hard-bounded object page request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncObjectPageRequest {
    version: u16,
    lease: DepositSyncAnchorLease,
    #[serde(deserialize_with = "deserialize_object_request_entries")]
    entries: Vec<DepositSyncObjectRequestEntry>,
}

impl DepositSyncObjectPageRequest {
    pub fn new(
        lease: DepositSyncAnchorLease,
        entries: Vec<DepositSyncObjectRequestEntry>,
    ) -> Result<Self, DepositSyncWireError> {
        let request = Self { version: DEPOSIT_SYNC_WIRE_VERSION, lease, entries };
        request.validate()?;
        Ok(request)
    }

    /// Validate bounded canonical structure without trusting capability tags.
    ///
    /// This is sufficient for a requester serializing capabilities previously returned by the
    /// source. The source must additionally call [`Self::authenticate_capabilities`].
    pub fn validate(&self) -> Result<(), DepositSyncWireError> {
        self.lease.validate()?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.entries.is_empty()
            || self.entries.len() > MAX_DEPOSIT_SYNC_REQUEST_OBJECTS
        {
            return Err(DepositSyncWireError::InvalidObjectRequest);
        }

        let mut targets = BTreeSet::new();
        let mut plaintext_bytes = 0_usize;
        for entry in &self.entries {
            entry.target.validate_for(self.lease)?;
            if !targets.insert(entry.target) {
                return Err(DepositSyncWireError::InvalidObjectRequest);
            }
            plaintext_bytes = plaintext_bytes
                .checked_add(
                    usize::try_from(entry.reference().plaintext_len())
                        .map_err(|_| DepositSyncWireError::InvalidObjectRequest)?,
                )
                .ok_or(DepositSyncWireError::InvalidObjectRequest)?;
            if self.lease.is_root_target(entry.target) {
                if entry.capability.is_some() {
                    return Err(DepositSyncWireError::InvalidObjectRequest);
                }
            } else {
                let capability =
                    entry.capability.ok_or(DepositSyncWireError::InvalidObjectCapability)?;
                capability.validate_binding(self.lease, capability.parent, entry.target)?;
            }
        }
        if plaintext_bytes > MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES {
            return Err(DepositSyncWireError::InvalidObjectRequest);
        }
        Ok(())
    }

    /// Authenticate every non-root entry with the source's local MAC key.
    pub fn authenticate_capabilities(
        &self,
        source: PartyId,
        requester: PartyId,
        mac_key: &[u8; 32],
    ) -> Result<(), DepositSyncWireError> {
        self.validate()?;
        self.lease.authenticate_for(mac_key, source, requester)?;
        reject_zero_mac_key(mac_key)?;
        for entry in &self.entries {
            if let Some(capability) = entry.capability {
                capability.authenticate_for(
                    mac_key,
                    self.lease,
                    capability.parent,
                    entry.target,
                )?;
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn context(&self) -> DepositSyncContext {
        self.lease.context
    }

    #[must_use]
    pub const fn anchor(&self) -> DepositSyncObjectAnchor {
        self.lease.anchor
    }

    #[must_use]
    pub const fn lease(&self) -> DepositSyncAnchorLease {
        self.lease
    }

    #[must_use]
    pub const fn source(&self) -> PartyId {
        self.lease.source
    }

    #[must_use]
    pub const fn requester(&self) -> PartyId {
        self.lease.requester
    }

    #[must_use]
    pub fn entries(&self) -> &[DepositSyncObjectRequestEntry] {
        &self.entries
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self).expect("validated object request serializes");
        length_prefixed_hash(OBJECT_REQUEST_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate()?;
        encode_canonical(self, MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES)
    }

    /// Decode and authenticate a request for the exact transport-authenticated parties.
    pub fn from_bytes(
        source: PartyId,
        requester: PartyId,
        mac_key: &[u8; 32],
        bytes: &[u8],
    ) -> Result<Self, DepositSyncWireError> {
        let request = decode_canonical::<Self>(bytes, MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES)?;
        request.authenticate_capabilities(source, requester, mac_key)?;
        require_canonical(&request, bytes, MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES)?;
        Ok(request)
    }

    /// Decode only enough bounded canonical structure to select the local wallet authority.
    ///
    /// The returned context does not authenticate the lease or capabilities. A handler must call
    /// [`Self::from_bytes`] immediately with its stable source key and authenticated peer IDs.
    pub fn context_from_bytes(bytes: &[u8]) -> Result<DepositSyncContext, DepositSyncWireError> {
        let request = decode_canonical::<Self>(bytes, MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES)?;
        request.lease.context.validate()?;
        if request.version != DEPOSIT_SYNC_WIRE_VERSION
            || request.entries.is_empty()
            || request.entries.len() > MAX_DEPOSIT_SYNC_REQUEST_OBJECTS
        {
            return Err(DepositSyncWireError::InvalidObjectRequest);
        }
        require_canonical(&request, bytes, MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES)?;
        Ok(request.lease.context)
    }
}

/// One exact response page plus newly issued child capabilities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncObjectPage {
    version: u16,
    context: DepositSyncContext,
    anchor: DepositSyncObjectAnchor,
    source: PartyId,
    requester: PartyId,
    request: [u8; 32],
    #[serde(deserialize_with = "deserialize_objects")]
    objects: Vec<DepositSyncObject>,
    #[serde(deserialize_with = "deserialize_object_capabilities")]
    capabilities: Vec<DepositSyncObjectCapability>,
}

impl DepositSyncObjectPage {
    pub fn build(
        request: &DepositSyncObjectPageRequest,
        objects: Vec<DepositSyncObject>,
        capabilities: Vec<DepositSyncObjectCapability>,
    ) -> Result<Self, DepositSyncWireError> {
        let page = Self {
            version: DEPOSIT_SYNC_WIRE_VERSION,
            context: request.context(),
            anchor: request.anchor(),
            source: request.source(),
            requester: request.requester(),
            request: request.digest(),
            objects,
            capabilities,
        };
        page.validate_for(request)?;
        Ok(page)
    }

    /// Validate exact request/response correspondence and every typed semantic edge before merge.
    pub fn validate_for(
        &self,
        request: &DepositSyncObjectPageRequest,
    ) -> Result<(), DepositSyncWireError> {
        request.validate()?;
        self.context.validate()?;
        if self.version != DEPOSIT_SYNC_WIRE_VERSION
            || self.context != request.context()
            || self.anchor != request.anchor()
            || self.source != request.source()
            || self.requester != request.requester()
            || self.request != request.digest()
            || self.objects.len() != request.entries.len()
            || self.objects.len() > MAX_DEPOSIT_SYNC_PAGE_OBJECTS
            || self.capabilities.len() > MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES
        {
            return Err(DepositSyncWireError::InvalidObjectPage);
        }

        let mut expected_edges = BTreeSet::new();
        let mut plaintext_bytes = 0_usize;
        for (object, entry) in self.objects.iter().zip(&request.entries) {
            if object.reference != entry.reference() {
                return Err(DepositSyncWireError::InvalidObjectPage);
            }
            object.validate_for(request.context().wallet)?;
            for child in object.authenticated_semantic_children(entry.target)? {
                child.validate_for(request.lease)?;
                expected_edges.insert((entry.target, child));
            }
            plaintext_bytes = plaintext_bytes
                .checked_add(object.bytes.len())
                .ok_or(DepositSyncWireError::InvalidObjectPage)?;
        }
        if plaintext_bytes > MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES {
            return Err(DepositSyncWireError::InvalidObjectPage);
        }

        let mut edges = BTreeSet::new();
        for capability in &self.capabilities {
            capability.validate_binding(request.lease, capability.parent, capability.child)?;
            if !edges.insert((capability.parent, capability.child)) {
                return Err(DepositSyncWireError::InvalidObjectPage);
            }
        }
        if edges != expected_edges {
            return Err(DepositSyncWireError::InvalidObjectPage);
        }
        Ok(())
    }

    #[must_use]
    pub fn objects(&self) -> &[DepositSyncObject] {
        &self.objects
    }

    #[must_use]
    pub fn capabilities(&self) -> &[DepositSyncObjectCapability] {
        &self.capabilities
    }

    /// Exact replay identity for this ordered request-bound response.
    ///
    /// Objects already commit to their plaintext. The canonical page bytes additionally bind
    /// their order and every issued source-local child capability.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self).expect("validated object response serializes");
        length_prefixed_hash(OBJECT_RESPONSE_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(
        &self,
        request: &DepositSyncObjectPageRequest,
    ) -> Result<Vec<u8>, DepositSyncWireError> {
        self.validate_for(request)?;
        encode_canonical(self, MAX_DEPOSIT_SYNC_WIRE_BYTES)
    }

    pub fn from_bytes(
        request: &DepositSyncObjectPageRequest,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncWireError> {
        let page = decode_canonical::<Self>(bytes, MAX_DEPOSIT_SYNC_WIRE_BYTES)?;
        page.validate_for(request)?;
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

fn capability_mac(
    mac_key: &[u8; 32],
    capability: &DepositSyncObjectCapability,
) -> Result<[u8; 32], DepositSyncWireError> {
    #[derive(Serialize)]
    struct Material {
        version: u16,
        domain: [u8; 16],
        context: DepositSyncContext,
        advertisement: [u8; 32],
        lease: [u8; 32],
        source: PartyId,
        requester: PartyId,
        parent: DepositSyncTraversalTarget,
        child: DepositSyncTraversalTarget,
    }
    let bytes = postcard::to_allocvec(&Material {
        version: capability.version,
        domain: capability.domain,
        context: capability.context,
        advertisement: capability.advertisement,
        lease: capability.lease,
        source: capability.source,
        requester: capability.requester,
        parent: capability.parent,
        child: capability.child,
    })
    .map_err(|_| DepositSyncWireError::Serialization)?;
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(&(OBJECT_CAPABILITY_MAC_DOMAIN.len() as u64).to_le_bytes());
    hasher.update(OBJECT_CAPABILITY_MAC_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn anchor_lease_mac(
    mac_key: &[u8; 32],
    lease: &DepositSyncAnchorLease,
) -> Result<[u8; 32], DepositSyncWireError> {
    #[derive(Serialize)]
    struct Material {
        version: u16,
        domain: [u8; 16],
        context: DepositSyncContext,
        anchor: DepositSyncObjectAnchor,
        source: PartyId,
        requester: PartyId,
    }
    let bytes = postcard::to_allocvec(&Material {
        version: lease.version,
        domain: lease.domain,
        context: lease.context,
        anchor: lease.anchor,
        source: lease.source,
        requester: lease.requester,
    })
    .map_err(|_| DepositSyncWireError::Serialization)?;
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(&(ANCHOR_LEASE_MAC_DOMAIN.len() as u64).to_le_bytes());
    hasher.update(ANCHOR_LEASE_MAC_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn reject_zero_mac_key(mac_key: &[u8; 32]) -> Result<(), DepositSyncWireError> {
    if *mac_key == [0; 32] {
        return Err(DepositSyncWireError::InvalidObjectCapability);
    }
    Ok(())
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

fn deserialize_object_request_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<DepositSyncObjectRequestEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    struct EntriesVisitor;

    impl<'de> Visitor<'de> for EntriesVisitor {
        type Value = Vec<DepositSyncObjectRequestEntry>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_DEPOSIT_SYNC_REQUEST_OBJECTS} deposit object request entries"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|hint| hint > MAX_DEPOSIT_SYNC_REQUEST_OBJECTS) {
                return Err(A::Error::custom("too many deposit object request entries"));
            }
            let mut entries = Vec::with_capacity(
                sequence.size_hint().unwrap_or(0).min(MAX_DEPOSIT_SYNC_REQUEST_OBJECTS),
            );
            while let Some(entry) = sequence.next_element()? {
                if entries.len() == MAX_DEPOSIT_SYNC_REQUEST_OBJECTS {
                    return Err(A::Error::custom("too many deposit object request entries"));
                }
                entries.push(entry);
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_seq(EntriesVisitor)
}

fn deserialize_object_capabilities<'de, D>(
    deserializer: D,
) -> Result<Vec<DepositSyncObjectCapability>, D::Error>
where
    D: Deserializer<'de>,
{
    struct CapabilitiesVisitor;

    impl<'de> Visitor<'de> for CapabilitiesVisitor {
        type Value = Vec<DepositSyncObjectCapability>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES} deposit object capabilities"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|hint| hint > MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES) {
                return Err(A::Error::custom("too many deposit object capabilities"));
            }
            let mut capabilities = Vec::with_capacity(
                sequence.size_hint().unwrap_or(0).min(MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES),
            );
            while let Some(capability) = sequence.next_element()? {
                if capabilities.len() == MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES {
                    return Err(A::Error::custom("too many deposit object capabilities"));
                }
                capabilities.push(capability);
            }
            Ok(capabilities)
        }
    }

    deserializer.deserialize_seq(CapabilitiesVisitor)
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
    #[error("the source-issued exact-anchor lease is malformed or unauthenticated")]
    InvalidHeadLease,
    #[error("the source-pin release request or acknowledgement is malformed or mismatched")]
    InvalidRelease,
    #[error("the request is not bound to the supplied advertised roots")]
    WrongAdvertisement,
    #[error("the object-page request is malformed or exceeds its limits")]
    InvalidObjectRequest,
    #[error("the source-issued object capability is malformed or unauthenticated")]
    InvalidObjectCapability,
    #[error("the object traversal target has the wrong semantic position")]
    InvalidTraversalTarget,
    #[error("a content-addressed object reference is malformed or wallet-mismatched")]
    InvalidObjectReference,
    #[error("a returned content-addressed object is malformed")]
    InvalidObject,
    #[error("returned object bytes do not authenticate to their exact reference")]
    ObjectAuthentication,
    #[error("a requested immutable object is unavailable")]
    ObjectUnavailable,
    #[error("the returned object page is malformed or does not match the request")]
    InvalidObjectPage,
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
    use std::collections::{BTreeMap, VecDeque};

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

    fn leased_head(
        fixture: &Fixture,
        mac_key: &[u8; 32],
    ) -> (DepositSyncHeadRequest, DepositSyncHeadResponse, DepositSyncAnchorLease) {
        let request =
            DepositSyncHeadRequest::new(fixture.advertisement.context(), PartyId(1), PartyId(2))
                .unwrap();
        let response =
            DepositSyncHeadResponse::issue(request, fixture.advertisement.clone(), mac_key)
                .unwrap();
        let lease = response.lease();
        (request, response, lease)
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

    #[test]
    fn successor_boundary_accepts_postterminal_digest_with_exact_ledger_position() {
        assert!(portable_index_respects_registry_boundary(9, 9, true, None));
        assert!(
            !portable_index_respects_registry_boundary(9, 9, false, None),
            "a successor boundary still requires the exact predecessor ledger head and next index",
        );
        assert!(
            !portable_index_respects_registry_boundary(8, 9, true, None),
            "an advertisement cannot precede its active registry boundary",
        );
    }

    #[test]
    fn epoch_zero_boundary_requires_the_exact_committed_checkpoint() {
        assert!(portable_index_respects_registry_boundary(0, 0, true, Some(true)));
        assert!(
            !portable_index_respects_registry_boundary(0, 0, true, Some(false)),
            "epoch zero directly commits the exact portable checkpoint digest",
        );
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
    fn head_response_and_restart_stable_anchor_lease_are_canonical_and_bound() {
        assert_eq!(MAX_DEPOSIT_SYNC_HEAD_REQUEST_BYTES, 256);
        let test_fixture = fixture(7);
        let mac_key = [0x71; 32];
        let (request, response, lease) = leased_head(&test_fixture, &mac_key);
        let bytes = request.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_DEPOSIT_SYNC_HEAD_REQUEST_BYTES);
        assert_eq!(
            DepositSyncHeadRequest::from_bytes(PartyId(1), PartyId(2), &bytes).unwrap(),
            request
        );
        assert!(matches!(
            DepositSyncHeadRequest::from_bytes(
                PartyId(1),
                PartyId(2),
                &vec![0; MAX_DEPOSIT_SYNC_HEAD_REQUEST_BYTES + 1],
            ),
            Err(DepositSyncWireError::WireTooLarge {
                actual,
                maximum: MAX_DEPOSIT_SYNC_HEAD_REQUEST_BYTES,
            }) if actual == MAX_DEPOSIT_SYNC_HEAD_REQUEST_BYTES + 1
        ));

        let response_bytes = response.to_bytes(request).unwrap();
        assert_eq!(
            DepositSyncHeadResponse::from_bytes(request, &response_bytes).unwrap(),
            response
        );
        assert_eq!(response.advertisement(), &test_fixture.advertisement);
        lease.authenticate_for(&mac_key, PartyId(1), PartyId(2)).unwrap();

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            DepositSyncHeadRequest::from_bytes(PartyId(1), PartyId(2), &trailing),
            Err(DepositSyncWireError::TrailingBytes)
        ));
        assert!(DepositSyncHeadRequest::from_bytes(PartyId(3), PartyId(2), &bytes).is_err());
        assert!(lease.authenticate_for(&[0x72; 32], PartyId(1), PartyId(2)).is_err());

        let anchor = response.advertisement().object_anchor();
        anchor.validate_context(request.context()).unwrap();
        assert!(anchor.validate_context(fixture(9).advertisement.context()).is_err());
        let mut malformed_anchor = postcard::to_allocvec(&anchor).unwrap();
        malformed_anchor[0] = u8::try_from(DEPOSIT_SYNC_WIRE_VERSION.saturating_add(1)).unwrap();
        let malformed_anchor: DepositSyncObjectAnchor =
            postcard::from_bytes(&malformed_anchor).unwrap();
        assert!(malformed_anchor.validate_context(request.context()).is_err());

        // Postcard's unsigned varint decoder must not let an overlong representation become a
        // second encoding of the current version.
        let mut overlong = bytes;
        overlong.splice(0..1, [0x81, 0x00]);
        assert!(DepositSyncHeadRequest::from_bytes(PartyId(1), PartyId(2), &overlong).is_err());
    }

    #[test]
    fn source_pin_release_and_typed_ack_are_exact_canonical_and_restart_stable() {
        assert_eq!(MAX_DEPOSIT_SYNC_RELEASE_REQUEST_BYTES, 2 * 1024);
        let test_fixture = fixture(8);
        let mac_key = [0x81; 32];
        let (_, _, lease) = leased_head(&test_fixture, &mac_key);
        let request = DepositSyncReleaseRequest::new(lease).unwrap();
        let bytes = request.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_DEPOSIT_SYNC_RELEASE_REQUEST_BYTES);
        assert_eq!(
            DepositSyncReleaseRequest::from_bytes(PartyId(1), PartyId(2), &mac_key, &bytes,)
                .unwrap(),
            request,
        );
        assert_eq!(request.lease_digest(), lease.digest());

        let acknowledgement = DepositSyncReleaseAck::issue(request).unwrap();
        let acknowledgement_bytes = acknowledgement.to_bytes(request).unwrap();
        assert!(acknowledgement_bytes.len() <= MAX_DEPOSIT_SYNC_RELEASE_ACK_BYTES);
        assert_eq!(
            DepositSyncReleaseAck::from_bytes(request, &acknowledgement_bytes).unwrap(),
            acknowledgement,
        );
        assert_eq!(acknowledgement.request_digest(), request.digest());

        assert!(
            DepositSyncReleaseRequest::from_bytes(PartyId(3), PartyId(2), &mac_key, &bytes,)
                .is_err()
        );
        assert!(
            DepositSyncReleaseRequest::from_bytes(PartyId(1), PartyId(3), &mac_key, &bytes,)
                .is_err()
        );
        assert!(
            DepositSyncReleaseRequest::from_bytes(PartyId(1), PartyId(2), &[0x82; 32], &bytes,)
                .is_err()
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            DepositSyncReleaseRequest::from_bytes(PartyId(1), PartyId(2), &mac_key, &trailing,),
            Err(DepositSyncWireError::TrailingBytes)
        ));

        let other = fixture(9);
        let (_, _, other_lease) = leased_head(&other, &[0x83; 32]);
        let other_request = DepositSyncReleaseRequest::new(other_lease).unwrap();
        assert!(
            DepositSyncReleaseAck::from_bytes(other_request, &acknowledgement_bytes).is_err(),
            "an acknowledgement for one lease must not retire another source pin",
        );

        let mut corrupted = request;
        corrupted.lease.tag[0] ^= 1;
        assert!(
            DepositSyncReleaseRequest::from_bytes(
                PartyId(1),
                PartyId(2),
                &mac_key,
                &raw_encode(&corrupted),
            )
            .is_err()
        );
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
        let target = DepositSyncTraversalTarget::ArchiveLeaf {
            reference,
            checkpoint_sequence: 17,
            kind: DepositSyncArchiveLeafKind::CertifiedObservation,
        };
        assert!(object.authenticated_semantic_children(target).unwrap().is_empty());
    }

    #[test]
    fn wrong_domain_wallet_and_version_fail_closed() {
        let fixture = fixture(9);
        let request =
            DepositSyncHeadRequest::new(fixture.advertisement.context(), PartyId(1), PartyId(2))
                .unwrap();

        let mut wrong_version = request;
        wrong_version.version = DEPOSIT_SYNC_WIRE_VERSION + 1;
        assert!(
            DepositSyncHeadRequest::from_bytes(
                PartyId(1),
                PartyId(2),
                &raw_encode(&wrong_version),
            )
            .is_err()
        );

        let mut wrong_domain = request;
        wrong_domain.context.domain[0] ^= 1;
        assert!(
            DepositSyncHeadRequest::from_bytes(PartyId(1), PartyId(2), &raw_encode(&wrong_domain),)
                .is_err()
        );

        let mut wrong_wallet = fixture.advertisement.clone();
        wrong_wallet.context.wallet = DepositWalletId([0x44; 32]);
        assert!(DepositSyncHeadResponse::issue(request, wrong_wallet, &[0x91; 32]).is_err());
    }

    #[test]
    fn request_and_reply_vector_bounds_are_enforced_during_decode() {
        let fixture = fixture(11);
        let root =
            DepositSyncObjectRef::Registry(fixture.advertisement.object_anchor().registry_root());
        let source = PartyId(1);
        let requester = PartyId(2);
        let mac_key = [0x91; 32];
        let (_, _, lease) = leased_head(&fixture, &mac_key);
        let root_target = lease
            .root_targets()
            .unwrap()
            .into_iter()
            .find(|target| target.reference() == root)
            .unwrap();
        let root_entry =
            DepositSyncObjectRequestEntry::advertised_root(lease, root_target).unwrap();
        let request = DepositSyncObjectPageRequest::new(lease, vec![root_entry]).unwrap();

        let mut oversized = request.clone();
        oversized.entries = vec![root_entry; MAX_DEPOSIT_SYNC_REQUEST_OBJECTS + 1];
        let bytes = raw_encode(&oversized);
        assert!(
            DepositSyncObjectPageRequest::from_bytes(source, requester, &mac_key, &bytes,).is_err()
        );

        assert!(DepositSyncObjectPageRequest::new(lease, Vec::new()).is_err());

        let object = DepositSyncObject::new(root, fixture.objects[&root].clone()).unwrap();
        let children = object.authenticated_semantic_children(root_target).unwrap();
        let capabilities = children
            .into_iter()
            .map(|child| {
                DepositSyncObjectCapability::issue(&mac_key, lease, root_target, child).unwrap()
            })
            .collect();
        let page = DepositSyncObjectPage::build(&request, vec![object], capabilities).unwrap();
        let mut oversized_page = page.clone();
        oversized_page.objects = vec![page.objects()[0].clone(); MAX_DEPOSIT_SYNC_PAGE_OBJECTS + 1];
        assert!(
            DepositSyncObjectPage::from_bytes(&request, &raw_encode(&oversized_page),).is_err()
        );

        let mut oversized_capabilities = page;
        let capability = oversized_capabilities.capabilities()[0];
        oversized_capabilities.capabilities =
            vec![capability; MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES + 1];
        assert!(
            DepositSyncObjectPage::from_bytes(&request, &raw_encode(&oversized_capabilities),)
                .is_err()
        );
    }

    #[test]
    fn object_authentication_root_admission_and_capabilities_fail_closed() {
        let current = fixture(13);
        let other = fixture(14);
        let root =
            DepositSyncObjectRef::Registry(current.advertisement.object_anchor().registry_root());
        let source = PartyId(1);
        let requester = PartyId(2);
        let mac_key = [0xa1; 32];
        let (head_request, _, lease) = leased_head(&current, &mac_key);
        let root_target = lease
            .root_targets()
            .unwrap()
            .into_iter()
            .find(|target| target.reference() == root)
            .unwrap();
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
        let detached_target =
            DepositSyncTraversalTarget::Registry(CompactRegistryTraversalTarget::Link {
                reference: detached_ref,
                epoch: 0,
                chain_root: [0x33; 32],
            });
        assert!(DepositSyncObjectRequestEntry::advertised_root(lease, detached_target).is_err());

        assert!(lease.validate_for_advertisement(head_request, &other.advertisement).is_err());
        let root_entry =
            DepositSyncObjectRequestEntry::advertised_root(lease, root_target).unwrap();
        let request = DepositSyncObjectPageRequest::new(lease, vec![root_entry]).unwrap();
        request.authenticate_capabilities(source, requester, &mac_key).unwrap();

        let root_object =
            DepositSyncObject::new(root, current.objects.get(&root).unwrap().clone()).unwrap();
        let child = root_object.authenticated_semantic_children(root_target).unwrap()[0];
        let capability =
            DepositSyncObjectCapability::issue(&mac_key, lease, root_target, child).unwrap();
        let child_request = DepositSyncObjectPageRequest::new(
            lease,
            vec![DepositSyncObjectRequestEntry::authorized(capability)],
        )
        .unwrap();
        let bytes = child_request.to_bytes().unwrap();
        assert_eq!(
            DepositSyncObjectPageRequest::from_bytes(source, requester, &mac_key, &bytes,).unwrap(),
            child_request
        );
        assert!(
            DepositSyncObjectPageRequest::from_bytes(source, requester, &[0xa2; 32], &bytes,)
                .is_err()
        );
        assert!(
            DepositSyncObjectPageRequest::from_bytes(PartyId(3), requester, &mac_key, &bytes,)
                .is_err()
        );
        assert!(
            DepositSyncObjectPageRequest::from_bytes(source, PartyId(3), &mac_key, &bytes,)
                .is_err()
        );
        assert!(DepositSyncObjectCapability::issue(&[0; 32], lease, root_target, child).is_err());

        let mut corrupted = child_request.clone();
        corrupted.entries[0].capability.as_mut().unwrap().tag[0] ^= 1;
        assert!(
            DepositSyncObjectPageRequest::from_bytes(
                source,
                requester,
                &mac_key,
                &raw_encode(&corrupted),
            )
            .is_err()
        );

        let root_with_capability =
            DepositSyncObjectRequestEntry { target: root_target, capability: Some(capability) };
        assert!(DepositSyncObjectPageRequest::new(lease, vec![root_with_capability]).is_err());
        let child_without_capability =
            DepositSyncObjectRequestEntry { target: child, capability: None };
        assert!(DepositSyncObjectPageRequest::new(lease, vec![child_without_capability]).is_err());
    }

    #[test]
    fn response_is_exact_request_bound_and_parent_structured() {
        let fixture = fixture(17);
        let source = PartyId(1);
        let requester = PartyId(2);
        let mac_key = [0xb1; 32];
        let references = connected_registry_references(&fixture, 2);
        assert_eq!(references.len(), 2);
        let root = references[0];
        let (_, _, lease) = leased_head(&fixture, &mac_key);
        let root_target = lease
            .root_targets()
            .unwrap()
            .into_iter()
            .find(|target| target.reference() == root)
            .unwrap();
        let root_entry =
            DepositSyncObjectRequestEntry::advertised_root(lease, root_target).unwrap();
        let request = DepositSyncObjectPageRequest::new(lease, vec![root_entry]).unwrap();
        let object = DepositSyncObject::new(root, fixture.objects[&root].clone()).unwrap();
        let children = object.authenticated_semantic_children(root_target).unwrap();
        assert!(children.iter().any(|target| target.reference() == references[1]));
        let capabilities: Vec<_> = children
            .iter()
            .copied()
            .map(|child| {
                DepositSyncObjectCapability::issue(&mac_key, lease, root_target, child).unwrap()
            })
            .collect();
        let page =
            DepositSyncObjectPage::build(&request, vec![object.clone()], capabilities).unwrap();
        let page_bytes = page.to_bytes(&request).unwrap();
        let response_digest = page.digest();
        assert_eq!(
            DepositSyncObjectPage::from_bytes(&request, &page_bytes).unwrap().digest(),
            response_digest,
            "canonical response replay must retain its exact identity",
        );
        assert_eq!(DepositSyncObjectPage::from_bytes(&request, &page_bytes).unwrap(), page);

        let child_capability = page
            .capabilities()
            .iter()
            .find(|capability| capability.child().reference() == references[1]);
        let next_request = DepositSyncObjectPageRequest::new(
            lease,
            vec![DepositSyncObjectRequestEntry::authorized(child_capability.copied().unwrap())],
        )
        .unwrap();
        next_request.authenticate_capabilities(source, requester, &mac_key).unwrap();

        let mut missing = page.clone();
        missing.objects.clear();
        assert!(missing.validate_for(&request).is_err());

        let mut extra = page.clone();
        extra.objects.push(object);
        assert!(extra.validate_for(&request).is_err());

        let mut unbound_parent = page;
        unbound_parent.capabilities[0].parent = unbound_parent.capabilities[0].child;
        assert_ne!(
            unbound_parent.digest(),
            response_digest,
            "issued capability order and bindings must enter the response identity",
        );
        assert!(unbound_parent.validate_for(&request).is_err());
    }

    #[test]
    fn registry_child_semantic_hash_and_depth_are_checked_before_merge() {
        let fixture = fixture(18);
        let (_, _, lease) = leased_head(&fixture, &[0xc1; 32]);
        let root_target = lease.root_targets().unwrap()[0];
        let root = root_target.reference();
        let root_object = DepositSyncObject::new(root, fixture.objects[&root].clone()).unwrap();
        let honest_child = root_object.authenticated_semantic_children(root_target).unwrap()[0];
        let references = connected_registry_references(&fixture, 3);
        let swapped_reference = references[2];
        let DepositSyncTraversalTarget::Registry(CompactRegistryTraversalTarget::Index {
            depth,
            semantic_hash,
            ..
        }) = honest_child
        else {
            panic!("registry root must yield an index target");
        };
        let swapped_target =
            DepositSyncTraversalTarget::Registry(CompactRegistryTraversalTarget::Index {
                reference: match swapped_reference {
                    DepositSyncObjectRef::Registry(reference) => reference,
                    _ => unreachable!(),
                },
                depth,
                semantic_hash,
            });
        let swapped =
            DepositSyncObject::new(swapped_reference, fixture.objects[&swapped_reference].clone())
                .unwrap();
        assert!(matches!(
            swapped.authenticated_semantic_children(swapped_target),
            Err(DepositSyncWireError::InvalidTraversalTarget)
        ));

        let wrong_depth =
            DepositSyncTraversalTarget::Registry(CompactRegistryTraversalTarget::Index {
                reference: match honest_child.reference() {
                    DepositSyncObjectRef::Registry(reference) => reference,
                    _ => unreachable!(),
                },
                depth: depth.saturating_add(1),
                semantic_hash,
            });
        let honest_reference = honest_child.reference();
        let honest =
            DepositSyncObject::new(honest_reference, fixture.objects[&honest_reference].clone())
                .unwrap();
        assert!(matches!(
            honest.authenticated_semantic_children(wrong_depth),
            Err(DepositSyncWireError::InvalidTraversalTarget)
        ));
    }

    #[test]
    fn archive_segment_end_and_event_ordinal_are_checked_before_merge() {
        #[derive(Serialize)]
        enum PayloadEncoding {
            LedgerCheckpoint { ledger: WalletArtifactRef, checkpoint: WalletArtifactRef },
        }
        #[derive(Serialize)]
        struct EventEncoding {
            version: u16,
            wallet: DepositWalletId,
            ordinal: u64,
            previous: Option<WalletArtifactRef>,
            payload: PayloadEncoding,
        }
        #[derive(Serialize)]
        struct SegmentEncoding {
            version: u16,
            wallet: DepositWalletId,
            start_ordinal: u64,
            previous: Option<WalletArtifactRef>,
            events: Vec<WalletArtifactRef>,
        }

        let wallet = DepositWalletId([0xd1; 32]);
        let ledger = WalletArtifactRef::for_contents(
            WalletId(wallet.0),
            CERTIFIED_LEDGER_ENTRY_ARTIFACT,
            b"ledger",
        )
        .unwrap();
        let checkpoint = WalletArtifactRef::for_contents(
            WalletId(wallet.0),
            DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
            b"checkpoint",
        )
        .unwrap();
        let event_bytes = raw_encode(&EventEncoding {
            version: 2,
            wallet,
            ordinal: 0,
            previous: None,
            payload: PayloadEncoding::LedgerCheckpoint { ledger, checkpoint },
        });
        DepositArchiveEvent::from_bytes(&event_bytes).unwrap();
        let event_reference = WalletArtifactRef::for_contents(
            WalletId(wallet.0),
            DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
            &event_bytes,
        )
        .unwrap();
        let event_object = DepositSyncObject::new(
            DepositSyncObjectRef::CertificateArchive(event_reference),
            event_bytes,
        )
        .unwrap();
        let event_target = DepositSyncTraversalTarget::ArchiveEvent {
            reference: event_reference,
            expected_ordinal: 0,
        };
        assert_eq!(event_object.authenticated_semantic_children(event_target).unwrap().len(), 2);
        assert!(matches!(
            event_object.authenticated_semantic_children(
                DepositSyncTraversalTarget::ArchiveEvent {
                    reference: event_reference,
                    expected_ordinal: 1,
                },
            ),
            Err(DepositSyncWireError::InvalidTraversalTarget)
        ));

        let segment_bytes = raw_encode(&SegmentEncoding {
            version: 2,
            wallet,
            start_ordinal: 0,
            previous: None,
            events: vec![event_reference],
        });
        DepositArchiveSegment::from_bytes(&segment_bytes).unwrap();
        let segment_reference = WalletArtifactRef::for_contents(
            WalletId(wallet.0),
            DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT,
            &segment_bytes,
        )
        .unwrap();
        let segment_object = DepositSyncObject::new(
            DepositSyncObjectRef::CertificateArchive(segment_reference),
            segment_bytes,
        )
        .unwrap();
        assert!(matches!(
            segment_object.authenticated_semantic_children(
                DepositSyncTraversalTarget::ArchiveSegment {
                    reference: segment_reference,
                    expected_end_ordinal: 2,
                    expected_last_event: Some(event_reference),
                },
            ),
            Err(DepositSyncWireError::InvalidTraversalTarget)
        ));
        let other_event = WalletArtifactRef::for_contents(
            WalletId(wallet.0),
            DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
            b"other-event",
        )
        .unwrap();
        assert!(matches!(
            segment_object.authenticated_semantic_children(
                DepositSyncTraversalTarget::ArchiveSegment {
                    reference: segment_reference,
                    expected_end_ordinal: 1,
                    expected_last_event: Some(other_event),
                },
            ),
            Err(DepositSyncWireError::InvalidTraversalTarget)
        ));
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
