//! Mutually authenticated QUIC framing for party-to-party protocol traffic.
//!
//! This module deliberately treats AVSS, QUAL, epoch, and deposit messages as opaque payloads. It
//! provides transport authentication, routing, framing, bounds, request correlation, and timeouts;
//! the protocol adapter remains responsible for validating each body. Key-rotation traffic is the
//! exception: its small route enum duplicates [`KeyRotationWire`]'s variant, so this layer performs
//! bounded canonical decoding and rejects any outer/inner operation mismatch before dispatch.
//!
//! A peer certificate is an exact leaf-certificate pin, not a general-purpose CA. Rustls first
//! validates the presented certificate against the configured leaf anchors, then this module maps
//! the exact leaf DER bytes to a [`PartyId`] before accepting a frame. Anonymous clients and
//! accept-all certificate verifiers are never enabled.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use quinn::{
    Endpoint, IdleTimeout, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rand_core::{CryptoRng, RngCore};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time;

#[cfg(test)]
use crate::deposit_state_transfer_wire::MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_BYTES;
use crate::{
    committee::PartyId,
    deposit_consensus::MAX_CONSENSUS_MESSAGE_BYTES,
    deposit_state_transfer_wire::{
        MAX_DEPOSIT_STATE_EXPORT_HEAD_REQUEST_BYTES,
        MAX_DEPOSIT_STATE_EXPORT_OBJECTS_REQUEST_BYTES,
        MAX_DEPOSIT_STATE_EXPORT_RELEASE_REQUEST_BYTES,
        MAX_DEPOSIT_STATE_IMPORTED_ACK_DELIVERY_BYTES,
        MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_DELIVERY_BYTES,
        MAX_POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_DELIVERY_BYTES,
        MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_BYTES, MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES,
    },
    deposit_sync_support::MAX_DEPOSIT_SYNC_SUPPORT_REQUEST_BYTES,
    deposit_sync_wire::{
        MAX_DEPOSIT_SYNC_HEAD_REQUEST_BYTES, MAX_DEPOSIT_SYNC_RELEASE_REQUEST_BYTES,
    },
    key_rotation::{
        KeyRotationWire, MAX_KEY_ADVERTISEMENT_BYTES, MAX_KEY_ROTATION_CERTIFICATE_BYTES,
        MAX_KEY_ROTATION_FALLBACK_VOTE_BYTES, MAX_KEY_ROTATION_ROUND_STATE_BYTES,
    },
};

const WIRE_VERSION: u16 = 8;
const ALPN: &[u8] = b"threshold-monero-peer/8";
const LENGTH_PREFIX_BYTES: usize = 4;
const HARD_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const HARD_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const HARD_MAX_REJECTION_MESSAGE_BYTES: usize = 4 * 1024;
const HARD_MAX_CONCURRENT_STREAMS: u32 = 256;
const HARD_MAX_IN_FLIGHT_FRAME_BYTES: usize = 128 * 1024 * 1024;
const MAX_REQUEST_PRELUDE_FRAME_BYTES: usize = 512;
const MAX_REQUEST_ADMISSION_FRAME_BYTES: usize = 8 * 1024;
// A Byzantine sender can ignore the v8 admission handshake and transmit a body early. Keep the
// initial QUIC stream credit independent of the 9 MiB application frame cap so such bytes remain
// transport-bounded until the application explicitly admits and drains the stream.
const INITIAL_STREAM_RECEIVE_WINDOW_BYTES: usize = 64 * 1024;
const MAX_CONFIGURED_TIMEOUT: Duration = Duration::from_secs(120);
// Body transfers must sustain this average rate after one idle-timeout allowance. An independent
// idle-progress timer catches a completely stalled stream sooner, while the absolute cap below
// prevents a sender from living forever by releasing one byte just before each idle deadline.
const MIN_REQUEST_BODY_BYTES_PER_SECOND: usize = 64 * 1024;
const MAX_REQUEST_BODY_TRANSFER_TIMEOUT: Duration = MAX_CONFIGURED_TIMEOUT;
// A signed envelope has fixed-size hashes, a session, a signature, and bounded postcard varints.
// Keeping this conservative allowance explicit avoids coupling the transport to private envelope
// layout while still rejecting an oversized key-rotation body before protocol verification.
const MAX_SIGNED_ENVELOPE_WIRE_OVERHEAD_BYTES: usize = 256;

/// Maximum canonical transport body for one X25519 key advertisement.
pub const MAX_KEY_ROTATION_ADVERTISEMENT_WIRE_BYTES: usize =
    MAX_KEY_ADVERTISEMENT_BYTES + MAX_SIGNED_ENVELOPE_WIRE_OVERHEAD_BYTES + 1;
/// Maximum canonical transport body for one source-committee selection-fallback vote.
pub const MAX_KEY_ROTATION_FALLBACK_VOTE_WIRE_BYTES: usize =
    MAX_KEY_ROTATION_FALLBACK_VOTE_BYTES + MAX_SIGNED_ENVELOPE_WIRE_OVERHEAD_BYTES + 1;
/// Maximum canonical transport body for one signed key-rotation consensus message.
pub const MAX_KEY_ROTATION_CONSENSUS_WIRE_BYTES: usize =
    MAX_CONSENSUS_MESSAGE_BYTES + MAX_SIGNED_ENVELOPE_WIRE_OVERHEAD_BYTES + 1;
/// Maximum canonical transport body for one portable key-rotation view certificate.
///
/// A view certificate must fit in the same durable round that retains and retries it. Using the
/// round-state engineering cap also keeps this exceptional nested-certificate path below the
/// endpoint's non-configurable 8 MiB body cap.
pub const MAX_KEY_ROTATION_VIEW_CERTIFICATE_WIRE_BYTES: usize = MAX_KEY_ROTATION_ROUND_STATE_BYTES;
/// Maximum canonical transport body for one terminal key-rotation certificate.
pub const MAX_KEY_ROTATION_CERTIFICATE_WIRE_BYTES: usize = MAX_KEY_ROTATION_CERTIFICATE_BYTES + 16;
/// Maximum canonical start request for one ordinary moving-tip prefix-support attempt.
///
/// The fixed allowance covers the typed start envelope and optional exact replacement digest;
/// the embedded terminal checkpoint remains bounded by the support protocol itself.
pub const MAX_DEPOSIT_PREFIX_SUPPORT_START_WIRE_BYTES: usize =
    MAX_DEPOSIT_SYNC_SUPPORT_REQUEST_BYTES + 1024;
/// Maximum canonical continuation request for one already-persisted prefix scan.
pub const MAX_DEPOSIT_PREFIX_SUPPORT_CONTINUE_WIRE_BYTES: usize = 1024;

// Every specialized v8 request cap is owned by its typed wire decoder. The transport must never
// admit more bytes for a route than that decoder accepts, and no protocol-specific cap may exceed
// the endpoint's non-configurable body ceiling.
const _: () = assert!(MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_BYTES <= HARD_MAX_BODY_BYTES);
const _: () = assert!(MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES <= HARD_MAX_BODY_BYTES);
const _: () =
    assert!(MAX_POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_DELIVERY_BYTES <= HARD_MAX_BODY_BYTES);
const _: () = assert!(MAX_DEPOSIT_STATE_EXPORT_HEAD_REQUEST_BYTES <= HARD_MAX_BODY_BYTES);
const _: () = assert!(MAX_DEPOSIT_STATE_EXPORT_OBJECTS_REQUEST_BYTES <= HARD_MAX_BODY_BYTES);
const _: () = assert!(MAX_DEPOSIT_STATE_EXPORT_RELEASE_REQUEST_BYTES <= HARD_MAX_BODY_BYTES);
const _: () = assert!(MAX_DEPOSIT_STATE_IMPORTED_ACK_DELIVERY_BYTES <= HARD_MAX_BODY_BYTES);
const _: () = assert!(MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_DELIVERY_BYTES <= HARD_MAX_BODY_BYTES);

/// Stable identifier used to correlate one response with one request.
///
/// Callers may derive this from a durable outbox key to make retries idempotent. The transport
/// does not infer request identity from stream order or connection state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId([u8; 32]);

struct RequestIdHashFlavor(blake3::Hasher);

impl postcard::ser_flavors::Flavor for RequestIdHashFlavor {
    type Output = [u8; 32];

    fn try_push(&mut self, byte: u8) -> postcard::Result<()> {
        self.0.update(&[byte]);
        Ok(())
    }

    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        self.0.update(bytes);
        Ok(())
    }

    fn finalize(self) -> postcard::Result<Self::Output> {
        Ok(*self.0.finalize().as_bytes())
    }
}

impl RequestId {
    #[must_use]
    /// Derive an idempotency key bound to one network/configuration trust domain.
    ///
    /// `network_id` should be a canonical digest of the deployment genesis or equivalent trust
    /// anchor. Reusing only `domain` and `material` across networks is intentionally impossible.
    pub fn derive(network_id: [u8; 32], domain: &[u8], material: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/quic-request-id/v1");
        hasher.update(&network_id);
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        hasher.update(&(material.len() as u64).to_le_bytes());
        hasher.update(material);
        Self(*hasher.finalize().as_bytes())
    }

    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0_u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Derive the only valid request identifier for one canonical authenticated route and body.
    ///
    /// Receivers recompute this from the decoded canonical frame. Reusing an identifier with a
    /// different sender, recipient, operation, or body therefore fails before reducer dispatch,
    /// including after process restart when runtime replay caches are empty.
    pub fn for_peer_request(
        network_id: [u8; 32],
        from: PartyId,
        to: PartyId,
        request: &PeerRequest,
    ) -> Result<Self, QuicTransportError> {
        const DOMAIN: &[u8] = b"canonical-authenticated-peer-request/v8";

        // Preserve `derive(network, domain, from || to || len || postcard(request))` exactly,
        // while feeding the canonical request bytes directly into BLAKE3. Request bodies may be
        // eight MiB, so materializing both `encoded` and `material` here would otherwise add two
        // attacker-sized allocations on every admitted inbound request.
        let encoded_len = postcard::experimental::serialized_size(request)
            .map_err(QuicTransportError::Serialization)?;
        let material_len =
            12_usize.checked_add(encoded_len).ok_or(QuicTransportError::FrameTooLarge {
                actual: encoded_len,
                maximum: HARD_MAX_FRAME_BYTES,
            })?;
        let encoded_len = u64::try_from(encoded_len).map_err(|_| {
            QuicTransportError::FrameTooLarge { actual: encoded_len, maximum: HARD_MAX_FRAME_BYTES }
        })?;
        let material_len =
            u64::try_from(material_len).map_err(|_| QuicTransportError::FrameTooLarge {
                actual: material_len,
                maximum: HARD_MAX_FRAME_BYTES,
            })?;
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/quic-request-id/v1");
        hasher.update(&network_id);
        hasher.update(&(DOMAIN.len() as u64).to_le_bytes());
        hasher.update(DOMAIN);
        hasher.update(&material_len.to_le_bytes());
        hasher.update(&from.0.to_le_bytes());
        hasher.update(&to.0.to_le_bytes());
        hasher.update(&encoded_len.to_le_bytes());
        postcard::serialize_with_flavor(request, RequestIdHashFlavor(hasher))
            .map(Self)
            .map_err(QuicTransportError::Serialization)
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AvssOperation {
    Deliver,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QualOperation {
    Deliver,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum EpochOperation {
    Acknowledge,
    Activate,
    Retire,
    /// Persist and verify a portable activation certificate without installing or retiring a
    /// signing share. Pre-provisioned future members use this to retain deposit genesis/history.
    Observe,
    /// Pull the immediate authenticated history successor or one bounded immutable-object chunk.
    History,
}

/// X25519 key-rotation messages carried only over mutually authenticated QUIC.
///
/// The operation is a routing assertion in addition to the enum tag inside [`KeyRotationWire`].
/// Decoding requires both to agree, so an intermediary cannot make advertisement bytes reach a
/// consensus handler (or vice versa) by changing only the outer route.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum KeyRotationOperation {
    Advertisement,
    FallbackVote,
    Consensus,
    ViewCertificate,
    Certificate,
}

impl KeyRotationOperation {
    /// Global causal order for a durable key-rotation relay.
    #[must_use]
    pub const fn causal_priority(self) -> u8 {
        match self {
            Self::Advertisement => 0,
            Self::FallbackVote => 1,
            Self::Consensus => 2,
            Self::ViewCertificate => 3,
            Self::Certificate => 4,
        }
    }

    /// Hard canonical body limit for this operation, independent of endpoint configuration.
    #[must_use]
    pub const fn max_body_bytes(self) -> usize {
        match self {
            Self::Advertisement => MAX_KEY_ROTATION_ADVERTISEMENT_WIRE_BYTES,
            Self::FallbackVote => MAX_KEY_ROTATION_FALLBACK_VOTE_WIRE_BYTES,
            Self::Consensus => MAX_KEY_ROTATION_CONSENSUS_WIRE_BYTES,
            Self::ViewCertificate => MAX_KEY_ROTATION_VIEW_CERTIFICATE_WIRE_BYTES,
            Self::Certificate => MAX_KEY_ROTATION_CERTIFICATE_WIRE_BYTES,
        }
    }

    /// Derive the only valid outer route for a portable key-rotation payload.
    #[must_use]
    pub const fn for_wire(wire: &KeyRotationWire) -> Self {
        match wire {
            KeyRotationWire::Advertisement(_) => Self::Advertisement,
            KeyRotationWire::FallbackVote(_) => Self::FallbackVote,
            KeyRotationWire::Consensus(_) => Self::Consensus,
            KeyRotationWire::ViewCertificate(_) => Self::ViewCertificate,
            KeyRotationWire::Certificate(_) => Self::Certificate,
        }
    }

    /// Canonically encode a key-rotation payload after checking its outer route and hard limit.
    pub fn encode_wire(self, wire: &KeyRotationWire) -> Result<Vec<u8>, QuicTransportError> {
        let encoded_operation = Self::for_wire(wire);
        if encoded_operation != self {
            return Err(QuicTransportError::WrongKeyRotationOperation {
                routed: self,
                encoded: encoded_operation,
            });
        }
        let body =
            postcard::to_allocvec(wire).map_err(QuicTransportError::KeyRotationSerialization)?;
        let maximum = self.max_body_bytes();
        if body.len() > maximum {
            return Err(QuicTransportError::BodyTooLarge { actual: body.len(), maximum });
        }
        Ok(body)
    }

    /// Decode a bounded, canonical payload and require it to agree with this outer route.
    ///
    /// This is structural transport validation only. Callers must still pass the returned value
    /// to `KeyRotationRound::handle_wire` with the authenticated peer and locally trusted context.
    pub fn decode_wire(self, body: &[u8]) -> Result<KeyRotationWire, QuicTransportError> {
        let maximum = self.max_body_bytes();
        if body.len() > maximum {
            return Err(QuicTransportError::BodyTooLarge { actual: body.len(), maximum });
        }
        let (wire, trailing) = postcard::take_from_bytes::<KeyRotationWire>(body)
            .map_err(QuicTransportError::KeyRotationDeserialization)?;
        if !trailing.is_empty() {
            return Err(QuicTransportError::TrailingKeyRotationBodyBytes(trailing.len()));
        }
        let canonical =
            postcard::to_allocvec(&wire).map_err(QuicTransportError::KeyRotationSerialization)?;
        if canonical != body {
            return Err(QuicTransportError::NonCanonicalKeyRotationBody);
        }
        let encoded_operation = Self::for_wire(&wire);
        if encoded_operation != self {
            return Err(QuicTransportError::WrongKeyRotationOperation {
                routed: self,
                encoded: encoded_operation,
            });
        }
        Ok(wire)
    }
}

/// Deposit-ledger messages carried only over mutually authenticated QUIC.
///
/// `ConsensusProposal`, `ConsensusMessage`, and `ConsensusCertificate` carry portable
/// Byzantine-agreement traffic for ledger and checkpoint decisions. `Attest` contributes one
/// committee signature; `Certificate` disseminates a committed ledger entry.
/// `DepositObservation`, `DepositObservationAttest`, and
/// `DepositObservationCertificate` provide the corresponding live proposal, witness, and
/// certificate routes for confirmed-output observations. `IndexCheckpointAttest` and
/// `IndexCheckpointCertificate` complete a ledger-bound portable-index checkpoint; the two
/// `DepositObservationIndexCheckpoint*` routes carry the separately certified observation lane
/// without inventing a ledger slot. `Consolidation` carries certified-intent consensus, all-to-all
/// ROAST contributions and candidates. The `Sync*` operations expose only the fresh compact
/// catch-up protocol: settled heads and root-connected immutable object pages. Prefix-support
/// start/continue/endorsement routes certify a stable semantic prefix under independently
/// authenticated local archive anchors. The post-handoff routes are deliberately distinct from
/// ordinary current-committee sync: they are authorized by certified transition capabilities.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DepositOperation {
    Attest,
    Certificate,
    /// Contribute one committee signature to the deterministic portable-index checkpoint.
    IndexCheckpointAttest,
    /// Disseminate the exact quorum certificate for the portable-index checkpoint.
    IndexCheckpointCertificate,
    /// Propose one exact, issuer-bound confirmed-output observation.
    DepositObservation,
    /// Contribute one committee witness to an exact confirmed-output observation.
    DepositObservationAttest,
    /// Disseminate the exact n-f-certified confirmed-output observation.
    DepositObservationCertificate,
    /// Contribute one checkpoint witness for an exact n-f-certified deposit observation.
    DepositObservationIndexCheckpointAttest,
    /// Disseminate the exact observation-only checkpoint certificate and observation binding.
    DepositObservationIndexCheckpointCertificate,
    /// Fetch settled compact-registry/archive and portable-index checkpoint heads.
    SyncHead,
    /// Fetch one page from a finite, root-connected immutable object manifest.
    SyncObjects,
    /// Release one exact durable historical-root lease after requester-side retirement.
    SyncRelease,
    /// Start one ordinary current-committee moving-tip prefix scan with the full bounded witness.
    PrefixSupportStart,
    /// Advance one persisted fixed-anchor scan without retransmitting its terminal checkpoint.
    PrefixSupportContinue,
    /// Propose one source-specific state-export seal after the registry handoff is certified.
    PostHandoffExportSealRequest,
    /// Contribute one predecessor-quorum vote to an exact state-export seal.
    PostHandoffExportSealVote,
    /// Disseminate one certified predecessor-quorum state-export seal.
    PostHandoffExportSealCertificate,
    /// Fetch a certified predecessor's immutable export head.
    ExportHead,
    /// Fetch one page from a certified predecessor export manifest.
    ExportObjects,
    /// Release one exact certified predecessor export lease.
    ExportRelease,
    /// Deliver one target-member acknowledgement of a completely imported semantic state.
    StateImportedAck,
    /// Disseminate the exact target-quorum state-imported certificate.
    StateImportedCertificate,
    /// Coordinator-free, durable Byzantine consolidation orchestration.
    Consolidation,
    /// Authenticated member gossip for one client allocation request.
    ClientRequest,
    /// Permanent, quorum-observed closure of a consolidation attempt invalidated by a reorg.
    ConsolidationAbandonment,
    /// A portable consensus proposal. This remains distinct so a vote cannot block the proposal
    /// needed to initialize a lagging receiver's reducer.
    ConsensusProposal,
    /// Portable prevote, precommit, and view-change envelopes.
    ConsensusMessage,
    /// Portable view-change and commit certificates.
    ConsensusCertificate,
}

impl DepositOperation {
    /// Global causal order used by both encrypted outbox enumeration and the QUIC relay.
    #[must_use]
    pub const fn causal_priority(self) -> u8 {
        match self {
            Self::ClientRequest => 0,
            Self::ConsolidationAbandonment => 1,
            Self::ConsensusProposal => 2,
            Self::ConsensusMessage => 3,
            Self::ConsensusCertificate => 4,
            // Consolidation intent consensus/certification must precede the portable ledger
            // completion it eventually authorizes. The Byzantine body carries its own finer
            // causal phase and exact delivery identifier.
            Self::Consolidation => 5,
            Self::Attest => 7,
            Self::Certificate => 8,
            Self::DepositObservation => 9,
            Self::DepositObservationAttest => 10,
            Self::DepositObservationCertificate => 11,
            Self::IndexCheckpointAttest | Self::DepositObservationIndexCheckpointAttest => 12,
            Self::IndexCheckpointCertificate
            | Self::DepositObservationIndexCheckpointCertificate => 13,
            Self::SyncHead
            | Self::SyncObjects
            | Self::SyncRelease
            | Self::PrefixSupportStart
            | Self::PrefixSupportContinue => 14,
            Self::PostHandoffExportSealRequest => 15,
            Self::PostHandoffExportSealVote => 16,
            Self::PostHandoffExportSealCertificate => 17,
            Self::ExportHead | Self::ExportObjects | Self::ExportRelease => 18,
            Self::StateImportedAck => 19,
            Self::StateImportedCertificate => 20,
        }
    }
}

/// Opaque protocol request carried by the authenticated transport.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PeerRequest {
    Avss { operation: AvssOperation, body: Vec<u8> },
    Qual { operation: QualOperation, body: Vec<u8> },
    Epoch { operation: EpochOperation, body: Vec<u8> },
    Deposit { operation: DepositOperation, body: Vec<u8> },
    KeyRotation { operation: KeyRotationOperation, body: Vec<u8> },
}

impl PeerRequest {
    /// Build a correctly routed, canonically encoded key-rotation request.
    pub fn key_rotation(wire: &KeyRotationWire) -> Result<Self, QuicTransportError> {
        let operation = KeyRotationOperation::for_wire(wire);
        Ok(Self::KeyRotation { operation, body: operation.encode_wire(wire)? })
    }

    fn body_len(&self) -> usize {
        match self {
            Self::Avss { body, .. }
            | Self::Qual { body, .. }
            | Self::Epoch { body, .. }
            | Self::Deposit { body, .. }
            | Self::KeyRotation { body, .. } => body.len(),
        }
    }

    fn route(&self) -> PeerRequestRoute {
        match self {
            Self::Avss { operation, .. } => PeerRequestRoute::Avss(*operation),
            Self::Qual { operation, .. } => PeerRequestRoute::Qual(*operation),
            Self::Epoch { operation, .. } => PeerRequestRoute::Epoch(*operation),
            Self::Deposit { operation, .. } => PeerRequestRoute::Deposit(*operation),
            Self::KeyRotation { operation, .. } => PeerRequestRoute::KeyRotation(*operation),
        }
    }

    fn into_body(self) -> Vec<u8> {
        match self {
            Self::Avss { body, .. }
            | Self::Qual { body, .. }
            | Self::Epoch { body, .. }
            | Self::Deposit { body, .. }
            | Self::KeyRotation { body, .. } => body,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum PeerRequestRoute {
    Avss(AvssOperation),
    Qual(QualOperation),
    Epoch(EpochOperation),
    Deposit(DepositOperation),
    KeyRotation(KeyRotationOperation),
}

impl PeerRequestRoute {
    fn with_body(self, body: Vec<u8>) -> PeerRequest {
        match self {
            Self::Avss(operation) => PeerRequest::Avss { operation, body },
            Self::Qual(operation) => PeerRequest::Qual { operation, body },
            Self::Epoch(operation) => PeerRequest::Epoch { operation, body },
            Self::Deposit(operation) => PeerRequest::Deposit { operation, body },
            Self::KeyRotation(operation) => PeerRequest::KeyRotation { operation, body },
        }
    }

    fn maximum_body_bytes(self, config: QuicTransportConfig) -> usize {
        match self {
            Self::KeyRotation(operation) => config.max_body_bytes.min(operation.max_body_bytes()),
            Self::Deposit(DepositOperation::PrefixSupportStart) => {
                config.max_body_bytes.min(MAX_DEPOSIT_PREFIX_SUPPORT_START_WIRE_BYTES)
            }
            Self::Deposit(DepositOperation::PrefixSupportContinue) => {
                config.max_body_bytes.min(MAX_DEPOSIT_PREFIX_SUPPORT_CONTINUE_WIRE_BYTES)
            }
            Self::Deposit(DepositOperation::SyncHead) => {
                config.max_body_bytes.min(MAX_DEPOSIT_SYNC_HEAD_REQUEST_BYTES)
            }
            Self::Deposit(DepositOperation::SyncRelease) => {
                config.max_body_bytes.min(MAX_DEPOSIT_SYNC_RELEASE_REQUEST_BYTES)
            }
            Self::Deposit(DepositOperation::PostHandoffExportSealRequest) => {
                config.max_body_bytes.min(MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_BYTES)
            }
            Self::Deposit(DepositOperation::PostHandoffExportSealVote) => {
                config.max_body_bytes.min(MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES)
            }
            Self::Deposit(DepositOperation::PostHandoffExportSealCertificate) => {
                config.max_body_bytes.min(MAX_POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_DELIVERY_BYTES)
            }
            Self::Deposit(DepositOperation::ExportHead) => {
                config.max_body_bytes.min(MAX_DEPOSIT_STATE_EXPORT_HEAD_REQUEST_BYTES)
            }
            Self::Deposit(DepositOperation::ExportObjects) => {
                config.max_body_bytes.min(MAX_DEPOSIT_STATE_EXPORT_OBJECTS_REQUEST_BYTES)
            }
            Self::Deposit(DepositOperation::ExportRelease) => {
                config.max_body_bytes.min(MAX_DEPOSIT_STATE_EXPORT_RELEASE_REQUEST_BYTES)
            }
            Self::Deposit(DepositOperation::StateImportedAck) => {
                config.max_body_bytes.min(MAX_DEPOSIT_STATE_IMPORTED_ACK_DELIVERY_BYTES)
            }
            Self::Deposit(DepositOperation::StateImportedCertificate) => {
                config.max_body_bytes.min(MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_DELIVERY_BYTES)
            }
            Self::Avss(_) | Self::Qual(_) | Self::Epoch(_) | Self::Deposit(_) => {
                config.max_body_bytes
            }
        }
    }

    fn is_deposit_sync_objects(self) -> bool {
        matches!(self, Self::Deposit(DepositOperation::SyncObjects))
    }

    fn is_deposit_export_objects(self) -> bool {
        matches!(self, Self::Deposit(DepositOperation::ExportObjects))
    }

    fn is_deposit_object_read(self) -> bool {
        self.is_deposit_sync_objects() || self.is_deposit_export_objects()
    }

    fn is_deposit_prefix_support_scan(self) -> bool {
        matches!(
            self,
            Self::Deposit(
                DepositOperation::PrefixSupportStart | DepositOperation::PrefixSupportContinue
            )
        )
    }

    fn is_deposit_sync_control(self) -> bool {
        matches!(self, Self::Deposit(DepositOperation::SyncHead | DepositOperation::SyncRelease))
    }

    fn is_deposit_sync_state_read(self) -> bool {
        matches!(
            self,
            Self::Deposit(
                DepositOperation::SyncHead
                    | DepositOperation::SyncObjects
                    | DepositOperation::PrefixSupportStart
                    | DepositOperation::PrefixSupportContinue
            )
        )
    }

    fn deposit_operation(self) -> Option<DepositOperation> {
        match self {
            Self::Deposit(operation) => Some(operation),
            Self::Avss(_) | Self::Qual(_) | Self::Epoch(_) | Self::KeyRotation(_) => None,
        }
    }
}

/// Protocol-independent rejection categories. Detailed protocol errors remain opaque strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RejectionCode {
    InvalidRequest,
    Unauthorized,
    Conflict,
    ResourceExhausted,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PeerResponse {
    Success { body: Vec<u8> },
    Rejected { code: RejectionCode, retryable: bool, message: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RequestPrelude {
    version: u16,
    network_id: [u8; 32],
    request_id: RequestId,
    from: PartyId,
    to: PartyId,
    route: PeerRequestRoute,
    body_len: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum RequestAdmission {
    Accepted,
    Rejected(PeerResponse),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RequestAdmissionFrame {
    version: u16,
    network_id: [u8; 32],
    request_id: RequestId,
    from: PartyId,
    to: PartyId,
    admission: RequestAdmission,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ResponseFrame {
    version: u16,
    network_id: [u8; 32],
    request_id: RequestId,
    from: PartyId,
    to: PartyId,
    response: PeerResponse,
}

/// Per-endpoint transport limits. All values are checked against non-configurable hard caps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicTransportConfig {
    pub max_body_bytes: usize,
    pub max_frame_bytes: usize,
    pub max_concurrent_bidi_streams: u32,
    pub handshake_timeout: Duration,
    pub stream_timeout: Duration,
    pub idle_timeout: Duration,
    pub keep_alive_interval: Option<Duration>,
}

impl Default for QuicTransportConfig {
    fn default() -> Self {
        Self {
            // A canonical consolidation intent or nested rotation view certificate may approach
            // the independent 8 MiB body cap. Reserve one additional MiB for the authenticated
            // outer frame and reduce stream concurrency so an endpoint cannot reserve an
            // unbounded receive window.
            max_body_bytes: HARD_MAX_BODY_BYTES,
            max_frame_bytes: 9 * 1024 * 1024,
            max_concurrent_bidi_streams: 8,
            handshake_timeout: Duration::from_secs(5),
            stream_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            keep_alive_interval: Some(Duration::from_secs(10)),
        }
    }
}

impl QuicTransportConfig {
    pub fn validate(self) -> Result<Self, QuicTransportError> {
        if self.max_body_bytes == 0
            || self.max_frame_bytes <= LENGTH_PREFIX_BYTES
            || self.max_body_bytes > self.max_frame_bytes
            || self.max_body_bytes > HARD_MAX_BODY_BYTES
            || self.max_frame_bytes > HARD_MAX_FRAME_BYTES
        {
            return Err(QuicTransportError::InvalidConfiguration(
                "size limits must satisfy 0 < body <= frame, with hard maxima of 8 MiB and 16 MiB",
            ));
        }
        if self.max_concurrent_bidi_streams == 0
            || self.max_concurrent_bidi_streams > HARD_MAX_CONCURRENT_STREAMS
        {
            return Err(QuicTransportError::InvalidConfiguration(
                "max_concurrent_bidi_streams must be in 1..=256",
            ));
        }
        if self
            .max_frame_bytes
            .checked_mul(self.max_concurrent_bidi_streams as usize)
            .is_none_or(|bytes| bytes > HARD_MAX_IN_FLIGHT_FRAME_BYTES)
        {
            return Err(QuicTransportError::InvalidConfiguration(
                "frame size times concurrent streams must not exceed 128 MiB",
            ));
        }
        for timeout in [self.handshake_timeout, self.stream_timeout, self.idle_timeout] {
            if timeout.is_zero() || timeout > MAX_CONFIGURED_TIMEOUT {
                return Err(QuicTransportError::InvalidConfiguration(
                    "handshake, stream, and idle timeouts must be in 1ns..=120s",
                ));
            }
        }
        if self.keep_alive_interval.is_some_and(|interval| {
            interval.is_zero() || interval >= self.idle_timeout || interval > MAX_CONFIGURED_TIMEOUT
        }) {
            return Err(QuicTransportError::InvalidConfiguration(
                "keep-alive must be nonzero and strictly less than the idle timeout",
            ));
        }
        Ok(self)
    }
}

/// Local certificate chain and corresponding private key.
///
/// Certificates must be suitable for both TLS server and client authentication. The first
/// certificate is the exact leaf certificate peers pin to this party.
pub struct LocalTlsIdentity {
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl LocalTlsIdentity {
    pub fn new(
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, QuicTransportError> {
        if certificate_chain.is_empty() {
            return Err(QuicTransportError::InvalidConfiguration(
                "the local TLS certificate chain cannot be empty",
            ));
        }
        Ok(Self { certificate_chain, private_key })
    }
}

/// Exact certificate pin and TLS DNS name for one peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedPeerCertificate {
    pub party: PartyId,
    pub server_name: String,
    pub leaf_certificate: CertificateDer<'static>,
}

#[derive(Debug, Error)]
pub enum QuicTransportError {
    #[error("invalid QUIC transport configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("duplicate pinned party {0}")]
    DuplicateParty(PartyId),
    #[error("one TLS certificate is pinned to multiple parties")]
    DuplicateCertificate,
    #[error("party {0} has no pinned TLS certificate")]
    UnknownPeer(PartyId),
    #[error("TLS configuration failed: {0}")]
    TlsConfiguration(String),
    #[error("QUIC endpoint I/O failed: {0}")]
    Endpoint(#[from] io::Error),
    #[error("QUIC connection setup failed: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("QUIC handshake or connection failed: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("QUIC stream write failed: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("QUIC stream finish failed: {0}")]
    Finish(#[from] quinn::ClosedStream),
    #[error("QUIC stream read failed: {0}")]
    Read(#[from] quinn::ReadExactError),
    #[error("QUIC stream had trailing bytes or failed before EOF: {0}")]
    ReadToEnd(#[from] quinn::ReadToEndError),
    #[error("{operation} timed out")]
    Timeout { operation: &'static str },
    #[error("peer did not present a TLS certificate")]
    MissingPeerCertificate,
    #[error("peer presented an unsupported TLS identity type")]
    UnsupportedPeerIdentity,
    #[error("peer TLS certificate is not pinned")]
    UnpinnedPeerCertificate,
    #[error("peer TLS certificate is pinned to party {actual}, expected {expected}")]
    WrongPeerCertificate { expected: PartyId, actual: PartyId },
    #[error("protocol body is {actual} bytes; maximum is {maximum}")]
    BodyTooLarge { actual: usize, maximum: usize },
    #[error("encoded frame is {actual} bytes; maximum is {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },
    #[error("frame serialization failed: {0}")]
    Serialization(#[source] postcard::Error),
    #[error("frame deserialization failed: {0}")]
    Deserialization(#[source] postcard::Error),
    #[error("key-rotation body serialization failed: {0}")]
    KeyRotationSerialization(#[source] postcard::Error),
    #[error("key-rotation body deserialization failed: {0}")]
    KeyRotationDeserialization(#[source] postcard::Error),
    #[error("frame encoding has {0} trailing bytes")]
    TrailingFrameBytes(usize),
    #[error("frame is not encoded using canonical postcard bytes")]
    NonCanonicalFrame,
    #[error("key-rotation body encoding has {0} trailing bytes")]
    TrailingKeyRotationBodyBytes(usize),
    #[error("key-rotation body is not encoded using canonical postcard bytes")]
    NonCanonicalKeyRotationBody,
    #[error("key-rotation body encodes operation {encoded:?}, but was routed as {routed:?}")]
    WrongKeyRotationOperation { routed: KeyRotationOperation, encoded: KeyRotationOperation },
    #[error("unsupported QUIC frame version {0}")]
    UnsupportedVersion(u16),
    #[error("frame is bound to another network or configuration")]
    WrongNetwork,
    #[error("authenticated frame sender is {actual}, expected {expected}")]
    WrongSender { expected: PartyId, actual: PartyId },
    #[error("frame recipient is {actual}, expected {expected}")]
    WrongRecipient { expected: PartyId, actual: PartyId },
    #[error("request ID differs from the canonical authenticated route and body")]
    WrongRequestId,
    #[error("a pre-body request admission may contain only Accepted or a rejected response")]
    InvalidRequestAdmission,
    #[error("rejection message is {actual} bytes; maximum is {maximum}")]
    RejectionMessageTooLarge { actual: usize, maximum: usize },
    #[error("QUIC endpoint is closed")]
    EndpointClosed,
}

impl QuicTransportError {
    /// Whether this request failure proves the shared multiplexed QUIC connection was lost.
    ///
    /// Stream resets, per-stream timeouts, and authenticated framing errors are local to one
    /// request. Evicting the cached connection for those failures tears down unrelated healthy
    /// streams and can turn one slow reducer into a reconnect storm.
    pub(crate) fn is_connection_lost(&self) -> bool {
        matches!(
            self,
            Self::Connection(_)
                | Self::Write(quinn::WriteError::ConnectionLost(_))
                | Self::Read(quinn::ReadExactError::ReadError(quinn::ReadError::ConnectionLost(_)))
                | Self::ReadToEnd(quinn::ReadToEndError::Read(quinn::ReadError::ConnectionLost(_)))
        )
    }
}

struct PeerTlsConfig {
    server_name: String,
    client_config: quinn::ClientConfig,
}

/// Bound QUIC endpoint which can accept and initiate mutually authenticated peer connections.
pub struct QuicPeerEndpoint {
    endpoint: Endpoint,
    local_party: PartyId,
    network_id: [u8; 32],
    config: QuicTransportConfig,
    pins_by_certificate: Arc<BTreeMap<Vec<u8>, PartyId>>,
    peer_tls: BTreeMap<PartyId, PeerTlsConfig>,
}

impl std::fmt::Debug for QuicPeerEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuicPeerEndpoint")
            .field("local_party", &self.local_party)
            .field("local_addr", &self.endpoint.local_addr().ok())
            .field("pinned_peers", &self.peer_tls.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl QuicPeerEndpoint {
    pub fn bind(
        local_addr: SocketAddr,
        local_party: PartyId,
        network_id: [u8; 32],
        local_identity: LocalTlsIdentity,
        peers: impl IntoIterator<Item = PinnedPeerCertificate>,
        config: QuicTransportConfig,
    ) -> Result<Self, QuicTransportError> {
        let config = config.validate()?;
        if local_party.0 == 0 {
            return Err(QuicTransportError::InvalidConfiguration(
                "the local party identifier must be nonzero",
            ));
        }
        if network_id == [0; 32] {
            return Err(QuicTransportError::InvalidConfiguration(
                "the network/configuration identifier must be nonzero",
            ));
        }
        let peers = peers.into_iter().collect::<Vec<_>>();
        if peers.is_empty() {
            return Err(QuicTransportError::InvalidConfiguration(
                "at least one mutually authenticated peer certificate is required",
            ));
        }

        let mut parties = BTreeSet::new();
        let mut pins_by_certificate = BTreeMap::new();
        let local_leaf = local_identity
            .certificate_chain
            .first()
            .expect("LocalTlsIdentity construction rejects an empty chain")
            .as_ref();
        for peer in &peers {
            if peer.party.0 == 0 {
                return Err(QuicTransportError::InvalidConfiguration(
                    "peer party identifiers must be nonzero",
                ));
            }
            if peer.party == local_party {
                return Err(QuicTransportError::InvalidConfiguration(
                    "the local party cannot be configured as its own peer",
                ));
            }
            if peer.leaf_certificate.as_ref() == local_leaf {
                return Err(QuicTransportError::InvalidConfiguration(
                    "the local TLS certificate cannot also identify a peer",
                ));
            }
            if !parties.insert(peer.party) {
                return Err(QuicTransportError::DuplicateParty(peer.party));
            }
            if pins_by_certificate
                .insert(peer.leaf_certificate.as_ref().to_vec(), peer.party)
                .is_some()
            {
                return Err(QuicTransportError::DuplicateCertificate);
            }
        }

        let transport = make_transport_config(config)?;
        let mut client_roots = RootCertStore::empty();
        for peer in &peers {
            client_roots
                .add(peer.leaf_certificate.clone())
                .map_err(|error| QuicTransportError::TlsConfiguration(error.to_string()))?;
        }
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|error| QuicTransportError::TlsConfiguration(error.to_string()))?;
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                local_identity.certificate_chain.clone(),
                local_identity.private_key.clone_key(),
            )
            .map_err(|error| QuicTransportError::TlsConfiguration(error.to_string()))?;
        server_crypto.alpn_protocols = vec![ALPN.to_vec()];
        // Require a fresh, fully authenticated TLS 1.3 handshake for every connection. Keeping
        // these values explicit prevents a future rustls default change from enabling replayable
        // 0-RTT data or server 0.5-RTT data before client authentication completes.
        server_crypto.max_early_data_size = 0;
        server_crypto.send_half_rtt_data = false;
        server_crypto.send_tls13_tickets = 0;
        let server_crypto = QuicServerConfig::try_from(server_crypto)
            .map_err(|error| QuicTransportError::TlsConfiguration(error.to_string()))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        server_config.transport_config(transport.clone());
        let endpoint = Endpoint::server(server_config, local_addr)?;

        let mut peer_tls = BTreeMap::new();
        for peer in peers {
            let mut roots = RootCertStore::empty();
            roots
                .add(peer.leaf_certificate)
                .map_err(|error| QuicTransportError::TlsConfiguration(error.to_string()))?;
            let mut client_crypto = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_client_auth_cert(
                    local_identity.certificate_chain.clone(),
                    local_identity.private_key.clone_key(),
                )
                .map_err(|error| QuicTransportError::TlsConfiguration(error.to_string()))?;
            client_crypto.alpn_protocols = vec![ALPN.to_vec()];
            client_crypto.enable_early_data = false;
            client_crypto.resumption = rustls::client::Resumption::disabled();
            let client_crypto = QuicClientConfig::try_from(client_crypto)
                .map_err(|error| QuicTransportError::TlsConfiguration(error.to_string()))?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
            client_config.transport_config(transport.clone());
            peer_tls
                .insert(peer.party, PeerTlsConfig { server_name: peer.server_name, client_config });
        }

        Ok(Self {
            endpoint,
            local_party,
            network_id,
            config,
            pins_by_certificate: Arc::new(pins_by_certificate),
            peer_tls,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, QuicTransportError> {
        Ok(self.endpoint.local_addr()?)
    }

    pub fn local_party(&self) -> PartyId {
        self.local_party
    }

    /// Trust-domain identifier bound into every request and response frame.
    pub fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    /// Establish a fresh authenticated connection. The returned connection may carry many
    /// concurrent request streams and can be cached by a higher-level durable peer manager.
    pub async fn connect(
        &self,
        peer: PartyId,
        remote_addr: SocketAddr,
    ) -> Result<AuthenticatedPeerConnection, QuicTransportError> {
        let tls = self.peer_tls.get(&peer).ok_or(QuicTransportError::UnknownPeer(peer))?;
        let connecting =
            self.endpoint.connect_with(tls.client_config.clone(), remote_addr, &tls.server_name)?;
        let connection =
            timeout(self.config.handshake_timeout, "QUIC client handshake", connecting).await??;
        authenticate_connection(
            connection,
            self.local_party,
            self.network_id,
            Some(peer),
            self.pins_by_certificate.clone(),
            self.config,
        )
    }

    /// Accept one authenticated connection. Waiting for a new connection is deliberately not
    /// timed out; only a handshake which has begun consumes the bounded handshake interval.
    pub async fn accept(&self) -> Result<AuthenticatedPeerConnection, QuicTransportError> {
        let incoming = self.endpoint.accept().await.ok_or(QuicTransportError::EndpointClosed)?;
        let connecting = incoming.accept()?;
        let connection =
            timeout(self.config.handshake_timeout, "QUIC server handshake", connecting).await??;
        authenticate_connection(
            connection,
            self.local_party,
            self.network_id,
            None,
            self.pins_by_certificate.clone(),
            self.config,
        )
    }

    pub fn close(&self, reason: &[u8]) {
        self.endpoint.close(VarInt::from_u32(0), reason);
    }

    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }
}

/// Reusable connection whose peer identity has been matched to an exact configured certificate.
#[derive(Clone)]
pub struct AuthenticatedPeerConnection {
    connection: quinn::Connection,
    local_party: PartyId,
    peer_party: PartyId,
    network_id: [u8; 32],
    config: QuicTransportConfig,
}

/// Locally observed transport phase which produced one authenticated response.
///
/// This is not encoded on the wire and therefore cannot be forged by the peer. A pre-body
/// rejection proves the current attempt was never dispatched. Once the body was admitted, cache
/// and reducer responses intentionally share one conservative class: an untrusted peer-controlled
/// rejection cannot prove that an earlier ambiguous execution did not commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuicResponseProvenance {
    RejectedBeforeBody,
    AfterBody,
}

pub(crate) struct QuicRequestOutcome {
    response: PeerResponse,
    provenance: QuicResponseProvenance,
}

impl QuicRequestOutcome {
    pub(crate) fn into_parts(self) -> (PeerResponse, QuicResponseProvenance) {
        (self.response, self.provenance)
    }
}

impl std::fmt::Debug for AuthenticatedPeerConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedPeerConnection")
            .field("local_party", &self.local_party)
            .field("peer_party", &self.peer_party)
            .field("remote_address", &self.connection.remote_address())
            .finish_non_exhaustive()
    }
}

impl AuthenticatedPeerConnection {
    pub fn peer_party(&self) -> PartyId {
        self.peer_party
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Send one correlated request over a new bidirectional stream.
    pub async fn request(
        &self,
        request_id: RequestId,
        request: PeerRequest,
    ) -> Result<PeerResponse, QuicTransportError> {
        self.request_with_timeout(request_id, request, self.config.stream_timeout).await
    }

    /// Send one correlated request with a caller-selected total RPC deadline.
    ///
    /// The runtime uses its protocol-class deadline here because the response cannot arrive until
    /// the remote durable reducer finishes. Capping that wait at the transport's shorter
    /// slow-stream timeout made the runtime's configured deadline ineffective and caused exact
    /// AVSS retries to pile up behind an honestly executing request. Direct transport callers keep
    /// the ordinary `stream_timeout` through [`Self::request`].
    pub(crate) async fn request_with_timeout(
        &self,
        request_id: RequestId,
        request: PeerRequest,
        request_timeout: Duration,
    ) -> Result<PeerResponse, QuicTransportError> {
        Ok(self.request_with_timeout_outcome(request_id, request, request_timeout).await?.response)
    }

    pub(crate) async fn request_with_timeout_outcome(
        &self,
        request_id: RequestId,
        request: PeerRequest,
        request_timeout: Duration,
    ) -> Result<QuicRequestOutcome, QuicTransportError> {
        validate_request(&request, self.config)?;
        if request_id
            != RequestId::for_peer_request(
                self.network_id,
                self.local_party,
                self.peer_party,
                &request,
            )?
        {
            return Err(QuicTransportError::WrongRequestId);
        }
        let route = request.route();
        let body_len =
            u32::try_from(request.body_len()).map_err(|_| QuicTransportError::BodyTooLarge {
                actual: request.body_len(),
                maximum: self.config.max_body_bytes,
            })?;
        let prelude = RequestPrelude {
            version: WIRE_VERSION,
            network_id: self.network_id,
            request_id,
            from: self.local_party,
            to: self.peer_party,
            route,
            body_len,
        };
        let body = request.into_body();
        let operation = async {
            let (mut send, mut receive) = self.connection.open_bi().await?;
            write_frame_bounded(&mut send, &prelude, MAX_REQUEST_PRELUDE_FRAME_BYTES).await?;
            let admission: RequestAdmissionFrame =
                read_frame_bounded(&mut receive, MAX_REQUEST_ADMISSION_FRAME_BYTES).await?;
            validate_request_admission_frame(
                &admission,
                request_id,
                self.network_id,
                self.peer_party,
                self.local_party,
                self.config,
            )?;
            if let RequestAdmission::Rejected(response) = admission.admission {
                let _ = send.reset(VarInt::from_u32(0));
                require_eof(&mut receive).await?;
                return Ok(QuicRequestOutcome {
                    response,
                    provenance: QuicResponseProvenance::RejectedBeforeBody,
                });
            }
            write_request_body_with_deadlines(&mut send, &body, self.config).await?;
            send.finish()?;
            let response: ResponseFrame = read_frame(&mut receive, self.config).await?;
            require_eof(&mut receive).await?;
            validate_response_frame(
                &response,
                request_id,
                self.network_id,
                self.peer_party,
                self.local_party,
                self.config,
            )?;
            Ok(QuicRequestOutcome {
                response: response.response,
                provenance: QuicResponseProvenance::AfterBody,
            })
        };
        timeout(request_timeout, "QUIC request stream", operation).await?
    }

    /// Accept and authenticate the bounded request prelude on the next stream.
    ///
    /// No request body is transmitted by a conforming peer until the caller invokes
    /// [`IncomingPeerRequestPrelude::read_request`]. A Byzantine peer which transmits early is
    /// constrained by the transport's small initial stream and connection receive windows.
    pub async fn accept_request(&self) -> Result<IncomingPeerRequestPrelude, QuicTransportError> {
        let (send, mut receive) = self.connection.accept_bi().await?;
        let operation = async {
            let prelude: RequestPrelude =
                read_frame_bounded(&mut receive, MAX_REQUEST_PRELUDE_FRAME_BYTES).await?;
            validate_request_prelude(
                &prelude,
                self.peer_party,
                self.local_party,
                self.network_id,
                self.config,
            )?;
            Ok::<RequestPrelude, QuicTransportError>(prelude)
        };
        let prelude =
            timeout(self.config.stream_timeout, "QUIC inbound request", operation).await??;
        Ok(IncomingPeerRequestPrelude { prelude, send, receive, config: self.config })
    }

    pub fn close(&self, reason: &[u8]) {
        self.connection.close(VarInt::from_u32(0), reason);
    }
}

/// Authenticated, size-bounded request metadata whose body has not been admitted or decoded.
pub struct IncomingPeerRequestPrelude {
    prelude: RequestPrelude,
    send: quinn::SendStream,
    receive: quinn::RecvStream,
    config: QuicTransportConfig,
}

impl std::fmt::Debug for IncomingPeerRequestPrelude {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IncomingPeerRequestPrelude")
            .field("request_id", &self.prelude.request_id)
            .field("from", &self.prelude.from)
            .field("to", &self.prelude.to)
            .field("route", &self.prelude.route)
            .field("body_len", &self.prelude.body_len)
            .finish_non_exhaustive()
    }
}

impl IncomingPeerRequestPrelude {
    pub fn request_id(&self) -> RequestId {
        self.prelude.request_id
    }

    pub fn peer_party(&self) -> PartyId {
        self.prelude.from
    }

    pub fn is_deposit_sync_objects(&self) -> bool {
        self.prelude.route.is_deposit_sync_objects()
    }

    /// Whether this is an ordinary or certified-export immutable object-page read.
    pub fn is_deposit_object_read(&self) -> bool {
        self.prelude.route.is_deposit_object_read()
    }

    /// Whether this request advances one persisted ordinary prefix-support scan.
    pub fn is_deposit_prefix_support_scan(&self) -> bool {
        self.prelude.route.is_deposit_prefix_support_scan()
    }

    /// Whether this is one of the small, authenticated Head/Release control messages.
    pub fn is_deposit_sync_control(&self) -> bool {
        self.prelude.route.is_deposit_sync_control()
    }

    /// Whether this prelude may read a current compact-state lease or object page. Callers use
    /// this before admitting the body so removed committee members cannot allocate or transmit a
    /// sync body merely to discover that their current-state authority expired.
    pub fn is_deposit_sync_state_read(&self) -> bool {
        self.prelude.route.is_deposit_sync_state_read()
    }

    /// Return the authenticated deposit route before admitting its body.
    ///
    /// This projection carries no protocol authority. It lets the runtime apply cheap
    /// committee-history admission before allocating large post-handoff request bodies; the
    /// typed reducer must still authenticate every exact transition and wire binding.
    pub fn deposit_operation(&self) -> Option<DepositOperation> {
        self.prelude.route.deposit_operation()
    }

    pub fn body_len(&self) -> usize {
        self.prelude.body_len as usize
    }

    /// Admit this request, notify the sender, then read its exact bounded body.
    pub async fn read_request(mut self) -> Result<IncomingPeerRequest, QuicTransportError> {
        let admission = self.admission_frame(RequestAdmission::Accepted);
        write_frame_bounded(&mut self.send, &admission, MAX_REQUEST_ADMISSION_FRAME_BYTES).await?;
        let body = read_request_body_with_deadlines(
            &mut self.receive,
            self.prelude.body_len as usize,
            self.config,
        )
        .await?;
        let request = self.prelude.route.with_body(body);
        validate_request(&request, self.config)?;
        if self.prelude.request_id
            != RequestId::for_peer_request(
                self.prelude.network_id,
                self.prelude.from,
                self.prelude.to,
                &request,
            )?
        {
            return Err(QuicTransportError::WrongRequestId);
        }
        Ok(IncomingPeerRequest {
            prelude: self.prelude,
            request,
            send: self.send,
            config: self.config,
        })
    }

    /// Reject a request before its body is transmitted or allocated.
    pub async fn reject_before_body(
        mut self,
        response: PeerResponse,
    ) -> Result<(), QuicTransportError> {
        if !matches!(response, PeerResponse::Rejected { .. }) {
            return Err(QuicTransportError::InvalidRequestAdmission);
        }
        validate_response(&response, self.config)?;
        let admission = self.admission_frame(RequestAdmission::Rejected(response));
        self.receive.stop(VarInt::from_u32(0))?;
        write_frame_bounded(&mut self.send, &admission, MAX_REQUEST_ADMISSION_FRAME_BYTES).await?;
        self.send.finish()?;
        Ok(())
    }

    fn admission_frame(&self, admission: RequestAdmission) -> RequestAdmissionFrame {
        RequestAdmissionFrame {
            version: WIRE_VERSION,
            network_id: self.prelude.network_id,
            request_id: self.prelude.request_id,
            from: self.prelude.to,
            to: self.prelude.from,
            admission,
        }
    }
}

/// Authenticated inbound request retaining the response half of its QUIC stream.
pub struct IncomingPeerRequest {
    prelude: RequestPrelude,
    request: PeerRequest,
    send: quinn::SendStream,
    config: QuicTransportConfig,
}

impl std::fmt::Debug for IncomingPeerRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IncomingPeerRequest")
            .field("request_id", &self.prelude.request_id)
            .field("from", &self.prelude.from)
            .field("to", &self.prelude.to)
            .field("route", &self.request.route())
            .field("body_len", &self.request.body_len())
            .finish_non_exhaustive()
    }
}

impl IncomingPeerRequest {
    pub fn request_id(&self) -> RequestId {
        self.prelude.request_id
    }

    pub fn peer_party(&self) -> PartyId {
        self.prelude.from
    }

    pub fn request(&self) -> &PeerRequest {
        &self.request
    }

    pub fn into_request(self) -> PeerRequest {
        self.request
    }

    /// Move the potentially large request body out without cloning it while retaining the
    /// authenticated response half of this stream.
    pub(crate) fn into_request_and_responder(self) -> (PeerRequest, IncomingPeerRequestResponder) {
        let Self { prelude, request, send, config } = self;
        (request, IncomingPeerRequestResponder { prelude, send, config })
    }

    pub async fn respond(self, response: PeerResponse) -> Result<(), QuicTransportError> {
        let (_, responder) = self.into_request_and_responder();
        responder.respond(response).await
    }
}

/// Authenticated response half retained after moving an inbound request body into its reducer.
pub(crate) struct IncomingPeerRequestResponder {
    prelude: RequestPrelude,
    send: quinn::SendStream,
    config: QuicTransportConfig,
}

impl IncomingPeerRequestResponder {
    pub(crate) async fn respond(
        mut self,
        response: PeerResponse,
    ) -> Result<(), QuicTransportError> {
        validate_response(&response, self.config)?;
        let frame = ResponseFrame {
            version: WIRE_VERSION,
            network_id: self.prelude.network_id,
            request_id: self.prelude.request_id,
            from: self.prelude.to,
            to: self.prelude.from,
            response,
        };
        let operation = async {
            write_frame(&mut self.send, &frame, self.config).await?;
            self.send.finish()?;
            Ok(())
        };
        timeout(self.config.stream_timeout, "QUIC response stream", operation).await?
    }
}

fn authenticate_connection(
    connection: quinn::Connection,
    local_party: PartyId,
    network_id: [u8; 32],
    expected_peer: Option<PartyId>,
    pins_by_certificate: Arc<BTreeMap<Vec<u8>, PartyId>>,
    config: QuicTransportConfig,
) -> Result<AuthenticatedPeerConnection, QuicTransportError> {
    let identity = connection.peer_identity().ok_or(QuicTransportError::MissingPeerCertificate)?;
    let certificates = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| QuicTransportError::UnsupportedPeerIdentity)?;
    let leaf = certificates.first().ok_or(QuicTransportError::MissingPeerCertificate)?;
    let peer_party = pins_by_certificate
        .get(leaf.as_ref())
        .copied()
        .ok_or(QuicTransportError::UnpinnedPeerCertificate)?;
    if let Some(expected) = expected_peer
        && peer_party != expected
    {
        return Err(QuicTransportError::WrongPeerCertificate { expected, actual: peer_party });
    }
    Ok(AuthenticatedPeerConnection { connection, local_party, peer_party, network_id, config })
}

fn make_transport_config(
    config: QuicTransportConfig,
) -> Result<Arc<quinn::TransportConfig>, QuicTransportError> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(config.max_concurrent_bidi_streams));
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    // The protocol uses only reliable bidirectional streams. Do not advertise or allocate the
    // default QUIC datagram buffers for a second, unhandled ingress path.
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    let initial_stream_window = u32::try_from(INITIAL_STREAM_RECEIVE_WINDOW_BYTES)
        .map_err(|_| QuicTransportError::InvalidConfiguration("stream window exceeds u32"))?;
    transport.stream_receive_window(VarInt::from_u32(initial_stream_window));
    let stream_count = usize::try_from(config.max_concurrent_bidi_streams).map_err(|_| {
        QuicTransportError::InvalidConfiguration(
            "stream concurrency does not fit the platform address space",
        )
    })?;
    let connection_window_bytes = INITIAL_STREAM_RECEIVE_WINDOW_BYTES
        .checked_mul(stream_count)
        .and_then(|window| u64::try_from(window).ok())
        .ok_or(QuicTransportError::InvalidConfiguration(
            "stream window and concurrency limits overflow the QUIC receive window",
        ))?;
    let connection_window = VarInt::from_u64(connection_window_bytes).map_err(|_| {
        QuicTransportError::InvalidConfiguration(
            "stream window and concurrency limits overflow the QUIC receive window",
        )
    })?;
    // Validation keeps this aggregate window between one 64 KiB stream and 16 MiB (64 KiB times
    // the hard 256-stream ceiling). Use the same checked aggregate as the local send window: a
    // peer that stops extending flow-control credit cannot make us queue an entire 8 MiB request
    // locally, while healthy streams still share one window proportional to configured
    // multiplexing.
    transport.receive_window(connection_window);
    transport.send_window(connection_window_bytes);
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(config.idle_timeout)
            .map_err(|error| QuicTransportError::TlsConfiguration(error.to_string()))?,
    ));
    transport.keep_alive_interval(config.keep_alive_interval);
    Ok(Arc::new(transport))
}

async fn write_frame<T: Serialize>(
    send: &mut quinn::SendStream,
    frame: &T,
    config: QuicTransportConfig,
) -> Result<(), QuicTransportError> {
    write_frame_bounded(send, frame, config.max_frame_bytes).await
}

async fn write_frame_bounded<T: Serialize>(
    send: &mut quinn::SendStream,
    frame: &T,
    maximum: usize,
) -> Result<(), QuicTransportError> {
    let encoded = postcard::to_allocvec(frame).map_err(QuicTransportError::Serialization)?;
    if encoded.len() > maximum {
        return Err(QuicTransportError::FrameTooLarge { actual: encoded.len(), maximum });
    }
    let length = u32::try_from(encoded.len())
        .map_err(|_| QuicTransportError::FrameTooLarge { actual: encoded.len(), maximum })?;
    send.write_all(&length.to_be_bytes()).await?;
    send.write_all(&encoded).await?;
    Ok(())
}

async fn read_frame<T: for<'de> Deserialize<'de> + Serialize>(
    receive: &mut quinn::RecvStream,
    config: QuicTransportConfig,
) -> Result<T, QuicTransportError> {
    read_frame_bounded(receive, config.max_frame_bytes).await
}

async fn read_frame_bounded<T: for<'de> Deserialize<'de> + Serialize>(
    receive: &mut quinn::RecvStream,
    maximum: usize,
) -> Result<T, QuicTransportError> {
    let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
    receive.read_exact(&mut prefix).await?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > maximum {
        return Err(QuicTransportError::FrameTooLarge { actual: length, maximum });
    }
    let mut encoded = vec![0_u8; length];
    receive.read_exact(&mut encoded).await?;
    let (frame, remaining) =
        postcard::take_from_bytes(&encoded).map_err(QuicTransportError::Deserialization)?;
    if !remaining.is_empty() {
        return Err(QuicTransportError::TrailingFrameBytes(remaining.len()));
    }
    // Postcard's decoder accepts some semantically equivalent non-minimal varints. Requiring the
    // decoded value to serialize to the exact received bytes gives every authenticated message a
    // single wire representation, which is important when higher layers hash or deduplicate it.
    let canonical = postcard::to_allocvec(&frame).map_err(QuicTransportError::Serialization)?;
    if canonical != encoded {
        return Err(QuicTransportError::NonCanonicalFrame);
    }
    Ok(frame)
}

fn request_body_transfer_timeout(body_len: usize, idle_timeout: Duration) -> Duration {
    let transfer_nanos = u128::try_from(body_len)
        .expect("usize always fits in u128")
        .saturating_mul(1_000_000_000)
        .div_ceil(
            u128::try_from(MIN_REQUEST_BODY_BYTES_PER_SECOND).expect("usize always fits in u128"),
        );
    let transfer_nanos = u64::try_from(transfer_nanos).unwrap_or(u64::MAX);
    idle_timeout
        .saturating_add(Duration::from_nanos(transfer_nanos))
        .min(MAX_REQUEST_BODY_TRANSFER_TIMEOUT)
}

async fn write_request_body_with_deadlines(
    send: &mut quinn::SendStream,
    body: &[u8],
    config: QuicTransportConfig,
) -> Result<(), QuicTransportError> {
    if body.is_empty() {
        return Ok(());
    }
    let total_timeout = request_body_transfer_timeout(body.len(), config.stream_timeout);
    let mut total_deadline = Box::pin(time::sleep(total_timeout));
    let mut idle_deadline = Box::pin(time::sleep(config.stream_timeout));
    let mut written = 0_usize;
    while written < body.len() {
        let progress = tokio::select! {
            biased;
            () = &mut total_deadline => {
                return Err(QuicTransportError::Timeout {
                    operation: "QUIC outbound request body total",
                });
            }
            () = &mut idle_deadline => {
                return Err(QuicTransportError::Timeout {
                    operation: "QUIC outbound request body idle",
                });
            }
            result = send.write(&body[written..]) => result?,
        };
        if progress == 0 {
            // Quinn documents a successful nonempty write as making progress. Keep the timers
            // armed if that invariant ever changes instead of granting a fresh idle interval.
            continue;
        }
        written += progress;
        idle_deadline.as_mut().reset(time::Instant::now() + config.stream_timeout);
    }
    Ok(())
}

async fn read_request_body_with_deadlines(
    receive: &mut quinn::RecvStream,
    body_len: usize,
    config: QuicTransportConfig,
) -> Result<Vec<u8>, QuicTransportError> {
    let total_timeout = request_body_transfer_timeout(body_len, config.stream_timeout);
    let mut total_deadline = Box::pin(time::sleep(total_timeout));
    let mut idle_deadline = Box::pin(time::sleep(config.stream_timeout));
    let mut body = vec![0_u8; body_len];
    let mut trailing = [0_u8; 1];
    let mut read = 0_usize;
    loop {
        let checking_eof = read == body.len();
        let buffer = if checking_eof { &mut trailing[..] } else { &mut body[read..] };
        let progress = tokio::select! {
            biased;
            () = &mut total_deadline => {
                return Err(QuicTransportError::Timeout {
                    operation: "QUIC inbound request body total",
                });
            }
            () = &mut idle_deadline => {
                return Err(QuicTransportError::Timeout {
                    operation: "QUIC inbound request body idle",
                });
            }
            result = receive.read(buffer) => result,
        };
        let progress = match progress {
            Ok(progress) => progress,
            Err(error) if checking_eof => {
                return Err(QuicTransportError::ReadToEnd(quinn::ReadToEndError::Read(error)));
            }
            Err(error) => {
                return Err(QuicTransportError::Read(quinn::ReadExactError::ReadError(error)));
            }
        };
        let Some(progress) = progress else {
            if checking_eof {
                return Ok(body);
            }
            return Err(QuicTransportError::Read(quinn::ReadExactError::FinishedEarly(read)));
        };
        if checking_eof {
            return Err(QuicTransportError::ReadToEnd(quinn::ReadToEndError::TooLong));
        }
        if progress == 0 {
            continue;
        }
        read += progress;
        idle_deadline.as_mut().reset(time::Instant::now() + config.stream_timeout);
    }
}

async fn require_eof(receive: &mut quinn::RecvStream) -> Result<(), QuicTransportError> {
    let trailing = receive.read_to_end(0).await?;
    debug_assert!(trailing.is_empty());
    Ok(())
}

fn validate_request(
    request: &PeerRequest,
    config: QuicTransportConfig,
) -> Result<(), QuicTransportError> {
    let actual = request.body_len();
    let maximum = request.route().maximum_body_bytes(config);
    if actual > maximum {
        return Err(QuicTransportError::BodyTooLarge { actual, maximum });
    }
    if let PeerRequest::KeyRotation { operation, body } = request {
        drop(operation.decode_wire(body)?);
    }
    Ok(())
}

fn validate_response(
    response: &PeerResponse,
    config: QuicTransportConfig,
) -> Result<(), QuicTransportError> {
    match response {
        PeerResponse::Success { body } if body.len() > config.max_body_bytes => {
            Err(QuicTransportError::BodyTooLarge {
                actual: body.len(),
                maximum: config.max_body_bytes,
            })
        }
        PeerResponse::Rejected { message, .. }
            if message.len() > HARD_MAX_REJECTION_MESSAGE_BYTES =>
        {
            Err(QuicTransportError::RejectionMessageTooLarge {
                actual: message.len(),
                maximum: HARD_MAX_REJECTION_MESSAGE_BYTES,
            })
        }
        _ => Ok(()),
    }
}

fn validate_request_prelude(
    prelude: &RequestPrelude,
    authenticated_peer: PartyId,
    local_party: PartyId,
    network_id: [u8; 32],
    config: QuicTransportConfig,
) -> Result<(), QuicTransportError> {
    if prelude.version != WIRE_VERSION {
        return Err(QuicTransportError::UnsupportedVersion(prelude.version));
    }
    if prelude.network_id != network_id {
        return Err(QuicTransportError::WrongNetwork);
    }
    if prelude.from != authenticated_peer {
        return Err(QuicTransportError::WrongSender {
            expected: authenticated_peer,
            actual: prelude.from,
        });
    }
    if prelude.to != local_party {
        return Err(QuicTransportError::WrongRecipient {
            expected: local_party,
            actual: prelude.to,
        });
    }
    let actual = prelude.body_len as usize;
    let maximum = prelude.route.maximum_body_bytes(config);
    if actual > maximum {
        return Err(QuicTransportError::BodyTooLarge { actual, maximum });
    }
    Ok(())
}

fn validate_request_admission_frame(
    frame: &RequestAdmissionFrame,
    request_id: RequestId,
    network_id: [u8; 32],
    authenticated_peer: PartyId,
    local_party: PartyId,
    config: QuicTransportConfig,
) -> Result<(), QuicTransportError> {
    if frame.version != WIRE_VERSION {
        return Err(QuicTransportError::UnsupportedVersion(frame.version));
    }
    if frame.network_id != network_id {
        return Err(QuicTransportError::WrongNetwork);
    }
    if frame.request_id != request_id {
        return Err(QuicTransportError::WrongRequestId);
    }
    if frame.from != authenticated_peer {
        return Err(QuicTransportError::WrongSender {
            expected: authenticated_peer,
            actual: frame.from,
        });
    }
    if frame.to != local_party {
        return Err(QuicTransportError::WrongRecipient { expected: local_party, actual: frame.to });
    }
    if let RequestAdmission::Rejected(response) = &frame.admission {
        if !matches!(response, PeerResponse::Rejected { .. }) {
            return Err(QuicTransportError::InvalidRequestAdmission);
        }
        validate_response(response, config)?;
    }
    Ok(())
}

fn validate_response_frame(
    frame: &ResponseFrame,
    request_id: RequestId,
    network_id: [u8; 32],
    authenticated_peer: PartyId,
    local_party: PartyId,
    config: QuicTransportConfig,
) -> Result<(), QuicTransportError> {
    if frame.version != WIRE_VERSION {
        return Err(QuicTransportError::UnsupportedVersion(frame.version));
    }
    if frame.network_id != network_id {
        return Err(QuicTransportError::WrongNetwork);
    }
    if frame.request_id != request_id {
        return Err(QuicTransportError::WrongRequestId);
    }
    if frame.from != authenticated_peer {
        return Err(QuicTransportError::WrongSender {
            expected: authenticated_peer,
            actual: frame.from,
        });
    }
    if frame.to != local_party {
        return Err(QuicTransportError::WrongRecipient { expected: local_party, actual: frame.to });
    }
    validate_response(&frame.response, config)
}

async fn timeout<T>(
    duration: Duration,
    operation: &'static str,
    future: impl Future<Output = T>,
) -> Result<T, QuicTransportError> {
    time::timeout(duration, future).await.map_err(|_| QuicTransportError::Timeout { operation })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    const TEST_NETWORK: [u8; 32] = [0x42; 32];

    struct TestIdentity {
        server_name: String,
        certificate: CertificateDer<'static>,
        private_key: Vec<u8>,
    }

    impl TestIdentity {
        fn generate(party: PartyId) -> Self {
            let server_name = format!("party-{}.threshold-monero.invalid", party.0);
            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(vec![server_name.clone()]).unwrap();
            Self {
                server_name,
                certificate: cert.der().clone(),
                private_key: signing_key.serialize_der(),
            }
        }

        fn local(&self) -> LocalTlsIdentity {
            LocalTlsIdentity::new(
                vec![self.certificate.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_key.clone())),
            )
            .unwrap()
        }

        fn pin(&self, party: PartyId) -> PinnedPeerCertificate {
            PinnedPeerCertificate {
                party,
                server_name: self.server_name.clone(),
                leaf_certificate: self.certificate.clone(),
            }
        }
    }

    fn loopback_config() -> QuicTransportConfig {
        QuicTransportConfig {
            max_body_bytes: 64,
            max_frame_bytes: 256,
            handshake_timeout: Duration::from_secs(3),
            stream_timeout: Duration::from_secs(3),
            idle_timeout: Duration::from_secs(10),
            keep_alive_interval: Some(Duration::from_secs(1)),
            ..Default::default()
        }
    }

    fn key_rotation_envelope(payload_len: usize) -> crate::identity::SignedEnvelope {
        crate::identity::SignedEnvelope {
            version: 1,
            committee: [0x51; 32],
            epoch: 4,
            session: crate::committee::SessionId([0x52; 32]),
            from: PartyId(1),
            to: None,
            sequence: 7,
            payload: vec![0x53; payload_len],
            signature: [0x54; 64],
        }
    }

    fn materialized_request_id(
        network_id: [u8; 32],
        from: PartyId,
        to: PartyId,
        request: &PeerRequest,
    ) -> RequestId {
        let encoded = postcard::to_allocvec(request).unwrap();
        let mut material = Vec::with_capacity(12 + encoded.len());
        material.extend_from_slice(&from.0.to_le_bytes());
        material.extend_from_slice(&to.0.to_le_bytes());
        material.extend_from_slice(&u64::try_from(encoded.len()).unwrap().to_le_bytes());
        material.extend_from_slice(&encoded);
        RequestId::derive(network_id, b"canonical-authenticated-peer-request/v8", &material)
    }

    #[test]
    fn request_ids_are_domain_separated() {
        let first = RequestId::derive(TEST_NETWORK, b"avss", b"same material");
        let second = RequestId::derive(TEST_NETWORK, b"qual", b"same material");
        let other_network = RequestId::derive([0x43; 32], b"avss", b"same material");
        assert_ne!(first, second);
        assert_ne!(first, other_network);
        assert_eq!(RequestId::from_bytes(first.to_bytes()), first);
    }

    #[test]
    fn streaming_request_ids_equal_the_reference_materialized_derivation() {
        let requests = [
            PeerRequest::Avss { operation: AvssOperation::Deliver, body: vec![] },
            PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![0x11] },
            PeerRequest::Epoch { operation: EpochOperation::History, body: vec![0x22; 127] },
            PeerRequest::Deposit {
                operation: DepositOperation::DepositObservation,
                body: vec![0x33; 128],
            },
            PeerRequest::Deposit {
                operation: DepositOperation::Consolidation,
                body: vec![0x44; 16_384],
            },
            PeerRequest::KeyRotation {
                operation: KeyRotationOperation::ViewCertificate,
                body: vec![0x55; 52_591],
            },
        ];
        for request in requests {
            assert_eq!(
                RequestId::for_peer_request(TEST_NETWORK, PartyId(9), PartyId(10), &request,)
                    .unwrap(),
                materialized_request_id(TEST_NETWORK, PartyId(9), PartyId(10), &request),
            );
        }
    }

    #[test]
    fn current_transport_contract_is_v8_and_request_ids_do_not_alias_v7() {
        assert_eq!(WIRE_VERSION, 8);
        assert_eq!(ALPN, b"threshold-monero-peer/8");

        let from = PartyId(1);
        let to = PartyId(2);
        let request = PeerRequest::Deposit {
            operation: DepositOperation::DepositObservation,
            body: vec![8; 52_591],
        };
        let encoded = postcard::to_allocvec(&request).unwrap();
        let mut material = Vec::with_capacity(12 + encoded.len());
        material.extend_from_slice(&from.0.to_le_bytes());
        material.extend_from_slice(&to.0.to_le_bytes());
        material.extend_from_slice(&u64::try_from(encoded.len()).unwrap().to_le_bytes());
        material.extend_from_slice(&encoded);

        let current = RequestId::for_peer_request(TEST_NETWORK, from, to, &request).unwrap();
        assert_eq!(
            current,
            RequestId::derive(TEST_NETWORK, b"canonical-authenticated-peer-request/v8", &material,)
        );
        assert_ne!(
            current,
            RequestId::derive(TEST_NETWORK, b"canonical-authenticated-peer-request/v7", &material,)
        );
    }

    #[test]
    fn sync_control_routes_have_exact_pre_body_caps_and_distinct_authority() {
        let config = QuicTransportConfig::default();
        let head = PeerRequestRoute::Deposit(DepositOperation::SyncHead);
        let release = PeerRequestRoute::Deposit(DepositOperation::SyncRelease);
        assert!(head.is_deposit_sync_control());
        assert!(release.is_deposit_sync_control());
        assert!(head.is_deposit_sync_state_read());
        assert!(
            !release.is_deposit_sync_state_read(),
            "the exact lease MAC, not current-committee membership, authorizes release",
        );

        for (operation, maximum) in [
            (DepositOperation::SyncHead, MAX_DEPOSIT_SYNC_HEAD_REQUEST_BYTES),
            (DepositOperation::SyncRelease, MAX_DEPOSIT_SYNC_RELEASE_REQUEST_BYTES),
        ] {
            let route = PeerRequestRoute::Deposit(operation);
            assert_eq!(route.maximum_body_bytes(config), maximum);

            let request = PeerRequest::Deposit { operation, body: vec![0x5a; maximum] };
            validate_request(&request, config).unwrap();
            let mut prelude = RequestPrelude {
                version: WIRE_VERSION,
                network_id: TEST_NETWORK,
                request_id: RequestId::for_peer_request(
                    TEST_NETWORK,
                    PartyId(1),
                    PartyId(2),
                    &request,
                )
                .unwrap(),
                from: PartyId(1),
                to: PartyId(2),
                route,
                body_len: u32::try_from(maximum).unwrap(),
            };
            validate_request_prelude(&prelude, PartyId(1), PartyId(2), TEST_NETWORK, config)
                .unwrap();

            prelude.body_len = u32::try_from(maximum + 1).unwrap();
            assert!(matches!(
                validate_request_prelude(
                    &prelude,
                    PartyId(1),
                    PartyId(2),
                    TEST_NETWORK,
                    config,
                ),
                Err(QuicTransportError::BodyTooLarge { actual, maximum: rejected_maximum })
                    if actual == maximum + 1 && rejected_maximum == maximum
            ));

            let oversized = PeerRequest::Deposit { operation, body: vec![0; maximum + 1] };
            assert!(matches!(
                validate_request(&oversized, config),
                Err(QuicTransportError::BodyTooLarge { actual, maximum: rejected_maximum })
                    if actual == maximum + 1 && rejected_maximum == maximum
            ));
        }
    }

    #[test]
    fn v8_reserves_distinct_typed_prefix_and_handoff_routes_with_exact_caps() {
        let routes = [
            DepositOperation::PrefixSupportStart,
            DepositOperation::PrefixSupportContinue,
            DepositOperation::PostHandoffExportSealRequest,
            DepositOperation::PostHandoffExportSealVote,
            DepositOperation::PostHandoffExportSealCertificate,
            DepositOperation::ExportHead,
            DepositOperation::ExportObjects,
            DepositOperation::ExportRelease,
            DepositOperation::StateImportedAck,
            DepositOperation::StateImportedCertificate,
        ];
        let tags = routes
            .into_iter()
            .map(|route| postcard::to_allocvec(&route).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(tags.len(), routes.len());

        let start = PeerRequestRoute::Deposit(DepositOperation::PrefixSupportStart);
        let continuation = PeerRequestRoute::Deposit(DepositOperation::PrefixSupportContinue);
        let export_objects = PeerRequestRoute::Deposit(DepositOperation::ExportObjects);
        assert!(start.is_deposit_prefix_support_scan());
        assert!(continuation.is_deposit_prefix_support_scan());
        assert!(start.is_deposit_sync_state_read());
        assert!(continuation.is_deposit_sync_state_read());
        assert!(export_objects.is_deposit_object_read());
        assert!(!export_objects.is_deposit_sync_objects());
        assert!(!export_objects.is_deposit_sync_state_read());

        let config = QuicTransportConfig::default();
        assert_eq!(start.maximum_body_bytes(config), MAX_DEPOSIT_PREFIX_SUPPORT_START_WIRE_BYTES);
        assert_eq!(
            continuation.maximum_body_bytes(config),
            MAX_DEPOSIT_PREFIX_SUPPORT_CONTINUE_WIRE_BYTES
        );
        for (operation, expected) in [
            (
                DepositOperation::PostHandoffExportSealRequest,
                MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_BYTES,
            ),
            (DepositOperation::PostHandoffExportSealVote, MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES),
            (
                DepositOperation::PostHandoffExportSealCertificate,
                MAX_POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_DELIVERY_BYTES,
            ),
            (DepositOperation::ExportHead, MAX_DEPOSIT_STATE_EXPORT_HEAD_REQUEST_BYTES),
            (DepositOperation::ExportObjects, MAX_DEPOSIT_STATE_EXPORT_OBJECTS_REQUEST_BYTES),
            (DepositOperation::ExportRelease, MAX_DEPOSIT_STATE_EXPORT_RELEASE_REQUEST_BYTES),
            (DepositOperation::StateImportedAck, MAX_DEPOSIT_STATE_IMPORTED_ACK_DELIVERY_BYTES),
            (
                DepositOperation::StateImportedCertificate,
                MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_DELIVERY_BYTES,
            ),
        ] {
            assert_eq!(
                PeerRequestRoute::Deposit(operation).maximum_body_bytes(config),
                expected,
                "{operation:?} must use its typed v8 decoder limit",
            );
            assert!(expected <= HARD_MAX_BODY_BYTES);
        }
        assert!(
            MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_BYTES
                > MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_BYTES,
            "the typed request cap must include its candidate plus authenticated request framing"
        );

        assert!(
            DepositOperation::PostHandoffExportSealRequest.causal_priority()
                < DepositOperation::PostHandoffExportSealVote.causal_priority()
        );
        assert!(
            DepositOperation::PostHandoffExportSealVote.causal_priority()
                < DepositOperation::PostHandoffExportSealCertificate.causal_priority()
        );
        assert!(
            DepositOperation::PostHandoffExportSealCertificate.causal_priority()
                < DepositOperation::ExportHead.causal_priority()
        );
        assert!(
            DepositOperation::ExportRelease.causal_priority()
                < DepositOperation::StateImportedCertificate.causal_priority()
        );

        let attempt =
            crate::deposit_sync_support::DepositSyncPrefixSupportAttempt::from_bytes([0x71; 32])
                .unwrap();
        let first_body =
            crate::deposit_sync_support::DepositSyncPrefixSupportContinue::new(attempt, 1)
                .unwrap()
                .to_bytes()
                .unwrap();
        let next_body =
            crate::deposit_sync_support::DepositSyncPrefixSupportContinue::new(attempt, 2)
                .unwrap()
                .to_bytes()
                .unwrap();
        let first = PeerRequest::Deposit {
            operation: DepositOperation::PrefixSupportContinue,
            body: first_body,
        };
        let next = PeerRequest::Deposit {
            operation: DepositOperation::PrefixSupportContinue,
            body: next_body,
        };
        assert_ne!(
            RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &first).unwrap(),
            RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &next).unwrap(),
            "each persisted scan revision must bypass the prior Pending response-cache entry"
        );
    }

    #[test]
    fn only_connection_loss_errors_invalidate_a_multiplexed_connection() {
        let stream_timeout = QuicTransportError::Timeout { operation: "QUIC request stream" };
        let stream_reset = QuicTransportError::Read(quinn::ReadExactError::ReadError(
            quinn::ReadError::Reset(VarInt::from_u32(7)),
        ));
        let connection_loss = QuicTransportError::Connection(quinn::ConnectionError::LocallyClosed);
        let nested_connection_loss = QuicTransportError::Write(quinn::WriteError::ConnectionLost(
            quinn::ConnectionError::Reset,
        ));

        assert!(!stream_timeout.is_connection_lost());
        assert!(!stream_reset.is_connection_lost());
        assert!(connection_loss.is_connection_lost());
        assert!(nested_connection_loss.is_connection_lost());
    }

    #[test]
    fn canonical_request_ids_bind_network_route_operation_and_body() {
        let request = PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![0x11] };
        let id =
            RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &request).unwrap();
        assert_eq!(
            id,
            RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &request).unwrap()
        );
        assert_ne!(
            id,
            RequestId::for_peer_request([0x43; 32], PartyId(1), PartyId(2), &request).unwrap()
        );
        assert_ne!(
            id,
            RequestId::for_peer_request(TEST_NETWORK, PartyId(3), PartyId(2), &request).unwrap()
        );
        assert_ne!(
            id,
            RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(3), &request).unwrap()
        );
        assert_ne!(
            id,
            RequestId::for_peer_request(
                TEST_NETWORK,
                PartyId(1),
                PartyId(2),
                &PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![0x22] },
            )
            .unwrap()
        );
    }

    #[test]
    fn observation_routes_have_distinct_canonical_tags_priorities_and_body_binding() {
        let routes = [
            DepositOperation::IndexCheckpointAttest,
            DepositOperation::IndexCheckpointCertificate,
            DepositOperation::DepositObservation,
            DepositOperation::DepositObservationAttest,
            DepositOperation::DepositObservationCertificate,
            DepositOperation::DepositObservationIndexCheckpointAttest,
            DepositOperation::DepositObservationIndexCheckpointCertificate,
        ];
        let tags = routes
            .into_iter()
            .map(|route| postcard::to_allocvec(&route).unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(tags.len(), routes.len());
        for route in routes {
            assert_eq!(
                postcard::from_bytes::<DepositOperation>(&postcard::to_allocvec(&route).unwrap())
                    .unwrap(),
                route
            );
        }
        assert_eq!(DepositOperation::DepositObservation.causal_priority(), 9);
        assert_eq!(DepositOperation::DepositObservationAttest.causal_priority(), 10);
        assert_eq!(DepositOperation::DepositObservationCertificate.causal_priority(), 11);
        assert_eq!(
            DepositOperation::DepositObservationIndexCheckpointAttest.causal_priority(),
            DepositOperation::IndexCheckpointAttest.causal_priority()
        );
        assert_eq!(
            DepositOperation::DepositObservationIndexCheckpointCertificate.causal_priority(),
            DepositOperation::IndexCheckpointCertificate.causal_priority()
        );
        assert!(
            DepositOperation::DepositObservationCertificate.causal_priority()
                < DepositOperation::DepositObservationIndexCheckpointAttest.causal_priority()
        );

        let body = vec![0x5a, 0xa5];
        let request_ids = [
            DepositOperation::DepositObservation,
            DepositOperation::DepositObservationAttest,
            DepositOperation::DepositObservationCertificate,
        ]
        .map(|operation| {
            RequestId::for_peer_request(
                TEST_NETWORK,
                PartyId(1),
                PartyId(2),
                &PeerRequest::Deposit { operation, body: body.clone() },
            )
            .unwrap()
        });
        assert_eq!(
            request_ids.into_iter().collect::<std::collections::BTreeSet<_>>().len(),
            request_ids.len()
        );
        for (operation, request_id) in [
            DepositOperation::DepositObservation,
            DepositOperation::DepositObservationAttest,
            DepositOperation::DepositObservationCertificate,
        ]
        .into_iter()
        .zip(request_ids)
        {
            assert_ne!(
                request_id,
                RequestId::for_peer_request(
                    TEST_NETWORK,
                    PartyId(1),
                    PartyId(2),
                    &PeerRequest::Deposit { operation, body: vec![0x5a, 0xa4] },
                )
                .unwrap()
            );
        }

        let config = loopback_config();
        for operation in [
            DepositOperation::DepositObservation,
            DepositOperation::DepositObservationAttest,
            DepositOperation::DepositObservationCertificate,
            DepositOperation::DepositObservationIndexCheckpointAttest,
            DepositOperation::DepositObservationIndexCheckpointCertificate,
        ] {
            assert!(matches!(
                validate_request(
                    &PeerRequest::Deposit {
                        operation,
                        body: vec![0; config.max_body_bytes + 1],
                    },
                    config,
                ),
                Err(QuicTransportError::BodyTooLarge { actual, maximum })
                    if actual == config.max_body_bytes + 1 && maximum == config.max_body_bytes
            ));
        }
    }

    #[test]
    fn key_rotation_routes_are_causally_ordered_and_independently_bounded() {
        assert_eq!(KeyRotationOperation::Advertisement.causal_priority(), 0);
        assert_eq!(KeyRotationOperation::FallbackVote.causal_priority(), 1);
        assert_eq!(KeyRotationOperation::Consensus.causal_priority(), 2);
        assert_eq!(KeyRotationOperation::ViewCertificate.causal_priority(), 3);
        assert_eq!(KeyRotationOperation::Certificate.causal_priority(), 4);

        assert_eq!(
            KeyRotationOperation::Advertisement.max_body_bytes(),
            MAX_KEY_ROTATION_ADVERTISEMENT_WIRE_BYTES
        );
        assert_eq!(
            KeyRotationOperation::FallbackVote.max_body_bytes(),
            MAX_KEY_ROTATION_FALLBACK_VOTE_WIRE_BYTES
        );
        assert_eq!(
            KeyRotationOperation::Consensus.max_body_bytes(),
            MAX_KEY_ROTATION_CONSENSUS_WIRE_BYTES
        );
        assert_eq!(
            KeyRotationOperation::ViewCertificate.max_body_bytes(),
            MAX_KEY_ROTATION_VIEW_CERTIFICATE_WIRE_BYTES
        );
        assert_eq!(
            KeyRotationOperation::Certificate.max_body_bytes(),
            MAX_KEY_ROTATION_CERTIFICATE_WIRE_BYTES
        );
        assert!(MAX_KEY_ROTATION_ADVERTISEMENT_WIRE_BYTES < HARD_MAX_BODY_BYTES);
        assert!(MAX_KEY_ROTATION_FALLBACK_VOTE_WIRE_BYTES < HARD_MAX_BODY_BYTES);
        assert!(MAX_KEY_ROTATION_CONSENSUS_WIRE_BYTES < HARD_MAX_BODY_BYTES);
        assert_eq!(MAX_KEY_ROTATION_VIEW_CERTIFICATE_WIRE_BYTES, HARD_MAX_BODY_BYTES);
        assert!(MAX_KEY_ROTATION_CERTIFICATE_WIRE_BYTES < HARD_MAX_BODY_BYTES);
    }

    #[test]
    fn key_rotation_bodies_are_canonical_and_bound_to_the_outer_route() {
        let wire = KeyRotationWire::Advertisement(key_rotation_envelope(32));
        let request = PeerRequest::key_rotation(&wire).unwrap();
        let PeerRequest::KeyRotation { operation, body } = request else {
            panic!("key-rotation constructor returned another request family");
        };
        assert_eq!(operation, KeyRotationOperation::Advertisement);
        assert_eq!(operation.decode_wire(&body).unwrap(), wire);
        validate_request(
            &PeerRequest::KeyRotation { operation, body: body.clone() },
            QuicTransportConfig::default(),
        )
        .unwrap();

        assert!(matches!(
            KeyRotationOperation::Consensus.decode_wire(&body),
            Err(QuicTransportError::WrongKeyRotationOperation {
                routed: KeyRotationOperation::Consensus,
                encoded: KeyRotationOperation::Advertisement,
            })
        ));
        assert!(matches!(
            KeyRotationOperation::Consensus.encode_wire(&wire),
            Err(QuicTransportError::WrongKeyRotationOperation { .. })
        ));

        let fallback = KeyRotationWire::FallbackVote(key_rotation_envelope(32));
        let fallback_request = PeerRequest::key_rotation(&fallback).unwrap();
        let PeerRequest::KeyRotation { operation: fallback_operation, body: fallback_body } =
            fallback_request
        else {
            panic!("key-rotation constructor returned another request family");
        };
        assert_eq!(fallback_operation, KeyRotationOperation::FallbackVote);
        assert_eq!(fallback_operation.decode_wire(&fallback_body).unwrap(), fallback);
        assert!(matches!(
            KeyRotationOperation::Advertisement.decode_wire(&fallback_body),
            Err(QuicTransportError::WrongKeyRotationOperation {
                routed: KeyRotationOperation::Advertisement,
                encoded: KeyRotationOperation::FallbackVote,
            })
        ));

        let mut trailing = body.clone();
        trailing.push(0xff);
        assert!(matches!(
            operation.decode_wire(&trailing),
            Err(QuicTransportError::TrailingKeyRotationBodyBytes(1))
        ));

        // Postcard accepts the overlong enum discriminant `0x80 0x00` as zero. Inner protocol
        // bytes remain opaque to the outer frame codec, so the operation decoder must reject this
        // second representation explicitly.
        assert_eq!(body[0], 0);
        let mut noncanonical = body;
        noncanonical[0] = 0x80;
        noncanonical.insert(1, 0);
        assert!(matches!(
            operation.decode_wire(&noncanonical),
            Err(QuicTransportError::NonCanonicalKeyRotationBody)
        ));
    }

    #[test]
    fn key_rotation_operation_caps_precede_the_endpoint_body_cap() {
        let wire = KeyRotationWire::Advertisement(key_rotation_envelope(
            MAX_KEY_ROTATION_ADVERTISEMENT_WIRE_BYTES,
        ));
        assert!(matches!(
            KeyRotationOperation::Advertisement.encode_wire(&wire),
            Err(QuicTransportError::BodyTooLarge { maximum, .. })
                if maximum == MAX_KEY_ROTATION_ADVERTISEMENT_WIRE_BYTES
        ));

        let body = postcard::to_allocvec(&wire).unwrap();
        let request =
            PeerRequest::KeyRotation { operation: KeyRotationOperation::Advertisement, body };
        assert!(matches!(
            validate_request(&request, QuicTransportConfig::default()),
            Err(QuicTransportError::BodyTooLarge { maximum, .. })
                if maximum == MAX_KEY_ROTATION_ADVERTISEMENT_WIRE_BYTES
        ));
    }

    #[test]
    fn limits_reject_oversized_bodies_and_error_messages() {
        let config = QuicTransportConfig { max_body_bytes: 4, ..Default::default() };
        let request = PeerRequest::Avss { operation: AvssOperation::Deliver, body: vec![0; 5] };
        assert!(matches!(
            validate_request(&request, config),
            Err(QuicTransportError::BodyTooLarge { actual: 5, maximum: 4 })
        ));

        let response = PeerResponse::Rejected {
            code: RejectionCode::InvalidRequest,
            retryable: false,
            message: "x".repeat(HARD_MAX_REJECTION_MESSAGE_BYTES + 1),
        };
        assert!(matches!(
            validate_response(&response, config),
            Err(QuicTransportError::RejectionMessageTooLarge { .. })
        ));

        let excessive_in_flight = QuicTransportConfig {
            max_body_bytes: HARD_MAX_BODY_BYTES,
            max_frame_bytes: HARD_MAX_FRAME_BYTES,
            max_concurrent_bidi_streams: HARD_MAX_CONCURRENT_STREAMS,
            ..Default::default()
        };
        assert!(matches!(
            excessive_in_flight.validate(),
            Err(QuicTransportError::InvalidConfiguration(
                "frame size times concurrent streams must not exceed 128 MiB"
            ))
        ));

        let ineffective_keep_alive = QuicTransportConfig {
            idle_timeout: Duration::from_secs(10),
            keep_alive_interval: Some(Duration::from_secs(10)),
            ..Default::default()
        };
        assert!(matches!(
            ineffective_keep_alive.validate(),
            Err(QuicTransportError::InvalidConfiguration(
                "keep-alive must be nonzero and strictly less than the idle timeout"
            ))
        ));
    }

    #[test]
    fn default_limits_fit_an_exact_eight_mebibyte_consolidation_body_safely() {
        let config = QuicTransportConfig::default().validate().unwrap();
        assert_eq!(config.max_body_bytes, HARD_MAX_BODY_BYTES);
        assert!(
            config.max_frame_bytes * config.max_concurrent_bidi_streams as usize
                <= HARD_MAX_IN_FLIGHT_FRAME_BYTES
        );

        let request = PeerRequest::Deposit {
            operation: DepositOperation::Consolidation,
            body: vec![0x5a; config.max_body_bytes],
        };
        validate_request(&request, config).unwrap();
        let prelude = RequestPrelude {
            version: WIRE_VERSION,
            network_id: TEST_NETWORK,
            request_id: RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &request)
                .unwrap(),
            from: PartyId(1),
            to: PartyId(2),
            route: request.route(),
            body_len: u32::try_from(request.body_len()).unwrap(),
        };
        assert!(postcard::to_allocvec(&prelude).unwrap().len() <= MAX_REQUEST_PRELUDE_FRAME_BYTES);
        assert!(
            INITIAL_STREAM_RECEIVE_WINDOW_BYTES * (config.max_concurrent_bidi_streams as usize)
                < config.max_frame_bytes * config.max_concurrent_bidi_streams as usize
        );

        let oversized = PeerRequest::Deposit {
            operation: DepositOperation::Consolidation,
            body: vec![0; config.max_body_bytes + 1],
        };
        assert!(matches!(
            validate_request(&oversized, config),
            Err(QuicTransportError::BodyTooLarge { actual, maximum })
                if actual == config.max_body_bytes + 1 && maximum == config.max_body_bytes
        ));
    }

    #[test]
    fn authenticated_party_route_and_admission_are_bound_to_preludes() {
        let config = QuicTransportConfig::default();
        let body = PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![] };
        let request = RequestPrelude {
            version: WIRE_VERSION,
            network_id: TEST_NETWORK,
            request_id: RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &body)
                .unwrap(),
            from: PartyId(1),
            to: PartyId(2),
            route: body.route(),
            body_len: u32::try_from(body.body_len()).unwrap(),
        };
        validate_request_prelude(&request, PartyId(1), PartyId(2), TEST_NETWORK, config).unwrap();
        let mut equivocation = request.clone();
        equivocation.body_len = u32::try_from(config.max_body_bytes + 1).unwrap();
        assert!(matches!(
            validate_request_prelude(&equivocation, PartyId(1), PartyId(2), TEST_NETWORK, config,),
            Err(QuicTransportError::BodyTooLarge { .. })
        ));
        assert!(matches!(
            validate_request_prelude(&request, PartyId(3), PartyId(2), TEST_NETWORK, config),
            Err(QuicTransportError::WrongSender { .. })
        ));
        assert!(matches!(
            validate_request_prelude(&request, PartyId(1), PartyId(2), [0x44; 32], config),
            Err(QuicTransportError::WrongNetwork)
        ));
        assert!(matches!(
            validate_request_prelude(&request, PartyId(1), PartyId(3), TEST_NETWORK, config),
            Err(QuicTransportError::WrongRecipient { .. })
        ));

        let response = RequestAdmissionFrame {
            version: WIRE_VERSION,
            network_id: TEST_NETWORK,
            request_id: RequestId::from_bytes([2; 32]),
            from: PartyId(2),
            to: PartyId(1),
            admission: RequestAdmission::Accepted,
        };
        assert!(matches!(
            validate_request_admission_frame(
                &response,
                RequestId::from_bytes([3; 32]),
                TEST_NETWORK,
                PartyId(2),
                PartyId(1),
                config,
            ),
            Err(QuicTransportError::WrongRequestId)
        ));
        validate_request_admission_frame(
            &response,
            RequestId::from_bytes([2; 32]),
            TEST_NETWORK,
            PartyId(2),
            PartyId(1),
            config,
        )
        .unwrap();
        assert!(matches!(
            validate_request_admission_frame(
                &response,
                RequestId::from_bytes([2; 32]),
                TEST_NETWORK,
                PartyId(3),
                PartyId(1),
                config,
            ),
            Err(QuicTransportError::WrongSender { .. })
        ));
        assert!(matches!(
            validate_request_admission_frame(
                &response,
                RequestId::from_bytes([2; 32]),
                TEST_NETWORK,
                PartyId(2),
                PartyId(3),
                config,
            ),
            Err(QuicTransportError::WrongRecipient { .. })
        ));
    }

    #[tokio::test]
    async fn loopback_streams_reject_oversized_prefixes_and_trailing_bytes() {
        let one = TestIdentity::generate(PartyId(1));
        let two = TestIdentity::generate(PartyId(2));
        let endpoint_two = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(2),
            TEST_NETWORK,
            two.local(),
            [one.pin(PartyId(1))],
            loopback_config(),
        )
        .unwrap();
        let two_addr = endpoint_two.local_addr().unwrap();
        let endpoint_one = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(1),
            TEST_NETWORK,
            one.local(),
            [two.pin(PartyId(2))],
            loopback_config(),
        )
        .unwrap();

        let client = endpoint_one.connect(PartyId(2), two_addr);
        let server = endpoint_two.accept();
        let (client, server) = tokio::join!(client, server);
        let client = client.unwrap();
        let server = server.unwrap();
        assert!(client.connection.max_datagram_size().is_none());
        assert!(server.connection.max_datagram_size().is_none());

        let (mut send, _receive) = client.connection.open_bi().await.unwrap();
        let oversized = u32::try_from(MAX_REQUEST_PRELUDE_FRAME_BYTES + 1).unwrap();
        send.write_all(&oversized.to_be_bytes()).await.unwrap();
        send.finish().unwrap();
        assert!(matches!(
            server.accept_request().await,
            Err(QuicTransportError::FrameTooLarge { actual, maximum })
                if actual == MAX_REQUEST_PRELUDE_FRAME_BYTES + 1
                    && maximum == MAX_REQUEST_PRELUDE_FRAME_BYTES
        ));

        let body =
            PeerRequest::Epoch { operation: EpochOperation::Activate, body: b"bounded".to_vec() };
        let frame = RequestPrelude {
            version: WIRE_VERSION,
            network_id: TEST_NETWORK,
            request_id: RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &body)
                .unwrap(),
            from: PartyId(1),
            to: PartyId(2),
            route: body.route(),
            body_len: u32::try_from(body.body_len()).unwrap(),
        };
        let encoded = postcard::to_allocvec(&frame).unwrap();
        let (mut send, _receive) = client.connection.open_bi().await.unwrap();
        send.write_all(&u32::try_from(encoded.len()).unwrap().to_be_bytes()).await.unwrap();
        send.write_all(&encoded).await.unwrap();
        send.write_all(b"bounded").await.unwrap();
        send.write_all(b"trailing").await.unwrap();
        send.finish().unwrap();
        let incoming = server.accept_request().await.unwrap();
        assert!(matches!(
            incoming.read_request().await,
            Err(QuicTransportError::ReadToEnd(quinn::ReadToEndError::TooLong))
        ));

        // Postcard accepts an overlong varint for the wire version (`0x81 0x00` also decodes to
        // one). It must not be accepted as a second wire representation of the same request.
        let mut noncanonical = encoded.clone();
        assert_eq!(noncanonical[0], WIRE_VERSION as u8);
        noncanonical[0] = 0x80 | WIRE_VERSION as u8;
        noncanonical.insert(1, 0);
        let (mut send, _receive) = client.connection.open_bi().await.unwrap();
        send.write_all(&u32::try_from(noncanonical.len()).unwrap().to_be_bytes()).await.unwrap();
        send.write_all(&noncanonical).await.unwrap();
        send.finish().unwrap();
        assert!(matches!(
            server.accept_request().await,
            Err(QuicTransportError::NonCanonicalFrame)
        ));

        let oversized_request = PeerRequest::Avss {
            operation: AvssOperation::Deliver,
            body: vec![0; loopback_config().max_body_bytes + 1],
        };
        assert!(matches!(
            client.request(RequestId::from_bytes([8; 32]), oversized_request).await,
            Err(QuicTransportError::BodyTooLarge { .. })
        ));

        client.close(b"test complete");
        endpoint_one.close(b"test complete");
        endpoint_two.close(b"test complete");
    }

    #[tokio::test]
    async fn rejected_sync_objects_body_is_never_transmitted_or_decoded_and_retry_succeeds() {
        let one = TestIdentity::generate(PartyId(1));
        let two = TestIdentity::generate(PartyId(2));
        let endpoint_two = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(2),
            TEST_NETWORK,
            two.local(),
            [one.pin(PartyId(1))],
            QuicTransportConfig::default(),
        )
        .unwrap();
        let two_addr = endpoint_two.local_addr().unwrap();
        let endpoint_one = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(1),
            TEST_NETWORK,
            one.local(),
            [two.pin(PartyId(2))],
            QuicTransportConfig::default(),
        )
        .unwrap();
        let (client, server) =
            tokio::join!(endpoint_one.connect(PartyId(2), two_addr), endpoint_two.accept());
        let client = client.unwrap();
        let server = server.unwrap();

        let request = PeerRequest::Deposit {
            operation: DepositOperation::SyncObjects,
            body: vec![0x51; HARD_MAX_BODY_BYTES],
        };
        let request_id =
            RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &request).unwrap();
        let first_client = client.clone();
        let first_timeout = first_client.config.stream_timeout;
        let first_task = tokio::spawn(async move {
            first_client.request_with_timeout_outcome(request_id, request, first_timeout).await
        });
        let first_prelude = server.accept_request().await.unwrap();
        assert!(first_prelude.is_deposit_sync_objects());
        assert_eq!(first_prelude.body_len(), HARD_MAX_BODY_BYTES);
        let first_request = first_prelude.read_request().await.unwrap();

        let retry_request = PeerRequest::Deposit {
            operation: DepositOperation::SyncObjects,
            body: vec![0x52; HARD_MAX_BODY_BYTES],
        };
        let retry_id =
            RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &retry_request)
                .unwrap();
        let retry_client = client.clone();
        let retry_timeout = retry_client.config.stream_timeout;
        let retry = tokio::spawn(async move {
            retry_client.request_with_timeout_outcome(retry_id, retry_request, retry_timeout).await
        });
        let mut rejected = server.accept_request().await.unwrap();
        assert!(rejected.is_deposit_sync_objects());
        assert_eq!(rejected.body_len(), HARD_MAX_BODY_BYTES);
        let mut body_probe = [0_u8; 1];
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                rejected.receive.read(&mut body_probe),
            )
            .await
            .is_err(),
            "a conforming sender must await pre-body admission before transmitting any body byte",
        );
        let exhausted = PeerResponse::Rejected {
            code: RejectionCode::ResourceExhausted,
            retryable: true,
            message: "test SyncObjects capacity is saturated".to_owned(),
        };
        rejected.reject_before_body(exhausted.clone()).await.unwrap();
        let (retry_response, retry_provenance) = retry.await.unwrap().unwrap().into_parts();
        assert_eq!(retry_response, exhausted);
        assert_eq!(retry_provenance, QuicResponseProvenance::RejectedBeforeBody);

        first_request.respond(PeerResponse::Success { body: vec![] }).await.unwrap();
        let (first_response, first_provenance) = first_task.await.unwrap().unwrap().into_parts();
        assert_eq!(first_response, PeerResponse::Success { body: vec![] });
        assert_eq!(first_provenance, QuicResponseProvenance::AfterBody);

        let retry_request = PeerRequest::Deposit {
            operation: DepositOperation::SyncObjects,
            body: vec![0x52; HARD_MAX_BODY_BYTES],
        };
        assert_eq!(
            RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &retry_request)
                .unwrap(),
            retry_id,
        );
        let retry_client = client.clone();
        let retry =
            tokio::spawn(async move { retry_client.request(retry_id, retry_request).await });
        let retry_request = server.accept_request().await.unwrap().read_request().await.unwrap();
        retry_request.respond(PeerResponse::Success { body: vec![] }).await.unwrap();
        assert_eq!(retry.await.unwrap().unwrap(), PeerResponse::Success { body: vec![] });

        client.close(b"test complete");
        endpoint_one.close(b"test complete");
        endpoint_two.close(b"test complete");
    }

    #[tokio::test]
    async fn caller_deadline_allows_a_slow_reducer_without_poisoning_the_connection() {
        let one = TestIdentity::generate(PartyId(1));
        let two = TestIdentity::generate(PartyId(2));
        let mut config = loopback_config();
        config.stream_timeout = Duration::from_millis(100);
        let endpoint_two = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(2),
            TEST_NETWORK,
            two.local(),
            [one.pin(PartyId(1))],
            config,
        )
        .unwrap();
        let two_addr = endpoint_two.local_addr().unwrap();
        let endpoint_one = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(1),
            TEST_NETWORK,
            one.local(),
            [two.pin(PartyId(2))],
            config,
        )
        .unwrap();

        let (client, server) =
            tokio::join!(endpoint_one.connect(PartyId(2), two_addr), endpoint_two.accept());
        let client = client.unwrap();
        let server = server.unwrap();

        let slow_request =
            PeerRequest::Avss { operation: AvssOperation::Deliver, body: b"slow".to_vec() };
        let slow_request_id =
            RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &slow_request)
                .unwrap();
        let slow_client = client.clone();
        let slow_task = tokio::spawn(async move {
            slow_client
                .request_with_timeout(slow_request_id, slow_request, Duration::from_secs(2))
                .await
        });
        let incoming = server.accept_request().await.unwrap().read_request().await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        let slow_response = PeerResponse::Success { body: b"durable".to_vec() };
        incoming.respond(slow_response.clone()).await.unwrap();
        assert_eq!(slow_task.await.unwrap().unwrap(), slow_response);

        // A slow reducer response is scoped to its request stream. The authenticated,
        // multiplexed connection must remain usable for the next RPC.
        let next_request =
            PeerRequest::Qual { operation: QualOperation::Deliver, body: b"next".to_vec() };
        let next_request_id =
            RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &next_request)
                .unwrap();
        let next_client = client.clone();
        let next_task = tokio::spawn(async move {
            next_client
                .request_with_timeout(next_request_id, next_request, Duration::from_secs(1))
                .await
        });
        let incoming = server.accept_request().await.unwrap().read_request().await.unwrap();
        let next_response = PeerResponse::Success { body: b"ready".to_vec() };
        incoming.respond(next_response.clone()).await.unwrap();
        assert_eq!(next_task.await.unwrap().unwrap(), next_response);

        client.close(b"test complete");
        endpoint_one.close(b"test complete");
        endpoint_two.close(b"test complete");
    }

    #[tokio::test]
    async fn opened_streams_are_bounded_by_the_stream_timeout() {
        let one = TestIdentity::generate(PartyId(1));
        let two = TestIdentity::generate(PartyId(2));
        let mut config = loopback_config();
        config.stream_timeout = Duration::from_millis(100);
        let endpoint_two = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(2),
            TEST_NETWORK,
            two.local(),
            [one.pin(PartyId(1))],
            config,
        )
        .unwrap();
        let two_addr = endpoint_two.local_addr().unwrap();
        let endpoint_one = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(1),
            TEST_NETWORK,
            one.local(),
            [two.pin(PartyId(2))],
            config,
        )
        .unwrap();

        let (client, server) =
            tokio::join!(endpoint_one.connect(PartyId(2), two_addr), endpoint_two.accept());
        let client = client.unwrap();
        let server = server.unwrap();
        let (mut send, _receive) = client.connection.open_bi().await.unwrap();
        // Quinn creates streams lazily; one byte makes the peer observe the opened stream while
        // still leaving the fixed-width frame prefix incomplete.
        send.write_all(&[0]).await.unwrap();
        assert!(matches!(
            server.accept_request().await,
            Err(QuicTransportError::Timeout { operation: "QUIC inbound request" })
        ));

        client.close(b"test complete");
        endpoint_one.close(b"test complete");
        endpoint_two.close(b"test complete");
    }

    #[test]
    fn request_body_transfer_budget_scales_and_caps_at_the_hard_maximum() {
        let idle_timeout = Duration::from_secs(10);
        assert_eq!(request_body_transfer_timeout(64 * 1024, idle_timeout), Duration::from_secs(11));
        assert_eq!(
            request_body_transfer_timeout(4 * 1024 * 1024, idle_timeout),
            Duration::from_secs(74)
        );
        assert_eq!(
            request_body_transfer_timeout(HARD_MAX_BODY_BYTES, idle_timeout),
            MAX_REQUEST_BODY_TRANSFER_TIMEOUT
        );
    }

    #[tokio::test]
    async fn max_sized_stalled_body_is_idle_bounded_without_blocking_concurrent_streams() {
        let one = TestIdentity::generate(PartyId(1));
        let two = TestIdentity::generate(PartyId(2));
        let mut config = loopback_config();
        config.max_body_bytes = HARD_MAX_BODY_BYTES;
        config.max_frame_bytes = 9 * 1024 * 1024;
        config.stream_timeout = Duration::from_millis(750);
        let endpoint_two = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(2),
            TEST_NETWORK,
            two.local(),
            [one.pin(PartyId(1))],
            config,
        )
        .unwrap();
        let two_addr = endpoint_two.local_addr().unwrap();
        let endpoint_one = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(1),
            TEST_NETWORK,
            one.local(),
            [two.pin(PartyId(2))],
            config,
        )
        .unwrap();

        let (client, server) =
            tokio::join!(endpoint_one.connect(PartyId(2), two_addr), endpoint_two.accept());
        let client = client.unwrap();
        let server = server.unwrap();

        // The request id is deliberately arbitrary: a stalled sender never reaches the
        // post-body canonical-id check. The declared length exercises the exact hard maximum and
        // its allocation without first materializing another 8 MiB request in the test.
        let request_id = RequestId([0x55; 32]);
        let prelude = RequestPrelude {
            version: WIRE_VERSION,
            network_id: TEST_NETWORK,
            request_id,
            from: PartyId(1),
            to: PartyId(2),
            route: PeerRequestRoute::Qual(QualOperation::Deliver),
            body_len: u32::try_from(HARD_MAX_BODY_BYTES).unwrap(),
        };
        let (mut stalled_send, mut stalled_receive) = client.connection.open_bi().await.unwrap();
        write_frame_bounded(&mut stalled_send, &prelude, MAX_REQUEST_PRELUDE_FRAME_BYTES)
            .await
            .unwrap();
        let stalled_request = server.accept_request().await.unwrap();
        let stalled_reader = tokio::spawn(stalled_request.read_request());
        let admission: RequestAdmissionFrame =
            read_frame_bounded(&mut stalled_receive, MAX_REQUEST_ADMISSION_FRAME_BYTES)
                .await
                .unwrap();
        assert_eq!(admission.request_id, request_id);
        assert!(matches!(admission.admission, RequestAdmission::Accepted));

        // New streams on the same authenticated connection must keep making progress while the
        // maximum-sized admitted stream is idle. This also guards the aggregate send-window
        // change: it bounds queued bytes without serializing independent streams.
        let mut quick_tasks = Vec::new();
        for sequence in 0_u8..3 {
            let quick_request =
                PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![b'q', sequence] };
            let quick_id =
                RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &quick_request)
                    .unwrap();
            let quick_client = client.clone();
            quick_tasks.push(tokio::spawn(async move {
                quick_client
                    .request_with_timeout(quick_id, quick_request, Duration::from_secs(3))
                    .await
            }));
        }
        for sequence in 0_u8..3 {
            let incoming = server.accept_request().await.unwrap().read_request().await.unwrap();
            let response = PeerResponse::Success { body: vec![b'a', sequence] };
            incoming.respond(response).await.unwrap();
        }
        for quick_task in quick_tasks {
            assert!(matches!(
                quick_task.await.unwrap().unwrap(),
                PeerResponse::Success { body } if body.len() == 2 && body[0] == b'a'
            ));
        }

        assert!(matches!(
            stalled_reader.await.unwrap(),
            Err(QuicTransportError::Timeout { operation: "QUIC inbound request body idle" })
        ));
        let _ = stalled_send.reset(VarInt::from_u32(0));

        client.close(b"test complete");
        endpoint_one.close(b"test complete");
        endpoint_two.close(b"test complete");
    }

    #[tokio::test]
    async fn request_body_succeeds_when_progress_stays_inside_idle_and_total_budgets() {
        let one = TestIdentity::generate(PartyId(1));
        let two = TestIdentity::generate(PartyId(2));
        let mut config = loopback_config();
        config.max_body_bytes = 32 * 1024;
        config.max_frame_bytes = 64 * 1024;
        config.stream_timeout = Duration::from_millis(500);
        let endpoint_two = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(2),
            TEST_NETWORK,
            two.local(),
            [one.pin(PartyId(1))],
            config,
        )
        .unwrap();
        let two_addr = endpoint_two.local_addr().unwrap();
        let endpoint_one = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(1),
            TEST_NETWORK,
            one.local(),
            [two.pin(PartyId(2))],
            config,
        )
        .unwrap();

        let (client, server) =
            tokio::join!(endpoint_one.connect(PartyId(2), two_addr), endpoint_two.accept());
        let client = client.unwrap();
        let server = server.unwrap();
        let request =
            PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![0x5a; 32 * 1024] };
        let request_id =
            RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &request).unwrap();
        let prelude = RequestPrelude {
            version: WIRE_VERSION,
            network_id: TEST_NETWORK,
            request_id,
            from: PartyId(1),
            to: PartyId(2),
            route: request.route(),
            body_len: u32::try_from(request.body_len()).unwrap(),
        };
        let body = request.clone().into_body();
        let (mut send, mut receive) = client.connection.open_bi().await.unwrap();
        write_frame_bounded(&mut send, &prelude, MAX_REQUEST_PRELUDE_FRAME_BYTES).await.unwrap();
        let reader = tokio::spawn(server.accept_request().await.unwrap().read_request());
        let admission: RequestAdmissionFrame =
            read_frame_bounded(&mut receive, MAX_REQUEST_ADMISSION_FRAME_BYTES).await.unwrap();
        assert!(matches!(admission.admission, RequestAdmission::Accepted));

        for (index, chunk) in body.chunks(4 * 1024).enumerate() {
            if index != 0 {
                time::sleep(Duration::from_millis(60)).await;
            }
            send.write_all(chunk).await.unwrap();
        }
        send.finish().unwrap();
        let incoming = reader.await.unwrap().unwrap();
        assert_eq!(incoming.request(), &request);
        let response = PeerResponse::Success { body: b"accepted".to_vec() };
        incoming.respond(response.clone()).await.unwrap();
        let frame: ResponseFrame = read_frame(&mut receive, config).await.unwrap();
        assert_eq!(frame.response, response);
        require_eof(&mut receive).await.unwrap();

        client.close(b"test complete");
        endpoint_one.close(b"test complete");
        endpoint_two.close(b"test complete");
    }

    #[tokio::test]
    async fn trickling_request_body_hits_the_size_scaled_total_deadline() {
        let one = TestIdentity::generate(PartyId(1));
        let two = TestIdentity::generate(PartyId(2));
        let mut config = loopback_config();
        config.max_body_bytes = 8 * 1024;
        config.max_frame_bytes = 16 * 1024;
        config.stream_timeout = Duration::from_millis(500);
        let endpoint_two = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(2),
            TEST_NETWORK,
            two.local(),
            [one.pin(PartyId(1))],
            config,
        )
        .unwrap();
        let two_addr = endpoint_two.local_addr().unwrap();
        let endpoint_one = QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            PartyId(1),
            TEST_NETWORK,
            one.local(),
            [two.pin(PartyId(2))],
            config,
        )
        .unwrap();

        let (client, server) =
            tokio::join!(endpoint_one.connect(PartyId(2), two_addr), endpoint_two.accept());
        let client = client.unwrap();
        let server = server.unwrap();
        let request =
            PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![0x44; 8 * 1024] };
        let request_id =
            RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &request).unwrap();
        let prelude = RequestPrelude {
            version: WIRE_VERSION,
            network_id: TEST_NETWORK,
            request_id,
            from: PartyId(1),
            to: PartyId(2),
            route: request.route(),
            body_len: u32::try_from(request.body_len()).unwrap(),
        };
        let (mut send, mut receive) = client.connection.open_bi().await.unwrap();
        write_frame_bounded(&mut send, &prelude, MAX_REQUEST_PRELUDE_FRAME_BYTES).await.unwrap();
        let reader = tokio::spawn(server.accept_request().await.unwrap().read_request());
        let admission: RequestAdmissionFrame =
            read_frame_bounded(&mut receive, MAX_REQUEST_ADMISSION_FRAME_BYTES).await.unwrap();
        assert!(matches!(admission.admission, RequestAdmission::Accepted));

        // Each write arrives well inside the 500 ms idle allowance, but 8 KiB receives only
        // another 125 ms of size-scaled total budget. The absolute deadline therefore fires at
        // roughly 625 ms even though the sender keeps resetting the idle timer.
        let trickler = tokio::spawn(async move {
            loop {
                if send.write_all(&[0x44]).await.is_err() {
                    break;
                }
                time::sleep(Duration::from_millis(250)).await;
            }
        });
        assert!(matches!(
            reader.await.unwrap(),
            Err(QuicTransportError::Timeout { operation: "QUIC inbound request body total" })
        ));
        trickler.abort();
        let _ = trickler.await;

        client.close(b"test complete");
        endpoint_one.close(b"test complete");
        endpoint_two.close(b"test complete");
    }
}
