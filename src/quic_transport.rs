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

use crate::{
    committee::PartyId,
    deposit_consensus::MAX_CONSENSUS_MESSAGE_BYTES,
    key_rotation::{
        KeyRotationWire, MAX_KEY_ADVERTISEMENT_BYTES, MAX_KEY_ROTATION_CERTIFICATE_BYTES,
        MAX_KEY_ROTATION_ROUND_STATE_BYTES,
    },
};

const WIRE_VERSION: u16 = 4;
const ALPN: &[u8] = b"threshold-monero-peer/4";
const LENGTH_PREFIX_BYTES: usize = 4;
const HARD_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const HARD_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const HARD_MAX_REJECTION_MESSAGE_BYTES: usize = 4 * 1024;
const HARD_MAX_CONCURRENT_STREAMS: u32 = 256;
const HARD_MAX_IN_FLIGHT_FRAME_BYTES: usize = 128 * 1024 * 1024;
const MAX_CONFIGURED_TIMEOUT: Duration = Duration::from_secs(120);
// A signed envelope has fixed-size hashes, a session, a signature, and bounded postcard varints.
// Keeping this conservative allowance explicit avoids coupling the transport to private envelope
// layout while still rejecting an oversized key-rotation body before protocol verification.
const MAX_SIGNED_ENVELOPE_WIRE_OVERHEAD_BYTES: usize = 256;

/// Maximum canonical transport body for one X25519 key advertisement.
pub const MAX_KEY_ROTATION_ADVERTISEMENT_WIRE_BYTES: usize =
    MAX_KEY_ADVERTISEMENT_BYTES + MAX_SIGNED_ENVELOPE_WIRE_OVERHEAD_BYTES + 1;
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

/// Stable identifier used to correlate one response with one request.
///
/// Callers may derive this from a durable outbox key to make retries idempotent. The transport
/// does not infer request identity from stream order or connection state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId([u8; 32]);

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
        let encoded = postcard::to_allocvec(request).map_err(QuicTransportError::Serialization)?;
        let mut material = Vec::with_capacity(12 + encoded.len());
        material.extend_from_slice(&from.0.to_le_bytes());
        material.extend_from_slice(&to.0.to_le_bytes());
        material.extend_from_slice(
            &u64::try_from(encoded.len())
                .map_err(|_| QuicTransportError::FrameTooLarge {
                    actual: encoded.len(),
                    maximum: HARD_MAX_FRAME_BYTES,
                })?
                .to_le_bytes(),
        );
        material.extend_from_slice(&encoded);
        Ok(Self::derive(network_id, b"canonical-authenticated-peer-request/v4", &material))
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
            Self::Consensus => 1,
            Self::ViewCertificate => 2,
            Self::Certificate => 3,
        }
    }

    /// Hard canonical body limit for this operation, independent of endpoint configuration.
    #[must_use]
    pub const fn max_body_bytes(self) -> usize {
        match self {
            Self::Advertisement => MAX_KEY_ROTATION_ADVERTISEMENT_WIRE_BYTES,
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
/// `Allocate`, `Handoff`, and `ConsolidationCompletion` carry portable ledger proposals;
/// `Attest` contributes one committee signature; `Certificate` disseminates a committed ledger
/// entry. `DepositObservation`, `DepositObservationAttest`, and
/// `DepositObservationCertificate` provide the corresponding live proposal, witness, and
/// certificate routes for confirmed-output observations. `IndexCheckpointAttest` and
/// `IndexCheckpointCertificate` complete a ledger-bound portable-index checkpoint; the two
/// `DepositObservationIndexCheckpoint*` routes carry the separately certified observation lane
/// without inventing a ledger slot. `Consolidation` carries certified-intent consensus, all-to-all
/// ROAST contributions and candidates. The two `Sync*` operations expose only the fresh compact
/// catch-up protocol: settled heads and root-connected immutable object pages.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DepositOperation {
    Allocate,
    Attest,
    Certificate,
    Handoff,
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
    ConsolidationCompletion,
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
            Self::Allocate | Self::Handoff | Self::ConsolidationCompletion => 6,
            Self::Attest => 7,
            Self::Certificate => 8,
            Self::DepositObservation => 9,
            Self::DepositObservationAttest => 10,
            Self::DepositObservationCertificate => 11,
            Self::IndexCheckpointAttest | Self::DepositObservationIndexCheckpointAttest => 12,
            Self::IndexCheckpointCertificate
            | Self::DepositObservationIndexCheckpointCertificate => 13,
            Self::SyncHead | Self::SyncObjects => 14,
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
struct RequestFrame {
    version: u16,
    network_id: [u8; 32],
    request_id: RequestId,
    from: PartyId,
    to: PartyId,
    request: PeerRequest,
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
    #[error("rejection message is {actual} bytes; maximum is {maximum}")]
    RejectionMessageTooLarge { actual: usize, maximum: usize },
    #[error("QUIC endpoint is closed")]
    EndpointClosed,
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
        let frame = RequestFrame {
            version: WIRE_VERSION,
            network_id: self.network_id,
            request_id,
            from: self.local_party,
            to: self.peer_party,
            request,
        };
        let operation = async {
            let (mut send, mut receive) = self.connection.open_bi().await?;
            write_frame(&mut send, &frame, self.config).await?;
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
            Ok(response.response)
        };
        timeout(self.config.stream_timeout, "QUIC request stream", operation).await?
    }

    /// Accept the next request stream. An idle authenticated connection may wait indefinitely;
    /// once a stream is opened, its frame must arrive within `stream_timeout`.
    pub async fn accept_request(&self) -> Result<IncomingPeerRequest, QuicTransportError> {
        let (send, mut receive) = self.connection.accept_bi().await?;
        let operation = async {
            let frame: RequestFrame = read_frame(&mut receive, self.config).await?;
            require_eof(&mut receive).await?;
            validate_request_frame(
                &frame,
                self.peer_party,
                self.local_party,
                self.network_id,
                self.config,
            )?;
            Ok::<RequestFrame, QuicTransportError>(frame)
        };
        let frame =
            timeout(self.config.stream_timeout, "QUIC inbound request", operation).await??;
        Ok(IncomingPeerRequest { frame, send, config: self.config })
    }

    pub fn close(&self, reason: &[u8]) {
        self.connection.close(VarInt::from_u32(0), reason);
    }
}

/// Authenticated inbound request retaining the response half of its QUIC stream.
pub struct IncomingPeerRequest {
    frame: RequestFrame,
    send: quinn::SendStream,
    config: QuicTransportConfig,
}

impl std::fmt::Debug for IncomingPeerRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IncomingPeerRequest")
            .field("request_id", &self.frame.request_id)
            .field("from", &self.frame.from)
            .field("to", &self.frame.to)
            .field("request", &self.frame.request)
            .finish_non_exhaustive()
    }
}

impl IncomingPeerRequest {
    pub fn request_id(&self) -> RequestId {
        self.frame.request_id
    }

    pub fn peer_party(&self) -> PartyId {
        self.frame.from
    }

    pub fn request(&self) -> &PeerRequest {
        &self.frame.request
    }

    pub fn into_request(self) -> PeerRequest {
        self.frame.request
    }

    pub async fn respond(mut self, response: PeerResponse) -> Result<(), QuicTransportError> {
        validate_response(&response, self.config)?;
        let frame = ResponseFrame {
            version: WIRE_VERSION,
            network_id: self.frame.network_id,
            request_id: self.frame.request_id,
            from: self.frame.to,
            to: self.frame.from,
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
    transport.stream_receive_window(VarInt::from_u32(
        u32::try_from(config.max_frame_bytes)
            .map_err(|_| QuicTransportError::InvalidConfiguration("frame limit exceeds u32"))?,
    ));
    let connection_window = config
        .max_frame_bytes
        .checked_mul(config.max_concurrent_bidi_streams as usize)
        .and_then(|window| u64::try_from(window).ok())
        .and_then(|window| VarInt::from_u64(window).ok())
        .ok_or(QuicTransportError::InvalidConfiguration(
            "frame and concurrency limits overflow the QUIC receive window",
        ))?;
    transport.receive_window(connection_window);
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
    let encoded = postcard::to_allocvec(frame).map_err(QuicTransportError::Serialization)?;
    if encoded.len() > config.max_frame_bytes {
        return Err(QuicTransportError::FrameTooLarge {
            actual: encoded.len(),
            maximum: config.max_frame_bytes,
        });
    }
    let length = u32::try_from(encoded.len()).map_err(|_| QuicTransportError::FrameTooLarge {
        actual: encoded.len(),
        maximum: config.max_frame_bytes,
    })?;
    send.write_all(&length.to_be_bytes()).await?;
    send.write_all(&encoded).await?;
    Ok(())
}

async fn read_frame<T: for<'de> Deserialize<'de> + Serialize>(
    receive: &mut quinn::RecvStream,
    config: QuicTransportConfig,
) -> Result<T, QuicTransportError> {
    let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
    receive.read_exact(&mut prefix).await?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > config.max_frame_bytes {
        return Err(QuicTransportError::FrameTooLarge {
            actual: length,
            maximum: config.max_frame_bytes,
        });
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
    let maximum = match request {
        PeerRequest::KeyRotation { operation, .. } => {
            config.max_body_bytes.min(operation.max_body_bytes())
        }
        PeerRequest::Avss { .. }
        | PeerRequest::Qual { .. }
        | PeerRequest::Epoch { .. }
        | PeerRequest::Deposit { .. } => config.max_body_bytes,
    };
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

fn validate_request_frame(
    frame: &RequestFrame,
    authenticated_peer: PartyId,
    local_party: PartyId,
    network_id: [u8; 32],
    config: QuicTransportConfig,
) -> Result<(), QuicTransportError> {
    if frame.version != WIRE_VERSION {
        return Err(QuicTransportError::UnsupportedVersion(frame.version));
    }
    if frame.network_id != network_id {
        return Err(QuicTransportError::WrongNetwork);
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
    validate_request(&frame.request, config)?;
    if frame.request_id
        != RequestId::for_peer_request(network_id, frame.from, frame.to, &frame.request)?
    {
        return Err(QuicTransportError::WrongRequestId);
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
    fn current_transport_contract_is_v4_and_request_ids_do_not_alias_v3() {
        assert_eq!(WIRE_VERSION, 4);
        assert_eq!(ALPN, b"threshold-monero-peer/4");

        let from = PartyId(1);
        let to = PartyId(2);
        let request =
            PeerRequest::Deposit { operation: DepositOperation::DepositObservation, body: vec![7] };
        let encoded = postcard::to_allocvec(&request).unwrap();
        let mut material = Vec::with_capacity(12 + encoded.len());
        material.extend_from_slice(&from.0.to_le_bytes());
        material.extend_from_slice(&to.0.to_le_bytes());
        material.extend_from_slice(&u64::try_from(encoded.len()).unwrap().to_le_bytes());
        material.extend_from_slice(&encoded);

        let current = RequestId::for_peer_request(TEST_NETWORK, from, to, &request).unwrap();
        assert_eq!(
            current,
            RequestId::derive(TEST_NETWORK, b"canonical-authenticated-peer-request/v4", &material,)
        );
        assert_ne!(
            current,
            RequestId::derive(TEST_NETWORK, b"canonical-authenticated-peer-request/v3", &material,)
        );
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
        assert_eq!(KeyRotationOperation::Consensus.causal_priority(), 1);
        assert_eq!(KeyRotationOperation::ViewCertificate.causal_priority(), 2);
        assert_eq!(KeyRotationOperation::Certificate.causal_priority(), 3);

        assert_eq!(
            KeyRotationOperation::Advertisement.max_body_bytes(),
            MAX_KEY_ROTATION_ADVERTISEMENT_WIRE_BYTES
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
        let frame = RequestFrame {
            version: WIRE_VERSION,
            network_id: TEST_NETWORK,
            request_id: RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &request)
                .unwrap(),
            from: PartyId(1),
            to: PartyId(2),
            request,
        };
        assert!(postcard::to_allocvec(&frame).unwrap().len() <= config.max_frame_bytes);

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
    fn authenticated_party_and_request_id_are_bound_to_frames() {
        let config = QuicTransportConfig::default();
        let body = PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![] };
        let request = RequestFrame {
            version: WIRE_VERSION,
            network_id: TEST_NETWORK,
            request_id: RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &body)
                .unwrap(),
            from: PartyId(1),
            to: PartyId(2),
            request: body,
        };
        validate_request_frame(&request, PartyId(1), PartyId(2), TEST_NETWORK, config).unwrap();
        let mut equivocation = request.clone();
        equivocation.request =
            PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![0x01] };
        assert!(matches!(
            validate_request_frame(&equivocation, PartyId(1), PartyId(2), TEST_NETWORK, config,),
            Err(QuicTransportError::WrongRequestId)
        ));
        assert!(matches!(
            validate_request_frame(&request, PartyId(3), PartyId(2), TEST_NETWORK, config),
            Err(QuicTransportError::WrongSender { .. })
        ));
        assert!(matches!(
            validate_request_frame(&request, PartyId(1), PartyId(2), [0x44; 32], config),
            Err(QuicTransportError::WrongNetwork)
        ));
        assert!(matches!(
            validate_request_frame(&request, PartyId(1), PartyId(3), TEST_NETWORK, config),
            Err(QuicTransportError::WrongRecipient { .. })
        ));

        let response = ResponseFrame {
            version: WIRE_VERSION,
            network_id: TEST_NETWORK,
            request_id: RequestId::from_bytes([2; 32]),
            from: PartyId(2),
            to: PartyId(1),
            response: PeerResponse::Success { body: vec![] },
        };
        assert!(matches!(
            validate_response_frame(
                &response,
                RequestId::from_bytes([3; 32]),
                TEST_NETWORK,
                PartyId(2),
                PartyId(1),
                config,
            ),
            Err(QuicTransportError::WrongRequestId)
        ));
        validate_response_frame(
            &response,
            RequestId::from_bytes([2; 32]),
            TEST_NETWORK,
            PartyId(2),
            PartyId(1),
            config,
        )
        .unwrap();
        assert!(matches!(
            validate_response_frame(
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
            validate_response_frame(
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
        let oversized = u32::try_from(loopback_config().max_frame_bytes + 1).unwrap();
        send.write_all(&oversized.to_be_bytes()).await.unwrap();
        send.finish().unwrap();
        assert!(matches!(
            server.accept_request().await,
            Err(QuicTransportError::FrameTooLarge { actual, maximum })
                if actual == loopback_config().max_frame_bytes + 1
                    && maximum == loopback_config().max_frame_bytes
        ));

        let frame = RequestFrame {
            version: WIRE_VERSION,
            network_id: TEST_NETWORK,
            request_id: RequestId::from_bytes([7; 32]),
            from: PartyId(1),
            to: PartyId(2),
            request: PeerRequest::Epoch {
                operation: EpochOperation::Activate,
                body: b"bounded".to_vec(),
            },
        };
        let encoded = postcard::to_allocvec(&frame).unwrap();
        let (mut send, _receive) = client.connection.open_bi().await.unwrap();
        send.write_all(&u32::try_from(encoded.len()).unwrap().to_be_bytes()).await.unwrap();
        send.write_all(&encoded).await.unwrap();
        send.write_all(b"trailing").await.unwrap();
        send.finish().unwrap();
        assert!(matches!(
            server.accept_request().await,
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
}
