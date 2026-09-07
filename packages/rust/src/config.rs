use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::{
    avss::{AvssError, MAX_AVSS_DEALERS, preflight_avss_resources},
    committee::{
        Committee, CommitteeError, MAX_COMMITTEE_MEMBERS, MAX_COMMITTEE_THRESHOLD, Member, PartyId,
    },
    key_rotation::{
        KeyRotationError, KeyRotationTargetPolicy, eligibility_reference_key,
        valid_x25519_public_key,
    },
    receiver_key_accumulator::{ReceiverKeyAccumulatorCommitment, ReceiverKeyAccumulatorError},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkKind {
    Regtest,
    Testnet,
    Mainnet,
}

/// Canonical Monero mainnet genesis block hash returned by `on_get_block_hash(0)`.
///
/// Source: Monero's `GENESIS_TX`/`GENESIS_NONCE = 10000` network configuration. This constant is
/// deliberately kept in RPC byte order so it can be compared directly with monero-oxide.
pub const MONERO_MAINNET_GENESIS_HASH: [u8; 32] = [
    0x41, 0x80, 0x15, 0xbb, 0x9a, 0xe9, 0x82, 0xa1, 0x97, 0x5d, 0xa7, 0xd7, 0x92, 0x77, 0xc2, 0x70,
    0x57, 0x27, 0xa5, 0x68, 0x94, 0xba, 0x0f, 0xb2, 0x46, 0xad, 0xaa, 0xbb, 0x1f, 0x46, 0x32, 0xe3,
];

/// Canonical Monero public-testnet genesis block hash returned by `on_get_block_hash(0)`.
///
/// Source: Monero's `GENESIS_TX`/`GENESIS_NONCE = 10001` testnet configuration.
pub const MONERO_TESTNET_GENESIS_HASH: [u8; 32] = [
    0x48, 0xca, 0x7c, 0xd3, 0xc8, 0xde, 0x5b, 0x6a, 0x4d, 0x53, 0xd2, 0x86, 0x1f, 0xbd, 0xae, 0xdc,
    0xa1, 0x41, 0x55, 0x35, 0x59, 0xf9, 0xbe, 0x95, 0x20, 0x06, 0x80, 0x53, 0xcd, 0xa8, 0x43, 0x0b,
];

/// Default hard ceiling for one autonomous deposit-consolidation fee.
pub const DEFAULT_DEPOSIT_MAXIMUM_FEE_ATOMIC_UNITS: u64 = 1_000_000_000;

/// Default interval between proactive share refreshes once an epoch is active.
///
/// The interval is committed by [`Scenario::quic_network_id`]. Parties configured with different
/// refresh clocks therefore cannot accidentally join one protocol network.
pub const DEFAULT_PROACTIVE_REFRESH_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

/// Only accepted scenario schema. Earlier schemas are intentionally unsupported.
pub const SCENARIO_SCHEMA_VERSION: u16 = 7;

/// Hard deployment bound for independently addressed daemon fallbacks assigned to one party.
///
/// Failover is deliberately small: one deposit operation has a finite RPC deadline and rotates
/// to the next endpoint after a failed attempt. An unbounded endpoint list would turn recovery
/// into an attacker-controlled availability loop.
pub const MAX_MONEROD_ENDPOINTS_PER_PARTY: usize = 4;

/// Hard deployment bound for parties which can accumulate in durable transport cursors.
///
/// Individual committees are smaller, but proactive resharing can rotate through distinct
/// participants over time. Bounding the complete configured identity set keeps those monotonic
/// cursors within their fixed authenticated-storage records.
pub const MAX_SCENARIO_PARTIES: usize = 32;

/// A zero interval would disable the mobile-adversary boundary while looking like a configured
/// refresh policy. Keep the on-wire policy explicit and positive instead.
pub const MIN_PROACTIVE_REFRESH_INTERVAL_SECONDS: u64 = 1;

/// Minimum sustainable proactive-refresh interval outside a demo-only private Regtest harness.
///
/// Every refresh permanently reserves the successor committee's receiver keys. Production-like
/// deployments therefore need a storage-rate floor even though short intervals remain useful for
/// deterministic acceptance and resilience campaigns.
pub const MIN_NON_DEMO_PROACTIVE_REFRESH_INTERVAL_SECONDS: u64 = 60 * 60;

/// Resource-policy ceiling rather than a cryptographic limit. Longer intervals can be represented
/// by stopping the service; a live configured network is expected to refresh at least yearly.
pub const MAX_PROACTIVE_REFRESH_INTERVAL_SECONDS: u64 = 365 * 24 * 60 * 60;

/// Maximum exponential pacemaker backoff applied to one BFT consensus view.
///
/// The cap bounds both durable timer state and the delay before an honest leader can make
/// progress after a run of Byzantine or unavailable leaders.
pub(crate) const MAX_BFT_VIEW_TIMEOUT_SHIFT: u32 = 6;

/// Largest Unix timestamp accepted by the persistent protocol state.
pub(crate) const MAX_SUPPORTED_UNIX_SECONDS: u64 = 253_402_300_799;

/// Largest millisecond value whose truncated seconds remain in the supported timestamp range.
pub(crate) const MAX_SUPPORTED_UNIX_MILLISECONDS: u64 = MAX_SUPPORTED_UNIX_SECONDS * 1_000 + 999;

impl NetworkKind {
    /// Exact `get_info.nettype` value required from the configured daemon.
    ///
    /// Monero reports private regtest/fakechain nodes as `fakechain`. Fakechain deliberately reuses
    /// mainnet's genesis block, so this value must be checked in addition to the genesis hash.
    #[must_use]
    pub const fn daemon_nettype(self) -> &'static str {
        match self {
            Self::Regtest => "fakechain",
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }

    /// Canonical genesis hash for this logical Monero network.
    ///
    /// Regtest/fakechain inherits Monero's mainnet genesis configuration; `daemon_nettype` keeps
    /// those otherwise-identical genesis domains distinct.
    #[must_use]
    pub const fn genesis_hash(self) -> [u8; 32] {
        match self {
            Self::Regtest | Self::Mainnet => MONERO_MAINNET_GENESIS_HASH,
            Self::Testnet => MONERO_TESTNET_GENESIS_HASH,
        }
    }

    pub(crate) const fn daemon_network_flags(self) -> (bool, bool, bool) {
        match self {
            Self::Regtest => (false, false, false),
            Self::Testnet => (false, true, false),
            Self::Mainnet => (true, false, false),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Dkg,
    Reshare,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hex32(pub [u8; 32]);

impl Serialize for Hex32 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

/// Deployment-wide Monero wallet birth checkpoint. It is part of the QUIC trust-domain digest so
/// parties configured with different scan origins cannot communicate as one committee network.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositBirthAnchor {
    pub height: u64,
    pub hash: Hex32,
}

impl<'de> Deserialize<'de> for Hex32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let bytes = hex::decode(value).map_err(serde::de::Error::custom)?;
        let bytes = bytes
            .try_into()
            .map_err(|_: Vec<u8>| serde::de::Error::custom("expected exactly 32 bytes"))?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioParty {
    pub id: PartyId,
    /// Local operator/control endpoint. This route is never part of a committee digest and must
    /// not be used for party-to-party protocol delivery.
    pub admin_endpoint: Url,
    /// UDP endpoint used by the mutually authenticated QUIC peer transport.
    pub quic_endpoint: Url,
    /// DNS name verified by rustls when this party is the QUIC server.
    pub quic_server_name: String,
    /// Public leaf certificate loaded and exactly pinned for this party.
    pub quic_certificate_file: PathBuf,
    /// Independently administered Monero RPC endpoints used by this party's local application
    /// predicate. The first endpoint is primary; bounded reconnect rotates through the remainder.
    ///
    /// Every URL in the scenario must be globally unique. Sharing an observer across parties
    /// would collapse independent n-f validation into a common-mode trust dependency.
    pub monerod_rpc_urls: Vec<Url>,
    pub signing_key: Hex32,
    /// Separately provisioned genesis-only X25519 key. Every activated successor key comes from a
    /// fresh durable advertisement and never from this value.
    pub bootstrap_encryption_key: Hex32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitteeSpec {
    pub epoch: u64,
    pub operation: Operation,
    pub threshold: u16,
    /// Explicit Byzantine bound used by CKLS AVSS and threshold-signing recovery; it is
    /// intentionally not inferred from `n`. For post-genesis receiver-key selection, this bound is
    /// also a governance assumption over the entire `eligible_members` roster: no more than this
    /// many eligible stable identities may be Byzantine, regardless of which subset is selected.
    pub fault_bound: u16,
    /// Governance shape defining only the desired committee size and threshold layout.
    ///
    /// Receiver-key agreement may certificate-select any exact `members.len()` subset of fresh
    /// advertisers from `eligible_members`. This list is not a priority roster.
    pub members: Vec<PartyId>,
    /// Canonical stable-identity pool authorized to advertise for this epoch. A post-genesis pool
    /// must contain at least `members.len() + fault_bound` identities.
    pub eligible_members: Vec<PartyId>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Scenario {
    pub schema_version: u16,
    pub demo_only: bool,
    pub network: NetworkKind,
    pub deposit_birth_anchor: Option<DepositBirthAnchor>,
    /// Private-Regtest mining/submission RPC used only by the one-shot acceptance driver.
    ///
    /// Signer parties never use this endpoint for their chain observations.
    pub acceptance_monerod_rpc_url: Url,
    pub parties: Vec<ScenarioParty>,
    pub committees: Vec<CommitteeSpec>,
    pub funding_blocks: u64,
    pub confirmation_blocks: u64,
    /// Hard policy ceiling for one autonomous deposit-consolidation transaction fee.
    pub deposit_maximum_fee_atomic_units: u64,
    pub poll_interval_ms: u64,
    /// Base timeout for one BFT view. Deployment liveness requires the complete honest-leader
    /// proposal, vote, delivery, reducer, and durable-storage pipeline to finish before the
    /// deadline capped at 64 times this value.
    pub protocol_timeout_seconds: u64,
    /// Fixed, scenario-bound wall-clock interval for proactive resharing. The deadline itself is
    /// persisted locally against the active activation certificate so a restart cannot reset it.
    pub proactive_refresh_interval_seconds: u64,
}

/// Serde treats every `Option<T>` field as implicitly optional, even without `#[serde(default)]`.
/// Wrap this one field during deserialization so the current schema must spell it explicitly;
/// `null` remains the canonical representation for a deployment which resolves its anchor at
/// first start.
#[derive(Deserialize)]
#[serde(untagged)]
enum RequiredDepositBirthAnchor {
    Present(DepositBirthAnchor),
    ExplicitNull(()),
}

impl RequiredDepositBirthAnchor {
    const fn into_option(self) -> Option<DepositBirthAnchor> {
        match self {
            Self::Present(anchor) => Some(anchor),
            Self::ExplicitNull(()) => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioWire {
    schema_version: u16,
    demo_only: bool,
    network: NetworkKind,
    deposit_birth_anchor: RequiredDepositBirthAnchor,
    acceptance_monerod_rpc_url: Url,
    parties: Vec<ScenarioParty>,
    committees: Vec<CommitteeSpec>,
    funding_blocks: u64,
    confirmation_blocks: u64,
    deposit_maximum_fee_atomic_units: u64,
    poll_interval_ms: u64,
    protocol_timeout_seconds: u64,
    proactive_refresh_interval_seconds: u64,
}

impl<'de> Deserialize<'de> for Scenario {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ScenarioWire::deserialize(deserializer)?;
        Ok(Self {
            schema_version: wire.schema_version,
            demo_only: wire.demo_only,
            network: wire.network,
            deposit_birth_anchor: wire.deposit_birth_anchor.into_option(),
            acceptance_monerod_rpc_url: wire.acceptance_monerod_rpc_url,
            parties: wire.parties,
            committees: wire.committees,
            funding_blocks: wire.funding_blocks,
            confirmation_blocks: wire.confirmation_blocks,
            deposit_maximum_fee_atomic_units: wire.deposit_maximum_fee_atomic_units,
            poll_interval_ms: wire.poll_interval_ms,
            protocol_timeout_seconds: wire.protocol_timeout_seconds,
            proactive_refresh_interval_seconds: wire.proactive_refresh_interval_seconds,
        })
    }
}

/// Static governance shape for one configured receiver-key rotation.
///
/// This intentionally contains no receiver-key accumulator. Configuration can validate future
/// committee sizes, stable identities, and Byzantine spare capacity, but only authenticated epoch
/// history can supply the accumulator commitment for a live transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredKeyRotationTargetShape {
    eligible: Committee,
    desired_n: u16,
    target_fault_bound: u16,
}

impl ConfiguredKeyRotationTargetShape {
    fn new(
        source: &Committee,
        mut eligible: Committee,
        desired_n: u16,
        target_fault_bound: u16,
    ) -> Result<Self, ConfigError> {
        source.validate()?;
        let target_epoch = source.epoch.checked_add(1).ok_or(ConfigError::NonContiguousEpochs)?;
        if eligible.epoch != target_epoch {
            return Err(KeyRotationError::InvalidTargetPolicy(
                "target epoch must immediately follow the source",
            )
            .into());
        }
        for member in &mut eligible.members {
            member.encryption_key =
                eligibility_reference_key(target_epoch, member.id, member.signing_key);
        }
        let eligible = eligible.canonicalized()?;
        let minimum_eligible = desired_n
            .checked_add(target_fault_bound)
            .ok_or(KeyRotationError::InvalidTargetPolicy("eligible target size overflow"))?;
        if desired_n == 0 || eligible.n() < minimum_eligible {
            return Err(KeyRotationError::InsufficientEligibleCandidates {
                actual: eligible.n(),
                desired: desired_n,
                fault_bound: target_fault_bound,
            }
            .into());
        }
        let selected_shape = Committee {
            epoch: eligible.epoch,
            threshold: eligible.threshold,
            members: eligible.members.iter().take(usize::from(desired_n)).cloned().collect(),
        };
        selected_shape.validate_async_security_with_faults(target_fault_bound)?;

        for member in &source.members {
            if !valid_x25519_public_key(member.encryption_key) {
                return Err(KeyRotationError::InvalidSourceKey(member.id).into());
            }
        }
        for member in &eligible.members {
            match source.member(member.id) {
                Ok(source_member) => {
                    if member.signing_key != source_member.signing_key {
                        return Err(KeyRotationError::TargetChangedStableIdentity(member.id).into());
                    }
                }
                Err(CommitteeError::UnknownParty(_)) => {
                    if source
                        .members
                        .iter()
                        .any(|source_member| source_member.signing_key == member.signing_key)
                    {
                        return Err(KeyRotationError::ReusedSourceSigningKey(member.id).into());
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }

        Ok(Self { eligible, desired_n, target_fault_bound })
    }

    #[must_use]
    pub const fn eligible(&self) -> &Committee {
        &self.eligible
    }

    #[must_use]
    pub const fn target_epoch(&self) -> u64 {
        self.eligible.epoch
    }

    #[must_use]
    pub const fn desired_n(&self) -> u16 {
        self.desired_n
    }

    #[must_use]
    pub const fn selection_size(&self) -> usize {
        self.desired_n as usize
    }

    #[must_use]
    pub const fn target_fault_bound(&self) -> u16 {
        self.target_fault_bound
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported scenario schema version {0}")]
    Schema(u16),
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("AVSS resource configuration error: {0}")]
    Avss(#[from] AvssError),
    #[error("key-rotation policy error: {0}")]
    KeyRotation(#[from] KeyRotationError),
    #[error("receiver-key accumulator error: {0}")]
    ReceiverKeyAccumulator(#[from] ReceiverKeyAccumulatorError),
    #[error("unknown party {0} in scenario")]
    UnknownParty(PartyId),
    #[error("duplicate party {0} in scenario")]
    DuplicateParty(PartyId),
    #[error("scenario has {actual} parties; maximum is {maximum}")]
    TooManyParties { actual: usize, maximum: usize },
    #[error("party {0} has an invalid bootstrap X25519 public key")]
    InvalidBootstrapEncryptionKey(PartyId),
    #[error("bootstrap X25519 public keys must be unique across parties")]
    DuplicateBootstrapEncryptionKey,
    #[error("stable Ed25519 public keys must be unique across parties")]
    DuplicateSigningKey,
    #[error("party {0} has an invalid admin HTTP endpoint")]
    InvalidAdminEndpoint(PartyId),
    #[error("party {0} has an invalid QUIC UDP endpoint")]
    InvalidQuicEndpoint(PartyId),
    #[error("party {0} has an invalid QUIC TLS server name")]
    InvalidQuicServerName(PartyId),
    #[error("party {0} must use an absolute QUIC certificate path")]
    InvalidQuicCertificateFile(PartyId),
    #[error("party {0} must configure 1..={MAX_MONEROD_ENDPOINTS_PER_PARTY} Monero RPC URLs")]
    InvalidMonerodEndpointCount(PartyId),
    #[error("party {0} has an invalid Monero HTTP RPC endpoint")]
    InvalidMonerodEndpoint(PartyId),
    #[error("acceptance and party Monero RPC endpoints must all be unique")]
    DuplicateMonerodEndpoint,
    #[error("acceptance Monero RPC endpoint is invalid")]
    InvalidAcceptanceMonerodEndpoint,
    #[error("deposit wallet birth anchor has an all-zero block hash")]
    InvalidDepositBirthAnchor,
    #[error("deposit maximum fee must be positive")]
    InvalidDepositMaximumFee,
    #[error("protocol timeout must be positive and fit every bounded BFT deadline")]
    InvalidProtocolTimeout,
    #[error(
        "proactive refresh interval must be in {MIN_PROACTIVE_REFRESH_INTERVAL_SECONDS}..={MAX_PROACTIVE_REFRESH_INTERVAL_SECONDS} seconds"
    )]
    InvalidProactiveRefreshInterval,
    #[error(
        "proactive refresh intervals below {MIN_NON_DEMO_PROACTIVE_REFRESH_INTERVAL_SECONDS} seconds are restricted to demo-only Regtest scenarios"
    )]
    NonDemoProactiveRefreshIntervalTooShort,
    #[error("QUIC endpoints must be unique across parties")]
    DuplicateQuicEndpoint,
    #[error("QUIC TLS server names must be unique across parties")]
    DuplicateQuicServerName,
    #[error("QUIC certificate paths must be unique across parties")]
    DuplicateQuicCertificateFile,
    #[error("committee epochs must be contiguous from zero")]
    NonContiguousEpochs,
    #[error("epoch zero must be a DKG and later epochs must be reshares")]
    InvalidOperations,
    #[error(
        "epoch {epoch} threshold {threshold} cannot safely abandon a signing attempt with fault bound {fault_bound}; threshold must exceed 2f"
    )]
    InsufficientSigningThreshold { epoch: u64, threshold: u16, fault_bound: u16 },
    #[error("epoch {epoch} eligible target candidates must be unique and canonical")]
    NonCanonicalEligibleMembers { epoch: u64 },
    #[error("epoch {epoch} desired target members are not all eligible")]
    DesiredMemberNotEligible { epoch: u64 },
    #[error("epoch zero eligible candidates must exactly equal its DKG committee")]
    GenesisEligibleMembersDiffer,
    #[error("epoch {epoch} has {actual} AVSS dealers; maximum is {maximum}")]
    TooManyDealers { epoch: u64, actual: usize, maximum: usize },
}

impl Scenario {
    pub async fn read(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let bytes = tokio::fs::read(path).await?;
        let scenario: Self = serde_json::from_slice(&bytes)?;
        scenario.validate()?;
        Ok(scenario)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != SCENARIO_SCHEMA_VERSION {
            return Err(ConfigError::Schema(self.schema_version));
        }
        if self.deposit_birth_anchor.is_some_and(|anchor| anchor.hash.0 == [0_u8; 32]) {
            return Err(ConfigError::InvalidDepositBirthAnchor);
        }
        if self.deposit_maximum_fee_atomic_units == 0 {
            return Err(ConfigError::InvalidDepositMaximumFee);
        }
        let protocol_timeout_ms =
            self.protocol_timeout_seconds.checked_mul(1_000).filter(|timeout| *timeout != 0);
        if protocol_timeout_ms.is_none_or(|timeout| {
            timeout
                .checked_mul(1_u64 << MAX_BFT_VIEW_TIMEOUT_SHIFT)
                .and_then(|backoff| MAX_SUPPORTED_UNIX_MILLISECONDS.checked_add(backoff))
                .is_none()
        }) {
            return Err(ConfigError::InvalidProtocolTimeout);
        }
        if !(MIN_PROACTIVE_REFRESH_INTERVAL_SECONDS..=MAX_PROACTIVE_REFRESH_INTERVAL_SECONDS)
            .contains(&self.proactive_refresh_interval_seconds)
        {
            return Err(ConfigError::InvalidProactiveRefreshInterval);
        }
        if !(self.demo_only && self.network == NetworkKind::Regtest)
            && self.proactive_refresh_interval_seconds
                < MIN_NON_DEMO_PROACTIVE_REFRESH_INTERVAL_SECONDS
        {
            return Err(ConfigError::NonDemoProactiveRefreshIntervalTooShort);
        }
        if !valid_monerod_endpoint(&self.acceptance_monerod_rpc_url) {
            return Err(ConfigError::InvalidAcceptanceMonerodEndpoint);
        }
        self.validate_parties()?;
        let mut committees = self.committees.clone();
        committees.sort_by_key(|committee| committee.epoch);
        for (expected, spec) in committees.iter().enumerate() {
            let current_members = spec.members.iter().copied().collect::<BTreeSet<_>>();
            let eligible_members = spec.eligible_members.iter().copied().collect::<BTreeSet<_>>();
            if eligible_members.len() != spec.eligible_members.len()
                || !spec.eligible_members.windows(2).all(|parties| parties[0] < parties[1])
            {
                return Err(ConfigError::NonCanonicalEligibleMembers { epoch: spec.epoch });
            }
            if !current_members.is_subset(&eligible_members) {
                return Err(ConfigError::DesiredMemberNotEligible { epoch: spec.epoch });
            }
            if spec.epoch == 0 && spec.eligible_members != spec.members {
                return Err(ConfigError::GenesisEligibleMembersDiffer);
            }
            // Reject allocation-driving dimensions before resolving members or constructing any
            // AVSS/QUAL state. These are deployment resource caps, not protocol-theory limits.
            if spec.members.len() > MAX_COMMITTEE_MEMBERS {
                return Err(CommitteeError::TooManyMembers {
                    members: spec.members.len(),
                    maximum: MAX_COMMITTEE_MEMBERS,
                }
                .into());
            }
            if spec.eligible_members.len() > MAX_COMMITTEE_MEMBERS {
                return Err(CommitteeError::TooManyMembers {
                    members: spec.eligible_members.len(),
                    maximum: MAX_COMMITTEE_MEMBERS,
                }
                .into());
            }
            if spec.threshold > MAX_COMMITTEE_THRESHOLD {
                return Err(CommitteeError::ThresholdTooLarge {
                    threshold: spec.threshold,
                    maximum: MAX_COMMITTEE_THRESHOLD,
                }
                .into());
            }
            if spec.epoch != expected as u64 {
                return Err(ConfigError::NonContiguousEpochs);
            }
            if (spec.epoch == 0 && spec.operation != Operation::Dkg)
                || (spec.epoch != 0 && spec.operation != Operation::Reshare)
            {
                return Err(ConfigError::InvalidOperations);
            }
            // Every member of the actually certified source committee is eligible to deal during
            // a reshare. A certificate may substitute identities within the configured target
            // pool, but its exact size is fixed by the preceding governance shape.
            let dealer_count = if spec.epoch == 0 {
                spec.members.len()
            } else {
                committees[expected - 1].members.len()
            };
            if dealer_count > MAX_AVSS_DEALERS {
                return Err(ConfigError::TooManyDealers {
                    epoch: spec.epoch,
                    actual: dealer_count,
                    maximum: MAX_AVSS_DEALERS,
                });
            }
            let committee = self.configured_committee_shape(spec.epoch)?;
            committee.validate_async_security_with_faults(spec.fault_bound)?;
            if spec.threshold <= spec.fault_bound.saturating_mul(2) {
                return Err(ConfigError::InsufficientSigningThreshold {
                    epoch: spec.epoch,
                    threshold: spec.threshold,
                    fault_bound: spec.fault_bound,
                });
            }
            preflight_avss_resources(&committee, dealer_count)?;
            if spec.epoch > 0 {
                let old = self.configured_committee_shape(spec.epoch - 1)?;
                let configured_shape = self
                    .configured_key_rotation_target_shape(&old)?
                    .ok_or(ConfigError::NonContiguousEpochs)?;
                if configured_shape.target_epoch() != spec.epoch {
                    return Err(ConfigError::NonContiguousEpochs);
                }
            }
        }
        // The static schedule eventually hands off to the indefinite same-layout refresh policy.
        // Validate its spare floor now instead of allowing a deployment which activates its final
        // configured epoch and then can never tolerate one silent receiver-key advertiser.
        let terminal = committees.last().ok_or(ConfigError::NonContiguousEpochs)?;
        let source = self.configured_committee_shape(terminal.epoch)?;
        drop(self.proactive_refresh_target_shape(&source, terminal.fault_bound)?);
        Ok(())
    }

    /// Stable trust-domain identifier carried by every party-to-party QUIC frame.
    ///
    /// Routing, operator endpoints, daemon URLs, and TLS certificate paths are deliberately
    /// excluded. They may be rotated without creating a new cryptographic network. Committee
    /// cryptographic material, Byzantine bounds, transition operations, source committee shapes,
    /// deposit birth anchor, and consolidation fee policy are included.
    ///
    /// # Errors
    ///
    /// Returns a configuration error if an epoch specification cannot be resolved to its
    /// cryptographic committee.
    pub fn quic_network_id(&self) -> Result<[u8; 32], ConfigError> {
        let mut specifications = self.committees.iter().collect::<Vec<_>>();
        specifications.sort_unstable_by_key(|specification| specification.epoch);

        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/quic-network-id/v3");
        hasher.update(&self.schema_version.to_le_bytes());
        hasher.update(&[match self.network {
            NetworkKind::Regtest => 0,
            NetworkKind::Testnet => 1,
            NetworkKind::Mainnet => 2,
        }]);
        // Bind the transport trust domain to the actual chain identity we require the daemon to
        // prove at startup. The nettype is included because Monero fakechain and mainnet share a
        // genesis block by design.
        let daemon_nettype = self.network.daemon_nettype().as_bytes();
        hasher.update(&(daemon_nettype.len() as u64).to_le_bytes());
        hasher.update(daemon_nettype);
        hasher.update(&self.network.genesis_hash());
        match self.deposit_birth_anchor {
            Some(anchor) => {
                hasher.update(&[1]);
                hasher.update(&anchor.height.to_le_bytes());
                hasher.update(&anchor.hash.0);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hasher.update(&self.deposit_maximum_fee_atomic_units.to_le_bytes());
        hasher.update(&self.protocol_timeout_seconds.to_le_bytes());
        hasher.update(&self.proactive_refresh_interval_seconds.to_le_bytes());
        let mut parties = self.parties.iter().collect::<Vec<_>>();
        parties.sort_unstable_by_key(|party| party.id);
        hasher.update(&(parties.len() as u64).to_le_bytes());
        for party in parties {
            hasher.update(&party.id.0.to_le_bytes());
            hasher.update(&party.signing_key.0);
            hasher.update(&party.bootstrap_encryption_key.0);
        }
        hasher.update(&(specifications.len() as u64).to_le_bytes());
        for specification in specifications {
            hasher.update(&specification.epoch.to_le_bytes());
            hasher.update(&[match specification.operation {
                Operation::Dkg => 0,
                Operation::Reshare => 1,
            }]);
            hasher.update(&specification.fault_bound.to_le_bytes());
            hasher.update(&self.configured_committee_shape(specification.epoch)?.digest());
            hasher.update(&(specification.eligible_members.len() as u64).to_le_bytes());
            for eligible in &specification.eligible_members {
                hasher.update(&eligible.0.to_le_bytes());
            }
        }
        Ok(*hasher.finalize().as_bytes())
    }

    fn validate_parties(&self) -> Result<(), ConfigError> {
        if self.parties.len() > MAX_SCENARIO_PARTIES {
            return Err(ConfigError::TooManyParties {
                actual: self.parties.len(),
                maximum: MAX_SCENARIO_PARTIES,
            });
        }
        let mut ids = BTreeSet::new();
        let mut quic_endpoints = BTreeSet::new();
        let mut quic_server_names = BTreeSet::new();
        let mut quic_certificate_files = BTreeSet::new();
        let mut monerod_endpoints = BTreeSet::from([self.acceptance_monerod_rpc_url.as_str()]);
        let mut signing_keys = BTreeSet::new();
        let mut bootstrap_encryption_keys = BTreeSet::new();

        for party in &self.parties {
            PartyId::new(party.id.0)?;
            if !ids.insert(party.id) {
                return Err(ConfigError::DuplicateParty(party.id));
            }
            if !signing_keys.insert(party.signing_key.0) {
                return Err(ConfigError::DuplicateSigningKey);
            }
            if !valid_x25519_public_key(party.bootstrap_encryption_key.0) {
                return Err(ConfigError::InvalidBootstrapEncryptionKey(party.id));
            }
            if !bootstrap_encryption_keys.insert(party.bootstrap_encryption_key.0) {
                return Err(ConfigError::DuplicateBootstrapEncryptionKey);
            }
            if !valid_admin_endpoint(&party.admin_endpoint) {
                return Err(ConfigError::InvalidAdminEndpoint(party.id));
            }
            if !valid_quic_endpoint(&party.quic_endpoint) {
                return Err(ConfigError::InvalidQuicEndpoint(party.id));
            }
            if !matches!(
                ServerName::try_from(party.quic_server_name.clone()),
                Ok(ServerName::DnsName(_))
            ) {
                return Err(ConfigError::InvalidQuicServerName(party.id));
            }
            if !valid_certificate_file(&party.quic_certificate_file) {
                return Err(ConfigError::InvalidQuicCertificateFile(party.id));
            }
            if party.monerod_rpc_urls.is_empty()
                || party.monerod_rpc_urls.len() > MAX_MONEROD_ENDPOINTS_PER_PARTY
            {
                return Err(ConfigError::InvalidMonerodEndpointCount(party.id));
            }
            for endpoint in &party.monerod_rpc_urls {
                if !valid_monerod_endpoint(endpoint) {
                    return Err(ConfigError::InvalidMonerodEndpoint(party.id));
                }
                if !monerod_endpoints.insert(endpoint.as_str()) {
                    return Err(ConfigError::DuplicateMonerodEndpoint);
                }
            }
            if !quic_endpoints.insert(party.quic_endpoint.as_str()) {
                return Err(ConfigError::DuplicateQuicEndpoint);
            }
            if !quic_server_names.insert(party.quic_server_name.to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateQuicServerName);
            }
            if !quic_certificate_files.insert(&party.quic_certificate_file) {
                return Err(ConfigError::DuplicateQuicCertificateFile);
            }
        }
        Ok(())
    }

    pub fn committee_spec(&self, epoch: u64) -> Result<&CommitteeSpec, ConfigError> {
        self.committees
            .iter()
            .find(|committee| committee.epoch == epoch)
            .ok_or(ConfigError::NonContiguousEpochs)
    }

    pub fn party(&self, id: PartyId) -> Result<&ScenarioParty, ConfigError> {
        self.parties.iter().find(|party| party.id == id).ok_or(ConfigError::UnknownParty(id))
    }

    /// Materialize the only committee whose X25519 keys are configuration-authoritative.
    pub fn genesis_committee(&self) -> Result<Committee, ConfigError> {
        self.configured_committee_shape(0)
    }

    /// Commit every configured bootstrap receiver key, including keys owned by shareless spares.
    ///
    /// The returned root is the deterministic epoch-zero boundary for receiver-key freshness.
    /// Later policies must use the commitment authenticated by their source epoch-history link,
    /// never reconstruct or extend this bootstrap commitment from configuration.
    pub fn bootstrap_receiver_key_accumulator(
        &self,
        network: [u8; 32],
    ) -> Result<ReceiverKeyAccumulatorCommitment, ConfigError> {
        let mut bootstrap_keys = self
            .parties
            .iter()
            .map(|party| (party.id, party.bootstrap_encryption_key.0))
            .collect::<Vec<_>>();
        bootstrap_keys.sort_unstable_by_key(|(party, _)| *party);
        Ok(ReceiverKeyAccumulatorCommitment::from_bootstrap_keys(network, &bootstrap_keys)?)
    }

    /// Materialize the accumulator-independent governance shape of a configured successor.
    ///
    /// This is suitable for static configuration preflight and for code which only needs to
    /// validate membership shape. It cannot authorize receiver keys or produce a rotation
    /// certificate.
    pub fn configured_key_rotation_target_shape(
        &self,
        source: &Committee,
    ) -> Result<Option<ConfiguredKeyRotationTargetShape>, ConfigError> {
        source.validate()?;
        let target_epoch = source.epoch.checked_add(1).ok_or(ConfigError::NonContiguousEpochs)?;
        let Ok(spec) = self.committee_spec(target_epoch) else {
            return Ok(None);
        };
        let members = spec
            .eligible_members
            .iter()
            .map(|id| {
                let party = self.party(*id)?;
                Ok(Member {
                    id: *id,
                    signing_key: party.signing_key.0,
                    encryption_key: eligibility_reference_key(
                        target_epoch,
                        *id,
                        party.signing_key.0,
                    ),
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;
        let eligible = Committee { epoch: target_epoch, threshold: spec.threshold, members };
        let desired_n =
            u16::try_from(spec.members.len()).map_err(|_| CommitteeError::TooManyMembers {
                members: spec.members.len(),
                maximum: MAX_COMMITTEE_MEMBERS,
            })?;
        Ok(Some(ConfiguredKeyRotationTargetShape::new(
            source,
            eligible,
            desired_n,
            spec.fault_bound,
        )?))
    }

    /// Materialize the configured immediate successor policy against a certified source.
    ///
    /// Every eligible identity must advertise a fresh durable key to be selected. `members`
    /// supplies the desired size and threshold layout; `eligible_members` supplies enough stable
    /// identities to replace up to `f` silent candidates without carrying any source/bootstrap
    /// receiver key. `source_receiver_keys` must be the accumulator commitment authenticated by
    /// the source epoch-history link. `None` means the static governance schedule is exhausted.
    pub fn configured_key_rotation_target_policy(
        &self,
        source: &Committee,
        source_receiver_keys: ReceiverKeyAccumulatorCommitment,
    ) -> Result<Option<KeyRotationTargetPolicy>, ConfigError> {
        let Some(shape) = self.configured_key_rotation_target_shape(source)? else {
            return Ok(None);
        };
        let source_fault_bound = self.committee_spec(source.epoch)?.fault_bound;
        let selection_fallback_window_ms = self
            .protocol_timeout_seconds
            .checked_mul(1_000)
            .ok_or(ConfigError::InvalidProtocolTimeout)?;
        Ok(Some(KeyRotationTargetPolicy::new(
            source,
            source_fault_bound,
            shape.eligible,
            shape.desired_n,
            shape.target_fault_bound,
            source_receiver_keys,
            selection_fallback_window_ms,
        )?))
    }

    fn proactive_refresh_target_shape(
        &self,
        source: &Committee,
        fault_bound: u16,
    ) -> Result<ConfiguredKeyRotationTargetShape, ConfigError> {
        let target_epoch = source.epoch.checked_add(1).ok_or(ConfigError::NonContiguousEpochs)?;
        let eligible = Committee {
            epoch: target_epoch,
            threshold: source.threshold,
            members: self
                .parties
                .iter()
                .map(|party| Member {
                    id: party.id,
                    signing_key: party.signing_key.0,
                    encryption_key: eligibility_reference_key(
                        target_epoch,
                        party.id,
                        party.signing_key.0,
                    ),
                })
                .collect(),
        };
        ConfiguredKeyRotationTargetShape::new(source, eligible, source.n(), fault_bound)
    }

    /// Static membership/threshold resource shape used only for configuration preflight.
    /// Post-genesis X25519 bytes are non-activated public sentinels and are also permanently
    /// forbidden as advertisement keys.
    fn configured_committee_shape(&self, epoch: u64) -> Result<Committee, ConfigError> {
        let spec = self.committee_spec(epoch)?;
        let members = spec
            .members
            .iter()
            .map(|id| {
                let party = self.party(*id)?;
                Ok(Member {
                    id: *id,
                    signing_key: party.signing_key.0,
                    encryption_key: party.bootstrap_encryption_key.0,
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;
        Ok(Committee { epoch, threshold: spec.threshold, members }.canonicalized()?)
    }
}

fn valid_admin_endpoint(endpoint: &Url) -> bool {
    matches!(endpoint.scheme(), "http" | "https")
        && endpoint.host_str().is_some()
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && endpoint.query().is_none()
        && endpoint.fragment().is_none()
}

fn valid_quic_endpoint(endpoint: &Url) -> bool {
    endpoint.scheme() == "quic"
        && endpoint.host_str().is_some()
        && endpoint.port().is_some_and(|port| port != 0)
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && matches!(endpoint.path(), "" | "/")
        && endpoint.query().is_none()
        && endpoint.fragment().is_none()
}

fn valid_monerod_endpoint(endpoint: &Url) -> bool {
    matches!(endpoint.scheme(), "http" | "https")
        && endpoint.host_str().is_some()
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && matches!(endpoint.path(), "" | "/")
        && endpoint.query().is_none()
        && endpoint.fragment().is_none()
}

fn valid_certificate_file(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(component, std::path::Component::RootDir | std::path::Component::Normal(_))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario() -> Scenario {
        Scenario {
            schema_version: SCENARIO_SCHEMA_VERSION,
            demo_only: true,
            network: NetworkKind::Regtest,
            deposit_birth_anchor: None,
            acceptance_monerod_rpc_url: "http://monerod-miner:18081".parse().unwrap(),
            parties: (1..=6)
                .map(|id| ScenarioParty {
                    id: PartyId(id),
                    admin_endpoint: format!("http://p{id}:8080").parse().unwrap(),
                    quic_endpoint: format!("quic://p{id}:8443").parse().unwrap(),
                    quic_server_name: format!("p{id}.threshold-monero.invalid"),
                    quic_certificate_file: PathBuf::from(format!(
                        "/etc/threshold-monero/quic/p{id}-cert.der"
                    )),
                    monerod_rpc_urls: vec![format!("http://monerod-p{id}:18081").parse().unwrap()],
                    signing_key: Hex32([u8::try_from(id).unwrap(); 32]),
                    bootstrap_encryption_key: Hex32([u8::try_from(id + 10).unwrap(); 32]),
                })
                .collect(),
            committees: vec![CommitteeSpec {
                epoch: 0,
                operation: Operation::Dkg,
                threshold: 3,
                fault_bound: 1,
                members: (1..=5).map(PartyId).collect(),
                eligible_members: (1..=5).map(PartyId).collect(),
            }],
            funding_blocks: 1,
            confirmation_blocks: 1,
            deposit_maximum_fee_atomic_units: DEFAULT_DEPOSIT_MAXIMUM_FEE_ATOMIC_UNITS,
            poll_interval_ms: 1,
            protocol_timeout_seconds: 1,
            proactive_refresh_interval_seconds: DEFAULT_PROACTIVE_REFRESH_INTERVAL_SECONDS,
        }
    }

    fn scenario_with_parties(count: u16) -> Scenario {
        let mut scenario = scenario();
        scenario.parties = (1..=count)
            .map(|id| ScenarioParty {
                id: PartyId(id),
                admin_endpoint: format!("http://p{id}:8080").parse().unwrap(),
                quic_endpoint: format!("quic://p{id}:8443").parse().unwrap(),
                quic_server_name: format!("p{id}.threshold-monero.invalid"),
                quic_certificate_file: PathBuf::from(format!(
                    "/etc/threshold-monero/quic/p{id}-cert.der"
                )),
                monerod_rpc_urls: vec![format!("http://monerod-p{id}:18081").parse().unwrap()],
                signing_key: Hex32([u8::try_from(id).unwrap(); 32]),
                bootstrap_encryption_key: Hex32([u8::try_from(id + 32).unwrap(); 32]),
            })
            .collect();
        scenario.committees[0].members = (1..=count).map(PartyId).collect();
        scenario.committees[0].eligible_members = scenario.committees[0].members.clone();
        scenario
    }

    fn reconfiguration_scenario() -> Scenario {
        let mut scenario = scenario_with_parties(8);
        scenario.committees = vec![
            CommitteeSpec {
                epoch: 0,
                operation: Operation::Dkg,
                threshold: 3,
                fault_bound: 1,
                members: (1..=5).map(PartyId).collect(),
                eligible_members: (1..=5).map(PartyId).collect(),
            },
            CommitteeSpec {
                epoch: 1,
                operation: Operation::Reshare,
                threshold: 4,
                fault_bound: 1,
                members: (1..=7).map(PartyId).collect(),
                eligible_members: (1..=8).map(PartyId).collect(),
            },
            CommitteeSpec {
                epoch: 2,
                operation: Operation::Reshare,
                threshold: 3,
                fault_bound: 1,
                members: [2, 3, 4, 6, 7].into_iter().map(PartyId).collect(),
                eligible_members: [2, 3, 4, 6, 7, 8].into_iter().map(PartyId).collect(),
            },
        ];
        scenario
    }

    #[test]
    fn rejects_previous_schema_and_removed_fields() {
        let mut previous = serde_json::to_value(scenario()).unwrap();
        previous["schema_version"] = serde_json::json!(6);
        let previous: Scenario = serde_json::from_value(previous).unwrap();
        assert!(matches!(previous.validate(), Err(ConfigError::Schema(6))));

        let mut missing_demo_only = serde_json::to_value(scenario()).unwrap();
        missing_demo_only.as_object_mut().unwrap().remove("demo_only");
        assert!(serde_json::from_value::<Scenario>(missing_demo_only).is_err());

        let mut missing_birth_anchor = serde_json::to_value(scenario()).unwrap();
        missing_birth_anchor.as_object_mut().unwrap().remove("deposit_birth_anchor");
        assert!(serde_json::from_value::<Scenario>(missing_birth_anchor).is_err());

        let mut missing_eligible = serde_json::to_value(scenario()).unwrap();
        missing_eligible["committees"][0].as_object_mut().unwrap().remove("eligible_members");
        assert!(serde_json::from_value::<Scenario>(missing_eligible).is_err());

        let mut removed_dealers = serde_json::to_value(scenario()).unwrap();
        removed_dealers["committees"][0]["old_dealers"] = serde_json::json!([]);
        assert!(serde_json::from_value::<Scenario>(removed_dealers).is_err());

        let mut shared_daemon = serde_json::to_value(scenario()).unwrap();
        shared_daemon["monerod_rpc_url"] = serde_json::json!("http://shared-daemon:18081");
        assert!(serde_json::from_value::<Scenario>(shared_daemon).is_err());

        let mut consensus_gate = serde_json::to_value(scenario()).unwrap();
        consensus_gate["deposit_consensus_start_epoch"] = serde_json::json!(0);
        assert!(serde_json::from_value::<Scenario>(consensus_gate).is_err());

        for removed in ["identity_seed_secret", "identity_seed_file", "encryption_keys"] {
            let mut obsolete_input = serde_json::to_value(scenario()).unwrap();
            obsolete_input["parties"][0][removed] = serde_json::json!("obsolete");
            assert!(
                serde_json::from_value::<Scenario>(obsolete_input).is_err(),
                "removed field {removed} was accepted"
            );
        }
    }

    #[test]
    fn scenario_accepts_the_resource_maximum() {
        let mut maximum = scenario_with_parties(MAX_COMMITTEE_THRESHOLD);
        maximum.committees[0].threshold = MAX_COMMITTEE_THRESHOLD;
        maximum.committees[0].fault_bound = 0;
        maximum.validate().unwrap();
        let committee = maximum.genesis_committee().unwrap();
        let bounds = preflight_avss_resources(&committee, MAX_AVSS_DEALERS).unwrap();
        assert!(bounds.maximum_wire_message_bytes < crate::avss::MAX_AVSS_WIRE_BODY_BYTES);
        assert!(bounds.maximum_persisted_session_bytes <= crate::storage::MAX_SESSION_STATE_BYTES);
    }

    #[test]
    fn scenario_party_set_is_bounded_for_durable_transport_cursors() {
        let mut maximum = scenario();
        maximum.parties =
            scenario_with_parties(u16::try_from(MAX_SCENARIO_PARTIES).unwrap()).parties;
        maximum.validate_parties().unwrap();

        let oversized_count = MAX_SCENARIO_PARTIES.checked_add(1).unwrap();
        let mut oversized = scenario();
        oversized.parties = scenario_with_parties(u16::try_from(oversized_count).unwrap()).parties;
        assert!(matches!(
            oversized.validate(),
            Err(ConfigError::TooManyParties { actual, maximum })
                if actual == oversized_count && maximum == MAX_SCENARIO_PARTIES
        ));
    }

    #[test]
    fn scenario_rejects_resource_dimensions_before_protocol_construction() {
        let oversized_count = MAX_COMMITTEE_THRESHOLD + 1;
        let mut too_many_members = scenario_with_parties(oversized_count);
        too_many_members.committees[0].threshold = MAX_COMMITTEE_THRESHOLD;
        too_many_members.committees[0].fault_bound = 0;
        assert!(matches!(
            too_many_members.validate(),
            Err(ConfigError::Committee(CommitteeError::TooManyMembers {
                members,
                maximum: MAX_COMMITTEE_MEMBERS,
            })) if members == MAX_COMMITTEE_MEMBERS + 1
        ));

        let mut threshold_too_large = scenario_with_parties(MAX_COMMITTEE_THRESHOLD);
        threshold_too_large.committees[0].threshold = MAX_COMMITTEE_THRESHOLD + 1;
        threshold_too_large.committees[0].fault_bound = 0;
        assert!(matches!(
            threshold_too_large.validate(),
            Err(ConfigError::Committee(CommitteeError::ThresholdTooLarge {
                threshold,
                maximum: MAX_COMMITTEE_THRESHOLD,
            })) if threshold == MAX_COMMITTEE_THRESHOLD + 1
        ));
    }

    #[test]
    fn scenario_rejects_a_threshold_that_cannot_safely_abandon_byzantine_signers() {
        let mut invalid = scenario();
        invalid.committees[0].threshold = 2;
        assert!(matches!(
            invalid.validate(),
            Err(ConfigError::InsufficientSigningThreshold {
                epoch: 0,
                threshold: 2,
                fault_bound: 1,
            })
        ));
    }

    #[test]
    fn routing_is_validated_but_excluded_from_committee_identity() {
        let original = scenario();
        original.validate().unwrap();
        let digest = original.genesis_committee().unwrap().digest();
        let network_id = original.quic_network_id().unwrap();

        let mut moved = original;
        moved.parties[0].admin_endpoint = "https://admin.example:9443".parse().unwrap();
        moved.parties[0].quic_endpoint = "quic://new-route.example:4433".parse().unwrap();
        moved.parties[0].quic_server_name = "new-route.example".into();
        moved.parties[0].quic_certificate_file = "/new/cert.der".into();
        moved.parties[0].monerod_rpc_urls =
            vec!["https://new-observer.example:18081".parse().unwrap()];
        moved.acceptance_monerod_rpc_url = "https://new-miner.example:18081".parse().unwrap();
        moved.validate().unwrap();

        assert_eq!(digest, moved.genesis_committee().unwrap().digest());
        assert_eq!(network_id, moved.quic_network_id().unwrap());
    }

    #[test]
    fn quic_network_id_binds_protocol_trust_configuration() {
        let original = scenario();
        let network_id = original.quic_network_id().unwrap();

        let mut changed_fault_bound = original.clone();
        changed_fault_bound.committees[0].fault_bound = 0;
        assert_ne!(network_id, changed_fault_bound.quic_network_id().unwrap());

        let mut changed_network = original.clone();
        changed_network.network = NetworkKind::Testnet;
        assert_ne!(network_id, changed_network.quic_network_id().unwrap());

        let mut changed_refresh_policy = original.clone();
        changed_refresh_policy.proactive_refresh_interval_seconds += 1;
        assert_ne!(network_id, changed_refresh_policy.quic_network_id().unwrap());

        let mut changed_bootstrap = original.clone();
        changed_bootstrap.parties[0].bootstrap_encryption_key = Hex32([0x61; 32]);
        assert_ne!(network_id, changed_bootstrap.quic_network_id().unwrap());

        let mut changed_fee_policy = original;
        changed_fee_policy.deposit_maximum_fee_atomic_units += 1;
        assert_ne!(network_id, changed_fee_policy.quic_network_id().unwrap());

        let mut changed_birth_anchor = scenario();
        changed_birth_anchor.deposit_birth_anchor =
            Some(DepositBirthAnchor { height: 42, hash: Hex32([0x42; 32]) });
        assert_ne!(network_id, changed_birth_anchor.quic_network_id().unwrap());
    }

    #[test]
    fn monero_network_identity_uses_canonical_nettypes_and_genesis_hashes() {
        assert_eq!(NetworkKind::Regtest.daemon_nettype(), "fakechain");
        assert_eq!(NetworkKind::Testnet.daemon_nettype(), "testnet");
        assert_eq!(NetworkKind::Mainnet.daemon_nettype(), "mainnet");
        assert_eq!(
            hex::encode(NetworkKind::Mainnet.genesis_hash()),
            "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3"
        );
        assert_eq!(
            hex::encode(NetworkKind::Testnet.genesis_hash()),
            "48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cda8430b"
        );
        assert_eq!(NetworkKind::Regtest.genesis_hash(), NetworkKind::Mainnet.genesis_hash());
    }

    #[test]
    fn rejects_zero_deposit_birth_anchor_hash() {
        let mut invalid = scenario();
        invalid.deposit_birth_anchor =
            Some(DepositBirthAnchor { height: 42, hash: Hex32([0; 32]) });
        assert!(matches!(invalid.validate(), Err(ConfigError::InvalidDepositBirthAnchor)));
    }

    #[test]
    fn proactive_refresh_interval_enforces_positive_bounded_policy() {
        let mut minimum = scenario();
        minimum.proactive_refresh_interval_seconds = MIN_PROACTIVE_REFRESH_INTERVAL_SECONDS;
        minimum.validate().unwrap();

        let mut maximum = scenario();
        maximum.proactive_refresh_interval_seconds = MAX_PROACTIVE_REFRESH_INTERVAL_SECONDS;
        maximum.validate().unwrap();

        let mut zero = scenario();
        zero.proactive_refresh_interval_seconds = 0;
        assert!(matches!(zero.validate(), Err(ConfigError::InvalidProactiveRefreshInterval)));

        let mut above_maximum = scenario();
        above_maximum.proactive_refresh_interval_seconds =
            MAX_PROACTIVE_REFRESH_INTERVAL_SECONDS + 1;
        assert!(matches!(
            above_maximum.validate(),
            Err(ConfigError::InvalidProactiveRefreshInterval)
        ));
    }

    #[test]
    fn protocol_timeout_is_positive_and_bound_into_the_transport_network() {
        let baseline_scenario = scenario();
        let baseline = baseline_scenario.quic_network_id().unwrap();

        let mut changed = baseline_scenario.clone();
        changed.protocol_timeout_seconds = changed.protocol_timeout_seconds.checked_add(1).unwrap();
        changed.validate().unwrap();
        assert_ne!(changed.quic_network_id().unwrap(), baseline);

        let mut zero = baseline_scenario;
        zero.protocol_timeout_seconds = 0;
        assert!(matches!(zero.validate(), Err(ConfigError::InvalidProtocolTimeout)));

        let maximum_seconds = (u64::MAX - MAX_SUPPORTED_UNIX_MILLISECONDS)
            / (1_u64 << MAX_BFT_VIEW_TIMEOUT_SHIFT)
            / 1_000;
        let mut maximum = scenario();
        maximum.protocol_timeout_seconds = maximum_seconds;
        maximum.validate().unwrap();

        let mut overflow = maximum;
        overflow.protocol_timeout_seconds = maximum_seconds + 1;
        assert!(matches!(overflow.validate(), Err(ConfigError::InvalidProtocolTimeout)));
    }

    #[test]
    fn non_demo_proactive_refresh_interval_enforces_storage_rate_floor() {
        assert_eq!(MIN_NON_DEMO_PROACTIVE_REFRESH_INTERVAL_SECONDS, 3_600);

        let mut below_minimum = scenario();
        below_minimum.demo_only = false;
        below_minimum.proactive_refresh_interval_seconds = 3_599;
        assert!(matches!(
            below_minimum.validate(),
            Err(ConfigError::NonDemoProactiveRefreshIntervalTooShort)
        ));

        let mut minimum = scenario();
        minimum.demo_only = false;
        minimum.proactive_refresh_interval_seconds = 3_600;
        minimum.validate().unwrap();

        let mut demo_regtest = scenario();
        demo_regtest.proactive_refresh_interval_seconds = 1;
        demo_regtest.validate().unwrap();
    }

    #[test]
    fn rejects_zero_deposit_fee_policy() {
        let mut invalid = scenario();
        invalid.deposit_maximum_fee_atomic_units = 0;
        assert!(matches!(invalid.validate(), Err(ConfigError::InvalidDepositMaximumFee)));
    }

    #[test]
    fn rejects_wrong_schemes_and_duplicate_certificate_paths() {
        let mut wrong_scheme = scenario();
        wrong_scheme.parties[0].quic_endpoint = "http://p1:8443".parse().unwrap();
        assert!(matches!(
            wrong_scheme.validate(),
            Err(ConfigError::InvalidQuicEndpoint(PartyId(1)))
        ));

        let mut duplicate_pin = scenario();
        duplicate_pin.parties[1].quic_certificate_file =
            duplicate_pin.parties[0].quic_certificate_file.clone();
        assert!(matches!(duplicate_pin.validate(), Err(ConfigError::DuplicateQuicCertificateFile)));

        let mut missing_observer = scenario();
        missing_observer.parties[0].monerod_rpc_urls.clear();
        assert!(matches!(
            missing_observer.validate(),
            Err(ConfigError::InvalidMonerodEndpointCount(PartyId(1)))
        ));

        let mut duplicate_observer = scenario();
        duplicate_observer.parties[1].monerod_rpc_urls =
            duplicate_observer.parties[0].monerod_rpc_urls.clone();
        assert!(matches!(
            duplicate_observer.validate(),
            Err(ConfigError::DuplicateMonerodEndpoint)
        ));

        let mut invalid_observer = scenario();
        invalid_observer.parties[0].monerod_rpc_urls =
            vec!["file:///tmp/monerod.sock".parse().unwrap()];
        assert!(matches!(
            invalid_observer.validate(),
            Err(ConfigError::InvalidMonerodEndpoint(PartyId(1)))
        ));
    }

    #[test]
    fn rejects_non_dns_tls_name_and_remote_admin_scheme() {
        let mut ip_server_name = scenario();
        ip_server_name.parties[0].quic_server_name = "127.0.0.1".into();
        assert!(matches!(
            ip_server_name.validate(),
            Err(ConfigError::InvalidQuicServerName(PartyId(1)))
        ));

        let mut file_admin = scenario();
        file_admin.parties[0].admin_endpoint = "file:///tmp/admin.sock".parse().unwrap();
        assert!(matches!(
            file_admin.validate(),
            Err(ConfigError::InvalidAdminEndpoint(PartyId(1)))
        ));

        let mut relative_certificate = scenario();
        relative_certificate.parties[0].quic_certificate_file = "quic/p1-cert.der".into();
        assert!(matches!(
            relative_certificate.validate(),
            Err(ConfigError::InvalidQuicCertificateFile(PartyId(1)))
        ));
    }

    #[test]
    fn bootstrap_keys_are_separate_unique_and_current_only() {
        let scenario = scenario();
        scenario.validate().unwrap();
        let genesis = scenario.genesis_committee().unwrap();
        for member in &genesis.members {
            assert_eq!(
                member.encryption_key,
                scenario.party(member.id).unwrap().bootstrap_encryption_key.0
            );
        }
        assert!(scenario.configured_key_rotation_target_shape(&genesis).unwrap().is_none());

        let mut invalid = scenario.clone();
        invalid.parties[0].bootstrap_encryption_key = Hex32([0_u8; 32]);
        assert!(matches!(
            invalid.validate(),
            Err(ConfigError::InvalidBootstrapEncryptionKey(PartyId(1)))
        ));

        let mut duplicate = scenario;
        duplicate.parties[1].bootstrap_encryption_key =
            duplicate.parties[0].bootstrap_encryption_key;
        assert!(matches!(duplicate.validate(), Err(ConfigError::DuplicateBootstrapEncryptionKey)));
    }

    #[test]
    fn bootstrap_accumulator_commits_every_configured_party_including_spares() {
        let scenario = scenario();
        scenario.validate().unwrap();
        let network = scenario.quic_network_id().unwrap();
        let commitment = scenario.bootstrap_receiver_key_accumulator(network).unwrap();

        let all_bootstrap_keys = scenario
            .parties
            .iter()
            .map(|party| (party.id, party.bootstrap_encryption_key.0))
            .collect::<Vec<_>>();
        let expected =
            ReceiverKeyAccumulatorCommitment::from_bootstrap_keys(network, &all_bootstrap_keys)
                .unwrap();
        assert_eq!(commitment, expected);

        let genesis = scenario.genesis_committee().unwrap();
        let genesis_only = genesis
            .members
            .iter()
            .map(|member| (member.id, member.encryption_key))
            .collect::<Vec<_>>();
        let missing_spare =
            ReceiverKeyAccumulatorCommitment::from_bootstrap_keys(network, &genesis_only).unwrap();
        assert_ne!(commitment, missing_spare);

        let mut reordered = scenario;
        reordered.parties.reverse();
        assert_eq!(
            commitment,
            reordered.bootstrap_receiver_key_accumulator(network).unwrap(),
            "scenario ordering must not alter the bootstrap accumulator"
        );
    }

    #[test]
    fn configured_policy_requires_an_explicit_authenticated_source_accumulator() {
        let scenario = reconfiguration_scenario();
        scenario.validate().unwrap();
        let source = scenario.genesis_committee().unwrap();
        let source_receiver_keys = scenario
            .bootstrap_receiver_key_accumulator(scenario.quic_network_id().unwrap())
            .unwrap();
        let policy = scenario
            .configured_key_rotation_target_policy(&source, source_receiver_keys)
            .unwrap()
            .expect("configured grow policy");

        assert_eq!(policy.target_epoch(), 1);
        assert_eq!(policy.desired_n(), 7);
        assert_eq!(policy.target_fault_bound(), 1);
        assert_eq!(policy.eligible().n(), 8);
    }

    #[test]
    fn configured_rotation_policy_materializes_spare_backed_eligible_pools() {
        let scenario = reconfiguration_scenario();
        scenario.validate().unwrap();

        let mut source = scenario.genesis_committee().unwrap();
        for member in &mut source.members {
            member.encryption_key = [0x40_u8 + u8::try_from(member.id.0).unwrap(); 32];
        }
        source.validate().unwrap();
        let grow = scenario
            .configured_key_rotation_target_shape(&source)
            .unwrap()
            .expect("configured grow shape");
        assert_eq!(grow.eligible().epoch, 1);
        assert_eq!(grow.eligible().threshold, 4);
        assert_eq!(grow.target_fault_bound(), 1);
        assert_eq!(grow.desired_n(), 7);
        for party in 1..=8 {
            let party = PartyId(party);
            assert_eq!(
                grow.eligible().member(party).unwrap().encryption_key,
                eligibility_reference_key(
                    grow.target_epoch(),
                    party,
                    scenario.party(party).unwrap().signing_key.0,
                )
            );
            assert_ne!(
                grow.eligible().member(party).unwrap().encryption_key,
                scenario.party(party).unwrap().bootstrap_encryption_key.0
            );
        }

        let mut certified_grow = Committee {
            epoch: grow.target_epoch(),
            threshold: grow.eligible().threshold,
            members: grow.eligible().members[..7].to_vec(),
        };
        for member in &mut certified_grow.members {
            member.encryption_key = [0x60_u8 + u8::try_from(member.id.0).unwrap(); 32];
        }
        certified_grow.validate().unwrap();
        let shrink = scenario
            .configured_key_rotation_target_shape(&certified_grow)
            .unwrap()
            .expect("configured shrink shape");
        assert_eq!(shrink.eligible().threshold, 3);
        assert_eq!(shrink.desired_n(), 5);
        assert_eq!(shrink.target_fault_bound(), 1);
        assert_eq!(shrink.eligible().n(), 6);
        assert_eq!(
            shrink.eligible().members.iter().map(|member| member.id).collect::<Vec<_>>(),
            vec![PartyId(2), PartyId(3), PartyId(4), PartyId(6), PartyId(7), PartyId(8),]
        );
        for member in &shrink.eligible().members {
            assert_eq!(
                member.encryption_key,
                eligibility_reference_key(
                    shrink.target_epoch(),
                    member.id,
                    scenario.party(member.id).unwrap().signing_key.0,
                )
            );
        }
    }

    #[test]
    fn configured_party_can_reenter_only_through_the_fresh_advertisement_pool() {
        let mut scenario = reconfiguration_scenario();
        scenario.committees[1].members.retain(|party| *party != PartyId(1));
        scenario.committees[2].members.retain(|party| *party != PartyId(2));
        scenario.committees[2].members.push(PartyId(1));
        scenario.committees[2].members.sort_unstable();
        scenario.committees[2].eligible_members.push(PartyId(1));
        scenario.committees[2].eligible_members.sort_unstable();
        scenario.validate().unwrap();
    }
}
