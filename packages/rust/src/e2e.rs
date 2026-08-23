//! Docker/regtest acceptance runner.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::Context as _;
use curve25519_dalek::{
    Scalar as DalekScalar, constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY,
};
use monero_oxide::transaction::Input;
use monero_simple_request_rpc::{SimpleRequestTransport, prelude::MoneroDaemon};
use monero_wallet::{
    DEFAULT_LOCK_WINDOW, OutputWithDecoys, Scanner, ViewPair,
    address::{MoneroAddress, Network, SubaddressIndex},
    ed25519::{Point, Scalar},
    interface::prelude::*,
    ringct::RctType,
    send::{Change, SignableTransaction},
    transaction::Transaction,
};
use rand_core::{OsRng, RngCore};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    auth::bearer_token_digest,
    committee::{Committee, Member, PartyId, SessionId},
    compact_epoch_registry::{ActiveIssuer, CompactEpochRegistry, VerifiedIssuerWindow},
    config::{NetworkKind, Scenario},
    deposit_clock::RegtestClockWriter,
    deposit_consolidation::{ConsolidationId, consolidation_signed_bytes_binding},
    deposit_ledger::{
        CertifiedLedgerEntry, LedgerPayload, LedgerRequestId, LedgerStatement, RequestBinding,
        UNUSED_ALLOCATION_TTL_SECONDS,
    },
    deposit_service::{
        DepositAddressRequest, PublicConsolidationPhase, PublicConsolidationStatus,
        PublicLiveConsolidationStatus, deposit_request_id_for_binding,
    },
    deposit_wallet::{
        CanonicalDepositAddress, ChainPoint, DepositAddressDeriver, SweepId, WalletOutputId,
    },
    deposit_worker::{DepositWorkerConfig, root_consolidation_destination_binding},
    epoch_history::{EpochHistoryLink, EpochHistoryParent},
    key_rotation::eligibility_reference_key,
    keys::EpochPublic,
    server::{
        AcceptanceDriverLatchKind, AcceptanceProactiveRefreshReleaseRequest,
        AcceptanceProactiveRefreshReleaseResponse, AvssStartRequest, AvssStepResponse,
        AvssTransition, DealPurpose, DepositConsolidationStatusRequest,
        DepositConsolidationStatusResponse, DepositHttpResponse, DepositHttpStatus, PartyStatus,
        acceptance_driver_binding, canonical_dkg_transition, canonical_refresh_session,
        canonical_reshare_session,
    },
};

const CONSOLIDATION_PRIMARY_OUTPUT_ATOMIC_UNITS: u64 = 1;
const INITIAL_ACCEPTANCE_DEPOSIT_OUTPUTS: usize = 2;
const REQUIRED_ACCEPTANCE_FUNDING_OUTPUTS: u64 = 6;
const DEPOSIT_ALLOCATION_ISSUANCE_LEAD_SECONDS: u64 = 60;
const DEPOSIT_TTL_ACCEPTANCE_FLAG: &str = "TM_E2E_DEPOSIT_TTL_ACCEPTANCE";
const ACCEPTANCE_HTTP_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// A certified committee handoff serializes four independently durable BFT stages: the terminal
/// Fence ledger slot, its portable checkpoint, the final Handoff ledger slot, and its checkpoint.
/// Each stage may legitimately consume one configured protocol window before the next exists.
const DEPOSIT_HANDOFF_ACCEPTANCE_WINDOWS: u32 = 4;

/// E2E campaigns which inspect the active ROAST transcript construct this wrapper only when the
/// optional hot view is present. Dereferencing keeps those checks readable, while `.0.portable`
/// remains available for the separate post-compaction/handoff assertion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ObservedConsolidation(PublicConsolidationStatus);

impl ObservedConsolidation {
    fn from_public(status: PublicConsolidationStatus) -> anyhow::Result<Self> {
        anyhow::ensure!(
            status.live.is_some(),
            "consolidation exposed portable terminal evidence but no live diagnostic state"
        );
        Ok(Self(status))
    }

    /// Compare the witness-independent consolidation decision reported by two replicas.
    ///
    /// Honest replicas may persist different canonical `n-f` witness subsets for the same BA,
    /// ROAST-intent, or ledger decision. Candidate relays can likewise leave different supersets
    /// of already sufficient `f+1` evidence in hot diagnostic state. Those differences are useful
    /// attribution data, but they are not forks. Every statement, transaction, attempt, key-image
    /// binding, phase, and chain point remains part of the comparison.
    fn same_quorum_decision(&self, other: &Self) -> bool {
        quorum_decision_projection(&self.0) == quorum_decision_projection(&other.0)
    }
}

fn quorum_decision_projection(status: &PublicConsolidationStatus) -> PublicConsolidationStatus {
    let mut projected = status.clone();
    if let Some(portable) = projected.portable.as_mut() {
        portable.current_certificate.attestations.clear();
        if let Some(abandonment) = portable.abandonment_certificate.as_mut() {
            abandonment.attestations.clear();
        }
    }
    if let Some(live) = projected.live.as_mut() {
        live.bootstrap_ba_view = 0;
        live.bootstrap_ba_proposer = PartyId(1);
        live.bootstrap_certificate_signers.clear();
        live.roast_candidate_count = 0;
        live.roast_endorsed_candidate_count = 0;
        live.roast_intent_certificate_signers.clear();
        live.roast_endorsed_witness_count = 0;
        live.roast_endorsed_evidence_digest = [0; 32];
        live.completion_certificate_signers.clear();
    }
    projected
}

fn same_portable_consolidation_decision(
    left: &PublicConsolidationStatus,
    right: &PublicConsolidationStatus,
) -> bool {
    quorum_decision_projection(left).portable == quorum_decision_projection(right).portable
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EqualObservationGroup<T> {
    value: T,
    parties: BTreeSet<PartyId>,
}

fn record_equal_observation<T: Eq>(
    groups: &mut Vec<EqualObservationGroup<T>>,
    party: PartyId,
    value: T,
) {
    for group in groups.iter_mut() {
        group.parties.remove(&party);
    }
    groups.retain(|group| !group.parties.is_empty());
    if let Some(group) = groups.iter_mut().find(|group| group.value == value) {
        group.parties.insert(party);
    } else {
        groups.push(EqualObservationGroup { value, parties: BTreeSet::from([party]) });
    }
}

fn equal_observation_quorum<'a, T>(
    groups: &'a [EqualObservationGroup<T>],
    required: usize,
    required_parties: &BTreeSet<PartyId>,
) -> anyhow::Result<Option<&'a EqualObservationGroup<T>>> {
    anyhow::ensure!(required > 0, "exact observation quorum must be positive");
    let mut matching = groups.iter().filter(|group| group.parties.len() >= required);
    let quorum = matching.next();
    anyhow::ensure!(
        matching.next().is_none(),
        "multiple conflicting exact observation groups reached quorum"
    );
    Ok(quorum.filter(|group| required_parties.iter().all(|party| group.parties.contains(party))))
}

impl Deref for ObservedConsolidation {
    type Target = PublicLiveConsolidationStatus;

    fn deref(&self) -> &Self::Target {
        self.0.live.as_ref().expect("validated live consolidation status")
    }
}

impl DerefMut for ObservedConsolidation {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.live.as_mut().expect("validated live consolidation status")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ConsolidationFaultProof {
    fault_party: PartyId,
    initial_view: u64,
    initial_view_count: u16,
    initial_relay_seed: PartyId,
    initial_signers: Vec<PartyId>,
    initial_intent_certificate_digest: [u8; 32],
    initial_attempt_binding_digest: [u8; 32],
    completed_view: u64,
    completed_view_count: u16,
    completed_relay_seed: PartyId,
    completed_signers: Vec<PartyId>,
    completed_intent_certificate_digest: [u8; 32],
    completed_attempt_binding_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingConsolidationFault {
    authorization: ConsolidationId,
    fault_party: PartyId,
    initial_view: u64,
    initial_view_count: u16,
    initial_relay_seed: PartyId,
    initial_signers: Vec<PartyId>,
    initial_intent_certificate_digest: [u8; 32],
    initial_attempt_binding_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingConsolidationBootstrapFault {
    sweep: SweepId,
    fault_party: PartyId,
    initial_ba_view: u64,
    initial_prepared_intent_digest: [u8; 32],
    prepared_intent_candidates: BTreeMap<PartyId, [u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConsolidationBootstrapProof {
    sweep: SweepId,
    fault_party: PartyId,
    initial_ba_view: u64,
    initial_prepared_intent_digest: [u8; 32],
    certified_ba_view: u64,
    certified_proposer: PartyId,
    certified_prepared_intent_digest: [u8; 32],
    certificate_digest: [u8; 32],
    certificate_signers: Vec<PartyId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AcceptanceConsolidationGateAction {
    Arm,
    Status,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct AcceptanceConsolidationGateRequest {
    action: AcceptanceConsolidationGateAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AcceptanceConsolidationGateState {
    Disarmed,
    Armed,
    Held,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
struct AcceptanceConsolidationGateResponse {
    party: PartyId,
    state: AcceptanceConsolidationGateState,
    authorization: Option<ConsolidationId>,
    roast_view: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
struct AcceptanceConsolidationBootstrapGateResponse {
    party: PartyId,
    state: AcceptanceConsolidationGateState,
    sweep: Option<SweepId>,
    bootstrap_ba_view: Option<u64>,
    proposer: Option<PartyId>,
    prepared_intent_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AcceptanceProtocolFaultBoundary {
    DealerStarted,
    QualRoundZero,
}

impl AcceptanceProtocolFaultBoundary {
    const fn marker(self) -> &'static str {
        match self {
            Self::DealerStarted => "dealer_started",
            Self::QualRoundZero => "qual_round_zero",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct AcceptanceProtocolFaultGateRequest {
    action: AcceptanceConsolidationGateAction,
    session: SessionId,
    epoch: u64,
    boundary: AcceptanceProtocolFaultBoundary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
struct AcceptanceProtocolFaultGateResponse {
    party: PartyId,
    state: AcceptanceConsolidationGateState,
    session: Option<SessionId>,
    epoch: Option<u64>,
    boundary: Option<AcceptanceProtocolFaultBoundary>,
    dealer: Option<PartyId>,
    qual_round: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct AcceptanceDriverLatchRequest {
    action: AcceptanceConsolidationGateAction,
    kind: AcceptanceDriverLatchKind,
    binding: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
struct AcceptanceDriverLatchResponse {
    party: PartyId,
    state: AcceptanceConsolidationGateState,
    kind: Option<AcceptanceDriverLatchKind>,
    binding: Option<[u8; 32]>,
    event_unix_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct AcceptanceDepositCheckpointGateRequest {
    action: AcceptanceConsolidationGateAction,
    output: WalletOutputId,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
struct AcceptanceDepositCheckpointEvidence {
    portable_index_digest: [u8; 32],
    checkpoint_statement_digest: [u8; 32],
    checkpoint_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
struct AcceptanceDepositCheckpointGateResponse {
    party: PartyId,
    state: AcceptanceConsolidationGateState,
    output: Option<WalletOutputId>,
    evidence: Option<AcceptanceDepositCheckpointEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AcceptanceProtocolFaultSpecification {
    epoch: u64,
    boundary: AcceptanceProtocolFaultBoundary,
    party: PartyId,
}

#[derive(Clone)]
struct PartyClient {
    http: reqwest::Client,
    admin_endpoints: BTreeMap<PartyId, url::Url>,
    admin_authorizations: BTreeMap<PartyId, HeaderValue>,
    deposit_authorizations: Option<BTreeMap<PartyId, HeaderValue>>,
    poll_interval: std::time::Duration,
    protocol_timeout: std::time::Duration,
    network_id: [u8; 32],
    avss_start_calls: Arc<AtomicU64>,
}

impl PartyClient {
    async fn new(timeout: std::time::Duration, scenario: &Scenario) -> anyhow::Result<Self> {
        let mut admin_endpoints = BTreeMap::new();
        for party in &scenario.parties {
            anyhow::ensure!(
                admin_endpoints.insert(party.id, party.admin_endpoint.clone()).is_none(),
                "duplicate admin route for party {}",
                party.id
            );
        }
        let admin_authorizations = read_party_bearer_authorizations(
            "TM_E2E_ADMIN_BEARER_TOKEN_DIRECTORY",
            scenario,
            "admin",
        )
        .await?;
        let deposit_authorizations =
            if std::env::var_os("TM_E2E_DEPOSIT_BEARER_TOKEN_DIRECTORY").is_some() {
                Some(
                    read_party_bearer_authorizations(
                        "TM_E2E_DEPOSIT_BEARER_TOKEN_DIRECTORY",
                        scenario,
                        "deposit",
                    )
                    .await?,
                )
            } else {
                None
            };
        Ok(Self {
            // Every control-plane operation is immediate and idempotent. Bound each party
            // independently so one Byzantine HTTP endpoint cannot consume the whole protocol
            // observation deadline before honest n-f responses are sampled.
            http: reqwest::Client::builder()
                .timeout(timeout.min(ACCEPTANCE_HTTP_REQUEST_TIMEOUT))
                .build()?,
            admin_endpoints,
            admin_authorizations,
            deposit_authorizations,
            poll_interval: std::time::Duration::from_millis(scenario.poll_interval_ms),
            protocol_timeout: timeout,
            network_id: scenario.quic_network_id()?,
            avss_start_calls: Arc::new(AtomicU64::new(0)),
        })
    }

    fn endpoint(&self, party: PartyId, path: &str) -> anyhow::Result<url::Url> {
        self.admin_endpoints
            .get(&party)
            .with_context(|| format!("missing admin route for party {party}"))?
            .join(path)
            .map_err(Into::into)
    }

    async fn post_authenticated<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        party: PartyId,
        path: &str,
        request: &T,
        authorization: &HeaderValue,
    ) -> anyhow::Result<R> {
        let endpoint = self.endpoint(party, path)?;
        let response = self
            .http
            .post(endpoint.clone())
            .header(AUTHORIZATION, authorization.clone())
            .json(request)
            .send()
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            anyhow::bail!(
                "party {party} {path} returned {status}: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        serde_json::from_slice(&bytes).with_context(|| format!("decoding response from {endpoint}"))
    }

    async fn post_admin<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        party: PartyId,
        path: &str,
        request: &T,
    ) -> anyhow::Result<R> {
        if path == "/v1/avss/start" {
            self.avss_start_calls.fetch_add(1, Ordering::Relaxed);
        }
        let authorization = self
            .admin_authorizations
            .get(&party)
            .with_context(|| format!("missing admin credential for party {party}"))?;
        self.post_authenticated(party, path, request, authorization).await
    }

    fn avss_start_calls(&self) -> u64 {
        self.avss_start_calls.load(Ordering::Relaxed)
    }

    async fn post_deposit<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        party: PartyId,
        path: &str,
        request: &T,
    ) -> anyhow::Result<R> {
        let authorization = self
            .deposit_authorizations
            .as_ref()
            .context("deposit acceptance requires TM_E2E_DEPOSIT_BEARER_TOKEN_DIRECTORY")?
            .get(&party)
            .with_context(|| format!("missing deposit credential for party {party}"))?;
        self.post_authenticated(party, path, request, authorization).await
    }

    async fn get_admin<R: DeserializeOwned>(
        &self,
        party: PartyId,
        path: &str,
    ) -> anyhow::Result<R> {
        let endpoint = self.endpoint(party, path)?;
        let authorization = self
            .admin_authorizations
            .get(&party)
            .with_context(|| format!("missing admin credential for party {party}"))?;
        let response = self
            .http
            .get(endpoint.clone())
            .header(AUTHORIZATION, authorization.clone())
            .send()
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            anyhow::bail!(
                "party {party} {path} returned {status}: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        serde_json::from_slice(&bytes).with_context(|| format!("decoding response from {endpoint}"))
    }
}

async fn read_party_bearer_authorizations(
    environment_variable: &str,
    scenario: &Scenario,
    role: &str,
) -> anyhow::Result<BTreeMap<PartyId, HeaderValue>> {
    let directory = std::env::var_os(environment_variable)
        .with_context(|| format!("{environment_variable} is required"))?;
    let directory = std::path::PathBuf::from(directory);
    let mut result = BTreeMap::new();
    for configured in &scenario.parties {
        let path = directory.join(format!("p{}-{role}-bearer-token", configured.id.0));
        let authorization = read_bearer_authorization_file(&path).await.with_context(|| {
            format!(
                "reading {role} credential for party {} from {environment_variable}",
                configured.id
            )
        })?;
        anyhow::ensure!(
            result.insert(configured.id, authorization).is_none(),
            "duplicate {role} credential target for party {}",
            configured.id
        );
    }
    Ok(result)
}

async fn read_bearer_authorization_file(path: &std::path::Path) -> anyhow::Result<HeaderValue> {
    let mut token = Zeroizing::new(tokio::fs::read(path).await?);
    while matches!(token.last(), Some(b'\r' | b'\n')) {
        token.pop();
    }
    bearer_token_digest(&token).context("invalid bearer token")?;

    let mut authorization = Zeroizing::new(Vec::with_capacity(7 + token.len()));
    authorization.extend_from_slice(b"Bearer ");
    authorization.extend_from_slice(&token);
    let mut value = HeaderValue::from_bytes(&authorization).context("invalid HTTP bearer value")?;
    value.set_sensitive(true);
    token.zeroize();
    authorization.zeroize();
    Ok(value)
}

#[derive(Clone, Debug)]
struct CertifiedDeposit {
    request: DepositAddressRequest,
    response: DepositHttpResponse,
    allocation_issuer: ActiveIssuer,
    funded_outputs: Vec<DepositOutputEvidence>,
}

/// Witness-independent identity of one fully validated Active allocation response.
///
/// The routing leader and certificate attestations are intentionally absent: honest replicas may
/// use different consensus views and different valid `n-f` witness subsets. Everything that can
/// select another allocation or compact-registry root remains part of exact quorum equality.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedDepositAllocationCandidate {
    allocation_issuer: ActiveIssuer,
    statement: LedgerStatement,
    address: CanonicalDepositAddress,
    created_at: u64,
    expires_at: u64,
    serving_registry: CompactEpochRegistry,
    issuer: VerifiedIssuerWindow,
}

#[derive(Clone, Debug)]
struct ValidatedDepositAllocationResponse {
    candidate: ValidatedDepositAllocationCandidate,
    response: DepositHttpResponse,
}

fn certified_deposit_candidate_quorum(
    request: DepositAddressRequest,
    groups: &[EqualObservationGroup<ValidatedDepositAllocationCandidate>],
    responses: &BTreeMap<PartyId, ValidatedDepositAllocationResponse>,
    required: usize,
    required_parties: &BTreeSet<PartyId>,
) -> anyhow::Result<Option<(CertifiedDeposit, Vec<PartyId>)>> {
    let Some(group) = equal_observation_quorum(groups, required, required_parties)? else {
        return Ok(None);
    };
    let representative =
        *group.parties.first().context("deposit candidate quorum has no representative")?;
    let validated = responses
        .get(&representative)
        .context("deposit candidate quorum omitted its representative response")?;
    anyhow::ensure!(
        validated.candidate == group.value,
        "deposit candidate representative differs from its exact quorum"
    );
    Ok(Some((
        CertifiedDeposit {
            request,
            response: validated.response.clone(),
            allocation_issuer: group.value.allocation_issuer.clone(),
            funded_outputs: Vec::new(),
        },
        group.parties.iter().copied().collect(),
    )))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScheduledDeposit {
    request: DepositAddressRequest,
    created_at: u64,
    expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DepositTtlAllocationFacts {
    request: [u8; 32],
    sequence: u64,
    account: u32,
    address_index: u32,
    address: String,
    created_at: u64,
    expires_at: u64,
    statement: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DepositOutputEvidence {
    id: WalletOutputId,
    index_on_blockchain: u64,
    amount_atomic_units: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SuccessorEpochSigningAcceptance {
    epoch: u64,
    transaction: [u8; 32],
    input_count: usize,
    exact_transaction_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExactRefreshEvidence {
    members: Vec<PartyId>,
    source_verification_shares: [u8; 32],
    target_verification_shares: [u8; 32],
    refresh_transition_digest: [u8; 32],
    reshare_transition_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptanceDepositFaultMode {
    ObserverFork,
    DepositCheckpoint,
}

fn parse_acceptance_deposit_fault_mode(mode: &str) -> anyhow::Result<AcceptanceDepositFaultMode> {
    match mode {
        "observer_fork" => Ok(AcceptanceDepositFaultMode::ObserverFork),
        "deposit_checkpoint" => Ok(AcceptanceDepositFaultMode::DepositCheckpoint),
        value => anyhow::bail!(
            "TM_ACCEPTANCE_DEPOSIT_FAULT_MODE must be observer_fork or deposit_checkpoint, got {value:?}"
        ),
    }
}

fn configured_acceptance_deposit_fault_mode() -> anyhow::Result<Option<AcceptanceDepositFaultMode>>
{
    if std::env::var("TM_ACCEPTANCE_ENABLE_FAULT_HOOKS").as_deref() != Ok("1")
        || std::env::var("TM_ACCEPTANCE_PAUSE_AFTER_DEPOSIT_FUNDING").as_deref() != Ok("1")
    {
        return Ok(None);
    }
    let mode = std::env::var("TM_ACCEPTANCE_DEPOSIT_FAULT_MODE")
        .context("deposit fault hook requires TM_ACCEPTANCE_DEPOSIT_FAULT_MODE")?;
    parse_acceptance_deposit_fault_mode(&mode).map(Some)
}

fn deposit_fault_confirmation_plan(
    mode: Option<AcceptanceDepositFaultMode>,
    confirmation_blocks: u64,
) -> anyhow::Result<(u64, u64)> {
    let remaining = confirmation_blocks
        .checked_sub(1)
        .context("deposit confirmation block count must be positive")?;
    if mode == Some(AcceptanceDepositFaultMode::DepositCheckpoint) {
        Ok((remaining, 0))
    } else {
        Ok((0, remaining))
    }
}

fn environment_flag(name: &str) -> anyhow::Result<bool> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(false);
    };
    let value = value.to_string_lossy();
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => anyhow::bail!("{name} must be one of 1/0, true/false, or yes/no"),
    }
}

fn exact_deposit_ttl_acceptance_flag() -> anyhow::Result<bool> {
    let Some(value) = std::env::var_os(DEPOSIT_TTL_ACCEPTANCE_FLAG) else {
        return Ok(false);
    };
    match value
        .to_str()
        .with_context(|| format!("{DEPOSIT_TTL_ACCEPTANCE_FLAG} must be valid UTF-8"))?
    {
        "0" => Ok(false),
        "1" => Ok(true),
        value => {
            anyhow::bail!("{DEPOSIT_TTL_ACCEPTANCE_FLAG} must be exactly 0 or 1, got {value:?}")
        }
    }
}

fn require_exact_environment_value(name: &str, expected: &str) -> anyhow::Result<()> {
    let value = std::env::var(name).with_context(|| {
        format!("focused deposit-TTL acceptance requires explicit {name}={expected}")
    })?;
    anyhow::ensure!(
        value == expected,
        "focused deposit-TTL acceptance requires exactly {name}={expected}, got {value:?}"
    );
    Ok(())
}

fn configured_deposit_ttl_clock(
    scenario: &Scenario,
    enabled: bool,
    deposits_enabled: bool,
    consolidation_required: bool,
    protocol_only: bool,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<Option<RegtestClockWriter>> {
    if !enabled {
        return Ok(None);
    }
    require_exact_environment_value("TM_E2E_PROTOCOL_ONLY", "0")?;
    require_exact_environment_value("TM_E2E_DEPOSITS", "1")?;
    require_exact_environment_value("TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION", "0")?;
    require_exact_environment_value(DEPOSIT_TTL_ACCEPTANCE_FLAG, "1")?;
    anyhow::ensure!(
        scenario.demo_only && scenario.network == NetworkKind::Regtest,
        "focused deposit-TTL acceptance is restricted to a demo-only private Regtest scenario"
    );
    anyhow::ensure!(
        deposits_enabled && !consolidation_required && !protocol_only,
        "focused deposit-TTL acceptance requires deposits only, with protocol-only and consolidation disabled"
    );
    anyhow::ensure!(
        acceptance_proactive_refresh_hold_enabled()?,
        "focused deposit-TTL acceptance requires TM_ACCEPTANCE_HOLD_PROACTIVE_REFRESH=1"
    );
    anyhow::ensure!(
        faulty.is_empty(),
        "focused deposit-TTL acceptance requires every epoch-0 replica to remain responsive"
    );

    let path = std::env::var_os("TM_E2E_DEPOSIT_CLOCK_FILE")
        .map(std::path::PathBuf::from)
        .context("focused deposit-TTL acceptance requires TM_E2E_DEPOSIT_CLOCK_FILE")?;
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => anyhow::bail!(
            "focused deposit-TTL acceptance requires an initially absent clock file at {}",
            path.display()
        ),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect focused deposit-TTL clock {}", path.display())
            });
        }
    }
    RegtestClockWriter::from_e2e_env(scenario)?
        .context("focused deposit-TTL acceptance requires TM_E2E_DEPOSIT_CLOCK_FILE")
        .map(Some)
}

fn acceptance_proactive_refresh_hold_enabled() -> anyhow::Result<bool> {
    let Some(value) = std::env::var_os("TM_ACCEPTANCE_HOLD_PROACTIVE_REFRESH") else {
        return Ok(false);
    };
    match value.to_str().context("TM_ACCEPTANCE_HOLD_PROACTIVE_REFRESH must be valid UTF-8")? {
        "0" => Ok(false),
        "1" => Ok(true),
        value => anyhow::bail!(
            "TM_ACCEPTANCE_HOLD_PROACTIVE_REFRESH must be exactly 0 or 1, got {value:?}"
        ),
    }
}

fn required_exact_refresh_epoch() -> anyhow::Result<Option<u64>> {
    let Some(value) = std::env::var_os("TM_ACCEPTANCE_REQUIRE_EXACT_REFRESH_EPOCH") else {
        return Ok(None);
    };
    let value =
        value.to_str().context("TM_ACCEPTANCE_REQUIRE_EXACT_REFRESH_EPOCH must be valid UTF-8")?;
    let epoch = value.parse::<u64>()?;
    anyhow::ensure!(epoch > 0, "an exact refresh target epoch must be positive");
    Ok(Some(epoch))
}

fn required_recovered_party() -> anyhow::Result<Option<PartyId>> {
    let Some(value) = std::env::var_os("TM_ACCEPTANCE_REQUIRE_RECOVERED_PARTY") else {
        return Ok(None);
    };
    let value =
        value.to_str().context("TM_ACCEPTANCE_REQUIRE_RECOVERED_PARTY must be valid UTF-8")?;
    Ok(Some(PartyId::new(value.parse::<u16>()?)?))
}

fn verify_protocol_only_environment(
    deposits_enabled: bool,
    consolidation_required: bool,
) -> anyhow::Result<bool> {
    if !environment_flag("TM_E2E_PROTOCOL_ONLY")? {
        return Ok(false);
    }
    for variable in ["TM_E2E_DEPOSITS", "TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION"] {
        let value = std::env::var(variable).with_context(|| {
            format!("protocol-only acceptance requires an explicit {variable}=0")
        })?;
        anyhow::ensure!(
            value == "0",
            "protocol-only acceptance requires exactly {variable}=0, got {value:?}"
        );
    }
    anyhow::ensure!(
        !deposits_enabled && !consolidation_required,
        "protocol-only acceptance cannot exercise deposits or consolidation"
    );
    Ok(true)
}

fn fresh_deposit_request() -> anyhow::Result<DepositAddressRequest> {
    let mut entropy = Zeroizing::new([0_u8; 64]);
    OsRng.fill_bytes(entropy.as_mut());
    let request = LedgerRequestId(
        *blake3::Hasher::new_derive_key("threshold-monero/e2e-deposit-request/v1")
            .update(&entropy[..32])
            .finalize()
            .as_bytes(),
    );
    let binding = RequestBinding(
        *blake3::Hasher::new_derive_key("threshold-monero/e2e-deposit-binding/v1")
            .update(&entropy[32..])
            .finalize()
            .as_bytes(),
    );
    entropy.zeroize();
    anyhow::ensure!(request.0 != [0_u8; 32] && binding.0 != [0_u8; 32]);
    Ok(DepositAddressRequest { request, binding })
}

fn tenant_bound_request_binding(request: DepositAddressRequest) -> RequestBinding {
    // `main` gives the dedicated credential this fixed principal name. Recomputing the server's
    // public binding here proves that a certificate was issued in this client's tenant domain.
    const PRINCIPAL: &str = "deposit-client";
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/deposit-http-tenant-binding/v2");
    hasher.update(&(PRINCIPAL.len() as u64).to_le_bytes());
    hasher.update(PRINCIPAL.as_bytes());
    hasher.update(&request.request.0);
    hasher.update(&request.binding.0);
    RequestBinding(*hasher.finalize().as_bytes())
}

fn tenant_certified_request_id(request: DepositAddressRequest) -> LedgerRequestId {
    deposit_request_id_for_binding(tenant_bound_request_binding(request))
}

/// Exercise DKG, a grow, timer-driven fixed-size refreshes or reshares both inside and beyond the
/// finite scenario chain, a shrink, and a real BFT deposit consolidation against the configured
/// daemon.
///
/// # Errors
///
/// Returns an error if configuration, a party transition, deposit allocation, BFT consolidation,
/// daemon acceptance, or block confirmation fails.
#[allow(clippy::too_many_lines)]
pub async fn run(scenario: &Scenario) -> anyhow::Result<()> {
    scenario.validate()?;
    anyhow::ensure!(
        scenario.network == NetworkKind::Regtest || !scenario.demo_only,
        "demo-only scenario cannot target a public network"
    );
    anyhow::ensure!(scenario.confirmation_blocks > 0, "confirmation_blocks must be positive");
    let deposit_ttl_acceptance = exact_deposit_ttl_acceptance_flag()?;
    let deposits_enabled = environment_flag("TM_E2E_DEPOSITS")?;
    let consolidation_required = environment_flag("TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION")?;
    let protocol_only = verify_protocol_only_environment(deposits_enabled, consolidation_required)?;
    anyhow::ensure!(
        !consolidation_required || deposits_enabled,
        "TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION requires TM_E2E_DEPOSITS"
    );
    if consolidation_required {
        anyhow::ensure!(
            acceptance_proactive_refresh_hold_enabled()?,
            "full successor-epoch signing acceptance requires \
             TM_ACCEPTANCE_HOLD_PROACTIVE_REFRESH=1"
        );
        anyhow::ensure!(
            scenario.funding_blocks >= REQUIRED_ACCEPTANCE_FUNDING_OUTPUTS,
            "full signing acceptance requires at least {REQUIRED_ACCEPTANCE_FUNDING_OUTPUTS} \
             independently spendable funding blocks"
        );
    }
    if deposits_enabled {
        anyhow::ensure!(
            scenario.network == NetworkKind::Regtest,
            "deposit acceptance is intentionally restricted to private regtest"
        );
    }
    if protocol_only {
        tracing::warn!(
            "running protocol-only resilience acceptance; deposit allocation and consolidation are intentionally disabled"
        );
    }
    let faulty = configured_faulty_parties(scenario)?;
    let mut deposit_ttl_clock = configured_deposit_ttl_clock(
        scenario,
        deposit_ttl_acceptance,
        deposits_enabled,
        consolidation_required,
        protocol_only,
        &faulty,
    )?;
    let required_exact_refresh_epoch = required_exact_refresh_epoch()?;
    anyhow::ensure!(
        required_exact_refresh_epoch.is_none() || required_exact_refresh_epoch == Some(2),
        "this acceptance lifecycle can require an exact same-committee refresh only at epoch 2"
    );
    anyhow::ensure!(
        required_exact_refresh_epoch.is_none() || scenario.network == NetworkKind::Regtest,
        "exact same-committee refresh acceptance is restricted to private Regtest"
    );
    let timeout = std::time::Duration::from_secs(scenario.protocol_timeout_seconds);
    let parties = PartyClient::new(timeout, scenario).await?;

    tracing::info!("observing epoch-0 distributed key generation");
    let initial = scenario.genesis_committee()?;
    let dkg_transition = canonical_dkg_transition(scenario)?;
    let manual_genesis = acceptance_protocol_fault_specification()?.is_some();
    anyhow::ensure!(
        deposit_ttl_clock.is_none() || !manual_genesis,
        "focused deposit-TTL acceptance requires autonomous observe-only genesis"
    );
    let mut current = if manual_genesis {
        let public = run_dkg(
            &parties,
            dkg_transition.session,
            dkg_transition.key_id,
            &initial,
            scenario.committee_spec(0)?.fault_bound,
            &faulty,
        )
        .await?;
        anyhow::ensure!(
            parties.avss_start_calls() > 0,
            "manual genesis completed without an acceptance-client AVSS start call"
        );
        public
    } else {
        let public = wait_for_transition_activation(&parties, &dkg_transition, &faulty).await?;
        let avss_start_calls = parties.avss_start_calls();
        anyhow::ensure!(
            avss_start_calls == 0,
            "ordinary genesis invoked /v1/avss/start {avss_start_calls} times"
        );
        println!(
            "TM_ACCEPTANCE_AUTONOMOUS_GENESIS epoch=0 control=observe-only avss_start_calls={} key_id={} group_key={}",
            avss_start_calls,
            hex::encode(public.key_id),
            hex::encode(public.group_key_bytes()),
        );
        public
    };
    tracing::info!(group_key = %hex::encode(current.group_key_bytes()), "DKG installed");

    let daemon =
        SimpleRequestTransport::new(scenario.acceptance_monerod_rpc_url.to_string()).await?;
    let view = threshold_view_pair(&current)?;
    let threshold_address = view.legacy_address(monero_network(scenario.network));
    let (funding_spend, funding_view, funding_address) =
        acceptance_funding_wallet(monero_network(scenario.network))?;
    println!("TM_ACCEPTANCE_REGTEST_MINING_ADDRESS={funding_address}");

    tracing::info!(
        address = %funding_address,
        blocks = scenario.funding_blocks,
        "funding the ephemeral acceptance wallet and advancing the private regtest chain"
    );
    let funding_start_height = daemon
        .latest_block_number()
        .await?
        .checked_add(1)
        .context("acceptance funding height overflow")?;
    daemon.generate_blocks(&funding_address, usize::try_from(scenario.funding_blocks)?).await?;

    if let Some(clock) = deposit_ttl_clock.as_mut() {
        run_deposit_ttl_acceptance(
            scenario,
            &parties,
            &current,
            &daemon,
            &view,
            &threshold_address,
            &funding_spend,
            &funding_view,
            &funding_address,
            funding_start_height,
            scenario.committee_spec(0)?.fault_bound,
            &faulty,
            clock,
        )
        .await?;
        return Ok(());
    }

    let mut deposit_acceptance = None;
    let mut consolidation_transaction = None;
    let mut consolidation_transaction_bytes = None;
    let mut confirmed_consolidation = None;
    let mut consolidation_fault_proof = None;
    let mut consolidation_bootstrap_proof = None;
    let mut successor_epoch_signatures = Vec::<SuccessorEpochSigningAcceptance>::new();
    if deposits_enabled {
        let mut certified = allocate_certified_deposit(
            scenario,
            &parties,
            &current,
            scenario.committee_spec(0)?.fault_bound,
            &faulty,
        )
        .await?;
        let deposit_address = MoneroAddress::from_str(
            monero_network(scenario.network),
            certified
                .response
                .address
                .as_ref()
                .context("certified allocation omitted its address")?
                .as_str(),
        )?;
        let initial_output_count =
            if consolidation_required { INITIAL_ACCEPTANCE_DEPOSIT_OUTPUTS } else { 1 };
        let (deposit_block, deposit_transaction, deposit_transaction_bytes) =
            fund_deposit_with_ordinary_transaction(
                &daemon,
                &funding_spend,
                &funding_view,
                &funding_address,
                funding_start_height,
                &deposit_address,
                initial_output_count,
                false,
                scenario.deposit_maximum_fee_atomic_units,
                scenario.poll_interval_ms,
                scenario.protocol_timeout_seconds,
            )
            .await?;
        let funded_outputs = verify_deposit_transaction_outputs(
            &daemon,
            &view,
            deposit_block,
            &certified,
            deposit_transaction,
            initial_output_count,
        )
        .await?;
        for output in &funded_outputs {
            validate_consolidation_fixture_economics(
                output.amount_atomic_units,
                scenario.deposit_maximum_fee_atomic_units,
            )?;
        }
        let checkpoint_output =
            funded_outputs.first().copied().context("deposit funding omitted its first output")?;
        certified.funded_outputs.extend(funded_outputs);
        let deposit_fault_mode = configured_acceptance_deposit_fault_mode()?;
        let (confirmations_before_barrier, confirmations_after_barrier) =
            deposit_fault_confirmation_plan(deposit_fault_mode, scenario.confirmation_blocks)?;
        for _ in 0..confirmations_before_barrier {
            daemon.generate_blocks(&threshold_address, 1).await?;
        }
        maybe_pause_at_deposit_fault_barrier(
            &parties,
            deposit_transaction,
            checkpoint_output.id,
            deposit_fault_mode,
        )
        .await?;
        println!(
            "TM_ACCEPTANCE_DEPOSIT_FUNDING_TRANSACTION txid={} bytes={} outputs={}",
            hex::encode(deposit_transaction),
            deposit_transaction_bytes.len(),
            initial_output_count
        );
        println!(
            "TM_ACCEPTANCE_DEPOSIT_FUNDING_TRANSACTION_HEX={}",
            hex::encode(&deposit_transaction_bytes)
        );
        anyhow::ensure!(
            !consolidation_required
                || certified.funded_outputs.len() == INITIAL_ACCEPTANCE_DEPOSIT_OUTPUTS,
            "full acceptance did not create exactly two simultaneously mined deposit outputs"
        );
        for _ in 0..confirmations_after_barrier {
            daemon.generate_blocks(&threshold_address, 1).await?;
        }
        wait_for_permanent_deposit(
            scenario,
            &parties,
            &current,
            scenario.committee_spec(0)?.fault_bound,
            &faulty,
            &certified,
        )
        .await?;
        let certified_amount = certified_deposit_total(&certified)?;
        tracing::info!(
            txid = %hex::encode(deposit_transaction),
            address = %deposit_address,
            outputs = certified.funded_outputs.len(),
            total_amount = certified_amount,
            "ordinary wallet transaction deposits were observed and made permanent"
        );
        if consolidation_required {
            arm_consolidation_bootstrap_fault_gate(&parties, &initial, &faulty).await?;
            arm_consolidation_fault_gate(&parties, &initial, &faulty).await?;
            // The scanner's retained horizon trails the daemon by `confirmation_blocks - 1`.
            // When the deposit first becomes permanent that horizon has only reached its
            // inclusion block, so advance it through Monero's ordinary output lock window.
            let maturity_blocks = DEFAULT_LOCK_WINDOW - 1;
            daemon.generate_blocks(&threshold_address, maturity_blocks).await?;
            tracing::info!(
                additional_blocks = maturity_blocks,
                "advanced the confirmed scanner horizon to ordinary deposit maturity"
            );
            let expected_destination = deposit_destination_binding(scenario, &current)?;
            let pending_bootstrap = maybe_pause_before_consolidation_bootstrap(
                &parties,
                &initial,
                scenario.committee_spec(0)?.fault_bound,
                &faulty,
            )
            .await?;
            let (pending_fault, completed_bootstrap) = if let Some(pending) = pending_bootstrap {
                let proof = complete_consolidation_bootstrap_fault_before_signing(
                    &parties,
                    &initial,
                    scenario.committee_spec(0)?.fault_bound,
                    &faulty,
                    &certified,
                    expected_destination,
                    &pending,
                )
                .await?;
                (None, Some(proof))
            } else {
                (
                    maybe_pause_before_consolidation_signing(
                        &parties,
                        &initial,
                        scenario.committee_spec(0)?.fault_bound,
                        &faulty,
                        &certified,
                        expected_destination,
                    )
                    .await?,
                    None,
                )
            };
            let broadcast = wait_for_consolidation_phase(
                &parties,
                &initial,
                scenario.committee_spec(0)?.fault_bound,
                &faulty,
                &certified,
                expected_destination,
                PublicConsolidationPhase::Broadcast,
            )
            .await?;
            let completed_fault = pending_fault
                .as_ref()
                .map(|pending| validate_consolidation_fault_recovery(pending, &broadcast))
                .transpose()?;
            if let Some(proof) = &completed_bootstrap {
                validate_consolidation_bootstrap_stability(proof, &broadcast)?;
            }
            anyhow::ensure!(
                daemon.block_hash(usize::try_from(broadcast.plan.at_tip.height)?).await?
                    == broadcast.plan.at_tip.hash,
                "consolidation plan scanner tip is not canonical"
            );
            let signed = broadcast
                .signed
                .context("broadcast consolidation omitted signed transaction binding")?;
            let consolidation_block = mine_confirmation(
                &daemon,
                &threshold_address,
                signed.transaction(),
                usize::try_from(broadcast.plan.at_tip.height)?,
                scenario.poll_interval_ms,
                scenario.protocol_timeout_seconds,
            )
            .await?;
            let consolidation_height = u64::try_from(consolidation_block.number())?;
            let confirmation = ChainPoint::new(consolidation_height, consolidation_block.hash())?;
            let accepted_transaction = verify_consolidation_transaction(
                &daemon,
                &view,
                consolidation_block,
                &certified,
                &broadcast,
            )
            .await?;
            anyhow::ensure!(
                broadcast.plan.inputs.len() == INITIAL_ACCEPTANCE_DEPOSIT_OUTPUTS,
                "initial production consolidation did not consume exactly two mature deposit inputs"
            );
            println!(
                "TM_ACCEPTANCE_MULTI_INPUT_CONSOLIDATION txid={} inputs={}",
                hex::encode(accepted_transaction.hash()),
                broadcast.plan.inputs.len()
            );
            consolidation_transaction_bytes = Some(accepted_transaction.serialize());
            for _ in 1..scenario.confirmation_blocks {
                daemon.generate_blocks(&threshold_address, 1).await?;
            }
            let confirmed = wait_for_consolidation_phase(
                &parties,
                &initial,
                scenario.committee_spec(0)?.fault_bound,
                &faulty,
                &certified,
                expected_destination,
                PublicConsolidationPhase::Confirmed,
            )
            .await?;
            let mut expected_confirmed = broadcast.clone();
            expected_confirmed.phase = PublicConsolidationPhase::Confirmed;
            expected_confirmed.confirmation = Some(confirmation);
            anyhow::ensure!(
                confirmed.same_quorum_decision(&expected_confirmed),
                "confirmation changed the witness-independent certified signing decision"
            );
            tracing::info!(
                txid = %hex::encode(signed.transaction()),
                height = confirmation.height,
                "autonomous threshold consolidation was mined and confirmed by n-f parties"
            );
            consolidation_transaction = Some(signed.transaction());
            confirmed_consolidation = Some(confirmed.clone());
            if let Some(proof) = completed_fault {
                maybe_pause_after_consolidation_fault_settlement(&parties, &proof, &confirmed)
                    .await?;
                consolidation_fault_proof = Some(proof);
            }
            if let Some(proof) = completed_bootstrap {
                validate_consolidation_bootstrap_stability(&proof, &confirmed)?;
                println!(
                    "TM_ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_SETTLED fault_party={} bootstrap_ba_view={} bootstrap_proposer={} prepared_intent={} roast_view={} key_image_binding={} key_image_unsigned_transaction={} key_image_authorizers={} key_image_quorum={}",
                    proof.fault_party,
                    proof.certified_ba_view,
                    proof.certified_proposer,
                    hex::encode(proof.certified_prepared_intent_digest),
                    confirmed.roast_view,
                    hex::encode(confirmed.key_image_binding_digest),
                    hex::encode(confirmed.key_image_unsigned_transaction_digest),
                    format_party_list(&confirmed.key_image_authorizers),
                    confirmed.key_image_authorization_quorum,
                );
                {
                    use std::io::Write as _;
                    std::io::stdout().flush()?;
                }
                consolidation_bootstrap_proof = Some(proof);
            }
        } else {
            tracing::warn!(
                "allocation-only deposit diagnostic passed; autonomous consolidation was not required"
            );
        }
        deposit_acceptance = Some(certified);
    }

    tracing::info!(
        interval_seconds = scenario.proactive_refresh_interval_seconds,
        "waiting for certified key rotation and timer-driven reshare to the larger epoch-1 committee"
    );
    let before_grow = current.clone();
    let grow_target = scenario
        .configured_key_rotation_target_shape(&before_grow.committee)?
        .context("epoch zero lacks its configured grow target")?
        .eligible()
        .clone();
    release_held_proactive_refresh(&parties, &before_grow.committee, &grow_target, &faulty).await?;
    current = wait_for_configured_successor(
        scenario,
        &parties,
        &current,
        1,
        &faulty,
        consolidation_fault_proof.as_ref().map(|proof| proof.fault_party),
    )
    .await?;
    let grow_subthreshold =
        validate_cross_epoch_subthreshold_non_identifiability(&before_grow, &current)?;
    tracing::info!(
        source_epoch = before_grow.committee.epoch,
        target_epoch = current.committee.epoch,
        subthreshold_mixed_sets = grow_subthreshold.mixed_sets,
        threshold_boundary_sets = grow_subthreshold.threshold_boundary_sets,
        "native-coordinate cross-epoch model left every subthreshold mixed observation set unable \
         to determine the common constant"
    );
    if let Some(proof) = &consolidation_fault_proof {
        current.committee.member(proof.fault_party)?;
        println!(
            "TM_ACCEPTANCE_CONSOLIDATION_PEER_QUIC_REJOINED party={} epoch={}",
            proof.fault_party, current.committee.epoch
        );
        {
            use std::io::Write as _;
            std::io::stdout().flush()?;
        }
        tracing::info!(
            party = %proof.fault_party,
            epoch = current.committee.epoch,
            "reconnected party participated in the authenticated QUIC reshare and activated its successor share"
        );
    }
    anyhow::ensure!(
        current.group_key_bytes() == threshold_spend_bytes(&view),
        "expanded committee changed the Monero spend key"
    );
    if let Some(deposit) = &deposit_acceptance {
        wait_for_deposit_checkpoint(
            scenario,
            &parties,
            &current,
            scenario.committee_spec(1)?.fault_bound,
            &faulty,
            deposit,
            confirmed_consolidation.as_ref(),
        )
        .await?;
    }
    if consolidation_required {
        successor_epoch_signatures.push(
            exercise_successor_epoch_signing(
                scenario,
                &parties,
                &daemon,
                &funding_spend,
                &funding_view,
                &funding_address,
                successor_acceptance_funding_height(funding_start_height, current.committee.epoch)?,
                &threshold_address,
                &view,
                &current,
                scenario.committee_spec(1)?.fault_bound,
                &faulty,
            )
            .await?,
        );
    }
    tracing::info!(
        interval_seconds = scenario.proactive_refresh_interval_seconds,
        "waiting for the current 4-of-7 committee to refresh itself at the configured deadline"
    );
    let before_refresh = current.clone();
    let exact_refresh_source_link = if required_exact_refresh_epoch == Some(2) {
        Some(
            observe_active_epoch_history_link(
                &parties,
                &before_refresh,
                scenario.committee_spec(before_refresh.committee.epoch)?.fault_bound,
                &faulty,
            )
            .await?,
        )
    } else {
        None
    };
    let refresh_target = scenario
        .configured_key_rotation_target_shape(&before_refresh.committee)?
        .context("epoch one lacks its configured refresh target")?
        .eligible()
        .clone();
    release_held_proactive_refresh(&parties, &before_refresh.committee, &refresh_target, &faulty)
        .await?;
    current = wait_for_configured_successor(scenario, &parties, &current, 2, &faulty, None).await?;
    validate_scheduled_refresh(&before_refresh, &current, threshold_spend_bytes(&view))?;
    if let Some(source_link) = exact_refresh_source_link {
        let target_link = observe_active_epoch_history_link(
            &parties,
            &current,
            scenario.committee_spec(current.committee.epoch)?.fault_bound,
            &faulty,
        )
        .await?;
        let evidence = validate_exact_same_committee_refresh(
            &before_refresh,
            &current,
            scenario.committee_spec(2)?.fault_bound,
            source_link.successor_parent()?,
            target_link.transition_digest(),
        )?;
        println!(
            "TM_ACCEPTANCE_EXACT_SAME_COMMITTEE_REFRESH source_epoch={} target_epoch={} purpose=refresh members={} key_id={} group_key={} source_verification_shares={} target_verification_shares={} receiver_keys=fresh transition_digest={} reshare_transition_digest={}",
            before_refresh.committee.epoch,
            current.committee.epoch,
            format_party_list(&evidence.members),
            hex::encode(current.key_id),
            hex::encode(current.group_key_bytes()),
            hex::encode(evidence.source_verification_shares),
            hex::encode(evidence.target_verification_shares),
            hex::encode(evidence.refresh_transition_digest),
            hex::encode(evidence.reshare_transition_digest),
        );
    }
    let refresh_subthreshold =
        validate_cross_epoch_subthreshold_non_identifiability(&before_refresh, &current)?;
    tracing::info!(
        epoch = current.committee.epoch,
        subthreshold_mixed_sets = refresh_subthreshold.mixed_sets,
        threshold_boundary_sets = refresh_subthreshold.threshold_boundary_sets,
        "fixed-interval proactive refresh activated with a fresh share polynomial and \
         subthreshold old/new observations left the common constant undetermined"
    );
    if let Some(deposit) = &deposit_acceptance {
        wait_for_deposit_checkpoint(
            scenario,
            &parties,
            &current,
            scenario.committee_spec(2)?.fault_bound,
            &faulty,
            deposit,
            confirmed_consolidation.as_ref(),
        )
        .await?;
    }
    if consolidation_required {
        successor_epoch_signatures.push(
            exercise_successor_epoch_signing(
                scenario,
                &parties,
                &daemon,
                &funding_spend,
                &funding_view,
                &funding_address,
                successor_acceptance_funding_height(funding_start_height, current.committee.epoch)?,
                &threshold_address,
                &view,
                &current,
                scenario.committee_spec(2)?.fault_bound,
                &faulty,
            )
            .await?,
        );
    }
    tracing::info!(
        interval_seconds = scenario.proactive_refresh_interval_seconds,
        "waiting for the refreshed 4-of-7 committee to re-arm and refresh itself again"
    );
    let before_second_refresh = current.clone();
    let second_refresh_target = scenario
        .configured_key_rotation_target_shape(&before_second_refresh.committee)?
        .context("epoch two lacks its configured refresh target")?
        .eligible()
        .clone();
    release_held_proactive_refresh(
        &parties,
        &before_second_refresh.committee,
        &second_refresh_target,
        &faulty,
    )
    .await?;
    current = wait_for_configured_successor(scenario, &parties, &current, 3, &faulty, None).await?;
    validate_scheduled_refresh(&before_second_refresh, &current, threshold_spend_bytes(&view))?;
    let second_refresh_subthreshold =
        validate_cross_epoch_subthreshold_non_identifiability(&before_second_refresh, &current)?;
    tracing::info!(
        epoch = current.committee.epoch,
        subthreshold_mixed_sets = second_refresh_subthreshold.mixed_sets,
        threshold_boundary_sets = second_refresh_subthreshold.threshold_boundary_sets,
        "second fixed-interval proactive refresh activated with another fresh share polynomial and \
         subthreshold old/new observations left the common constant undetermined"
    );
    if let Some(deposit) = &deposit_acceptance {
        wait_for_deposit_checkpoint(
            scenario,
            &parties,
            &current,
            scenario.committee_spec(3)?.fault_bound,
            &faulty,
            deposit,
            confirmed_consolidation.as_ref(),
        )
        .await?;
    }
    if consolidation_required {
        successor_epoch_signatures.push(
            exercise_successor_epoch_signing(
                scenario,
                &parties,
                &daemon,
                &funding_spend,
                &funding_view,
                &funding_address,
                successor_acceptance_funding_height(funding_start_height, current.committee.epoch)?,
                &threshold_address,
                &view,
                &current,
                scenario.committee_spec(3)?.fault_bound,
                &faulty,
            )
            .await?,
        );
    }

    tracing::info!(
        interval_seconds = scenario.proactive_refresh_interval_seconds,
        "waiting for certified key rotation and timer-driven reshare to the smaller epoch-4 committee"
    );
    let before_shrink = current.clone();
    let shrink_target = scenario
        .configured_key_rotation_target_shape(&before_shrink.committee)?
        .context("epoch three lacks its configured shrink target")?
        .eligible()
        .clone();
    release_held_proactive_refresh(&parties, &before_shrink.committee, &shrink_target, &faulty)
        .await?;
    current = wait_for_configured_successor(scenario, &parties, &current, 4, &faulty, None).await?;
    let shrink_subthreshold =
        validate_cross_epoch_subthreshold_non_identifiability(&before_shrink, &current)?;
    anyhow::ensure!(
        current.group_key_bytes() == threshold_spend_bytes(&view),
        "smaller committee changed the Monero spend key"
    );
    tracing::info!(
        source_epoch = before_shrink.committee.epoch,
        target_epoch = current.committee.epoch,
        subthreshold_mixed_sets = shrink_subthreshold.mixed_sets,
        threshold_boundary_sets = shrink_subthreshold.threshold_boundary_sets,
        "smaller successor used native epoch coordinates and every mixed observation set below both \
         thresholds left the common constant undetermined"
    );
    if let Some(deposit) = &deposit_acceptance {
        wait_for_deposit_checkpoint(
            scenario,
            &parties,
            &current,
            scenario.committee_spec(4)?.fault_bound,
            &faulty,
            deposit,
            confirmed_consolidation.as_ref(),
        )
        .await?;
    }
    if consolidation_required {
        successor_epoch_signatures.push(
            exercise_successor_epoch_signing(
                scenario,
                &parties,
                &daemon,
                &funding_spend,
                &funding_view,
                &funding_address,
                successor_acceptance_funding_height(funding_start_height, current.committee.epoch)?,
                &threshold_address,
                &view,
                &current,
                scenario.committee_spec(4)?.fault_bound,
                &faulty,
            )
            .await?,
        );
    }

    let final_spec = scenario.committee_spec(4)?;
    let final_fault_bound = final_spec.fault_bound;
    let before_dynamic_refresh = current.clone();
    let dynamic_epoch = before_dynamic_refresh
        .committee
        .epoch
        .checked_add(1)
        .context("dynamic refresh epoch exhausted")?;
    let dynamic_target = Committee {
        epoch: dynamic_epoch,
        threshold: before_dynamic_refresh.committee.threshold,
        members: scenario
            .parties
            .iter()
            .map(|party| Member {
                id: party.id,
                signing_key: party.signing_key.0,
                encryption_key: eligibility_reference_key(
                    dynamic_epoch,
                    party.id,
                    party.signing_key.0,
                ),
            })
            .collect(),
    }
    .canonicalized()?;
    let (dynamic_fault_party, dynamic_faulty) = configured_dynamic_rotation_selected_member_fault(
        &before_dynamic_refresh.committee,
        &dynamic_target,
        final_fault_bound,
        &faulty,
    )?;
    maybe_pause_before_dynamic_refresh(
        &parties,
        before_dynamic_refresh.committee.epoch,
        dynamic_fault_party,
    )
    .await?;
    tracing::info!(
        interval_seconds = scenario.proactive_refresh_interval_seconds,
        source_epoch = before_dynamic_refresh.committee.epoch,
        "waiting for a dynamic refresh beyond the finite configured committee chain"
    );
    release_held_proactive_refresh(
        &parties,
        &before_dynamic_refresh.committee,
        &dynamic_target,
        &dynamic_faulty,
    )
    .await?;
    current = wait_for_dynamic_refresh(
        scenario,
        &parties,
        &before_dynamic_refresh,
        final_fault_bound,
        &dynamic_faulty,
    )
    .await?;
    let dynamic_subthreshold =
        validate_cross_epoch_subthreshold_non_identifiability(&before_dynamic_refresh, &current)?;
    tracing::info!(
        epoch = current.committee.epoch,
        subthreshold_mixed_sets = dynamic_subthreshold.mixed_sets,
        threshold_boundary_sets = dynamic_subthreshold.threshold_boundary_sets,
        "autonomous dynamic refresh activated with rotated encryption keys, a fresh share \
         polynomial, and subthreshold old/new observations left the common constant undetermined"
    );
    if let Some(deposit) = &deposit_acceptance {
        wait_for_deposit_checkpoint(
            scenario,
            &parties,
            &current,
            final_fault_bound,
            &dynamic_faulty,
            deposit,
            confirmed_consolidation.as_ref(),
        )
        .await?;
    }
    if consolidation_required {
        successor_epoch_signatures.push(
            exercise_successor_epoch_signing(
                scenario,
                &parties,
                &daemon,
                &funding_spend,
                &funding_view,
                &funding_address,
                successor_acceptance_funding_height(funding_start_height, current.committee.epoch)?,
                &threshold_address,
                &view,
                &current,
                final_fault_bound,
                &dynamic_faulty,
            )
            .await?,
        );
    }

    anyhow::ensure!(
        !consolidation_required || consolidation_transaction.is_some(),
        "required deposit consolidation did not complete"
    );
    if consolidation_required {
        let expected_successor_epochs = (1_u64..=5).collect::<Vec<_>>();
        anyhow::ensure!(
            successor_epoch_signatures
                .iter()
                .map(|accepted| accepted.epoch)
                .eq(expected_successor_epochs.iter().copied()),
            "successor signing acceptance did not cover each grow/refresh/shrink/dynamic epoch"
        );
    }

    if let Some(transaction) = consolidation_transaction {
        println!(
            "deposit consolidation transaction {} was threshold-signed, mined, and confirmed",
            hex::encode(transaction)
        );
        let bytes = consolidation_transaction_bytes
            .as_deref()
            .context("confirmed consolidation omitted exact daemon transaction bytes")?;
        let input_count = confirmed_consolidation
            .as_ref()
            .context("confirmed consolidation omitted its public status")?
            .plan
            .inputs
            .len();
        println!(
            "TM_ACCEPTANCE_SIGNED_TRANSACTION txid={} bytes={} inputs={} hex={}",
            hex::encode(transaction),
            bytes.len(),
            input_count,
            hex::encode(bytes)
        );
    }
    for accepted in &successor_epoch_signatures {
        println!(
            "TM_ACCEPTANCE_SUCCESSOR_EPOCH_SIGNED_TRANSACTION epoch={} txid={} bytes={} inputs={} hex={}",
            accepted.epoch,
            hex::encode(accepted.transaction),
            accepted.exact_transaction_bytes.len(),
            accepted.input_count,
            hex::encode(&accepted.exact_transaction_bytes),
        );
    }

    if let Some(proof) = consolidation_fault_proof {
        println!(
            "fault-resilient consolidation acceptance passed; peer-QUIC-silent party {} forced ROAST view {} signers {} to rotate to view {} signers {} before the real sweep was broadcast, mined, and settled",
            proof.fault_party,
            proof.initial_view,
            format_party_list(&proof.initial_signers),
            proof.completed_view,
            format_party_list(&proof.completed_signers),
        );
    }

    if let Some(proof) = consolidation_bootstrap_proof {
        println!(
            "fault-resilient consolidation bootstrap acceptance passed; stopped slot-zero proposer {} forced bootstrap BA view {} intent {} to rotate to view {} proposer {} independently prepared intent {}, then the restarted proposer caught up before ROAST signing, broadcast, mining, and settlement",
            proof.fault_party,
            proof.initial_ba_view,
            hex::encode(proof.initial_prepared_intent_digest),
            proof.certified_ba_view,
            proof.certified_proposer,
            hex::encode(proof.certified_prepared_intent_digest),
        );
    }

    if deposits_enabled && !consolidation_required {
        println!(
            "allocation-only deposit acceptance passed; the address was funded, observed, and made permanent while consolidation was intentionally out of scope"
        );
    }

    if protocol_only {
        println!(
            "protocol-only resilience acceptance passed; deposits and consolidation were intentionally out of scope"
        );
    }

    if consolidation_required {
        println!(
            "successor epoch signing acceptance passed; epochs 1 through 5 each threshold-signed, broadcast, mined, and confirmed a fresh Monero consolidation"
        );
    }
    println!(
        "threshold Monero regtest accepted 3-of-5 -> 4-of-7 -> two scheduled 4-of-7 refreshes -> 3-of-5 resharing -> autonomous dynamic 3-of-5 refresh-or-reshare"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_deposit_ttl_acceptance(
    scenario: &Scenario,
    client: &PartyClient,
    public: &EpochPublic,
    daemon: &MoneroDaemon<SimpleRequestTransport>,
    view: &ViewPair,
    threshold_address: &MoneroAddress,
    funding_spend: &Zeroizing<Scalar>,
    funding_view: &ViewPair,
    funding_address: &MoneroAddress,
    funding_start_height: usize,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    clock: &mut RegtestClockWriter,
) -> anyhow::Result<()> {
    let bootstrap = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock precedes the Unix epoch")?
        .as_secs()
        .checked_add(1)
        .context("deposit-TTL bootstrap time overflow")?;
    advance_deposit_clock(clock, 1, bootstrap, "bootstrap")?;

    let unused_schedule =
        schedule_deposit_allocation(scenario, client, public, fault_bound, faulty, bootstrap)
            .await?;
    let unused_visible = bootstrap
        .checked_add(DEPOSIT_ALLOCATION_ISSUANCE_LEAD_SECONDS)
        .context("unused allocation visibility time overflow")?;
    anyhow::ensure!(
        unused_schedule.created_at == unused_visible,
        "unused allocation was not scheduled at the exact issuance lead"
    );
    advance_deposit_clock(clock, 2, unused_visible, "unused-visible")?;
    let (unused, _) = wait_for_scheduled_deposit_active(
        scenario,
        client,
        public,
        fault_bound,
        faulty,
        unused_schedule,
    )
    .await?;

    let permanent_schedule =
        schedule_deposit_allocation(scenario, client, public, fault_bound, faulty, unused_visible)
            .await?;
    let permanent_visible = unused_visible
        .checked_add(DEPOSIT_ALLOCATION_ISSUANCE_LEAD_SECONDS)
        .context("permanent allocation visibility time overflow")?;
    anyhow::ensure!(
        permanent_schedule.created_at == permanent_visible,
        "funded allocation was not scheduled at the exact issuance lead"
    );
    advance_deposit_clock(clock, 3, permanent_visible, "permanent-visible")?;
    let (mut permanent, _) = wait_for_scheduled_deposit_active(
        scenario,
        client,
        public,
        fault_bound,
        faulty,
        permanent_schedule,
    )
    .await?;

    let permanent_address = MoneroAddress::from_str(
        monero_network(scenario.network),
        permanent
            .response
            .address
            .as_ref()
            .context("focused funded allocation omitted its address")?
            .as_str(),
    )?;
    let (deposit_block, funding_transaction, funding_transaction_bytes) =
        fund_deposit_with_ordinary_transaction(
            daemon,
            funding_spend,
            funding_view,
            funding_address,
            funding_start_height,
            &permanent_address,
            1,
            true,
            scenario.deposit_maximum_fee_atomic_units,
            scenario.poll_interval_ms,
            scenario.protocol_timeout_seconds,
        )
        .await?;
    let funded_outputs = verify_deposit_transaction_outputs(
        daemon,
        view,
        deposit_block,
        &permanent,
        funding_transaction,
        1,
    )
    .await?;
    anyhow::ensure!(
        funded_outputs.len() == 1,
        "focused deposit-TTL funding must create exactly one certified output"
    );
    validate_consolidation_fixture_economics(
        funded_outputs[0].amount_atomic_units,
        scenario.deposit_maximum_fee_atomic_units,
    )?;
    permanent.funded_outputs.extend(funded_outputs);
    println!(
        "TM_ACCEPTANCE_DEPOSIT_FUNDING_TRANSACTION txid={} bytes={} outputs=1",
        hex::encode(funding_transaction),
        funding_transaction_bytes.len(),
    );
    println!(
        "TM_ACCEPTANCE_DEPOSIT_FUNDING_TRANSACTION_HEX={}",
        hex::encode(&funding_transaction_bytes)
    );
    for _ in 1..scenario.confirmation_blocks {
        daemon.generate_blocks(threshold_address, 1).await?;
    }
    wait_for_ttl_deposit_status(
        client,
        public,
        fault_bound,
        faulty,
        &permanent,
        DepositHttpStatus::Permanent,
    )
    .await?;

    let unused_last_active =
        unused_schedule.expires_at.checked_sub(1).context("unused expiry underflow")?;
    advance_deposit_clock(clock, 4, unused_last_active, "unused-last-active")?;
    let active_replicas = wait_for_ttl_deposit_status(
        client,
        public,
        fault_bound,
        faulty,
        &unused,
        DepositHttpStatus::Active,
    )
    .await?;
    let unused_facts = deposit_ttl_allocation_facts(&unused)?;
    println!(
        "TM_ACCEPTANCE_DEPOSIT_TTL_ACTIVE request={} sequence={} index={}:{} created_at={} observed_at={} expires_at={} statement={} replicas={} clock_generation=4",
        hex::encode(unused_facts.request),
        unused_facts.sequence,
        unused_facts.account,
        unused_facts.address_index,
        unused_facts.created_at,
        unused_last_active,
        unused_facts.expires_at,
        hex::encode(unused_facts.statement),
        format_party_list(&active_replicas),
    );

    let unused_expired = unused_schedule.expires_at;
    advance_deposit_clock(clock, 5, unused_expired, "unused-expired")?;
    let expired_replicas = wait_for_ttl_deposit_status(
        client,
        public,
        fault_bound,
        faulty,
        &unused,
        DepositHttpStatus::Expired,
    )
    .await?;
    println!(
        "TM_ACCEPTANCE_DEPOSIT_TTL_EXPIRED request={} sequence={} index={}:{} observed_at={} expires_at={} address_hidden=true certificate_hidden=true replicas={} clock_generation=5",
        hex::encode(unused_facts.request),
        unused_facts.sequence,
        unused_facts.account,
        unused_facts.address_index,
        unused_expired,
        unused_facts.expires_at,
        format_party_list(&expired_replicas),
    );

    let replacement_schedule =
        schedule_deposit_allocation(scenario, client, public, fault_bound, faulty, unused_expired)
            .await?;
    let replacement_visible = permanent_schedule.expires_at;
    anyhow::ensure!(
        replacement_schedule.created_at == replacement_visible,
        "replacement allocation did not become visible at the funded allocation's exact expiry"
    );
    advance_deposit_clock(clock, 6, replacement_visible, "replacement-visible")?;
    let (replacement, replacement_replicas) = wait_for_scheduled_deposit_active(
        scenario,
        client,
        public,
        fault_bound,
        faulty,
        replacement_schedule,
    )
    .await?;

    let permanent_facts = deposit_ttl_allocation_facts(&permanent)?;
    let replacement_facts = deposit_ttl_allocation_facts(&replacement)?;
    validate_deposit_ttl_acceptance_facts(
        [
            bootstrap,
            unused_visible,
            permanent_visible,
            unused_last_active,
            unused_expired,
            replacement_visible,
        ],
        &unused_facts,
        &permanent_facts,
        &replacement_facts,
    )?;
    println!(
        "TM_ACCEPTANCE_DEPOSIT_TTL_NOT_REUSED expired_sequence={} expired_index={}:{} expired_address={} new_sequence={} new_index={}:{} new_address={} replicas={} clock_generation=6",
        unused_facts.sequence,
        unused_facts.account,
        unused_facts.address_index,
        unused_facts.address,
        replacement_facts.sequence,
        replacement_facts.account,
        replacement_facts.address_index,
        replacement_facts.address,
        format_party_list(&replacement_replicas),
    );

    let permanent_replicas = wait_for_ttl_deposit_status(
        client,
        public,
        fault_bound,
        faulty,
        &permanent,
        DepositHttpStatus::Permanent,
    )
    .await?;
    let output = permanent
        .funded_outputs
        .first()
        .copied()
        .context("focused funded allocation omitted output evidence")?;
    anyhow::ensure!(
        permanent.funded_outputs.len() == 1
            && output.id.transaction == funding_transaction
            && output.id.index_in_transaction == 0,
        "focused permanent evidence is not bound to the exact one-output funding transaction"
    );
    println!(
        "TM_ACCEPTANCE_DEPOSIT_TTL_PERMANENT request={} sequence={} index={}:{} observed_at={} expires_at={} output={}:{} statement={} replicas={} clock_generation=6",
        hex::encode(permanent_facts.request),
        permanent_facts.sequence,
        permanent_facts.account,
        permanent_facts.address_index,
        replacement_visible,
        permanent_facts.expires_at,
        hex::encode(output.id.transaction),
        output.id.index_in_transaction,
        hex::encode(permanent_facts.statement),
        format_party_list(&permanent_replicas),
    );
    println!(
        "deposit TTL acceptance passed; exact boundary, non-reuse, and permanent retrieval verified"
    );
    Ok(())
}

fn advance_deposit_clock(
    clock: &mut RegtestClockWriter,
    generation: u64,
    unix_seconds: u64,
    phase: &'static str,
) -> anyhow::Result<()> {
    let sample = clock.set_unix_seconds(unix_seconds)?;
    anyhow::ensure!(
        sample.unix_seconds == unix_seconds
            && sample.unix_millis == unix_seconds.checked_mul(1_000).context("clock overflow")?,
        "deposit clock writer returned a sample different from the committed time"
    );
    println!(
        "TM_ACCEPTANCE_DEPOSIT_CLOCK generation={generation} unix_seconds={unix_seconds} phase={phase}"
    );
    Ok(())
}

async fn schedule_deposit_allocation(
    scenario: &Scenario,
    client: &PartyClient,
    public: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    admitted_at: u64,
) -> anyhow::Result<ScheduledDeposit> {
    let request_parties = allocation_request_parties(&public.committee, fault_bound, faulty)?;
    let required_deliveries = usize::from(
        fault_bound.checked_add(1).context("deposit allocation delivery threshold overflow")?,
    );
    anyhow::ensure!(
        request_parties.len() >= required_deliveries,
        "deposit allocation has {} request recipients, requires f+1={required_deliveries}",
        request_parties.len()
    );
    let request = fresh_deposit_request()?;
    let expected_created_at = admitted_at
        .checked_add(DEPOSIT_ALLOCATION_ISSUANCE_LEAD_SECONDS)
        .context("scheduled deposit creation time overflow")?;
    let expected_expires_at = expected_created_at
        .checked_add(UNUSED_ALLOCATION_TTL_SECONDS)
        .context("scheduled deposit expiry overflow")?;
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let mut observations = BTreeMap::<PartyId, String>::new();
    let mut valid_pending = BTreeSet::new();
    loop {
        for request_party in &request_parties {
            let observation = match client
                .post_deposit::<_, DepositHttpResponse>(
                    *request_party,
                    "/v1/deposits/allocate",
                    &request,
                )
                .await
            {
                Ok(response)
                    if deposit_status_reached_current_epoch(
                        &response,
                        DepositHttpStatus::Pending,
                        public,
                        fault_bound,
                    ) && response.created_at.is_some() =>
                {
                    match validate_scheduled_deposit_response(
                        scenario,
                        public,
                        fault_bound,
                        request,
                        expected_created_at,
                        expected_expires_at,
                        &response,
                    ) {
                        Ok(()) => {
                            valid_pending.insert(*request_party);
                            if valid_pending.len() >= required_deliveries {
                                return Ok(ScheduledDeposit {
                                    request,
                                    created_at: expected_created_at,
                                    expires_at: expected_expires_at,
                                });
                            }
                            format!(
                                "request party {request_party} accepted the schedule; \
                                 deliveries={}/{required_deliveries}",
                                valid_pending.len()
                            )
                        }
                        Err(error) => {
                            format!(
                                "request party {request_party} returned invalid Pending state: {error:#}"
                            )
                        }
                    }
                }
                Ok(response) => format!(
                    "request party {request_party} returned {:?} leader={} created_at={:?}",
                    response.status, response.leader, response.created_at
                ),
                Err(error) => format!("request party {request_party} failed: {error:#}"),
            };
            observations.insert(*request_party, observation);
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "deposit allocation was not durably scheduled before its visibility boundary: \
                 {observations:?}"
            );
        }
        tokio::time::sleep(client.poll_interval).await;
    }
}

fn validate_scheduled_deposit_response(
    scenario: &Scenario,
    public: &EpochPublic,
    fault_bound: u16,
    request: DepositAddressRequest,
    expected_created_at: u64,
    expected_expires_at: u64,
    response: &DepositHttpResponse,
) -> anyhow::Result<()> {
    anyhow::ensure!(response.request == request.request);
    anyhow::ensure!(response.certified_request == tenant_certified_request_id(request));
    anyhow::ensure!(response.status == DepositHttpStatus::Pending);
    validate_serving_deposit_registry(response, public, fault_bound)?;
    anyhow::ensure!(
        response.address.is_none() && response.certificate.is_none(),
        "pending deposit leaked its address or allocation certificate"
    );
    anyhow::ensure!(response.created_at == Some(expected_created_at));
    anyhow::ensure!(response.expires_at == Some(expected_expires_at));
    anyhow::ensure!(
        expected_expires_at.checked_sub(expected_created_at) == Some(UNUSED_ALLOCATION_TTL_SECONDS)
    );
    let issuer =
        response.allocation_issuer.as_ref().context("pending deposit omitted allocation issuer")?;
    issuer.validate()?;
    anyhow::ensure!(
        issuer.issuer() == response.serving_registry.active(),
        "pending deposit allocation issuer differs from its serving registry"
    );
    anyhow::ensure!(
        issuer.terminal().is_none(),
        "pending deposit returned a terminal allocation issuer"
    );
    anyhow::ensure!(
        scenario.network == NetworkKind::Regtest,
        "scheduled deposit validation is restricted to Regtest"
    );
    Ok(())
}

async fn wait_for_scheduled_deposit_active(
    scenario: &Scenario,
    client: &PartyClient,
    public: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    scheduled: ScheduledDeposit,
) -> anyhow::Result<(CertifiedDeposit, Vec<PartyId>)> {
    let committee = &public.committee;
    anyhow::ensure!(fault_bound < committee.n());
    let required = usize::from(committee.n() - fault_bound);
    let responsive = committee
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    anyhow::ensure!(responsive.len() >= required, "not enough responsive deposit replicas");
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut groups = Vec::<EqualObservationGroup<ValidatedDepositAllocationCandidate>>::new();
        let mut responses = BTreeMap::<PartyId, ValidatedDepositAllocationResponse>::new();
        for party in &responsive {
            let response = match client
                .post_deposit::<_, DepositHttpResponse>(
                    *party,
                    "/v1/deposits/status",
                    &scheduled.request,
                )
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                    continue;
                }
            };
            observations
                .insert(*party, format!("{:?} leader={}", response.status, response.leader));
            if !deposit_status_reached_current_epoch(
                &response,
                DepositHttpStatus::Active,
                public,
                fault_bound,
            ) {
                continue;
            }
            let candidate = match validate_new_deposit_certificate(
                scenario.network,
                public,
                fault_bound,
                scheduled.request,
                &response,
            ) {
                Ok(registry) => registry,
                Err(error) => {
                    observations.insert(*party, format!("invalid Active response: {error:#}"));
                    continue;
                }
            };
            if response.created_at != Some(scheduled.created_at)
                || response.expires_at != Some(scheduled.expires_at)
            {
                observations
                    .insert(*party, "Active response changed its certified schedule".to_owned());
                continue;
            }
            observations.insert(*party, "valid exact Active candidate".to_owned());
            record_equal_observation(&mut groups, *party, candidate.clone());
            responses.insert(*party, ValidatedDepositAllocationResponse { candidate, response });
        }
        if let Some(certified) = certified_deposit_candidate_quorum(
            scheduled.request,
            &groups,
            &responses,
            required,
            &BTreeSet::new(),
        )? {
            return Ok(certified);
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "scheduled deposit did not become Active on n-f exact replicas: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

async fn wait_for_ttl_deposit_status(
    client: &PartyClient,
    public: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
    expected_status: DepositHttpStatus,
) -> anyhow::Result<Vec<PartyId>> {
    let committee = &public.committee;
    anyhow::ensure!(fault_bound < committee.n());
    anyhow::ensure!(
        matches!(
            expected_status,
            DepositHttpStatus::Active | DepositHttpStatus::Expired | DepositHttpStatus::Permanent
        ),
        "focused deposit-TTL observation requested a non-terminal visibility status"
    );
    let required = usize::from(committee.n() - fault_bound);
    let responsive = committee
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    anyhow::ensure!(responsive.len() >= required, "not enough responsive deposit replicas");
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut groups =
            Vec::<EqualObservationGroup<(CompactEpochRegistry, VerifiedIssuerWindow)>>::new();
        for party in &responsive {
            let response = match client
                .post_deposit::<_, DepositHttpResponse>(
                    *party,
                    "/v1/deposits/status",
                    &deposit.request,
                )
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                    continue;
                }
            };
            observations
                .insert(*party, format!("{:?} leader={}", response.status, response.leader));
            if !deposit_status_reached_current_epoch(
                &response,
                expected_status,
                public,
                fault_bound,
            ) {
                continue;
            }
            match validate_ttl_replica_response(
                public,
                fault_bound,
                *party,
                deposit,
                expected_status,
                &response,
            ) {
                Ok(authority) => record_equal_observation(&mut groups, *party, authority),
                Err(error) => {
                    observations.insert(*party, format!("invalid response: {error:#}"));
                }
            }
        }
        if let Some(group) = equal_observation_quorum(&groups, required, &BTreeSet::new())? {
            return Ok(group.parties.iter().copied().collect());
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "deposit did not reach {expected_status:?} on n-f replicas; observations: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

fn validate_ttl_replica_response(
    public: &EpochPublic,
    fault_bound: u16,
    party: PartyId,
    deposit: &CertifiedDeposit,
    expected_status: DepositHttpStatus,
    response: &DepositHttpResponse,
) -> anyhow::Result<(CompactEpochRegistry, VerifiedIssuerWindow)> {
    anyhow::ensure!(response.status == expected_status);
    validate_serving_deposit_registry(response, public, fault_bound)?;
    anyhow::ensure!(response.request == deposit.response.request);
    anyhow::ensure!(response.certified_request == deposit.response.certified_request);
    anyhow::ensure!(response.created_at == deposit.response.created_at);
    anyhow::ensure!(response.expires_at == deposit.response.expires_at);
    let issuer = validate_response_allocation_issuer(response, &deposit.allocation_issuer)?;
    match expected_status {
        DepositHttpStatus::Active | DepositHttpStatus::Permanent => {
            anyhow::ensure!(response.address == deposit.response.address);
            let certificate = response
                .certificate
                .as_ref()
                .with_context(|| format!("party {party} omitted its deposit certificate"))?;
            validate_replica_deposit_certificate(party, deposit, certificate, issuer)?;
        }
        DepositHttpStatus::Expired => {
            let retained = deposit
                .response
                .certificate
                .as_ref()
                .context("expired deposit omitted its retained allocation certificate")?;
            validate_replica_deposit_certificate(party, deposit, retained, issuer)?;
            anyhow::ensure!(
                response.address.is_none() && response.certificate.is_none(),
                "party {party} leaked an expired address or allocation certificate"
            );
        }
        DepositHttpStatus::Syncing | DepositHttpStatus::Pending => {
            anyhow::bail!("focused deposit-TTL validation received a non-visible status")
        }
    }
    Ok((response.serving_registry.clone(), issuer.clone()))
}

fn deposit_ttl_allocation_facts(
    deposit: &CertifiedDeposit,
) -> anyhow::Result<DepositTtlAllocationFacts> {
    let address =
        deposit.response.address.as_ref().context("certified deposit omitted its address")?;
    let certificate = deposit
        .response
        .certificate
        .as_ref()
        .context("certified deposit omitted its certificate")?;
    let LedgerPayload::Allocation(allocation) = &certificate.statement.payload else {
        anyhow::bail!("certified deposit statement is not an allocation");
    };
    anyhow::ensure!(allocation.address == *address);
    let index = address.index();
    Ok(DepositTtlAllocationFacts {
        request: deposit.response.request.0,
        sequence: certificate.statement.sequence,
        account: index.account(),
        address_index: index.address(),
        address: address.as_str().to_owned(),
        created_at: deposit
            .response
            .created_at
            .context("certified deposit omitted creation time")?,
        expires_at: deposit.response.expires_at.context("certified deposit omitted expiry time")?,
        statement: certificate.statement.digest(),
    })
}

fn validate_deposit_ttl_acceptance_facts(
    clock: [u64; 6],
    unused: &DepositTtlAllocationFacts,
    permanent: &DepositTtlAllocationFacts,
    replacement: &DepositTtlAllocationFacts,
) -> anyhow::Result<()> {
    anyhow::ensure!(clock.iter().all(|value| *value > 0), "deposit clock contains zero");
    anyhow::ensure!(
        clock.windows(2).all(|window| window[0] < window[1]),
        "deposit clock generations are not strictly monotonic"
    );
    anyhow::ensure!(
        clock[0].checked_add(DEPOSIT_ALLOCATION_ISSUANCE_LEAD_SECONDS) == Some(clock[1])
            && clock[1].checked_add(DEPOSIT_ALLOCATION_ISSUANCE_LEAD_SECONDS) == Some(clock[2]),
        "deposit allocations did not use the exact sixty-second issuance lead"
    );
    let unused_expiry =
        clock[1].checked_add(UNUSED_ALLOCATION_TTL_SECONDS).context("unused expiry overflow")?;
    let permanent_expiry =
        clock[2].checked_add(UNUSED_ALLOCATION_TTL_SECONDS).context("permanent expiry overflow")?;
    anyhow::ensure!(
        clock[3].checked_add(1) == Some(unused_expiry)
            && clock[4] == unused_expiry
            && clock[5] == permanent_expiry
            && clock[4].checked_add(DEPOSIT_ALLOCATION_ISSUANCE_LEAD_SECONDS) == Some(clock[5]),
        "deposit clock does not encode expiry-minus-one, exact expiry, and funded expiry exactly"
    );
    anyhow::ensure!(
        unused.created_at == clock[1] && unused.expires_at == clock[4],
        "unused allocation timestamps do not match the controlled clock"
    );
    anyhow::ensure!(
        permanent.created_at == clock[2] && permanent.expires_at == clock[5],
        "funded allocation timestamps do not match the controlled clock"
    );
    anyhow::ensure!(
        replacement.created_at == clock[5]
            && replacement.expires_at
                == clock[5]
                    .checked_add(UNUSED_ALLOCATION_TTL_SECONDS)
                    .context("replacement expiry overflow")?,
        "replacement allocation timestamps do not match the controlled clock"
    );
    anyhow::ensure!(
        unused.sequence < permanent.sequence && permanent.sequence < replacement.sequence,
        "replacement allocation did not advance the durable ledger sequence"
    );
    anyhow::ensure!(
        unused.account == permanent.account
            && permanent.account == replacement.account
            && unused.address_index < permanent.address_index
            && permanent.address_index < replacement.address_index,
        "replacement allocation did not advance the permanent subaddress index"
    );
    anyhow::ensure!(
        unused.address != permanent.address
            && permanent.address != replacement.address
            && unused.address != replacement.address,
        "deposit allocation reused a canonical Monero address"
    );
    anyhow::ensure!(
        unused.request != permanent.request
            && permanent.request != replacement.request
            && unused.request != replacement.request,
        "deposit allocation reused an external idempotency key"
    );
    anyhow::ensure!(
        unused.statement != permanent.statement
            && permanent.statement != replacement.statement
            && unused.statement != replacement.statement,
        "deposit allocation reused a ledger statement"
    );
    Ok(())
}

async fn allocate_certified_deposit(
    scenario: &Scenario,
    client: &PartyClient,
    public: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<CertifiedDeposit> {
    let committee = &public.committee;
    let request_parties = allocation_request_parties(committee, fault_bound, faulty)?;
    let required = usize::from(committee.n() - fault_bound);
    let required_parties = required_recovered_party()?.into_iter().collect::<BTreeSet<_>>();
    anyhow::ensure!(
        required_parties.iter().all(|party| request_parties.contains(party)),
        "required recovered party is not a responsive deposit request party"
    );
    let request = fresh_deposit_request()?;
    // One view timeout cannot also cover leader replacement, the independent portable
    // checkpoint, and the allocation's deliberately delayed release.
    let deadline = tokio::time::Instant::now()
        + deposit_allocation_acceptance_timeout(client.protocol_timeout)?;
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut groups = Vec::<EqualObservationGroup<ValidatedDepositAllocationCandidate>>::new();
        let mut responses = BTreeMap::<PartyId, ValidatedDepositAllocationResponse>::new();
        for request_party in &request_parties {
            match client
                .post_deposit::<_, DepositHttpResponse>(
                    *request_party,
                    "/v1/deposits/allocate",
                    &request,
                )
                .await
            {
                Ok(response) if response.status == DepositHttpStatus::Active => {
                    match validate_new_deposit_certificate(
                        scenario.network,
                        public,
                        fault_bound,
                        request,
                        &response,
                    ) {
                        Ok(candidate) => {
                            observations
                                .insert(*request_party, "valid exact Active candidate".to_owned());
                            record_equal_observation(
                                &mut groups,
                                *request_party,
                                candidate.clone(),
                            );
                            responses.insert(
                                *request_party,
                                ValidatedDepositAllocationResponse { candidate, response },
                            );
                        }
                        Err(error) => {
                            observations.insert(
                                *request_party,
                                format!(
                                    "request party {request_party} returned an invalid Active state: \
                                     {error:#}"
                                ),
                            );
                        }
                    }
                }
                Ok(response) => {
                    observations.insert(
                        *request_party,
                        format!("request party {request_party} returned {:?}", response.status),
                    );
                }
                Err(error) => {
                    observations.insert(
                        *request_party,
                        format!("request party {request_party} failed: {error:#}"),
                    );
                }
            }
        }
        if let Some((certified, _)) = certified_deposit_candidate_quorum(
            request,
            &groups,
            &responses,
            required,
            &required_parties,
        )? {
            return Ok(certified);
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "deposit allocation did not reach an n-f exact certified active state: \
             {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

fn allocation_request_parties(
    committee: &Committee,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<Vec<PartyId>> {
    anyhow::ensure!(
        fault_bound < committee.n(),
        "deposit allocation fault bound exhausts its committee"
    );
    let parties = committee
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    let required = usize::from(committee.n() - fault_bound);
    anyhow::ensure!(
        parties.len() >= required,
        "deposit committee has {} responsive request parties, requires n-f={required}",
        parties.len()
    );
    Ok(parties)
}

fn validate_new_deposit_certificate(
    network: NetworkKind,
    public: &EpochPublic,
    fault_bound: u16,
    request: DepositAddressRequest,
    response: &DepositHttpResponse,
) -> anyhow::Result<ValidatedDepositAllocationCandidate> {
    anyhow::ensure!(response.request == request.request);
    anyhow::ensure!(response.certified_request == tenant_certified_request_id(request));
    anyhow::ensure!(response.status == DepositHttpStatus::Active);
    validate_serving_deposit_registry(response, public, fault_bound)?;
    let address = response.address.as_ref().context("active deposit omitted address")?;
    address.validate()?;
    anyhow::ensure!(address.network() == network);
    let certificate =
        response.certificate.as_ref().context("active deposit omitted certificate")?;
    let created_at = response.created_at.context("active deposit omitted creation time")?;
    let expires_at = response.expires_at.context("active deposit omitted expiry time")?;
    anyhow::ensure!(
        expires_at.checked_sub(created_at) == Some(UNUSED_ALLOCATION_TTL_SECONDS),
        "deposit allocation does not use the exact thirty-day unused lifetime"
    );
    let issuer =
        response.allocation_issuer.as_ref().context("active deposit omitted allocation issuer")?;
    issuer.validate()?;
    anyhow::ensure!(
        issuer.terminal().is_none(),
        "active deposit returned a terminal allocation issuer"
    );
    anyhow::ensure!(issuer.issuer() == response.serving_registry.active());
    anyhow::ensure!(issuer.issuer().wallet() == address.wallet_id());
    let verified = certificate.verify(issuer, None)?;
    anyhow::ensure!(verified.required() == public.committee.n() - fault_bound);
    let LedgerPayload::Allocation(allocation) = &certificate.statement.payload else {
        anyhow::bail!("deposit response certificate is not an allocation");
    };
    anyhow::ensure!(allocation.request == response.certified_request);
    anyhow::ensure!(allocation.binding == tenant_bound_request_binding(request));
    anyhow::ensure!(&allocation.address == address);
    anyhow::ensure!(allocation.created_at == created_at && allocation.expires_at == expires_at);
    anyhow::ensure!(certificate.statement.wallet == address.wallet_id());
    Ok(ValidatedDepositAllocationCandidate {
        allocation_issuer: issuer.issuer().clone(),
        statement: certificate.statement.clone(),
        address: address.clone(),
        created_at,
        expires_at,
        serving_registry: response.serving_registry.clone(),
        issuer: issuer.clone(),
    })
}

fn validate_replica_deposit_certificate(
    party: PartyId,
    deposit: &CertifiedDeposit,
    observed: &CertifiedLedgerEntry,
    issuer: &VerifiedIssuerWindow,
) -> anyhow::Result<Vec<PartyId>> {
    let expected = deposit
        .response
        .certificate
        .as_ref()
        .context("original certified deposit omitted its certificate")?;
    anyhow::ensure!(
        observed.statement == expected.statement,
        "party {party} returned a certificate for a different ledger statement"
    );
    issuer.validate()?;
    anyhow::ensure!(issuer.issuer() == &deposit.allocation_issuer);
    let verified = observed.verify(issuer, None)?;
    let observed_signers =
        observed.attestations.iter().map(|attestation| attestation.from).collect::<Vec<_>>();
    anyhow::ensure!(
        observed_signers.windows(2).all(|window| window[0] < window[1]),
        "party {party} returned a certificate with non-canonical signer order"
    );
    anyhow::ensure!(
        observed_signers.len() == verified.signers().len()
            && observed_signers.len() >= usize::from(verified.required()),
        "party {party} returned a certificate without its verified n-f signer quorum"
    );

    if observed != expected {
        let expected_signers =
            expected.attestations.iter().map(|attestation| attestation.from).collect::<Vec<_>>();
        anyhow::ensure!(
            observed_signers != expected_signers,
            "party {party} returned different certificate bytes for an identical signer set"
        );
        tracing::info!(
            %party,
            statement = %hex::encode(observed.statement.digest()),
            ?expected_signers,
            ?observed_signers,
            "replica returned an alternate valid quorum certificate for the same ledger statement"
        );
    }
    Ok(observed_signers)
}

async fn wait_for_permanent_deposit(
    _scenario: &Scenario,
    client: &PartyClient,
    public: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
) -> anyhow::Result<()> {
    wait_for_deposit_status(
        client,
        public,
        fault_bound,
        faulty,
        deposit,
        DepositHttpStatus::Permanent,
        client.protocol_timeout,
    )
    .await
}

fn deposit_allocation_acceptance_timeout(
    protocol_timeout: std::time::Duration,
) -> anyhow::Result<std::time::Duration> {
    // Initial view (1), backed-off replacement view (2), then checkpoint (1).
    protocol_timeout
        .checked_mul(4)
        .and_then(|timeout| {
            timeout.checked_add(std::time::Duration::from_secs(
                DEPOSIT_ALLOCATION_ISSUANCE_LEAD_SECONDS,
            ))
        })
        .context("deposit allocation acceptance timeout overflowed")
}

fn deposit_handoff_acceptance_timeout(
    protocol_timeout: std::time::Duration,
) -> anyhow::Result<std::time::Duration> {
    protocol_timeout
        .checked_mul(DEPOSIT_HANDOFF_ACCEPTANCE_WINDOWS)
        .context("deposit handoff acceptance timeout overflowed")
}

async fn wait_for_permanent_deposit_after_handoff(
    client: &PartyClient,
    public: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
) -> anyhow::Result<()> {
    wait_for_deposit_status(
        client,
        public,
        fault_bound,
        faulty,
        deposit,
        DepositHttpStatus::Permanent,
        deposit_handoff_acceptance_timeout(client.protocol_timeout)?,
    )
    .await
}

async fn wait_for_deposit_status(
    client: &PartyClient,
    public: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
    expected_status: DepositHttpStatus,
    observation_timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let committee = &public.committee;
    anyhow::ensure!(fault_bound < committee.n());
    let required = usize::from(committee.n() - fault_bound);
    let responsive = committee
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    anyhow::ensure!(responsive.len() >= required, "not enough responsive deposit replicas");
    let recovered_party = required_recovered_party()?;
    if let Some(recovered_party) = recovered_party {
        anyhow::ensure!(
            responsive.contains(&recovered_party),
            "required recovered party {recovered_party} is not a responsive epoch-{} member",
            committee.epoch
        );
    }
    let deadline = tokio::time::Instant::now() + observation_timeout;
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut groups =
            Vec::<EqualObservationGroup<(CompactEpochRegistry, VerifiedIssuerWindow)>>::new();
        for party in &responsive {
            match client
                .post_deposit::<_, DepositHttpResponse>(
                    *party,
                    "/v1/deposits/status",
                    &deposit.request,
                )
                .await
            {
                Ok(response) => {
                    observations.insert(
                        *party,
                        format!("{:?} leader={}", response.status, response.leader),
                    );
                    // The certificate below remains the immutable historical allocation, while
                    // `leader` is routing metadata for the active consensus view. A legitimate
                    // view change may select any member of the expected committee; the exact
                    // request, schedule, allocation issuer, and certificate remain checked below.
                    if !deposit_status_reached_current_epoch(
                        &response,
                        expected_status,
                        public,
                        fault_bound,
                    ) {
                        continue;
                    }
                    let validated = match (|| -> anyhow::Result<_> {
                        anyhow::ensure!(
                            response.request == deposit.response.request,
                            "response names another request"
                        );
                        anyhow::ensure!(
                            response.certified_request == deposit.response.certified_request,
                            "response names another certified request"
                        );
                        anyhow::ensure!(
                            response.address == deposit.response.address,
                            "response names another address"
                        );
                        anyhow::ensure!(
                            response.created_at == deposit.response.created_at
                                && response.expires_at == deposit.response.expires_at,
                            "response changed the allocation schedule"
                        );
                        let issuer = validate_response_allocation_issuer(
                            &response,
                            &deposit.allocation_issuer,
                        )?;
                        let certificate = response
                            .certificate
                            .as_ref()
                            .context("response omitted certificate")?;
                        let signers = validate_replica_deposit_certificate(
                            *party,
                            deposit,
                            certificate,
                            issuer,
                        )?;
                        Ok((signers, (response.serving_registry.clone(), issuer.clone())))
                    })() {
                        Ok(validated) => validated,
                        Err(error) => {
                            observations
                                .insert(*party, format!("invalid/non-candidate status: {error:#}"));
                            continue;
                        }
                    };
                    let (signers, authority) = validated;
                    observations.insert(
                        *party,
                        format!("{:?} certificate_signers={signers:?}", response.status),
                    );
                    record_equal_observation(&mut groups, *party, authority);
                }
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                }
            }
        }
        let required_parties = recovered_party.into_iter().collect::<BTreeSet<_>>();
        if equal_observation_quorum(&groups, required, &required_parties)?.is_some() {
            return Ok(());
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "deposit did not reach {expected_status:?} on n-f replicas; observations: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

fn validate_serving_deposit_registry(
    response: &DepositHttpResponse,
    expected: &EpochPublic,
    fault_bound: u16,
) -> anyhow::Result<()> {
    expected.validate()?;
    let registry = &response.serving_registry;
    registry.validate()?;
    let active = registry.active();
    anyhow::ensure!(registry.active_epoch() == expected.committee.epoch);
    anyhow::ensure!(active.committee() == &expected.committee);
    anyhow::ensure!(active.fault_bound() == fault_bound);
    anyhow::ensure!(active.activation() == expected.activation_digest()?);
    anyhow::ensure!(active.key_id() == expected.key_id);
    anyhow::ensure!(active.group_key() == expected.group_key_bytes());
    active.committee().member(response.leader)?;
    Ok(())
}

fn validate_response_allocation_issuer<'a>(
    response: &'a DepositHttpResponse,
    expected: &ActiveIssuer,
) -> anyhow::Result<&'a VerifiedIssuerWindow> {
    let window =
        response.allocation_issuer.as_ref().context("response omitted allocation issuer")?;
    window.validate()?;
    anyhow::ensure!(
        window.issuer() == expected,
        "response returned another immutable allocation issuer"
    );
    let serving_epoch = response.serving_registry.active_epoch();
    anyhow::ensure!(
        serving_epoch >= expected.epoch(),
        "serving registry predates the allocation issuer"
    );
    if serving_epoch > expected.epoch() {
        let terminal =
            window.terminal().context("historical allocation issuer omitted its terminal seal")?;
        anyhow::ensure!(
            terminal.successor_epoch
                == expected.epoch().checked_add(1).context("allocation issuer epoch overflow")?,
            "allocation issuer terminal seal names another successor"
        );
    } else {
        anyhow::ensure!(
            window.terminal().is_none(),
            "current allocation issuer unexpectedly retained a terminal seal"
        );
    }
    Ok(window)
}

fn deposit_status_reached_current_epoch(
    response: &DepositHttpResponse,
    expected_status: DepositHttpStatus,
    expected: &EpochPublic,
    fault_bound: u16,
) -> bool {
    response.status == expected_status
        && validate_serving_deposit_registry(response, expected, fault_bound).is_ok()
}

fn consolidation_fault_gate_enabled() -> anyhow::Result<bool> {
    Ok(std::env::var("TM_ACCEPTANCE_ENABLE_FAULT_HOOKS").as_deref() == Ok("1")
        && environment_flag("TM_ACCEPTANCE_REQUIRE_CONSOLIDATION_GATE")?)
}

fn consolidation_bootstrap_fault_gate_enabled() -> anyhow::Result<bool> {
    Ok(std::env::var("TM_ACCEPTANCE_ENABLE_FAULT_HOOKS").as_deref() == Ok("1")
        && environment_flag("TM_ACCEPTANCE_REQUIRE_CONSOLIDATION_BOOTSTRAP_GATE")?)
}

async fn arm_consolidation_bootstrap_fault_gate(
    client: &PartyClient,
    committee: &Committee,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<()> {
    if !consolidation_bootstrap_fault_gate_enabled()? {
        return Ok(());
    }
    anyhow::ensure!(
        consolidation_fault_gate_enabled()?,
        "bootstrap omission also requires the certified pre-nonce consolidation gate"
    );
    anyhow::ensure!(
        faulty.is_empty(),
        "bootstrap gate must be armed on every epoch-0 party before the proposer is stopped"
    );
    for member in &committee.members {
        let response = client
            .post_admin::<_, AcceptanceConsolidationBootstrapGateResponse>(
                member.id,
                "/v1/acceptance/consolidation-bootstrap-gate",
                &AcceptanceConsolidationGateRequest {
                    action: AcceptanceConsolidationGateAction::Arm,
                },
            )
            .await
            .with_context(|| {
                format!("arming consolidation bootstrap gate on party {}", member.id)
            })?;
        anyhow::ensure!(response.party == member.id);
        anyhow::ensure!(response.state == AcceptanceConsolidationGateState::Armed);
        anyhow::ensure!(
            response.sweep.is_none()
                && response.bootstrap_ba_view.is_none()
                && response.proposer.is_none()
                && response.prepared_intent_digest.is_none()
        );
    }
    tracing::warn!(
        parties = committee.members.len(),
        "armed acceptance-only bootstrap BA gates before deposit maturity"
    );
    Ok(())
}

async fn wait_for_consolidation_bootstrap_held(
    client: &PartyClient,
    committee: &Committee,
) -> anyhow::Result<PendingConsolidationBootstrapFault> {
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let request =
        AcceptanceConsolidationGateRequest { action: AcceptanceConsolidationGateAction::Status };
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut held = BTreeMap::new();
        for member in &committee.members {
            let response = match client
                .post_admin::<_, AcceptanceConsolidationBootstrapGateResponse>(
                    member.id,
                    "/v1/acceptance/consolidation-bootstrap-gate",
                    &request,
                )
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    observations.insert(member.id, format!("bootstrap gate error: {error:#}"));
                    continue;
                }
            };
            anyhow::ensure!(response.party == member.id);
            observations.insert(member.id, format!("{response:?}"));
            if response.state != AcceptanceConsolidationGateState::Held {
                continue;
            }
            let sweep = response.sweep.context("held bootstrap gate omitted its sweep")?;
            let bootstrap_ba_view =
                response.bootstrap_ba_view.context("held bootstrap gate omitted its BA view")?;
            let proposer = response.proposer.context("held bootstrap gate omitted its proposer")?;
            let digest = response
                .prepared_intent_digest
                .context("held bootstrap gate omitted its prepared intent")?;
            anyhow::ensure!(sweep.0 != [0; 32] && digest != [0; 32]);
            anyhow::ensure!(bootstrap_ba_view == 0, "bootstrap gate missed BA view zero");
            committee.member(proposer)?;
            held.insert(member.id, (sweep, bootstrap_ba_view, proposer, digest));
        }
        if held.len() == committee.members.len() {
            let (_, (sweep, initial_ba_view, fault_party, _)) =
                held.first_key_value().context("bootstrap gate omitted all held parties")?;
            let sweep = *sweep;
            let initial_ba_view = *initial_ba_view;
            let fault_party = *fault_party;
            anyhow::ensure!(
                held.values().all(|entry| {
                    entry.0 == sweep && entry.1 == initial_ba_view && entry.2 == fault_party
                }),
                "bootstrap gates disagree on their sweep, view, or deterministic proposer"
            );
            let prepared_intent_candidates =
                held.iter().map(|(party, entry)| (*party, entry.3)).collect::<BTreeMap<_, _>>();
            let initial_prepared_intent_digest = *prepared_intent_candidates
                .get(&fault_party)
                .context("slot-zero proposer omitted its prepared intent")?;
            anyhow::ensure!(
                prepared_intent_candidates.iter().any(|(party, digest)| {
                    *party != fault_party && *digest != initial_prepared_intent_digest
                }),
                "bootstrap candidates were not independently randomized across proposers"
            );
            return Ok(PendingConsolidationBootstrapFault {
                sweep,
                fault_party,
                initial_ba_view,
                initial_prepared_intent_digest,
                prepared_intent_candidates,
            });
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "all consolidation bootstrap gates did not reach Held; observations: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

async fn wait_for_consolidation_bootstrap_released(
    client: &PartyClient,
    committee: &Committee,
    required_parties: &BTreeSet<PartyId>,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let request =
        AcceptanceConsolidationGateRequest { action: AcceptanceConsolidationGateAction::Status };
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut released = BTreeSet::new();
        for party in required_parties {
            committee.member(*party)?;
            let response = match client
                .post_admin::<_, AcceptanceConsolidationBootstrapGateResponse>(
                    *party,
                    "/v1/acceptance/consolidation-bootstrap-gate",
                    &request,
                )
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    observations.insert(*party, format!("bootstrap gate error: {error:#}"));
                    continue;
                }
            };
            anyhow::ensure!(response.party == *party);
            observations.insert(*party, format!("{response:?}"));
            if response.state == AcceptanceConsolidationGateState::Released {
                anyhow::ensure!(
                    response.sweep.is_none()
                        && response.bootstrap_ba_view.is_none()
                        && response.proposer.is_none()
                        && response.prepared_intent_digest.is_none()
                );
                released.insert(*party);
            }
        }
        if released == *required_parties {
            return Ok(());
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "bootstrap gates did not release on the required parties; observations: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

async fn maybe_pause_before_consolidation_bootstrap(
    client: &PartyClient,
    committee: &Committee,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<Option<PendingConsolidationBootstrapFault>> {
    if !consolidation_bootstrap_fault_gate_enabled()? {
        return Ok(None);
    }
    anyhow::ensure!(faulty.is_empty());
    anyhow::ensure!(fault_bound > 0 && fault_bound < committee.n());
    let pending = wait_for_consolidation_bootstrap_held(client, committee).await?;
    let mut survivors = committee.members.iter().map(|member| member.id).collect::<BTreeSet<_>>();
    survivors.remove(&pending.fault_party);
    anyhow::ensure!(survivors.len() >= usize::from(committee.n() - fault_bound));
    println!(
        "TM_ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_BARRIER sweep={} fault_party={} initial_ba_view={} initial_prepared_intent={} candidates={}",
        hex::encode(pending.sweep.0),
        pending.fault_party,
        pending.initial_ba_view,
        hex::encode(pending.initial_prepared_intent_digest),
        pending
            .prepared_intent_candidates
            .iter()
            .map(|(party, digest)| format!("{}:{}", party, hex::encode(digest)))
            .collect::<Vec<_>>()
            .join(","),
    );
    {
        use std::io::Write as _;
        std::io::stdout().flush()?;
    }
    wait_for_consolidation_bootstrap_released(client, committee, &survivors).await?;
    Ok(Some(pending))
}

fn validate_consolidation_bootstrap_recovery(
    pending: &PendingConsolidationBootstrapFault,
    status: &ObservedConsolidation,
    committee: &Committee,
    fault_bound: u16,
) -> anyhow::Result<ConsolidationBootstrapProof> {
    anyhow::ensure!(status.sweep == pending.sweep);
    anyhow::ensure!(
        status.bootstrap_ba_view > pending.initial_ba_view,
        "stopped slot-zero proposer did not force a bootstrap BA view change"
    );
    anyhow::ensure!(
        status.bootstrap_ba_proposer != pending.fault_party,
        "bootstrap BA still certified the stopped slot-zero proposer"
    );
    committee.member(status.bootstrap_ba_proposer)?;
    anyhow::ensure!(
        status.bootstrap_prepared_intent_digest != pending.initial_prepared_intent_digest,
        "bootstrap BA view change reused the stopped proposer's prepared intent"
    );
    anyhow::ensure!(
        pending.prepared_intent_candidates.get(&status.bootstrap_ba_proposer)
            == Some(&status.bootstrap_prepared_intent_digest),
        "bootstrap BA did not certify the replacement proposer's independently prepared intent"
    );
    anyhow::ensure!(
        status.bootstrap_certificate_digest != [0; 32],
        "bootstrap BA omitted its durable certificate digest"
    );
    let required = usize::from(committee.n() - fault_bound);
    anyhow::ensure!(
        status.bootstrap_certificate_signers.len() >= required
            && status.bootstrap_certificate_signers.len() <= usize::from(committee.n()),
        "bootstrap BA certificate lacks n-f bounded signers"
    );
    anyhow::ensure!(
        status.bootstrap_certificate_signers.windows(2).all(|pair| pair[0] < pair[1]),
        "bootstrap BA certificate signers are not canonical and unique"
    );
    for signer in &status.bootstrap_certificate_signers {
        committee.member(*signer)?;
    }
    anyhow::ensure!(
        status.roast_view == 0,
        "bootstrap BA evidence was conflated with an outer ROAST signer-view change"
    );
    Ok(ConsolidationBootstrapProof {
        sweep: pending.sweep,
        fault_party: pending.fault_party,
        initial_ba_view: pending.initial_ba_view,
        initial_prepared_intent_digest: pending.initial_prepared_intent_digest,
        certified_ba_view: status.bootstrap_ba_view,
        certified_proposer: status.bootstrap_ba_proposer,
        certified_prepared_intent_digest: status.bootstrap_prepared_intent_digest,
        certificate_digest: status.bootstrap_certificate_digest,
        certificate_signers: status.bootstrap_certificate_signers.clone(),
    })
}

fn validate_consolidation_bootstrap_stability(
    proof: &ConsolidationBootstrapProof,
    status: &ObservedConsolidation,
) -> anyhow::Result<()> {
    anyhow::ensure!(status.sweep == proof.sweep);
    anyhow::ensure!(
        status.bootstrap_prepared_intent_digest == proof.certified_prepared_intent_digest
    );
    anyhow::ensure!(status.bootstrap_certificate_digest == proof.certificate_digest);
    anyhow::ensure!(
        status.roast_view == 0,
        "outer ROAST view changed after the bootstrap proposer had already rejoined"
    );
    Ok(())
}

async fn complete_consolidation_bootstrap_fault_before_signing(
    client: &PartyClient,
    committee: &Committee,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
    expected_destination: [u8; 32],
    pending: &PendingConsolidationBootstrapFault,
) -> anyhow::Result<ConsolidationBootstrapProof> {
    anyhow::ensure!(faulty.is_empty());
    let required = usize::from(committee.n() - fault_bound);
    let mut bootstrap_faulty = faulty.clone();
    bootstrap_faulty.insert(pending.fault_party);
    let no_required_gate_parties = BTreeSet::new();
    let (held_authorization, _) = wait_for_consolidation_fault_gate_state(
        client,
        committee,
        AcceptanceConsolidationGateState::Held,
        required,
        &no_required_gate_parties,
    )
    .await?;
    let held_authorization = held_authorization
        .context("bootstrap survivors held no certified pre-nonce authorization")?;
    let reserved = wait_for_consolidation_phase(
        client,
        committee,
        fault_bound,
        &bootstrap_faulty,
        deposit,
        expected_destination,
        PublicConsolidationPhase::Reserved,
    )
    .await?;
    anyhow::ensure!(reserved.authorization == held_authorization);
    anyhow::ensure!(reserved.signed.is_none() && reserved.certificate_digest.is_none());
    anyhow::ensure!(
        reserved.roast_candidate_count == 0
            && reserved.roast_endorsed_candidate_count == 0
            && reserved.roast_endorsed_witness_count == 0
    );
    anyhow::ensure!(
        reserved.key_image_binding_digest == [0; 32]
            && reserved.key_image_unsigned_transaction_digest == [0; 32]
            && reserved.key_image_authorizers.is_empty()
            && reserved.key_image_authorization_quorum == 0,
        "bootstrap certificate gate was crossed after key-image authorization began"
    );
    let proof =
        validate_consolidation_bootstrap_recovery(pending, &reserved, committee, fault_bound)?;
    println!(
        "TM_ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_CERTIFIED sweep={} fault_party={} initial_ba_view={} certified_ba_view={} certified_proposer={} initial_prepared_intent={} certified_prepared_intent={} bootstrap_certificate={} bootstrap_certificate_signers={} roast_view={}",
        hex::encode(proof.sweep.0),
        proof.fault_party,
        proof.initial_ba_view,
        proof.certified_ba_view,
        proof.certified_proposer,
        hex::encode(proof.initial_prepared_intent_digest),
        hex::encode(proof.certified_prepared_intent_digest),
        hex::encode(proof.certificate_digest),
        format_party_list(&proof.certificate_signers),
        reserved.roast_view,
    );
    {
        use std::io::Write as _;
        std::io::stdout().flush()?;
    }

    let all_parties = committee.members.iter().map(|member| member.id).collect::<BTreeSet<_>>();
    // Docker restarts the stopped proposer and releases only its still-durable bootstrap gate.
    wait_for_consolidation_bootstrap_released(client, committee, &all_parties).await?;
    let rejoined_required_parties = BTreeSet::from([pending.fault_party]);
    let (rejoined_authorization, held_parties) = wait_for_consolidation_fault_gate_state(
        client,
        committee,
        AcceptanceConsolidationGateState::Held,
        required,
        &rejoined_required_parties,
    )
    .await?;
    anyhow::ensure!(rejoined_authorization == Some(held_authorization));
    anyhow::ensure!(
        held_parties.len() >= required && held_parties.contains(&pending.fault_party),
        "bootstrap proposer did not rejoin the n-f held-authorization observation"
    );
    let rejoined = wait_for_consolidation_phase(
        client,
        committee,
        fault_bound,
        faulty,
        deposit,
        expected_destination,
        PublicConsolidationPhase::Reserved,
    )
    .await?;
    anyhow::ensure!(
        rejoined.same_quorum_decision(&reserved),
        "rejoined bootstrap replicas changed the certified consolidation decision"
    );
    validate_consolidation_bootstrap_stability(&proof, &rejoined)?;
    println!(
        "TM_ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_REJOINED party={} bootstrap_ba_view={} roast_view={} authorization={}",
        proof.fault_party,
        proof.certified_ba_view,
        rejoined.roast_view,
        hex::encode(rejoined.authorization.0),
    );
    {
        use std::io::Write as _;
        std::io::stdout().flush()?;
    }
    let _ = wait_for_consolidation_fault_gate_state(
        client,
        committee,
        AcceptanceConsolidationGateState::Released,
        required,
        &rejoined_required_parties,
    )
    .await?;
    Ok(proof)
}

async fn arm_consolidation_fault_gate(
    client: &PartyClient,
    committee: &Committee,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<()> {
    if !consolidation_fault_gate_enabled()? {
        return Ok(());
    }
    anyhow::ensure!(faulty.is_empty(), "consolidation gate must be armed on every epoch-0 party");
    for member in &committee.members {
        let response = client
            .post_admin::<_, AcceptanceConsolidationGateResponse>(
                member.id,
                "/v1/acceptance/consolidation-gate",
                &AcceptanceConsolidationGateRequest {
                    action: AcceptanceConsolidationGateAction::Arm,
                },
            )
            .await
            .with_context(|| format!("arming consolidation gate on party {}", member.id))?;
        anyhow::ensure!(response.party == member.id);
        anyhow::ensure!(response.state == AcceptanceConsolidationGateState::Armed);
        anyhow::ensure!(response.authorization.is_none() && response.roast_view.is_none());
    }
    tracing::warn!(
        parties = committee.members.len(),
        "armed acceptance-only consolidation gates before deposit maturity"
    );
    Ok(())
}

async fn wait_for_consolidation_fault_gate_state(
    client: &PartyClient,
    committee: &Committee,
    expected: AcceptanceConsolidationGateState,
    required: usize,
    required_parties: &BTreeSet<PartyId>,
) -> anyhow::Result<(Option<ConsolidationId>, BTreeSet<PartyId>)> {
    anyhow::ensure!(required > 0 && required <= committee.members.len());
    for party in required_parties {
        committee.member(*party).with_context(|| {
            format!("required consolidation-gate observer {party} is not a committee member")
        })?;
    }
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let request =
        AcceptanceConsolidationGateRequest { action: AcceptanceConsolidationGateAction::Status };
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut held_groups = Vec::<EqualObservationGroup<ConsolidationId>>::new();
        let mut matching_parties = BTreeSet::new();
        for member in &committee.members {
            let response = match client
                .post_admin::<_, AcceptanceConsolidationGateResponse>(
                    member.id,
                    "/v1/acceptance/consolidation-gate",
                    &request,
                )
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    observations.insert(member.id, format!("gate status error: {error:#}"));
                    continue;
                }
            };
            observations.insert(
                member.id,
                format!(
                    "{:?} authorization={:?} roast_view={:?}",
                    response.state, response.authorization, response.roast_view
                ),
            );
            let authorization = match (|| -> anyhow::Result<Option<ConsolidationId>> {
                anyhow::ensure!(
                    response.party == member.id,
                    "gate status endpoint returned another party ID"
                );
                if response.state != expected {
                    return Ok(None);
                }
                if expected != AcceptanceConsolidationGateState::Held {
                    anyhow::ensure!(
                        response.authorization.is_none() && response.roast_view.is_none(),
                        "inactive consolidation gate retained authorization or ROAST state"
                    );
                    return Ok(None);
                }
                let authorization = response
                    .authorization
                    .context("held consolidation gate omitted its authorization")?;
                anyhow::ensure!(
                    authorization.0 != [0; 32],
                    "held consolidation gate returned a zero authorization"
                );
                anyhow::ensure!(
                    response.roast_view == Some(0),
                    "held consolidation gate did not remain at ROAST view zero"
                );
                Ok(Some(authorization))
            })() {
                Ok(authorization) => authorization,
                Err(error) => {
                    observations
                        .insert(member.id, format!("invalid/non-candidate gate status: {error:#}"));
                    continue;
                }
            };
            if response.state != expected {
                continue;
            }
            if let Some(authorization) = authorization {
                record_equal_observation(&mut held_groups, member.id, authorization);
            } else {
                matching_parties.insert(member.id);
            }
        }
        if expected == AcceptanceConsolidationGateState::Held {
            if let Some(group) =
                equal_observation_quorum(&held_groups, required, &required_parties)?
            {
                return Ok((Some(group.value), group.parties.clone()));
            }
        } else if matching_parties.len() >= required
            && required_parties.is_subset(&matching_parties)
        {
            return Ok((None, matching_parties));
        }
        let held_group_summary = held_groups
            .iter()
            .enumerate()
            .map(|(index, group)| {
                format!(
                    "group {index}: authorization={} parties={}",
                    hex::encode(group.value.0),
                    format_party_list(&group.parties.iter().copied().collect::<Vec<_>>()),
                )
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "consolidation gates did not reach {expected:?} on {required} parties; \
             held_groups: {held_group_summary:?}; observations: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

/// Compose-only barrier for the consolidation omission campaign. The last block has already made
/// the real deposit output mature on chain. Requiring an n-f exact `Reserved` view proves that no
/// signing result or nonce-bearing round can begin: the party runtimes are also durably `Held` at
/// an explicitly armed acceptance gate. The Docker driver releases those gates over authenticated
/// admin endpoints only after removing one selected signer from the peer-QUIC network.
async fn maybe_pause_before_consolidation_signing(
    client: &PartyClient,
    committee: &Committee,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
    expected_destination: [u8; 32],
) -> anyhow::Result<Option<PendingConsolidationFault>> {
    if !consolidation_fault_gate_enabled()? {
        return Ok(None);
    }
    anyhow::ensure!(fault_bound > 0, "consolidation omission requires a positive fault bound");
    let required = usize::from(committee.n() - fault_bound);
    let no_required_gate_parties = BTreeSet::new();
    let (held_authorization, held_parties) = wait_for_consolidation_fault_gate_state(
        client,
        committee,
        AcceptanceConsolidationGateState::Held,
        required,
        &no_required_gate_parties,
    )
    .await?;
    let held_authorization = held_authorization
        .context("held consolidation gates omitted their agreed authorization")?;
    let reserved = wait_for_consolidation_phase(
        client,
        committee,
        fault_bound,
        faulty,
        deposit,
        expected_destination,
        PublicConsolidationPhase::Reserved,
    )
    .await?;
    anyhow::ensure!(reserved.authorization == held_authorization);
    anyhow::ensure!(reserved.roast_view == 0, "fault barrier did not observe ROAST view zero");
    anyhow::ensure!(
        reserved.roast_view_count == 1,
        "fault barrier observed more than the initial ROAST view"
    );
    anyhow::ensure!(reserved.signed.is_none(), "fault barrier observed a signed transaction");
    anyhow::ensure!(
        reserved.certificate_digest.is_none(),
        "fault barrier observed a completed consolidation certificate"
    );
    anyhow::ensure!(
        reserved.roast_candidate_count == 0 && reserved.roast_endorsed_candidate_count == 0,
        "fault barrier observed a transaction candidate before the omission"
    );
    anyhow::ensure!(
        reserved.roast_endorsed_witness_count == 0,
        "fault barrier observed an endorsed witness before nonce release"
    );
    anyhow::ensure!(
        reserved.key_image_binding_digest == [0; 32]
            && reserved.key_image_unsigned_transaction_digest == [0; 32]
            && reserved.key_image_authorizers.is_empty()
            && reserved.key_image_authorization_quorum == 0,
        "fault barrier observed key-image authorization before FROST round one"
    );

    let next_signers = deterministic_roast_signers(committee, fault_bound, 1)?;
    let fault_party = reserved
        .roast_signers
        .iter()
        .rev()
        .copied()
        .find(|party| held_parties.contains(party) && !next_signers.contains(party))
        .context(
            "the next ROAST view did not replace a selected signer durably held before nonce release",
        )?;
    let pending = PendingConsolidationFault {
        authorization: reserved.authorization,
        fault_party,
        initial_view: reserved.roast_view,
        initial_view_count: reserved.roast_view_count,
        initial_relay_seed: reserved.roast_relay_seed,
        initial_signers: reserved.roast_signers.clone(),
        initial_intent_certificate_digest: reserved.roast_intent_certificate_digest,
        initial_attempt_binding_digest: reserved.roast_attempt_binding_digest,
    };
    println!(
        "TM_ACCEPTANCE_CONSOLIDATION_FAULT_BARRIER authorization={} fault_party={} initial_view={} initial_view_count={} relay_seed={} signers={} intent_certificate={} attempt_binding={}",
        hex::encode(pending.authorization.0),
        pending.fault_party,
        pending.initial_view,
        pending.initial_view_count,
        pending.initial_relay_seed,
        format_party_list(&pending.initial_signers),
        hex::encode(pending.initial_intent_certificate_digest),
        hex::encode(pending.initial_attempt_binding_digest),
    );
    {
        use std::io::Write as _;
        std::io::stdout().flush()?;
    }
    tracing::warn!(
        authorization = %hex::encode(pending.authorization.0),
        fault_party = %pending.fault_party,
        initial_view = pending.initial_view,
        initial_signers = ?pending.initial_signers,
        "mature consolidation is durably held at the pre-signing fault barrier"
    );
    let rejoined_required_parties = BTreeSet::from([pending.fault_party]);
    let _ = wait_for_consolidation_fault_gate_state(
        client,
        committee,
        AcceptanceConsolidationGateState::Released,
        required,
        &rejoined_required_parties,
    )
    .await?;
    tracing::warn!(
        authorization = %hex::encode(pending.authorization.0),
        "n-f acceptance-only consolidation gates, including the omitted signer, released after fault injection"
    );
    Ok(Some(pending))
}

fn validate_consolidation_fault_recovery(
    pending: &PendingConsolidationFault,
    broadcast: &ObservedConsolidation,
) -> anyhow::Result<ConsolidationFaultProof> {
    anyhow::ensure!(
        broadcast.roast_view > pending.initial_view,
        "peer-QUIC omission did not force a later ROAST view"
    );
    anyhow::ensure!(
        broadcast.roast_view_count > pending.initial_view_count,
        "peer-QUIC omission did not increase the durable ROAST view count"
    );
    anyhow::ensure!(
        broadcast.roast_signers != pending.initial_signers,
        "peer-QUIC omission did not replace the selected signer subset"
    );
    anyhow::ensure!(
        broadcast.roast_intent_certificate_digest != pending.initial_intent_certificate_digest,
        "replacement ROAST view reused the initial intent certificate"
    );
    anyhow::ensure!(
        broadcast.roast_attempt_binding_digest != pending.initial_attempt_binding_digest,
        "replacement ROAST view reused the initial signing-attempt binding"
    );
    anyhow::ensure!(
        !broadcast.roast_signers.contains(&pending.fault_party),
        "the completed ROAST view still selected peer-QUIC-silent party {}",
        pending.fault_party
    );
    anyhow::ensure!(
        broadcast.roast_candidate_count > 0 && broadcast.roast_endorsed_candidate_count > 0,
        "the replacement ROAST view did not produce an endorsed transaction candidate"
    );
    let signed = broadcast.signed.context("broadcast consolidation omitted signed binding")?;
    anyhow::ensure!(
        signed.attempt()
            == broadcast.roast_view.checked_add(1).context("ROAST attempt counter overflow")?,
        "broadcast transaction came from another ROAST view instead of the replacement subset"
    );
    anyhow::ensure!(
        signed.attempt_binding_digest() == broadcast.roast_attempt_binding_digest,
        "broadcast transaction is not bound to the replacement ROAST attempt"
    );
    Ok(ConsolidationFaultProof {
        fault_party: pending.fault_party,
        initial_view: pending.initial_view,
        initial_view_count: pending.initial_view_count,
        initial_relay_seed: pending.initial_relay_seed,
        initial_signers: pending.initial_signers.clone(),
        initial_intent_certificate_digest: pending.initial_intent_certificate_digest,
        initial_attempt_binding_digest: pending.initial_attempt_binding_digest,
        completed_view: broadcast.roast_view,
        completed_view_count: broadcast.roast_view_count,
        completed_relay_seed: broadcast.roast_relay_seed,
        completed_signers: broadcast.roast_signers.clone(),
        completed_intent_certificate_digest: broadcast.roast_intent_certificate_digest,
        completed_attempt_binding_digest: broadcast.roast_attempt_binding_digest,
    })
}

async fn maybe_pause_after_consolidation_fault_settlement(
    client: &PartyClient,
    proof: &ConsolidationFaultProof,
    confirmed: &ObservedConsolidation,
) -> anyhow::Result<()> {
    anyhow::ensure!(confirmed.phase == PublicConsolidationPhase::Confirmed);
    anyhow::ensure!(confirmed.roast_view == proof.completed_view);
    anyhow::ensure!(confirmed.roast_view_count == proof.completed_view_count);
    anyhow::ensure!(confirmed.roast_relay_seed == proof.completed_relay_seed);
    anyhow::ensure!(confirmed.roast_signers == proof.completed_signers);
    anyhow::ensure!(
        confirmed.roast_intent_certificate_digest == proof.completed_intent_certificate_digest
    );
    anyhow::ensure!(
        confirmed.roast_attempt_binding_digest == proof.completed_attempt_binding_digest
    );
    let signed = confirmed
        .signed
        .context("confirmed consolidation omitted its signed transaction binding")?;
    let confirmation = confirmed
        .confirmation
        .context("confirmed consolidation omitted its canonical confirmation point")?;
    let proof_bytes = postcard::to_allocvec(proof)?;
    let status_bytes = postcard::to_allocvec(confirmed)?;
    let mut material = Vec::with_capacity(
        1 + std::mem::size_of::<u64>() * 2 + proof_bytes.len() + status_bytes.len(),
    );
    material.push(1);
    material.extend_from_slice(&(proof_bytes.len() as u64).to_le_bytes());
    material.extend_from_slice(&proof_bytes);
    material.extend_from_slice(&(status_bytes.len() as u64).to_le_bytes());
    material.extend_from_slice(&status_bytes);
    let kind = AcceptanceDriverLatchKind::ConsolidationPeerReconnect;
    let binding = acceptance_driver_binding(kind, &material);
    let armed: AcceptanceDriverLatchResponse = client
        .post_admin(
            proof.fault_party,
            "/v1/acceptance/driver-latch",
            &AcceptanceDriverLatchRequest {
                action: AcceptanceConsolidationGateAction::Arm,
                kind,
                binding,
            },
        )
        .await?;
    anyhow::ensure!(
        armed.party == proof.fault_party
            && armed.state == AcceptanceConsolidationGateState::Held
            && armed.kind == Some(kind)
            && armed.binding == Some(binding)
            && armed.event_unix_ms.is_none(),
        "omitted signer held a different consolidation-reconnect latch"
    );
    println!(
        "TM_ACCEPTANCE_CONSOLIDATION_FAULT_SETTLED fault_party={} initial_view={} completed_view={} completed_view_count={} completed_relay_seed={} completed_signers={} intent_certificate={} attempt_binding={} key_image_binding={} key_image_unsigned_transaction={} key_image_authorizers={} key_image_quorum={}",
        proof.fault_party,
        proof.initial_view,
        proof.completed_view,
        proof.completed_view_count,
        proof.completed_relay_seed,
        format_party_list(&proof.completed_signers),
        hex::encode(proof.completed_intent_certificate_digest),
        hex::encode(proof.completed_attempt_binding_digest),
        hex::encode(confirmed.key_image_binding_digest),
        hex::encode(confirmed.key_image_unsigned_transaction_digest),
        format_party_list(&confirmed.key_image_authorizers),
        confirmed.key_image_authorization_quorum,
    );
    println!(
        "TM_ACCEPTANCE_CONSOLIDATION_PEER_RECONNECT_LATCH_HELD party={} txid={} confirmation_height={} confirmation_hash={} binding={}",
        proof.fault_party,
        hex::encode(signed.transaction()),
        confirmation.height,
        hex::encode(confirmation.hash),
        hex::encode(binding),
    );
    {
        use std::io::Write as _;
        std::io::stdout().flush()?;
    }
    tracing::warn!(
        fault_party = %proof.fault_party,
        completed_view = proof.completed_view,
        completed_signers = ?proof.completed_signers,
        binding = %hex::encode(binding),
        "fault-resilient consolidation settled; awaiting authenticated peer-QUIC reconnection release"
    );
    wait_for_authenticated_driver_release(client, proof.fault_party, kind, binding).await?;
    println!(
        "TM_ACCEPTANCE_CONSOLIDATION_PEER_RECONNECT_LATCH_RELEASED party={} txid={} binding={}",
        proof.fault_party,
        hex::encode(signed.transaction()),
        hex::encode(binding),
    );
    Ok(())
}

fn format_party_list(parties: &[PartyId]) -> String {
    parties.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
}

fn certified_deposit_inputs(deposit: &CertifiedDeposit) -> anyhow::Result<Vec<WalletOutputId>> {
    anyhow::ensure!(!deposit.funded_outputs.is_empty(), "deposit output evidence is missing");
    let mut inputs =
        deposit.funded_outputs.iter().map(|output| output.id).collect::<Vec<WalletOutputId>>();
    inputs.sort_unstable();
    anyhow::ensure!(
        inputs.windows(2).all(|pair| pair[0] != pair[1]),
        "deposit output evidence contains a duplicate wallet output"
    );
    Ok(inputs)
}

fn certified_deposit_total(deposit: &CertifiedDeposit) -> anyhow::Result<u64> {
    deposit.funded_outputs.iter().try_fold(0_u64, |total, output| {
        total
            .checked_add(output.amount_atomic_units)
            .context("certified deposit input amount overflow")
    })
}

fn assign_certified_input_ring(
    ring_position: usize,
    ring_candidates: &[Vec<WalletOutputId>],
    visited_outputs: &mut BTreeSet<WalletOutputId>,
    input_ring_mapping: &mut BTreeMap<WalletOutputId, usize>,
) -> bool {
    for output in &ring_candidates[ring_position] {
        if !visited_outputs.insert(*output) {
            continue;
        }
        let can_assign = match input_ring_mapping.get(output).copied() {
            None => true,
            Some(displaced_ring) => assign_certified_input_ring(
                displaced_ring,
                ring_candidates,
                visited_outputs,
                input_ring_mapping,
            ),
        };
        if can_assign {
            input_ring_mapping.insert(*output, ring_position);
            return true;
        }
    }
    false
}

fn deterministic_roast_signers(
    committee: &Committee,
    fault_bound: u16,
    view: u64,
) -> anyhow::Result<Vec<PartyId>> {
    crate::consolidation_roast::deterministic_roast_signers(committee, fault_bound, view)
        .map_err(Into::into)
}

fn consolidation_phase_satisfies_observer(
    actual: PublicConsolidationPhase,
    expected: PublicConsolidationPhase,
) -> bool {
    // Polling can miss Broadcast when an earlier maturity-block advance already mined the tx.
    actual == expected
        || (expected == PublicConsolidationPhase::Broadcast
            && actual == PublicConsolidationPhase::Confirmed)
}

async fn wait_for_consolidation_phase(
    client: &PartyClient,
    committee: &Committee,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
    expected_destination: [u8; 32],
    expected_phase: PublicConsolidationPhase,
) -> anyhow::Result<ObservedConsolidation> {
    anyhow::ensure!(fault_bound < committee.n());
    let expected_inputs = certified_deposit_inputs(deposit)?;
    let queried_output =
        *expected_inputs.first().context("certified deposit has no consolidation output")?;
    let status_request =
        DepositConsolidationStatusRequest { request: deposit.request, output: queried_output };
    let required = usize::from(committee.n() - fault_bound);
    let responsive = committee
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    anyhow::ensure!(responsive.len() >= required, "not enough responsive consolidation replicas");
    let recovered_party = required_recovered_party()?;
    if let Some(recovered_party) = recovered_party {
        anyhow::ensure!(
            responsive.contains(&recovered_party),
            "required recovered party {recovered_party} is not a responsive epoch-{} member",
            committee.epoch
        );
    }
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut decision_groups = Vec::<(ObservedConsolidation, usize, bool, Vec<PartyId>)>::new();
        for party in &responsive {
            let response = match client
                .post_deposit::<_, DepositConsolidationStatusResponse>(
                    *party,
                    "/v1/deposits/consolidations/status",
                    &status_request,
                )
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                    continue;
                }
            };
            let status = match (|| -> anyhow::Result<ObservedConsolidation> {
                anyhow::ensure!(
                    response.request == deposit.request.request,
                    "response names another request"
                );
                anyhow::ensure!(
                    response.certified_request == tenant_certified_request_id(deposit.request),
                    "response names another certified request"
                );
                anyhow::ensure!(
                    response.output == queried_output,
                    "response names another deposit output"
                );
                let status = response
                    .consolidation
                    .context("consolidation is not discovered on this replica")?;
                let status = ObservedConsolidation::from_public(status)?;
                anyhow::ensure!(
                    status.plan.inputs.as_slice() == expected_inputs.as_slice(),
                    "consolidation did not claim the queried deposit set"
                );
                validate_public_consolidation(
                    &status,
                    committee,
                    fault_bound,
                    deposit,
                    expected_destination,
                )?;
                anyhow::ensure!(
                    !matches!(
                        status.phase,
                        PublicConsolidationPhase::Quarantined | PublicConsolidationPhase::Aborted
                    ),
                    "consolidation entered terminal failure phase {:?}",
                    status.phase
                );
                Ok(status)
            })() {
                Ok(status) => status,
                Err(error) => {
                    observations.insert(*party, format!("invalid/non-candidate status: {error:#}"));
                    continue;
                }
            };
            observations.insert(
                *party,
                format!(
                    "{:?} bootstrap_ba_view={} bootstrap_proposer={} bootstrap_certificate_signers={} roast_view={} relay_seed={} signers={} views={} candidates={}/{} witnesses={} view_cert_signers={} completion_signers={} key_image_authorizers={} key_image_quorum={} bootstrap_prepared_intent={} bootstrap_certificate={} intent_certificate={} attempt_binding={} key_image_binding={} key_image_unsigned_transaction={} evidence={}",
                    status.phase,
                    status.bootstrap_ba_view,
                    status.bootstrap_ba_proposer,
                    format_party_list(&status.bootstrap_certificate_signers),
                    status.roast_view,
                    status.roast_relay_seed,
                    format_party_list(&status.roast_signers),
                    status.roast_view_count,
                    status.roast_endorsed_candidate_count,
                    status.roast_candidate_count,
                    status.roast_endorsed_witness_count,
                    format_party_list(&status.roast_intent_certificate_signers),
                    format_party_list(&status.completion_certificate_signers),
                    format_party_list(&status.key_image_authorizers),
                    status.key_image_authorization_quorum,
                    hex::encode(status.bootstrap_prepared_intent_digest),
                    hex::encode(status.bootstrap_certificate_digest),
                    hex::encode(status.roast_intent_certificate_digest),
                    hex::encode(status.roast_attempt_binding_digest),
                    hex::encode(status.key_image_binding_digest),
                    hex::encode(status.key_image_unsigned_transaction_digest),
                    hex::encode(status.roast_endorsed_evidence_digest),
                ),
            );
            if !consolidation_phase_satisfies_observer(status.phase, expected_phase) {
                continue;
            }
            if let Some((_, count, recovered, parties)) = decision_groups
                .iter_mut()
                .find(|(candidate, _, _, _)| candidate.same_quorum_decision(&status))
            {
                *count = count.saturating_add(1);
                *recovered |= Some(*party) == recovered_party;
                parties.push(*party);
            } else {
                decision_groups.push((
                    status,
                    1,
                    recovered_party.is_none() || Some(*party) == recovered_party,
                    vec![*party],
                ));
            }
        }
        if let Some((agreed, _, _, _)) =
            decision_groups.iter().find(|(_, count, recovered, _)| *count >= required && *recovered)
        {
            return Ok(agreed.clone());
        }
        let decision_summary = decision_groups
            .iter()
            .enumerate()
            .map(|(index, (_, count, _, parties))| {
                format!("group {index}: replicas={} parties={}", count, format_party_list(parties))
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "consolidation did not reach {expected_phase:?} on n-f replicas; \
             decisions: {decision_summary:?}; observations: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

/// Require the exact witness-independent portable terminal and ledger statements to survive a
/// committee transition on `n-f` members. Different valid witness subsets are not treated as
/// forks; the observation quorum, rather than those representation bytes, establishes agreement.
/// Hot worker/coordinator/ROAST diagnostics may already have been compacted and are deliberately
/// not part of this handoff predicate.
async fn wait_for_confirmed_consolidation_checkpoint(
    _scenario: &Scenario,
    client: &PartyClient,
    public: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
    expected: &ObservedConsolidation,
) -> anyhow::Result<()> {
    wait_for_permanent_deposit_after_handoff(client, public, fault_bound, faulty, deposit).await?;
    let committee = &public.committee;
    anyhow::ensure!(expected.phase == PublicConsolidationPhase::Confirmed);
    let expected_inputs = certified_deposit_inputs(deposit)?;
    let queried_output =
        *expected_inputs.first().context("certified deposit has no consolidation output")?;
    let status_request =
        DepositConsolidationStatusRequest { request: deposit.request, output: queried_output };
    expected
        .0
        .portable
        .as_ref()
        .context("confirmed consolidation omitted portable terminal evidence")?;
    let required = usize::from(committee.n() - fault_bound);
    let responsive = committee
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        responsive.len() >= required,
        "not enough responsive consolidation checkpoint replicas"
    );
    let recovered_party = required_recovered_party()?;
    if let Some(recovered_party) = recovered_party {
        anyhow::ensure!(
            responsive.contains(&recovered_party),
            "required recovered party {recovered_party} is not in checkpoint epoch {}",
            committee.epoch
        );
    }
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut matching = 0_usize;
        let mut recovered_party_matching = recovered_party.is_none();
        for party in &responsive {
            let response = match client
                .post_deposit::<_, DepositConsolidationStatusResponse>(
                    *party,
                    "/v1/deposits/consolidations/status",
                    &status_request,
                )
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                    continue;
                }
            };
            if response.request != deposit.request.request
                || response.certified_request != tenant_certified_request_id(deposit.request)
                || response.output != queried_output
            {
                observations.insert(*party, "response names another request or output".to_owned());
                continue;
            }
            let Some(status) = response.consolidation else {
                observations.insert(*party, "not handed off".to_owned());
                continue;
            };
            if !same_portable_consolidation_decision(&status, &expected.0) {
                observations
                    .insert(*party, "conflicting portable terminal or ledger statement".to_owned());
                continue;
            }
            observations.insert(
                *party,
                if status.live.is_some() {
                    "same portable decision with live diagnostics".to_owned()
                } else {
                    "same compacted portable decision".to_owned()
                },
            );
            matching = matching.saturating_add(1);
            recovered_party_matching |= Some(*party) == recovered_party;
        }
        if matching >= required && recovered_party_matching {
            tracing::info!(
                epoch = committee.epoch,
                replicas = matching,
                txid = %hex::encode(
                    expected
                        .signed
                        .context("confirmed checkpoint omitted signed transaction")?
                        .transaction()
                ),
                "BFT consolidation confirmation survived the committee checkpoint"
            );
            return Ok(());
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "confirmed consolidation was not handed off to n-f epoch-{} replicas; observations: {observations:?}",
            committee.epoch
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

async fn wait_for_deposit_checkpoint(
    scenario: &Scenario,
    client: &PartyClient,
    public: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
    confirmed: Option<&ObservedConsolidation>,
) -> anyhow::Result<()> {
    if let Some(confirmed) = confirmed {
        wait_for_confirmed_consolidation_checkpoint(
            scenario,
            client,
            public,
            fault_bound,
            faulty,
            deposit,
            confirmed,
        )
        .await
    } else {
        wait_for_permanent_deposit_after_handoff(client, public, fault_bound, faulty, deposit).await
    }
}

/// Fund and settle one brand-new deposit under the exact currently active epoch. Repeating this
/// after every transition proves more than key continuity: the successor's newly installed
/// shares must produce a daemon-accepted CLSAG transaction before the next handoff can quiesce.
#[allow(clippy::too_many_arguments)]
async fn exercise_successor_epoch_signing(
    scenario: &Scenario,
    client: &PartyClient,
    daemon: &MoneroDaemon<SimpleRequestTransport>,
    funding_spend: &Zeroizing<Scalar>,
    funding_view: &ViewPair,
    funding_address: &MoneroAddress,
    funding_height: usize,
    threshold_address: &MoneroAddress,
    threshold_view: &ViewPair,
    public: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<SuccessorEpochSigningAcceptance> {
    public.validate()?;
    public.committee.validate_async_security_with_faults(fault_bound)?;
    anyhow::ensure!(
        public.committee.epoch > 0,
        "successor signing acceptance cannot run against the genesis epoch"
    );

    let mut deposit =
        allocate_certified_deposit(scenario, client, public, fault_bound, faulty).await?;
    tracing::info!(epoch = public.committee.epoch, "successor epoch deposit allocation certified");
    let deposit_address = MoneroAddress::from_str(
        monero_network(scenario.network),
        deposit
            .response
            .address
            .as_ref()
            .context("successor certified allocation omitted its address")?
            .as_str(),
    )?;
    let (deposit_block, deposit_transaction, _) = fund_deposit_with_ordinary_transaction(
        daemon,
        funding_spend,
        funding_view,
        funding_address,
        funding_height,
        &deposit_address,
        1,
        false,
        scenario.deposit_maximum_fee_atomic_units,
        scenario.poll_interval_ms,
        scenario.protocol_timeout_seconds,
    )
    .await?;
    let funded_output = verify_deposit_transaction_outputs(
        daemon,
        threshold_view,
        deposit_block,
        &deposit,
        deposit_transaction,
        1,
    )
    .await?
    .into_iter()
    .next()
    .context("successor funding omitted its deposit output")?;
    validate_consolidation_fixture_economics(
        funded_output.amount_atomic_units,
        scenario.deposit_maximum_fee_atomic_units,
    )?;
    deposit.funded_outputs.push(funded_output);
    tracing::info!(
        epoch = public.committee.epoch,
        txid = %hex::encode(deposit_transaction),
        "successor epoch deposit funding mined and independently verified"
    );

    for _ in 1..scenario.confirmation_blocks {
        daemon.generate_blocks(threshold_address, 1).await?;
    }
    wait_for_permanent_deposit(scenario, client, public, fault_bound, faulty, &deposit).await?;
    tracing::info!(epoch = public.committee.epoch, "successor epoch deposit became permanent");

    // The worker's confirmed horizon trails the daemon by confirmation_depth - 1. Advancing the
    // chain through the normal Monero lock window makes this exact output eligible for a sweep.
    daemon.generate_blocks(threshold_address, DEFAULT_LOCK_WINDOW - 1).await?;
    let expected_destination = deposit_destination_binding(scenario, public)?;
    let broadcast = wait_for_consolidation_phase(
        client,
        &public.committee,
        fault_bound,
        faulty,
        &deposit,
        expected_destination,
        PublicConsolidationPhase::Broadcast,
    )
    .await?;
    let signed = broadcast
        .signed
        .context("successor epoch broadcast omitted its signed transaction binding")?;
    let containing_block = mine_confirmation(
        daemon,
        threshold_address,
        signed.transaction(),
        usize::try_from(broadcast.plan.at_tip.height)?,
        scenario.poll_interval_ms,
        scenario.protocol_timeout_seconds,
    )
    .await?;
    let confirmation_height = u64::try_from(containing_block.number())?;
    let confirmation = ChainPoint::new(confirmation_height, containing_block.hash())?;
    let accepted_transaction = verify_consolidation_transaction(
        daemon,
        threshold_view,
        containing_block,
        &deposit,
        &broadcast,
    )
    .await?;
    let exact_transaction_bytes = accepted_transaction.serialize();
    let input_count = broadcast.plan.inputs.len();
    anyhow::ensure!(
        input_count == 1,
        "epoch-{} single-deposit acceptance unexpectedly consolidated {input_count} inputs",
        public.committee.epoch,
    );

    for _ in 1..scenario.confirmation_blocks {
        daemon.generate_blocks(threshold_address, 1).await?;
    }
    let confirmed = wait_for_consolidation_phase(
        client,
        &public.committee,
        fault_bound,
        faulty,
        &deposit,
        expected_destination,
        PublicConsolidationPhase::Confirmed,
    )
    .await?;
    let mut expected_confirmed = broadcast;
    expected_confirmed.phase = PublicConsolidationPhase::Confirmed;
    expected_confirmed.confirmation = Some(confirmation);
    anyhow::ensure!(
        confirmed.same_quorum_decision(&expected_confirmed),
        "epoch-{} confirmation changed the witness-independent certified signing decision",
        public.committee.epoch
    );
    anyhow::ensure!(
        accepted_transaction.hash() == signed.transaction(),
        "epoch-{} daemon transaction hash differs from the certified transaction",
        public.committee.epoch
    );

    tracing::info!(
        epoch = public.committee.epoch,
        threshold = public.committee.threshold,
        members = public.committee.n(),
        txid = %hex::encode(signed.transaction()),
        exact_bytes = exact_transaction_bytes.len(),
        "fresh successor shares threshold-signed a Monero transaction accepted and confirmed by the daemon"
    );
    Ok(SuccessorEpochSigningAcceptance {
        epoch: public.committee.epoch,
        transaction: signed.transaction(),
        input_count,
        exact_transaction_bytes,
    })
}

fn validate_public_consolidation(
    status: &ObservedConsolidation,
    committee: &Committee,
    fault_bound: u16,
    deposit: &CertifiedDeposit,
    expected_destination: [u8; 32],
) -> anyhow::Result<()> {
    let expected_inputs = certified_deposit_inputs(deposit)?;
    let amount = certified_deposit_total(deposit)?;
    let wallet = deposit
        .response
        .address
        .as_ref()
        .context("certified deposit omitted its address")?
        .wallet_id();
    anyhow::ensure!(status.authorization.0 != [0_u8; 32]);
    anyhow::ensure!(status.sweep == status.plan.id && status.sweep.0 != [0_u8; 32]);
    anyhow::ensure!(status.plan.wallet == wallet);
    anyhow::ensure!(status.plan.epoch == committee.epoch);
    anyhow::ensure!(
        status.plan.inputs.as_slice() == expected_inputs.as_slice(),
        "consolidation plan did not claim every exact certified deposit input"
    );
    anyhow::ensure!(status.plan.total_input_atomic_units == amount);
    anyhow::ensure!(status.plan.destination_binding == expected_destination);
    anyhow::ensure!(status.destination_binding == expected_destination);
    committee.member(status.bootstrap_ba_proposer)?;
    anyhow::ensure!(
        status.bootstrap_prepared_intent_digest != [0; 32],
        "consolidation omitted its certified bootstrap prepared-intent digest"
    );
    anyhow::ensure!(
        status.bootstrap_certificate_digest != [0; 32],
        "consolidation omitted its bootstrap BA certificate digest"
    );
    anyhow::ensure!(
        status.roast_intent_certificate_digest != [0; 32],
        "consolidation omitted its certified ROAST intent/view digest"
    );
    anyhow::ensure!(
        status.roast_attempt_binding_digest != [0; 32],
        "consolidation omitted its exact ROAST attempt binding"
    );
    let required = usize::from(committee.n() - fault_bound);
    anyhow::ensure!(
        status.bootstrap_certificate_signers.len() >= required
            && status.bootstrap_certificate_signers.len() <= usize::from(committee.n()),
        "bootstrap BA certificate does not contain n-f bounded signers"
    );
    anyhow::ensure!(
        status.bootstrap_certificate_signers.windows(2).all(|pair| pair[0] < pair[1]),
        "bootstrap BA certificate signer identities are not canonical and unique"
    );
    for signer in &status.bootstrap_certificate_signers {
        committee.member(*signer)?;
    }
    anyhow::ensure!(
        status.roast_intent_certificate_signers.len() >= required
            && status.roast_intent_certificate_signers.len() <= usize::from(committee.n()),
        "ROAST intent/view certificate does not contain n-f bounded signers"
    );
    anyhow::ensure!(
        status.roast_intent_certificate_signers.windows(2).all(|pair| pair[0] < pair[1]),
        "ROAST intent/view certificate signer identities are not canonical and unique"
    );
    for signer in &status.roast_intent_certificate_signers {
        committee.member(*signer)?;
    }
    let expected_signers = deterministic_roast_signers(committee, fault_bound, status.roast_view)?;
    anyhow::ensure!(
        status.roast_signers == expected_signers,
        "consolidation reported a non-deterministic ROAST signer subset"
    );
    anyhow::ensure!(
        usize::from(status.roast_view_count)
            >= usize::try_from(status.roast_view)?
                .checked_add(1)
                .context("ROAST view count overflow")?,
        "consolidation ROAST view count does not include its winning view"
    );
    let relay_index = usize::try_from(status.roast_view)? % status.roast_signers.len();
    anyhow::ensure!(
        status.roast_relay_seed == status.roast_signers[relay_index],
        "consolidation reported a non-deterministic ROAST relay seed"
    );
    anyhow::ensure!(
        status.roast_endorsed_candidate_count <= status.roast_candidate_count,
        "consolidation endorsed-candidate count exceeds its candidate count"
    );
    anyhow::ensure!(
        usize::from(status.roast_endorsed_witness_count) <= status.roast_signers.len(),
        "consolidation endorsed-witness count exceeds its signer subset"
    );
    if status.roast_endorsed_witness_count == 0 {
        anyhow::ensure!(
            status.roast_endorsed_evidence_digest == [0; 32],
            "consolidation reported evidence without an endorsed witness"
        );
    } else {
        anyhow::ensure!(
            status.roast_endorsed_evidence_digest != [0; 32],
            "consolidation witness set lacks its evidence digest"
        );
    }
    if let Some(signed) = status.signed {
        anyhow::ensure!(
            signed.attempt()
                == status.roast_view.checked_add(1).context("ROAST attempt counter overflow")?,
            "signed consolidation transaction belongs to another ROAST view"
        );
        anyhow::ensure!(
            signed.attempt_binding_digest() == status.roast_attempt_binding_digest,
            "signed consolidation transaction belongs to another ROAST attempt binding"
        );
    }
    if matches!(
        status.phase,
        PublicConsolidationPhase::Certified
            | PublicConsolidationPhase::Broadcast
            | PublicConsolidationPhase::Confirmed
    ) {
        anyhow::ensure!(status.signed.is_some());
        anyhow::ensure!(
            status.certificate_digest.is_some_and(|digest| digest != [0; 32]),
            "certified consolidation lacks its completion certificate digest"
        );
        let portable = status
            .0
            .portable
            .as_ref()
            .context("certified consolidation lacks its exact portable terminal evidence")?;
        anyhow::ensure!(
            portable.terminal.sweep_id() == status.sweep
                && portable.terminal.inputs() == expected_inputs.as_slice()
                && Some(portable.current_certificate.statement.digest())
                    == status.certificate_digest,
            "portable terminal does not match the live certified consolidation"
        );
        anyhow::ensure!(
            portable
                .current_certificate
                .attestations
                .iter()
                .map(|attestation| attestation.from)
                .eq(status.completion_certificate_signers.iter().copied()),
            "portable and live completion certificate signer rosters differ"
        );
        anyhow::ensure!(
            status.roast_candidate_count > 0 && status.roast_endorsed_candidate_count > 0,
            "certified consolidation lacks an endorsed ROAST transaction candidate"
        );
        anyhow::ensure!(
            status.roast_endorsed_witness_count >= fault_bound.saturating_add(1),
            "certified consolidation lacks f+1 endorsed transaction witnesses"
        );
        anyhow::ensure!(
            status.completion_certificate_signers.len() >= required
                && status.completion_certificate_signers.len() <= usize::from(committee.n()),
            "completion certificate does not contain n-f bounded signers"
        );
        anyhow::ensure!(
            status.completion_certificate_signers.windows(2).all(|pair| pair[0] < pair[1]),
            "completion certificate signer identities are not canonical and unique"
        );
        for signer in &status.completion_certificate_signers {
            committee.member(*signer)?;
        }
        anyhow::ensure!(
            status.key_image_binding_digest != [0; 32],
            "certified consolidation lacks its durable key-image family binding"
        );
        anyhow::ensure!(
            status.key_image_unsigned_transaction_digest != [0; 32],
            "certified consolidation lacks its key-image-bound unsigned transaction digest"
        );
        anyhow::ensure!(
            status.key_image_preprocess_set_digest != [0; 32],
            "certified consolidation lacks its proof-bearing preprocess set digest"
        );
        anyhow::ensure!(
            usize::from(status.key_image_authorization_quorum) == required,
            "key-image authorization did not record the exact n-f quorum"
        );
        anyhow::ensure!(
            status.key_image_authorizers.len() == required,
            "key-image authorization does not contain the exact n-f signer roster"
        );
        anyhow::ensure!(
            status.key_image_authorizers.windows(2).all(|pair| pair[0] < pair[1]),
            "key-image authorizer identities are not canonical and unique"
        );
        for authorizer in &status.key_image_authorizers {
            committee.member(*authorizer)?;
        }
    } else {
        anyhow::ensure!(
            status.completion_certificate_signers.is_empty(),
            "uncertified consolidation reported completion certificate signers"
        );
    }
    if status.phase == PublicConsolidationPhase::Confirmed {
        anyhow::ensure!(status.confirmation.is_some());
    }
    Ok(())
}

fn deposit_destination_binding(
    scenario: &Scenario,
    public: &EpochPublic,
) -> anyhow::Result<[u8; 32]> {
    let private_view = DalekScalar::from_bytes_mod_order([0x42; 32]).to_bytes();
    let deriver = DepositAddressDeriver::new(
        scenario.network,
        public.group_key_bytes(),
        &Zeroizing::new(private_view),
    )?;
    let config = DepositWorkerConfig {
        confirmation_depth: u32::try_from(scenario.confirmation_blocks)?,
        maximum_fee_atomic_units: scenario.deposit_maximum_fee_atomic_units,
        ..Default::default()
    };
    Ok(root_consolidation_destination_binding(&deriver, config))
}

fn validate_consolidation_fixture_economics(
    amount_atomic_units: u64,
    maximum_fee_atomic_units: u64,
) -> anyhow::Result<()> {
    let maximum_fee_and_primary_output = maximum_fee_atomic_units
        .checked_add(CONSOLIDATION_PRIMARY_OUTPUT_ATOMIC_UNITS)
        .context("deposit maximum fee plus primary output overflows atomic units")?;
    anyhow::ensure!(
        amount_atomic_units > maximum_fee_and_primary_output,
        "deposit acceptance amount {amount_atomic_units} must exceed maximum fee \
         {maximum_fee_atomic_units} plus the one-atomic-unit primary output so a positive change \
         output remains"
    );
    Ok(())
}

fn successor_acceptance_funding_height(
    funding_start_height: usize,
    epoch: u64,
) -> anyhow::Result<usize> {
    anyhow::ensure!(epoch > 0, "successor funding requires a nonzero epoch");
    let successor_offset = usize::try_from(epoch)?;
    funding_start_height.checked_add(successor_offset).context("successor funding height overflow")
}

fn acceptance_funding_wallet(
    network: Network,
) -> anyhow::Result<(Zeroizing<Scalar>, ViewPair, MoneroAddress)> {
    let spend = Zeroizing::new(Scalar::random(&mut OsRng));
    anyhow::ensure!(*spend != Scalar::ZERO, "sampled a zero acceptance funding spend key");
    let spend_scalar: DalekScalar = (*spend).into();
    let spend_public = Point::from(ED25519_BASEPOINT_POINT * spend_scalar);
    let view = Zeroizing::new(Scalar::random(&mut OsRng));
    anyhow::ensure!(*view != Scalar::ZERO, "sampled a zero acceptance funding view key");
    let pair = ViewPair::new(spend_public, view)?;
    let address = pair.legacy_address(network);
    Ok((spend, pair, address))
}

/// Inspect the wallet crate's public `SignableTransaction` encoding before any signature or
/// publication. Monero requires a change output and the wallet deliberately shuffles it with the
/// payment. The focused TTL contract needs a canonical output identifier (`txid:0`), so its
/// private-Regtest-only call samples a fresh outgoing-view seed until the actual payment is first.
fn signable_transaction_starts_with_payment(
    signable: &SignableTransaction,
) -> anyhow::Result<bool> {
    let encoded = Zeroizing::new(signable.serialize());
    let mut cursor = std::io::Cursor::new(encoded.as_slice());
    let _rct_type = monero_wallet::io::read_byte(&mut cursor)?;
    let mut outgoing_view_key = Zeroizing::new([0_u8; 32]);
    std::io::Read::read_exact(&mut cursor, outgoing_view_key.as_mut())?;
    let input_count = <usize as monero_wallet::io::VarInt>::read(&mut cursor)?;
    anyhow::ensure!(
        input_count == 1,
        "acceptance funding transaction unexpectedly encoded {input_count} inputs"
    );
    OutputWithDecoys::read(&mut cursor)?;
    let payment_count = <usize as monero_wallet::io::VarInt>::read(&mut cursor)?;
    anyhow::ensure!(
        payment_count == 2,
        "focused one-payment funding transaction unexpectedly encoded {payment_count} outputs"
    );
    Ok(monero_wallet::io::read_byte(&mut cursor)? == 0)
}

#[allow(clippy::too_many_arguments)]
async fn fund_deposit_with_ordinary_transaction(
    daemon: &MoneroDaemon<SimpleRequestTransport>,
    funding_spend: &Zeroizing<Scalar>,
    funding_view: &ViewPair,
    mining_address: &MoneroAddress,
    funding_start_height: usize,
    deposit_address: &MoneroAddress,
    deposit_output_count: usize,
    require_deposit_output_zero: bool,
    maximum_consolidation_fee: u64,
    poll_interval_ms: u64,
    timeout_seconds: u64,
) -> anyhow::Result<(monero_wallet::block::Block, [u8; 32], Vec<u8>)> {
    anyhow::ensure!(
        (1..=INITIAL_ACCEPTANCE_DEPOSIT_OUTPUTS).contains(&deposit_output_count),
        "acceptance funding output count is outside 1..={INITIAL_ACCEPTANCE_DEPOSIT_OUTPUTS}"
    );
    anyhow::ensure!(
        !require_deposit_output_zero || deposit_output_count == 1,
        "a fixed deposit output index is available only to the focused one-output Regtest fixture"
    );
    let latest = daemon.latest_block_number().await?;
    let latest_block = daemon.block_by_number(latest).await?;
    anyhow::ensure!(
        matches!(latest_block.header.hardfork_version, 15 | 16),
        "acceptance funding requires Monero hard fork 15 or 16"
    );

    let mined = daemon.block_by_number(funding_start_height).await?;
    let mut scanner = Scanner::new(funding_view.clone());
    let mut matured = scanner
        .scan(daemon.expand_to_scannable_block(mined).await?)?
        .additional_timelock_satisfied_by(latest, 0);
    anyhow::ensure!(
        matured.len() == 1,
        "acceptance funding block yielded {} mature wallet outputs, expected one",
        matured.len()
    );
    let funding_output = matured.swap_remove(0);
    let funding_amount = funding_output.commitment().amount;
    let deposit_amount = maximum_consolidation_fee
        .checked_add(1_000_000_000)
        .context("acceptance deposit amount overflow")?;
    let deposit_total = deposit_amount
        .checked_mul(u64::try_from(deposit_output_count)?)
        .context("acceptance aggregate deposit amount overflow")?;
    let required_input = deposit_total
        .checked_add(maximum_consolidation_fee)
        .context("acceptance funding requirement overflow")?;
    anyhow::ensure!(
        funding_amount > required_input,
        "mature funding output {funding_amount} cannot cover deposits {deposit_total} plus \
         consolidation-fee headroom {maximum_consolidation_fee}"
    );

    let mut rng = OsRng;
    let input = OutputWithDecoys::new(&mut rng, daemon, 16, latest, funding_output).await?;
    let fee_rate = daemon.fee_rate(FeePriority::Unimportant, u64::MAX).await?;
    let signable = {
        let mut selected = None;
        for _ in 0..256 {
            let mut outgoing_view_key = Zeroizing::new([0_u8; 32]);
            rng.fill_bytes(outgoing_view_key.as_mut());
            if outgoing_view_key.as_ref() == &[0_u8; 32] {
                continue;
            }
            let candidate = SignableTransaction::new(
                RctType::ClsagBulletproofPlus,
                outgoing_view_key,
                vec![input.clone()],
                vec![(*deposit_address, deposit_amount); deposit_output_count],
                Change::new(funding_view.clone(), None),
                vec![],
                fee_rate,
            )?;
            if !require_deposit_output_zero || signable_transaction_starts_with_payment(&candidate)?
            {
                selected = Some(candidate);
                break;
            }
        }
        selected.context(
            "failed to construct a focused Regtest funding transaction with deposit output zero",
        )?
    };
    let signed = signable.sign(&mut rng, funding_spend)?;
    let transaction = signed.hash();
    let locally_signed_bytes = signed.serialize();
    daemon.publish_transaction(&signed).await?;
    let containing_block = mine_confirmation(
        daemon,
        mining_address,
        transaction,
        latest,
        poll_interval_ms,
        timeout_seconds,
    )
    .await?;
    let daemon_transaction = daemon.transaction(transaction).await?;
    let daemon_bytes = daemon_transaction.serialize();
    anyhow::ensure!(daemon_transaction.hash() == transaction);
    anyhow::ensure!(
        daemon_bytes == locally_signed_bytes,
        "daemon-returned deposit funding bytes differ from the submitted wallet transaction"
    );
    anyhow::ensure!(
        containing_block.transactions.contains(&transaction),
        "mined deposit block omitted the submitted funding transaction"
    );
    anyhow::ensure!(
        daemon_transaction.prefix().additional_timelock
            == monero_oxide::transaction::Timelock::None,
        "ordinary acceptance funding transaction unexpectedly set an additional timelock"
    );
    Ok((containing_block, transaction, daemon_bytes))
}

async fn verify_consolidation_transaction(
    daemon: &MoneroDaemon<SimpleRequestTransport>,
    view: &ViewPair,
    block: monero_wallet::block::Block,
    deposit: &CertifiedDeposit,
    status: &ObservedConsolidation,
) -> anyhow::Result<Transaction> {
    let expected_inputs = certified_deposit_inputs(deposit)?;
    let mut expected_by_global_index = BTreeMap::<u64, WalletOutputId>::new();
    for output in &deposit.funded_outputs {
        anyhow::ensure!(
            expected_by_global_index.insert(output.index_on_blockchain, output.id).is_none(),
            "two certified deposit outputs share one global output index"
        );
    }
    anyhow::ensure!(
        expected_by_global_index.len() == expected_inputs.len(),
        "certified deposit input/global-index evidence is incomplete"
    );
    let signed = status.signed.context("consolidation omitted signed transaction binding")?;
    let transaction = daemon.transaction(signed.transaction()).await?;
    let bytes = transaction.serialize();
    anyhow::ensure!(transaction.hash() == signed.transaction());
    anyhow::ensure!(u32::try_from(bytes.len())? == signed.exact_bytes_len());
    anyhow::ensure!(
        consolidation_signed_bytes_binding(&bytes) == signed.exact_bytes_digest(),
        "daemon transaction bytes differ from the quorum-certified binding"
    );
    let prefix = transaction.prefix();
    anyhow::ensure!(prefix.inputs.len() == status.plan.inputs.len());
    anyhow::ensure!(
        status.plan.inputs.as_slice() == expected_inputs.as_slice(),
        "daemon transaction belongs to a plan with different certified inputs"
    );
    let mut ring_candidates = Vec::<Vec<WalletOutputId>>::with_capacity(prefix.inputs.len());
    for (ring_position, input) in prefix.inputs.iter().enumerate() {
        let Input::ToKey { amount, key_offsets, key_image: _ } = input else {
            anyhow::bail!("consolidation contains a miner input");
        };
        anyhow::ensure!(amount.is_none(), "consolidation input is not RingCT");
        anyhow::ensure!(key_offsets.len() == 16, "consolidation ring size is not sixteen");
        let mut absolute = 0_u64;
        let mut certified_ring_members = Vec::<WalletOutputId>::new();
        for offset in key_offsets {
            absolute = absolute.checked_add(*offset).context("ring offset overflow")?;
            if let Some(output) = expected_by_global_index.get(&absolute) {
                certified_ring_members.push(*output);
            }
        }
        certified_ring_members.sort_unstable();
        certified_ring_members.dedup();
        anyhow::ensure!(
            !certified_ring_members.is_empty(),
            "consolidation input ring {ring_position} contains no certified deposit output"
        );
        ring_candidates.push(certified_ring_members);
    }
    let mut input_ring_mapping = BTreeMap::<WalletOutputId, usize>::new();
    for ring_position in 0..ring_candidates.len() {
        anyhow::ensure!(
            assign_certified_input_ring(
                ring_position,
                &ring_candidates,
                &mut BTreeSet::new(),
                &mut input_ring_mapping,
            ),
            "transaction rings cannot be mapped bijectively to the certified deposit outputs"
        );
    }
    anyhow::ensure!(
        input_ring_mapping.len() == expected_inputs.len()
            && expected_inputs.iter().all(|input| input_ring_mapping.contains_key(input)),
        "transaction input rings do not map bijectively to every certified deposit output"
    );
    tracing::info!(
        txid = %hex::encode(signed.transaction()),
        inputs = input_ring_mapping.len(),
        ?input_ring_mapping,
        "daemon transaction input rings map bijectively to the certified deposit outputs"
    );

    let mut scanner = Scanner::new(view.clone());
    let root_outputs = scanner
        .scan(daemon.expand_to_scannable_block(block).await?)?
        .not_additionally_locked()
        .into_iter()
        .filter(|output| output.transaction() == signed.transaction())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        root_outputs.len() == prefix.outputs.len(),
        "not every consolidation output belongs to the root threshold wallet"
    );
    anyhow::ensure!(root_outputs.iter().all(|output| output.subaddress().is_none()));
    let root_amount = root_outputs.iter().try_fold(0_u64, |total, output| {
        total.checked_add(output.commitment().amount).context("root output amount overflow")
    })?;
    let Transaction::V2 { proofs: Some(ref proofs), .. } = transaction else {
        anyhow::bail!("consolidation transaction is not a proved RingCT v2 transaction");
    };
    anyhow::ensure!(
        root_amount.checked_add(proofs.base.fee) == Some(status.plan.total_input_atomic_units),
        "root outputs plus fee do not equal the certified deposit input amount"
    );
    Ok(transaction)
}

async fn wait_for_authenticated_driver_release(
    client: &PartyClient,
    party: PartyId,
    kind: AcceptanceDriverLatchKind,
    binding: [u8; 32],
) -> anyhow::Result<()> {
    anyhow::ensure!(binding != [0; 32], "acceptance driver binding is invalid");
    loop {
        let status: anyhow::Result<AcceptanceDriverLatchResponse> = client
            .post_admin(
                party,
                "/v1/acceptance/driver-latch",
                &AcceptanceDriverLatchRequest {
                    action: AcceptanceConsolidationGateAction::Status,
                    kind,
                    binding,
                },
            )
            .await;
        match status {
            Ok(response) => {
                anyhow::ensure!(
                    response.party == party
                        && response.kind == Some(kind)
                        && response.binding == Some(binding)
                        && (response.event_unix_ms.is_none()
                            || (kind == AcceptanceDriverLatchKind::ProactiveDeadline
                                && response.event_unix_ms.is_some_and(|event| event != 0))),
                    "party {party} reported another acceptance driver latch"
                );
                match response.state {
                    AcceptanceConsolidationGateState::Released => return Ok(()),
                    AcceptanceConsolidationGateState::Held => {}
                    AcceptanceConsolidationGateState::Disarmed
                    | AcceptanceConsolidationGateState::Armed => {
                        anyhow::bail!("party {party} lost its held acceptance driver latch")
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%party, %error, "acceptance driver latch temporarily unavailable");
            }
        }
        tokio::time::sleep(client.poll_interval).await;
    }
}

/// Optional Compose-only durable barrier after a real deposit is mined. The observer-fork latch is
/// reached immediately after inclusion, while p2's crash gate is reached only after the exact
/// output has enough confirmations to enter an `n-f` portable checkpoint. Neither path has a
/// timer: only an authenticated release lets the acceptance client continue.
async fn maybe_pause_at_deposit_fault_barrier(
    client: &PartyClient,
    transaction: [u8; 32],
    output: WalletOutputId,
    mode: Option<AcceptanceDepositFaultMode>,
) -> anyhow::Result<()> {
    let Some(mode) = mode else {
        return Ok(());
    };
    anyhow::ensure!(output.transaction == transaction);
    match mode {
        AcceptanceDepositFaultMode::ObserverFork => {
            let mut material = Vec::with_capacity(40);
            material.extend_from_slice(&transaction);
            material.extend_from_slice(&output.index_in_transaction.to_le_bytes());
            let binding =
                acceptance_driver_binding(AcceptanceDriverLatchKind::ObserverFork, &material);
            let party = PartyId::new(1)?;
            let armed: AcceptanceDriverLatchResponse = client
                .post_admin(
                    party,
                    "/v1/acceptance/driver-latch",
                    &AcceptanceDriverLatchRequest {
                        action: AcceptanceConsolidationGateAction::Arm,
                        kind: AcceptanceDriverLatchKind::ObserverFork,
                        binding,
                    },
                )
                .await?;
            anyhow::ensure!(
                armed.party == party
                    && armed.state == AcceptanceConsolidationGateState::Held
                    && armed.kind == Some(AcceptanceDriverLatchKind::ObserverFork)
                    && armed.binding == Some(binding)
                    && armed.event_unix_ms.is_none(),
                "p1 held a different observer-fault latch"
            );
            println!(
                "TM_ACCEPTANCE_OBSERVER_FAULT_LATCH_HELD party=1 txid={} output_index={} binding={}",
                hex::encode(transaction),
                output.index_in_transaction,
                hex::encode(binding),
            );
            {
                use std::io::Write as _;
                std::io::stdout().flush()?;
            }
            wait_for_authenticated_driver_release(
                client,
                party,
                AcceptanceDriverLatchKind::ObserverFork,
                binding,
            )
            .await?;
            println!(
                "TM_ACCEPTANCE_OBSERVER_FAULT_LATCH_RELEASED party=1 binding={}",
                hex::encode(binding)
            );
            Ok(())
        }
        AcceptanceDepositFaultMode::DepositCheckpoint => {
            let party = PartyId::new(2)?;
            let request = AcceptanceDepositCheckpointGateRequest {
                action: AcceptanceConsolidationGateAction::Arm,
                output,
            };
            let deadline = tokio::time::Instant::now() + client.protocol_timeout;
            let held = loop {
                match client
                    .post_admin::<_, AcceptanceDepositCheckpointGateResponse>(
                        party,
                        "/v1/acceptance/deposit-checkpoint-gate",
                        &request,
                    )
                    .await
                {
                    Ok(response)
                        if response.party == party
                            && response.state == AcceptanceConsolidationGateState::Held
                            && response.output == Some(output)
                            && response.evidence.is_some() =>
                    {
                        break response;
                    }
                    Ok(response) => {
                        tracing::warn!(?response, "p2 deposit checkpoint gate is not held yet");
                    }
                    Err(error) => {
                        tracing::warn!(%error, "p2 has not checkpointed the exact deposit yet");
                    }
                }
                anyhow::ensure!(
                    tokio::time::Instant::now() < deadline,
                    "p2 did not durably checkpoint the exact deposit output before the deadline"
                );
                tokio::time::sleep(client.poll_interval).await;
            };
            let evidence = held.evidence.context("held deposit gate omitted evidence")?;
            println!(
                "TM_ACCEPTANCE_DEPOSIT_CHECKPOINT_HELD party=2 txid={} output_index={} portable_index={} checkpoint_statement={} checkpoint_sequence={}",
                hex::encode(transaction),
                output.index_in_transaction,
                hex::encode(evidence.portable_index_digest),
                hex::encode(evidence.checkpoint_statement_digest),
                evidence.checkpoint_sequence,
            );
            {
                use std::io::Write as _;
                std::io::stdout().flush()?;
            }
            loop {
                let status = client
                    .post_admin::<_, AcceptanceDepositCheckpointGateResponse>(
                        party,
                        "/v1/acceptance/deposit-checkpoint-gate",
                        &AcceptanceDepositCheckpointGateRequest {
                            action: AcceptanceConsolidationGateAction::Status,
                            output,
                        },
                    )
                    .await;
                match status {
                    Ok(response) => {
                        anyhow::ensure!(
                            response.party == party
                                && response.output == Some(output)
                                && response.evidence.as_ref() == Some(&evidence),
                            "p2 deposit checkpoint gate changed while held"
                        );
                        match response.state {
                            AcceptanceConsolidationGateState::Released => break,
                            AcceptanceConsolidationGateState::Held => {}
                            AcceptanceConsolidationGateState::Disarmed
                            | AcceptanceConsolidationGateState::Armed => {
                                anyhow::bail!("p2 lost its durable deposit checkpoint gate")
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "p2 deposit checkpoint gate temporarily unavailable");
                    }
                }
                tokio::time::sleep(client.poll_interval).await;
            }
            println!(
                "TM_ACCEPTANCE_DEPOSIT_CHECKPOINT_RELEASED party=2 txid={} output_index={} portable_index={} checkpoint_statement={} checkpoint_sequence={}",
                hex::encode(transaction),
                output.index_in_transaction,
                hex::encode(evidence.portable_index_digest),
                hex::encode(evidence.checkpoint_statement_digest),
                evidence.checkpoint_sequence,
            );
            Ok(())
        }
    }
}

async fn verify_deposit_transaction_outputs(
    daemon: &MoneroDaemon<SimpleRequestTransport>,
    view: &ViewPair,
    block: monero_wallet::block::Block,
    deposit: &CertifiedDeposit,
    transaction: [u8; 32],
    expected_output_count: usize,
) -> anyhow::Result<Vec<DepositOutputEvidence>> {
    anyhow::ensure!(
        (1..=INITIAL_ACCEPTANCE_DEPOSIT_OUTPUTS).contains(&expected_output_count),
        "expected deposit output count is outside 1..={INITIAL_ACCEPTANCE_DEPOSIT_OUTPUTS}"
    );
    let allocated =
        deposit.response.address.as_ref().context("certified deposit omitted its address")?.index();
    let subaddress = SubaddressIndex::new(allocated.account(), allocated.address())
        .context("certified deposit used the primary address index")?;
    let mut scanner = Scanner::new(view.clone());
    scanner.register_subaddress(subaddress);
    let received = scanner
        .scan(daemon.expand_to_scannable_block(block).await?)?
        .not_additionally_locked()
        .into_iter()
        .filter(|output| {
            output.transaction() == transaction && output.subaddress() == Some(subaddress)
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        received.len() == expected_output_count,
        "deposit transaction created {} outputs for the certified subaddress, expected {expected_output_count}",
        received.len(),
    );
    Ok(received
        .into_iter()
        .map(|output| DepositOutputEvidence {
            id: WalletOutputId { transaction, index_in_transaction: output.index_in_transaction() },
            index_on_blockchain: output.index_on_blockchain(),
            amount_atomic_units: output.commitment().amount,
        })
        .collect())
}

async fn run_dkg(
    client: &PartyClient,
    session: SessionId,
    key_id: [u8; 32],
    committee: &Committee,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<EpochPublic> {
    run_avss(
        client,
        AvssTransition {
            purpose: DealPurpose::Dkg,
            session,
            key_id,
            fault_bound,
            history_parent: EpochHistoryParent::genesis(client.network_id, key_id)?,
            old: None,
            target: committee.clone(),
            eligible_dealers: vec![],
        },
        fault_bound,
        faulty,
    )
    .await
}

/// Release the demo-Regtest-only durable schedule hold on every source/target participant. The
/// source epoch in the authenticated request makes delayed retries fail closed instead of
/// accidentally releasing a later refresh. Outside the explicit acceptance overlay, production
/// and ordinary demo networks retain their autonomous fixed-interval behavior.
async fn release_held_proactive_refresh(
    client: &PartyClient,
    source: &Committee,
    target: &Committee,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<()> {
    if !acceptance_proactive_refresh_hold_enabled()? {
        return Ok(());
    }
    source.validate()?;
    target.validate()?;
    anyhow::ensure!(
        source.epoch.checked_add(1) == Some(target.epoch),
        "acceptance refresh release requires an immediate successor"
    );
    let participants = source
        .members
        .iter()
        .chain(&target.members)
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(!participants.is_empty(), "held proactive refresh has no participants");
    let request = AcceptanceProactiveRefreshReleaseRequest { source_epoch: source.epoch };
    let mut deadlines = BTreeMap::<PartyId, u64>::new();
    for party in participants {
        let response: AcceptanceProactiveRefreshReleaseResponse =
            client.post_admin(party, "/v1/acceptance/proactive-refresh/release", &request).await?;
        anyhow::ensure!(
            response.party == party
                && response.source_epoch == source.epoch
                && response.target_epoch == target.epoch,
            "party {party} released a different proactive-refresh schedule"
        );
        anyhow::ensure!(
            response.due_unix_ms != 0 && response.due_unix_ms != u64::MAX,
            "party {party} did not replace the durable acceptance hold"
        );
        deadlines.insert(party, response.due_unix_ms);
    }
    tracing::info!(
        source_epoch = source.epoch,
        target_epoch = target.epoch,
        ?deadlines,
        "released every participant's exact durable proactive-refresh schedule"
    );
    if let Some(selected) = std::env::var_os("TM_ACCEPTANCE_PROACTIVE_DEADLINE_SOURCE_EPOCH") {
        let selected = selected
            .to_str()
            .context("TM_ACCEPTANCE_PROACTIVE_DEADLINE_SOURCE_EPOCH must be valid UTF-8")?
            .parse::<u64>()?;
        if selected == source.epoch {
            let (party, due_unix_ms) = source
                .members
                .iter()
                .map(|member| member.id)
                .filter(|party| !faulty.contains(party))
                .find_map(|party| deadlines.get(&party).copied().map(|due| (party, due)))
                .context(
                    "proactive deadline campaign requires one responsive certified source member",
                )?;
            let interval_ms = acceptance_refresh_interval_millis()?;
            let released_at_unix_ms = due_unix_ms
                .checked_sub(interval_ms)
                .context("proactive refresh deadline precedes its configured interval")?;
            let mut material = Vec::with_capacity(34);
            material.extend_from_slice(&source.epoch.to_le_bytes());
            material.extend_from_slice(&target.epoch.to_le_bytes());
            material.extend_from_slice(&due_unix_ms.to_le_bytes());
            material.extend_from_slice(&interval_ms.to_le_bytes());
            material.extend_from_slice(&party.0.to_le_bytes());
            let kind = AcceptanceDriverLatchKind::ProactiveDeadline;
            let binding = acceptance_driver_binding(kind, &material);
            let armed: AcceptanceDriverLatchResponse = client
                .post_admin(
                    party,
                    "/v1/acceptance/driver-latch",
                    &AcceptanceDriverLatchRequest {
                        action: AcceptanceConsolidationGateAction::Arm,
                        kind,
                        binding,
                    },
                )
                .await?;
            anyhow::ensure!(
                armed.party == party
                    && armed.state == AcceptanceConsolidationGateState::Held
                    && armed.kind == Some(kind)
                    && armed.binding == Some(binding)
                    && armed.event_unix_ms.is_none(),
                "party {party} held a different proactive-deadline latch"
            );
            println!(
                "TM_ACCEPTANCE_PROACTIVE_DEADLINE_HELD party={party} source_epoch={} target_epoch={} released_at_unix_ms={} interval_ms={} due_unix_ms={} binding={}",
                source.epoch,
                target.epoch,
                released_at_unix_ms,
                interval_ms,
                due_unix_ms,
                hex::encode(binding),
            );
            {
                use std::io::Write as _;
                std::io::stdout().flush()?;
            }
            wait_for_authenticated_driver_release(client, party, kind, binding).await?;
            println!(
                "TM_ACCEPTANCE_PROACTIVE_DEADLINE_RELEASED party={party} source_epoch={} target_epoch={} due_unix_ms={} binding={}",
                source.epoch,
                target.epoch,
                due_unix_ms,
                hex::encode(binding),
            );
        }
    }
    Ok(())
}

fn acceptance_refresh_interval_millis() -> anyhow::Result<u64> {
    // All participant releases use the scenario's same fixed interval. The campaign preflight
    // checks this explicit value against the current scenario before launching the client.
    let seconds = std::env::var("TM_ACCEPTANCE_PROACTIVE_DEADLINE_INTERVAL_SECONDS")
        .context("deadline campaign requires its exact configured interval")?
        .parse::<u64>()?;
    anyhow::ensure!(seconds > 0, "proactive deadline interval must be positive");
    seconds.checked_mul(1_000).context("proactive deadline interval overflow")
}

/// Observe one configured successor which the party runtimes must key-rotate and activate
/// themselves. This path intentionally never calls `/v1/avss/start`: grow, same-layout refresh,
/// and shrink all prove the fixed-interval scheduler, target-advertisement ceremony, source
/// consensus certificate, and QUIC AVSS driver.
async fn wait_for_configured_successor(
    scenario: &Scenario,
    client: &PartyClient,
    old: &EpochPublic,
    new_epoch: u64,
    faulty: &BTreeSet<PartyId>,
    required_observer: Option<PartyId>,
) -> anyhow::Result<EpochPublic> {
    old.validate()?;
    let expected_epoch =
        old.committee.epoch.checked_add(1).context("configured successor epoch exhausted")?;
    anyhow::ensure!(
        new_epoch == expected_epoch,
        "configured successor must be immediate epoch {expected_epoch}, requested {new_epoch}"
    );
    let policy = scenario
        .configured_key_rotation_target_shape(&old.committee)?
        .context("configured successor lacks a target key-rotation policy")?;
    anyhow::ensure!(policy.target_epoch() == new_epoch);
    let required = usize::from(
        policy
            .desired_n()
            .checked_sub(policy.target_fault_bound())
            .context("configured successor fault bound exhausts its target committee")?,
    );
    let responsive = policy
        .eligible()
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        responsive.len() >= required,
        "configured epoch-{new_epoch} has {} responsive target members, requires n-f={}",
        responsive.len(),
        required
    );
    let mut required_parties = required_recovered_party()?.into_iter().collect::<BTreeSet<_>>();
    required_parties.extend(required_observer);
    for recovered_party in &required_parties {
        anyhow::ensure!(
            responsive.contains(recovered_party),
            "required recovered party {recovered_party} is not an eligible epoch-{new_epoch} observer"
        );
    }

    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut activated = Vec::<EqualObservationGroup<EpochPublic>>::new();
        for party in &responsive {
            match client.get_admin::<PartyStatus>(*party, "/v1/status").await {
                Ok(status) => {
                    observations.insert(
                        *party,
                        format!(
                            "active={:?}, staged={:?}, epochs={:?}, refresh={:?}",
                            status.active_epoch,
                            status.staged_epochs,
                            status.epochs.iter().map(|epoch| epoch.epoch).collect::<Vec<_>>(),
                            status.proactive_refresh,
                        ),
                    );
                    let public = match (|| -> anyhow::Result<Option<EpochPublic>> {
                        anyhow::ensure!(
                            status.party == *party,
                            "status endpoint returned another party ID"
                        );
                        anyhow::ensure!(
                            status.ready,
                            "party {party} reported that it is not ready"
                        );
                        if let Some(observed) = status.active_epoch {
                            anyhow::ensure!(
                                observed <= new_epoch,
                                "party {party} advanced past configured target epoch {new_epoch} to {observed}"
                            );
                        }
                        if status.active_epoch != Some(new_epoch) {
                            return Ok(None);
                        }
                        let matching = status
                            .epochs
                            .iter()
                            .filter(|epoch| epoch.epoch == new_epoch)
                            .collect::<Vec<_>>();
                        anyhow::ensure!(
                            matching.len() == 1,
                            "party {party} reported configured epoch {new_epoch} without exactly one public value"
                        );
                        let public = matching[0].public.clone();
                        validate_configured_successor(scenario, old, &public).with_context(
                            || {
                                format!(
                                    "party {party} reported an invalid configured epoch-{new_epoch}"
                                )
                            },
                        )?;
                        public.committee.member(*party).with_context(|| {
                            format!(
                                "party {party} is not a member of its reported epoch-{new_epoch} committee"
                            )
                        })?;
                        Ok(Some(public))
                    })() {
                        Ok(public) => public,
                        Err(error) => {
                            observations
                                .insert(*party, format!("invalid/non-candidate status: {error:#}"));
                            continue;
                        }
                    };
                    if let Some(public) = public {
                        record_equal_observation(&mut activated, *party, public);
                    }
                }
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                }
            }
        }

        if let Some(group) = equal_observation_quorum(&activated, required, &required_parties)? {
            let expected = group.value.clone();
            let agreeing_parties = group.parties.clone();
            let selected_ids =
                expected.committee.members.iter().map(|member| member.id).collect::<BTreeSet<_>>();
            let rotated = validate_configured_successor(scenario, old, &expected)?;
            tracing::info!(
                epoch = new_epoch,
                parties = selected_ids.len(),
                agreeing_parties = ?agreeing_parties,
                omitted = responsive.len().saturating_sub(selected_ids.len()),
                rotated_encryption_keys = rotated,
                "configured timer-driven QUIC successor activated"
            );
            return Ok(expected);
        }

        let group_summary = activated
            .iter()
            .enumerate()
            .map(|(index, group)| {
                format!(
                    "group {index}: parties={}",
                    format_party_list(&group.parties.iter().copied().collect::<Vec<_>>()),
                )
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "configured epoch-{new_epoch} did not activate before the protocol deadline; \
             groups: {group_summary:?}; observations: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

fn validate_configured_successor(
    scenario: &Scenario,
    before: &EpochPublic,
    after: &EpochPublic,
) -> anyhow::Result<usize> {
    before.validate()?;
    after.validate()?;
    let policy = scenario
        .configured_key_rotation_target_shape(&before.committee)?
        .context("configured successor lacks a target key-rotation policy")?;
    let eligible = policy.eligible();
    anyhow::ensure!(
        after.committee.epoch == policy.target_epoch(),
        "configured successor activated the wrong epoch"
    );
    anyhow::ensure!(
        after.key_id == before.key_id && after.group_key_bytes() == before.group_key_bytes(),
        "configured successor changed the distributed Monero spend key"
    );
    anyhow::ensure!(
        after.committee.threshold == eligible.threshold
            && after.committee.n() == policy.desired_n(),
        "configured successor changed the target membership size or threshold"
    );
    for member in &after.committee.members {
        let eligible_member = eligible.member(member.id)?;
        anyhow::ensure!(
            member.signing_key == eligible_member.signing_key,
            "configured successor changed party {}'s stable signing key",
            member.id
        );
    }
    anyhow::ensure!(
        after.committee.members.iter().all(|member| eligible.member(member.id).is_ok()),
        "configured successor added a party outside the target policy"
    );
    let rotated = after
        .committee
        .members
        .iter()
        .filter(|member| {
            before
                .committee
                .members
                .iter()
                .chain(eligible.members.iter())
                .all(|prior| prior.encryption_key != member.encryption_key)
        })
        .count();
    anyhow::ensure!(
        rotated == policy.selection_size(),
        "configured successor supplied {rotated} fresh X25519 keys, requires exact selected size={}",
        policy.selection_size()
    );
    anyhow::ensure!(
        after.verification_shares != before.verification_shares,
        "configured successor reused the source verification-share polynomial"
    );
    Ok(rotated)
}

async fn observe_active_epoch_history_link(
    client: &PartyClient,
    expected: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<EpochHistoryLink> {
    expected.validate()?;
    let committee = &expected.committee;
    anyhow::ensure!(
        fault_bound < committee.n(),
        "history-link fault bound exhausts epoch-{} committee",
        committee.epoch
    );
    let required = usize::from(committee.n() - fault_bound);
    let responsive = committee
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        responsive.len() >= required,
        "active epoch has {} responsive history observers, requires n-f={required}",
        responsive.len()
    );
    let recovered_party = required_recovered_party()?;
    if let Some(recovered_party) = recovered_party {
        anyhow::ensure!(
            responsive.contains(&recovered_party),
            "required recovered party {recovered_party} is not a responsive epoch-{} history observer",
            committee.epoch
        );
    }
    let required_parties = recovered_party.into_iter().collect::<BTreeSet<_>>();
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut links = Vec::<EqualObservationGroup<EpochHistoryLink>>::new();
        for party in &responsive {
            match client.get_admin::<PartyStatus>(*party, "/v1/status").await {
                Ok(status) => {
                    let matching = status
                        .epochs
                        .iter()
                        .filter(|epoch| epoch.epoch == committee.epoch)
                        .collect::<Vec<_>>();
                    observations.insert(
                        *party,
                        format!(
                            "active={:?}, matching_history_entries={}",
                            status.active_epoch,
                            matching.len()
                        ),
                    );
                    let link = match (|| -> anyhow::Result<Option<EpochHistoryLink>> {
                        anyhow::ensure!(
                            status.party == *party,
                            "status endpoint returned another party ID"
                        );
                        anyhow::ensure!(
                            status.ready,
                            "party {party} reported that it is not ready"
                        );
                        if status.active_epoch != Some(committee.epoch) {
                            return Ok(None);
                        }
                        anyhow::ensure!(
                            matching.len() == 1,
                            "party {party} reported active epoch {} without exactly one history entry",
                            committee.epoch
                        );
                        let epoch = matching[0];
                        let _ = epoch.history_link.root()?;
                        anyhow::ensure!(
                            epoch.public == *expected
                                && epoch.history_link.network() == client.network_id
                                && epoch.history_link.epoch() == committee.epoch
                                && epoch.history_link.key_id() == epoch.public.key_id
                                && epoch.history_link.activation_digest()
                                    == epoch.public.activation_digest()?,
                            "party {party} exposed a history link for a different active public epoch"
                        );
                        Ok(Some(epoch.history_link))
                    })() {
                        Ok(link) => link,
                        Err(error) => {
                            observations.insert(
                                *party,
                                format!("invalid/non-candidate history status: {error:#}"),
                            );
                            continue;
                        }
                    };
                    if let Some(link) = link {
                        record_equal_observation(&mut links, *party, link);
                    }
                }
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                }
            }
        }
        if let Some(group) = equal_observation_quorum(&links, required, &required_parties)? {
            return Ok(group.value);
        }
        let group_summary = links
            .iter()
            .enumerate()
            .map(|(index, group)| {
                format!(
                    "group {index}: parties={}",
                    format_party_list(&group.parties.iter().copied().collect::<Vec<_>>()),
                )
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "responsive parties did not expose one n-f active epoch-history link before the \
             deadline; groups: {group_summary:?}; observations: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

fn acceptance_avss_transition_digest(transition: &AvssTransition) -> anyhow::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/avss-transition/v3");
    hasher.update(&[match transition.purpose {
        DealPurpose::Dkg => 0,
        DealPurpose::Refresh => 1,
        DealPurpose::Reshare => 2,
    }]);
    hasher.update(&transition.session.0);
    hasher.update(&transition.key_id);
    hasher.update(&transition.fault_bound.to_le_bytes());
    hasher.update(&transition.history_parent.transition_binding()?);
    hasher.update(&transition.old.as_ref().map_or(Ok([0; 32]), EpochPublic::activation_digest)?);
    hasher.update(&transition.target.digest());
    for dealer in &transition.eligible_dealers {
        hasher.update(&dealer.0.to_le_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

fn verification_shares_digest(public: &EpochPublic) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/e2e-verification-shares/v1");
    for (party, share) in &public.verification_shares {
        hasher.update(&party.0.to_le_bytes());
        hasher.update(&share.0);
    }
    *hasher.finalize().as_bytes()
}

fn validate_exact_same_committee_refresh(
    before: &EpochPublic,
    after: &EpochPublic,
    fault_bound: u16,
    history_parent: EpochHistoryParent,
    observed_transition_digest: [u8; 32],
) -> anyhow::Result<ExactRefreshEvidence> {
    before.validate()?;
    after.validate()?;
    anyhow::ensure!(
        before.committee.epoch.checked_add(1) == Some(after.committee.epoch),
        "exact proactive refresh is not an immediate successor"
    );
    anyhow::ensure!(
        before.key_id == after.key_id && before.group_key_bytes() == after.group_key_bytes(),
        "exact proactive refresh changed its key ID or group spend key"
    );
    anyhow::ensure!(
        before.committee.threshold == after.committee.threshold
            && before.committee.n() == after.committee.n(),
        "exact proactive refresh changed its committee shape"
    );
    let source_members = before
        .committee
        .members
        .iter()
        .map(|member| (member.id, member.signing_key))
        .collect::<Vec<_>>();
    let target_members = after
        .committee
        .members
        .iter()
        .map(|member| (member.id, member.signing_key))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        target_members == source_members,
        "required proactive refresh substituted a stable committee identity"
    );
    let source_receiver_keys = before
        .committee
        .members
        .iter()
        .map(|member| member.encryption_key)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        after
            .committee
            .members
            .iter()
            .all(|member| !source_receiver_keys.contains(&member.encryption_key)),
        "required proactive refresh reused a source receiver key"
    );
    anyhow::ensure!(
        before.verification_shares.keys().eq(after.verification_shares.keys())
            && before.verification_shares != after.verification_shares,
        "required proactive refresh did not install a fresh verification-share polynomial"
    );

    let members = source_members.iter().map(|(party, _)| *party).collect::<Vec<_>>();
    let refresh = AvssTransition {
        purpose: DealPurpose::Refresh,
        session: canonical_refresh_session(before, &after.committee, history_parent)?,
        key_id: before.key_id,
        fault_bound,
        history_parent,
        old: Some(before.clone()),
        target: after.committee.clone(),
        eligible_dealers: members.clone(),
    };
    let refresh_transition_digest = acceptance_avss_transition_digest(&refresh)?;
    anyhow::ensure!(
        observed_transition_digest == refresh_transition_digest,
        "authenticated epoch history does not bind the expected zero-constant refresh transition"
    );
    let mut reshare = refresh;
    reshare.purpose = DealPurpose::Reshare;
    reshare.session = canonical_reshare_session(before, &after.committee, history_parent)?;
    let reshare_transition_digest = acceptance_avss_transition_digest(&reshare)?;
    anyhow::ensure!(
        observed_transition_digest != reshare_transition_digest,
        "authenticated epoch history ambiguously matches old-share redistribution"
    );

    Ok(ExactRefreshEvidence {
        members,
        source_verification_shares: verification_shares_digest(before),
        target_verification_shares: verification_shares_digest(after),
        refresh_transition_digest,
        reshare_transition_digest,
    })
}

fn validate_scheduled_refresh(
    before: &EpochPublic,
    after: &EpochPublic,
    expected_group_key: [u8; 32],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        after.group_key_bytes() == expected_group_key,
        "scheduled proactive refresh changed the Monero spend key"
    );
    anyhow::ensure!(
        before.committee.threshold == after.committee.threshold
            && before.committee.n() == after.committee.n(),
        "scheduled proactive refresh unexpectedly changed the committee shape"
    );
    anyhow::ensure!(
        before.verification_shares != after.verification_shares,
        "scheduled proactive refresh reused the prior public share polynomial"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CrossEpochSubthresholdEvidence {
    mixed_sets: usize,
    threshold_boundary_sets: usize,
}

/// Model two adjacent sharings as independently randomized Shamir polynomials with one common
/// constant. Old and new observations occupy separate coefficient blocks and use the FROST
/// coordinate native to their own epoch. A PartyId present in both epochs therefore contributes
/// two distinct typed observations, while added and removed parties remain in their respective
/// observation domains.
///
/// The common scalar is determined by an observation set exactly when the unit vector selecting
/// that constant lies in the row span of the observation matrix. Every mixed set strictly below
/// both epoch thresholds must leave it outside the span. Conversely, every minimal threshold set
/// from either epoch must span it; those shares reconstruct by design and are not called isolated.
///
/// This structural check is conditional on the AVSS reshare supplying fresh independently random
/// nonconstant coefficients. Proactive security additionally requires fewer than each epoch's
/// threshold shares to be exposed and retired scalar shares to be securely erased.
fn validate_cross_epoch_subthreshold_non_identifiability(
    before: &EpochPublic,
    after: &EpochPublic,
) -> anyhow::Result<CrossEpochSubthresholdEvidence> {
    before.validate()?;
    after.validate()?;
    anyhow::ensure!(
        after.committee.epoch
            == before.committee.epoch.checked_add(1).context("epoch exhausted")?,
        "cross-epoch subthreshold analysis requires adjacent epochs"
    );
    anyhow::ensure!(
        before.key_id == after.key_id && before.group_key == after.group_key,
        "cross-epoch subthreshold analysis requires one unchanged distributed key"
    );
    anyhow::ensure!(
        before.verification_shares != after.verification_shares,
        "cross-epoch subthreshold analysis requires a changed successor public share table"
    );

    let old_parties = before.committee.members.iter().map(|member| member.id).collect::<Vec<_>>();
    let new_parties = after.committee.members.iter().map(|member| member.id).collect::<Vec<_>>();
    let old_threshold = usize::from(before.committee.threshold);
    let new_threshold = usize::from(after.committee.threshold);
    let width = old_threshold
        .checked_add(new_threshold)
        .and_then(|sum| sum.checked_sub(1))
        .context("cross-epoch coefficient width overflow")?;

    let old_rows = old_parties
        .iter()
        .map(|party| {
            Ok((
                *party,
                old_epoch_observation_row(&before.committee, *party, old_threshold, new_threshold)?,
            ))
        })
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
    let new_rows = new_parties
        .iter()
        .map(|party| {
            Ok((
                *party,
                new_epoch_observation_row(&after.committee, *party, old_threshold, new_threshold)?,
            ))
        })
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;

    let old_subthreshold = (1..old_threshold)
        .flat_map(|subset_width| fixed_width_party_subsets(&old_parties, subset_width))
        .collect::<Vec<_>>();
    let new_subthreshold = (1..new_threshold)
        .flat_map(|subset_width| fixed_width_party_subsets(&new_parties, subset_width))
        .collect::<Vec<_>>();
    let mut mixed_sets = 0_usize;
    for old_subset in &old_subthreshold {
        for new_subset in &new_subthreshold {
            let rows = observation_rows(old_subset, new_subset, &old_rows, &new_rows);
            anyhow::ensure!(
                !common_constant_is_determined(&rows, width),
                "subthreshold epoch-{} observations {old_subset:?} and epoch-{} observations \
                 {new_subset:?} determined the common constant",
                before.committee.epoch,
                after.committee.epoch
            );
            mixed_sets =
                mixed_sets.checked_add(1).context("cross-epoch mixed-set count overflow")?;
        }
    }

    let mut threshold_boundary_sets = 0_usize;
    for old_subset in fixed_width_party_subsets(&old_parties, old_threshold) {
        let rows = observation_rows(&old_subset, &[], &old_rows, &new_rows);
        anyhow::ensure!(
            common_constant_is_determined(&rows, width),
            "threshold epoch-{} observations {old_subset:?} did not determine the common constant",
            before.committee.epoch
        );
        threshold_boundary_sets = threshold_boundary_sets
            .checked_add(1)
            .context("cross-epoch threshold-boundary count overflow")?;
    }
    for new_subset in fixed_width_party_subsets(&new_parties, new_threshold) {
        let rows = observation_rows(&[], &new_subset, &old_rows, &new_rows);
        anyhow::ensure!(
            common_constant_is_determined(&rows, width),
            "threshold epoch-{} observations {new_subset:?} did not determine the common constant",
            after.committee.epoch
        );
        threshold_boundary_sets = threshold_boundary_sets
            .checked_add(1)
            .context("cross-epoch threshold-boundary count overflow")?;
    }

    Ok(CrossEpochSubthresholdEvidence { mixed_sets, threshold_boundary_sets })
}

fn old_epoch_observation_row(
    committee: &Committee,
    party: PartyId,
    old_threshold: usize,
    new_threshold: usize,
) -> anyhow::Result<Vec<DalekScalar>> {
    let width = old_threshold
        .checked_add(new_threshold)
        .and_then(|sum| sum.checked_sub(1))
        .context("cross-epoch coefficient width overflow")?;
    let mut row = vec![DalekScalar::ZERO; width];
    row[0] = DalekScalar::ONE;
    let x = DalekScalar::from(u64::from(committee.frost_index(party)?));
    let mut power = x;
    for coefficient in row.iter_mut().take(old_threshold).skip(1) {
        *coefficient = power;
        power *= x;
    }
    Ok(row)
}

fn new_epoch_observation_row(
    committee: &Committee,
    party: PartyId,
    old_threshold: usize,
    new_threshold: usize,
) -> anyhow::Result<Vec<DalekScalar>> {
    let width = old_threshold
        .checked_add(new_threshold)
        .and_then(|sum| sum.checked_sub(1))
        .context("cross-epoch coefficient width overflow")?;
    let mut row = vec![DalekScalar::ZERO; width];
    row[0] = DalekScalar::ONE;
    let x = DalekScalar::from(u64::from(committee.frost_index(party)?));
    let mut power = x;
    for coefficient in row.iter_mut().skip(old_threshold) {
        *coefficient = power;
        power *= x;
    }
    Ok(row)
}

fn observation_rows(
    old_subset: &[PartyId],
    new_subset: &[PartyId],
    old_rows: &BTreeMap<PartyId, Vec<DalekScalar>>,
    new_rows: &BTreeMap<PartyId, Vec<DalekScalar>>,
) -> Vec<Vec<DalekScalar>> {
    old_subset
        .iter()
        .map(|party| old_rows[party].clone())
        .chain(new_subset.iter().map(|party| new_rows[party].clone()))
        .collect()
}

fn common_constant_is_determined(rows: &[Vec<DalekScalar>], width: usize) -> bool {
    let rank = scalar_matrix_rank(rows, width);
    let mut with_constant = rows.to_vec();
    let mut constant = vec![DalekScalar::ZERO; width];
    constant[0] = DalekScalar::ONE;
    with_constant.push(constant);
    scalar_matrix_rank(&with_constant, width) == rank
}

fn scalar_matrix_rank(rows: &[Vec<DalekScalar>], width: usize) -> usize {
    debug_assert!(rows.iter().all(|row| row.len() == width));
    let mut matrix = rows.to_vec();
    let mut pivot_row = 0_usize;
    for column in 0..width {
        let Some(next_pivot) =
            (pivot_row..matrix.len()).find(|row| matrix[*row][column] != DalekScalar::ZERO)
        else {
            continue;
        };
        matrix.swap(pivot_row, next_pivot);
        let pivot_inverse = matrix[pivot_row][column].invert();
        let pivot = matrix[pivot_row].clone();
        for row in matrix.iter_mut().skip(pivot_row + 1) {
            let factor = row[column] * pivot_inverse;
            if factor == DalekScalar::ZERO {
                continue;
            }
            for (entry, pivot_entry) in row[column..].iter_mut().zip(&pivot[column..]) {
                *entry -= factor * *pivot_entry;
            }
        }
        pivot_row += 1;
        if pivot_row == matrix.len() {
            break;
        }
    }
    pivot_row
}

fn fixed_width_party_subsets(parties: &[PartyId], width: usize) -> Vec<Vec<PartyId>> {
    fn extend(
        parties: &[PartyId],
        width: usize,
        start: usize,
        selected: &mut Vec<PartyId>,
        subsets: &mut Vec<Vec<PartyId>>,
    ) {
        if selected.len() == width {
            subsets.push(selected.clone());
            return;
        }
        let remaining = width - selected.len();
        for index in start..=parties.len() - remaining {
            selected.push(parties[index]);
            extend(parties, width, index + 1, selected, subsets);
            selected.pop();
        }
    }

    if width == 0 || width > parties.len() {
        return Vec::new();
    }
    let mut subsets = Vec::new();
    extend(parties, width, 0, &mut Vec::with_capacity(width), &mut subsets);
    subsets
}

/// Validate a fixed-size, fixed-threshold proactive successor whose target was learned from the
/// live network, not from the finite scenario fixture. Eligible-member substitution may make this
/// a reshare instead of a true same-membership refresh. The returned count is useful acceptance
/// evidence for the independently rotated X25519 keys.
fn validate_dynamic_refresh(
    scenario: &Scenario,
    before: &EpochPublic,
    after: &EpochPublic,
    fault_bound: u16,
) -> anyhow::Result<usize> {
    before.validate()?;
    after.validate()?;
    before.committee.validate_async_security_with_faults(fault_bound)?;
    after.committee.validate_async_security_with_faults(fault_bound)?;

    let expected_epoch = before
        .committee
        .epoch
        .checked_add(1)
        .context("dynamic proactive refresh epoch exhausted")?;
    anyhow::ensure!(
        after.committee.epoch == expected_epoch,
        "dynamic proactive refresh must activate immediate epoch {expected_epoch}, found {}",
        after.committee.epoch
    );
    anyhow::ensure!(
        after.key_id == before.key_id,
        "dynamic proactive refresh changed the distributed key identifier"
    );
    anyhow::ensure!(
        after.group_key_bytes() == before.group_key_bytes(),
        "dynamic proactive refresh changed the Monero spend key"
    );
    anyhow::ensure!(
        after.committee.threshold == before.committee.threshold,
        "dynamic proactive refresh changed the signing threshold"
    );
    anyhow::ensure!(
        after.committee.n() == before.committee.n(),
        "dynamic proactive refresh selected {} members, expected exact desired_n={}",
        after.committee.n(),
        before.committee.n()
    );

    let before_members = before.committee.by_id();
    let after_members = after.committee.by_id();
    let mut rotated_encryption_keys = 0_usize;
    for (party, new_member) in &after_members {
        let configured = scenario.party(*party)?;
        anyhow::ensure!(
            new_member.signing_key == configured.signing_key.0,
            "dynamic proactive refresh changed party {party}'s stable signing key"
        );
        anyhow::ensure!(
            before_members
                .values()
                .all(|old_member| old_member.encryption_key != new_member.encryption_key),
            "dynamic proactive refresh reused a source receiver key for party {party}"
        );
        rotated_encryption_keys = rotated_encryption_keys.saturating_add(1);
    }
    anyhow::ensure!(
        rotated_encryption_keys == usize::from(after.committee.n()),
        "dynamic proactive refresh must rotate every certificate-selected receiver key"
    );
    anyhow::ensure!(
        after.verification_shares != before.verification_shares,
        "dynamic proactive refresh reused the source verification-share polynomial"
    );
    Ok(rotated_encryption_keys)
}

/// Observe the first autonomous successor beyond the configured scenario chain. This function has
/// no target committee argument by design: every target key and the public sharing polynomial are
/// learned independently from each responsive party's authenticated status endpoint.
async fn wait_for_dynamic_refresh(
    scenario: &Scenario,
    client: &PartyClient,
    old: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<EpochPublic> {
    let target_epoch =
        old.committee.epoch.checked_add(1).context("dynamic proactive refresh epoch exhausted")?;
    anyhow::ensure!(
        fault_bound < old.committee.n(),
        "dynamic proactive refresh fault bound exhausts the target committee"
    );
    let required = usize::from(old.committee.n() - fault_bound);
    let responsive = client
        .admin_endpoints
        .keys()
        .copied()
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        responsive.len() >= required,
        "dynamic proactive refresh has {} responsive final-committee parties, requires n-f={required}",
        responsive.len()
    );
    let recovered_party = required_recovered_party()?;
    if let Some(recovered_party) = recovered_party {
        anyhow::ensure!(
            responsive.contains(&recovered_party),
            "required recovered party {recovered_party} has no responsive dynamic-refresh endpoint"
        );
    }
    let required_parties = recovered_party.into_iter().collect::<BTreeSet<_>>();

    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut activated = Vec::<EqualObservationGroup<EpochPublic>>::new();
        for party in &responsive {
            match client.get_admin::<PartyStatus>(*party, "/v1/status").await {
                Ok(status) => {
                    observations.insert(
                        *party,
                        format!(
                            "active={:?}, staged={:?}, epochs={:?}, refresh={:?}",
                            status.active_epoch,
                            status.staged_epochs,
                            status.epochs.iter().map(|epoch| epoch.epoch).collect::<Vec<_>>(),
                            status.proactive_refresh,
                        ),
                    );
                    let public = match (|| -> anyhow::Result<Option<EpochPublic>> {
                        anyhow::ensure!(
                            status.party == *party,
                            "status endpoint returned another party ID"
                        );
                        anyhow::ensure!(
                            status.ready,
                            "party {party} reported that it is not ready"
                        );
                        if let Some(observed) = status.active_epoch {
                            anyhow::ensure!(
                                observed <= target_epoch,
                                "party {party} advanced past dynamic target epoch {target_epoch} to {observed}"
                            );
                        }
                        if status.active_epoch != Some(target_epoch) {
                            return Ok(None);
                        }
                        let matching = status
                            .epochs
                            .iter()
                            .filter(|epoch| epoch.epoch == target_epoch)
                            .collect::<Vec<_>>();
                        anyhow::ensure!(
                            matching.len() == 1,
                            "party {party} reported dynamic epoch {target_epoch} without exactly one public epoch value"
                        );
                        let public = matching[0].public.clone();
                        validate_dynamic_refresh(scenario, old, &public, fault_bound)
                            .with_context(|| {
                                format!(
                                    "party {party} reported an invalid dynamic epoch-{target_epoch}"
                                )
                            })?;
                        public.committee.member(*party).with_context(|| {
                            format!(
                                "party {party} is not a member of its reported epoch-{target_epoch} committee"
                            )
                        })?;
                        Ok(Some(public))
                    })() {
                        Ok(public) => public,
                        Err(error) => {
                            observations
                                .insert(*party, format!("invalid/non-candidate status: {error:#}"));
                            continue;
                        }
                    };
                    if let Some(public) = public {
                        record_equal_observation(&mut activated, *party, public);
                    }
                }
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                }
            }
        }

        if let Some(group) = equal_observation_quorum(&activated, required, &required_parties)? {
            let expected = group.value.clone();
            let agreeing_parties = group.parties.clone();
            let selected_ids =
                expected.committee.members.iter().map(|member| member.id).collect::<BTreeSet<_>>();
            let rotated = validate_dynamic_refresh(scenario, old, &expected, fault_bound)?;
            tracing::info!(
                epoch = target_epoch,
                parties = selected_ids.len(),
                agreeing_parties = ?agreeing_parties,
                omitted = responsive.len().saturating_sub(selected_ids.len()),
                rotated_encryption_keys = rotated,
                "autonomous dynamic QUIC refresh activated"
            );
            return Ok(expected);
        }

        let group_summary = activated
            .iter()
            .enumerate()
            .map(|(index, group)| {
                format!(
                    "group {index}: parties={}",
                    format_party_list(&group.parties.iter().copied().collect::<Vec<_>>()),
                )
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "dynamic epoch-{target_epoch} did not activate before the protocol deadline; \
             groups: {group_summary:?}; observations: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

#[allow(clippy::too_many_lines)]
async fn run_avss(
    client: &PartyClient,
    transition: AvssTransition,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<EpochPublic> {
    anyhow::ensure!(
        transition.fault_bound == fault_bound,
        "transition fault bound differs from the runner configuration"
    );
    anyhow::ensure!(
        transition.fault_bound < transition.target.n(),
        "transition fault bound exhausts its target committee"
    );
    let dealers = match transition.purpose {
        DealPurpose::Dkg => {
            transition.target.members.iter().map(|member| member.id).collect::<Vec<_>>()
        }
        DealPurpose::Refresh | DealPurpose::Reshare => transition.eligible_dealers.clone(),
    };
    let fault_specification = acceptance_protocol_fault_specification()?;
    let matching_fault =
        fault_specification.filter(|specification| specification.epoch == transition.target.epoch);
    if let Some(specification) = matching_fault {
        arm_acceptance_protocol_fault_gate(client, &transition, specification).await?;
    }
    let minimum_started_dealers = match (&transition.purpose, &transition.old) {
        (DealPurpose::Dkg, None) | (DealPurpose::Refresh, Some(_)) => {
            usize::from(transition.target.n() - transition.fault_bound)
        }
        (DealPurpose::Reshare, Some(old)) => usize::from(old.committee.threshold),
        _ => anyhow::bail!("AVSS purpose and old epoch are inconsistent"),
    };
    let available_dealers = dealers.iter().filter(|dealer| !faulty.contains(dealer)).count();
    anyhow::ensure!(
        available_dealers >= minimum_started_dealers,
        "transition has {available_dealers} available AVSS dealers, requires {minimum_started_dealers}"
    );
    let mut started_dealers = BTreeSet::new();
    let mut start_observations = BTreeMap::<PartyId, String>::new();
    let mut fault_boundary_observed = false;
    for dealer in &dealers {
        if faulty.contains(dealer) {
            continue;
        }
        let response: AvssStepResponse = match client
            .post_admin(
                *dealer,
                "/v1/avss/start",
                &AvssStartRequest { transition: transition.clone() },
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                start_observations.insert(*dealer, format!("AVSS start error: {error:#}"));
                continue;
            }
        };
        if response.party != *dealer || response.dealer != *dealer {
            start_observations.insert(
                *dealer,
                format!(
                    "invalid AVSS start response: party={} dealer={}",
                    response.party, response.dealer
                ),
            );
            continue;
        }
        start_observations.insert(*dealer, "started".to_owned());
        started_dealers.insert(*dealer);
        if let Some(specification) = matching_fault.filter(|_| !fault_boundary_observed) {
            let boundary_reachable = match specification.boundary {
                AcceptanceProtocolFaultBoundary::DealerStarted => *dealer == specification.party,
                AcceptanceProtocolFaultBoundary::QualRoundZero => {
                    started_dealers.len() >= minimum_started_dealers
                }
            };
            if boundary_reachable {
                wait_for_acceptance_protocol_fault_release(client, &transition, specification)
                    .await?;
                fault_boundary_observed = true;
            }
        }
    }
    anyhow::ensure!(
        started_dealers.len() >= minimum_started_dealers,
        "transition started {} valid AVSS dealers, requires {minimum_started_dealers}; observations: {start_observations:?}",
        started_dealers.len()
    );
    anyhow::ensure!(
        matching_fault.is_none() || fault_boundary_observed,
        "configured acceptance protocol fault boundary was not reachable"
    );

    wait_for_transition_activation(client, &transition, faulty).await
}

async fn wait_for_transition_activation(
    client: &PartyClient,
    transition: &AvssTransition,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<EpochPublic> {
    // The acceptance runner deliberately does not relay any protocol message. AVSS, QUAL,
    // staging, activation acknowledgements, activation, and retirement must progress through each
    // party's durable QUIC runtime. HTTP is used only to observe the resulting state.
    let target_epoch = transition.target.epoch;
    let expected_committee_digest = transition.target.digest();
    anyhow::ensure!(
        transition.fault_bound < transition.target.n(),
        "transition fault bound exhausts epoch-{target_epoch} target committee"
    );
    let required = usize::from(transition.target.n() - transition.fault_bound);
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let responsive = transition
        .target
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        responsive.len() >= required,
        "transition has {} responsive target parties, requires n-f={required}",
        responsive.len()
    );
    let mut required_parties = required_recovered_party()?.into_iter().collect::<BTreeSet<_>>();
    if let Some(specification) = acceptance_protocol_fault_specification()?
        .filter(|specification| specification.epoch == target_epoch)
    {
        required_parties.insert(specification.party);
    }
    for party in &required_parties {
        anyhow::ensure!(
            responsive.contains(party),
            "required recovered transition party {party} is not a responsive epoch-{target_epoch} target member"
        );
    }

    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut activated = Vec::<EqualObservationGroup<EpochPublic>>::new();
        for party in &responsive {
            match client.get_admin::<PartyStatus>(*party, "/v1/status").await {
                Ok(status) => {
                    observations.insert(
                        *party,
                        format!(
                            "active={:?}, staged={:?}, epochs={:?}",
                            status.active_epoch,
                            status.staged_epochs,
                            status.epochs.iter().map(|epoch| epoch.epoch).collect::<Vec<_>>()
                        ),
                    );
                    let public = match (|| -> anyhow::Result<Option<EpochPublic>> {
                        anyhow::ensure!(
                            status.party == *party,
                            "status endpoint returned another party ID"
                        );
                        anyhow::ensure!(
                            status.ready,
                            "party {party} reported that it is not ready"
                        );
                        if let Some(observed) = status.active_epoch {
                            anyhow::ensure!(
                                observed <= target_epoch,
                                "party {party} advanced past target epoch {target_epoch} to {observed}"
                            );
                        }
                        if status.active_epoch != Some(target_epoch) {
                            return Ok(None);
                        }
                        let matching = status
                            .epochs
                            .iter()
                            .filter(|epoch| epoch.epoch == target_epoch)
                            .collect::<Vec<_>>();
                        anyhow::ensure!(
                            matching.len() == 1,
                            "party {party} reported active epoch {target_epoch} without exactly one public epoch value"
                        );
                        let public = matching[0].public.clone();
                        public.validate()?;
                        anyhow::ensure!(
                            public.key_id == transition.key_id,
                            "party {party} activated the wrong key ID for epoch {target_epoch}"
                        );
                        anyhow::ensure!(
                            public.committee.digest() == expected_committee_digest,
                            "party {party} activated a different epoch-{target_epoch} committee"
                        );
                        Ok(Some(public))
                    })() {
                        Ok(public) => public,
                        Err(error) => {
                            observations
                                .insert(*party, format!("invalid/non-candidate status: {error:#}"));
                            continue;
                        }
                    };
                    if let Some(public) = public {
                        record_equal_observation(&mut activated, *party, public);
                    }
                }
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                }
            }
        }

        if let Some(group) = equal_observation_quorum(&activated, required, &required_parties)? {
            let expected = group.value.clone();
            tracing::info!(
                epoch = target_epoch,
                parties = group.parties.len(),
                agreeing_parties = ?group.parties,
                "autonomous QUIC transition activated"
            );
            return Ok(expected);
        }

        let group_summary = activated
            .iter()
            .enumerate()
            .map(|(index, group)| {
                format!(
                    "group {index}: parties={}",
                    format_party_list(&group.parties.iter().copied().collect::<Vec<_>>()),
                )
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "epoch-{target_epoch} did not activate through QUIC before the protocol deadline; \
             groups: {group_summary:?}; observations: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

fn parse_acceptance_protocol_fault_specification(
    specification: Option<&str>,
) -> anyhow::Result<Option<AcceptanceProtocolFaultSpecification>> {
    let Some(specification) = specification else {
        return Ok(None);
    };
    let mut fields = specification.split(':');
    let epoch = fields.next().context("protocol fault gate omitted its epoch")?.parse::<u64>()?;
    let boundary = match fields.next().context("protocol fault gate omitted its boundary")? {
        "dealer_started" => AcceptanceProtocolFaultBoundary::DealerStarted,
        "qual_round_zero" => AcceptanceProtocolFaultBoundary::QualRoundZero,
        other => anyhow::bail!("unsupported protocol fault boundary {other}"),
    };
    let party = PartyId::new(
        fields.next().context("protocol fault gate omitted its party")?.parse::<u16>()?,
    )?;
    anyhow::ensure!(fields.next().is_none(), "protocol fault gate has trailing fields");
    anyhow::ensure!(epoch == 0, "protocol fault gate may target only canonical epoch zero");
    Ok(Some(AcceptanceProtocolFaultSpecification { epoch, boundary, party }))
}

fn acceptance_protocol_fault_specification()
-> anyhow::Result<Option<AcceptanceProtocolFaultSpecification>> {
    if std::env::var("TM_ACCEPTANCE_ENABLE_FAULT_HOOKS").as_deref() != Ok("1") {
        return Ok(None);
    }
    let specification = match std::env::var("TM_ACCEPTANCE_PROTOCOL_FAULT_GATE") {
        Ok(specification) => Some(specification),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error).context("reading TM_ACCEPTANCE_PROTOCOL_FAULT_GATE"),
    };
    parse_acceptance_protocol_fault_specification(specification.as_deref())
}

async fn arm_acceptance_protocol_fault_gate(
    client: &PartyClient,
    transition: &AvssTransition,
    specification: AcceptanceProtocolFaultSpecification,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        transition.target.epoch == specification.epoch && transition.purpose == DealPurpose::Dkg,
        "acceptance protocol fault gate must target the canonical DKG"
    );
    transition.target.member(specification.party)?;
    let request = AcceptanceProtocolFaultGateRequest {
        action: AcceptanceConsolidationGateAction::Arm,
        session: transition.session,
        epoch: specification.epoch,
        boundary: specification.boundary,
    };
    let response = client
        .post_admin::<_, AcceptanceProtocolFaultGateResponse>(
            specification.party,
            "/v1/acceptance/protocol-fault-gate",
            &request,
        )
        .await?;
    anyhow::ensure!(
        response.party == specification.party
            && response.state == AcceptanceConsolidationGateState::Armed
            && response.session == Some(transition.session)
            && response.epoch == Some(specification.epoch)
            && response.boundary == Some(specification.boundary)
            && response.dealer.is_none()
            && response.qual_round.is_none(),
        "party {} did not arm the exact protocol fault gate",
        specification.party
    );
    Ok(())
}

async fn wait_for_acceptance_protocol_fault_release(
    client: &PartyClient,
    transition: &AvssTransition,
    specification: AcceptanceProtocolFaultSpecification,
) -> anyhow::Result<()> {
    let request = AcceptanceProtocolFaultGateRequest {
        action: AcceptanceConsolidationGateAction::Status,
        session: transition.session,
        epoch: specification.epoch,
        boundary: specification.boundary,
    };
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let held = loop {
        if let Ok(response) = client
            .post_admin::<_, AcceptanceProtocolFaultGateResponse>(
                specification.party,
                "/v1/acceptance/protocol-fault-gate",
                &request,
            )
            .await
        {
            anyhow::ensure!(
                response.party == specification.party
                    && response.session == Some(transition.session)
                    && response.epoch == Some(specification.epoch)
                    && response.boundary == Some(specification.boundary),
                "protocol fault gate status differs from its exact binding"
            );
            if response.state == AcceptanceConsolidationGateState::Held {
                break response;
            }
            anyhow::ensure!(
                response.state == AcceptanceConsolidationGateState::Armed,
                "protocol fault gate left Armed without reaching Held"
            );
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "party {} did not durably hold {} before the protocol deadline",
            specification.party,
            specification.boundary.marker()
        );
        tokio::time::sleep(client.poll_interval).await;
    };
    match specification.boundary {
        AcceptanceProtocolFaultBoundary::DealerStarted => {
            anyhow::ensure!(
                held.dealer == Some(specification.party) && held.qual_round.is_none(),
                "dealer-start hold lacks exact durable dealer evidence"
            );
        }
        AcceptanceProtocolFaultBoundary::QualRoundZero => {
            anyhow::ensure!(
                held.dealer.is_none() && held.qual_round == Some(0),
                "QUAL hold lacks exact durable round-zero evidence"
            );
        }
    }
    println!(
        "TM_ACCEPTANCE_PROTOCOL_FAULT_GATE_HELD party={} epoch={} boundary={} session={}",
        specification.party,
        specification.epoch,
        specification.boundary.marker(),
        transition.session
    );
    {
        use std::io::Write as _;
        std::io::stdout().flush()?;
    }
    tracing::warn!(
        party = %specification.party,
        epoch = specification.epoch,
        boundary = specification.boundary.marker(),
        session = %transition.session,
        "durable acceptance protocol fault boundary held"
    );

    loop {
        if let Ok(response) = client
            .post_admin::<_, AcceptanceProtocolFaultGateResponse>(
                specification.party,
                "/v1/acceptance/protocol-fault-gate",
                &request,
            )
            .await
        {
            anyhow::ensure!(
                response.party == specification.party
                    && response.session == Some(transition.session)
                    && response.epoch == Some(specification.epoch)
                    && response.boundary == Some(specification.boundary),
                "released protocol fault gate differs from its exact binding"
            );
            if response.state == AcceptanceConsolidationGateState::Released {
                break;
            }
            anyhow::ensure!(
                response.state == AcceptanceConsolidationGateState::Held,
                "protocol fault gate changed before authenticated release"
            );
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "party {} protocol fault gate was not released before the deadline",
            specification.party
        );
        tokio::time::sleep(client.poll_interval).await;
    }
    println!(
        "TM_ACCEPTANCE_PROTOCOL_FAULT_GATE_RELEASED party={} epoch={} boundary={} session={}",
        specification.party,
        specification.epoch,
        specification.boundary.marker(),
        transition.session
    );
    Ok(())
}

/// Demo-only barrier emitted after the configured epoch chain has completed and immediately before
/// the runner begins observing the dynamic successor. The rotation-silent campaign uses the pause
/// to remove one actual certificate-selected source member only from the peer-QUIC Docker network
/// while keeping its process and HTTP endpoint healthy. Production party processes never enable
/// this hook.
async fn maybe_pause_before_dynamic_refresh(
    client: &PartyClient,
    source_epoch: u64,
    fault_party: Option<PartyId>,
) -> anyhow::Result<()> {
    if std::env::var("TM_ACCEPTANCE_ENABLE_FAULT_HOOKS").as_deref() != Ok("1")
        || !environment_flag("TM_ACCEPTANCE_PAUSE_BEFORE_DYNAMIC_REFRESH")?
    {
        return Ok(());
    }
    let target_epoch = source_epoch
        .checked_add(1)
        .context("dynamic proactive refresh epoch exhausted at fault barrier")?;
    let party = fault_party
        .context("dynamic refresh fault barrier requires the selected-member fault mode")?;
    let mut material = Vec::with_capacity(18);
    material.extend_from_slice(&source_epoch.to_le_bytes());
    material.extend_from_slice(&target_epoch.to_le_bytes());
    material.extend_from_slice(&party.0.to_le_bytes());
    let kind = AcceptanceDriverLatchKind::DynamicRotationOmission;
    let binding = acceptance_driver_binding(kind, &material);
    let armed: AcceptanceDriverLatchResponse = client
        .post_admin(
            party,
            "/v1/acceptance/driver-latch",
            &AcceptanceDriverLatchRequest {
                action: AcceptanceConsolidationGateAction::Arm,
                kind,
                binding,
            },
        )
        .await?;
    anyhow::ensure!(
        armed.party == party
            && armed.state == AcceptanceConsolidationGateState::Held
            && armed.kind == Some(kind)
            && armed.binding == Some(binding)
            && armed.event_unix_ms.is_none(),
        "party {party} held a different dynamic-rotation latch"
    );

    println!(
        "TM_ACCEPTANCE_DYNAMIC_REFRESH_BARRIER source_epoch={source_epoch} target_epoch={target_epoch}"
    );
    println!(
        "TM_ACCEPTANCE_DYNAMIC_REFRESH_LATCH_HELD party={party} source_epoch={source_epoch} target_epoch={target_epoch} binding={}",
        hex::encode(binding)
    );
    {
        use std::io::Write as _;
        std::io::stdout().flush()?;
    }
    tracing::warn!(source_epoch, target_epoch, "dynamic refresh fault barrier reached");
    wait_for_authenticated_driver_release(client, party, kind, binding).await?;
    println!(
        "TM_ACCEPTANCE_DYNAMIC_REFRESH_LATCH_RELEASED party={party} source_epoch={source_epoch} target_epoch={target_epoch} binding={}",
        hex::encode(binding)
    );
    Ok(())
}

async fn mine_confirmation(
    daemon: &MoneroDaemon<SimpleRequestTransport>,
    mining_address: &MoneroAddress,
    tx_hash: [u8; 32],
    mut next_height: usize,
    poll_interval_ms: u64,
    timeout_seconds: u64,
) -> anyhow::Result<monero_wallet::block::Block> {
    // Signing may finish during an earlier maturity-block advance. Inspect every block since
    // the funding/signing snapshot before mining more; watching only newly generated blocks
    // permanently misses a transaction which is already canonical.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds);
    loop {
        let tip = daemon.latest_block_number().await?;
        while next_height <= tip {
            let block = daemon.block_by_number(next_height).await?;
            if block.transactions.contains(&tx_hash) {
                return Ok(block);
            }
            next_height = next_height.checked_add(1).context("confirmation height overflow")?;
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "transaction {} was not mined before the protocol deadline",
            hex::encode(tx_hash)
        );
        // Unrelayed Dandelion++ stem transactions may need another block after their embargo.
        daemon.generate_blocks(mining_address, 1).await?;
        tokio::time::sleep(std::time::Duration::from_millis(poll_interval_ms)).await;
    }
}

fn threshold_view_pair(public: &EpochPublic) -> anyhow::Result<ViewPair> {
    let spend =
        CompressedEdwardsY(public.group_key_bytes()).decompress().context("invalid group point")?;
    let view = DalekScalar::from_bytes_mod_order([0x42; 32]);
    Ok(ViewPair::new(Point::from(spend), Zeroizing::new(Scalar::from(view)))?)
}

fn threshold_spend_bytes(view: &ViewPair) -> [u8; 32] {
    view.spend().compress().to_bytes()
}

fn configured_faulty_parties(scenario: &Scenario) -> anyhow::Result<BTreeSet<PartyId>> {
    let configured = std::env::var("TM_FAULTY_PARTIES").unwrap_or_default();
    let mut faulty = BTreeSet::new();
    for value in configured.split(',').map(str::trim).filter(|value| !value.is_empty()) {
        let party = PartyId::new(value.parse::<u16>()?)?;
        scenario.party(party)?;
        anyhow::ensure!(faulty.insert(party), "duplicate faulty party {party}");
    }
    for spec in &scenario.committees {
        let actual = spec.eligible_members.iter().filter(|party| faulty.contains(party)).count();
        anyhow::ensure!(
            actual <= usize::from(spec.fault_bound),
            "epoch {} declares f={} but {} configured faulty eligible members are present",
            spec.epoch,
            spec.fault_bound,
            actual
        );
    }
    if !faulty.is_empty() {
        tracing::warn!(?faulty, "running deterministic silent-party fault profile");
    }
    Ok(faulty)
}

/// Add one selected-source-member omission which begins only after the finite scenario chain has
/// completed. Keeping this separate from `TM_FAULTY_PARTIES` ensures the rotation-silent campaign
/// cannot obtain an easier DKG/grow/shrink path by asking the client to ignore that party before
/// the Docker fault actually exists.
fn configured_dynamic_rotation_selected_member_fault(
    source: &Committee,
    eligible_target: &Committee,
    fault_bound: u16,
    already_faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<(Option<PartyId>, BTreeSet<PartyId>)> {
    source.validate_async_security_with_faults(fault_bound)?;
    eligible_target.validate()?;
    let mut combined = already_faulty.clone();
    let prior_eligible_faults =
        eligible_target.members.iter().filter(|member| combined.contains(&member.id)).count();
    anyhow::ensure!(
        prior_eligible_faults <= usize::from(fault_bound),
        "dynamic epoch {} declares f={fault_bound} but {prior_eligible_faults} configured faulty \
         eligible members are present",
        eligible_target.epoch
    );
    if !environment_flag("TM_ACCEPTANCE_DYNAMIC_ROTATION_SELECTED_MEMBER_FAULT")? {
        return Ok((None, combined));
    }
    anyhow::ensure!(
        std::env::var("TM_ACCEPTANCE_ENABLE_FAULT_HOOKS").as_deref() == Ok("1")
            && environment_flag("TM_ACCEPTANCE_PAUSE_BEFORE_DYNAMIC_REFRESH")?,
        "dynamic selected-member fault requires the acceptance-only dynamic-refresh barrier"
    );
    anyhow::ensure!(
        prior_eligible_faults < usize::from(fault_bound),
        "dynamic selected-member fault would exceed epoch {} eligible-roster fault bound \
         f={fault_bound}",
        eligible_target.epoch
    );
    let selected = source
        .members
        .iter()
        .map(|member| member.id)
        .find(|party| !combined.contains(party) && eligible_target.member(*party).is_ok())
        .context("dynamic selected-member fault has no responsive certified source member")?;
    anyhow::ensure!(combined.insert(selected));
    tracing::warn!(
        party = %selected,
        ?combined,
        source_epoch = source.epoch,
        "enabling one certified-source-member fault only for the post-scenario dynamic transition"
    );
    Ok((Some(selected), combined))
}

fn monero_network(network: NetworkKind) -> Network {
    match network {
        // Monero's regtest daemon deliberately uses mainnet-format addresses.
        NetworkKind::Regtest | NetworkKind::Mainnet => Network::Mainnet,
        NetworkKind::Testnet => Network::Testnet,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn consolidation_observer_accepts_confirmed_broadcast_without_weakening_other_phases() {
        use PublicConsolidationPhase::*;

        let phases =
            [Reserved, Signing, Certified, Broadcast, Confirmed, Quarantined, Aborted, Abandoned];
        for expected in [Reserved, Broadcast, Confirmed] {
            for actual in phases {
                let allowed = match expected {
                    Reserved => actual == Reserved,
                    Broadcast => matches!(actual, Broadcast | Confirmed),
                    Confirmed => actual == Confirmed,
                    _ => unreachable!(),
                };
                assert_eq!(
                    super::consolidation_phase_satisfies_observer(actual, expected),
                    allowed,
                    "actual={actual:?}, expected={expected:?}"
                );
            }
        }

        // Eligibility must not merge different phases or confirmation chain points into a quorum.
        let broadcast = observed_consolidation_decision_fixture();
        let mut confirmed = broadcast.clone();
        confirmed.phase = Confirmed;
        confirmed.confirmation = Some(ChainPoint::new(102, [0x31; 32]).unwrap());
        assert!(!broadcast.same_quorum_decision(&confirmed));
        assert!(confirmed.same_quorum_decision(&confirmed.clone()));
        let mut conflicting = confirmed.clone();
        conflicting.confirmation = Some(ChainPoint::new(102, [0x32; 32]).unwrap());
        assert!(!confirmed.same_quorum_decision(&conflicting));
    }

    #[tokio::test]
    async fn confirmation_finds_an_already_mined_transaction_without_mining_more() {
        use axum::{Json, Router, routing::post};
        use monero_oxide::{
            block::{Block, BlockHeader},
            transaction::{Input, Timelock, Transaction, TransactionPrefix},
        };
        use serde_json::{Value, json};

        let tx_hash = [0x39; 32];
        let app = Router::new()
            .route("/get_height", post(|| async { Json(json!({"height": 11})) }))
            .route("/json_rpc", post(move |body: axum::body::Bytes| async move {
                let request: Value = serde_json::from_slice(&body).unwrap();
                if request.is_array() {
                    return Json(json!({"error": {"code": -32700}}));
                }
                assert_eq!(request["method"], "get_block", "already-mined transactions must not trigger mining");
                let height = request["params"]["height"].as_u64().unwrap() as usize;
                let block = Block::new(
                    BlockHeader { hardfork_version: 16, hardfork_signal: 16, timestamp: 1, previous: [9; 32], nonce: 0 },
                    Transaction::V1 {
                        prefix: TransactionPrefix { additional_timelock: Timelock::None, inputs: vec![Input::Gen(height)], outputs: vec![], extra: vec![] },
                        signatures: vec![],
                    },
                    if height == 8 { vec![tx_hash] } else { vec![] },
                ).unwrap();
                Json(json!({"id": request["id"], "result": {"blob": hex::encode(block.serialize())}}))
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let daemon =
            monero_simple_request_rpc::SimpleRequestTransport::new(format!("http://{address}"))
                .await
                .unwrap();
        let (_, _, mining_address) =
            super::acceptance_funding_wallet(monero_wallet::address::Network::Mainnet).unwrap();
        let result = super::mine_confirmation(&daemon, &mining_address, tx_hash, 6, 1, 0).await;
        server.abort();
        let block = result.unwrap();
        assert_eq!(block.number(), 8, "confirmation must use the containing height, not tip 10");
        assert_eq!(block.transactions, vec![tx_hash]);
    }

    use super::{
        AcceptanceDepositFaultMode, AcceptanceProtocolFaultBoundary,
        AcceptanceProtocolFaultSpecification, CertifiedDeposit, DEPOSIT_HANDOFF_ACCEPTANCE_WINDOWS,
        DepositHttpStatus, DepositTtlAllocationFacts, ObservedConsolidation, PartyId,
        ValidatedDepositAllocationResponse, acceptance_avss_transition_digest,
        allocation_request_parties, assign_certified_input_ring,
        certified_deposit_candidate_quorum, deposit_fault_confirmation_plan,
        deposit_handoff_acceptance_timeout, deposit_status_reached_current_epoch,
        deterministic_roast_signers, equal_observation_quorum, parse_acceptance_deposit_fault_mode,
        parse_acceptance_protocol_fault_specification, record_equal_observation,
        successor_acceptance_funding_height, tenant_bound_request_binding,
        tenant_certified_request_id, validate_consolidation_fixture_economics,
        validate_cross_epoch_subthreshold_non_identifiability,
        validate_deposit_ttl_acceptance_facts, validate_dynamic_refresh,
        validate_exact_same_committee_refresh, validate_new_deposit_certificate,
        validate_ttl_replica_response,
    };
    use crate::{
        committee::{Committee, Member, SessionId},
        compact_epoch_registry::{
            CompactEpochRegistry, IssuerTerminalSeal, RegistryLink, VerifiedIssuerWindow,
        },
        compact_registry_archive::prepare_compact_registry_genesis,
        config::{NetworkKind, Scenario},
        deposit_consolidation::{ConsolidationId, OpaqueIntentBinding, SignedTransactionBinding},
        deposit_ledger::{
            CertifiedLedgerEntry, LedgerRequestId, LedgerStatement, RequestBinding,
            UNUSED_ALLOCATION_TTL_SECONDS,
        },
        deposit_service::{
            DepositAddressRequest, PublicConsolidationPhase, PublicConsolidationStatus,
            PublicLiveConsolidationStatus,
        },
        deposit_wallet::{
            ChainPoint, DepositAddressDeriver, DepositSubaddressIndex, DepositWalletId, SweepId,
            WalletOutputId, derive_sweep_signing_session,
        },
        deposit_worker::SweepPlan,
        epoch_history::EpochHistoryParent,
        identity::Identity,
        key_rotation::VerifiedRegistryHandoffTarget,
        keys::{EpochPublic, PointBytes, scalar_for_party},
        server::{
            AvssTransition, DealPurpose, DepositHttpResponse, canonical_refresh_session,
            canonical_reshare_session,
        },
    };
    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};
    use std::collections::{BTreeMap, BTreeSet};
    use zeroize::Zeroizing;

    #[test]
    fn deposit_allocation_budget_covers_failover_checkpoint_and_release() {
        assert_eq!(
            super::deposit_allocation_acceptance_timeout(std::time::Duration::from_secs(180))
                .unwrap(),
            std::time::Duration::from_secs(780)
        );
        assert!(super::deposit_allocation_acceptance_timeout(std::time::Duration::MAX).is_err());
    }

    #[test]
    fn deposit_handoff_budget_covers_each_serial_bft_stage() {
        let protocol_timeout = std::time::Duration::from_secs(180);
        assert_eq!(DEPOSIT_HANDOFF_ACCEPTANCE_WINDOWS, 4);
        assert_eq!(
            deposit_handoff_acceptance_timeout(protocol_timeout).unwrap(),
            std::time::Duration::from_secs(720)
        );
        assert!(deposit_handoff_acceptance_timeout(std::time::Duration::MAX).is_err());
    }

    #[test]
    fn exact_observation_quorum_ignores_a_conflicting_first_response() {
        let mut groups = Vec::new();
        record_equal_observation(&mut groups, PartyId(1), 1_u8);
        for party in 2_u16..=5 {
            record_equal_observation(&mut groups, PartyId(party), 2_u8);
        }

        let required_parties = BTreeSet::from([PartyId(2)]);
        let quorum = equal_observation_quorum(&groups, 4, &required_parties).unwrap().unwrap();
        assert_eq!(quorum.value, 2);
        assert_eq!(quorum.parties, (2_u16..=5).map(PartyId).collect::<BTreeSet<_>>());

        // Re-observing one identity under the honest value cannot count that identity in both
        // groups, and the required-party predicate is additive to the numeric quorum.
        let required_parties = BTreeSet::from([PartyId(1)]);
        assert!(equal_observation_quorum(&groups, 4, &required_parties).unwrap().is_none());
        record_equal_observation(&mut groups, PartyId(1), 2_u8);
        let quorum = equal_observation_quorum(&groups, 4, &required_parties).unwrap().unwrap();
        assert_eq!(quorum.parties.len(), 5);
        assert_eq!(groups.iter().filter(|group| group.parties.contains(&PartyId(1))).count(), 1);
    }

    #[test]
    fn exact_observation_quorum_rejects_two_conflicting_quorums() {
        let mut groups = Vec::new();
        record_equal_observation(&mut groups, PartyId(1), 1_u8);
        record_equal_observation(&mut groups, PartyId(2), 1_u8);
        record_equal_observation(&mut groups, PartyId(3), 2_u8);
        record_equal_observation(&mut groups, PartyId(4), 2_u8);

        assert!(
            equal_observation_quorum(&groups, 2, &BTreeSet::new()).is_err(),
            "the selector must never anchor on the first of two conflicting quorums"
        );
    }

    fn observed_consolidation_decision_fixture() -> ObservedConsolidation {
        let wallet = DepositWalletId([0x11; 32]);
        let sweep = SweepId([0x12; 32]);
        let session = SessionId([0x13; 32]);
        let plan = SweepPlan {
            id: sweep,
            wallet,
            sequence: 7,
            epoch: 0,
            destination_binding: [0x14; 32],
            at_tip: ChainPoint::new(101, [0x15; 32]).unwrap(),
            inputs: vec![WalletOutputId { transaction: [0x16; 32], index_in_transaction: 0 }],
            total_input_atomic_units: 12_000_000_000,
        };
        let signed = SignedTransactionBinding {
            authorization: [0x17; 32],
            attempt: 1,
            attempt_binding: [0x18; 32],
            session,
            signing_context: [0x19; 32],
            opaque_intent: OpaqueIntentBinding([0x1a; 32]),
            transaction: [0x1b; 32],
            exact_bytes: [0x1c; 32],
            exact_bytes_len: 2_167,
        };
        ObservedConsolidation(PublicConsolidationStatus {
            portable: None,
            live: Some(PublicLiveConsolidationStatus {
                authorization: ConsolidationId([0x1d; 32]),
                sweep,
                plan,
                signed: Some(signed),
                certificate_digest: Some([0x1e; 32]),
                phase: PublicConsolidationPhase::Broadcast,
                destination_binding: [0x14; 32],
                confirmation: None,
                bootstrap_ba_view: 0,
                bootstrap_ba_proposer: PartyId(2),
                bootstrap_prepared_intent_digest: [0x1f; 32],
                bootstrap_certificate_digest: [0x20; 32],
                bootstrap_certificate_signers: vec![PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
                roast_view: 0,
                roast_relay_seed: PartyId(1),
                roast_signers: vec![PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
                roast_view_count: 1,
                roast_candidate_count: 1,
                roast_endorsed_candidate_count: 1,
                roast_intent_certificate_digest: [0x20; 32],
                roast_intent_certificate_signers: vec![
                    PartyId(1),
                    PartyId(2),
                    PartyId(3),
                    PartyId(4),
                ],
                roast_attempt_binding_digest: [0x18; 32],
                roast_endorsed_witness_count: 2,
                roast_endorsed_evidence_digest: [0x21; 32],
                completion_certificate_signers: vec![
                    PartyId(1),
                    PartyId(2),
                    PartyId(3),
                    PartyId(4),
                ],
                key_image_binding_digest: [0x22; 32],
                key_image_unsigned_transaction_digest: [0x23; 32],
                key_image_preprocess_set_digest: [0x24; 32],
                key_image_authorizers: vec![PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
                key_image_authorization_quorum: 4,
            }),
        })
    }

    #[test]
    fn consolidation_quorum_ignores_valid_witness_subset_and_diagnostic_supersets() {
        let expected = observed_consolidation_decision_fixture();
        let mut alternate = expected.clone();
        let live = alternate.0.live.as_mut().unwrap();
        live.bootstrap_ba_view = 3;
        live.bootstrap_ba_proposer = PartyId(5);
        live.bootstrap_certificate_signers = vec![PartyId(1), PartyId(2), PartyId(3), PartyId(5)];
        live.roast_intent_certificate_signers =
            vec![PartyId(1), PartyId(3), PartyId(4), PartyId(5)];
        live.completion_certificate_signers = vec![PartyId(2), PartyId(3), PartyId(4), PartyId(5)];
        live.roast_candidate_count = 3;
        live.roast_endorsed_candidate_count = 2;
        live.roast_endorsed_witness_count = 4;
        live.roast_endorsed_evidence_digest = [0x25; 32];
        assert!(expected.same_quorum_decision(&alternate));

        alternate.0.live.as_mut().unwrap().roast_attempt_binding_digest = [0x26; 32];
        assert!(!expected.same_quorum_decision(&alternate));
    }

    fn deposit_ttl_facts_fixture()
    -> ([u64; 6], DepositTtlAllocationFacts, DepositTtlAllocationFacts, DepositTtlAllocationFacts)
    {
        const TTL: u64 = crate::deposit_ledger::UNUSED_ALLOCATION_TTL_SECONDS;
        let bootstrap = 1_700_000_000;
        let unused_visible = bootstrap + 60;
        let permanent_visible = unused_visible + 60;
        let unused_expired = unused_visible + TTL;
        let permanent_expired = permanent_visible + TTL;
        (
            [
                bootstrap,
                unused_visible,
                permanent_visible,
                unused_expired - 1,
                unused_expired,
                permanent_expired,
            ],
            DepositTtlAllocationFacts {
                request: [1; 32],
                sequence: 1,
                account: 0,
                address_index: 1,
                address: "unused".to_owned(),
                created_at: unused_visible,
                expires_at: unused_expired,
                statement: [11; 32],
            },
            DepositTtlAllocationFacts {
                request: [2; 32],
                sequence: 2,
                account: 0,
                address_index: 2,
                address: "permanent".to_owned(),
                created_at: permanent_visible,
                expires_at: permanent_expired,
                statement: [12; 32],
            },
            DepositTtlAllocationFacts {
                request: [3; 32],
                sequence: 3,
                account: 0,
                address_index: 3,
                address: "replacement".to_owned(),
                created_at: permanent_expired,
                expires_at: permanent_expired + TTL,
                statement: [13; 32],
            },
        )
    }

    #[test]
    fn deposit_ttl_acceptance_facts_require_exact_boundaries_and_non_reuse() {
        let (clock, unused, permanent, replacement) = deposit_ttl_facts_fixture();
        validate_deposit_ttl_acceptance_facts(clock, &unused, &permanent, &replacement).unwrap();
    }

    #[test]
    fn deposit_ttl_acceptance_facts_reject_an_off_by_one_expiry_boundary() {
        let (mut clock, unused, permanent, replacement) = deposit_ttl_facts_fixture();
        clock[3] -= 1;
        assert!(
            validate_deposit_ttl_acceptance_facts(clock, &unused, &permanent, &replacement)
                .is_err()
        );
    }

    #[test]
    fn deposit_ttl_acceptance_facts_reject_reused_or_non_monotonic_allocations() {
        let (clock, unused, permanent, mut replacement) = deposit_ttl_facts_fixture();
        replacement.address = unused.address.clone();
        assert!(
            validate_deposit_ttl_acceptance_facts(clock, &unused, &permanent, &replacement)
                .is_err()
        );

        let (clock, unused, permanent, mut replacement) = deposit_ttl_facts_fixture();
        replacement.sequence = permanent.sequence;
        assert!(
            validate_deposit_ttl_acceptance_facts(clock, &unused, &permanent, &replacement)
                .is_err()
        );
    }

    fn certified_deposit_status_fixture()
    -> (EpochPublic, CertifiedDeposit, CompactEpochRegistry, DepositHttpResponse) {
        let identities = (1_u16..=4)
            .map(|party| {
                let id = PartyId(party);
                let mut encryption_secret = [0x58; 32];
                encryption_secret[1] = u8::try_from(party).unwrap();
                let identity = Identity::from_test_secrets(
                    id,
                    0,
                    &[u8::try_from(party).unwrap(); 32],
                    encryption_secret,
                )
                .unwrap();
                (id, identity)
            })
            .collect::<BTreeMap<_, _>>();
        let committee = Committee {
            epoch: 0,
            threshold: 2,
            members: identities
                .values()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        }
        .canonicalized()
        .unwrap();
        committee.validate_async_security_with_faults(1).unwrap();

        let root_spend_key = (ED25519_BASEPOINT_POINT * Scalar::from(42_u64)).compress().to_bytes();
        let deriver = DepositAddressDeriver::new(
            crate::config::NetworkKind::Regtest,
            root_spend_key,
            &Zeroizing::new(Scalar::from(17_u64).to_bytes()),
        )
        .unwrap();
        let index = DepositSubaddressIndex::new(0, 1).unwrap();
        let public = polynomial_public_with_coefficients(committee.clone(), [0xd2; 32], &[42, 7]);
        let activation = public.activation_digest().unwrap();
        let registry_for_authority = |activation, certified_root| {
            let target = VerifiedRegistryHandoffTarget::for_test(
                committee.clone(),
                1,
                activation,
                certified_root,
                deriver.wallet_id(),
                public.key_id,
                public.group_key_bytes(),
            )
            .unwrap();
            let registry = prepare_compact_registry_genesis(&target, index, [0x44; 32])
                .unwrap()
                .proposed_head()
                .registry()
                .clone();
            let link = RegistryLink::genesis(&target, index, [0x44; 32]).unwrap();
            let issuer =
                VerifiedIssuerWindow::from_links(&link, registry.id().index_root(), None).unwrap();
            (registry, issuer)
        };
        let (registry, issuer) = registry_for_authority(activation, [0xd1; 32]);
        let (alternate_registry, alternate_issuer) = registry_for_authority(activation, [0xd4; 32]);
        let (conflicting_registry, _) = registry_for_authority([0xee; 32], [0xd5; 32]);

        let request = DepositAddressRequest {
            request: LedgerRequestId([0x61; 32]),
            binding: RequestBinding([0x62; 32]),
        };
        let certified_request = tenant_certified_request_id(request);
        let address = deriver.derive(index);
        let created_at = 1_700_000_000;
        let statement = LedgerStatement::allocation(
            &registry,
            registry.active().start_sequence(),
            registry.active().predecessor_ledger_head(),
            certified_request,
            tenant_bound_request_binding(request),
            address.clone(),
            ChainPoint::new(100, [0x63; 32]).unwrap(),
            created_at,
        )
        .unwrap();
        let payload = statement.attestation_payload().unwrap();
        let attestations = identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        &committee,
                        statement.slot_session(),
                        None,
                        statement.sequence,
                        payload.clone(),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let certificate = CertifiedLedgerEntry { statement, attestations };
        certificate.verify_active(&registry, None).unwrap();
        let response = DepositHttpResponse {
            request: request.request,
            certified_request,
            status: DepositHttpStatus::Active,
            address: Some(address),
            certificate: Some(certificate),
            allocation_issuer: Some(issuer.clone()),
            serving_registry: registry.clone(),
            created_at: Some(created_at),
            expires_at: Some(created_at + UNUSED_ALLOCATION_TTL_SECONDS),
            leader: PartyId(1),
        };
        let mut alternate_response = response.clone();
        alternate_response.serving_registry = alternate_registry;
        alternate_response.allocation_issuer = Some(alternate_issuer);
        (
            public,
            CertifiedDeposit {
                request,
                response,
                allocation_issuer: issuer.issuer().clone(),
                funded_outputs: Vec::new(),
            },
            conflicting_registry,
            alternate_response,
        )
    }

    #[test]
    fn deposit_allocation_quorum_ignores_a_valid_alternate_root_first() {
        let (public, deposit, _, alternate_response) = certified_deposit_status_fixture();
        let canonical = validate_new_deposit_certificate(
            NetworkKind::Regtest,
            &public,
            1,
            deposit.request,
            &deposit.response,
        )
        .unwrap();
        let alternate = validate_new_deposit_certificate(
            NetworkKind::Regtest,
            &public,
            1,
            deposit.request,
            &alternate_response,
        )
        .unwrap();
        assert_eq!(canonical.statement, alternate.statement);
        assert_ne!(canonical, alternate);

        let mut groups = Vec::new();
        let mut responses = BTreeMap::new();
        record_equal_observation(&mut groups, PartyId(1), alternate.clone());
        responses.insert(
            PartyId(1),
            ValidatedDepositAllocationResponse {
                candidate: alternate,
                response: alternate_response,
            },
        );
        for party in 2_u16..=4 {
            let party = PartyId(party);
            let mut response = deposit.response.clone();
            response.leader = party;
            record_equal_observation(&mut groups, party, canonical.clone());
            responses.insert(
                party,
                ValidatedDepositAllocationResponse { candidate: canonical.clone(), response },
            );
        }

        let (selected, replicas) = certified_deposit_candidate_quorum(
            deposit.request,
            &groups,
            &responses,
            3,
            &BTreeSet::new(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(replicas, vec![PartyId(2), PartyId(3), PartyId(4)]);
        assert_eq!(selected.response.serving_registry, deposit.response.serving_registry);
        assert_eq!(selected.response.certificate, deposit.response.certificate);
    }

    #[test]
    fn current_active_status_rejects_a_terminal_issuer_window() {
        let (public, deposit, _, _) = certified_deposit_status_fixture();
        let mut response = deposit.response.clone();
        let certificate = response.certificate.as_ref().unwrap();
        let issuer = response.allocation_issuer.as_ref().unwrap();
        let terminal = IssuerTerminalSeal {
            sequence: certificate.statement.sequence,
            statement_digest: certificate.statement.digest(),
            successor_epoch: issuer.issuer().epoch().checked_add(1).unwrap(),
        };
        let mut encoded = serde_json::to_value(issuer).unwrap();
        encoded["terminal"] = serde_json::to_value(terminal).unwrap();
        let terminal_issuer: VerifiedIssuerWindow = serde_json::from_value(encoded).unwrap();
        terminal_issuer.validate().unwrap();
        certificate.verify(&terminal_issuer, None).unwrap();
        response.allocation_issuer = Some(terminal_issuer);

        assert!(
            validate_new_deposit_certificate(
                NetworkKind::Regtest,
                &public,
                1,
                deposit.request,
                &response,
            )
            .is_err()
        );
        assert!(
            validate_ttl_replica_response(
                &public,
                1,
                PartyId(2),
                &deposit,
                DepositHttpStatus::Active,
                &response,
            )
            .is_err()
        );
    }

    #[test]
    fn expired_status_rejects_a_corrupt_retained_certificate() {
        let (public, mut deposit, _, _) = certified_deposit_status_fixture();
        deposit.response.certificate.as_mut().unwrap().statement.sequence += 1;
        let mut expired = deposit.response.clone();
        expired.status = DepositHttpStatus::Expired;
        expired.address = None;
        expired.certificate = None;

        assert!(
            validate_ttl_replica_response(
                &public,
                1,
                PartyId(2),
                &deposit,
                DepositHttpStatus::Expired,
                &expired,
            )
            .is_err()
        );
    }

    #[test]
    fn certified_status_accepts_consensus_view_changes_between_committee_members() {
        let (public, deposit, _, _) = certified_deposit_status_fixture();

        let mut active = deposit.response.clone();
        active.leader = PartyId(2);
        validate_ttl_replica_response(
            &public,
            1,
            PartyId(3),
            &deposit,
            DepositHttpStatus::Active,
            &active,
        )
        .unwrap();

        let mut permanent = active.clone();
        permanent.status = DepositHttpStatus::Permanent;
        validate_ttl_replica_response(
            &public,
            1,
            PartyId(3),
            &deposit,
            DepositHttpStatus::Permanent,
            &permanent,
        )
        .unwrap();

        let mut expired = active;
        expired.status = DepositHttpStatus::Expired;
        expired.address = None;
        expired.certificate = None;
        validate_ttl_replica_response(
            &public,
            1,
            PartyId(3),
            &deposit,
            DepositHttpStatus::Expired,
            &expired,
        )
        .unwrap();
    }

    #[test]
    fn certified_status_rejects_non_member_leaders_and_conflicting_authority() {
        let (public, deposit, conflicting_registry, _) = certified_deposit_status_fixture();

        let mut non_member = deposit.response.clone();
        non_member.leader = PartyId(9);
        assert!(
            validate_ttl_replica_response(
                &public,
                1,
                PartyId(3),
                &deposit,
                DepositHttpStatus::Active,
                &non_member,
            )
            .is_err()
        );

        let mut wrong_registry = deposit.response.clone();
        wrong_registry.leader = PartyId(2);
        wrong_registry.serving_registry = conflicting_registry;
        assert!(
            validate_ttl_replica_response(
                &public,
                1,
                PartyId(3),
                &deposit,
                DepositHttpStatus::Active,
                &wrong_registry,
            )
            .is_err()
        );

        let mut wrong_certificate = deposit.response.clone();
        wrong_certificate.leader = PartyId(2);
        wrong_certificate.certificate.as_mut().unwrap().statement.sequence += 1;
        assert!(
            validate_ttl_replica_response(
                &public,
                1,
                PartyId(3),
                &deposit,
                DepositHttpStatus::Active,
                &wrong_certificate,
            )
            .is_err()
        );
    }

    fn polynomial_public_with_coefficients(
        committee: Committee,
        key_id: [u8; 32],
        coefficients: &[u64],
    ) -> EpochPublic {
        assert_eq!(coefficients.len(), usize::from(committee.threshold));
        let coefficients = coefficients.iter().copied().map(Scalar::from).collect::<Vec<_>>();
        let verification_shares = committee
            .members
            .iter()
            .map(|member| {
                let x = scalar_for_party(&committee, member.id).unwrap();
                let evaluation = coefficients
                    .iter()
                    .rev()
                    .fold(Scalar::ZERO, |evaluation, coefficient| (evaluation * x) + coefficient);
                (member.id, PointBytes::from(ED25519_BASEPOINT_POINT * evaluation))
            })
            .collect::<BTreeMap<_, _>>();
        let public = EpochPublic {
            key_id,
            committee,
            verification_shares,
            group_key: PointBytes::from(ED25519_BASEPOINT_POINT * coefficients[0]),
        };
        public.validate().unwrap();
        public
    }

    fn configured_shape(scenario: &Scenario, epoch: u64) -> Committee {
        let spec = scenario.committee_spec(epoch).unwrap();
        Committee {
            epoch,
            threshold: spec.threshold,
            members: spec
                .members
                .iter()
                .map(|party| {
                    let configured = scenario.party(*party).unwrap();
                    crate::committee::Member {
                        id: *party,
                        signing_key: configured.signing_key.0,
                        encryption_key: configured.bootstrap_encryption_key.0,
                    }
                })
                .collect(),
        }
        .canonicalized()
        .unwrap()
    }

    fn dynamic_refresh_fixture(rotated_members: usize) -> (EpochPublic, EpochPublic) {
        let scenario: Scenario =
            serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
        let source = polynomial_public_with_coefficients(
            configured_shape(&scenario, 4),
            [0x5a; 32],
            &[11, 17, 19],
        );
        let mut target = source.committee.clone();
        target.epoch = 5;
        for member in target.members.iter_mut().take(rotated_members) {
            let signing_seed = [u8::try_from(member.id.0).unwrap(); 32];
            let x25519_secret = [0x80_u8.wrapping_add(u8::try_from(member.id.0).unwrap()); 32];
            let rotated =
                Identity::from_test_secrets(member.id, 5, &signing_seed, x25519_secret).unwrap();
            member.encryption_key = rotated.encryption_public_key();
        }
        let refreshed = polynomial_public_with_coefficients(target, source.key_id, &[11, 23, 29]);
        (source, refreshed)
    }

    #[test]
    fn regtest_fixture_uses_separate_signing_and_bootstrap_x25519_secrets() {
        let scenario: Scenario =
            serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
        scenario.validate().unwrap();
        assert_eq!(scenario.committees.len(), 5);
        assert_eq!(scenario.proactive_refresh_interval_seconds, 15);
        let refresh_source = scenario.committee_spec(1).unwrap();
        let refresh_target = scenario.committee_spec(2).unwrap();
        assert_eq!(refresh_source.threshold, 4);
        assert_eq!(refresh_source.fault_bound, 1);
        assert_eq!(refresh_source.members, refresh_target.members);
        assert_eq!(refresh_source.eligible_members, refresh_target.eligible_members);
        assert_eq!(
            refresh_target.eligible_members.len(),
            refresh_target.members.len() + usize::from(refresh_target.fault_bound)
        );

        let signing_seeds = [
            include_str!("../docker/demo-secrets/p1-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p2-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p3-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p4-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p5-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p6-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p7-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p8-signing-seed.hex"),
        ];
        let bootstrap_x25519_secrets = [
            include_str!("../docker/demo-secrets/p1-bootstrap-x25519-secret.hex"),
            include_str!("../docker/demo-secrets/p2-bootstrap-x25519-secret.hex"),
            include_str!("../docker/demo-secrets/p3-bootstrap-x25519-secret.hex"),
            include_str!("../docker/demo-secrets/p4-bootstrap-x25519-secret.hex"),
            include_str!("../docker/demo-secrets/p5-bootstrap-x25519-secret.hex"),
        ];
        for (index, encoded_signing_seed) in signing_seeds.into_iter().enumerate() {
            let party_id = PartyId(u16::try_from(index + 1).unwrap());
            let signing_seed: [u8; 32] =
                hex::decode(encoded_signing_seed.trim()).unwrap().try_into().unwrap();
            let party = scenario.party(party_id).unwrap();
            assert_eq!(
                Identity::signing_public_key_from_seed(&signing_seed).unwrap(),
                party.signing_key.0
            );
        }
        let mut provisioned_bootstrap_keys = BTreeSet::new();
        for (index, encoded_bootstrap_secret) in bootstrap_x25519_secrets.into_iter().enumerate() {
            let party_id = PartyId(u16::try_from(index + 1).unwrap());
            let bootstrap_secret: [u8; 32] =
                hex::decode(encoded_bootstrap_secret.trim()).unwrap().try_into().unwrap();
            let party = scenario.party(party_id).unwrap();
            let bootstrap_public =
                x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bootstrap_secret))
                    .to_bytes();
            assert_eq!(bootstrap_public, party.bootstrap_encryption_key.0);
            assert!(provisioned_bootstrap_keys.insert(bootstrap_public));
        }
        for party_id in (6_u16..=8).map(PartyId) {
            let sentinel = scenario.party(party_id).unwrap().bootstrap_encryption_key.0;
            assert_ne!(sentinel, [0; 32]);
            assert!(
                !provisioned_bootstrap_keys.contains(&sentinel),
                "post-genesis party {party_id} unexpectedly has a provisioned bootstrap secret"
            );
        }

        let genesis = scenario.genesis_committee().unwrap();
        let grow = scenario
            .configured_key_rotation_target_shape(&genesis)
            .unwrap()
            .expect("configured grow");
        assert_eq!(grow.eligible().epoch, 1);
        assert_eq!(grow.eligible().threshold, 4);
        assert_eq!(grow.desired_n(), 7);
        // Eligible members carry a publicly derivable eligibility-reference key rather than any
        // real encryption key: the target policy overwrites every X25519 byte with a deterministic
        // domain separator that can never be used for encryption or become a successor key. Confirm
        // the added parties expose exactly that reference and that it is distinct from their real
        // bootstrap encryption key.
        for party in [PartyId(6), PartyId(7)] {
            let signing_key = scenario.party(party).unwrap().signing_key.0;
            let reference = crate::key_rotation::eligibility_reference_key(1, party, signing_key);
            assert_eq!(grow.eligible().member(party).unwrap().encryption_key, reference);
            assert_ne!(reference, scenario.party(party).unwrap().bootstrap_encryption_key.0);
        }

        let shrink = scenario
            .configured_key_rotation_target_shape(&configured_shape(&scenario, 3))
            .unwrap()
            .expect("configured shrink");
        assert_eq!(shrink.eligible().threshold, 3);
        assert_eq!(shrink.desired_n(), 5);
        assert_eq!(
            shrink.eligible().members.iter().map(|member| member.id).collect::<Vec<_>>(),
            [2_u16, 3, 4, 6, 7, 8].into_iter().map(PartyId).collect::<Vec<_>>()
        );
    }

    #[test]
    fn dynamic_refresh_accepts_an_exact_fresh_selected_committee_and_polynomial() {
        let scenario: Scenario =
            serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
        let (source, refreshed) = dynamic_refresh_fixture(5);
        assert_eq!(validate_dynamic_refresh(&scenario, &source, &refreshed, 1).unwrap(), 5);
        let evidence =
            validate_cross_epoch_subthreshold_non_identifiability(&source, &refreshed).unwrap();
        assert_eq!(evidence.mixed_sets, 225);
        assert_eq!(evidence.threshold_boundary_sets, 20);
    }

    #[test]
    fn exact_refresh_evidence_authenticates_refresh_and_rejects_reshare_purpose() {
        let (source, refreshed) = dynamic_refresh_fixture(5);
        let history_parent =
            EpochHistoryParent::genesis([0x71; 32], source.key_id).expect("history parent");
        let dealers = source.committee.members.iter().map(|member| member.id).collect::<Vec<_>>();
        let refresh = AvssTransition {
            purpose: DealPurpose::Refresh,
            session: canonical_refresh_session(&source, &refreshed.committee, history_parent)
                .unwrap(),
            key_id: source.key_id,
            fault_bound: 1,
            history_parent,
            old: Some(source.clone()),
            target: refreshed.committee.clone(),
            eligible_dealers: dealers,
        };
        let refresh_digest = acceptance_avss_transition_digest(&refresh).unwrap();
        let evidence = validate_exact_same_committee_refresh(
            &source,
            &refreshed,
            1,
            history_parent,
            refresh_digest,
        )
        .unwrap();
        assert_eq!(
            evidence.members,
            source.committee.members.iter().map(|member| member.id).collect::<Vec<_>>()
        );
        assert_ne!(evidence.source_verification_shares, evidence.target_verification_shares);
        assert_eq!(evidence.refresh_transition_digest, refresh_digest);
        assert_ne!(evidence.refresh_transition_digest, evidence.reshare_transition_digest);

        let mut reshare = refresh;
        reshare.purpose = DealPurpose::Reshare;
        reshare.session =
            canonical_reshare_session(&source, &refreshed.committee, history_parent).unwrap();
        let reshare_digest = acceptance_avss_transition_digest(&reshare).unwrap();
        assert_eq!(evidence.reshare_transition_digest, reshare_digest);
        let error = validate_exact_same_committee_refresh(
            &source,
            &refreshed,
            1,
            history_parent,
            reshare_digest,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not bind the expected zero-constant refresh"), "{error}");
    }

    #[test]
    fn cross_epoch_model_covers_added_and_removed_parties_at_native_coordinates() {
        let scenario: Scenario =
            serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
        let key_id = [0x6b; 32];

        let before_grow = polynomial_public_with_coefficients(
            configured_shape(&scenario, 0),
            key_id,
            &[11, 17, 19],
        );
        let after_grow = polynomial_public_with_coefficients(
            configured_shape(&scenario, 1),
            key_id,
            &[11, 23, 29, 31],
        );
        let grow = validate_cross_epoch_subthreshold_non_identifiability(&before_grow, &after_grow)
            .unwrap();
        assert_eq!(grow.mixed_sets, 945);
        assert_eq!(grow.threshold_boundary_sets, 45);
        for added in [PartyId(6), PartyId(7)] {
            assert!(before_grow.committee.member(added).is_err());
            assert!(after_grow.committee.member(added).is_ok());
        }

        let before_shrink = polynomial_public_with_coefficients(
            configured_shape(&scenario, 3),
            key_id,
            &[11, 17, 19, 23],
        );
        let after_shrink = polynomial_public_with_coefficients(
            configured_shape(&scenario, 4),
            key_id,
            &[11, 29, 31],
        );
        assert_eq!(before_shrink.committee.frost_index(PartyId(2)).unwrap(), 2);
        assert_eq!(after_shrink.committee.frost_index(PartyId(2)).unwrap(), 1);
        for removed in [PartyId(1), PartyId(5)] {
            assert!(before_shrink.committee.member(removed).is_ok());
            assert!(after_shrink.committee.member(removed).is_err());
        }
        assert!(after_shrink.committee.member(PartyId(3)).is_ok());
        let shrink =
            validate_cross_epoch_subthreshold_non_identifiability(&before_shrink, &after_shrink)
                .unwrap();
        assert_eq!(shrink.mixed_sets, 945);
        assert_eq!(shrink.threshold_boundary_sets, 45);
    }

    #[test]
    fn dynamic_refresh_rejects_too_few_rotated_encryption_keys() {
        let scenario: Scenario =
            serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
        let (source, refreshed) = dynamic_refresh_fixture(2);
        let error =
            validate_dynamic_refresh(&scenario, &source, &refreshed, 1).unwrap_err().to_string();
        assert!(error.contains("reused a source receiver key"), "{error}");
    }

    #[test]
    fn dynamic_refresh_rejects_reused_share_polynomial() {
        let scenario: Scenario =
            serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
        let (source, mut refreshed) = dynamic_refresh_fixture(5);
        refreshed.verification_shares.clone_from(&source.verification_shares);
        refreshed.group_key = source.group_key;
        refreshed.validate().unwrap();
        let error =
            validate_dynamic_refresh(&scenario, &source, &refreshed, 1).unwrap_err().to_string();
        assert!(error.contains("reused the source verification-share polynomial"), "{error}");
    }

    #[test]
    fn dynamic_refresh_rejects_non_immediate_epoch_and_signing_key_change() {
        let scenario: Scenario =
            serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
        let (source, mut skipped) = dynamic_refresh_fixture(5);
        skipped.committee.epoch = 6;
        let error =
            validate_dynamic_refresh(&scenario, &source, &skipped, 1).unwrap_err().to_string();
        assert!(error.contains("must activate immediate epoch 5"), "{error}");

        let (_, mut changed_identity) = dynamic_refresh_fixture(5);
        changed_identity.committee.members[0].signing_key = [0xee; 32];
        changed_identity.validate().unwrap();
        let error = validate_dynamic_refresh(&scenario, &source, &changed_identity, 1)
            .unwrap_err()
            .to_string();
        assert!(error.contains("stable signing key"), "{error}");
    }

    #[test]
    fn protocol_fault_gate_requires_an_exact_boundary_and_party() {
        assert_eq!(parse_acceptance_protocol_fault_specification(None).unwrap(), None);
        assert_eq!(
            parse_acceptance_protocol_fault_specification(Some("0:dealer_started:3")).unwrap(),
            Some(AcceptanceProtocolFaultSpecification {
                epoch: 0,
                boundary: AcceptanceProtocolFaultBoundary::DealerStarted,
                party: PartyId(3),
            })
        );
        assert_eq!(
            parse_acceptance_protocol_fault_specification(Some("0:qual_round_zero:3")).unwrap(),
            Some(AcceptanceProtocolFaultSpecification {
                epoch: 0,
                boundary: AcceptanceProtocolFaultBoundary::QualRoundZero,
                party: PartyId(3),
            })
        );
        assert!(parse_acceptance_protocol_fault_specification(Some("0")).is_err());
        assert!(
            parse_acceptance_protocol_fault_specification(Some("0:future_boundary:3")).is_err()
        );
        assert!(parse_acceptance_protocol_fault_specification(Some("0:dealer_started:0")).is_err());
        assert!(parse_acceptance_protocol_fault_specification(Some("1:dealer_started:3")).is_err());
    }

    #[test]
    fn deposit_checkpoint_fault_premine_is_mode_specific() {
        let checkpoint = parse_acceptance_deposit_fault_mode("deposit_checkpoint").unwrap();
        assert_eq!(checkpoint, AcceptanceDepositFaultMode::DepositCheckpoint);
        assert_eq!(deposit_fault_confirmation_plan(Some(checkpoint), 10).unwrap(), (9, 0));

        let observer = parse_acceptance_deposit_fault_mode("observer_fork").unwrap();
        assert_eq!(observer, AcceptanceDepositFaultMode::ObserverFork);
        assert_eq!(deposit_fault_confirmation_plan(Some(observer), 10).unwrap(), (0, 9));
        assert_eq!(deposit_fault_confirmation_plan(None, 10).unwrap(), (0, 9));
        assert!(deposit_fault_confirmation_plan(Some(checkpoint), 0).is_err());
    }

    #[test]
    fn deposit_fault_mode_rejects_unknown_values() {
        assert!(parse_acceptance_deposit_fault_mode("future_mode").is_err());
        assert!(parse_acceptance_deposit_fault_mode("").is_err());
    }

    #[test]
    fn deposit_request_rotates_over_all_responsive_committee_members() {
        let scenario: Scenario =
            serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
        let committee = scenario.genesis_committee().unwrap();
        assert_eq!(
            allocation_request_parties(&committee, 1, &BTreeSet::new()).unwrap(),
            (1_u16..=5).map(PartyId).collect::<Vec<_>>()
        );
        assert_eq!(
            allocation_request_parties(&committee, 1, &BTreeSet::from([PartyId(1)])).unwrap(),
            vec![PartyId(2), PartyId(3), PartyId(4), PartyId(5)]
        );
        assert!(
            allocation_request_parties(
                &committee,
                1,
                &committee.members.iter().map(|member| member.id).collect(),
            )
            .is_err()
        );
    }

    #[test]
    fn deposit_status_accepts_any_expected_committee_leader_and_rejects_outsiders() {
        let (public, deposit, _, _) = certified_deposit_status_fixture();
        let mut response = deposit.response;
        response.status = DepositHttpStatus::Permanent;
        assert!(deposit_status_reached_current_epoch(
            &response,
            DepositHttpStatus::Permanent,
            &public,
            1,
        ));
        response.leader = PartyId(2);
        assert!(deposit_status_reached_current_epoch(
            &response,
            DepositHttpStatus::Permanent,
            &public,
            1,
        ));
        response.leader = PartyId(9);
        assert!(!deposit_status_reached_current_epoch(
            &response,
            DepositHttpStatus::Permanent,
            &public,
            1,
        ));
        response.leader = PartyId(2);
        response.status = DepositHttpStatus::Active;
        assert!(!deposit_status_reached_current_epoch(
            &response,
            DepositHttpStatus::Permanent,
            &public,
            1,
        ));
    }

    #[test]
    fn overlapping_leader_cannot_make_a_stale_registry_count_as_the_successor_epoch() {
        let (source, deposit, _, _) = certified_deposit_status_fixture();
        let successor_committee = Committee {
            epoch: 1,
            threshold: source.committee.threshold,
            members: source.committee.members.clone(),
        }
        .canonicalized()
        .unwrap();
        let successor =
            polynomial_public_with_coefficients(successor_committee, source.key_id, &[42, 9]);
        assert_eq!(source.group_key_bytes(), successor.group_key_bytes());

        let mut stale = deposit.response;
        stale.status = DepositHttpStatus::Permanent;
        stale.leader = PartyId(1);
        assert!(source.committee.member(stale.leader).is_ok());
        assert!(successor.committee.member(stale.leader).is_ok());
        assert!(!deposit_status_reached_current_epoch(
            &stale,
            DepositHttpStatus::Permanent,
            &successor,
            1,
        ));
    }

    #[test]
    fn consolidation_fixture_requires_value_beyond_fee_payment_and_positive_change() {
        let maximum_fee = 5_000_000_000;
        assert!(validate_consolidation_fixture_economics(maximum_fee + 1, maximum_fee).is_err());
        assert!(validate_consolidation_fixture_economics(maximum_fee + 2, maximum_fee).is_ok());
    }

    #[test]
    fn consolidation_fixture_rejects_policy_sum_overflow() {
        assert!(validate_consolidation_fixture_economics(u64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn regtest_deposit_fixture_has_policy_headroom() {
        assert!(validate_consolidation_fixture_economics(100_000_000_000, 5_000_000_000).is_ok());
    }

    #[test]
    fn certified_outputs_map_bijectively_across_overlapping_input_rings() {
        let first = WalletOutputId { transaction: [1; 32], index_in_transaction: 0 };
        let second = WalletOutputId { transaction: [1; 32], index_in_transaction: 1 };
        let candidates = vec![vec![first, second], vec![second]];
        let mut mapping = BTreeMap::new();
        for ring_position in 0..candidates.len() {
            assert!(assign_certified_input_ring(
                ring_position,
                &candidates,
                &mut BTreeSet::new(),
                &mut mapping,
            ));
        }
        assert_eq!(mapping, BTreeMap::from([(first, 0), (second, 1)]));

        let impossible = vec![vec![first], vec![first]];
        let mut mapping = BTreeMap::new();
        assert!(assign_certified_input_ring(0, &impossible, &mut BTreeSet::new(), &mut mapping,));
        assert!(!assign_certified_input_ring(1, &impossible, &mut BTreeSet::new(), &mut mapping,));
    }

    #[test]
    fn successor_funding_uses_the_five_outputs_after_the_initial_fixture() {
        assert_eq!(successor_acceptance_funding_height(100, 1).unwrap(), 101);
        assert_eq!(successor_acceptance_funding_height(100, 5).unwrap(), 105);
        assert!(successor_acceptance_funding_height(100, 0).is_err());
    }

    #[test]
    fn consolidation_fault_target_is_replaced_by_the_next_lexicographic_roast_subset() {
        let scenario: Scenario =
            serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
        let committee = scenario.genesis_committee().unwrap();
        let first = deterministic_roast_signers(&committee, 1, 0).unwrap();
        let second = deterministic_roast_signers(&committee, 1, 1).unwrap();
        assert_eq!(first, vec![PartyId(1), PartyId(2), PartyId(3), PartyId(4)]);
        assert_eq!(second, vec![PartyId(1), PartyId(2), PartyId(3), PartyId(5)]);
        assert_eq!(
            first.iter().rev().copied().find(|party| !second.contains(party)),
            Some(PartyId(4))
        );
    }

    #[test]
    fn deterministic_roast_subsets_cycle_with_fresh_absolute_attempts() {
        let scenario: Scenario =
            serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
        let committee = scenario.genesis_committee().unwrap();
        let first_cycle = (0_u64..5)
            .map(|view| deterministic_roast_signers(&committee, 1, view).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(first_cycle.len(), 5);
        assert_eq!(
            deterministic_roast_signers(&committee, 1, 5).unwrap(),
            deterministic_roast_signers(&committee, 1, 0).unwrap()
        );

        let first_attempt = 1_u64;
        let cycled_attempt = 6_u64;
        assert_ne!(first_attempt, cycled_attempt);
        let wallet = DepositWalletId([0x41; 32]);
        let sweep = SweepId([0x42; 32]);
        assert_ne!(
            derive_sweep_signing_session(wallet, sweep, first_attempt).unwrap(),
            derive_sweep_signing_session(wallet, sweep, cycled_attempt).unwrap(),
        );
    }
}
