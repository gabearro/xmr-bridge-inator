//! Docker/regtest acceptance runner.

use std::collections::{BTreeMap, BTreeSet};

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
    committee::{Committee, PartyId, SessionId},
    compact_epoch_registry::CompactEpochRegistry,
    config::{NetworkKind, Scenario},
    deposit_consolidation::{ConsolidationId, consolidation_signed_bytes_binding},
    deposit_ledger::{
        CertifiedLedgerEntry, LedgerPayload, LedgerRequestId, RequestBinding,
        UNUSED_ALLOCATION_TTL_SECONDS,
    },
    deposit_service::{
        DepositAddressRequest, PublicConsolidationPhase, PublicConsolidationStatus,
        deposit_request_id_for_binding,
    },
    deposit_wallet::{ChainPoint, DepositAddressDeriver, SweepId, WalletOutputId},
    deposit_worker::{DepositWorkerConfig, root_consolidation_destination_binding},
    epoch_history::EpochHistoryParent,
    keys::EpochPublic,
    server::{
        AcceptanceProactiveRefreshReleaseRequest, AcceptanceProactiveRefreshReleaseResponse,
        AvssStartRequest, AvssStepResponse, AvssTransition, DealPurpose,
        DepositConsolidationStatusResponse, DepositHttpResponse, DepositHttpStatus, PartyStatus,
    },
};

const CONSOLIDATION_PRIMARY_OUTPUT_ATOMIC_UNITS: u64 = 1;
const REQUIRED_ACCEPTANCE_FUNDING_OUTPUTS: u64 = 6;

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AcceptanceDriverLatchKind {
    ObserverFork,
    DynamicRotationOmission,
    ProactiveDeadline,
}

impl AcceptanceDriverLatchKind {
    const fn marker(self) -> &'static str {
        match self {
            Self::ObserverFork => "observer_fork",
            Self::DynamicRotationOmission => "dynamic_rotation_omission",
            Self::ProactiveDeadline => "proactive_deadline",
        }
    }
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
            http: reqwest::Client::builder().timeout(timeout).build()?,
            admin_endpoints,
            admin_authorizations,
            deposit_authorizations,
            poll_interval: std::time::Duration::from_millis(scenario.poll_interval_ms),
            protocol_timeout: timeout,
            network_id: scenario.quic_network_id()?,
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
        let authorization = self
            .admin_authorizations
            .get(&party)
            .with_context(|| format!("missing admin credential for party {party}"))?;
        self.post_authenticated(party, path, request, authorization).await
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
    issuer_registry: CompactEpochRegistry,
    funded_output: Option<DepositOutputEvidence>,
    funded_amount: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DepositOutputEvidence {
    id: WalletOutputId,
    index_on_blockchain: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SuccessorEpochSigningAcceptance {
    epoch: u64,
    transaction: [u8; 32],
    exact_transaction_bytes: Vec<u8>,
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

/// Exercise DKG, a grow, timer-driven same-committee refreshes both inside and beyond the finite
/// scenario chain, a shrink, and a real BFT deposit consolidation against the configured daemon.
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
    let timeout = std::time::Duration::from_secs(scenario.protocol_timeout_seconds);
    let parties = PartyClient::new(timeout, scenario).await?;

    tracing::info!("running epoch-0 distributed key generation");
    let initial = scenario.genesis_committee()?;
    let (key_id, dkg_session) = crate::server::canonical_dkg_identity(scenario)?;
    let mut current = run_dkg(
        &parties,
        dkg_session,
        key_id,
        &initial,
        scenario.committee_spec(0)?.fault_bound,
        &faulty,
    )
    .await?;
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
        let (deposit_block, deposit_transaction, deposit_transaction_bytes) =
            fund_deposit_with_ordinary_transaction(
                &daemon,
                &funding_spend,
                &funding_view,
                &funding_address,
                funding_start_height,
                &deposit_address,
                scenario.deposit_maximum_fee_atomic_units,
                scenario.poll_interval_ms,
                scenario.protocol_timeout_seconds,
            )
            .await?;
        let (funded_output, funded_amount) = verify_deposit_transaction_output(
            &daemon,
            &view,
            deposit_block,
            &certified,
            deposit_transaction,
        )
        .await?;
        validate_consolidation_fixture_economics(
            funded_amount,
            scenario.deposit_maximum_fee_atomic_units,
        )?;
        certified.funded_output = Some(funded_output);
        certified.funded_amount = Some(funded_amount);
        maybe_pause_at_deposit_fault_barrier(&parties, deposit_transaction, funded_output.id)
            .await?;
        println!(
            "TM_ACCEPTANCE_DEPOSIT_FUNDING_TRANSACTION txid={} bytes={}",
            hex::encode(deposit_transaction),
            deposit_transaction_bytes.len()
        );
        println!(
            "TM_ACCEPTANCE_DEPOSIT_FUNDING_TRANSACTION_HEX={}",
            hex::encode(&deposit_transaction_bytes)
        );
        for _ in 1..scenario.confirmation_blocks {
            daemon.generate_blocks(&threshold_address, 1).await?;
        }
        wait_for_permanent_deposit(
            scenario,
            &parties,
            &initial,
            scenario.committee_spec(0)?.fault_bound,
            &faulty,
            &certified,
        )
        .await?;
        tracing::info!(
            txid = %hex::encode(deposit_transaction),
            address = %deposit_address,
            amount = funded_amount,
            "ordinary wallet transaction deposit was observed and made permanent"
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
                scenario.poll_interval_ms,
                scenario.protocol_timeout_seconds,
            )
            .await?;
            let consolidation_height = u64::try_from(daemon.latest_block_number().await?)?;
            let confirmation = ChainPoint::new(consolidation_height, consolidation_block.hash())?;
            let accepted_transaction = verify_consolidation_transaction(
                &daemon,
                &view,
                consolidation_block,
                &certified,
                &broadcast,
            )
            .await?;
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
            anyhow::ensure!(confirmed.authorization == broadcast.authorization);
            anyhow::ensure!(confirmed.sweep == broadcast.sweep);
            anyhow::ensure!(confirmed.plan == broadcast.plan);
            anyhow::ensure!(confirmed.signed == broadcast.signed);
            anyhow::ensure!(confirmed.certificate_digest == broadcast.certificate_digest);
            anyhow::ensure!(confirmed.confirmation == Some(confirmation));
            anyhow::ensure!(confirmed.roast_view == broadcast.roast_view);
            anyhow::ensure!(confirmed.roast_relay_seed == broadcast.roast_relay_seed);
            anyhow::ensure!(confirmed.roast_signers == broadcast.roast_signers);
            anyhow::ensure!(confirmed.roast_view_count == broadcast.roast_view_count);
            anyhow::ensure!(confirmed.roast_candidate_count == broadcast.roast_candidate_count);
            anyhow::ensure!(
                confirmed.roast_endorsed_candidate_count
                    == broadcast.roast_endorsed_candidate_count
            );
            anyhow::ensure!(
                confirmed.roast_intent_certificate_digest
                    == broadcast.roast_intent_certificate_digest
            );
            anyhow::ensure!(
                confirmed.roast_intent_certificate_signers
                    == broadcast.roast_intent_certificate_signers
            );
            anyhow::ensure!(
                confirmed.roast_attempt_binding_digest == broadcast.roast_attempt_binding_digest
            );
            anyhow::ensure!(
                confirmed.roast_endorsed_witness_count == broadcast.roast_endorsed_witness_count
            );
            anyhow::ensure!(
                confirmed.roast_endorsed_evidence_digest
                    == broadcast.roast_endorsed_evidence_digest
            );
            anyhow::ensure!(
                confirmed.completion_certificate_signers
                    == broadcast.completion_certificate_signers
            );
            anyhow::ensure!(
                confirmed.key_image_binding_digest == broadcast.key_image_binding_digest,
                "confirmed consolidation changed its durable key-image family binding"
            );
            anyhow::ensure!(
                confirmed.key_image_unsigned_transaction_digest
                    == broadcast.key_image_unsigned_transaction_digest,
                "confirmed consolidation changed its key-image-bound unsigned transaction"
            );
            anyhow::ensure!(
                confirmed.key_image_preprocess_set_digest
                    == broadcast.key_image_preprocess_set_digest,
                "confirmed consolidation changed its proof-bearing preprocess set"
            );
            anyhow::ensure!(
                confirmed.key_image_authorizers == broadcast.key_image_authorizers,
                "confirmed consolidation changed its key-image authorization roster"
            );
            anyhow::ensure!(
                confirmed.key_image_authorization_quorum
                    == broadcast.key_image_authorization_quorum,
                "confirmed consolidation changed its key-image authorization count"
            );
            anyhow::ensure!(confirmed.bootstrap_ba_view == broadcast.bootstrap_ba_view);
            anyhow::ensure!(confirmed.bootstrap_ba_proposer == broadcast.bootstrap_ba_proposer);
            anyhow::ensure!(
                confirmed.bootstrap_prepared_intent_digest
                    == broadcast.bootstrap_prepared_intent_digest
            );
            anyhow::ensure!(
                confirmed.bootstrap_certificate_digest == broadcast.bootstrap_certificate_digest
            );
            anyhow::ensure!(
                confirmed.bootstrap_certificate_signers == broadcast.bootstrap_certificate_signers
            );
            tracing::info!(
                txid = %hex::encode(signed.transaction()),
                height = confirmation.height,
                "autonomous threshold consolidation was mined and confirmed by n-f parties"
            );
            consolidation_transaction = Some(signed.transaction());
            confirmed_consolidation = Some(confirmed.clone());
            if let Some(proof) = completed_fault {
                maybe_pause_after_consolidation_fault_settlement(&proof, &confirmed).await?;
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
        .configured_key_rotation_target_policy(&before_grow.committee)?
        .context("epoch zero lacks its configured grow target")?
        .eligible()
        .clone();
    release_held_proactive_refresh(&parties, &before_grow.committee, &grow_target, &faulty).await?;
    current = wait_for_configured_successor(scenario, &parties, &current, 1, &faulty).await?;
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
            &current.committee,
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
                funding_start_height
                    .checked_add(usize::try_from(current.committee.epoch)?)
                    .context("successor funding height overflow")?,
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
    let refresh_target = scenario
        .configured_key_rotation_target_policy(&before_refresh.committee)?
        .context("epoch one lacks its configured refresh target")?
        .eligible()
        .clone();
    release_held_proactive_refresh(&parties, &before_refresh.committee, &refresh_target, &faulty)
        .await?;
    current = wait_for_configured_successor(scenario, &parties, &current, 2, &faulty).await?;
    validate_scheduled_refresh(&before_refresh, &current, threshold_spend_bytes(&view))?;
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
            &current.committee,
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
                funding_start_height
                    .checked_add(usize::try_from(current.committee.epoch)?)
                    .context("successor funding height overflow")?,
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
        .configured_key_rotation_target_policy(&before_second_refresh.committee)?
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
    current = wait_for_configured_successor(scenario, &parties, &current, 3, &faulty).await?;
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
            &current.committee,
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
                funding_start_height
                    .checked_add(usize::try_from(current.committee.epoch)?)
                    .context("successor funding height overflow")?,
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
        .configured_key_rotation_target_policy(&before_shrink.committee)?
        .context("epoch three lacks its configured shrink target")?
        .eligible()
        .clone();
    release_held_proactive_refresh(&parties, &before_shrink.committee, &shrink_target, &faulty)
        .await?;
    current = wait_for_configured_successor(scenario, &parties, &current, 4, &faulty).await?;
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
            &current.committee,
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
                funding_start_height
                    .checked_add(usize::try_from(current.committee.epoch)?)
                    .context("successor funding height overflow")?,
                &threshold_address,
                &view,
                &current,
                scenario.committee_spec(4)?.fault_bound,
                &faulty,
            )
            .await?,
        );
    }

    let final_fault_bound = scenario.committee_spec(4)?.fault_bound;
    let dynamic_faulty = configured_dynamic_rotation_faulty_parties(
        scenario,
        &current.committee,
        final_fault_bound,
        &faulty,
    )?;
    maybe_pause_before_dynamic_refresh(&parties, current.committee.epoch).await?;
    tracing::info!(
        interval_seconds = scenario.proactive_refresh_interval_seconds,
        source_epoch = current.committee.epoch,
        "waiting for a dynamic refresh beyond the finite configured committee chain"
    );
    let before_dynamic_refresh = current.clone();
    let mut dynamic_target = before_dynamic_refresh.committee.clone();
    dynamic_target.epoch =
        dynamic_target.epoch.checked_add(1).context("dynamic refresh epoch exhausted")?;
    release_held_proactive_refresh(
        &parties,
        &before_dynamic_refresh.committee,
        &dynamic_target,
        &faulty,
    )
    .await?;
    current = wait_for_dynamic_refresh(
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
            &current.committee,
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
                funding_start_height
                    .checked_add(usize::try_from(current.committee.epoch)?)
                    .context("successor funding height overflow")?,
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
        println!("TM_ACCEPTANCE_SIGNED_TRANSACTION_HEX={}", hex::encode(bytes));
    }
    for accepted in &successor_epoch_signatures {
        println!(
            "TM_ACCEPTANCE_SUCCESSOR_EPOCH_SIGNED_TRANSACTION epoch={} txid={} bytes={} hex={}",
            accepted.epoch,
            hex::encode(accepted.transaction),
            accepted.exact_transaction_bytes.len(),
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
        "threshold Monero regtest accepted 3-of-5 -> 4-of-7 -> two scheduled 4-of-7 refreshes -> 2-of-4 resharing -> autonomous dynamic 2-of-4 refresh"
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
    let request_party = allocation_request_party(committee, faulty)?;
    let request = fresh_deposit_request()?;
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    loop {
        let observation = match client
            .post_deposit::<_, DepositHttpResponse>(
                request_party,
                "/v1/deposits/allocate",
                &request,
            )
            .await
        {
            Ok(response) if response.status == DepositHttpStatus::Active => {
                let issuer_registry = validate_new_deposit_certificate(
                    scenario,
                    public,
                    fault_bound,
                    request,
                    &response,
                )?;
                let certified = CertifiedDeposit {
                    request,
                    response,
                    issuer_registry,
                    funded_output: None,
                    funded_amount: None,
                };
                wait_for_deposit_status(
                    client,
                    committee,
                    fault_bound,
                    faulty,
                    &certified,
                    DepositHttpStatus::Active,
                )
                .await?;
                return Ok(certified);
            }
            Ok(response) => {
                format!("request party {request_party} returned {:?}", response.status)
            }
            Err(error) => format!("request party {request_party} failed: {error:#}"),
        };
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "deposit allocation did not reach a certified active state: {observation}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

fn allocation_request_party(
    committee: &Committee,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<PartyId> {
    committee
        .members
        .iter()
        .map(|member| member.id)
        .find(|party| !faulty.contains(party))
        .context("deposit committee has no responsive request party")
}

fn validate_new_deposit_certificate(
    scenario: &Scenario,
    public: &EpochPublic,
    fault_bound: u16,
    request: DepositAddressRequest,
    response: &DepositHttpResponse,
) -> anyhow::Result<CompactEpochRegistry> {
    anyhow::ensure!(response.request == request.request);
    anyhow::ensure!(response.certified_request == tenant_certified_request_id(request));
    anyhow::ensure!(response.status == DepositHttpStatus::Active);
    let address = response.address.as_ref().context("active deposit omitted address")?;
    address.validate()?;
    anyhow::ensure!(address.network() == scenario.network);
    let certificate =
        response.certificate.as_ref().context("active deposit omitted certificate")?;
    let created_at = response.created_at.context("active deposit omitted creation time")?;
    let expires_at = response.expires_at.context("active deposit omitted expiry time")?;
    anyhow::ensure!(
        expires_at.checked_sub(created_at) == Some(UNUSED_ALLOCATION_TTL_SECONDS),
        "deposit allocation does not use the exact thirty-day unused lifetime"
    );
    let registry = response
        .issuer_registry
        .clone()
        .context("active deposit omitted compact issuer registry")?;
    registry.validate()?;
    anyhow::ensure!(registry.wallet() == address.wallet_id());
    anyhow::ensure!(registry.active_epoch() == public.committee.epoch);
    anyhow::ensure!(registry.active().committee().digest() == public.committee.digest());
    anyhow::ensure!(registry.active().fault_bound() == fault_bound);
    anyhow::ensure!(registry.active().activation() == public.activation_digest()?);
    anyhow::ensure!(registry.active().key_id() == public.key_id);
    anyhow::ensure!(registry.active().group_key() == public.group_key_bytes());
    let verified = certificate.verify_active(&registry, None)?;
    anyhow::ensure!(verified.required() == public.committee.n() - fault_bound);
    let LedgerPayload::Allocation(allocation) = &certificate.statement.payload else {
        anyhow::bail!("deposit response certificate is not an allocation");
    };
    anyhow::ensure!(allocation.request == response.certified_request);
    anyhow::ensure!(allocation.binding == tenant_bound_request_binding(request));
    anyhow::ensure!(&allocation.address == address);
    anyhow::ensure!(allocation.created_at == created_at && allocation.expires_at == expires_at);
    anyhow::ensure!(certificate.statement.wallet == address.wallet_id());
    Ok(registry)
}

fn validate_replica_deposit_certificate(
    party: PartyId,
    deposit: &CertifiedDeposit,
    observed: &CertifiedLedgerEntry,
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
    let verified = observed.verify_active(&deposit.issuer_registry, None)?;
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
    committee: &Committee,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
) -> anyhow::Result<()> {
    wait_for_deposit_status(
        client,
        committee,
        fault_bound,
        faulty,
        deposit,
        DepositHttpStatus::Permanent,
    )
    .await
}

async fn wait_for_deposit_status(
    client: &PartyClient,
    committee: &Committee,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
    expected_status: DepositHttpStatus,
) -> anyhow::Result<()> {
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
    let expected_leader =
        committee.members.first().map(|member| member.id).context("deposit committee is empty")?;
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut matching = 0_usize;
        let mut recovered_party_matching = recovered_party.is_none();
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
                    // The certificate below remains the immutable historical allocation from
                    // epoch zero, while `leader` is routing metadata for the deposit registry's
                    // currently active issuer. Threshold-key activation can race ahead of the
                    // durable deposit handoff, so an old leader is a retryable convergence state.
                    if !deposit_status_reached_current_epoch(
                        response.status,
                        response.leader,
                        expected_status,
                        expected_leader,
                    ) {
                        continue;
                    }
                    anyhow::ensure!(response.request == deposit.response.request);
                    anyhow::ensure!(
                        response.certified_request == deposit.response.certified_request
                    );
                    anyhow::ensure!(response.address == deposit.response.address);
                    anyhow::ensure!(response.created_at == deposit.response.created_at);
                    anyhow::ensure!(response.expires_at == deposit.response.expires_at);
                    let certificate = response.certificate.as_ref().with_context(|| {
                        format!("party {party} omitted its deposit certificate")
                    })?;
                    let signers =
                        validate_replica_deposit_certificate(*party, deposit, certificate)?;
                    observations.insert(
                        *party,
                        format!("{:?} certificate_signers={signers:?}", response.status),
                    );
                    matching = matching.saturating_add(1);
                    recovered_party_matching |= Some(*party) == recovered_party;
                }
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                }
            }
        }
        if matching >= required && recovered_party_matching {
            return Ok(());
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "deposit did not reach {expected_status:?} on n-f replicas; observations: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

fn deposit_status_reached_current_epoch(
    observed_status: DepositHttpStatus,
    observed_leader: PartyId,
    expected_status: DepositHttpStatus,
    expected_leader: PartyId,
) -> bool {
    observed_status == expected_status && observed_leader == expected_leader
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
    status: &PublicConsolidationStatus,
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
    status: &PublicConsolidationStatus,
) -> anyhow::Result<()> {
    anyhow::ensure!(status.sweep == proof.sweep);
    anyhow::ensure!(status.bootstrap_ba_view == proof.certified_ba_view);
    anyhow::ensure!(status.bootstrap_ba_proposer == proof.certified_proposer);
    anyhow::ensure!(
        status.bootstrap_prepared_intent_digest == proof.certified_prepared_intent_digest
    );
    anyhow::ensure!(status.bootstrap_certificate_digest == proof.certificate_digest);
    anyhow::ensure!(status.bootstrap_certificate_signers == proof.certificate_signers);
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
    let (held_authorization, _) = wait_for_consolidation_fault_gate_state(
        client,
        committee,
        AcceptanceConsolidationGateState::Held,
        required,
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
    let (rejoined_authorization, held_parties) = wait_for_consolidation_fault_gate_state(
        client,
        committee,
        AcceptanceConsolidationGateState::Held,
        committee.members.len(),
    )
    .await?;
    anyhow::ensure!(rejoined_authorization == Some(held_authorization));
    anyhow::ensure!(held_parties == all_parties);
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
    anyhow::ensure!(rejoined == reserved);
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
        committee.members.len(),
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
) -> anyhow::Result<(Option<ConsolidationId>, BTreeSet<PartyId>)> {
    anyhow::ensure!(required > 0 && required <= committee.members.len());
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let request =
        AcceptanceConsolidationGateRequest { action: AcceptanceConsolidationGateAction::Status };
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut matching = 0_usize;
        let mut agreed_authorization = None;
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
            anyhow::ensure!(response.party == member.id);
            observations.insert(
                member.id,
                format!(
                    "{:?} authorization={:?} roast_view={:?}",
                    response.state, response.authorization, response.roast_view
                ),
            );
            if response.state != expected {
                continue;
            }
            if expected == AcceptanceConsolidationGateState::Held {
                let authorization = response
                    .authorization
                    .context("held consolidation gate omitted its authorization")?;
                anyhow::ensure!(authorization.0 != [0; 32]);
                anyhow::ensure!(response.roast_view == Some(0));
                if let Some(agreed) = agreed_authorization {
                    anyhow::ensure!(
                        agreed == authorization,
                        "held gates disagree on authorization"
                    );
                } else {
                    agreed_authorization = Some(authorization);
                }
            }
            matching = matching.saturating_add(1);
            matching_parties.insert(member.id);
        }
        if matching >= required {
            return Ok((agreed_authorization, matching_parties));
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "consolidation gates did not reach {expected:?} on {required} parties; observations: {observations:?}"
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
    let (held_authorization, held_parties) = wait_for_consolidation_fault_gate_state(
        client,
        committee,
        AcceptanceConsolidationGateState::Held,
        required,
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
        initial_signers: reserved.roast_signers,
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
    let _ = wait_for_consolidation_fault_gate_state(
        client,
        committee,
        AcceptanceConsolidationGateState::Released,
        committee.members.len(),
    )
    .await?;
    tracing::warn!(
        authorization = %hex::encode(pending.authorization.0),
        "all acceptance-only consolidation gates released after fault injection"
    );
    Ok(Some(pending))
}

fn validate_consolidation_fault_recovery(
    pending: &PendingConsolidationFault,
    broadcast: &PublicConsolidationStatus,
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
    proof: &ConsolidationFaultProof,
    confirmed: &PublicConsolidationStatus,
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
    let pause_seconds = acceptance_barrier_seconds("consolidation settlement")?;
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
    {
        use std::io::Write as _;
        std::io::stdout().flush()?;
    }
    tracing::warn!(
        fault_party = %proof.fault_party,
        completed_view = proof.completed_view,
        completed_signers = ?proof.completed_signers,
        pause_seconds,
        "fault-resilient consolidation settled; pausing for peer-QUIC reconnection"
    );
    tokio::time::sleep(std::time::Duration::from_secs(pause_seconds)).await;
    Ok(())
}

fn acceptance_barrier_seconds(kind: &str) -> anyhow::Result<u64> {
    let pause_seconds = std::env::var("TM_ACCEPTANCE_BARRIER_SECONDS")
        .unwrap_or_else(|_| "30".to_owned())
        .parse::<u64>()?;
    anyhow::ensure!(
        (1..=120).contains(&pause_seconds),
        "{kind} fault barrier pause must be between 1 and 120 seconds"
    );
    Ok(pause_seconds)
}

fn format_party_list(parties: &[PartyId]) -> String {
    parties.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
}

fn deterministic_roast_signers(
    committee: &Committee,
    fault_bound: u16,
    view: u64,
) -> anyhow::Result<Vec<PartyId>> {
    crate::consolidation_roast::deterministic_roast_signers(committee, fault_bound, view)
        .map_err(Into::into)
}

async fn wait_for_consolidation_phase(
    client: &PartyClient,
    committee: &Committee,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
    expected_destination: [u8; 32],
    expected_phase: PublicConsolidationPhase,
) -> anyhow::Result<PublicConsolidationStatus> {
    anyhow::ensure!(fault_bound < committee.n());
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
        let mut agreed = None::<PublicConsolidationStatus>;
        let mut matching = 0_usize;
        let mut recovered_party_matching = recovered_party.is_none();
        for party in &responsive {
            let response = match client
                .post_deposit::<_, DepositConsolidationStatusResponse>(
                    *party,
                    "/v1/deposits/consolidations/status",
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
            anyhow::ensure!(response.request == deposit.request.request);
            anyhow::ensure!(
                response.certified_request == tenant_certified_request_id(deposit.request)
            );
            let funded = deposit.funded_output.context("deposit output evidence is missing")?;
            let candidates = response
                .consolidations
                .into_iter()
                .filter(|status| status.plan.inputs.contains(&funded.id))
                .collect::<Vec<_>>();
            anyhow::ensure!(
                candidates.len() <= 1,
                "party {party} reported multiple consolidations claiming one deposit output"
            );
            let Some(status) = candidates.into_iter().next() else {
                observations.insert(*party, "not discovered".to_owned());
                continue;
            };
            validate_public_consolidation(
                &status,
                committee,
                fault_bound,
                deposit,
                expected_destination,
            )?;
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
            anyhow::ensure!(
                !matches!(
                    status.phase,
                    PublicConsolidationPhase::Quarantined | PublicConsolidationPhase::Aborted
                ),
                "consolidation entered terminal failure phase {:?}",
                status.phase
            );
            if status.phase != expected_phase {
                continue;
            }
            if let Some(expected) = &agreed {
                anyhow::ensure!(
                    expected == &status,
                    "party {party} reported conflicting public consolidation state"
                );
            } else {
                agreed = Some(status);
            }
            matching = matching.saturating_add(1);
            recovered_party_matching |= Some(*party) == recovered_party;
        }
        if matching >= required && recovered_party_matching {
            return agreed.context("consolidation quorum omitted its agreed state");
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "consolidation did not reach {expected_phase:?} on n-f replicas; observations: {observations:?}"
        );
        tokio::time::sleep(client.poll_interval).await;
    }
}

/// Require the exact already-validated confirmation record to survive a committee transition and
/// be served byte-for-byte by `n-f` members of the new active committee. The immutable plan and
/// its certificates remain bound to the committee that signed them; equality with the original
/// fully validated record is therefore the correct handoff predicate instead of reinterpreting
/// its signer roster under the successor epoch.
async fn wait_for_confirmed_consolidation_checkpoint(
    scenario: &Scenario,
    client: &PartyClient,
    committee: &Committee,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
    expected: &PublicConsolidationStatus,
) -> anyhow::Result<()> {
    wait_for_permanent_deposit(scenario, client, committee, fault_bound, faulty, deposit).await?;
    anyhow::ensure!(expected.phase == PublicConsolidationPhase::Confirmed);
    let funded = deposit.funded_output.context("deposit output evidence is missing")?;
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
            anyhow::ensure!(response.request == deposit.request.request);
            anyhow::ensure!(
                response.certified_request == tenant_certified_request_id(deposit.request)
            );
            let candidates = response
                .consolidations
                .into_iter()
                .filter(|status| status.plan.inputs.contains(&funded.id))
                .collect::<Vec<_>>();
            anyhow::ensure!(
                candidates.len() <= 1,
                "party {party} reported multiple checkpoint consolidations for one deposit"
            );
            let Some(status) = candidates.into_iter().next() else {
                observations.insert(*party, "not handed off".to_owned());
                continue;
            };
            if &status != expected {
                observations.insert(
                    *party,
                    format!("conflicting {:?} epoch-{} plan", status.phase, status.plan.epoch),
                );
                continue;
            }
            observations.insert(*party, "exact confirmed record".to_owned());
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
    committee: &Committee,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
    deposit: &CertifiedDeposit,
    confirmed: Option<&PublicConsolidationStatus>,
) -> anyhow::Result<()> {
    if let Some(confirmed) = confirmed {
        wait_for_confirmed_consolidation_checkpoint(
            scenario,
            client,
            committee,
            fault_bound,
            faulty,
            deposit,
            confirmed,
        )
        .await
    } else {
        wait_for_permanent_deposit(scenario, client, committee, fault_bound, faulty, deposit).await
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
        scenario.deposit_maximum_fee_atomic_units,
        scenario.poll_interval_ms,
        scenario.protocol_timeout_seconds,
    )
    .await?;
    let (funded_output, funded_amount) = verify_deposit_transaction_output(
        daemon,
        threshold_view,
        deposit_block,
        &deposit,
        deposit_transaction,
    )
    .await?;
    validate_consolidation_fixture_economics(
        funded_amount,
        scenario.deposit_maximum_fee_atomic_units,
    )?;
    deposit.funded_output = Some(funded_output);
    deposit.funded_amount = Some(funded_amount);

    for _ in 1..scenario.confirmation_blocks {
        daemon.generate_blocks(threshold_address, 1).await?;
    }
    wait_for_permanent_deposit(scenario, client, &public.committee, fault_bound, faulty, &deposit)
        .await?;

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
        scenario.poll_interval_ms,
        scenario.protocol_timeout_seconds,
    )
    .await?;
    let confirmation_height = u64::try_from(daemon.latest_block_number().await?)?;
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
        confirmed == expected_confirmed,
        "epoch-{} confirmation changed the certified signing transcript",
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
        exact_transaction_bytes,
    })
}

fn validate_public_consolidation(
    status: &PublicConsolidationStatus,
    committee: &Committee,
    fault_bound: u16,
    deposit: &CertifiedDeposit,
    expected_destination: [u8; 32],
) -> anyhow::Result<()> {
    let funded = deposit.funded_output.context("deposit output evidence is missing")?;
    let amount = deposit.funded_amount.context("deposit amount evidence is missing")?;
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
    anyhow::ensure!(status.plan.inputs.as_slice() == [funded.id]);
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
            == usize::try_from(status.roast_view)?
                .checked_add(1)
                .context("ROAST view count overflow")?,
        "consolidation ROAST view count does not include exactly the current view chain"
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

#[allow(clippy::too_many_arguments)]
async fn fund_deposit_with_ordinary_transaction(
    daemon: &MoneroDaemon<SimpleRequestTransport>,
    funding_spend: &Zeroizing<Scalar>,
    funding_view: &ViewPair,
    mining_address: &MoneroAddress,
    funding_start_height: usize,
    deposit_address: &MoneroAddress,
    maximum_consolidation_fee: u64,
    poll_interval_ms: u64,
    timeout_seconds: u64,
) -> anyhow::Result<(monero_wallet::block::Block, [u8; 32], Vec<u8>)> {
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
    let required_input = deposit_amount
        .checked_add(maximum_consolidation_fee)
        .context("acceptance funding requirement overflow")?;
    anyhow::ensure!(
        funding_amount > required_input,
        "mature funding output {funding_amount} cannot cover deposit {deposit_amount} plus \
         consolidation-fee headroom {maximum_consolidation_fee}"
    );

    let mut rng = OsRng;
    let input = OutputWithDecoys::new(&mut rng, daemon, 16, latest, funding_output).await?;
    let fee_rate = daemon.fee_rate(FeePriority::Unimportant, u64::MAX).await?;
    let mut outgoing_view_key = Zeroizing::new([0_u8; 32]);
    rng.fill_bytes(outgoing_view_key.as_mut());
    anyhow::ensure!(
        outgoing_view_key.as_ref() != &[0_u8; 32],
        "sampled a zero acceptance outgoing-view seed"
    );
    let signable = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        outgoing_view_key,
        vec![input],
        vec![(*deposit_address, deposit_amount)],
        Change::new(funding_view.clone(), None),
        vec![],
        fee_rate,
    )?;
    let signed = signable.sign(&mut rng, funding_spend)?;
    let transaction = signed.hash();
    let locally_signed_bytes = signed.serialize();
    daemon.publish_transaction(&signed).await?;
    let containing_block =
        mine_confirmation(daemon, mining_address, transaction, poll_interval_ms, timeout_seconds)
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
    status: &PublicConsolidationStatus,
) -> anyhow::Result<Transaction> {
    let funded = deposit.funded_output.context("deposit output evidence is missing")?;
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
    for input in &prefix.inputs {
        let Input::ToKey { amount, key_offsets, key_image: _ } = input else {
            anyhow::bail!("consolidation contains a miner input");
        };
        anyhow::ensure!(amount.is_none(), "consolidation input is not RingCT");
        anyhow::ensure!(key_offsets.len() == 16, "consolidation ring size is not sixteen");
        let mut absolute = 0_u64;
        let mut includes_deposit = false;
        for offset in key_offsets {
            absolute = absolute.checked_add(*offset).context("ring offset overflow")?;
            includes_deposit |= absolute == funded.index_on_blockchain;
        }
        anyhow::ensure!(
            includes_deposit,
            "consolidation ring does not contain the certified deposit output"
        );
    }

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

fn acceptance_driver_binding(kind: AcceptanceDriverLatchKind, material: &[u8]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/e2e-acceptance-driver-binding/v1");
    hasher.update(kind.marker().as_bytes());
    hasher.update(&(material.len() as u64).to_le_bytes());
    hasher.update(material);
    *hasher.finalize().as_bytes()
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
                        && response.binding == Some(binding),
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

/// Optional Compose-only durable barrier after a real deposit is mined. The driver selects either
/// an observer-fork latch or p2's exact `n-f` portable-output checkpoint crash gate. Neither path
/// has a timer: only an authenticated release lets the acceptance client continue.
async fn maybe_pause_at_deposit_fault_barrier(
    client: &PartyClient,
    transaction: [u8; 32],
    output: WalletOutputId,
) -> anyhow::Result<()> {
    if std::env::var("TM_ACCEPTANCE_ENABLE_FAULT_HOOKS").as_deref() != Ok("1")
        || std::env::var("TM_ACCEPTANCE_PAUSE_AFTER_DEPOSIT_FUNDING").as_deref() != Ok("1")
    {
        return Ok(());
    }
    anyhow::ensure!(output.transaction == transaction);
    let mode = std::env::var("TM_ACCEPTANCE_DEPOSIT_FAULT_MODE")
        .context("deposit fault hook requires TM_ACCEPTANCE_DEPOSIT_FAULT_MODE")?;
    match mode.as_str() {
        "observer_fork" => {
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
                    && armed.binding == Some(binding),
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
        "deposit_checkpoint" => {
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
        value => anyhow::bail!(
            "TM_ACCEPTANCE_DEPOSIT_FAULT_MODE must be observer_fork or deposit_checkpoint, got {value:?}"
        ),
    }
}

async fn verify_deposit_transaction_output(
    daemon: &MoneroDaemon<SimpleRequestTransport>,
    view: &ViewPair,
    block: monero_wallet::block::Block,
    deposit: &CertifiedDeposit,
    transaction: [u8; 32],
) -> anyhow::Result<(DepositOutputEvidence, u64)> {
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
        received.len() == 1,
        "deposit transaction created {} outputs for the certified subaddress, expected one",
        received.len()
    );
    let output = &received[0];
    Ok((
        DepositOutputEvidence {
            id: WalletOutputId { transaction, index_in_transaction: output.index_in_transaction() },
            index_on_blockchain: output.index_on_blockchain(),
        },
        output.commitment().amount,
    ))
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
            let party = PartyId::new(2)?;
            let due_unix_ms = *deadlines
                .get(&party)
                .context("proactive deadline campaign requires p2 in the transition")?;
            let interval_ms = acceptance_refresh_interval_millis()?;
            let released_at_unix_ms = due_unix_ms
                .checked_sub(interval_ms)
                .context("proactive refresh deadline precedes its configured interval")?;
            let mut material = Vec::with_capacity(32);
            material.extend_from_slice(&source.epoch.to_le_bytes());
            material.extend_from_slice(&target.epoch.to_le_bytes());
            material.extend_from_slice(&due_unix_ms.to_le_bytes());
            material.extend_from_slice(&interval_ms.to_le_bytes());
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
                    && armed.binding == Some(binding),
                "p2 held a different proactive-deadline latch"
            );
            println!(
                "TM_ACCEPTANCE_PROACTIVE_DEADLINE_HELD party=2 source_epoch={} target_epoch={} released_at_unix_ms={} interval_ms={} due_unix_ms={} binding={}",
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
                "TM_ACCEPTANCE_PROACTIVE_DEADLINE_RELEASED party=2 source_epoch={} target_epoch={} due_unix_ms={} binding={}",
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
) -> anyhow::Result<EpochPublic> {
    old.validate()?;
    let expected_epoch =
        old.committee.epoch.checked_add(1).context("configured successor epoch exhausted")?;
    anyhow::ensure!(
        new_epoch == expected_epoch,
        "configured successor must be immediate epoch {expected_epoch}, requested {new_epoch}"
    );
    let policy = scenario
        .configured_key_rotation_target_policy(&old.committee)?
        .context("configured successor lacks a target key-rotation policy")?;
    anyhow::ensure!(policy.target_epoch() == new_epoch);
    let responsive = policy
        .eligible()
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        responsive.len() >= policy.selection_size(),
        "configured epoch-{new_epoch} has {} responsive target members, requires n-f={}",
        responsive.len(),
        policy.selection_size()
    );

    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut activated = BTreeMap::<PartyId, EpochPublic>::new();
        for party in &responsive {
            match client.get_admin::<PartyStatus>(*party, "/v1/status").await {
                Ok(status) => {
                    anyhow::ensure!(
                        status.party == *party,
                        "status endpoint returned another party ID"
                    );
                    anyhow::ensure!(status.ready, "party {party} reported that it is not ready");
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
                    if let Some(observed) = status.active_epoch {
                        anyhow::ensure!(
                            observed <= new_epoch,
                            "party {party} advanced past configured target epoch {new_epoch} to {observed}"
                        );
                    }
                    if status.active_epoch != Some(new_epoch) {
                        continue;
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
                    validate_configured_successor(scenario, old, &public).with_context(|| {
                        format!("party {party} reported an invalid configured epoch-{new_epoch}")
                    })?;
                    activated.insert(*party, public);
                }
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                }
            }
        }

        if activated.len() == responsive.len() {
            let expected = activated.values().next().context("empty activated party set")?.clone();
            for (party, public) in &activated {
                anyhow::ensure!(
                    public == &expected,
                    "party {party} activated a conflicting public value for configured epoch {new_epoch}"
                );
            }
            let rotated = validate_configured_successor(scenario, old, &expected)?;
            tracing::info!(
                epoch = new_epoch,
                parties = activated.len(),
                rotated_encryption_keys = rotated,
                "configured timer-driven QUIC successor activated"
            );
            return Ok(expected);
        }

        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "configured epoch-{new_epoch} did not activate before the protocol deadline; observations: {observations:?}"
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
        .configured_key_rotation_target_policy(&before.committee)?
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
            && before.committee.members.iter().map(|member| member.id).eq(after
                .committee
                .members
                .iter()
                .map(|member| member.id)),
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

/// Validate a same-committee proactive refresh whose target was learned from the live network,
/// not from the finite scenario fixture. The returned count is useful acceptance evidence for the
/// independently rotated X25519 keys.
fn validate_dynamic_refresh(
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

    let before_members = before.committee.by_id();
    let after_members = after.committee.by_id();
    anyhow::ensure!(
        before_members.keys().eq(after_members.keys()),
        "dynamic proactive refresh changed committee member IDs"
    );
    let mut rotated_encryption_keys = 0_usize;
    for (party, old_member) in before_members {
        let new_member = after_members
            .get(&party)
            .context("dynamic proactive refresh omitted a source member")?;
        anyhow::ensure!(
            new_member.signing_key == old_member.signing_key,
            "dynamic proactive refresh changed party {party}'s stable signing key"
        );
        if new_member.encryption_key != old_member.encryption_key {
            rotated_encryption_keys = rotated_encryption_keys.saturating_add(1);
        }
    }
    let required_rotations = usize::from(
        before
            .committee
            .n()
            .checked_sub(fault_bound)
            .context("dynamic proactive refresh fault bound exceeds committee size")?,
    );
    anyhow::ensure!(
        rotated_encryption_keys >= required_rotations,
        "dynamic proactive refresh rotated {rotated_encryption_keys} X25519 keys, requires at least n-f={required_rotations}"
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
    client: &PartyClient,
    old: &EpochPublic,
    fault_bound: u16,
    faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<EpochPublic> {
    let target_epoch =
        old.committee.epoch.checked_add(1).context("dynamic proactive refresh epoch exhausted")?;
    let responsive = old
        .committee
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    let required_responsive = usize::from(
        old.committee
            .n()
            .checked_sub(fault_bound)
            .context("dynamic proactive refresh fault bound exceeds committee size")?,
    );
    anyhow::ensure!(
        responsive.len() >= required_responsive,
        "dynamic proactive refresh has {} responsive final-committee parties, requires n-f={required_responsive}",
        responsive.len()
    );

    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut activated = BTreeMap::<PartyId, EpochPublic>::new();
        for party in &responsive {
            match client.get_admin::<PartyStatus>(*party, "/v1/status").await {
                Ok(status) => {
                    anyhow::ensure!(
                        status.party == *party,
                        "status endpoint returned another party ID"
                    );
                    anyhow::ensure!(status.ready, "party {party} reported that it is not ready");
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
                    if let Some(observed) = status.active_epoch {
                        anyhow::ensure!(
                            observed <= target_epoch,
                            "party {party} advanced past dynamic target epoch {target_epoch} to {observed}"
                        );
                    }
                    if status.active_epoch != Some(target_epoch) {
                        continue;
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
                    validate_dynamic_refresh(old, &public, fault_bound).with_context(|| {
                        format!("party {party} reported an invalid dynamic epoch-{target_epoch}")
                    })?;
                    activated.insert(*party, public);
                }
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                }
            }
        }

        if activated.len() == responsive.len() {
            let expected = activated.values().next().context("empty activated party set")?.clone();
            for (party, public) in &activated {
                anyhow::ensure!(
                    public == &expected,
                    "party {party} activated a conflicting public value for dynamic epoch {target_epoch}"
                );
            }
            let rotated = validate_dynamic_refresh(old, &expected, fault_bound)?;
            tracing::info!(
                epoch = target_epoch,
                parties = activated.len(),
                rotated_encryption_keys = rotated,
                "autonomous dynamic QUIC refresh activated"
            );
            return Ok(expected);
        }

        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "dynamic epoch-{target_epoch} did not activate before the protocol deadline; observations: {observations:?}"
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
    let responsive_dealers = dealers.iter().filter(|dealer| !faulty.contains(dealer)).count();
    let mut started_dealers = 0_usize;
    let mut fault_boundary_observed = false;
    for dealer in &dealers {
        if faulty.contains(dealer) {
            continue;
        }
        let response: AvssStepResponse = client
            .post_admin(
                *dealer,
                "/v1/avss/start",
                &AvssStartRequest { transition: transition.clone() },
            )
            .await?;
        anyhow::ensure!(response.party == *dealer && response.dealer == *dealer);
        started_dealers = started_dealers.saturating_add(1);
        if let Some(specification) = matching_fault {
            let boundary_reachable = match specification.boundary {
                AcceptanceProtocolFaultBoundary::DealerStarted => *dealer == specification.party,
                AcceptanceProtocolFaultBoundary::QualRoundZero => {
                    started_dealers == responsive_dealers
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
        matching_fault.is_none() || fault_boundary_observed,
        "configured acceptance protocol fault boundary was not reachable"
    );

    anyhow::ensure!(
        dealers.iter().any(|dealer| !faulty.contains(dealer)),
        "transition has no responsive AVSS dealer"
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
    let deadline = tokio::time::Instant::now() + client.protocol_timeout;
    let responsive = transition
        .target
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !faulty.contains(party))
        .collect::<Vec<_>>();
    anyhow::ensure!(!responsive.is_empty(), "transition has no responsive target party");

    let mut observations = BTreeMap::<PartyId, String>::new();
    loop {
        let mut activated = BTreeMap::<PartyId, EpochPublic>::new();
        for party in &responsive {
            match client.get_admin::<PartyStatus>(*party, "/v1/status").await {
                Ok(status) => {
                    anyhow::ensure!(
                        status.party == *party,
                        "status endpoint returned another party ID"
                    );
                    anyhow::ensure!(status.ready, "party {party} reported that it is not ready");
                    observations.insert(
                        *party,
                        format!(
                            "active={:?}, staged={:?}, epochs={:?}",
                            status.active_epoch,
                            status.staged_epochs,
                            status.epochs.iter().map(|epoch| epoch.epoch).collect::<Vec<_>>()
                        ),
                    );
                    if let Some(observed) = status.active_epoch {
                        anyhow::ensure!(
                            observed <= target_epoch,
                            "party {party} advanced past target epoch {target_epoch} to {observed}"
                        );
                    }
                    if status.active_epoch != Some(target_epoch) {
                        continue;
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
                    activated.insert(*party, public);
                }
                Err(error) => {
                    observations.insert(*party, format!("status error: {error:#}"));
                }
            }
        }

        if activated.len() == responsive.len() {
            let expected = activated.values().next().context("empty activated party set")?.clone();
            for (party, public) in &activated {
                anyhow::ensure!(
                    public == &expected,
                    "party {party} activated a conflicting public value for epoch {target_epoch}"
                );
            }
            tracing::info!(
                epoch = target_epoch,
                parties = activated.len(),
                "autonomous QUIC transition activated"
            );
            return Ok(expected);
        }

        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "epoch-{target_epoch} did not activate through QUIC before the protocol deadline; observations: {observations:?}"
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
/// to remove p2 only from the peer-QUIC Docker network while keeping its process and HTTP endpoint
/// healthy. Production party processes never enable this hook.
async fn maybe_pause_before_dynamic_refresh(
    client: &PartyClient,
    source_epoch: u64,
) -> anyhow::Result<()> {
    if std::env::var("TM_ACCEPTANCE_ENABLE_FAULT_HOOKS").as_deref() != Ok("1")
        || !environment_flag("TM_ACCEPTANCE_PAUSE_BEFORE_DYNAMIC_REFRESH")?
    {
        return Ok(());
    }
    let target_epoch = source_epoch
        .checked_add(1)
        .context("dynamic proactive refresh epoch exhausted at fault barrier")?;
    let mut material = Vec::with_capacity(16);
    material.extend_from_slice(&source_epoch.to_le_bytes());
    material.extend_from_slice(&target_epoch.to_le_bytes());
    let kind = AcceptanceDriverLatchKind::DynamicRotationOmission;
    let binding = acceptance_driver_binding(kind, &material);
    let party = PartyId::new(2)?;
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
            && armed.binding == Some(binding),
        "p2 held a different dynamic-rotation latch"
    );

    println!(
        "TM_ACCEPTANCE_DYNAMIC_REFRESH_BARRIER source_epoch={source_epoch} target_epoch={target_epoch}"
    );
    println!(
        "TM_ACCEPTANCE_DYNAMIC_REFRESH_LATCH_HELD party=2 source_epoch={source_epoch} target_epoch={target_epoch} binding={}",
        hex::encode(binding)
    );
    {
        use std::io::Write as _;
        std::io::stdout().flush()?;
    }
    tracing::warn!(source_epoch, target_epoch, "dynamic refresh fault barrier reached");
    wait_for_authenticated_driver_release(client, party, kind, binding).await?;
    println!(
        "TM_ACCEPTANCE_DYNAMIC_REFRESH_LATCH_RELEASED party=2 source_epoch={source_epoch} target_epoch={target_epoch} binding={}",
        hex::encode(binding)
    );
    Ok(())
}

async fn mine_confirmation(
    daemon: &MoneroDaemon<SimpleRequestTransport>,
    mining_address: &MoneroAddress,
    tx_hash: [u8; 32],
    poll_interval_ms: u64,
    timeout_seconds: u64,
) -> anyhow::Result<monero_wallet::block::Block> {
    // A locally submitted transaction first enters Monero's Dandelion++ stem pool. In an offline
    // regtest daemon there is no peer to relay it to, so it becomes mineable only after the local
    // embargo expires. This mirrors monero-oxide's own `mine_until_unlocked` test helper, with an
    // explicit deadline so a rejected or lost transaction cannot spin forever.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds);
    loop {
        let number = daemon.latest_block_number().await? + 1;
        daemon.generate_blocks(mining_address, 1).await?;
        let block = daemon.block_by_number(number).await?;
        if block.transactions.contains(&tx_hash) {
            return Ok(block);
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "transaction {} was not mined before the protocol deadline",
            hex::encode(tx_hash)
        );
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
        let actual = spec.members.iter().filter(|party| faulty.contains(party)).count();
        anyhow::ensure!(
            actual <= usize::from(spec.fault_bound),
            "epoch {} declares f={} but {} configured faulty members are present",
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

/// Add omission faults which begin only after the finite scenario chain has completed. Keeping
/// this separate from `TM_FAULTY_PARTIES` ensures the rotation-silent campaign does not obtain an
/// easier DKG/grow/shrink path by asking the client to ignore p2 before the Docker fault exists.
fn configured_dynamic_rotation_faulty_parties(
    scenario: &Scenario,
    source: &Committee,
    fault_bound: u16,
    already_faulty: &BTreeSet<PartyId>,
) -> anyhow::Result<BTreeSet<PartyId>> {
    source.validate_async_security_with_faults(fault_bound)?;
    let configured = std::env::var("TM_DYNAMIC_ROTATION_FAULTY_PARTIES").unwrap_or_default();
    let mut dynamic_only = BTreeSet::new();
    for value in configured.split(',').map(str::trim).filter(|value| !value.is_empty()) {
        let party = PartyId::new(value.parse::<u16>()?)?;
        scenario.party(party)?;
        source.member(party).with_context(|| {
            format!("dynamic rotation fault party {party} is not in epoch-{}", source.epoch)
        })?;
        anyhow::ensure!(
            dynamic_only.insert(party),
            "duplicate dynamic rotation faulty party {party}"
        );
    }

    let mut combined = already_faulty.clone();
    combined.extend(dynamic_only);
    let source_faults =
        source.members.iter().filter(|member| combined.contains(&member.id)).count();
    anyhow::ensure!(
        source_faults <= usize::from(fault_bound),
        "dynamic epoch {} declares f={fault_bound} but {source_faults} configured faulty members are present",
        source.epoch
    );
    if !configured.is_empty() {
        tracing::warn!(
            ?combined,
            source_epoch = source.epoch,
            "enabling faults only for the post-scenario dynamic refresh"
        );
    }
    Ok(combined)
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
    use super::{
        AcceptanceProtocolFaultBoundary, AcceptanceProtocolFaultSpecification, DepositHttpStatus,
        PartyId, allocation_request_party, deposit_status_reached_current_epoch,
        deterministic_roast_signers, parse_acceptance_protocol_fault_specification,
        validate_consolidation_fixture_economics,
        validate_cross_epoch_subthreshold_non_identifiability, validate_dynamic_refresh,
    };
    use crate::{
        committee::Committee,
        config::Scenario,
        deposit_wallet::{DepositWalletId, SweepId, derive_sweep_signing_session},
        identity::Identity,
        keys::{EpochPublic, PointBytes, scalar_for_party},
    };
    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};
    use std::collections::{BTreeMap, BTreeSet};

    fn polynomial_public(
        committee: Committee,
        key_id: [u8; 32],
        constant: u64,
        nonconstant: u64,
    ) -> EpochPublic {
        polynomial_public_with_coefficients(committee, key_id, &[constant, nonconstant])
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
        let source = polynomial_public(configured_shape(&scenario, 4), [0x5a; 32], 11, 17);
        let mut target = source.committee.clone();
        target.epoch = 5;
        for member in target.members.iter_mut().take(rotated_members) {
            let signing_seed = [u8::try_from(member.id.0).unwrap(); 32];
            let x25519_secret = [0x80_u8.wrapping_add(u8::try_from(member.id.0).unwrap()); 32];
            let rotated =
                Identity::from_test_secrets(member.id, 5, &signing_seed, x25519_secret).unwrap();
            member.encryption_key = rotated.encryption_public_key();
        }
        let refreshed = polynomial_public(target, source.key_id, 11, 23);
        (source, refreshed)
    }

    #[test]
    fn regtest_fixture_uses_separate_signing_and_bootstrap_x25519_secrets() {
        let scenario: Scenario =
            serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
        scenario.validate().unwrap();
        assert_eq!(scenario.committees.len(), 5);
        assert_eq!(scenario.proactive_refresh_interval_seconds, 15);

        let signing_seeds = [
            include_str!("../docker/demo-secrets/p1-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p2-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p3-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p4-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p5-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p6-signing-seed.hex"),
            include_str!("../docker/demo-secrets/p7-signing-seed.hex"),
        ];
        let bootstrap_x25519_secrets = [
            include_str!("../docker/demo-secrets/p1-bootstrap-x25519-secret.hex"),
            include_str!("../docker/demo-secrets/p2-bootstrap-x25519-secret.hex"),
            include_str!("../docker/demo-secrets/p3-bootstrap-x25519-secret.hex"),
            include_str!("../docker/demo-secrets/p4-bootstrap-x25519-secret.hex"),
            include_str!("../docker/demo-secrets/p5-bootstrap-x25519-secret.hex"),
            include_str!("../docker/demo-secrets/p6-bootstrap-x25519-secret.hex"),
            include_str!("../docker/demo-secrets/p7-bootstrap-x25519-secret.hex"),
        ];
        for (index, (encoded_signing_seed, encoded_bootstrap_secret)) in
            signing_seeds.into_iter().zip(bootstrap_x25519_secrets).enumerate()
        {
            let party_id = PartyId(u16::try_from(index + 1).unwrap());
            let signing_seed: [u8; 32] =
                hex::decode(encoded_signing_seed.trim()).unwrap().try_into().unwrap();
            let bootstrap_secret: [u8; 32] =
                hex::decode(encoded_bootstrap_secret.trim()).unwrap().try_into().unwrap();
            let party = scenario.party(party_id).unwrap();
            assert_eq!(
                Identity::signing_public_key_from_seed(&signing_seed).unwrap(),
                party.signing_key.0
            );
            let bootstrap_public =
                x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bootstrap_secret))
                    .to_bytes();
            assert_eq!(bootstrap_public, party.bootstrap_encryption_key.0);
        }

        let genesis = scenario.genesis_committee().unwrap();
        let grow = scenario
            .configured_key_rotation_target_policy(&genesis)
            .unwrap()
            .expect("configured grow");
        assert_eq!(grow.eligible().epoch, 1);
        assert_eq!(grow.eligible().threshold, 4);
        assert_eq!(grow.selection_size(), 7);
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
    }

    #[test]
    fn dynamic_refresh_accepts_an_immediate_n_minus_f_key_rotation_and_fresh_polynomial() {
        let (source, refreshed) = dynamic_refresh_fixture(3);
        assert_eq!(validate_dynamic_refresh(&source, &refreshed, 1).unwrap(), 3);
        let evidence =
            validate_cross_epoch_subthreshold_non_identifiability(&source, &refreshed).unwrap();
        assert_eq!(evidence.mixed_sets, 16);
        assert_eq!(evidence.threshold_boundary_sets, 12);
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
        let after_shrink =
            polynomial_public_with_coefficients(configured_shape(&scenario, 4), key_id, &[11, 29]);
        assert_eq!(before_shrink.committee.frost_index(PartyId(2)).unwrap(), 2);
        assert_eq!(after_shrink.committee.frost_index(PartyId(2)).unwrap(), 1);
        for removed in [PartyId(1), PartyId(3), PartyId(5)] {
            assert!(before_shrink.committee.member(removed).is_ok());
            assert!(after_shrink.committee.member(removed).is_err());
        }
        let shrink =
            validate_cross_epoch_subthreshold_non_identifiability(&before_shrink, &after_shrink)
                .unwrap();
        assert_eq!(shrink.mixed_sets, 252);
        assert_eq!(shrink.threshold_boundary_sets, 41);
    }

    #[test]
    fn dynamic_refresh_rejects_too_few_rotated_encryption_keys() {
        let (source, refreshed) = dynamic_refresh_fixture(2);
        let error = validate_dynamic_refresh(&source, &refreshed, 1).unwrap_err().to_string();
        assert!(error.contains("requires at least n-f=3"), "{error}");
    }

    #[test]
    fn dynamic_refresh_rejects_reused_share_polynomial() {
        let (source, mut refreshed) = dynamic_refresh_fixture(3);
        refreshed.verification_shares.clone_from(&source.verification_shares);
        refreshed.group_key = source.group_key;
        refreshed.validate().unwrap();
        let error = validate_dynamic_refresh(&source, &refreshed, 1).unwrap_err().to_string();
        assert!(error.contains("reused the source verification-share polynomial"), "{error}");
    }

    #[test]
    fn dynamic_refresh_rejects_non_immediate_epoch_and_signing_key_change() {
        let (source, mut skipped) = dynamic_refresh_fixture(3);
        skipped.committee.epoch = 6;
        let error = validate_dynamic_refresh(&source, &skipped, 1).unwrap_err().to_string();
        assert!(error.contains("must activate immediate epoch 5"), "{error}");

        let (_, mut changed_identity) = dynamic_refresh_fixture(3);
        changed_identity.committee.members[0].signing_key = [0xee; 32];
        changed_identity.validate().unwrap();
        let error =
            validate_dynamic_refresh(&source, &changed_identity, 1).unwrap_err().to_string();
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
    fn deposit_request_uses_the_first_responsive_committee_member() {
        let scenario: Scenario =
            serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
        let committee = scenario.genesis_committee().unwrap();
        assert_eq!(allocation_request_party(&committee, &BTreeSet::new()).unwrap(), PartyId(1));
        assert_eq!(
            allocation_request_party(&committee, &BTreeSet::from([PartyId(1)])).unwrap(),
            PartyId(2)
        );
        assert!(
            allocation_request_party(
                &committee,
                &committee.members.iter().map(|member| member.id).collect(),
            )
            .is_err()
        );
    }

    #[test]
    fn deposit_status_retries_a_historical_leader_until_the_current_handoff_arrives() {
        assert!(!deposit_status_reached_current_epoch(
            DepositHttpStatus::Permanent,
            PartyId(1),
            DepositHttpStatus::Permanent,
            PartyId(2),
        ));
        assert!(deposit_status_reached_current_epoch(
            DepositHttpStatus::Permanent,
            PartyId(2),
            DepositHttpStatus::Permanent,
            PartyId(2),
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
