use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "threshold-monero", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run one threshold-signing party (QUIC peer transport plus HTTP admin/control).
    Party {
        #[arg(long, env = "TM_PARTY_ID")]
        party_id: u16,
        #[arg(long, env = "TM_ADMIN_LISTEN_ADDR", default_value = "127.0.0.1:8080")]
        admin_listen_addr: std::net::SocketAddr,
        #[arg(long, env = "TM_QUIC_LISTEN_ADDR", default_value = "127.0.0.1:8443")]
        quic_listen_addr: std::net::SocketAddr,
        #[arg(long, env = "TM_QUIC_PRIVATE_KEY_FILE")]
        quic_private_key_file: std::path::PathBuf,
        #[arg(long, env = "TM_STATE_DIR")]
        state_dir: std::path::PathBuf,
        /// Stable Ed25519 signing seed. This seed is never used to derive X25519 material.
        #[arg(long, env = "TM_SIGNING_SEED_FILE")]
        signing_seed_file: std::path::PathBuf,
        /// Separately provisioned epoch-zero/joining-baseline X25519 private key.
        #[arg(long, env = "TM_BOOTSTRAP_X25519_SECRET_FILE")]
        bootstrap_x25519_secret_file: std::path::PathBuf,
        #[arg(long, env = "TM_SCENARIO_FILE")]
        scenario: std::path::PathBuf,
        /// Explicitly permit a non-demo testnet scenario. Mainnet remains disabled in this build.
        #[arg(long, env = "TM_ALLOW_TESTNET", default_value_t = false)]
        allow_testnet: bool,
        #[arg(long, env = "TM_ADMIN_BEARER_TOKEN_FILE")]
        admin_bearer_token_file: std::path::PathBuf,
        /// Optional credential dedicated to deposit-address clients. Deposit routes remain
        /// unavailable when no deposit wallet/view key is configured.
        #[arg(long, env = "TM_DEPOSIT_BEARER_TOKEN_FILE")]
        deposit_bearer_token_file: Option<std::path::PathBuf>,
        /// Private Monero view scalar enabling durable deposit-address allocation and scanning.
        #[arg(long, env = "TM_DEPOSIT_VIEW_KEY_FILE")]
        deposit_view_key_file: Option<std::path::PathBuf>,
        #[arg(long, env = "TM_DEPOSIT_BIRTH_HEIGHT")]
        deposit_birth_height: Option<u64>,
        #[arg(long, env = "TM_DEPOSIT_BIRTH_HASH")]
        deposit_birth_hash: Option<String>,
        /// Start this party's canonical epoch-zero DKG dealer after QUIC is bound. The operation
        /// is durable and idempotent, so an ordinary process restart cannot create another DKG.
        #[arg(long, env = "TM_AUTO_START_GENESIS", default_value_t = false)]
        auto_start_genesis: bool,
    },
    /// Run the Docker/regtest end-to-end acceptance flow.
    E2e {
        #[arg(long, env = "TM_SCENARIO_FILE")]
        scenario: std::path::PathBuf,
    },
    /// Parse canonical Monero transaction bytes and independently bind them to their txid.
    VerifyTransactionArtifact {
        #[arg(long)]
        transaction_hex: String,
        #[arg(long)]
        expected_txid: String,
    },
}

// Monero transaction construction and proof verification contain deep synchronous call chains.
// Keep the party runtime independent of Tokio's comparatively small default worker stack; an
// exhausted worker aborts the entire process rather than returning a recoverable protocol error.
const PARTY_RUNTIME_THREAD_STACK_BYTES: usize = 16 * 1024 * 1024;

fn main() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(PARTY_RUNTIME_THREAD_STACK_BYTES)
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "threshold_monero=info".into()),
        )
        .init();

    match Cli::parse().command {
        Commands::Party {
            party_id,
            admin_listen_addr,
            quic_listen_addr,
            quic_private_key_file,
            state_dir,
            signing_seed_file,
            bootstrap_x25519_secret_file,
            scenario,
            allow_testnet,
            admin_bearer_token_file,
            deposit_bearer_token_file,
            deposit_view_key_file,
            deposit_birth_height,
            deposit_birth_hash,
            auto_start_genesis,
        } => {
            use anyhow::Context as _;
            let party = threshold_monero::PartyId::new(party_id)?;
            let scenario = threshold_monero::Scenario::read(scenario).await?;
            match scenario.network {
                threshold_monero::NetworkKind::Regtest => {}
                threshold_monero::NetworkKind::Testnet => anyhow::ensure!(
                    allow_testnet && !scenario.demo_only,
                    "testnet requires --allow-testnet and a non-demo scenario"
                ),
                threshold_monero::NetworkKind::Mainnet => anyhow::bail!(
                    "mainnet party mode is disabled until an explicit production feature is audited"
                ),
            }
            let signing_seed =
                read_hex_32_secret(signing_seed_file, "stable Ed25519 signing seed").await?;
            let bootstrap_x25519_secret =
                read_hex_32_secret(bootstrap_x25519_secret_file, "bootstrap X25519 secret").await?;
            let configured_party = scenario.party(party)?;
            anyhow::ensure!(
                threshold_monero::identity::Identity::signing_public_key_from_seed(&signing_seed,)?
                    == configured_party.signing_key.0,
                "signing seed does not match the configured stable Ed25519 public key"
            );
            anyhow::ensure!(
                x25519_public_key_from_secret(&bootstrap_x25519_secret)
                    == configured_party.bootstrap_encryption_key.0,
                "bootstrap X25519 secret does not match the configured public key"
            );
            let quic_endpoint =
                build_quic_endpoint(party, quic_listen_addr, &scenario, quic_private_key_file)
                    .await?;
            anyhow::ensure!(
                deposit_bearer_token_file.is_none() || deposit_view_key_file.is_some(),
                "a deposit bearer token requires TM_DEPOSIT_VIEW_KEY_FILE"
            );
            let server = if let Some(view_key_file) = deposit_view_key_file {
                let birth_anchor = match (deposit_birth_height, deposit_birth_hash) {
                    (Some(height), Some(hash)) => {
                        Some(threshold_monero::deposit_wallet::ChainPoint::new(
                            height,
                            decode_hex_32(&hash, "deposit birth hash")?,
                        )?)
                    }
                    (None, None) => None,
                    _ => anyhow::bail!(
                        "TM_DEPOSIT_BIRTH_HEIGHT and TM_DEPOSIT_BIRTH_HASH must be set together"
                    ),
                };
                if scenario.network != threshold_monero::NetworkKind::Regtest {
                    anyhow::ensure!(
                        birth_anchor.is_some(),
                        "testnet deposits require an explicit birth height and block hash"
                    );
                }
                let private_view_scalar =
                    read_hex_32_secret(view_key_file, "deposit view scalar").await?;
                let confirmation_depth = u32::try_from(scenario.confirmation_blocks)
                    .context("confirmation_blocks exceeds the deposit worker limit")?;
                let worker = threshold_monero::deposit_worker::DepositWorkerConfig {
                    confirmation_depth,
                    maximum_fee_atomic_units: scenario.deposit_maximum_fee_atomic_units,
                    ..Default::default()
                };
                // Core identity restore and QUIC availability are independent of monerod. The
                // first deposit operation performs the pinned network/genesis probe, and a failed
                // RPC discards the client so a later worker tick can reconnect.
                let daemon = std::sync::Arc::new(
                    threshold_monero::reconnecting_monero::ReconnectingMoneroDaemon::new(
                        scenario.party(party)?.monerod_rpc_urls.iter().map(ToString::to_string),
                        scenario.network,
                        threshold_monero::deposit_worker::MoneroRpcLimits::default(),
                    )?,
                );
                let chain_source: std::sync::Arc<
                    dyn threshold_monero::deposit_worker::DepositChainSource,
                > = daemon.clone();
                let chain_readiness = daemon.readiness();
                let consolidation_backend: std::sync::Arc<
                    dyn threshold_monero::deposit_worker::DepositConsolidationBackend,
                > = daemon;
                threshold_monero::server::PartyServer::new_with_deposits(
                    party,
                    scenario,
                    state_dir,
                    &signing_seed,
                    &bootstrap_x25519_secret,
                    threshold_monero::server::PartyDepositConfig {
                        private_view_scalar,
                        birth_anchor,
                        worker,
                        chain_source,
                        consolidation_backend,
                        chain_readiness,
                    },
                )
                .await
            } else {
                threshold_monero::server::PartyServer::new(
                    party,
                    scenario,
                    state_dir,
                    &signing_seed,
                    &bootstrap_x25519_secret,
                )
                .await
            }
            .context("cannot restore durable party state")?;
            let admin_token = read_secret_token(admin_bearer_token_file)
                .await
                .context("cannot read admin bearer token")?;
            let deposit_token = match deposit_bearer_token_file {
                Some(path) => Some(
                    read_secret_token(path).await.context("cannot read deposit bearer token")?,
                ),
                None => None,
            };
            let mut credentials = vec![threshold_monero::auth::BearerCredentialConfig {
                principal: "operator".to_owned(),
                role: threshold_monero::auth::AuthRole::Admin,
                token_digest: threshold_monero::config::Hex32(
                    threshold_monero::auth::bearer_token_digest(&admin_token)?,
                ),
            }];
            if let Some(token) = &deposit_token {
                credentials.push(threshold_monero::auth::BearerCredentialConfig {
                    principal: "deposit-client".to_owned(),
                    role: threshold_monero::auth::AuthRole::Deposits,
                    token_digest: threshold_monero::config::Hex32(
                        threshold_monero::auth::bearer_token_digest(token)?,
                    ),
                });
            }
            let authenticator = threshold_monero::auth::BearerAuthenticator::from_config(
                threshold_monero::auth::BearerAuthConfig {
                    schema_version: threshold_monero::auth::BEARER_AUTH_SCHEMA_VERSION,
                    credentials,
                },
            )?;
            let runtime = std::sync::Arc::new(threshold_monero::quic_runtime::QuicRuntime::new(
                quic_endpoint,
                server.clone(),
                threshold_monero::quic_runtime::QuicRuntimeConfig::default(),
            )?);
            server.mark_quic_runtime_attached().context("cannot publish QUIC runtime readiness")?;
            let mut runtime_task = tokio::spawn(runtime.clone().run());
            if auto_start_genesis {
                let started = server
                    .start_canonical_genesis_if_eligible()
                    .await
                    .context("cannot durably start canonical epoch-zero DKG")?;
                tracing::info!(
                    party = %party,
                    eligible_dealer = started,
                    "autonomous genesis policy evaluated"
                );
            }
            let mut admin_task =
                tokio::spawn(server.clone().serve(admin_listen_addr, authenticator));
            tokio::select! {
                admin = &mut admin_task => {
                    server.mark_quic_runtime_detached();
                    runtime.shutdown();
                    let runtime_result = runtime_task.await
                        .context("QUIC runtime task panicked during control-plane shutdown")?;
                    admin
                        .context("party control service task panicked")?
                        .context("party control service failed")?;
                    runtime_result?;
                    Ok(())
                }
                runtime_result = &mut runtime_task => {
                    server.mark_quic_runtime_detached();
                    runtime.shutdown();
                    admin_task.abort();
                    let _ = admin_task.await;
                    match runtime_result.context("QUIC runtime task panicked")? {
                        Ok(()) => Err(anyhow::anyhow!(
                            "QUIC runtime stopped while the control service was still live"
                        )),
                        Err(error) => Err(error.into()),
                    }
                }
            }
        }
        Commands::E2e { scenario } => {
            use anyhow::Context as _;

            let scenario = threshold_monero::Scenario::read(scenario).await?;
            let verified_daemon = threshold_monero::deposit_worker::PinnedMoneroDaemon::connect(
                scenario.acceptance_monerod_rpc_url.to_string(),
                scenario.network,
                threshold_monero::deposit_worker::MoneroRpcLimits::default(),
            )
            .await
            .context("configured Monero daemon failed network/genesis verification")?;
            tracing::info!(
                network = ?verified_daemon.network(),
                genesis = %hex::encode(verified_daemon.genesis_hash()),
                "verified E2E Monero daemon chain identity"
            );
            threshold_monero::e2e::run(&scenario).await
        }
        Commands::VerifyTransactionArtifact { transaction_hex, expected_txid } => {
            verify_transaction_artifact(&transaction_hex, &expected_txid)
        }
    }
}

fn verify_transaction_artifact(transaction_hex: &str, expected_txid: &str) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use monero_oxide::transaction::Transaction;

    let bytes = hex::decode(transaction_hex).context("transaction hex is invalid")?;
    anyhow::ensure!(!bytes.is_empty(), "transaction artifact is empty");
    let expected = decode_hex_32(expected_txid, "expected transaction id")?;
    let mut cursor = std::io::Cursor::new(bytes.as_slice());
    let transaction =
        Transaction::read(&mut cursor).context("transaction artifact is not canonical Monero")?;
    anyhow::ensure!(
        usize::try_from(cursor.position())? == bytes.len(),
        "transaction artifact has trailing bytes"
    );
    let mut canonical = Vec::with_capacity(bytes.len());
    transaction.write(&mut canonical)?;
    anyhow::ensure!(canonical == bytes, "transaction artifact is not canonically encoded");
    let derived = transaction.hash();
    anyhow::ensure!(
        derived == expected,
        "transaction artifact derives txid {}, expected {}",
        hex::encode(derived),
        expected_txid
    );
    println!(
        "TM_TRANSACTION_ARTIFACT_VERIFIED txid={} bytes={}",
        hex::encode(derived),
        bytes.len()
    );
    Ok(())
}

async fn build_quic_endpoint(
    party: threshold_monero::PartyId,
    listen: std::net::SocketAddr,
    scenario: &threshold_monero::Scenario,
    private_key_file: std::path::PathBuf,
) -> anyhow::Result<threshold_monero::quic_transport::QuicPeerEndpoint> {
    use anyhow::Context as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use threshold_monero::quic_transport::{
        LocalTlsIdentity, PinnedPeerCertificate, QuicPeerEndpoint, QuicTransportConfig,
    };

    let configured = scenario.party(party)?;
    let local_certificate = CertificateDer::from(
        tokio::fs::read(&configured.quic_certificate_file)
            .await
            .context("cannot read local QUIC certificate")?,
    );
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        tokio::fs::read(private_key_file).await.context("cannot read local QUIC private key")?,
    ));
    let identity = LocalTlsIdentity::new(vec![local_certificate], private_key)
        .context("invalid local QUIC identity")?;
    let mut peers = Vec::with_capacity(scenario.parties.len().saturating_sub(1));
    for peer in &scenario.parties {
        if peer.id == party {
            continue;
        }
        peers.push(PinnedPeerCertificate {
            party: peer.id,
            server_name: peer.quic_server_name.clone(),
            leaf_certificate: CertificateDer::from(
                tokio::fs::read(&peer.quic_certificate_file).await.with_context(|| {
                    format!("cannot read QUIC certificate for party {}", peer.id)
                })?,
            ),
        });
    }
    Ok(QuicPeerEndpoint::bind(
        listen,
        party,
        scenario.quic_network_id()?,
        identity,
        peers,
        QuicTransportConfig::default(),
    )
    .context("cannot bind mutually authenticated QUIC endpoint")?)
}

async fn read_secret_token(
    path: std::path::PathBuf,
) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bytes = zeroize::Zeroizing::new(tokio::fs::read(path).await?);
    while bytes.last().is_some_and(|byte| matches!(byte, b'\n' | b'\r')) {
        bytes.pop();
    }
    threshold_monero::auth::bearer_token_digest(&bytes)?;
    Ok(bytes)
}

async fn read_hex_32_secret(
    path: std::path::PathBuf,
    description: &'static str,
) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
    use zeroize::Zeroize;

    let mut encoded = tokio::fs::read_to_string(path).await?;
    let mut decoded = hex::decode(encoded.trim())?;
    encoded.zeroize();
    let result = decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{description} must contain exactly 32 bytes"));
    decoded.zeroize();
    Ok(zeroize::Zeroizing::new(result?))
}

fn x25519_public_key_from_secret(secret: &zeroize::Zeroizing<[u8; 32]>) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(**secret);
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

fn decode_hex_32(encoded: &str, description: &'static str) -> anyhow::Result<[u8; 32]> {
    let decoded = hex::decode(encoded.trim())?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{description} must contain exactly 32 bytes"))
}
