//! Lazy, reconnecting adapter for the concrete Monero RPC backend.
//!
//! Party identity restore, QUIC bind, DKG, QUAL, key rotation, and proactive refresh must not
//! depend on an RPC daemon being online at process start. This adapter performs the pinned
//! network/genesis probe on the first deposit operation. Any failed operation invalidates the
//! cached client, so the next bounded worker tick rotates to another independently configured
//! endpoint, reconnects, and re-verifies chain identity.
//!
//! This adapter does not vote across RPC endpoints. Consolidation, abandonment, and settlement
//! authority already require n-f party attestations whose application predicates reproduce their
//! chain-dependent facts against each party's local scanner and daemon. First-use/permanence is
//! still only a local safety fence and needs separate portable certification. Accordingly, a party
//! and all of its endpoints form one fault domain; deployments must ensure at most f committee
//! identities are Byzantine or have faulty chain observation.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use monero_oxide::transaction::Transaction;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::{
    NetworkKind,
    config::MAX_MONEROD_ENDPOINTS_PER_PARTY,
    deposit_wallet::{DepositAddressDeriver, SignedSweepTransaction},
    deposit_worker::{
        ChainFuture, ChainSourceError, DepositBlockScanCursor, DepositBlockScanResult,
        DepositChainSource, DepositConsolidationBackend, DepositOutputIndexBackend,
        DepositWorkerState, MoneroRpcLimits, PinnedMoneroDaemon, PreparedFrostlassSweep, SweepPlan,
    },
};

/// Independently report chain/deposit readiness without conflating it with core party liveness.
#[derive(Clone, Debug)]
pub struct DepositChainReadiness {
    ready: Arc<AtomicBool>,
}

impl DepositChainReadiness {
    fn new() -> Self {
        Self { ready: Arc::new(AtomicBool::new(false)) }
    }

    /// Whether a daemon client has passed network/genesis verification and has not since failed.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    fn set(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }
}

#[derive(Clone)]
struct ConnectedDaemon {
    endpoint_index: usize,
    daemon: Arc<PinnedMoneroDaemon>,
}

/// A daemon backend whose first network operation is lazy and whose failed client is discarded.
#[derive(Clone)]
pub struct ReconnectingMoneroDaemon {
    endpoints: Arc<[Arc<str>]>,
    expected_network: NetworkKind,
    limits: MoneroRpcLimits,
    cached: Arc<Mutex<Option<ConnectedDaemon>>>,
    next_endpoint: Arc<AtomicUsize>,
    readiness: DepositChainReadiness,
}

impl std::fmt::Debug for ReconnectingMoneroDaemon {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReconnectingMoneroDaemon")
            .field("endpoint_count", &self.endpoints.len())
            .field("expected_network", &self.expected_network)
            .field("ready", &self.readiness.is_ready())
            .finish_non_exhaustive()
    }
}

impl ReconnectingMoneroDaemon {
    /// Construct a bounded, lazy endpoint rotation without performing network I/O.
    ///
    /// Only one endpoint is attempted per deposit operation. A failed identity probe or RPC moves
    /// the cursor before returning, so the next independently bounded worker tick tries the next
    /// endpoint instead of multiplying one operation's deadline by the endpoint count.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, blank, or duplicate endpoint set.
    pub fn new<I, S>(
        endpoints: I,
        expected_network: NetworkKind,
        limits: MoneroRpcLimits,
    ) -> Result<Self, ChainSourceError>
    where
        I: IntoIterator<Item = S>,
        S: Into<Arc<str>>,
    {
        let endpoints = endpoints.into_iter().map(Into::into).collect::<Vec<Arc<str>>>();
        if endpoints.is_empty()
            || endpoints.len() > MAX_MONEROD_ENDPOINTS_PER_PARTY
            || endpoints.iter().any(|endpoint| endpoint.trim().is_empty())
            || endpoints
                .iter()
                .enumerate()
                .any(|(index, endpoint)| endpoints[..index].contains(endpoint))
        {
            return Err(ChainSourceError::Invalid(
                "invalid reconnecting Monero endpoint set".to_owned(),
            ));
        }
        Ok(Self {
            endpoints: endpoints.into(),
            expected_network,
            limits,
            cached: Arc::new(Mutex::new(None)),
            next_endpoint: Arc::new(AtomicUsize::new(0)),
            readiness: DepositChainReadiness::new(),
        })
    }

    /// Whether this process currently has a daemon client whose network and genesis were pinned.
    ///
    /// A subsequent RPC failure changes this to false. It is intentionally deposit readiness,
    /// not core protocol liveness.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.readiness.is_ready()
    }

    /// Cloneable status handle for the HTTP control-plane readiness report.
    #[must_use]
    pub fn readiness(&self) -> DepositChainReadiness {
        self.readiness.clone()
    }

    async fn connected(&self) -> Result<ConnectedDaemon, ChainSourceError> {
        let mut cached = self.cached.lock().await;
        if let Some(daemon) = cached.as_ref() {
            return Ok(daemon.clone());
        }
        let endpoint_index =
            self.next_endpoint.fetch_add(1, Ordering::AcqRel) % self.endpoints.len();
        let endpoint = self.endpoints[endpoint_index].to_string();
        let daemon = timeout(
            self.limits.request_timeout,
            PinnedMoneroDaemon::connect(endpoint, self.expected_network, self.limits),
        )
        .await
        .map_err(|_| ChainSourceError::Rpc("Monero endpoint identity probe timed out".to_owned()))?
        .map_err(|error| ChainSourceError::Rpc(error.to_string()))?;
        let connected = ConnectedDaemon { endpoint_index, daemon: Arc::new(daemon) };
        *cached = Some(connected.clone());
        self.readiness.set(true);
        Ok(connected)
    }

    async fn invalidate(&self, failed: &ConnectedDaemon) {
        let mut cached = self.cached.lock().await;
        if cached.as_ref().is_some_and(|current| Arc::ptr_eq(&current.daemon, &failed.daemon)) {
            *cached = None;
            self.next_endpoint.store(failed.endpoint_index.wrapping_add(1), Ordering::Release);
            self.readiness.set(false);
        }
    }

    async fn chain_connection(&self) -> Result<ConnectedDaemon, ChainSourceError> {
        match self.connected().await {
            Ok(daemon) => Ok(daemon),
            Err(error) => {
                self.readiness.set(false);
                Err(error)
            }
        }
    }

    async fn consolidation_connection(&self) -> Result<ConnectedDaemon, ChainSourceError> {
        self.chain_connection().await.map_err(|error| {
            ChainSourceError::Consolidation(format!("Monero daemon is unavailable: {error}"))
        })
    }
}

impl DepositChainSource for ReconnectingMoneroDaemon {
    fn latest_height(&self) -> ChainFuture<'_, u64> {
        Box::pin(async move {
            let daemon = self.chain_connection().await?;
            let result = daemon.daemon.latest_height().await;
            if result.is_err() {
                self.invalidate(&daemon).await;
            }
            result
        })
    }

    fn block_hash(&self, height: u64) -> ChainFuture<'_, [u8; 32]> {
        Box::pin(async move {
            let daemon = self.chain_connection().await?;
            let result = daemon.daemon.block_hash(height).await;
            if result.is_err() {
                self.invalidate(&daemon).await;
            }
            result
        })
    }

    fn scanned_block_evidence<'a>(
        &'a self,
        height: u64,
        deriver: &'a DepositAddressDeriver,
        output_index: &'a dyn DepositOutputIndexBackend,
        portable_snapshot: [u8; 32],
        resume: Option<DepositBlockScanCursor>,
    ) -> ChainFuture<'a, DepositBlockScanResult> {
        Box::pin(async move {
            let daemon = self.chain_connection().await?;
            let result = daemon
                .daemon
                .scanned_block_evidence(height, deriver, output_index, portable_snapshot, resume)
                .await;
            if result.is_err() {
                self.invalidate(&daemon).await;
            }
            result
        })
    }

    fn full_transaction(
        &self,
        transaction: [u8; 32],
    ) -> ChainFuture<'_, Option<SignedSweepTransaction>> {
        Box::pin(async move {
            let daemon = self.chain_connection().await?;
            let result = daemon.daemon.full_transaction(transaction).await;
            if result.is_err() {
                self.invalidate(&daemon).await;
            }
            result
        })
    }
}

impl DepositConsolidationBackend for ReconnectingMoneroDaemon {
    fn prepare_sweep<'a>(
        &'a self,
        state: &'a DepositWorkerState,
        deriver: &'a DepositAddressDeriver,
        plan: &'a SweepPlan,
    ) -> ChainFuture<'a, PreparedFrostlassSweep> {
        Box::pin(async move {
            let daemon = self.consolidation_connection().await?;
            let result = daemon.daemon.prepare_sweep(state, deriver, plan).await;
            if result.is_err() {
                self.invalidate(&daemon).await;
            }
            result
        })
    }

    fn validate_prepared_sweep<'a>(
        &'a self,
        state: &'a DepositWorkerState,
        prepared: &'a PreparedFrostlassSweep,
    ) -> ChainFuture<'a, ()> {
        Box::pin(async move {
            let daemon = self.consolidation_connection().await?;
            let result = daemon.daemon.validate_prepared_sweep(state, prepared).await;
            if result.is_err() {
                self.invalidate(&daemon).await;
            }
            result
        })
    }

    fn publish_sweep<'a>(&'a self, transaction: &'a Transaction) -> ChainFuture<'a, ()> {
        Box::pin(async move {
            let daemon = self.consolidation_connection().await?;
            let result = daemon.daemon.publish_sweep(transaction).await;
            if result.is_err() {
                self.invalidate(&daemon).await;
            }
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    #[test]
    fn construction_is_network_lazy_and_reports_deposit_unready() {
        let daemon = ReconnectingMoneroDaemon::new(
            ["http://127.0.0.1:1"],
            NetworkKind::Regtest,
            MoneroRpcLimits::default(),
        )
        .unwrap();
        assert!(!daemon.is_ready());
    }

    #[test]
    fn endpoint_set_is_finite_nonempty_and_unique() {
        for endpoints in [vec![], vec![""], vec!["http://a", "http://a"]] {
            assert!(
                ReconnectingMoneroDaemon::new(
                    endpoints,
                    NetworkKind::Regtest,
                    MoneroRpcLimits::default(),
                )
                .is_err()
            );
        }
        let oversized = (0..=MAX_MONEROD_ENDPOINTS_PER_PARTY)
            .map(|index| format!("http://daemon-{index}"))
            .collect::<Vec<_>>();
        assert!(
            ReconnectingMoneroDaemon::new(
                oversized,
                NetworkKind::Regtest,
                MoneroRpcLimits::default(),
            )
            .is_err()
        );
    }

    async fn malformed_rpc_server() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut request = [0_u8; 4096];
                    let _ = stream.read(&mut request).await;
                    let response =
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
                    let _ = stream.write_all(response).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (endpoint, task)
    }

    async fn stalled_rpc_server() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut request = [0_u8; 4096];
                    let _ = stream.read(&mut request).await;
                    let held_open = stream;
                    std::future::pending::<()>().await;
                    drop(held_open);
                });
            }
        });
        (endpoint, task)
    }

    #[tokio::test]
    async fn stalled_lying_and_down_endpoints_each_fail_within_one_deadline_and_rotate() {
        let (stalled, stalled_task) = stalled_rpc_server().await;
        let (lying, lying_task) = malformed_rpc_server().await;
        let unavailable = "http://127.0.0.1:9".to_owned();
        let per_attempt = Duration::from_millis(100);
        let daemon = ReconnectingMoneroDaemon::new(
            [stalled, lying, unavailable],
            NetworkKind::Regtest,
            MoneroRpcLimits { request_timeout: per_attempt, ..Default::default() },
        )
        .unwrap();

        for expected_cursor in 1..=3 {
            let started = Instant::now();
            assert!(daemon.latest_height().await.is_err());
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "one failed endpoint exceeded its bounded operation deadline"
            );
            assert_eq!(daemon.next_endpoint.load(Ordering::Acquire), expected_cursor);
            assert!(!daemon.is_ready());
        }

        stalled_task.abort();
        lying_task.abort();
    }
}
