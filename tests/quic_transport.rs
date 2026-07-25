use std::time::Duration;

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use threshold_monero::{
    PartyId, SessionId,
    identity::SignedEnvelope,
    key_rotation::KeyRotationWire,
    quic_transport::{
        AvssOperation, KeyRotationOperation, LocalTlsIdentity, PeerRequest, PeerResponse,
        PinnedPeerCertificate, QuicPeerEndpoint, QuicTransportConfig, RequestId,
    },
};

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

fn test_config() -> QuicTransportConfig {
    QuicTransportConfig {
        handshake_timeout: Duration::from_secs(3),
        stream_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(10),
        keep_alive_interval: Some(Duration::from_secs(1)),
        ..Default::default()
    }
}

fn key_rotation_wire() -> KeyRotationWire {
    KeyRotationWire::Advertisement(SignedEnvelope {
        version: 1,
        committee: [0x51; 32],
        epoch: 4,
        session: SessionId([0x52; 32]),
        from: PartyId(1),
        to: None,
        sequence: 0,
        payload: b"next epoch x25519 key".to_vec(),
        signature: [0x53; 64],
    })
}

#[tokio::test]
async fn mutually_authenticated_connection_round_trips_correlated_requests() {
    let one = TestIdentity::generate(PartyId(1));
    let two = TestIdentity::generate(PartyId(2));
    let endpoint_two = QuicPeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        PartyId(2),
        TEST_NETWORK,
        two.local(),
        [one.pin(PartyId(1))],
        test_config(),
    )
    .unwrap();
    let two_addr = endpoint_two.local_addr().unwrap();
    let endpoint_one = QuicPeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        PartyId(1),
        TEST_NETWORK,
        one.local(),
        [two.pin(PartyId(2))],
        test_config(),
    )
    .unwrap();

    let expected_rotation = key_rotation_wire();
    let avss_request = PeerRequest::Avss {
        operation: AvssOperation::Deliver,
        body: b"encrypted AVSS wire".to_vec(),
    };
    let rotation_request = PeerRequest::key_rotation(&expected_rotation).unwrap();
    let request_id =
        RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &avss_request).unwrap();
    let rotation_request_id =
        RequestId::for_peer_request(TEST_NETWORK, PartyId(1), PartyId(2), &rotation_request)
            .unwrap();
    let server_rotation = expected_rotation.clone();
    let server = tokio::spawn(async move {
        let connection = endpoint_two.accept().await.unwrap();
        assert_eq!(connection.peer_party(), PartyId(1));
        let request = connection.accept_request().await.unwrap();
        assert_eq!(request.peer_party(), PartyId(1));
        assert_eq!(request.request_id(), request_id);
        assert_eq!(
            request.request(),
            &PeerRequest::Avss {
                operation: AvssOperation::Deliver,
                body: b"encrypted AVSS wire".to_vec(),
            }
        );
        request.respond(PeerResponse::Success { body: b"accepted".to_vec() }).await.unwrap();

        let request = connection.accept_request().await.unwrap();
        assert_eq!(request.request_id(), rotation_request_id);
        let PeerRequest::KeyRotation { operation, body } = request.request() else {
            panic!("key rotation used another QUIC request family");
        };
        assert_eq!(*operation, KeyRotationOperation::Advertisement);
        assert_eq!(operation.decode_wire(body).unwrap(), server_rotation);
        request.respond(PeerResponse::Success { body: b"persisted".to_vec() }).await.unwrap();
        endpoint_two.wait_idle().await;
    });

    let connection = endpoint_one.connect(PartyId(2), two_addr).await.unwrap();
    assert_eq!(connection.peer_party(), PartyId(2));
    let response = connection.request(request_id, avss_request).await.unwrap();
    assert_eq!(response, PeerResponse::Success { body: b"accepted".to_vec() });

    let response = connection.request(rotation_request_id, rotation_request).await.unwrap();
    assert_eq!(response, PeerResponse::Success { body: b"persisted".to_vec() });
    connection.close(b"test complete");
    endpoint_one.close(b"test complete");
    server.await.unwrap();
}

#[tokio::test]
async fn exact_peer_pins_accept_members_and_reject_unpinned_certificates() {
    let one = TestIdentity::generate(PartyId(1));
    let two = TestIdentity::generate(PartyId(2));
    let three = TestIdentity::generate(PartyId(3));
    let endpoint_two = QuicPeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        PartyId(2),
        TEST_NETWORK,
        two.local(),
        [one.pin(PartyId(1))],
        test_config(),
    )
    .unwrap();
    let two_addr = endpoint_two.local_addr().unwrap();
    let endpoint_three = QuicPeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        PartyId(3),
        TEST_NETWORK,
        three.local(),
        [two.pin(PartyId(2))],
        test_config(),
    )
    .unwrap();

    let accept = tokio::spawn(async move { endpoint_two.accept().await });
    // TLS 1.3 lets the client authenticate the server before it necessarily observes the
    // server-side client-certificate rejection. If `connect` returns first, the first request must
    // still fail closed and the server must never produce an authenticated connection.
    if let Ok(connection) = endpoint_three.connect(PartyId(2), two_addr).await {
        let body = PeerRequest::Avss { operation: AvssOperation::Deliver, body: vec![] };
        let request = connection
            .request(
                RequestId::for_peer_request(TEST_NETWORK, PartyId(3), PartyId(2), &body).unwrap(),
                body,
            )
            .await;
        assert!(request.is_err(), "server accepted an unpinned client certificate");
    }
    assert!(accept.await.unwrap().is_err());
}

#[tokio::test]
async fn clients_reject_a_server_that_does_not_match_the_exact_leaf_pin() {
    let one = TestIdentity::generate(PartyId(1));
    let actual_two = TestIdentity::generate(PartyId(2));
    // Same authenticated DNS name, different key and leaf DER. Hostname validation alone would
    // accept either certificate if they shared a CA; this endpoint trusts only the exact leaf.
    let expected_two = TestIdentity::generate(PartyId(2));
    let endpoint_two = QuicPeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        PartyId(2),
        TEST_NETWORK,
        actual_two.local(),
        [one.pin(PartyId(1))],
        test_config(),
    )
    .unwrap();
    let two_addr = endpoint_two.local_addr().unwrap();
    let endpoint_one = QuicPeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        PartyId(1),
        TEST_NETWORK,
        one.local(),
        [expected_two.pin(PartyId(2))],
        test_config(),
    )
    .unwrap();

    let (client, _server) =
        tokio::join!(endpoint_one.connect(PartyId(2), two_addr), endpoint_two.accept());
    assert!(client.is_err(), "client accepted a server whose leaf DER was not pinned");
}
