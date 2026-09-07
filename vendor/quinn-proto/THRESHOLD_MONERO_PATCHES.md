# Threshold Monero patch

This is the published `quinn-proto` 0.11.16 crate, from upstream commit
`a96949f6cd257c665f544626af4e8ce668a40b30` (`quinn-proto` directory).
Original crate SHA-256:
`2f4bfc015262b9df63c8845072ce59068853ff5872180c2ce2f13038b970e560`.
The upstream Apache-2.0 and MIT licenses are retained.

The only source change is in `Connection::handle_first_packet`: propagate a
connection error raised by an Initial CONNECTION_CLOSE through the existing
failed-accept cleanup. Otherwise the connection enters `Draining` without a
close timer, retaining the endpoint entry and UDP socket until the idle timeout.
This occurs during ordinary reconnects when a close packet reaches a restarted
endpoint before any ClientHello.

Regression:

```sh
cargo test --locked --test quic_transport initial_close_packet_does_not_retain_endpoint_socket
```

It forwards a real close packet while discarding the preceding ClientHello and
requires both the expected rejection and bounded socket reuse.

Remove this local patch when a released upstream version passes that regression.
No transport deadline, certificate check, or application authentication is relaxed.
