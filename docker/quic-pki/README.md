# Public demo QUIC certificate pins

These eight DER files are deterministic, self-signed Ed25519 leaf certificates for the local
Compose scenario. They are public trust anchors pinned byte-for-byte by party ID. Their matching
private keys are committed under `docker/demo-secrets` solely so the demo can be reproduced.

They provide realistic mutual-TLS wiring tests, not secrecy, identity assurance, revocation,
rotation, forward secrecy for stored traffic, or protection from a compromised host. Never use
these certificates or keys outside the private local demo. A real deployment needs independently
generated keys, authenticated enrollment, protected private-key storage, expiry/rotation, and a
revocation or membership-removal procedure.

Regenerate or verify the fixtures from the repository root:

```sh
./docker/generate-demo-quic-pki.sh --write
./docker/generate-demo-quic-pki.sh --check
```
