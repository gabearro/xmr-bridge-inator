# Demo secrets only

Every signing seed, bootstrap X25519 secret, QUIC private key, and per-party HTTP bearer token in
this directory is public, deterministic, committed test material. The signing seeds and bootstrap
X25519 secrets are independently generated key families: a signing seed cannot reproduce an
epoch-zero receiver secret. The default Compose file exposes each party credential only to its
matching signer; the acceptance client receives all bearer tokens so it can drive and audit the
harness. The values provide no security and must never be reused on testnet, stagenet, mainnet, or
any production deployment.

Production secret provisioning is an external deployment-owner responsibility and is not
implemented or tested by this repository. A deployment must replace these file-backed fixtures
with independently generated signing, bootstrap X25519, and transport keys, provide authenticated
certificate enrollment/revocation/rotation, and choose suitable secret-manager or HSM custody. A
party must never be able to read another party's signing seed, bootstrap X25519 secret, QUIC
private key, bearer capability, or persisted share volume.

`../generate-demo-quic-pki.sh --check` verifies that the checked-in fixtures match the deterministic
recipe. The fixture files are deliberately world-readable because file-backed Docker Compose
secrets preserve host ownership/mode and the containers run as an unrelated unprivileged UID. That
is acceptable only because every value here is public. Real secret files must instead be delivered
with ownership readable by the service UID or through a secret manager. Reproducibility here is a
testing feature and the opposite of production key generation.
