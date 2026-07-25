#!/bin/sh
set -eu

# Reproducible, public test fixtures for the local Compose deployment. This is deliberately not a
# production PKI generator: every private seed is deterministically derived from a committed label.

usage() {
  echo "usage: $0 --check | --write" >&2
  exit 2
}

[ "$#" -eq 1 ] || usage
mode=$1
[ "$mode" = "--check" ] || [ "$mode" = "--write" ] || usage

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cert_dir="$script_dir/quic-pki"
secret_dir="$script_dir/demo-secrets"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/threshold-monero-demo-quic-pki.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required" >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required" >&2
  exit 1
}

for party in 1 2 3 4 5 6 7 8; do
  server_name="p${party}.threshold-monero.invalid"
  key_file="$work_dir/p${party}-quic-key.der"
  cert_file="$work_dir/p${party}-cert.der"
  extensions_file="$work_dir/p${party}-extensions.cnf"

  python3 - "$party" "$key_file" <<'PY'
import hashlib
import pathlib
import sys

party = int(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
seed = hashlib.sha256(
    f"threshold-monero/public-demo/quic-ed25519/v1/party-{party}".encode("ascii")
).digest()

# RFC 8410 OneAsymmetricKey for an Ed25519 seed:
# SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING seed } }
destination.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + seed)
PY

  # The generated certificate is byte-for-byte reproducible: Ed25519 signatures are deterministic,
  # and the subject, serial, validity window, extensions, and PKCS#8 key are all fixed.
  printf '%s\n' \
    '[v3_leaf]' \
    'basicConstraints = critical,CA:FALSE' \
    'keyUsage = critical,digitalSignature' \
    'extendedKeyUsage = serverAuth,clientAuth' \
    "subjectAltName = DNS:${server_name}" \
    'subjectKeyIdentifier = hash' \
    >"$extensions_file"

  openssl x509 -new \
    -key "$key_file" -keyform DER \
    -subj "/O=Threshold Monero Demo/OU=Public deterministic fixture/CN=${server_name}" \
    -set_serial "$party" \
    -not_before 20250101000000Z \
    -not_after 21250101000000Z \
    -extfile "$extensions_file" -extensions v3_leaf \
    -outform DER -out "$cert_file"

  openssl pkey -in "$key_file" -inform DER -noout -check >/dev/null
  openssl x509 -in "$cert_file" -inform DER -noout -checkhost "$server_name" >/dev/null
done

python3 - "$work_dir" >"$work_dir/SHA256SUMS" <<'PY'
import hashlib
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])
for path in sorted(directory.glob("p*-cert.der")):
    print(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
PY

if [ "$mode" = "--write" ]; then
  mkdir -p -- "$cert_dir" "$secret_dir"
  for party in 1 2 3 4 5 6 7 8; do
    install -m 0644 "$work_dir/p${party}-cert.der" "$cert_dir/p${party}-cert.der"
    # Compose file-backed secrets preserve host ownership and mode. These keys are intentionally
    # public fixtures, so make them readable by the image's unprivileged UID on every host.
    install -m 0644 "$work_dir/p${party}-quic-key.der" \
      "$secret_dir/p${party}-quic-key.der"
  done
  install -m 0644 "$work_dir/SHA256SUMS" "$cert_dir/SHA256SUMS"
  echo "wrote deterministic demo QUIC fixtures"
  exit 0
fi

for party in 1 2 3 4 5 6 7 8; do
  cmp "$work_dir/p${party}-cert.der" "$cert_dir/p${party}-cert.der"
  cmp "$work_dir/p${party}-quic-key.der" "$secret_dir/p${party}-quic-key.der"
done
cmp "$work_dir/SHA256SUMS" "$cert_dir/SHA256SUMS"

cert_count=$(find "$cert_dir" -type f -name 'p*-cert.der' | wc -l | tr -d ' ')
unique_count=$(python3 - "$cert_dir" <<'PY'
import hashlib
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])
print(len({hashlib.sha256(path.read_bytes()).digest() for path in directory.glob("p*-cert.der")}))
PY
)
[ "$cert_count" = 8 ] && [ "$unique_count" = 8 ] || {
  echo "expected eight distinct pinned certificates" >&2
  exit 1
}

echo "deterministic demo QUIC fixtures are current and all eight pins are distinct"
