#!/bin/sh
set -eu

readonly expected_upstream_commit=946ec5f00ff071b129758ee8cba5528539fccfe4
readonly script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
readonly manifest=THRESHOLD_MONERO_SOURCES.sha256
readonly multisig_source=monero-oxide/wallet/src/send/multisig.rs
readonly direct_sign_error='direct TransactionSignMachine::sign is disabled; bind the transaction before releasing a signature share'

cd "$script_dir"

if ! grep -Fq "\`$expected_upstream_commit\`" THRESHOLD_MONERO_PATCHES.md; then
  echo "vendor provenance document does not name the reviewed upstream commit" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum --check "$manifest"
elif command -v shasum >/dev/null 2>&1; then
  shasum --algorithm 256 --check "$manifest"
else
  echo "sha256sum or shasum is required to verify vendored sources" >&2
  exit 1
fi

if grep -Eq 'pub[[:space:]]+fn[[:space:]]+multisig[[:space:]]*\(' "$multisig_source"; then
  echo "zero-context multisig compatibility entry point must not be restored" >&2
  exit 1
fi
if ! grep -Fq 'if context == [0; 32]' "$multisig_source"; then
  echo "multisig_with_context no longer rejects the all-zero context sentinel" >&2
  exit 1
fi
if ! grep -Fq "$direct_sign_error" "$multisig_source"; then
  echo "generic TransactionSignMachine::sign no longer fails closed" >&2
  exit 1
fi
if [ "$(grep -Fc 'sign_bound_transaction' "$multisig_source")" -ne 2 ]; then
  echo "private transaction-bound signing body has an unexpected definition or call site" >&2
  exit 1
fi
if ! grep -Fq 'self.machine.sign_bound_transaction(self.commitments)' "$multisig_source"; then
  echo "transaction-bound release no longer invokes the private signing body" >&2
  exit 1
fi

echo "verified Threshold Monero vendored monero-oxide sources at $expected_upstream_commit"
