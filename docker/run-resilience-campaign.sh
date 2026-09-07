#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: docker/run-resilience-campaign.sh MODE

MODE is one of:
  preflight           static current-schema, secret, QUIC, health, and persistence validation
  rust                complete all-target Rust suite with serial test execution
  clean               full deposit/consolidation acceptance on a fresh private chain
  observer-byzantine  one party observer forks, stalls, then stops while full acceptance continues
  avss-crash          full acceptance plus p3 restart after its durable epoch-0 dealer start
  deposit-restart     full acceptance plus p2 restart after deposit mining, before maturity
  deposit-ttl         exact unused-expiry, non-reuse, and used-address permanence boundaries
  consolidation-silent  full acceptance plus selected-signer omission during consolidation
  consolidation-bootstrap-silent  stop the slot-zero intent proposer before bootstrap BA
  silent              protocol-only silent-p1 omission and autonomous QUAL round advance
  deposit-silent      allocation/funding/permanence with silent p1 and no consolidation
  leader-down         full signing plus an exact same-committee refresh after p1 is stopped
  rotation-silent     disconnect one selected epoch-4 member's QUIC, then require dynamic epoch 5
  network-restart     stop all parties across an overdue refresh, restore, then sign a real sweep
  proactive-deadline  restart one selected source member inside the exact 15-second deadline
  qual-crash-silent   protocol-only silent p1 plus p3 restart in the bounded QUAL window
  all                 run every mode in the order above

The script never builds an image. Build the pinned images only after the source tree is green.
By default, every Compose mode destroys only its dedicated threshold-monero-resilience-* demo
volumes before starting. Set TM_CAMPAIGN_PROJECT_SUFFIX to 1-4 lowercase letters or digits to use
a fresh suffixed project without deleting a collided project. Evidence is left under artifacts/.
EOF
  exit 2
}

[[ $# -eq 1 ]] || usage
mode=$1
case "$mode" in
  preflight|rust|clean|observer-byzantine|avss-crash|deposit-restart|deposit-ttl|consolidation-silent|consolidation-bootstrap-silent|silent|deposit-silent|leader-down|rotation-silent|network-restart|proactive-deadline|qual-crash-silent|all) ;;
  *) usage ;;
esac

project_suffix=""
project_suffix_enabled=0
if [[ "${TM_CAMPAIGN_PROJECT_SUFFIX+x}" == x ]]; then
  project_suffix=$TM_CAMPAIGN_PROJECT_SUFFIX
  if (( ${#project_suffix} < 1 || ${#project_suffix} > 4 )) \
    || [[ "$project_suffix" == *[!abcdefghijklmnopqrstuvwxyz0123456789]* ]]; then
    echo "TM_CAMPAIGN_PROJECT_SUFFIX must be 1..=4 lowercase ASCII letters or digits" >&2
    exit 2
  fi
  project_suffix_enabled=1
fi
readonly project_suffix project_suffix_enabled

python_optimization=$(
  python3 -c 'import sys; print(sys.flags.optimize)'
) || {
  echo "python3 is required to validate the resilience campaign" >&2
  exit 2
}
[[ "$python_optimization" == 0 ]] || {
  echo "Python optimization must be disabled; campaign assertions are release-integrity checks" >&2
  exit 2
}

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_dir"

campaign_timeout=${TM_CAMPAIGN_TIMEOUT_SECONDS:-900}
marker_timeout=${TM_CAMPAIGN_MARKER_TIMEOUT_SECONDS:-120}
keep_running=${TM_CAMPAIGN_KEEP_RUNNING:-0}
[[ "$campaign_timeout" =~ ^[0-9]+$ ]] && ((campaign_timeout >= 60 && campaign_timeout <= 3600)) || {
  echo "TM_CAMPAIGN_TIMEOUT_SECONDS must be an integer in 60..=3600" >&2
  exit 2
}
[[ "$marker_timeout" =~ ^[0-9]+$ ]] && ((marker_timeout >= 10 && marker_timeout <= 300)) || {
  echo "TM_CAMPAIGN_MARKER_TIMEOUT_SECONDS must be an integer in 10..=300" >&2
  exit 2
}
[[ "$keep_running" == 0 || "$keep_running" == 1 ]] || {
  echo "TM_CAMPAIGN_KEEP_RUNNING must be 0 or 1" >&2
  exit 2
}
if [[ "$mode" == all && "$keep_running" == 1 ]]; then
  echo "TM_CAMPAIGN_KEEP_RUNNING=1 is not supported with all; run one Compose mode" >&2
  exit 2
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
artifact_root=${TM_CAMPAIGN_ARTIFACT_DIR:-"$repo_dir/artifacts/resilience-$stamp"}
if [[ "$mode" != preflight ]]; then
  if [[ -L "$artifact_root" ]]; then
    echo "campaign artifact root must not be a symbolic link: $artifact_root" >&2
    exit 2
  fi
  if [[ -e "$artifact_root" ]]; then
    [[ -d "$artifact_root" ]] || {
      echo "campaign artifact root exists but is not a directory: $artifact_root" >&2
      exit 2
    }
    artifact_entry=$(find "$artifact_root" -mindepth 1 -maxdepth 1 -print -quit) || {
      echo "unable to verify that campaign artifact root is empty: $artifact_root" >&2
      exit 2
    }
    [[ -z "$artifact_entry" ]] || {
      echo "campaign artifact root must be fresh and empty: $artifact_root" >&2
      exit 2
    }
  fi
  mkdir -p -- "$artifact_root"
fi

COMPOSE_FILES=()
PROJECT=""
ACTIVE_CASE=""
CURRENT_SIGNER_SOURCE_SHA256=""
SIGNER_IMAGE_SOURCE_SHA256=""
readonly -a PROTOCOL_ONLY_E2E_OVERRIDES=(
  --env=TM_E2E_PROTOCOL_ONLY=1
  --env=TM_E2E_DEPOSITS=0
  --env=TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION=0
)
readonly -a ALLOCATION_ONLY_E2E_OVERRIDES=(
  --env=TM_E2E_PROTOCOL_ONLY=0
  --env=TM_E2E_DEPOSITS=1
  --env=TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION=0
)
readonly -a DEPOSIT_TTL_E2E_OVERRIDES=(
  --env=TM_E2E_PROTOCOL_ONLY=0
  --env=TM_E2E_DEPOSITS=1
  --env=TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION=0
  --env=TM_E2E_DEPOSIT_TTL_ACCEPTANCE=1
)
readonly -a LEADER_DOWN_E2E_OVERRIDES=(
  --env=TM_E2E_PROTOCOL_ONLY=0
  --env=TM_E2E_DEPOSITS=1
  --env=TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION=1
  --env=TM_FAULTY_PARTIES=1
  --env=TM_ACCEPTANCE_REQUIRE_EXACT_REFRESH_EPOCH=2
)
readonly -a ROTATION_SILENT_E2E_OVERRIDES=(
  --env=TM_E2E_PROTOCOL_ONLY=1
  --env=TM_E2E_DEPOSITS=0
  --env=TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION=0
  --env=TM_ACCEPTANCE_DYNAMIC_ROTATION_SELECTED_MEMBER_FAULT=1
)
readonly -a NETWORK_RESTART_E2E_OVERRIDES=(
  --env=TM_ACCEPTANCE_PROACTIVE_DEADLINE_SOURCE_EPOCH=4
  --env=TM_ACCEPTANCE_PROACTIVE_DEADLINE_INTERVAL_SECONDS=15
)
readonly -a OBSERVER_BYZANTINE_E2E_OVERRIDES=(
  --env=TM_FAULTY_PARTIES=1
)
readonly RUST_TERMINAL_MARKER='TM_RESILIENCE_RUST_TERMINAL all-target tests passed'
readonly ALLOCATION_TERMINAL_MARKER='allocation-only deposit acceptance passed; the address was funded, observed, and made permanent while consolidation was intentionally out of scope'
readonly PROTOCOL_TERMINAL_MARKER='protocol-only resilience acceptance passed; deposits and consolidation were intentionally out of scope'
readonly DEPOSIT_TTL_TERMINAL_MARKER='deposit TTL acceptance passed; exact boundary, non-reuse, and permanent retrieval verified'
readonly AUTONOMOUS_GENESIS_MARKER='TM_ACCEPTANCE_AUTONOMOUS_GENESIS epoch=0 control=observe-only avss_start_calls=0 '
readonly EXACT_REFRESH_MARKER='TM_ACCEPTANCE_EXACT_SAME_COMMITTEE_REFRESH '
readonly ALL_EPOCHS_TERMINAL_MARKER='threshold Monero regtest accepted 3-of-5 -> 4-of-7 -> two scheduled 4-of-7 refreshes -> 3-of-5 resharing -> autonomous dynamic 3-of-5 refresh-or-reshare'
readonly CONSOLIDATION_TRANSACTION_MARKER='deposit consolidation transaction '
readonly SIGNED_TRANSACTION_MARKER='TM_ACCEPTANCE_SIGNED_TRANSACTION '
readonly MULTI_INPUT_CONSOLIDATION_MARKER='TM_ACCEPTANCE_MULTI_INPUT_CONSOLIDATION '
readonly SUCCESSOR_EPOCH_SIGNED_TRANSACTION_MARKER='TM_ACCEPTANCE_SUCCESSOR_EPOCH_SIGNED_TRANSACTION epoch='
readonly SUCCESSOR_EPOCH_SIGNING_TERMINAL_MARKER='successor epoch signing acceptance passed; epochs 1 through 5 each threshold-signed, broadcast, mined, and confirmed a fresh Monero consolidation'
readonly CONSOLIDATION_FAULT_BARRIER_MARKER='TM_ACCEPTANCE_CONSOLIDATION_FAULT_BARRIER'
readonly CONSOLIDATION_FAULT_SETTLED_MARKER='TM_ACCEPTANCE_CONSOLIDATION_FAULT_SETTLED'
readonly CONSOLIDATION_RECONNECT_LATCH_HELD_MARKER='TM_ACCEPTANCE_CONSOLIDATION_PEER_RECONNECT_LATCH_HELD'
readonly CONSOLIDATION_RECONNECT_LATCH_RELEASED_MARKER='TM_ACCEPTANCE_CONSOLIDATION_PEER_RECONNECT_LATCH_RELEASED'
readonly CONSOLIDATION_PEER_REJOINED_MARKER='TM_ACCEPTANCE_CONSOLIDATION_PEER_QUIC_REJOINED'
readonly CONSOLIDATION_FAULT_TERMINAL_MARKER='fault-resilient consolidation acceptance passed'
readonly CONSOLIDATION_BOOTSTRAP_BARRIER_MARKER='TM_ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_BARRIER'
readonly CONSOLIDATION_BOOTSTRAP_CERTIFIED_MARKER='TM_ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_CERTIFIED'
readonly CONSOLIDATION_BOOTSTRAP_REJOINED_MARKER='TM_ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_REJOINED'
readonly CONSOLIDATION_BOOTSTRAP_SETTLED_MARKER='TM_ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_SETTLED'
readonly CONSOLIDATION_BOOTSTRAP_TERMINAL_MARKER='fault-resilient consolidation bootstrap acceptance passed'
readonly DEPOSIT_FAULT_BARRIER_MARKER='TM_ACCEPTANCE_DEPOSIT_FAULT_BARRIER'
readonly DEPOSIT_CHECKPOINT_HELD_MARKER='TM_ACCEPTANCE_DEPOSIT_CHECKPOINT_HELD'
readonly DEPOSIT_CHECKPOINT_RELEASED_MARKER='TM_ACCEPTANCE_DEPOSIT_CHECKPOINT_RELEASED'
readonly OBSERVER_FAULT_LATCH_HELD_MARKER='TM_ACCEPTANCE_OBSERVER_FAULT_LATCH_HELD'
readonly OBSERVER_FAULT_LATCH_RELEASED_MARKER='TM_ACCEPTANCE_OBSERVER_FAULT_LATCH_RELEASED'
readonly DYNAMIC_REFRESH_LATCH_HELD_MARKER='TM_ACCEPTANCE_DYNAMIC_REFRESH_LATCH_HELD'
readonly DYNAMIC_REFRESH_LATCH_RELEASED_MARKER='TM_ACCEPTANCE_DYNAMIC_REFRESH_LATCH_RELEASED'
readonly PROACTIVE_DEADLINE_HELD_MARKER='TM_ACCEPTANCE_PROACTIVE_DEADLINE_HELD'
readonly PROACTIVE_DEADLINE_RELEASED_MARKER='TM_ACCEPTANCE_PROACTIVE_DEADLINE_RELEASED'
readonly REGTEST_MINING_ADDRESS_MARKER='TM_ACCEPTANCE_REGTEST_MINING_ADDRESS='
readonly DEPOSIT_CLOCK_MARKER='TM_ACCEPTANCE_DEPOSIT_CLOCK '
readonly DEPOSIT_TTL_ACTIVE_MARKER='TM_ACCEPTANCE_DEPOSIT_TTL_ACTIVE '
readonly DEPOSIT_TTL_EXPIRED_MARKER='TM_ACCEPTANCE_DEPOSIT_TTL_EXPIRED '
readonly DEPOSIT_TTL_NOT_REUSED_MARKER='TM_ACCEPTANCE_DEPOSIT_TTL_NOT_REUSED '
readonly DEPOSIT_TTL_PERMANENT_MARKER='TM_ACCEPTANCE_DEPOSIT_TTL_PERMANENT '
readonly DEPOSIT_FUNDING_TRANSACTION_MARKER='TM_ACCEPTANCE_DEPOSIT_FUNDING_TRANSACTION '
readonly DEPOSIT_FUNDING_TRANSACTION_HEX_MARKER='TM_ACCEPTANCE_DEPOSIT_FUNDING_TRANSACTION_HEX='

compose() {
  docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" "$@"
}

cleanup_on_exit() {
  local status=$?
  if ((status != 0)) && [[ -n "$ACTIVE_CASE" && -n "$PROJECT" ]]; then
    set +e
    capture_evidence "$ACTIVE_CASE"
    if [[ "$keep_running" == 0 ]]; then
      compose down --remove-orphans >/dev/null 2>&1
    fi
  fi
  exit "$status"
}
trap cleanup_on_exit EXIT

campaign_project_name() {
  local case_name=$1
  local project
  if [[ -z "$case_name" \
    || "$case_name" == *[!abcdefghijklmnopqrstuvwxyz0123456789-]* ]]; then
    echo "invalid internal campaign case name: $case_name" >&2
    return 1
  fi
  project="threshold-monero-resilience-$case_name"
  if ((project_suffix_enabled == 1)); then
    project="${project}-${project_suffix}"
  fi
  if ((${#project} > 63)); then
    echo "derived campaign project name exceeds 63 characters: $project" >&2
    return 1
  fi
  printf '%s\n' "$project"
}

select_case() {
  local case_name=$1
  local silent=$2
  PROJECT=$(campaign_project_name "$case_name")
  COMPOSE_FILES=(
    -f compose.yaml
    -f compose.acceptance-proactive-refresh-hold.yaml
  )
  if [[ "$silent" == 1 ]]; then
    COMPOSE_FILES+=(-f compose.byzantine-silent.yaml)
  fi
}

compose_uses_file() {
  local expected=$1
  local item
  for item in "${COMPOSE_FILES[@]}"; do
    [[ "$item" == "$expected" ]] && return 0
  done
  return 1
}

verify_vendored_monero_sources() {
  "$repo_dir/vendor/monero-oxide/verify-threshold-monero-sources.sh"
}

derive_x25519_public_hex() {
  local secret_hex=$1
  local public_der
  # RFC 8410 PKCS#8 and SubjectPublicKeyInfo wrappers around raw 32-byte X25519 material.
  public_der=$(
    printf '%s%s' 302e020100300506032b656e04220420 "$secret_hex" \
      | xxd -r -p \
      | openssl pkey -inform DER -pubout -outform DER 2>/dev/null \
      | xxd -p -c 256
  )
  [[ "$public_der" =~ ^302a300506032b656e032100[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "${public_der#302a300506032b656e032100}"
}

scenario_bootstrap_public_for_party() {
  local party=$1
  awk -v wanted="$party" '
    $0 ~ "\"id\": " wanted "," { in_party = 1 }
    in_party && /"bootstrap_encryption_key":/ {
      value = $0
      sub(/^.*"bootstrap_encryption_key": "/, "", value)
      sub(/".*$/, "", value)
      print value
      exit
    }
  ' docker/configs/regtest-scenario.json
}

verify_deposit_clock_hook_scope() {
  local rendered=$1
  local clock_target=/run/threshold-monero-acceptance/deposit-clock
  local clock_mount=/run/threshold-monero-acceptance
  if compose_uses_file compose.acceptance-deposit-clock.yaml; then
    [[ -n "${TM_ACCEPTANCE_DEPOSIT_CLOCK_DIR:-}" \
      && "$TM_ACCEPTANCE_DEPOSIT_CLOCK_DIR" == /* ]] || {
      echo "deposit clock overlay requires an explicit absolute host directory" >&2
      return 1
    }
    python3 -c '
import json
import os
import sys

clock_directory, clock_mount, clock_target = sys.argv[1:]
rendered = json.load(sys.stdin)
party_env = "TM_ACCEPTANCE_DEPOSIT_CLOCK_FILE"
writer_env = "TM_E2E_DEPOSIT_CLOCK_FILE"
allowed = {*(f"p{party}" for party in range(1, 9)), "e2e"}

for name, service in rendered["services"].items():
    environment = service.get("environment", {})
    mounts = {
        mount["target"]: mount
        for mount in service.get("volumes", [])
    }
    if name.startswith("p") and name[1:].isdigit() and 1 <= int(name[1:]) <= 8:
        assert environment.get(party_env) == clock_target
        assert writer_env not in environment
        mount = mounts[clock_mount]
        assert mount["type"] == "bind"
        assert os.path.realpath(mount["source"]) == os.path.realpath(clock_directory)
        assert mount.get("read_only") is True
    elif name == "e2e":
        assert environment.get(writer_env) == clock_target
        assert party_env not in environment
        mount = mounts[clock_mount]
        assert mount["type"] == "bind"
        assert os.path.realpath(mount["source"]) == os.path.realpath(clock_directory)
        assert not mount.get("read_only", False)
    else:
        assert party_env not in environment
        assert writer_env not in environment
        assert clock_mount not in mounts

assert {
    name
    for name, service in rendered["services"].items()
    if clock_mount in {mount["target"] for mount in service.get("volumes", [])}
} == allowed
' "$TM_ACCEPTANCE_DEPOSIT_CLOCK_DIR" "$clock_mount" "$clock_target" <<<"$rendered" || {
      echo "deposit clock must be read-only on p1-p8, writable only on E2E, and absent elsewhere" >&2
      return 1
    }
  else
    python3 -c '
import json
import sys

clock_mount, party_env, writer_env = sys.argv[1:]
rendered = json.load(sys.stdin)
for service in rendered["services"].values():
    environment = service.get("environment", {})
    assert party_env not in environment
    assert writer_env not in environment
    assert all(
        mount["target"] != clock_mount
        for mount in service.get("volumes", [])
    )
' "$clock_mount" \
      TM_ACCEPTANCE_DEPOSIT_CLOCK_FILE TM_E2E_DEPOSIT_CLOCK_FILE <<<"$rendered" || {
      echo "acceptance deposit clock hook leaked into the ordinary Compose topology" >&2
      return 1
    }
  fi
}

verify_private_regtest_topology() {
  local case_name=$1
  local rendered expected_auto_start manual_count party other secret_file secret_hex
  local signing_file signing_hex
  local derived_public configured_public other_public
  rendered=$(compose --profile acceptance config --format json)
  verify_deposit_clock_hook_scope "$rendered"

  grep -Fq '"TM_E2E_ADMIN_BEARER_TOKEN_DIRECTORY": "/run/secrets"' <<<"$rendered" || {
    echo "acceptance client is missing the per-party admin capability directory" >&2
    return 1
  }
  grep -Fq '"TM_E2E_DEPOSIT_BEARER_TOKEN_DIRECTORY": "/run/secrets"' <<<"$rendered" || {
    echo "acceptance client is missing the per-party deposit capability directory" >&2
    return 1
  }
  [[ $(grep -Fo '"target": "admin_bearer_token"' <<<"$rendered" | wc -l | tr -d ' ') -eq 8 ]] || {
    echo "each party must mount exactly one local admin capability" >&2
    return 1
  }
  [[ $(grep -Fo '"target": "deposit_bearer_token"' <<<"$rendered" | wc -l | tr -d ' ') -eq 8 ]] || {
    echo "each party must mount exactly one local deposit capability" >&2
    return 1
  }
  for party in 1 2 3 4 5 6 7 8; do
    grep -Fq "\"target\": \"p${party}-admin-bearer-token\"" <<<"$rendered" || {
      echo "acceptance client is missing p${party}'s admin capability" >&2
      return 1
    }
    grep -Fq "\"target\": \"p${party}-deposit-bearer-token\"" <<<"$rendered" || {
      echo "acceptance client is missing p${party}'s deposit capability" >&2
      return 1
    }
    [[ -s "docker/demo-secrets/p${party}-admin-bearer-token.txt" \
      && -s "docker/demo-secrets/p${party}-deposit-bearer-token.txt" ]] || {
      echo "p${party} is missing a nonempty local HTTP capability" >&2
      return 1
    }
    ! cmp -s \
      "docker/demo-secrets/p${party}-admin-bearer-token.txt" \
      "docker/demo-secrets/p${party}-deposit-bearer-token.txt" || {
      echo "p${party}'s admin and deposit capabilities must be distinct" >&2
      return 1
    }
    for ((other = party + 1; other <= 8; other++)); do
      ! cmp -s \
        "docker/demo-secrets/p${party}-admin-bearer-token.txt" \
        "docker/demo-secrets/p${other}-admin-bearer-token.txt" || {
        echo "p${party} and p${other} share an admin capability" >&2
        return 1
      }
      ! cmp -s \
        "docker/demo-secrets/p${party}-deposit-bearer-token.txt" \
        "docker/demo-secrets/p${other}-deposit-bearer-token.txt" || {
        echo "p${party} and p${other} share a deposit capability" >&2
        return 1
      }
    done
  done

  manual_count=0
  compose_uses_file compose.acceptance-manual-bootstrap.yaml && manual_count=1
  if compose_uses_file compose.byzantine-silent.yaml; then
    python3 -c '
import json
import sys
rendered = json.load(sys.stdin)
p1 = rendered["services"]["p1"]
assert p1["environment"]["TM_QUIC_LISTEN_ADDR"] == "127.0.0.1:8443"
assert "peer-quic" not in p1.get("networks", {})
assert "control" in p1.get("networks", {})
assert "monero-rpc-p1" in p1.get("networks", {})
for party in range(2, 9):
    assert "peer-quic" in rendered["services"][f"p{party}"].get("networks", {})
' <<<"$rendered" || {
      echo "$case_name silent overlay does not make p1 loopback-only and peer-unreachable" >&2
      return 1
    }
  fi
  compose_uses_file compose.acceptance-proactive-refresh-hold.yaml || {
    echo "$case_name requires the deterministic proactive-refresh acceptance hold" >&2
    return 1
  }
  [[ $(grep -Fo '"TM_ACCEPTANCE_HOLD_PROACTIVE_REFRESH": "1"' <<<"$rendered" \
      | wc -l | tr -d ' ') -eq 9 \
    && $(grep -Fc 'TM_ACCEPTANCE_HOLD_PROACTIVE_REFRESH: "1"' \
      compose.acceptance-proactive-refresh-hold.yaml) -eq 9 ]] || {
    echo "$case_name must hold proactive refresh on eight parties and declare it to E2E" >&2
    return 1
  }
  case "$case_name" in
    avss-crash|qual-crash-silent)
      [[ "$manual_count" -eq 1 ]] || {
        echo "$case_name requires the deterministic manual-genesis fault overlay" >&2
        return 1
      }
      compose_uses_file compose.acceptance-protocol-fault-gate.yaml || {
        echo "$case_name requires the durable protocol fault-gate overlay" >&2
        return 1
      }
      [[ $(grep -Fo '"TM_ACCEPTANCE_ENABLE_PROTOCOL_FAULT_GATE": "1"' <<<"$rendered" \
        | wc -l | tr -d ' ') -eq 1 ]] || {
        echo "$case_name must enable the protocol fault gate on exactly p3" >&2
        return 1
      }
      expected_auto_start=false
      ;;
    *)
      [[ "$manual_count" -eq 0 ]] || {
        echo "manual genesis is permitted only for the two deterministic AVSS crash campaigns" >&2
        return 1
      }
      ! compose_uses_file compose.acceptance-protocol-fault-gate.yaml || {
        echo "the protocol fault gate is permitted only for AVSS/QUAL crash campaigns" >&2
        return 1
      }
      expected_auto_start=true
      ;;
  esac
  if [[ "$expected_auto_start" == true ]]; then
    [[ $(grep -Fo '"TM_AUTO_START_GENESIS": "true"' <<<"$rendered" | wc -l | tr -d ' ') -ge 8 \
      && $(grep -Fo '"TM_AUTO_START_GENESIS": "false"' <<<"$rendered" | wc -l | tr -d ' ') -eq 0 ]] || {
      echo "$case_name must keep all eight party services on autonomous genesis" >&2
      return 1
    }
  else
    # Some Compose releases include uninstantiated x-* templates in formatted JSON. Count only
    # the eight explicit false overrides; the overlay itself names every concrete party.
    [[ $(grep -Fo '"TM_AUTO_START_GENESIS": "false"' <<<"$rendered" | wc -l | tr -d ' ') -eq 8 \
      && $(grep -Fc 'TM_AUTO_START_GENESIS: "false"' \
        compose.acceptance-manual-bootstrap.yaml) -eq 8 ]] || {
      echo "$case_name must disable autonomous genesis on exactly eight party services" >&2
      return 1
    }
  fi

  [[ $(grep -Fc '"schema_version": 7' docker/configs/regtest-scenario.json) -eq 1 \
    && $(grep -Fc '"demo_only": true' docker/configs/regtest-scenario.json) -eq 1 \
    && $(grep -Fc '"network": "regtest"' docker/configs/regtest-scenario.json) -eq 1 \
    && $(grep -Fc '"deposit_birth_anchor": null' \
      docker/configs/regtest-scenario.json) -eq 1 \
    && $(grep -Fc '"members": [1, 2, 3, 4, 5]' docker/configs/regtest-scenario.json) -eq 1 \
    && $(grep -Fc '"eligible_members": [1, 2, 3, 4, 5, 6, 7, 8]' \
      docker/configs/regtest-scenario.json) -eq 3 \
    && $(grep -Fc '"members": [2, 3, 4, 6, 7]' \
      docker/configs/regtest-scenario.json) -eq 1 \
    && $(grep -Fc '"eligible_members": [2, 3, 4, 6, 7, 8]' \
      docker/configs/regtest-scenario.json) -eq 1 \
    && $(grep -Fc '"quic_endpoint": "quic://p' docker/configs/regtest-scenario.json) -eq 8 \
    && $(grep -Fc '"bootstrap_encryption_key":' docker/configs/regtest-scenario.json) -eq 8 \
    && $(grep -Fc '"encryption_keys":' docker/configs/regtest-scenario.json) -eq 0 \
    && $(grep -Fc '"old_dealers":' docker/configs/regtest-scenario.json) -eq 0 ]] || {
    echo "campaign requires the single explicit current-format private-Regtest fixture and ordered epoch-0 committee" >&2
    return 1
  }
  python3 - <<'PY' || {
import json

with open("docker/configs/regtest-scenario.json", encoding="utf-8") as handle:
    scenario = json.load(handle)
committees = {entry["epoch"]: entry for entry in scenario["committees"]}
source = committees[1]
target = committees[2]
assert source["operation"] == target["operation"] == "reshare"
assert source["threshold"] == target["threshold"] == 4
assert source["fault_bound"] == target["fault_bound"] == 1
assert source["members"] == target["members"] == [1, 2, 3, 4, 5, 6, 7]
assert source["eligible_members"] == target["eligible_members"] == [1, 2, 3, 4, 5, 6, 7, 8]
assert len(target["eligible_members"]) == len(target["members"]) + target["fault_bound"]
PY
    echo "campaign requires adjacent epoch-1/2 4-of-7 shapes with one explicit spare identity" >&2
    return 1
  }
  [[ $(grep -Fo '"target": "signing_seed"' <<<"$rendered" | wc -l | tr -d ' ') -eq 8 \
    && $(grep -Fo '"target": "bootstrap_x25519_secret"' <<<"$rendered" \
      | wc -l | tr -d ' ') -eq 5 \
    && $(grep -Fc 'TM_SIGNING_SEED_FILE: /run/secrets/signing_seed' compose.yaml) -eq 1 \
    && $(grep -Fc \
      'TM_BOOTSTRAP_X25519_SECRET_FILE: /run/secrets/bootstrap_x25519_secret' \
      compose.yaml) -eq 5 \
    && $(grep -Fc 'TM_IDENTITY_SEED_FILE' compose.yaml) -eq 0 \
    && $(grep -Fc 'target: identity_seed' compose.yaml) -eq 0 ]] || {
    echo "campaign requires eight signing seeds and genesis-only bootstrap secrets on p1-p5" >&2
    return 1
  }
  python3 -c '
import json
import sys
rendered = json.load(sys.stdin)
for party in range(1, 9):
    service = rendered["services"][f"p{party}"]
    environment = service.get("environment", {})
    secrets = {
        (entry["source"], entry["target"])
        for entry in service.get("secrets", [])
    }
    bootstrap = (f"demo-p{party}-bootstrap-x25519-secret", "bootstrap_x25519_secret")
    if party <= 5:
        assert environment["TM_BOOTSTRAP_X25519_SECRET_FILE"] == \
            "/run/secrets/bootstrap_x25519_secret"
        assert bootstrap in secrets
    else:
        assert "TM_BOOTSTRAP_X25519_SECRET_FILE" not in environment
        assert bootstrap not in secrets
' <<<"$rendered" || {
    echo "only the five epoch-zero dealers may receive bootstrap X25519 secrets" >&2
    return 1
  }
  python3 -c '
import json
import sys

rendered = json.load(sys.stdin)
for party in range(1, 9):
    service = rendered["services"][f"p{party}"]
    assert service["restart"] == "unless-stopped"
    assert service["read_only"] is True
    assert not service.get("ports")
    assert not service.get("depends_on")
    expected_networks = {
        "control",
        "peer-quic",
        f"monero-rpc-p{party}",
    }
    if party == 1 and service["environment"]["TM_QUIC_LISTEN_ADDR"] == \
        "127.0.0.1:8443":
        expected_networks.remove("peer-quic")
    assert set(service["networks"]) == expected_networks
    assert service["healthcheck"]["test"] == [
        "CMD",
        "/usr/local/bin/party-healthcheck",
    ]
    volumes = {volume["target"]: volume for volume in service["volumes"]}
    state = volumes["/var/lib/threshold-monero"]
    assert state["type"] == "volume" and not state.get("read_only", False)
    assert volumes["/etc/threshold-monero/regtest-scenario.json"]["read_only"] is True
    assert volumes["/etc/threshold-monero/quic"]["read_only"] is True

for name in ["monerod-miner", *(f"monerod-p{party}" for party in range(1, 9))]:
    service = rendered["services"][name]
    assert service["restart"] == "unless-stopped"
    assert service["read_only"] is True
    assert not service.get("ports")
    assert any(
        volume["target"] == "/data"
        and volume["type"] == "volume"
        and not volume.get("read_only", False)
        for volume in service["volumes"]
    )

assert rendered["services"]["e2e"]["restart"] == "no"
assert "peer-quic" not in rendered["services"]["e2e"]["networks"]
assert all(network["internal"] is True for network in rendered["networks"].values())
' <<<"$rendered" || {
    echo "rendered Compose health, persistence, restart, or network isolation contract changed" >&2
    return 1
  }
  [[ $(grep -Fc '  cpus: 0.75' compose.yaml) -eq 1 \
    && $(grep -Fc '  mem_limit: 512m' compose.yaml) -eq 1 \
    && $(grep -Fc '  pids_limit: 128' compose.yaml) -eq 1 \
    && $(grep -Fc '  cpus: 1.0' compose.yaml) -eq 1 \
    && $(grep -Fc '  mem_limit: 768m' compose.yaml) -eq 1 \
    && $(grep -Fc '  pids_limit: 256' compose.yaml) -eq 1 ]] || {
    echo "campaign requires the bounded signer and Monero resource anchors" >&2
    return 1
  }
  for party in 1 2 3 4 5 6 7 8; do
    secret_file="docker/demo-secrets/p${party}-bootstrap-x25519-secret.hex"
    signing_file="docker/demo-secrets/p${party}-signing-seed.hex"
    [[ -s "$signing_file" ]] || {
      echo "p${party} is missing its current signing fixture" >&2
      return 1
    }
    signing_hex=$(tr -d '\r\n' <"$signing_file")
    [[ "$signing_hex" =~ ^[0-9a-f]{64}$ ]] || {
      echo "p${party}'s signing fixture is not exactly 32 lowercase hexadecimal bytes" >&2
      return 1
    }
    configured_public=$(scenario_bootstrap_public_for_party "$party")
    [[ "$configured_public" =~ ^[0-9a-f]{64}$ ]] || {
      echo "p${party}'s bootstrap X25519 public sentinel is not exactly 32 lowercase hexadecimal bytes" >&2
      return 1
    }
    grep -Fq "\"source\": \"demo-p${party}-signing-seed\"" <<<"$rendered" || {
      echo "p${party} does not mount its matching signing fixture" >&2
      return 1
    }
    if ((party <= 5)); then
      [[ -s "$secret_file" ]] || {
        echo "epoch-zero party p${party} is missing its bootstrap X25519 fixture" >&2
        return 1
      }
      secret_hex=$(tr -d '\r\n' <"$secret_file")
      [[ "$secret_hex" =~ ^[0-9a-f]{64}$ ]] || {
        echo "p${party}'s bootstrap X25519 fixture is not exactly 32 lowercase hexadecimal bytes" >&2
        return 1
      }
      derived_public=$(derive_x25519_public_hex "$secret_hex") || {
        echo "failed to derive p${party}'s bootstrap X25519 public key" >&2
        return 1
      }
      [[ "$configured_public" == "$derived_public" ]] || {
        echo "p${party}'s bootstrap X25519 secret does not match the scenario public key" >&2
        return 1
      }
      grep -Fq "\"source\": \"demo-p${party}-bootstrap-x25519-secret\"" \
        <<<"$rendered" || {
        echo "epoch-zero party p${party} does not mount its matching bootstrap fixture" >&2
        return 1
      }
    else
      [[ ! -e "$secret_file" ]] || {
        echo "non-genesis party p${party} must not retain a bootstrap secret fixture" >&2
        return 1
      }
      ! grep -Fq "\"source\": \"demo-p${party}-bootstrap-x25519-secret\"" \
        <<<"$rendered" || {
        echo "non-genesis party p${party} must not receive a bootstrap fixture" >&2
        return 1
      }
    fi
    grep -Fq "\"quic_endpoint\": \"quic://p${party}-quic:8443\"" \
      docker/configs/regtest-scenario.json || {
      echo "p${party} is missing its configured QUIC-only peer endpoint" >&2
      return 1
    }
    if ((party == 1)) && compose_uses_file compose.byzantine-silent.yaml; then
      ! grep -Fq "\"p${party}-quic\"" <<<"$rendered" || {
        echo "silent p1 unexpectedly retains its peer QUIC network alias" >&2
        return 1
      }
    else
      grep -Fq "\"p${party}-quic\"" <<<"$rendered" || {
        echo "p${party} is missing its peer QUIC network alias" >&2
        return 1
      }
    fi
    for ((other = party + 1; other <= 8; other++)); do
      ! cmp -s "$signing_file" "docker/demo-secrets/p${other}-signing-seed.hex" || {
        echo "p${party} and p${other} share a signing seed" >&2
        return 1
      }
      other_public=$(scenario_bootstrap_public_for_party "$other")
      [[ "$configured_public" != "$other_public" ]] || {
        echo "p${party} and p${other} share a bootstrap X25519 public sentinel" >&2
        return 1
      }
    done
    if ((party <= 5)); then
      for ((other = party + 1; other <= 5; other++)); do
        ! cmp -s "$secret_file" \
          "docker/demo-secrets/p${other}-bootstrap-x25519-secret.hex" || {
          echo "p${party} and p${other} share a bootstrap X25519 secret" >&2
          return 1
        }
      done
    fi
    for other in 1 2 3 4 5; do
      ! cmp -s "$signing_file" \
        "docker/demo-secrets/p${other}-bootstrap-x25519-secret.hex" || {
        echo "p${party}'s signing seed is reused as p${other}'s bootstrap X25519 secret" >&2
        return 1
      }
    done
  done
  [[ $(grep -Fc '"monerod_rpc_urls": ["http://monerod-p' \
      docker/configs/regtest-scenario.json) -eq 8 \
    && $(grep -Eo 'monerod-p[1-8]:18081' docker/configs/regtest-scenario.json \
      | LC_ALL=C sort -u | wc -l | tr -d ' ') -eq 8 \
    && $(grep -Fc '"acceptance_monerod_rpc_url": "http://monerod-miner:18081"' \
      docker/configs/regtest-scenario.json) -eq 1 ]] || {
    echo "campaign requires eight unique party observers plus a separate acceptance miner" >&2
    return 1
  }
  for party in 1 2 3 4 5 6 7 8; do
    grep -Fq "\"monerod-p${party}\":" <<<"$rendered" || {
      echo "rendered topology is missing monerod-p${party}" >&2
      return 1
    }
    grep -Fq "\"monero-rpc-p${party}\":" <<<"$rendered" || {
      echo "rendered topology is missing p${party}'s isolated Monero RPC bridge" >&2
      return 1
    }
  done
  grep -Fq '"monerod-miner":' <<<"$rendered" || {
    echo "rendered topology is missing the separate acceptance miner" >&2
    return 1
  }
}

require_images() {
  local missing=0
  for tool in docker openssl python3 xxd; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "missing campaign evidence tool: $tool" >&2
      missing=1
    fi
  done
  for image in threshold-monero/signer:local threshold-monero/monerod:0.18.5.1; do
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      echo "missing prebuilt image: $image" >&2
      missing=1
    fi
  done
  if ((missing != 0)); then
    echo "after the source is green, run: docker compose build" >&2
    return 1
  fi
  verify_vendored_monero_sources || {
    echo "vendored Monero signing sources failed their pinned-source verification" >&2
    return 1
  }
  "$script_dir/generate-demo-quic-pki.sh" --check || {
    echo "deterministic demo QUIC fixtures failed their preflight check" >&2
    return 1
  }
  local monero_version monero_source
  monero_version=$(docker image inspect threshold-monero/monerod:0.18.5.1 \
    --format '{{index .Config.Labels "org.opencontainers.image.version"}}')
  monero_source=$(docker image inspect threshold-monero/monerod:0.18.5.1 \
    --format '{{index .Config.Labels "org.opencontainers.image.source"}}')
  [[ "$monero_version" == 0.18.5.1 \
    && "$monero_source" == https://github.com/monero-project/monero ]] || {
    echo "Monero image does not carry the pinned official-release identity labels" >&2
    return 1
  }
  verify_signer_source_binding
}

canonical_signer_source_sha256() {
  while IFS= read -r source_file; do
    local source_digest
    source_digest=$(openssl dgst -sha256 "$source_file" | awk '{print $NF}')
    printf '%s  %s\n' "$source_digest" "$source_file"
  done < <(
    find Cargo.toml Cargo.lock Dockerfile docker/party-healthcheck.sh src vendor -type f -print \
      | LC_ALL=C sort
  ) | openssl dgst -sha256 | awk '{print $NF}'
}

verify_signer_source_binding() {
  local current embedded image=threshold-monero/signer:local
  current=$(canonical_signer_source_sha256)
  [[ "$current" =~ ^[0-9a-f]{64}$ ]] || {
    echo "failed to derive the canonical signer source digest" >&2
    return 1
  }
  if ! embedded=$(docker run --rm --network none --read-only --cap-drop ALL \
    --entrypoint /bin/sh "$image" -eu -c 'cat /build-source-sha256'); then
    echo "signer image lacks /build-source-sha256; rebuild it from the green source tree" >&2
    return 1
  fi
  [[ "$embedded" =~ ^[0-9a-f]{64}$ ]] || {
    echo "signer image contains an invalid /build-source-sha256 value" >&2
    return 1
  }
  [[ "$embedded" == "$current" ]] || {
    echo "signer image is stale: image source=$embedded current source=$current" >&2
    echo "after the source is green, run: docker compose build" >&2
    return 1
  }
  CURRENT_SIGNER_SOURCE_SHA256=$current
  SIGNER_IMAGE_SOURCE_SHA256=$embedded
}

assert_exact_project_resources_absent() {
  local case_name=$1
  local expected_project containers volumes networks
  expected_project=$(campaign_project_name "$case_name") || return 1
  [[ "$PROJECT" == "$expected_project" ]] || {
    echo "refusing to inspect resources for an unbound Compose project: $PROJECT" >&2
    return 1
  }

  containers=$(docker container ls --all --quiet \
    --filter "label=com.docker.compose.project=$PROJECT")
  if [[ -n "$containers" ]]; then
    echo "fresh-state check found containers for exact project $PROJECT:" >&2
    docker container ls --all \
      --filter "label=com.docker.compose.project=$PROJECT" \
      --format '  {{.ID}} {{.Names}} {{.Status}}' >&2
    return 1
  fi

  volumes=$(docker volume ls --quiet \
    --filter "label=com.docker.compose.project=$PROJECT")
  if [[ -n "$volumes" ]]; then
    echo "fresh-state check found volumes for exact project $PROJECT:" >&2
    docker volume ls \
      --filter "label=com.docker.compose.project=$PROJECT" \
      --format '  {{.Name}}' >&2
    return 1
  fi

  networks=$(docker network ls --quiet \
    --filter "label=com.docker.compose.project=$PROJECT")
  if [[ -n "$networks" ]]; then
    echo "fresh-state check found networks for exact project $PROJECT:" >&2
    docker network ls \
      --filter "label=com.docker.compose.project=$PROJECT" \
      --format '  {{.ID}} {{.Name}}' >&2
    return 1
  fi
}

prepare_fresh_compose() {
  local case_name=$1
  mkdir -p -- "$artifact_root/$case_name"
  compose config --quiet
  verify_private_regtest_topology "$case_name"
  printf 'case=%s\nstarted_at=%s\nproject=%s\n' \
    "$case_name" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PROJECT" \
    >"$artifact_root/$case_name/case-metadata.env"

  if ((project_suffix_enabled == 1)); then
    # A suffix is an opt-in fresh namespace. Refuse collisions before the exit
    # trap owns the case, so a typo cannot tear down preserved forensic state.
    assert_exact_project_resources_absent "$case_name"
    ACTIVE_CASE=$case_name
  else
    # The canonical project names retain the campaign's disposable clean-state behavior.
    ACTIVE_CASE=$case_name
    compose down --volumes --remove-orphans >/dev/null
    assert_exact_project_resources_absent "$case_name"
  fi
  compose up --detach --no-build --wait --wait-timeout 300
}

verify_full_acceptance_contract() {
  local rendered
  verify_signer_source_binding
  rendered=$(compose --profile acceptance config --format json)
  grep -Fq '"TM_E2E_DEPOSITS": "1"' <<<"$rendered" || {
    echo "acceptance must enable the deposit flow" >&2
    return 1
  }
  grep -Fq '"TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION": "1"' <<<"$rendered" || {
    echo "acceptance must fail closed unless deposit consolidation is verified" >&2
    return 1
  }
}

verify_protocol_only_acceptance_contract() {
  local require_silent_overlay=${1:-1}
  local expected actual matches
  local rendered
  [[ "$require_silent_overlay" == 0 || "$require_silent_overlay" == 1 ]] || {
    echo "protocol-only topology expectation must be 0 or 1" >&2
    return 2
  }
  # Keep the official Compose profile fail-closed. Only named protocol-only fault paths pass these
  # overrides, and the E2E binary independently rejects anything other than exact zero values.
  verify_full_acceptance_contract
  [[ ${#PROTOCOL_ONLY_E2E_OVERRIDES[@]} -eq 3 ]] || {
    echo "protocol-only acceptance must have exactly three E2E overrides" >&2
    return 1
  }
  for expected in \
    --env=TM_E2E_PROTOCOL_ONLY=1 \
    --env=TM_E2E_DEPOSITS=0 \
    --env=TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION=0
  do
    matches=0
    for actual in "${PROTOCOL_ONLY_E2E_OVERRIDES[@]}"; do
      [[ "$actual" == "$expected" ]] && matches=$((matches + 1))
    done
    [[ $matches -eq 1 ]] || {
      echo "protocol-only acceptance override missing or duplicated: $expected" >&2
      return 1
    }
  done
  rendered=$(compose --profile acceptance config --format json)
  if [[ "$require_silent_overlay" == 1 ]]; then
    grep -Fq '"TM_FAULTY_PARTIES": "1"' <<<"$rendered" || {
      echo "protocol-only acceptance requires the explicit silent-p1 overlay" >&2
      return 1
    }
  else
    ! grep -Fq '"TM_FAULTY_PARTIES": "1"' <<<"$rendered" || {
      echo "ordinary protocol-only acceptance must not inherit the silent-p1 overlay" >&2
      return 1
    }
  fi
}

verify_allocation_only_acceptance_contract() {
  local expected actual matches
  local rendered
  # The base acceptance profile remains fail-closed. This one named fault campaign narrows the
  # runtime gate only to allocation, real funding, observation, and permanent-address recovery.
  verify_full_acceptance_contract
  [[ ${#ALLOCATION_ONLY_E2E_OVERRIDES[@]} -eq 3 ]] || {
    echo "allocation-only acceptance must have exactly three E2E overrides" >&2
    return 1
  }
  for expected in \
    --env=TM_E2E_PROTOCOL_ONLY=0 \
    --env=TM_E2E_DEPOSITS=1 \
    --env=TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION=0
  do
    matches=0
    for actual in "${ALLOCATION_ONLY_E2E_OVERRIDES[@]}"; do
      [[ "$actual" == "$expected" ]] && matches=$((matches + 1))
    done
    [[ $matches -eq 1 ]] || {
      echo "allocation-only acceptance override missing or duplicated: $expected" >&2
      return 1
    }
  done
  rendered=$(compose --profile acceptance config --format json)
  grep -Fq '"TM_FAULTY_PARTIES": "1"' <<<"$rendered" || {
    echo "allocation-only acceptance requires the explicit silent-p1 overlay" >&2
    return 1
  }
}

verify_deposit_ttl_acceptance_contract() {
  local expected actual matches rendered
  [[ ${#COMPOSE_FILES[@]} -eq 6 \
    && "${COMPOSE_FILES[0]}" == -f \
    && "${COMPOSE_FILES[1]}" == compose.yaml \
    && "${COMPOSE_FILES[2]}" == -f \
    && "${COMPOSE_FILES[3]}" == compose.acceptance-proactive-refresh-hold.yaml \
    && "${COMPOSE_FILES[4]}" == -f \
    && "${COMPOSE_FILES[5]}" == compose.acceptance-deposit-clock.yaml ]] || {
    echo "deposit-ttl acceptance must use only the ordinary, refresh-hold, and clock topology" >&2
    return 1
  }
  verify_full_acceptance_contract
  [[ ${#DEPOSIT_TTL_E2E_OVERRIDES[@]} -eq 4 ]] || {
    echo "deposit-ttl acceptance must have exactly four E2E overrides" >&2
    return 1
  }
  for expected in \
    --env=TM_E2E_PROTOCOL_ONLY=0 \
    --env=TM_E2E_DEPOSITS=1 \
    --env=TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION=0 \
    --env=TM_E2E_DEPOSIT_TTL_ACCEPTANCE=1
  do
    matches=0
    for actual in "${DEPOSIT_TTL_E2E_OVERRIDES[@]}"; do
      [[ "$actual" == "$expected" ]] && matches=$((matches + 1))
    done
    [[ $matches -eq 1 ]] || {
      echo "deposit-ttl acceptance override missing or duplicated: $expected" >&2
      return 1
    }
  done
  rendered=$(compose --profile acceptance config --format json)
  ! grep -Fq '"TM_E2E_DEPOSIT_TTL_ACCEPTANCE":' <<<"$rendered" || {
    echo "focused deposit-TTL execution flag must not leak into a long-running Compose service" >&2
    return 1
  }
  [[ $(grep -Fc \
      'TM_ACCEPTANCE_DEPOSIT_CLOCK_FILE: /run/threshold-monero-acceptance/deposit-clock' \
      compose.acceptance-deposit-clock.yaml) -eq 8 \
    && $(grep -Fc \
      'TM_E2E_DEPOSIT_CLOCK_FILE: /run/threshold-monero-acceptance/deposit-clock' \
      compose.acceptance-deposit-clock.yaml) -eq 1 ]] || {
    echo "deposit clock overlay must configure exactly eight readers and one E2E writer" >&2
    return 1
  }
}

verify_leader_down_acceptance_contract() {
  local expected actual matches
  # This case uses the ordinary peer topology, then stops p1's container. Unlike the silent
  # overlay, the fault is declared directly on the one-shot client command so it never probes the
  # stopped admin endpoint while every live party still treats p1 as a committee member.
  [[ ${#COMPOSE_FILES[@]} -eq 4 \
    && "${COMPOSE_FILES[0]}" == -f \
    && "${COMPOSE_FILES[1]}" == compose.yaml \
    && "${COMPOSE_FILES[2]}" == -f \
    && "${COMPOSE_FILES[3]}" == compose.acceptance-proactive-refresh-hold.yaml ]] || {
    echo "leader-down acceptance must use only the ordinary and refresh-hold topology" >&2
    return 1
  }
  verify_full_acceptance_contract
  [[ ${#LEADER_DOWN_E2E_OVERRIDES[@]} -eq 5 ]] || {
    echo "leader-down acceptance must have exactly five E2E overrides" >&2
    return 1
  }
  for expected in \
    --env=TM_E2E_PROTOCOL_ONLY=0 \
    --env=TM_E2E_DEPOSITS=1 \
    --env=TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION=1 \
    --env=TM_FAULTY_PARTIES=1 \
    --env=TM_ACCEPTANCE_REQUIRE_EXACT_REFRESH_EPOCH=2
  do
    matches=0
    for actual in "${LEADER_DOWN_E2E_OVERRIDES[@]}"; do
      [[ "$actual" == "$expected" ]] && matches=$((matches + 1))
    done
    [[ $matches -eq 1 ]] || {
      echo "leader-down acceptance override missing or duplicated: $expected" >&2
      return 1
    }
  done
}

verify_rotation_silent_acceptance_contract() {
  local expected actual matches
  # Every party remains fully healthy for DKG and every configured transition. The E2E runner
  # chooses one actual certified epoch-4 member only at its post-epoch-4 barrier; this driver then
  # disconnects that member from peer QUIC while leaving its control network and process intact.
  [[ ${#COMPOSE_FILES[@]} -eq 4 \
    && "${COMPOSE_FILES[0]}" == -f \
    && "${COMPOSE_FILES[1]}" == compose.yaml \
    && "${COMPOSE_FILES[2]}" == -f \
    && "${COMPOSE_FILES[3]}" == compose.acceptance-proactive-refresh-hold.yaml ]] || {
    echo "rotation-silent acceptance must start from the ordinary and refresh-hold topology" >&2
    return 1
  }
  verify_full_acceptance_contract
  [[ ${#ROTATION_SILENT_E2E_OVERRIDES[@]} -eq 4 ]] || {
    echo "rotation-silent acceptance must have exactly four E2E overrides" >&2
    return 1
  }
  for expected in \
    --env=TM_E2E_PROTOCOL_ONLY=1 \
    --env=TM_E2E_DEPOSITS=0 \
    --env=TM_E2E_REQUIRE_DEPOSIT_CONSOLIDATION=0 \
    --env=TM_ACCEPTANCE_DYNAMIC_ROTATION_SELECTED_MEMBER_FAULT=1
  do
    matches=0
    for actual in "${ROTATION_SILENT_E2E_OVERRIDES[@]}"; do
      [[ "$actual" == "$expected" ]] && matches=$((matches + 1))
    done
    [[ $matches -eq 1 ]] || {
      echo "rotation-silent acceptance override missing or duplicated: $expected" >&2
      return 1
    }
  done
}

verify_network_restart_acceptance_contract() {
  local expected actual matches
  [[ ${#COMPOSE_FILES[@]} -eq 4 \
    && "${COMPOSE_FILES[0]}" == -f \
    && "${COMPOSE_FILES[1]}" == compose.yaml \
    && "${COMPOSE_FILES[2]}" == -f \
    && "${COMPOSE_FILES[3]}" == compose.acceptance-proactive-refresh-hold.yaml ]] || {
    echo "network-restart acceptance must use only the ordinary and refresh-hold topology" >&2
    return 1
  }
  verify_full_acceptance_contract
  [[ ${#NETWORK_RESTART_E2E_OVERRIDES[@]} -eq 2 ]] || {
    echo "network-restart acceptance must have exactly two deadline overrides" >&2
    return 1
  }
  for expected in \
    --env=TM_ACCEPTANCE_PROACTIVE_DEADLINE_SOURCE_EPOCH=4 \
    --env=TM_ACCEPTANCE_PROACTIVE_DEADLINE_INTERVAL_SECONDS=15
  do
    matches=0
    for actual in "${NETWORK_RESTART_E2E_OVERRIDES[@]}"; do
      [[ "$actual" == "$expected" ]] && matches=$((matches + 1))
    done
    [[ $matches -eq 1 ]] || {
      echo "network-restart acceptance override missing or duplicated: $expected" >&2
      return 1
    }
  done
  python3 - docker/configs/regtest-scenario.json <<'PY'
import json
import sys

scenario = json.load(open(sys.argv[1], encoding="utf-8"))
assert scenario["demo_only"] is True
assert scenario["network"] == "regtest"
assert scenario["proactive_refresh_interval_seconds"] == 15
epoch_four = next(item for item in scenario["committees"] if item["epoch"] == 4)
assert epoch_four["threshold"] == 3
assert len(epoch_four["members"]) == 5
assert epoch_four["fault_bound"] == 1
PY
}

verify_consolidation_silent_acceptance_contract() {
  # The fault is injected only after a real deposit is allocated, funded, confirmed, permanent,
  # and mature. This campaign must therefore retain the ordinary topology and both fail-closed
  # deposit/consolidation gates; it has no protocol-only or allocation-only escape hatch.
  [[ ${#COMPOSE_FILES[@]} -eq 6 \
    && "${COMPOSE_FILES[0]}" == -f \
    && "${COMPOSE_FILES[1]}" == compose.yaml \
    && "${COMPOSE_FILES[2]}" == -f \
    && "${COMPOSE_FILES[3]}" == compose.acceptance-proactive-refresh-hold.yaml \
    && "${COMPOSE_FILES[4]}" == -f \
    && "${COMPOSE_FILES[5]}" == compose.acceptance-consolidation-gate.yaml ]] || {
    echo "consolidation-silent acceptance must use only the base, refresh, and consolidation gates" >&2
    return 1
  }
  verify_full_acceptance_contract
  local rendered
  rendered=$(compose --profile acceptance config --format json)
  [[ $(grep -Fo '"TM_ACCEPTANCE_ENABLE_CONSOLIDATION_GATE": "1"' <<<"$rendered" | wc -l) -eq 8 ]] || {
    echo "consolidation-silent acceptance must enable the gate on exactly eight party services" >&2
    return 1
  }
}

verify_consolidation_bootstrap_silent_acceptance_contract() {
  # This case starts with the ordinary peer topology. Its only overlay enables two authenticated,
  # regtest/demo-only controls: one before initial intent BA and one after the replacement intent
  # certificate but before nonce creation.
  [[ ${#COMPOSE_FILES[@]} -eq 6 \
    && "${COMPOSE_FILES[0]}" == -f \
    && "${COMPOSE_FILES[1]}" == compose.yaml \
    && "${COMPOSE_FILES[2]}" == -f \
    && "${COMPOSE_FILES[3]}" == compose.acceptance-proactive-refresh-hold.yaml \
    && "${COMPOSE_FILES[4]}" == -f \
    && "${COMPOSE_FILES[5]}" == compose.acceptance-consolidation-bootstrap-gate.yaml ]] || {
    echo "consolidation-bootstrap-silent must use only the base and exact acceptance gates" >&2
    return 1
  }
  verify_full_acceptance_contract
  local rendered
  rendered=$(compose --profile acceptance config --format json)
  [[ $(grep -Fo '"TM_ACCEPTANCE_ENABLE_CONSOLIDATION_BOOTSTRAP_GATE": "1"' <<<"$rendered" | wc -l) -eq 8 ]] || {
    echo "bootstrap acceptance must enable its pre-BA gate on exactly eight party services" >&2
    return 1
  }
  [[ $(grep -Fo '"TM_ACCEPTANCE_ENABLE_CONSOLIDATION_GATE": "1"' <<<"$rendered" | wc -l) -eq 8 ]] || {
    echo "bootstrap acceptance must enable its pre-nonce gate on exactly eight party services" >&2
    return 1
  }
}

record_acceptance_contract() {
  local case_name=$1
  local contract=$2
  local deposits=$3
  local consolidation=$4
  local genesis=autonomous
  compose_uses_file compose.acceptance-manual-bootstrap.yaml && genesis=manual-fault-barrier
  printf 'contract=%s\ndeposits=%s\nconsolidation=%s\nnetwork=private-regtest\nstate_format=current-only\ngenesis=%s\ncompose_files=' \
    "$contract" "$deposits" "$consolidation" "$genesis" \
    >"$artifact_root/$case_name/acceptance-contract.txt"
  printf '%q ' "${COMPOSE_FILES[@]}" >>"$artifact_root/$case_name/acceptance-contract.txt"
  printf '\n' >>"$artifact_root/$case_name/acceptance-contract.txt"
  printf 'current_signer_source_sha256=%s\nimage_signer_source_sha256=%s\n' \
    "$CURRENT_SIGNER_SOURCE_SHA256" "$SIGNER_IMAGE_SOURCE_SHA256" \
    >>"$artifact_root/$case_name/acceptance-contract.txt"
  printf 'kind\tline\tevidence\n' >"$artifact_root/$case_name/required-markers.tsv"
  echo "running '$case_name' as $contract acceptance (deposits=$deposits, consolidation=$consolidation)"
}

capture_evidence() {
  local case_name=$1
  local destination="$artifact_root/$case_name"
  compose --profile acceptance config >"$destination/rendered-compose.yaml" 2>&1 || true
  compose ps --all >"$destination/compose-ps.txt"
  compose logs --no-color \
    monerod-miner monerod-p1 monerod-p2 monerod-p3 monerod-p4 \
    monerod-p5 monerod-p6 monerod-p7 monerod-p8 p1 p2 p3 p4 p5 p6 p7 p8 \
    >"$destination/services.log" 2>&1 || true
  docker image inspect \
    threshold-monero/signer:local threshold-monero/monerod:0.18.5.1 \
    >"$destination/images.json" 2>&1 || true
  git status --short >"$destination/source-status.txt" 2>&1 || true
  : >"$destination/source-sha256.txt"
  while IFS= read -r source_file; do
    openssl dgst -sha256 "$source_file" >>"$destination/source-sha256.txt"
  done < <(
    find .dockerignore Cargo.toml Cargo.lock Dockerfile Dockerfile.monero compose.yaml \
      compose.debug.yaml compose.byzantine-silent.yaml \
      compose.acceptance-manual-bootstrap.yaml \
      compose.acceptance-protocol-fault-gate.yaml \
      compose.acceptance-deposit-clock.yaml \
      compose.acceptance-proactive-refresh-hold.yaml \
      compose.acceptance-consolidation-gate.yaml \
      compose.acceptance-consolidation-bootstrap-gate.yaml docker src tests vendor \
      -type f -print | LC_ALL=C sort
  )
  : >"$destination/party-status.jsonl"
  for party in p1 p2 p3 p4 p5 p6 p7 p8; do
    if compose ps --status running --quiet "$party" | grep -q .; then
      compose exec -T "$party" sh -eu -c '
        token=$(tr -d "\r\n" </run/secrets/admin_bearer_token)
        curl --fail --silent --show-error \
          -H "Authorization: Bearer $token" http://127.0.0.1:8080/v1/status
      ' >>"$destination/party-status.jsonl" || true
      printf '\n' >>"$destination/party-status.jsonl"
    fi
  done
}

finish_compose() {
  local case_name=$1
  capture_evidence "$case_name"
  printf 'completed_at=%s\nresult=passed\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >>"$artifact_root/$case_name/case-metadata.env"
  printf 'TM_RESILIENCE_CASE_PASSED=%s\n' "$case_name" \
    >"$artifact_root/$case_name/case-result.env"
  if [[ "$keep_running" == 0 ]]; then
    compose down --remove-orphans >/dev/null
  else
    echo "$PROJECT remains running for inspection"
  fi
  ACTIVE_CASE=""
}

wait_for_process() {
  local pid=$1
  local deadline=$2
  local log_file=$3
  while kill -0 "$pid" 2>/dev/null; do
    if (( $(date +%s) >= deadline )); then
      echo "acceptance process exceeded ${campaign_timeout}s" >&2
      kill "$pid" 2>/dev/null || true
      return 124
    fi
    sleep 1
  done
  local status=0
  wait "$pid" || status=$?
  if ((status != 0)); then
    echo "acceptance process failed with status $status; tail follows" >&2
    tail -n 120 "$log_file" >&2 || true
    return "$status"
  fi
}

wait_for_marker() {
  local pid=$1
  local log_file=$2
  local marker=$3
  local timeout_seconds=${4:-$marker_timeout}
  local deadline=$(( $(date +%s) + timeout_seconds ))
  while ! grep -Fq "$marker" "$log_file" 2>/dev/null; do
    if ! kill -0 "$pid" 2>/dev/null; then
      local status=0
      wait "$pid" || status=$?
      echo "acceptance exited with status $status before fault barrier: $marker" >&2
      tail -n 120 "$log_file" >&2 || true
      return 1
    fi
    if (( $(date +%s) >= deadline )); then
      echo "fault barrier was not reached within ${timeout_seconds}s: $marker" >&2
      kill "$pid" 2>/dev/null || true
      return 124
    fi
    sleep 1
  done
}

record_p3_process() {
  local destination=$1
  local label=$2
  local container
  container=$(compose ps --all --quiet p3)
  [[ -n "$container" ]] || {
    echo "p3 container is missing during the AVSS crash campaign" >&2
    return 1
  }
  docker inspect --format \
    "$label container={{.Id}} running={{.State.Running}} pid={{.State.Pid}} started={{.State.StartedAt}} restarts={{.RestartCount}} volumes={{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}}:{{.Destination}};{{end}}{{end}}" \
    "$container" >>"$destination/p3-restart.txt"
}

record_p2_process() {
  local destination=$1
  local label=$2
  local container
  container=$(compose ps --quiet p2)
  docker inspect --format \
    "$label container={{.Id}} pid={{.State.Pid}} started={{.State.StartedAt}} restarts={{.RestartCount}} volumes={{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}}:{{.Destination}};{{end}}{{end}}" \
    "$container" >>"$destination/p2-restart.txt"
}

record_p1_process() {
  local destination=$1
  local label=$2
  local container
  container=$(compose ps --all --quiet p1)
  [[ -n "$container" ]] || {
    echo "p1 container is missing" >&2
    return 1
  }
  docker inspect --format \
    "$label container={{.Id}} status={{.State.Status}} running={{.State.Running}} pid={{.State.Pid}} started={{.State.StartedAt}} finished={{.State.FinishedAt}} restarts={{.RestartCount}}" \
    "$container" >>"$destination/p1-down.txt"
}

assert_p1_down() {
  local container running
  container=$(compose ps --all --quiet p1)
  [[ -n "$container" ]] || {
    echo "p1 container disappeared instead of remaining stopped for evidence" >&2
    return 1
  }
  running=$(docker inspect --format '{{.State.Running}}' "$container")
  [[ "$running" == false ]] || {
    echo "p1 unexpectedly remained or became running during leader-down acceptance" >&2
    return 1
  }
  [[ -z "$(compose ps --status running --quiet p1)" ]] || {
    echo "Compose still reports p1 as running during leader-down acceptance" >&2
    return 1
  }
}

assert_silent_p1_isolated() {
  local destination=$1
  local label=$2
  local container peer_network container_name sockets response
  container=$(compose ps --quiet p1)
  [[ -n "$container" && $(docker inspect --format '{{.State.Running}}' "$container") == true ]] || {
    echo "silent p1 is not running for omission evidence" >&2
    return 1
  }
  peer_network=$(peer_quic_network)
  container_name=$(docker inspect --format '{{.Name}}' "$container" | sed 's#^/##')
  ! docker network inspect --format '{{range .Containers}}{{.Name}} {{end}}' "$peer_network" \
    | tr ' ' '\n' | grep -Fxq "$container_name" || {
    echo "silent p1 is still attached to peer-quic" >&2
    return 1
  }
  ! compose exec -T p2 getent hosts p1-quic >/dev/null 2>&1 || {
    echo "a live peer can still resolve silent p1's QUIC route" >&2
    return 1
  }
  sockets=$(compose exec -T p1 sh -eu -c '
    awk "\$2 ~ /:20FB$/ {print \$2}" /proc/net/udp /proc/net/udp6 2>/dev/null || true
  ')
  [[ $(grep -Ec '^0100007F:20FB$' <<<"$sockets") -eq 1 \
    && $(grep -Ec '^(00000000|00000000000000000000000000000000):20FB$' <<<"$sockets") -eq 0 ]] || {
    echo "silent p1 QUIC socket is not exactly one IPv4 loopback listener: $sockets" >&2
    return 1
  }
  response=$(party_admin_status p1)
  python3 - "$response" <<'PY'
import json
import sys
value = json.loads(sys.argv[1])
assert value["party"] == 1
assert value["ready"] is True
assert value["authenticated_quic_ingress"] == 0
assert value["authenticated_quic_responses"] == 0
PY
  printf '%s container=%s peer_network=%s sockets=%q status=%s\n' \
    "$label" "$container" "$peer_network" "$sockets" "$response" \
    >>"$destination/p1-silent-omission-evidence.txt"
}

record_rotation_party_peer_network() {
  local destination=$1
  local party=$2
  local label=$3
  local container
  validate_party_service "$party"
  container=$(compose ps --quiet "$party")
  [[ -n "$container" ]] || {
    echo "$party container is missing during dynamic rotation omission" >&2
    return 1
  }
  docker inspect --format \
    "$label party=$party container={{.Id}} running={{.State.Running}} pid={{.State.Pid}} networks={{json .NetworkSettings.Networks}}" \
    "$container" >>"$destination/${party}-rotation-silent.txt"
}

disconnect_rotation_party_from_peer_quic() {
  local party=$1
  local container peer_network peer_networks
  validate_party_service "$party"
  container=$(compose ps --quiet "$party")
  [[ -n "$container" ]] || {
    echo "$party container is missing before dynamic rotation fault" >&2
    return 1
  }
  peer_networks=$(docker network ls \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.network=peer-quic" \
    --format '{{.Name}}')
  [[ $(wc -w <<<"$peer_networks") -eq 1 ]] || {
    echo "expected exactly one peer-quic network for $PROJECT, found: $peer_networks" >&2
    return 1
  }
  peer_network=$peer_networks
  docker network disconnect "$peer_network" "$container"
  [[ $(docker inspect --format '{{.State.Running}}' "$container") == true ]] || {
    echo "$party process stopped while applying the dynamic rotation omission" >&2
    return 1
  }
  ! docker network inspect --format '{{range .Containers}}{{.Name}} {{end}}' "$peer_network" \
    | tr ' ' '\n' | grep -Fxq "$(docker inspect --format '{{.Name}}' "$container" | sed 's#^/##')" || {
    echo "$party remained attached to peer QUIC after disconnect" >&2
    return 1
  }
}

assert_rotation_party_peer_quic_disconnected() {
  local party=$1
  local container container_name peer_networks peer_network
  validate_party_service "$party"
  container=$(compose ps --quiet "$party")
  [[ -n "$container" ]] || {
    echo "$party container is missing while checking dynamic rotation omission" >&2
    return 1
  }
  [[ $(docker inspect --format '{{.State.Running}}' "$container") == true ]] || {
    echo "$party process is not running during dynamic rotation omission" >&2
    return 1
  }
  peer_networks=$(docker network ls \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.network=peer-quic" \
    --format '{{.Name}}')
  [[ $(wc -w <<<"$peer_networks") -eq 1 ]] || {
    echo "expected exactly one peer-quic network for $PROJECT, found: $peer_networks" >&2
    return 1
  }
  peer_network=$peer_networks
  container_name=$(docker inspect --format '{{.Name}}' "$container" | sed 's#^/##')
  ! docker network inspect --format '{{range .Containers}}{{.Name}} {{end}}' "$peer_network" \
    | tr ' ' '\n' | grep -Fxq "$container_name" || {
    echo "$party reattached to peer QUIC during dynamic rotation acceptance" >&2
    return 1
  }
}

peer_quic_network() {
  local peer_networks
  peer_networks=$(docker network ls \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.network=peer-quic" \
    --format '{{.Name}}')
  [[ $(wc -w <<<"$peer_networks") -eq 1 ]] || {
    echo "expected exactly one peer-quic network for $PROJECT, found: $peer_networks" >&2
    return 1
  }
  printf '%s\n' "$peer_networks"
}

monero_p2p_network() {
  local networks
  networks=$(docker network ls \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.network=monero-p2p" \
    --format '{{.Name}}')
  [[ $(wc -w <<<"$networks") -eq 1 ]] || {
    echo "expected exactly one monero-p2p network for $PROJECT, found: $networks" >&2
    return 1
  }
  printf '%s\n' "$networks"
}

record_observer_fault_state() {
  local destination=$1
  local label=$2
  local container
  container=$(compose ps --all --quiet monerod-p1)
  [[ -n "$container" ]] || {
    echo "monerod-p1 container is missing during observer fault" >&2
    return 1
  }
  docker inspect --format \
    "$label container={{.Id}} status={{.State.Status}} running={{.State.Running}} paused={{.State.Paused}} pid={{.State.Pid}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} networks={{json .NetworkSettings.Networks}} volumes={{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}}:{{.Destination}};{{end}}{{end}}" \
    "$container" >>"$destination/observer-fault-state.txt"
}

record_p1_core_status() {
  local destination=$1
  local label=$2
  local response
  response=$(compose exec -T p1 sh -eu -c '
    token=$(tr -d "\r\n" </run/secrets/admin_bearer_token)
    curl --fail --silent --show-error \
      --header "Authorization: Bearer $token" \
      http://127.0.0.1:8080/v1/status
  ')
  grep -Eq '"party"[[:space:]]*:[[:space:]]*1([,}])' <<<"$response" || {
    echo "p1 status lost its authenticated identity during observer fault: $response" >&2
    return 1
  }
  grep -Eq '"ready"[[:space:]]*:[[:space:]]*true([,}])' <<<"$response" || {
    echo "p1 core readiness fell with its observer: $response" >&2
    return 1
  }
  printf '%s response=%s\n' "$label" "$response" \
    >>"$destination/observer-fault-party-status.jsonl"
}

disconnect_and_fork_p1_observer() {
  local destination=$1
  local mining_address=$2
  local fork_blocks=$3
  local container p2p_network container_name response before_p1 before_miner after_p1 after_miner
  local common_tip_deadline
  [[ "$mining_address" =~ ^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{90,110}$ ]] || {
    echo "invalid private-Regtest mining address in E2E marker" >&2
    return 1
  }
  [[ "$fork_blocks" =~ ^[1-9][0-9]*$ ]] || return 2
  common_tip_deadline=$(( $(date +%s) + marker_timeout ))
  while :; do
    before_p1=$(compose exec -T monerod-p1 sh -eu -c '
      curl --fail --silent --show-error -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"id\":\"tip\",\"method\":\"get_last_block_header\"}" \
        http://127.0.0.1:18081/json_rpc
    ')
    before_miner=$(compose exec -T monerod-miner sh -eu -c '
      curl --fail --silent --show-error -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"id\":\"tip\",\"method\":\"get_last_block_header\"}" \
        http://127.0.0.1:18081/json_rpc
    ')
    if python3 - "$before_p1" "$before_miner" <<'PY'
import json
import re
import sys
def tip(raw):
    header = json.loads(raw)["result"]["block_header"]
    height = int(header["height"])
    block_hash = header["hash"]
    assert re.fullmatch(r"[0-9a-f]{64}", block_hash)
    return height, block_hash
raise SystemExit(0 if tip(sys.argv[1]) == tip(sys.argv[2]) else 1)
PY
    then
      break
    fi
    (( $(date +%s) < common_tip_deadline )) || {
      echo "observer and miner never reached one exact common pre-fork tip" >&2
      printf 'p1=%s\nminer=%s\n' "$before_p1" "$before_miner" >&2
      return 1
    }
    sleep 0.25
  done
  container=$(compose ps --quiet monerod-p1)
  [[ -n "$container" ]] || {
    echo "monerod-p1 is not running before fork injection" >&2
    return 1
  }
  p2p_network=$(monero_p2p_network)
  docker network disconnect "$p2p_network" "$container"
  container_name=$(docker inspect --format '{{.Name}}' "$container" | sed 's#^/##')
  ! docker network inspect --format '{{range .Containers}}{{.Name}} {{end}}' "$p2p_network" \
    | tr ' ' '\n' | grep -Fxq "$container_name" || {
    echo "monerod-p1 remained connected to the common fakechain producer" >&2
    return 1
  }
  response=$(compose exec -T \
    -e "TM_OBSERVER_FAULT_MINING_ADDRESS=$mining_address" \
    -e "TM_OBSERVER_FAULT_BLOCKS=$fork_blocks" \
    monerod-p1 sh -eu -c '
      payload=$(printf \
        "{\"jsonrpc\":\"2.0\",\"id\":\"observer-fault\",\"method\":\"generateblocks\",\"params\":{\"wallet_address\":\"%s\",\"amount_of_blocks\":%s,\"reserve_size\":20}}" \
        "$TM_OBSERVER_FAULT_MINING_ADDRESS" "$TM_OBSERVER_FAULT_BLOCKS")
      curl --fail --max-time 30 --show-error --silent \
        --header "Content-Type: application/json" \
        --data "$payload" \
        http://127.0.0.1:18081/json_rpc
    ')
  python3 - "$response" "$fork_blocks" <<'PY'
import json
import re
import sys
value = json.loads(sys.argv[1])
count = int(sys.argv[2])
result = value["result"]
assert result["status"] == "OK"
blocks = result["blocks"]
assert len(blocks) == count
assert len(set(blocks)) == count
assert all(re.fullmatch(r"[0-9a-f]{64}", block) for block in blocks)
PY
  printf '%s\n' "$response" >"$destination/observer-fork-rpc.json"
  after_p1=$(compose exec -T monerod-p1 sh -eu -c '
    curl --fail --silent --show-error -H "Content-Type: application/json" \
      --data "{\"jsonrpc\":\"2.0\",\"id\":\"tip\",\"method\":\"get_last_block_header\"}" \
      http://127.0.0.1:18081/json_rpc
  ')
  after_miner=$(compose exec -T monerod-miner sh -eu -c '
    curl --fail --silent --show-error -H "Content-Type: application/json" \
      --data "{\"jsonrpc\":\"2.0\",\"id\":\"tip\",\"method\":\"get_last_block_header\"}" \
      http://127.0.0.1:18081/json_rpc
  ')
  python3 - "$before_p1" "$before_miner" "$after_p1" "$after_miner" "$fork_blocks" <<'PY'
import json
import re
import sys
def tip(raw):
    header = json.loads(raw)["result"]["block_header"]
    height = int(header["height"])
    block_hash = header["hash"]
    assert re.fullmatch(r"[0-9a-f]{64}", block_hash)
    return height, block_hash
before_p1, before_miner, after_p1, after_miner = map(tip, sys.argv[1:5])
count = int(sys.argv[5])
assert before_p1 == before_miner
assert after_p1[0] == before_p1[0] + count
assert after_miner == before_miner
assert after_p1 != after_miner
assert after_p1[1] != after_miner[1]
PY
  printf 'before_p1=%s\nbefore_miner=%s\nafter_p1=%s\nafter_miner=%s\nfork_blocks=%s\n' \
    "$before_p1" "$before_miner" "$after_p1" "$after_miner" "$fork_blocks" \
    >"$destination/observer-tip-divergence.jsonl"
}

pause_then_stop_p1_observer() {
  local destination=$1
  local stall_interval_ms=$2
  local container stalled_at_unix_ms checked_at_unix_ms observed_stall_ms
  [[ "$stall_interval_ms" =~ ^[1-9][0-9]*$ ]] && ((stall_interval_ms <= 60000)) || {
    echo "observer stall interval must be in 1..=60000ms" >&2
    return 2
  }
  container=$(compose ps --quiet monerod-p1)
  [[ -n "$container" ]] || {
    echo "monerod-p1 is not running before stall injection" >&2
    return 1
  }
  docker pause "$container" >/dev/null
  [[ $(docker inspect --format '{{.State.Paused}}' "$container") == true ]] || {
    echo "monerod-p1 did not enter the stalled state" >&2
    return 1
  }
  record_observer_fault_state "$destination" stalled
  record_p1_core_status "$destination" while-observer-stalled
  stalled_at_unix_ms=$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')
  python3 - "$stall_interval_ms" <<'PY'
import sys
import time
time.sleep(int(sys.argv[1]) / 1000)
PY
  checked_at_unix_ms=$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')
  observed_stall_ms=$((checked_at_unix_ms - stalled_at_unix_ms))
  ((observed_stall_ms >= stall_interval_ms)) || {
    echo "observer did not remain stalled through the configured polling interval" >&2
    return 1
  }
  [[ $(docker inspect --format '{{.State.Paused}}' "$container") == true ]] || {
    echo "observer left the stalled state before the configured polling interval elapsed" >&2
    return 1
  }
  record_observer_fault_state "$destination" stalled-after-poll-interval
  record_p1_core_status "$destination" after-observer-stall-interval
  printf 'required_stall_interval_ms=%s observed_stall_ms=%s stalled_at_unix_ms=%s checked_at_unix_ms=%s\n' \
    "$stall_interval_ms" "$observed_stall_ms" "$stalled_at_unix_ms" "$checked_at_unix_ms" \
    >"$destination/observer-stall-interval.txt"
  docker unpause "$container" >/dev/null
  compose stop --timeout 0 monerod-p1 >/dev/null
  [[ $(docker inspect --format '{{.State.Running}}' "$container") == false ]] || {
    echo "monerod-p1 remained running after the down fault" >&2
    return 1
  }
  record_observer_fault_state "$destination" stopped
  record_p1_core_status "$destination" after-observer-stop
}

validate_party_service() {
  local party=$1
  case "$party" in
    p1|p2|p3|p4|p5|p6|p7|p8) ;;
    *)
      echo "invalid party service selected by E2E barrier: $party" >&2
      return 1
      ;;
  esac
}

record_party_peer_network() {
  local destination=$1
  local party=$2
  local label=$3
  local container
  validate_party_service "$party"
  container=$(compose ps --quiet "$party")
  [[ -n "$container" ]] || {
    echo "$party container is missing during consolidation omission" >&2
    return 1
  }
  docker inspect --format \
    "$label party=$party container={{.Id}} running={{.State.Running}} pid={{.State.Pid}} networks={{json .NetworkSettings.Networks}}" \
    "$container" >>"$destination/consolidation-silent-peer.txt"
}

record_bootstrap_party_process() {
  local destination=$1
  local party=$2
  local label=$3
  local container
  validate_party_service "$party"
  container=$(compose ps --all --quiet "$party")
  [[ -n "$container" ]] || {
    echo "$party container is missing during bootstrap proposer fault" >&2
    return 1
  }
  docker inspect --format \
    "$label party=$party container={{.Id}} status={{.State.Status}} running={{.State.Running}} pid={{.State.Pid}} started={{.State.StartedAt}} finished={{.State.FinishedAt}} restarts={{.RestartCount}} networks={{json .NetworkSettings.Networks}} volumes={{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}}:{{.Destination}};{{end}}{{end}}" \
    "$container" >>"$destination/consolidation-bootstrap-process.txt"
}

assert_bootstrap_party_stopped() {
  local party=$1
  local container
  validate_party_service "$party"
  container=$(compose ps --all --quiet "$party")
  [[ -n "$container" ]] || {
    echo "$party container disappeared instead of remaining stopped" >&2
    return 1
  }
  [[ $(docker inspect --format '{{.State.Running}}' "$container") == false ]] || {
    echo "$party remained running after the bootstrap proposer stop" >&2
    return 1
  }
  [[ -z "$(compose ps --status running --quiet "$party")" ]] || {
    echo "Compose still reports stopped bootstrap proposer $party as running" >&2
    return 1
  }
}

wait_for_party_healthy() {
  local party=$1
  local deadline=$(( $(date +%s) + 180 ))
  local container running health
  validate_party_service "$party"
  while (( $(date +%s) < deadline )); do
    container=$(compose ps --all --quiet "$party")
    if [[ -n "$container" ]]; then
      running=$(docker inspect --format '{{.State.Running}}' "$container")
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container")
      if [[ "$running" == true && "$health" == healthy ]]; then
        return 0
      fi
    fi
    sleep 1
  done
  echo "$party did not become healthy within 180 seconds after restart" >&2
  return 1
}

assert_party_control_healthy() {
  local destination=$1
  local party=$2
  local label=$3
  local expected_id=${party#p}
  local response
  validate_party_service "$party"
  response=$(compose exec -T "$party" sh -eu -c '
    token=$(tr -d "\r\n" </run/secrets/admin_bearer_token)
    curl --fail --silent --show-error \
      --header "Authorization: Bearer $token" \
      http://127.0.0.1:8080/v1/status
  ')
  grep -Eq '"party"[[:space:]]*:[[:space:]]*'"$expected_id"'([,}])' <<<"$response" || {
    echo "$party control status did not identify the expected live party: $response" >&2
    return 1
  }
  grep -Eq '"ready"[[:space:]]*:[[:space:]]*true([,}])' <<<"$response" || {
    echo "$party control status is live but its restored QUIC runtime is not ready: $response" >&2
    return 1
  }
  printf '%s party=%s response=%s\n' "$label" "$party" "$response" \
    >>"$destination/consolidation-silent-control.jsonl"
}

require_terminal_party_health() {
  local destination=$1
  local party expected_id container compose_container running health response canonical
  printf 'party\tcontainer\trunning\thealth\n' \
    >"$destination/terminal-party-process.tsv"
  : >"$destination/terminal-party-status.jsonl"

  for party in p1 p2 p3 p4 p5 p6 p7 p8; do
    validate_party_service "$party"
    expected_id=${party#p}
    container=$(compose ps --all --quiet "$party")
    [[ -n "$container" ]] || {
      echo "$party container is missing at the persistent-network terminal check" >&2
      return 1
    }
    compose_container=$(compose ps --status running --quiet "$party")
    [[ "$compose_container" == "$container" ]] || {
      echo "$party is not the running Compose service at the persistent-network terminal check" >&2
      return 1
    }
    running=$(docker inspect --format '{{.State.Running}}' "$container")
    health=$(docker inspect --format \
      '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container")
    printf '%s\t%s\t%s\t%s\n' "$party" "$container" "$running" "$health" \
      >>"$destination/terminal-party-process.tsv"
    [[ "$running" == true && "$health" == healthy ]] || {
      echo "$party is not running and healthy at the persistent-network terminal check: running=$running health=$health" >&2
      return 1
    }

    response=$(compose exec -T "$party" sh -eu -c '
      token=$(tr -d "\r\n" </run/secrets/admin_bearer_token)
      curl --fail --silent --show-error \
        --header "Authorization: Bearer $token" \
        http://127.0.0.1:8080/v1/status
    ')
    canonical=$(python3 - "$response" "$expected_id" <<'PY'
import json
import sys

value = json.loads(sys.argv[1])
expected_party = int(sys.argv[2])
assert value["party"] == expected_party
assert value["ready"] is True
print(json.dumps(value, sort_keys=True, separators=(",", ":")))
PY
    ) || {
      echo "$party authenticated terminal status is not restored with QUIC ready: $response" >&2
      return 1
    }
    printf '%s\n' "$canonical" >>"$destination/terminal-party-status.jsonl"
  done
}

assert_party_peer_quic_state() {
  local party=$1
  local expected=$2
  local container container_name peer_network attached
  validate_party_service "$party"
  [[ "$expected" == attached || "$expected" == disconnected ]] || {
    echo "invalid peer-QUIC state assertion: $expected" >&2
    return 1
  }
  container=$(compose ps --quiet "$party")
  [[ -n "$container" ]] || {
    echo "$party container is missing while checking peer-QUIC state" >&2
    return 1
  }
  [[ $(docker inspect --format '{{.State.Running}}' "$container") == true ]] || {
    echo "$party process stopped during the consolidation omission" >&2
    return 1
  }
  peer_network=$(peer_quic_network)
  container_name=$(docker inspect --format '{{.Name}}' "$container" | sed 's#^/##')
  attached=disconnected
  if docker network inspect --format '{{range .Containers}}{{.Name}} {{end}}' "$peer_network" \
    | tr ' ' '\n' | grep -Fxq "$container_name"; then
    attached=attached
  fi
  [[ "$attached" == "$expected" ]] || {
    echo "$party peer-QUIC state is $attached, expected $expected" >&2
    return 1
  }
}

disconnect_party_from_peer_quic() {
  local party=$1
  local container peer_network
  validate_party_service "$party"
  container=$(compose ps --quiet "$party")
  [[ -n "$container" ]] || {
    echo "$party container is missing before consolidation omission" >&2
    return 1
  }
  peer_network=$(peer_quic_network)
  docker network disconnect "$peer_network" "$container"
  assert_party_peer_quic_state "$party" disconnected
}

reconnect_party_to_peer_quic() {
  local party=$1
  local container peer_network
  validate_party_service "$party"
  container=$(compose ps --quiet "$party")
  [[ -n "$container" ]] || {
    echo "$party container is missing before peer-QUIC reconnection" >&2
    return 1
  }
  peer_network=$(peer_quic_network)
  docker network connect --alias "$party" --alias "${party}-quic" "$peer_network" "$container"
  assert_party_peer_quic_state "$party" attached
}

record_reconnected_peer_dns() {
  local destination=$1
  local party=$2
  local resolver=p1
  [[ "$party" != p1 ]] || resolver=p2
  local result
  result=$(compose exec -T "$resolver" getent hosts "${party}-quic")
  [[ -n "$result" ]] || {
    echo "$resolver could not resolve restored QUIC alias ${party}-quic" >&2
    return 1
  }
  printf 'resolver=%s target=%s result=%s\n' "$resolver" "${party}-quic" "$result" \
    >>"$destination/consolidation-silent-control.jsonl"
}

release_consolidation_fault_gates() {
  local destination=$1
  local party response
  : >"$destination/consolidation-gate-release.jsonl"
  # The E2E barrier arms all eight configured parties and does not advance until every
  # party reports Released. Peer-QUIC fault injection leaves the admin/control path
  # reachable, so release the omitted signer as well as the seven connected replicas.
  for party in p1 p2 p3 p4 p5 p6 p7 p8; do
    response=$(compose exec -T "$party" sh -eu -c '
      token=$(tr -d "\r\n" </run/secrets/admin_bearer_token)
      curl --fail --silent --show-error \
        --request POST \
        --header "Authorization: Bearer $token" \
        --header "Content-Type: application/json" \
        --data "{\"action\":\"release\"}" \
        http://127.0.0.1:8080/v1/acceptance/consolidation-gate
    ')
    grep -Eq '"state"[[:space:]]*:[[:space:]]*"released"' <<<"$response" || {
      echo "$party did not authenticate and release its held consolidation gate: $response" >&2
      return 1
    }
    printf 'party=%s response=%s\n' "$party" "$response" \
      >>"$destination/consolidation-gate-release.jsonl"
  done
}

release_consolidation_bootstrap_gate_for_party() {
  local destination=$1
  local party=$2
  local response
  validate_party_service "$party"
  response=$(compose exec -T "$party" sh -eu -c '
    token=$(tr -d "\r\n" </run/secrets/admin_bearer_token)
    curl --fail --silent --show-error \
      --request POST \
      --header "Authorization: Bearer $token" \
      --header "Content-Type: application/json" \
      --data "{\"action\":\"release\"}" \
      http://127.0.0.1:8080/v1/acceptance/consolidation-bootstrap-gate
  ')
  grep -Eq '"state"[[:space:]]*:[[:space:]]*"released"' <<<"$response" || {
    echo "$party did not authenticate and release its bootstrap gate: $response" >&2
    return 1
  }
  printf 'party=%s response=%s\n' "$party" "$response" \
    >>"$destination/consolidation-bootstrap-gate-release.jsonl"
}

release_consolidation_bootstrap_survivors() {
  local destination=$1
  local fault_party=$2
  local party
  : >"$destination/consolidation-bootstrap-gate-release.jsonl"
  # The bootstrap barrier is held by every epoch-0 member. Release every live
  # survivor; the stopped proposer is released separately after its restart.
  for party in p1 p2 p3 p4 p5 p6 p7 p8; do
    [[ "$party" == "$fault_party" ]] && continue
    release_consolidation_bootstrap_gate_for_party "$destination" "$party"
  done
}

record_required_e2e_marker() {
  local log_file=$1
  local marker=$2
  local match_mode=${3:-contains}
  local destination matches count kind
  destination=${log_file%/*}
  case "$match_mode" in
    contains)
      matches=$(grep -nF -- "$marker" "$log_file" || true)
      ;;
    exact)
      matches=$(grep -nFx -- "$marker" "$log_file" || true)
      ;;
    *)
      echo "invalid marker match mode: $match_mode" >&2
      return 2
      ;;
  esac
  count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
  [[ "$count" -eq 1 ]] || {
    echo "acceptance requires exactly one '$match_mode' marker, found $count: $marker" >&2
    tail -n 120 "$log_file" >&2 || true
    return 1
  }
  kind=$match_mode
  printf '%s\t%s\t%s\n' "$kind" "${matches%%:*}" "${matches#*:}" \
    >>"$destination/required-markers.tsv"
}

marker_line_number() {
  local log_file=$1
  local marker=$2
  local match_mode=${3:-contains}
  case "$match_mode" in
    contains)
      grep -nF -- "$marker" "$log_file" | cut -d: -f1
      ;;
    exact)
      grep -nFx -- "$marker" "$log_file" | cut -d: -f1
      ;;
    *)
      return 2
      ;;
  esac
}

require_marker_order() {
  local log_file=$1
  shift
  local marker line previous=0
  for marker in "$@"; do
    line=$(marker_line_number "$log_file" "$marker")
    [[ "$line" =~ ^[1-9][0-9]*$ && "$line" -gt "$previous" ]] || {
      echo "required marker order is invalid at '$marker' (line=$line, previous=$previous)" >&2
      return 1
    }
    previous=$line
  done
}

record_canonical_transaction_artifact() {
  local artifact_directory=$1
  local artifact_name=$2
  local expected_txid=$3
  local expected_byte_count=$4
  local input_count=$5
  local transaction_hex=$6
  local artifact_prefix binary_path roundtrip actual_byte_count digest verifier_line
  local derived_txid verified_input_count verified_class
  local expected_class=monero_v2_clsag_bulletproof_plus_ring16_two_output

  [[ "$expected_txid" =~ ^[0-9a-f]{64}$ \
    && "$expected_byte_count" =~ ^[1-9][0-9]*$ \
    && "$input_count" =~ ^[1-9][0-9]*$ \
    && "$transaction_hex" =~ ^[0-9a-f]+$ \
    && $((${#transaction_hex} % 2)) -eq 0 \
    && ${#transaction_hex} -eq $((expected_byte_count * 2)) ]] || {
    echo "signed transaction marker has malformed txid, size, input count, or exact hex" >&2
    return 1
  }

  mkdir -p -- "$artifact_directory"
  artifact_prefix="$artifact_directory/$artifact_name"
  printf '%s' "$transaction_hex" >"$artifact_prefix.hex"
  xxd -r -p "$artifact_prefix.hex" >"$artifact_prefix.bin"
  roundtrip=$(xxd -p "$artifact_prefix.bin" | tr -d '\n')
  [[ "$roundtrip" == "$transaction_hex" ]] || {
    echo "$artifact_name failed its exact hex/binary round trip" >&2
    return 1
  }
  actual_byte_count=$(wc -c <"$artifact_prefix.bin" | tr -d ' ')
  [[ "$actual_byte_count" -eq "$expected_byte_count" ]] || {
    echo "$artifact_name has an inconsistent binary byte length" >&2
    return 1
  }

  binary_path=$(
    CDPATH= cd -- "$(dirname -- "$artifact_prefix.bin")" \
      && printf '%s/%s\n' "$PWD" "$(basename -- "$artifact_prefix.bin")"
  )
  if ! docker run --rm --network none --read-only --cap-drop ALL \
    --mount "type=bind,source=$binary_path,target=/transaction.bin,readonly" \
    threshold-monero/signer:local \
    verify-transaction-artifact \
    --transaction-file /transaction.bin \
    --expected-txid "$expected_txid" \
    --expected-input-count "$input_count" \
    >"$artifact_prefix.verifier.txt" 2>&1; then
    echo "$artifact_name failed independent canonical Monero transaction verification" >&2
    cat "$artifact_prefix.verifier.txt" >&2
    return 1
  fi
  verifier_line=$(grep -E \
    '^TM_TRANSACTION_ARTIFACT_VERIFIED txid=[0-9a-f]{64} bytes=[1-9][0-9]* inputs=[1-9][0-9]* class=monero_v2_clsag_bulletproof_plus_ring16_two_output$' \
    "$artifact_prefix.verifier.txt" || true)
  [[ $(printf '%s\n' "$verifier_line" | sed '/^$/d' | wc -l | tr -d ' ') -eq 1 \
    && "$verifier_line" =~ ^TM_TRANSACTION_ARTIFACT_VERIFIED[[:space:]]txid=([0-9a-f]{64})[[:space:]]bytes=([1-9][0-9]*)[[:space:]]inputs=([1-9][0-9]*)[[:space:]]class=([a-z0-9_]+)$ ]] || {
    echo "$artifact_name verifier did not emit one strict canonical result" >&2
    cat "$artifact_prefix.verifier.txt" >&2
    return 1
  }
  derived_txid=${BASH_REMATCH[1]}
  actual_byte_count=${BASH_REMATCH[2]}
  verified_input_count=${BASH_REMATCH[3]}
  verified_class=${BASH_REMATCH[4]}
  [[ "$derived_txid" == "$expected_txid" \
    && "$actual_byte_count" -eq "$expected_byte_count" \
    && "$verified_input_count" -eq "$input_count" \
    && "$verified_class" == "$expected_class" ]] || {
    echo "$artifact_name verifier result differs from its acceptance marker" >&2
    return 1
  }

  digest=$(openssl dgst -sha256 "$artifact_prefix.bin" | awk '{print $NF}')
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
    echo "failed to hash $artifact_name" >&2
    return 1
  }
  printf '%s\n' "$expected_txid" >"$artifact_prefix.expected-txid"
  printf '%s\n' "$derived_txid" >"$artifact_prefix.derived-txid"
  printf '%s  %s.bin\n' "$digest" "$artifact_name" >"$artifact_prefix.sha256"
  printf 'source=daemon-returned-transaction-serialize\nexpected_txid=%s\nderived_txid=%s\nbytes=%s\nexpected_inputs=%s\nverified_inputs=%s\nexpected_class=%s\nverified_class=%s\nsha256=%s\ncanonical_verifier=threshold-monero/verify-transaction-artifact\n' \
    "$expected_txid" "$derived_txid" "$expected_byte_count" \
    "$input_count" "$verified_input_count" "$expected_class" "$verified_class" "$digest" \
    >"$artifact_prefix.evidence.env"
}

record_signed_transaction_evidence() {
  local log_file=$1
  local destination=$2
  local matches payload txid byte_count input_count transaction_hex multi_input_line

  record_required_e2e_marker "$log_file" "$SIGNED_TRANSACTION_MARKER"
  matches=$(grep -nF -- "$SIGNED_TRANSACTION_MARKER" "$log_file")
  payload=${matches#*:}
  if [[ ! "$payload" =~ ^TM_ACCEPTANCE_SIGNED_TRANSACTION[[:space:]]txid=([0-9a-f]{64})[[:space:]]bytes=([1-9][0-9]*)[[:space:]]inputs=(2)[[:space:]]hex=([0-9a-f]+)$ ]]; then
    echo "initial two-input signed transaction marker is malformed" >&2
    return 1
  fi
  txid=${BASH_REMATCH[1]}
  byte_count=${BASH_REMATCH[2]}
  input_count=${BASH_REMATCH[3]}
  transaction_hex=${BASH_REMATCH[4]}

  multi_input_line=$(grep -F -- "$MULTI_INPUT_CONSOLIDATION_MARKER" "$log_file")
  [[ "$multi_input_line" == \
    "TM_ACCEPTANCE_MULTI_INPUT_CONSOLIDATION txid=$txid inputs=$input_count" ]] || {
    echo "multi-input ring-mapping acceptance is not bound to the initial transaction" >&2
    return 1
  }
  record_canonical_transaction_artifact \
    "$destination" signed-transaction "$txid" "$byte_count" "$input_count" "$transaction_hex"
}

record_successor_epoch_signing_evidence() {
  local log_file=$1
  local destination=$2
  local epoch marker matches count payload line_number previous=0 first=0
  local txid byte_count input_count transaction_hex artifact_directory digest
  local initial_line terminal_line
  local successor_root="$destination/successor-epoch-signed-transactions"
  mkdir -p -- "$successor_root"
  printf 'epoch\ttxid\tbytes\tinputs\tsha256\tartifact_directory\n' \
    >"$destination/successor-epoch-signed-transactions.tsv"

  initial_line=$(marker_line_number "$log_file" "$SIGNED_TRANSACTION_MARKER")
  terminal_line=$(
    marker_line_number "$log_file" "$SUCCESSOR_EPOCH_SIGNING_TERMINAL_MARKER" exact
  )
  [[ "$initial_line" =~ ^[1-9][0-9]*$ && "$terminal_line" =~ ^[1-9][0-9]*$ ]] || {
    echo "successor signing evidence lacks its initial or terminal ordering anchor" >&2
    return 1
  }

  for epoch in 1 2 3 4 5; do
    marker="${SUCCESSOR_EPOCH_SIGNED_TRANSACTION_MARKER}${epoch} "
    matches=$(grep -nF -- "$marker" "$log_file" || true)
    count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
    [[ "$count" -eq 1 ]] || {
      echo "acceptance requires exactly one successor signing marker for epoch $epoch, found $count" >&2
      return 1
    }
    line_number=${matches%%:*}
    payload=${matches#*:}
    if [[ ! "$payload" =~ ^TM_ACCEPTANCE_SUCCESSOR_EPOCH_SIGNED_TRANSACTION[[:space:]]epoch=${epoch}[[:space:]]txid=([0-9a-f]{64})[[:space:]]bytes=([1-9][0-9]*)[[:space:]]inputs=(1)[[:space:]]hex=([0-9a-f]+)$ ]]; then
      echo "epoch-$epoch single-input successor signing marker is malformed" >&2
      return 1
    fi
    txid=${BASH_REMATCH[1]}
    byte_count=${BASH_REMATCH[2]}
    input_count=${BASH_REMATCH[3]}
    transaction_hex=${BASH_REMATCH[4]}
    [[ "$line_number" -gt "$previous" ]] || {
      echo "successor signing markers are not in strict epoch order at epoch $epoch" >&2
      return 1
    }
    [[ "$first" -ne 0 ]] || first=$line_number
    previous=$line_number
    printf 'contains\t%s\t%s\n' "$line_number" "$payload" \
      >>"$destination/required-markers.tsv"

    artifact_directory="$successor_root/epoch-$epoch"
    record_canonical_transaction_artifact \
      "$artifact_directory" transaction "$txid" "$byte_count" "$input_count" "$transaction_hex"
    digest=$(awk '{print $1}' "$artifact_directory/transaction.sha256")
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$epoch" "$txid" "$byte_count" "$input_count" "$digest" \
      "successor-epoch-signed-transactions/epoch-$epoch" \
      >>"$destination/successor-epoch-signed-transactions.tsv"
  done

  [[ "$first" -gt "$initial_line" && "$previous" -lt "$terminal_line" ]] || {
    echo "successor signing evidence is outside the initial-signing/terminal marker interval" >&2
    return 1
  }
}

record_exact_refresh_evidence() {
  local log_file=$1
  local destination=$2
  local marker_line
  record_required_e2e_marker "$log_file" "$EXACT_REFRESH_MARKER"
  marker_line=$(grep -F -- "$EXACT_REFRESH_MARKER" "$log_file")
  python3 - "$marker_line" >"$destination/exact-same-committee-refresh.env" <<'PY'
import re
import sys

line = sys.argv[1]
match = re.fullmatch(
    r"TM_ACCEPTANCE_EXACT_SAME_COMMITTEE_REFRESH "
    r"source_epoch=(1) target_epoch=(2) purpose=(refresh) "
    r"members=(2,3,4,5,6,7,8) "
    r"key_id=([0-9a-f]{64}) group_key=([0-9a-f]{64}) "
    r"source_verification_shares=([0-9a-f]{64}) "
    r"target_verification_shares=([0-9a-f]{64}) "
    r"receiver_keys=(fresh) transition_digest=([0-9a-f]{64}) "
    r"reshare_transition_digest=([0-9a-f]{64})",
    line,
)
assert match, "malformed exact-refresh marker"
(
    source,
    target,
    purpose,
    members,
    key_id,
    group_key,
    source_shares,
    target_shares,
    receiver_keys,
    refresh_digest,
    reshare_digest,
) = match.groups()
assert key_id != "0" * 64 and group_key != "0" * 64
assert source_shares != target_shares
assert refresh_digest != reshare_digest
print(f"source_epoch={source}")
print(f"target_epoch={target}")
print(f"purpose={purpose}")
print(f"members={members}")
print(f"key_id={key_id}")
print(f"group_key={group_key}")
print(f"source_verification_shares={source_shares}")
print(f"target_verification_shares={target_shares}")
print(f"receiver_keys={receiver_keys}")
print(f"refresh_transition_digest={refresh_digest}")
print(f"rejected_reshare_transition_digest={reshare_digest}")
print("signature_artifact=successor-epoch-signed-transactions/epoch-2/transaction.bin")
PY
  [[ -s "$destination/successor-epoch-signed-transactions/epoch-2/transaction.bin" \
    && -s "$destination/successor-epoch-signed-transactions/epoch-2/transaction.evidence.env" ]] || {
    echo "exact refresh lacks its canonical epoch-2 Regtest Monero signature artifact" >&2
    return 1
  }
}

reject_successor_epoch_signing_evidence() {
  local log_file=$1
  if grep -Fq -- "$SUCCESSOR_EPOCH_SIGNED_TRANSACTION_MARKER" "$log_file" \
    || grep -Fxq -- "$SUCCESSOR_EPOCH_SIGNING_TERMINAL_MARKER" "$log_file" \
    || grep -Fq -- "$SIGNED_TRANSACTION_MARKER" "$log_file" \
    || grep -Fq -- "$MULTI_INPUT_CONSOLIDATION_MARKER" "$log_file"; then
    echo "narrowed acceptance emitted full-only transaction signing evidence" >&2
    return 1
  fi
}

require_genesis_contract() {
  local log_file=$1
  if compose_uses_file compose.acceptance-manual-bootstrap.yaml; then
    if grep -Fq -- "$AUTONOMOUS_GENESIS_MARKER" "$log_file"; then
      echo "manual fault-gate acceptance falsely claimed observer-only autonomous genesis" >&2
      return 1
    fi
    return 0
  fi
  record_required_e2e_marker "$log_file" "$AUTONOMOUS_GENESIS_MARKER"
}

require_terminal_contract() {
  local log_file=$1
  local destination=$2
  local contract=$3

  require_genesis_contract "$log_file"
  record_required_e2e_marker "$log_file" "$ALL_EPOCHS_TERMINAL_MARKER" exact
  case "$contract" in
    full)
      record_required_e2e_marker "$log_file" "$CONSOLIDATION_TRANSACTION_MARKER"
      record_required_e2e_marker "$log_file" "$MULTI_INPUT_CONSOLIDATION_MARKER"
      record_signed_transaction_evidence "$log_file" "$destination"
      record_required_e2e_marker \
        "$log_file" "$SUCCESSOR_EPOCH_SIGNING_TERMINAL_MARKER" exact
      record_successor_epoch_signing_evidence "$log_file" "$destination"
      require_marker_order \
        "$log_file" \
        "$CONSOLIDATION_TRANSACTION_MARKER" \
        "$SIGNED_TRANSACTION_MARKER" \
        "$SUCCESSOR_EPOCH_SIGNING_TERMINAL_MARKER" \
        "$ALL_EPOCHS_TERMINAL_MARKER"
      ;;
    allocation-only)
      record_required_e2e_marker "$log_file" "$ALLOCATION_TERMINAL_MARKER" exact
      reject_successor_epoch_signing_evidence "$log_file"
      require_marker_order \
        "$log_file" "$ALLOCATION_TERMINAL_MARKER" "$ALL_EPOCHS_TERMINAL_MARKER"
      ;;
    protocol-only)
      record_required_e2e_marker "$log_file" "$PROTOCOL_TERMINAL_MARKER" exact
      reject_successor_epoch_signing_evidence "$log_file"
      require_marker_order \
        "$log_file" "$PROTOCOL_TERMINAL_MARKER" "$ALL_EPOCHS_TERMINAL_MARKER"
      ;;
    *)
      echo "unsupported terminal contract: $contract" >&2
      return 2
      ;;
  esac
}

run_full_e2e() {
  local case_name=$1
  local log_file="$artifact_root/$case_name/e2e.log"
  local destination="$artifact_root/$case_name"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  verify_full_acceptance_contract
  record_acceptance_contract "$case_name" full 1 1
  compose --profile acceptance run --rm --no-deps e2e >"$log_file" 2>&1 &
  local pid=$!
  wait_for_process "$pid" "$deadline" "$log_file"
  require_terminal_contract "$log_file" "$destination" full
  require_marker_order \
    "$log_file" \
    "$AUTONOMOUS_GENESIS_MARKER" \
    "$REGTEST_MINING_ADDRESS_MARKER" \
    "$SIGNED_TRANSACTION_MARKER" \
    "$ALL_EPOCHS_TERMINAL_MARKER"
  cat "$log_file"
}

run_observer_byzantine_e2e() {
  local case_name=$1
  local log_file="$artifact_root/$case_name/e2e.log"
  local destination="$artifact_root/$case_name"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  local marker_budget mining_address marker_line binding response fork_blocks poll_interval_ms
  local stall_interval_ms
  verify_full_acceptance_contract
  [[ ${#OBSERVER_BYZANTINE_E2E_OVERRIDES[@]} -eq 1 \
    && "${OBSERVER_BYZANTINE_E2E_OVERRIDES[0]}" == --env=TM_FAULTY_PARTIES=1 ]] || {
    echo "observer Byzantine acceptance must exclude exactly p1 from n-f client polling" >&2
    return 1
  }
  record_acceptance_contract "$case_name" full-with-one-byzantine-observer 1 1
  printf '%s\n' \
    'fault_identity=p1' \
    'observer=monerod-p1' \
    'sequence=isolated-fork,process-stall,process-down' \
    'party_process_remains_live=true' \
    >"$destination/observer-fault-contract.env"
  : >"$destination/observer-fault-state.txt"
  : >"$destination/observer-fault-party-status.jsonl"
  record_observer_fault_state "$destination" before
  record_p1_core_status "$destination" before

  compose --profile acceptance run --rm --no-deps \
    "${OBSERVER_BYZANTINE_E2E_OVERRIDES[@]}" \
    -e TM_ACCEPTANCE_ENABLE_FAULT_HOOKS=1 \
    -e TM_ACCEPTANCE_PAUSE_AFTER_DEPOSIT_FUNDING=1 \
    -e TM_ACCEPTANCE_DEPOSIT_FAULT_MODE=observer_fork \
    e2e >"$log_file" 2>&1 &
  local pid=$!
  marker_budget=$(( deadline - $(date +%s) ))
  ((marker_budget > 0)) || {
    echo "observer Byzantine campaign exhausted its deadline before the deposit barrier" >&2
    return 124
  }
  wait_for_marker "$pid" "$log_file" "$OBSERVER_FAULT_LATCH_HELD_MARKER" "$marker_budget"
  wait_for_marker "$pid" "$log_file" "$REGTEST_MINING_ADDRESS_MARKER" 10
  mining_address=$(sed -nE \
    "s/^${REGTEST_MINING_ADDRESS_MARKER}([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$/\\1/p" \
    "$log_file" | tail -n 1)
  [[ -n "$mining_address" ]] || {
    echo "E2E did not emit an exact private-Regtest mining address" >&2
    return 1
  }

  marker_line=$(grep -F "$OBSERVER_FAULT_LATCH_HELD_MARKER" "$log_file")
  [[ $(grep -Fc "$OBSERVER_FAULT_LATCH_HELD_MARKER" "$log_file") -eq 1 ]] || {
    echo "observer fault latch emitted ambiguous held evidence" >&2
    return 1
  }
  binding=$(sed -nE 's/.* binding=([0-9a-f]{64})$/\1/p' <<<"$marker_line")
  [[ "$binding" =~ ^[0-9a-f]{64}$ ]] || {
    echo "observer fault latch binding is malformed: $marker_line" >&2
    return 1
  }
  response=$(driver_latch_call p1 status observer_fork "$binding")
  validate_driver_latch_response "$response" p1 held observer_fork "$binding"
  printf 'held %s\n' "$response" >"$destination/observer-driver-latch.jsonl"
  fork_blocks=$(python3 - <<'PY'
import json
with open("docker/configs/regtest-scenario.json", encoding="utf-8") as handle:
    print(int(json.load(handle)["confirmation_blocks"]) + 1)
PY
)
  disconnect_and_fork_p1_observer "$destination" "$mining_address" "$fork_blocks"
  record_observer_fault_state "$destination" isolated-fork
  record_p1_core_status "$destination" after-isolated-fork
  poll_interval_ms=$(python3 - <<'PY'
import json
with open("docker/configs/regtest-scenario.json", encoding="utf-8") as handle:
    print(int(json.load(handle)["poll_interval_ms"]))
PY
)
  stall_interval_ms=$((poll_interval_ms * 2))
  pause_then_stop_p1_observer "$destination" "$stall_interval_ms"
  response=$(driver_latch_call p1 release observer_fork "$binding")
  validate_driver_latch_response "$response" p1 released observer_fork "$binding"
  printf 'released %s\n' "$response" >>"$destination/observer-driver-latch.jsonl"

  wait_for_process "$pid" "$deadline" "$log_file"
  record_required_e2e_marker "$log_file" "$REGTEST_MINING_ADDRESS_MARKER"
  record_required_e2e_marker "$log_file" "$OBSERVER_FAULT_LATCH_HELD_MARKER"
  record_required_e2e_marker "$log_file" "$OBSERVER_FAULT_LATCH_RELEASED_MARKER"
  require_terminal_contract "$log_file" "$destination" full
  require_marker_order \
    "$log_file" \
    "$REGTEST_MINING_ADDRESS_MARKER" \
    "$OBSERVER_FAULT_LATCH_HELD_MARKER" \
    "$OBSERVER_FAULT_LATCH_RELEASED_MARKER" \
    "$CONSOLIDATION_TRANSACTION_MARKER" \
    "$SIGNED_TRANSACTION_MARKER" \
    "$ALL_EPOCHS_TERMINAL_MARKER"
  record_observer_fault_state "$destination" after-e2e
  record_p1_core_status "$destination" after-e2e
  [[ -z "$(compose ps --status running --quiet monerod-p1)" ]] || {
    echo "monerod-p1 restarted after its explicit down fault" >&2
    return 1
  }
  cat "$log_file"
}

run_protocol_only_e2e() {
  local case_name=$1
  local log_file="$artifact_root/$case_name/e2e.log"
  local destination="$artifact_root/$case_name"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  verify_protocol_only_acceptance_contract
  record_acceptance_contract "$case_name" protocol-only 0 0
  compose --profile acceptance run --rm --no-deps \
    "${PROTOCOL_ONLY_E2E_OVERRIDES[@]}" \
    e2e >"$log_file" 2>&1 &
  local pid=$!
  wait_for_process "$pid" "$deadline" "$log_file"
  require_terminal_contract "$log_file" "$destination" protocol-only
  cat "$log_file"
}

run_allocation_only_e2e() {
  local case_name=$1
  local log_file="$artifact_root/$case_name/e2e.log"
  local destination="$artifact_root/$case_name"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  verify_allocation_only_acceptance_contract
  record_acceptance_contract "$case_name" allocation-only 1 0
  compose --profile acceptance run --rm --no-deps \
    "${ALLOCATION_ONLY_E2E_OVERRIDES[@]}" \
    e2e >"$log_file" 2>&1 &
  local pid=$!
  wait_for_process "$pid" "$deadline" "$log_file"
  require_terminal_contract "$log_file" "$destination" allocation-only
  cat "$log_file"
}

prepare_deposit_ttl_clock_directory() {
  local destination=$1
  local clock_directory="$destination/deposit-clock-live"
  mkdir -p -- "$clock_directory"
  if find "$clock_directory" -mindepth 1 -print -quit | grep -q .; then
    echo "deposit-ttl acceptance requires an empty clock directory" >&2
    return 1
  fi
  chmod 0777 "$clock_directory"
  clock_directory=$(
    CDPATH= cd -- "$clock_directory" \
      && printf '%s\n' "$PWD"
  )
  export TM_ACCEPTANCE_DEPOSIT_CLOCK_DIR=$clock_directory
  {
    printf 'host_directory=%s\n' "$clock_directory"
    printf 'container_file=/run/threshold-monero-acceptance/deposit-clock\n'
    printf 'initial_file=absent\n'
    printf 'initial_generation=1\n'
    printf 'party_mount=read-only\n'
    printf 'e2e_mount=read-write\n'
  } >"$destination/deposit-clock-contract.env"
  ls -ld "$clock_directory" >"$destination/deposit-clock-directory-before.txt"
}

record_deposit_ttl_evidence() {
  local log_file=$1
  local destination=$2
  local live_clock_file=$3
  [[ -s "$live_clock_file" ]] || {
    echo "deposit-ttl E2E did not leave its canonical final clock file" >&2
    return 1
  }
  mkdir -p -- "$destination/deposit-clock-generations"
  python3 - "$log_file" "$live_clock_file" "$destination" <<'PY'
import hashlib
import re
import sys
from pathlib import Path

log_path, live_clock_path, destination_path = map(Path, sys.argv[1:])
lines = log_path.read_text(encoding="utf-8").splitlines()
destination_path.mkdir(parents=True, exist_ok=True)
archive = destination_path / "deposit-clock-generations"
archive.mkdir(parents=True, exist_ok=True)

def one(pattern, name):
    matches = []
    for line in lines:
        match = re.fullmatch(pattern, line)
        if match:
            matches.append((line, match))
    assert len(matches) == 1, f"expected one exact {name} marker, found {len(matches)}"
    return matches[0]

def canonical_u64(value):
    assert re.fullmatch(r"0|[1-9]\d*", value)
    parsed = int(value)
    assert 0 <= parsed < 2**64
    return parsed

def positive_u64(value):
    parsed = canonical_u64(value)
    assert parsed > 0
    return parsed

def index(account, address):
    account = canonical_u64(account)
    address = canonical_u64(address)
    assert account < 2**32 and 0 < address < 2**32
    return account, address

def replicas(value):
    parsed = [int(item) for item in value.split(",")]
    assert parsed == sorted(set(parsed))
    assert len(parsed) >= 4
    assert set(parsed).issubset(set(range(1, 6)))
    return parsed

clock_pattern = (
    r"TM_ACCEPTANCE_DEPOSIT_CLOCK generation=(\d+) unix_seconds=(\d+) "
    r"phase=([a-z-]+)"
)
clock_matches = [
    (line, re.fullmatch(clock_pattern, line))
    for line in lines
    if line.startswith("TM_ACCEPTANCE_DEPOSIT_CLOCK ")
]
assert len(clock_matches) == 6
assert all(match is not None for _, match in clock_matches)
expected_phases = [
    "bootstrap",
    "unused-visible",
    "permanent-visible",
    "unused-last-active",
    "unused-expired",
    "replacement-visible",
]
clock_values = []
for expected_generation, expected_phase, (line, match) in zip(
    range(1, 7), expected_phases, clock_matches, strict=True
):
    generation = positive_u64(match.group(1))
    unix_seconds = positive_u64(match.group(2))
    phase = match.group(3)
    assert generation == expected_generation
    assert phase == expected_phase
    clock_values.append((generation, unix_seconds, phase, line))
assert all(
    previous[1] < current[1]
    for previous, current in zip(clock_values, clock_values[1:])
)

active_line, active_match = one(
    r"TM_ACCEPTANCE_DEPOSIT_TTL_ACTIVE "
    r"request=([0-9a-f]{64}) sequence=(\d+) index=(\d+):(\d+) "
    r"created_at=(\d+) observed_at=(\d+) expires_at=(\d+) "
    r"statement=([0-9a-f]{64}) replicas=([1-8](?:,[1-8])*) "
    r"clock_generation=(\d+)",
    "deposit TTL Active",
)
expired_line, expired_match = one(
    r"TM_ACCEPTANCE_DEPOSIT_TTL_EXPIRED "
    r"request=([0-9a-f]{64}) sequence=(\d+) index=(\d+):(\d+) "
    r"observed_at=(\d+) expires_at=(\d+) "
    r"address_hidden=true certificate_hidden=true replicas=([1-8](?:,[1-8])*) "
    r"clock_generation=(\d+)",
    "deposit TTL Expired",
)
not_reused_line, not_reused_match = one(
    r"TM_ACCEPTANCE_DEPOSIT_TTL_NOT_REUSED "
    r"expired_sequence=(\d+) expired_index=(\d+):(\d+) "
    r"expired_address=([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{95}) "
    r"new_sequence=(\d+) new_index=(\d+):(\d+) "
    r"new_address=([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{95}) "
    r"replicas=([1-8](?:,[1-8])*) clock_generation=(\d+)",
    "deposit TTL non-reuse",
)
permanent_line, permanent_match = one(
    r"TM_ACCEPTANCE_DEPOSIT_TTL_PERMANENT "
    r"request=([0-9a-f]{64}) sequence=(\d+) index=(\d+):(\d+) "
    r"observed_at=(\d+) expires_at=(\d+) "
    r"output=([0-9a-f]{64}):(\d+) statement=([0-9a-f]{64}) "
    r"replicas=([1-8](?:,[1-8])*) clock_generation=(\d+)",
    "deposit TTL Permanent",
)
funding_line, funding_match = one(
    r"TM_ACCEPTANCE_DEPOSIT_FUNDING_TRANSACTION "
    r"txid=([0-9a-f]{64}) bytes=([1-9]\d*) outputs=(1)",
    "deposit funding transaction",
)
funding_hex_line, funding_hex_match = one(
    r"TM_ACCEPTANCE_DEPOSIT_FUNDING_TRANSACTION_HEX=([0-9a-f]+)",
    "deposit funding transaction hex",
)

ttl_seconds = 30 * 24 * 60 * 60
active_request = active_match.group(1)
active_sequence = positive_u64(active_match.group(2))
active_index = index(active_match.group(3), active_match.group(4))
active_created = positive_u64(active_match.group(5))
active_observed = positive_u64(active_match.group(6))
active_expires = positive_u64(active_match.group(7))
active_statement = active_match.group(8)
replicas(active_match.group(9))
assert positive_u64(active_match.group(10)) == 4

assert expired_match.group(1) == active_request
assert positive_u64(expired_match.group(2)) == active_sequence
assert index(expired_match.group(3), expired_match.group(4)) == active_index
expired_observed = positive_u64(expired_match.group(5))
expired_expires = positive_u64(expired_match.group(6))
replicas(expired_match.group(7))
assert positive_u64(expired_match.group(8)) == 5

expired_sequence = positive_u64(not_reused_match.group(1))
expired_index = index(not_reused_match.group(2), not_reused_match.group(3))
expired_address = not_reused_match.group(4)
new_sequence = positive_u64(not_reused_match.group(5))
new_index = index(not_reused_match.group(6), not_reused_match.group(7))
new_address = not_reused_match.group(8)
replicas(not_reused_match.group(9))
assert positive_u64(not_reused_match.group(10)) == 6

permanent_request = permanent_match.group(1)
permanent_sequence = positive_u64(permanent_match.group(2))
permanent_index = index(permanent_match.group(3), permanent_match.group(4))
permanent_observed = positive_u64(permanent_match.group(5))
permanent_expires = positive_u64(permanent_match.group(6))
permanent_output_txid = permanent_match.group(7)
permanent_output_index = canonical_u64(permanent_match.group(8))
permanent_statement = permanent_match.group(9)
replicas(permanent_match.group(10))
assert positive_u64(permanent_match.group(11)) == 6

funding_txid = funding_match.group(1)
funding_bytes = positive_u64(funding_match.group(2))
funding_outputs = positive_u64(funding_match.group(3))
funding_hex = funding_hex_match.group(1)
assert len(funding_hex) % 2 == 0
funding_binary = bytes.fromhex(funding_hex)
assert len(funding_binary) == funding_bytes
assert funding_outputs == 1
assert permanent_output_txid == funding_txid
assert permanent_output_index < funding_outputs

times = [entry[1] for entry in clock_values]
assert times[1] - times[0] == 60
assert times[2] - times[1] == 60
assert times[3] == times[1] + ttl_seconds - 1
assert times[4] == times[1] + ttl_seconds
assert times[5] == times[2] + ttl_seconds == times[4] + 60
assert active_created == times[1]
assert active_observed == times[3]
assert active_expires == times[4]
assert active_expires - active_created == ttl_seconds
assert active_observed + 1 == active_expires
assert expired_observed == expired_expires == active_expires
assert expired_sequence == active_sequence
assert expired_index == active_index
assert new_sequence > permanent_sequence > expired_sequence
assert new_index[0] == permanent_index[0] == expired_index[0]
assert new_index[1] > permanent_index[1] > expired_index[1]
assert new_address != expired_address
assert permanent_request != active_request
assert permanent_statement != active_statement
assert permanent_observed == permanent_expires == times[5]
assert permanent_expires - times[2] == ttl_seconds

live_bytes = live_clock_path.read_bytes()
live_text = live_bytes.decode("utf-8")
live_match = re.fullmatch(
    r"threshold-monero-deposit-clock-v1\n"
    r"network=([0-9a-f]{64})\n"
    r"generation=([1-9]\d*)\n"
    r"unix_seconds=([1-9]\d*)\n",
    live_text,
)
assert live_match is not None
network = live_match.group(1)
assert positive_u64(live_match.group(2)) == 6
assert positive_u64(live_match.group(3)) == times[5]

manifest_lines = ["generation\tphase\tunix_seconds\tsha256\tfile"]
for generation, unix_seconds, phase, _ in clock_values:
    canonical = (
        "threshold-monero-deposit-clock-v1\n"
        f"network={network}\n"
        f"generation={generation}\n"
        f"unix_seconds={unix_seconds}\n"
    ).encode()
    path = archive / f"generation-{generation:02d}-{phase}.clock"
    path.write_bytes(canonical)
    digest = hashlib.sha256(canonical).hexdigest()
    manifest_lines.append(
        f"{generation}\t{phase}\t{unix_seconds}\t{digest}\t{path.name}"
    )
assert (archive / "generation-06-replacement-visible.clock").read_bytes() == live_bytes
(destination_path / "deposit-clock-generations.tsv").write_text(
    "\n".join(manifest_lines) + "\n",
    encoding="utf-8",
)
(destination_path / "deposit-ttl-semantic-markers.txt").write_text(
    "\n".join([active_line, expired_line, not_reused_line, permanent_line]) + "\n",
    encoding="utf-8",
)
(destination_path / "deposit-funding-transaction.hex").write_text(
    funding_hex + "\n",
    encoding="ascii",
)
(destination_path / "deposit-funding-transaction.bin").write_bytes(funding_binary)
funding_sha256 = hashlib.sha256(funding_binary).hexdigest()
(destination_path / "deposit-funding-transaction.sha256").write_text(
    f"{funding_sha256}  deposit-funding-transaction.bin\n",
    encoding="ascii",
)
(destination_path / "deposit-ttl-evidence.env").write_text(
    "\n".join([
        "contract=focused-deposit-ttl",
        f"clock_network={network}",
        "clock_generations=6",
        f"ttl_seconds={ttl_seconds}",
        f"unused_request={active_request}",
        f"unused_sequence={active_sequence}",
        f"unused_index={active_index[0]}:{active_index[1]}",
        f"unused_created_at={active_created}",
        f"unused_last_active_at={active_observed}",
        f"unused_expires_at={active_expires}",
        "expired_address_hidden=true",
        "expired_certificate_hidden=true",
        f"replacement_sequence={new_sequence}",
        f"replacement_index={new_index[0]}:{new_index[1]}",
        "replacement_address_reused=false",
        f"permanent_request={permanent_request}",
        f"permanent_sequence={permanent_sequence}",
        f"permanent_index={permanent_index[0]}:{permanent_index[1]}",
        f"permanent_retrieved_at={permanent_observed}",
        f"permanent_expires_at={permanent_expires}",
        f"permanent_statement={permanent_statement}",
        f"permanent_output={permanent_output_txid}:{permanent_output_index}",
        f"funding_txid={funding_txid}",
        f"funding_bytes={funding_bytes}",
        f"funding_outputs={funding_outputs}",
        f"funding_sha256={funding_sha256}",
        "consolidation=disabled",
        "result=validated",
    ]) + "\n",
    encoding="utf-8",
)
PY
  cp -- "$live_clock_file" "$destination/deposit-clock-final.clock"
  cmp -- "$live_clock_file" \
    "$destination/deposit-clock-generations/generation-06-replacement-visible.clock"
}

record_deposit_funding_daemon_evidence() {
  local destination=$1
  local txid response_file="$destination/deposit-funding-daemon-response.json"
  txid=$(awk -F= '$1 == "funding_txid" { print $2 }' \
    "$destination/deposit-ttl-evidence.env")
  [[ "$txid" =~ ^[0-9a-f]{64}$ ]] || {
    echo "deposit-TTL evidence contains a malformed funding transaction ID" >&2
    return 1
  }
  compose exec -T -e "TM_ACCEPTANCE_FUNDING_TXID=$txid" monerod-miner sh -eu -c '
    curl --fail --silent --show-error \
      --header "Content-Type: application/json" \
      --data "{\"txs_hashes\":[\"$TM_ACCEPTANCE_FUNDING_TXID\"],\"decode_as_json\":false,\"prune\":false}" \
      http://127.0.0.1:18081/get_transactions
  ' >"$response_file"
  python3 - \
    "$response_file" \
    "$destination/deposit-funding-transaction.hex" \
    "$txid" \
    >"$destination/deposit-funding-daemon-evidence.env" <<'PY'
import json
import sys
from pathlib import Path

response_path, transaction_path = map(Path, sys.argv[1:3])
expected_txid = sys.argv[3]
response = json.loads(response_path.read_text(encoding="utf-8"))
assert response["status"] == "OK"
assert response.get("missed_tx", []) == []
assert len(response["txs"]) == 1
transaction = response["txs"][0]
expected_hex = transaction_path.read_text(encoding="ascii").strip()
assert transaction["tx_hash"] == expected_txid
assert transaction["as_hex"] == expected_hex
assert transaction["in_pool"] is False
assert isinstance(transaction["block_height"], int) and transaction["block_height"] > 0
print(f"daemon_txid={transaction['tx_hash']}")
print(f"daemon_block_height={transaction['block_height']}")
print("daemon_in_pool=false")
print("daemon_exact_hex_match=true")
print("result=confirmed")
PY
}

run_deposit_ttl_e2e() {
  local case_name=$1
  local destination="$artifact_root/$case_name"
  local log_file="$destination/e2e.log"
  local live_clock_file="$TM_ACCEPTANCE_DEPOSIT_CLOCK_DIR/deposit-clock"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  local generation marker
  verify_deposit_ttl_acceptance_contract
  record_acceptance_contract "$case_name" focused-deposit-ttl 1 0
  compose --profile acceptance run --rm --no-deps \
    "${DEPOSIT_TTL_E2E_OVERRIDES[@]}" \
    e2e >"$log_file" 2>&1 &
  local pid=$!
  wait_for_process "$pid" "$deadline" "$log_file"

  record_deposit_ttl_evidence "$log_file" "$destination" "$live_clock_file"
  record_deposit_funding_daemon_evidence "$destination"
  ls -la "$TM_ACCEPTANCE_DEPOSIT_CLOCK_DIR" \
    >"$destination/deposit-clock-directory-after.txt"

  record_required_e2e_marker "$log_file" "$AUTONOMOUS_GENESIS_MARKER"
  record_required_e2e_marker "$log_file" "$REGTEST_MINING_ADDRESS_MARKER"
  record_required_e2e_marker "$log_file" "$DEPOSIT_FUNDING_TRANSACTION_MARKER"
  record_required_e2e_marker "$log_file" "$DEPOSIT_FUNDING_TRANSACTION_HEX_MARKER"
  for generation in 1 2 3 4 5 6; do
    record_required_e2e_marker \
      "$log_file" "${DEPOSIT_CLOCK_MARKER}generation=$generation "
  done
  record_required_e2e_marker "$log_file" "$DEPOSIT_TTL_ACTIVE_MARKER"
  record_required_e2e_marker "$log_file" "$DEPOSIT_TTL_EXPIRED_MARKER"
  record_required_e2e_marker "$log_file" "$DEPOSIT_TTL_NOT_REUSED_MARKER"
  record_required_e2e_marker "$log_file" "$DEPOSIT_TTL_PERMANENT_MARKER"
  record_required_e2e_marker "$log_file" "$DEPOSIT_TTL_TERMINAL_MARKER" exact

  for marker in \
    "$ALLOCATION_TERMINAL_MARKER" \
    "$PROTOCOL_TERMINAL_MARKER" \
    "$ALL_EPOCHS_TERMINAL_MARKER" \
    "$CONSOLIDATION_TRANSACTION_MARKER" \
    "$SIGNED_TRANSACTION_MARKER" \
    "$MULTI_INPUT_CONSOLIDATION_MARKER" \
    "$SUCCESSOR_EPOCH_SIGNED_TRANSACTION_MARKER" \
    "$SUCCESSOR_EPOCH_SIGNING_TERMINAL_MARKER"
  do
    ! grep -Fq -- "$marker" "$log_file" || {
      echo "focused deposit-TTL acceptance emitted out-of-scope evidence: $marker" >&2
      return 1
    }
  done

  require_marker_order \
    "$log_file" \
    "$AUTONOMOUS_GENESIS_MARKER" \
    "$REGTEST_MINING_ADDRESS_MARKER" \
    "${DEPOSIT_CLOCK_MARKER}generation=1 " \
    "${DEPOSIT_CLOCK_MARKER}generation=2 " \
    "${DEPOSIT_CLOCK_MARKER}generation=3 " \
    "$DEPOSIT_FUNDING_TRANSACTION_MARKER" \
    "$DEPOSIT_FUNDING_TRANSACTION_HEX_MARKER" \
    "${DEPOSIT_CLOCK_MARKER}generation=4 " \
    "$DEPOSIT_TTL_ACTIVE_MARKER" \
    "${DEPOSIT_CLOCK_MARKER}generation=5 " \
    "$DEPOSIT_TTL_EXPIRED_MARKER" \
    "${DEPOSIT_CLOCK_MARKER}generation=6 " \
    "$DEPOSIT_TTL_NOT_REUSED_MARKER" \
    "$DEPOSIT_TTL_PERMANENT_MARKER" \
    "$DEPOSIT_TTL_TERMINAL_MARKER"
  cat "$log_file"
}

run_leader_down_e2e() {
  local case_name=$1
  local log_file="$artifact_root/$case_name/e2e.log"
  local destination="$artifact_root/$case_name"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  verify_leader_down_acceptance_contract
  record_acceptance_contract "$case_name" full-with-persistent-signer-down 1 1
  compose --profile acceptance run --rm --no-deps \
    "${LEADER_DOWN_E2E_OVERRIDES[@]}" \
    e2e >"$log_file" 2>&1 &
  local pid=$!
  wait_for_process "$pid" "$deadline" "$log_file"
  require_terminal_contract "$log_file" "$destination" full
  record_exact_refresh_evidence "$log_file" "$destination"
  require_marker_order \
    "$log_file" \
    "$AUTONOMOUS_GENESIS_MARKER" \
    "$EXACT_REFRESH_MARKER" \
    "${SUCCESSOR_EPOCH_SIGNED_TRANSACTION_MARKER}2 " \
    "$SUCCESSOR_EPOCH_SIGNING_TERMINAL_MARKER" \
    "$ALL_EPOCHS_TERMINAL_MARKER"
  cat "$log_file"
}

run_rotation_silent_e2e() {
  local case_name=$1
  local log_file="$artifact_root/$case_name/e2e.log"
  local destination="$artifact_root/$case_name"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  local marker_budget marker_line party_number rotation_party binding response
  local held_evidence_marker released_evidence_marker
  verify_rotation_silent_acceptance_contract
  record_acceptance_contract "$case_name" rotation-silent 0 0
  compose --profile acceptance run --rm --no-deps \
    "${ROTATION_SILENT_E2E_OVERRIDES[@]}" \
    -e TM_ACCEPTANCE_ENABLE_FAULT_HOOKS=1 \
    -e TM_ACCEPTANCE_PAUSE_BEFORE_DYNAMIC_REFRESH=1 \
    e2e >"$log_file" 2>&1 &
  local pid=$!
  # DKG, the configured grow/refresh/shrink chain, and the first Monero spend all precede this
  # barrier, so allow the remaining whole-campaign budget rather than the early-round timeout.
  marker_budget=$(( deadline - $(date +%s) ))
  ((marker_budget > 0)) || {
    echo "rotation-silent campaign exhausted its deadline before the dynamic refresh barrier" >&2
    return 124
  }
  wait_for_marker \
    "$pid" "$log_file" \
    "$DYNAMIC_REFRESH_LATCH_HELD_MARKER" \
    "$marker_budget"
  marker_line=$(grep -F "$DYNAMIC_REFRESH_LATCH_HELD_MARKER" "$log_file")
  [[ $(grep -Fc "$DYNAMIC_REFRESH_LATCH_HELD_MARKER" "$log_file") -eq 1 ]] || {
    echo "dynamic refresh latch emitted ambiguous held evidence" >&2
    return 1
  }
  read -r party_number binding < <(
    python3 - "$marker_line" <<'PY'
import re
import sys
match = re.fullmatch(
    r"TM_ACCEPTANCE_DYNAMIC_REFRESH_LATCH_HELD party=(\d+) "
    r"source_epoch=4 target_epoch=5 binding=([0-9a-f]{64})",
    sys.argv[1],
)
assert match
print(*match.groups())
PY
  )
  [[ "$party_number" =~ ^[1-8]$ && "$binding" =~ ^[0-9a-f]{64}$ ]] || {
    echo "dynamic refresh latch binding is malformed: $marker_line" >&2
    return 1
  }
  rotation_party="p${party_number}"
  validate_party_service "$rotation_party"
  held_evidence_marker="$DYNAMIC_REFRESH_LATCH_HELD_MARKER party=$party_number source_epoch=4 target_epoch=5 binding=$binding"
  released_evidence_marker="$DYNAMIC_REFRESH_LATCH_RELEASED_MARKER party=$party_number source_epoch=4 target_epoch=5 binding=$binding"
  response=$(driver_latch_call "$rotation_party" status dynamic_rotation_omission "$binding")
  validate_driver_latch_response \
    "$response" "$rotation_party" held dynamic_rotation_omission "$binding"
  printf 'held %s\n' "$response" \
    >"$destination/${rotation_party}-rotation-driver-latch.jsonl"

  : >"$destination/${rotation_party}-rotation-silent.txt"
  record_rotation_party_peer_network "$destination" "$rotation_party" before
  disconnect_rotation_party_from_peer_quic "$rotation_party"
  record_rotation_party_peer_network "$destination" "$rotation_party" after-disconnect
  assert_rotation_party_peer_quic_disconnected "$rotation_party"
  assert_party_control_healthy "$destination" "$rotation_party" after-runtime-detach
  response=$(driver_latch_call "$rotation_party" release dynamic_rotation_omission "$binding")
  validate_driver_latch_response \
    "$response" "$rotation_party" released dynamic_rotation_omission "$binding"
  printf 'released %s\n' "$response" \
    >>"$destination/${rotation_party}-rotation-driver-latch.jsonl"

  wait_for_process "$pid" "$deadline" "$log_file"
  assert_rotation_party_peer_quic_disconnected "$rotation_party"
  record_required_e2e_marker \
    "$log_file" "TM_ACCEPTANCE_DYNAMIC_REFRESH_BARRIER source_epoch=4 target_epoch=5" exact
  record_required_e2e_marker "$log_file" "$held_evidence_marker" exact
  record_required_e2e_marker "$log_file" "$released_evidence_marker" exact
  require_terminal_contract "$log_file" "$destination" protocol-only
  require_marker_order \
    "$log_file" \
    "TM_ACCEPTANCE_DYNAMIC_REFRESH_BARRIER source_epoch=4 target_epoch=5" \
    "$held_evidence_marker" \
    "$released_evidence_marker" \
    "$PROTOCOL_TERMINAL_MARKER" \
    "$ALL_EPOCHS_TERMINAL_MARKER"
  record_rotation_party_peer_network "$destination" "$rotation_party" after-e2e
  cat "$log_file"
}

party_admin_status() {
  local party=$1
  validate_party_service "$party"
  compose exec -T "$party" sh -eu -c '
    token=$(tr -d "\r\n" </run/secrets/admin_bearer_token)
    curl --fail --silent --show-error \
      -H "Authorization: Bearer $token" \
      http://127.0.0.1:8080/v1/status
  '
}

capture_network_restart_statuses() {
  local output_file=$1
  local party response
  : >"$output_file"
  for party in p1 p2 p3 p4 p5 p6 p7 p8; do
    response=$(party_admin_status "$party")
    printf '%s\n' "$response" >>"$output_file"
  done
}

validate_network_restart_source_statuses() {
  local status_file=$1
  local marker_party=$2
  local marker_due_unix_ms=$3
  python3 - "$status_file" "${marker_party#p}" "$marker_due_unix_ms" <<'PY'
import hashlib
import json
import sys

path, marker_party, marker_due = sys.argv[1:]
marker_party = int(marker_party)
marker_due = int(marker_due)
statuses = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
assert len(statuses) == 8
assert {status["party"] for status in statuses} == set(range(1, 9))
assert all(status["ready"] is True for status in statuses)

deadlines = {}
active = {}
for status in statuses:
    schedule = status["proactive_refresh"]
    assert schedule["source_epoch"] == 4
    assert schedule["target_epoch"] == 5
    due = schedule["due_unix_ms"]
    assert isinstance(due, int) and 0 < due < 2**64 - 1
    deadlines[status["party"]] = due
    if status["active_epoch"] == 4:
        epochs = [entry for entry in status["epochs"] if entry["epoch"] == 4]
        assert len(epochs) == 1
        active[status["party"]] = epochs[0]["public"]

assert deadlines[marker_party] == marker_due
assert active
canonical_values = {
    json.dumps(public, sort_keys=True, separators=(",", ":")) for public in active.values()
}
assert len(canonical_values) == 1
canonical = next(iter(canonical_values))
public = json.loads(canonical)
committee = public["committee"]
members = [member["id"] for member in committee["members"]]
assert committee["epoch"] == 4
assert committee["threshold"] == 3
assert len(members) == 5 and len(set(members)) == 5
assert set(active).issubset(set(members))
required = len(members) - 1
witnesses = sorted(party for party, value in active.items() if value == public)
assert len(witnesses) >= required
assert any(public["key_id"]) and any(public["group_key"])
assert len(public["verification_shares"]) == len(members)

def as_hex(value):
    return bytes(value).hex()

print("source_epoch=4")
print("target_epoch=5")
print(f"source_public_sha256={hashlib.sha256(canonical.encode()).hexdigest()}")
print(f"source_key_id={as_hex(public['key_id'])}")
print(f"source_group_key={as_hex(public['group_key'])}")
print(f"source_members={','.join(map(str, members))}")
print(f"source_active_witnesses={','.join(map(str, witnesses))}")
print(f"required_active={required}")
print(f"minimum_due_unix_ms={min(deadlines.values())}")
print(f"maximum_due_unix_ms={max(deadlines.values())}")
PY
}

validate_network_restart_successor_statuses() {
  local source_status_file=$1
  local successor_status_file=$2
  python3 - "$source_status_file" "$successor_status_file" <<'PY'
import hashlib
import json
import sys

source_path, successor_path = sys.argv[1:]
source_statuses = [
    json.loads(line) for line in open(source_path, encoding="utf-8") if line.strip()
]
successor_statuses = [
    json.loads(line) for line in open(successor_path, encoding="utf-8") if line.strip()
]
assert len(source_statuses) == len(successor_statuses) == 8
assert {status["party"] for status in successor_statuses} == set(range(1, 9))
assert all(status["ready"] is True for status in successor_statuses)

source_publics = []
for status in source_statuses:
    if status["active_epoch"] == 4:
        epochs = [entry for entry in status["epochs"] if entry["epoch"] == 4]
        assert len(epochs) == 1
        source_publics.append(epochs[0]["public"])
assert source_publics
assert all(public == source_publics[0] for public in source_publics)
source = source_publics[0]

active = {}
for status in successor_statuses:
    if status["active_epoch"] == 5:
        epochs = [entry for entry in status["epochs"] if entry["epoch"] == 5]
        assert len(epochs) == 1
        active[status["party"]] = epochs[0]["public"]
assert active
canonical_values = {
    json.dumps(public, sort_keys=True, separators=(",", ":")) for public in active.values()
}
assert len(canonical_values) == 1
canonical = next(iter(canonical_values))
successor = json.loads(canonical)
committee = successor["committee"]
members = [member["id"] for member in committee["members"]]
assert committee["epoch"] == 5
assert committee["threshold"] == 3
assert len(members) == 5 and len(set(members)) == 5
assert set(active).issubset(set(members))
required = len(members) - 1
witnesses = sorted(party for party, value in active.items() if value == successor)
assert len(witnesses) >= required

assert successor["key_id"] == source["key_id"]
assert successor["group_key"] == source["group_key"]
assert successor["verification_shares"] != source["verification_shares"]
source_receiver_keys = {
    bytes(member["encryption_key"]) for member in source["committee"]["members"]
}
assert all(
    bytes(member["encryption_key"]) not in source_receiver_keys
    for member in successor["committee"]["members"]
)

def as_hex(value):
    return bytes(value).hex()

print("successor_epoch=5")
print(f"successor_public_sha256={hashlib.sha256(canonical.encode()).hexdigest()}")
print(f"successor_key_id={as_hex(successor['key_id'])}")
print(f"successor_group_key={as_hex(successor['group_key'])}")
print(f"successor_members={','.join(map(str, members))}")
print(f"successor_active_witnesses={','.join(map(str, witnesses))}")
print(f"required_active={required}")
print(f"observed_active={len(witnesses)}")
print("receiver_keys=fresh")
print("verification_shares=fresh")
PY
}

validate_proactive_deadline_status() {
  local response=$1
  local party=$2
  local expected_epoch=$3
  local source_epoch=$4
  local target_epoch=$5
  local due_unix_ms=$6
  validate_party_service "$party"
  python3 - \
    "$response" "${party#p}" "$expected_epoch" "$source_epoch" "$target_epoch" "$due_unix_ms" <<'PY'
import json
import sys
value = json.loads(sys.argv[1])
party, expected, source, target, due = map(int, sys.argv[2:])
assert value["party"] == party
assert value["ready"] is True
assert value["active_epoch"] == expected
schedule = value["proactive_refresh"]
if expected == source:
    assert schedule["source_epoch"] == source
    assert schedule["target_epoch"] == target
    assert schedule["due_unix_ms"] == due
    fallback = schedule["selection_fallback_due_unix_ms"]
    assert isinstance(fallback, int)
    assert fallback >= due
PY
}

run_proactive_deadline_e2e() {
  local case_name=$1
  local log_file="$artifact_root/$case_name/e2e.log"
  local destination="$artifact_root/$case_name"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  local marker_budget marker_line binding response
  local party_number restart_party source_epoch target_epoch released_at interval_ms due_unix_ms
  local held_evidence_marker released_evidence_marker
  local before_container before_pid before_volumes after_container after_pid after_volumes
  local before_status after_status current_ms activated_status event_response event_unix_ms
  verify_protocol_only_acceptance_contract 0
  record_acceptance_contract "$case_name" protocol-only-with-finite-refresh-restart 0 0
  compose --profile acceptance run --rm --no-deps \
    "${PROTOCOL_ONLY_E2E_OVERRIDES[@]}" \
    -e TM_ACCEPTANCE_PROACTIVE_DEADLINE_SOURCE_EPOCH=4 \
    -e TM_ACCEPTANCE_PROACTIVE_DEADLINE_INTERVAL_SECONDS=15 \
    e2e >"$log_file" 2>&1 &
  local pid=$!
  marker_budget=$(( deadline - $(date +%s) ))
  ((marker_budget > 0)) || return 124
  wait_for_marker "$pid" "$log_file" "$PROACTIVE_DEADLINE_HELD_MARKER" "$marker_budget"
  marker_line=$(grep -F "$PROACTIVE_DEADLINE_HELD_MARKER" "$log_file")
  [[ $(grep -Fc "$PROACTIVE_DEADLINE_HELD_MARKER" "$log_file") -eq 1 ]] || {
    echo "proactive deadline latch emitted ambiguous held evidence" >&2
    return 1
  }
  read -r party_number source_epoch target_epoch released_at interval_ms due_unix_ms binding < <(
    python3 - "$marker_line" <<'PY'
import re
import sys
match = re.fullmatch(
    r"TM_ACCEPTANCE_PROACTIVE_DEADLINE_HELD party=(\d+) source_epoch=(\d+) "
    r"target_epoch=(\d+) released_at_unix_ms=(\d+) interval_ms=(\d+) "
    r"due_unix_ms=(\d+) binding=([0-9a-f]{64})",
    sys.argv[1],
)
assert match
print(*match.groups())
PY
  )
  [[ "$party_number" =~ ^[1-8]$ && "$source_epoch" == 4 && "$target_epoch" == 5 \
    && "$interval_ms" == 15000 \
    && $((released_at + interval_ms)) -eq "$due_unix_ms" ]] || {
    echo "proactive deadline marker does not prove exact now+15s scheduling" >&2
    return 1
  }
  restart_party="p${party_number}"
  validate_party_service "$restart_party"
  held_evidence_marker="$PROACTIVE_DEADLINE_HELD_MARKER party=$party_number source_epoch=$source_epoch target_epoch=$target_epoch released_at_unix_ms=$released_at interval_ms=$interval_ms due_unix_ms=$due_unix_ms binding=$binding"
  released_evidence_marker="$PROACTIVE_DEADLINE_RELEASED_MARKER party=$party_number source_epoch=$source_epoch target_epoch=$target_epoch due_unix_ms=$due_unix_ms binding=$binding"
  response=$(driver_latch_call "$restart_party" status proactive_deadline "$binding")
  validate_driver_latch_response \
    "$response" "$restart_party" held proactive_deadline "$binding" absent
  printf 'held %s\n' "$response" >"$destination/proactive-deadline-latch.jsonl"
  before_status=$(party_admin_status "$restart_party")
  validate_proactive_deadline_status \
    "$before_status" "$restart_party" \
    "$source_epoch" "$source_epoch" "$target_epoch" "$due_unix_ms"
  printf 'before-restart %s\n' "$before_status" >"$destination/proactive-deadline-status.jsonl"

  before_container=$(compose ps --quiet "$restart_party")
  before_pid=$(docker inspect --format '{{.State.Pid}}' "$before_container")
  before_volumes=$(docker inspect --format \
    '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}};{{end}}{{end}}' \
    "$before_container")
  compose kill --signal SIGKILL "$restart_party"
  compose up --detach --no-build --wait --wait-timeout 12 "$restart_party"
  after_container=$(compose ps --quiet "$restart_party")
  after_pid=$(docker inspect --format '{{.State.Pid}}' "$after_container")
  after_volumes=$(docker inspect --format \
    '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}};{{end}}{{end}}' \
    "$after_container")
  [[ "$after_container" == "$before_container" \
    && "$after_pid" =~ ^[1-9][0-9]*$ && "$after_pid" != "$before_pid" \
    && "$after_volumes" == "$before_volumes" ]] || {
    echo "$restart_party did not restart in place from the same durable volume inside the deadline" >&2
    return 1
  }
  response=$(driver_latch_call "$restart_party" status proactive_deadline "$binding")
  validate_driver_latch_response \
    "$response" "$restart_party" held proactive_deadline "$binding" absent
  printf 'after-restart-held %s\n' "$response" \
    >>"$destination/proactive-deadline-latch.jsonl"
  current_ms=$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')
  ((current_ms < due_unix_ms)) || {
    echo "$restart_party restart exceeded the exact proactive refresh deadline" >&2
    return 1
  }
  after_status=$(party_admin_status "$restart_party")
  validate_proactive_deadline_status \
    "$after_status" "$restart_party" \
    "$source_epoch" "$source_epoch" "$target_epoch" "$due_unix_ms"
  printf 'after-restart %s\n' "$after_status" >>"$destination/proactive-deadline-status.jsonl"

  while :; do
    event_response=$(driver_latch_call "$restart_party" status proactive_deadline "$binding")
    validate_driver_latch_response \
      "$event_response" "$restart_party" held proactive_deadline "$binding"
    event_unix_ms=$(python3 - "$event_response" <<'PY'
import json
import sys
event = json.loads(sys.argv[1])["event_unix_ms"]
print("" if event is None else int(event))
PY
)
    if [[ -n "$event_unix_ms" ]]; then
      break
    fi
    before_status=$(party_admin_status "$restart_party")
    if ! validate_proactive_deadline_status \
      "$before_status" "$restart_party" \
      "$source_epoch" "$source_epoch" "$target_epoch" "$due_unix_ms"
    then
      # Do not accept an activated successor unless a second authenticated read proves its
      # write-ahead start event was durably committed first.
      event_response=$(driver_latch_call "$restart_party" status proactive_deadline "$binding")
      event_unix_ms=$(python3 - "$event_response" <<'PY'
import json
import sys
event = json.loads(sys.argv[1])["event_unix_ms"]
print("" if event is None else int(event))
PY
)
      [[ -n "$event_unix_ms" ]] || {
        echo "$restart_party left the source epoch without a durable proactive start event" >&2
        return 1
      }
      validate_driver_latch_response \
        "$event_response" "$restart_party" held proactive_deadline "$binding" "$event_unix_ms"
      break
    fi
    printf 'pre-event response=%s\n' "$before_status" \
      >>"$destination/proactive-deadline-status.jsonl"
    (( $(date +%s) < deadline )) || return 124
    sleep 0.05
  done
  [[ "$event_unix_ms" =~ ^[1-9][0-9]*$ ]] && ((event_unix_ms >= due_unix_ms)) || {
    echo "durable proactive start event predates its exact deadline: $event_response" >&2
    return 1
  }
  current_ms=$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')
  ((current_ms >= event_unix_ms)) || {
    echo "authenticated proactive start event lies in the future" >&2
    return 1
  }
  printf 'start-event observed_at_unix_ms=%s %s\n' "$current_ms" "$event_response" \
    >>"$destination/proactive-deadline-latch.jsonl"

  while :; do
    activated_status=$(party_admin_status "$restart_party")
    if python3 - "$activated_status" "$target_epoch" <<'PY'
import json
import sys
raise SystemExit(0 if json.loads(sys.argv[1])["active_epoch"] == int(sys.argv[2]) else 1)
PY
    then
      break
    fi
    (( $(date +%s) < deadline )) || return 124
    sleep 0.05
  done
  current_ms=$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')
  ((current_ms >= event_unix_ms)) || {
    echo "$restart_party activated before its durable proactive start event" >&2
    return 1
  }
  validate_proactive_deadline_status \
    "$activated_status" "$restart_party" \
    "$target_epoch" "$source_epoch" "$target_epoch" "$due_unix_ms"
  printf 'activated observed_at_unix_ms=%s response=%s\n' "$current_ms" "$activated_status" \
    >>"$destination/proactive-deadline-status.jsonl"
  response=$(driver_latch_call "$restart_party" release proactive_deadline "$binding")
  validate_driver_latch_response \
    "$response" "$restart_party" released proactive_deadline "$binding" "$event_unix_ms"
  printf 'released %s\n' "$response" >>"$destination/proactive-deadline-latch.jsonl"

  wait_for_process "$pid" "$deadline" "$log_file"
  record_required_e2e_marker "$log_file" "$held_evidence_marker" exact
  record_required_e2e_marker "$log_file" "$released_evidence_marker" exact
  require_terminal_contract "$log_file" "$destination" protocol-only
  require_marker_order \
    "$log_file" "$held_evidence_marker" "$released_evidence_marker" \
    "$PROTOCOL_TERMINAL_MARKER" "$ALL_EPOCHS_TERMINAL_MARKER"
  cat "$log_file"
}

run_network_restart_e2e() {
  local case_name=$1
  local log_file="$artifact_root/$case_name/e2e.log"
  local destination="$artifact_root/$case_name"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  local marker_budget marker_line binding response event_response event_unix_ms
  local party_number latch_party source_epoch target_epoch released_at interval_ms
  local due_unix_ms minimum_due_unix_ms maximum_due_unix_ms
  local held_evidence_marker released_evidence_marker
  local party container pid running volumes now_unix_ms stopped_at_unix_ms
  local overdue_at_unix_ms restarted_at_unix_ms successor_observed_at_unix_ms
  local successor_status_file="$destination/network-restart-successor-status.jsonl"
  local successor_evidence_file="$destination/network-restart-successor.env"
  local source_status_file="$destination/network-restart-source-status.jsonl"
  local source_evidence_file="$destination/network-restart-source.env"
  local -a party_services=(p1 p2 p3 p4 p5 p6 p7 p8)
  local -A before_containers=()
  local -A before_pids=()
  local -A before_volumes=()

  verify_network_restart_acceptance_contract
  record_acceptance_contract "$case_name" full-with-whole-network-overdue-restart 1 1
  compose --profile acceptance run --rm --no-deps \
    "${NETWORK_RESTART_E2E_OVERRIDES[@]}" \
    e2e >"$log_file" 2>&1 &
  local e2e_pid=$!

  marker_budget=$(( deadline - $(date +%s) ))
  ((marker_budget > 0)) || return 124
  wait_for_marker "$e2e_pid" "$log_file" "$PROACTIVE_DEADLINE_HELD_MARKER" "$marker_budget"
  marker_line=$(grep -F "$PROACTIVE_DEADLINE_HELD_MARKER" "$log_file")
  [[ $(grep -Fc "$PROACTIVE_DEADLINE_HELD_MARKER" "$log_file") -eq 1 ]] || {
    echo "network-restart proactive deadline latch emitted ambiguous held evidence" >&2
    return 1
  }
  read -r party_number source_epoch target_epoch released_at interval_ms due_unix_ms binding < <(
    python3 - "$marker_line" <<'PY'
import re
import sys
match = re.fullmatch(
    r"TM_ACCEPTANCE_PROACTIVE_DEADLINE_HELD party=(\d+) source_epoch=(\d+) "
    r"target_epoch=(\d+) released_at_unix_ms=(\d+) interval_ms=(\d+) "
    r"due_unix_ms=(\d+) binding=([0-9a-f]{64})",
    sys.argv[1],
)
assert match
print(*match.groups())
PY
  )
  [[ "$party_number" =~ ^[1-8]$ && "$source_epoch" == 4 && "$target_epoch" == 5 \
    && "$interval_ms" == 15000 \
    && $((released_at + interval_ms)) -eq "$due_unix_ms" ]] || {
    echo "network-restart marker does not bind the exact epoch-4 deadline" >&2
    return 1
  }
  latch_party="p${party_number}"
  held_evidence_marker="$PROACTIVE_DEADLINE_HELD_MARKER party=$party_number source_epoch=$source_epoch target_epoch=$target_epoch released_at_unix_ms=$released_at interval_ms=$interval_ms due_unix_ms=$due_unix_ms binding=$binding"
  released_evidence_marker="$PROACTIVE_DEADLINE_RELEASED_MARKER party=$party_number source_epoch=$source_epoch target_epoch=$target_epoch due_unix_ms=$due_unix_ms binding=$binding"
  response=$(driver_latch_call "$latch_party" status proactive_deadline "$binding")
  validate_driver_latch_response \
    "$response" "$latch_party" held proactive_deadline "$binding" absent
  printf 'before-stop %s\n' "$response" >"$destination/network-restart-latch.jsonl"

  capture_network_restart_statuses "$source_status_file"
  validate_network_restart_source_statuses \
    "$source_status_file" "$latch_party" "$due_unix_ms" >"$source_evidence_file"
  minimum_due_unix_ms=$(
    awk -F= '$1 == "minimum_due_unix_ms" { print $2 }' "$source_evidence_file"
  )
  maximum_due_unix_ms=$(
    awk -F= '$1 == "maximum_due_unix_ms" { print $2 }' "$source_evidence_file"
  )
  [[ "$minimum_due_unix_ms" =~ ^[1-9][0-9]*$ \
    && "$maximum_due_unix_ms" =~ ^[1-9][0-9]*$ \
    && "$minimum_due_unix_ms" -le "$due_unix_ms" \
    && "$due_unix_ms" -le "$maximum_due_unix_ms" ]] || {
    echo "network-restart source evidence contains invalid participant deadlines" >&2
    return 1
  }

  printf 'phase\tobserved_at_unix_ms\tservice\tcontainer\tpid\trunning\tvolumes\n' \
    >"$destination/network-restart-containers.tsv"
  now_unix_ms=$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')
  ((now_unix_ms < minimum_due_unix_ms)) || {
    echo "network-restart did not observe every party before the earliest persisted deadline" >&2
    return 1
  }
  for party in "${party_services[@]}"; do
    container=$(compose ps --all --quiet "$party")
    [[ -n "$container" ]] || {
      echo "$party container is absent before whole-network stop" >&2
      return 1
    }
    read -r running pid < <(docker inspect --format '{{.State.Running}} {{.State.Pid}}' "$container")
    volumes=$(docker inspect --format \
      '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}};{{end}}{{end}}' \
      "$container")
    [[ "$running" == true && "$pid" =~ ^[1-9][0-9]*$ \
      && "$volumes" == *":/var/lib/threshold-monero;"* ]] || {
      echo "$party lacks a running process or its named state volume before whole-network stop" >&2
      return 1
    }
    before_containers["$party"]=$container
    before_pids["$party"]=$pid
    before_volumes["$party"]=$volumes
    printf 'before-stop\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$now_unix_ms" "$party" "$container" "$pid" "$running" "$volumes" \
      >>"$destination/network-restart-containers.tsv"
  done

  # This explicit Compose stop suppresses `unless-stopped` recovery. The one-shot E2E process stays
  # live on the control network and cannot pass its durable latch until this driver restores it.
  compose stop --timeout 0 "${party_services[@]}" >/dev/null
  stopped_at_unix_ms=$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')
  ((stopped_at_unix_ms < minimum_due_unix_ms)) || {
    echo "all parties were not stopped before the earliest persisted refresh deadline" >&2
    return 1
  }
  for party in "${party_services[@]}"; do
    container=$(compose ps --all --quiet "$party")
    read -r running pid < <(docker inspect --format '{{.State.Running}} {{.State.Pid}}' "$container")
    volumes=$(docker inspect --format \
      '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}};{{end}}{{end}}' \
      "$container")
    [[ "$container" == "${before_containers[$party]}" && "$running" == false && "$pid" == 0 \
      && "$volumes" == "${before_volumes[$party]}" ]] || {
      echo "$party did not stop in place while retaining its exact named state volume" >&2
      return 1
    }
    printf 'stopped\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$stopped_at_unix_ms" "$party" "$container" "$pid" "$running" "$volumes" \
      >>"$destination/network-restart-containers.tsv"
  done

  while :; do
    now_unix_ms=$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')
    ((now_unix_ms > maximum_due_unix_ms)) && break
    (( $(date +%s) < deadline )) || return 124
    sleep 0.05
  done
  overdue_at_unix_ms=$now_unix_ms
  for party in "${party_services[@]}"; do
    container=$(compose ps --all --quiet "$party")
    read -r running pid < <(docker inspect --format '{{.State.Running}} {{.State.Pid}}' "$container")
    volumes=$(docker inspect --format \
      '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}};{{end}}{{end}}' \
      "$container")
    [[ "$container" == "${before_containers[$party]}" && "$running" == false && "$pid" == 0 \
      && "$volumes" == "${before_volumes[$party]}" ]] || {
      echo "$party restarted or changed volume before every persisted deadline became overdue" >&2
      return 1
    }
    printf 'overdue-stopped\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$overdue_at_unix_ms" "$party" "$container" "$pid" "$running" "$volumes" \
      >>"$destination/network-restart-containers.tsv"
  done
  {
    printf 'stopped_at_unix_ms=%s\n' "$stopped_at_unix_ms"
    printf 'overdue_at_unix_ms=%s\n' "$overdue_at_unix_ms"
  } >>"$source_evidence_file"

  compose up --detach --no-build --wait --wait-timeout 120 "${party_services[@]}"
  restarted_at_unix_ms=$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')
  ((restarted_at_unix_ms > maximum_due_unix_ms)) || {
    echo "whole-network restart began before every persisted deadline was overdue" >&2
    return 1
  }
  for party in "${party_services[@]}"; do
    container=$(compose ps --all --quiet "$party")
    read -r running pid < <(docker inspect --format '{{.State.Running}} {{.State.Pid}}' "$container")
    volumes=$(docker inspect --format \
      '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}};{{end}}{{end}}' \
      "$container")
    [[ "$container" == "${before_containers[$party]}" && "$running" == true \
      && "$pid" =~ ^[1-9][0-9]*$ && "$pid" != "${before_pids[$party]}" \
      && "$volumes" == "${before_volumes[$party]}" ]] || {
      echo "$party did not restore in place from its exact named state volume" >&2
      return 1
    }
    printf 'restarted\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$restarted_at_unix_ms" "$party" "$container" "$pid" "$running" "$volumes" \
      >>"$destination/network-restart-containers.tsv"
  done

  while :; do
    event_response=$(driver_latch_call "$latch_party" status proactive_deadline "$binding")
    validate_driver_latch_response \
      "$event_response" "$latch_party" held proactive_deadline "$binding"
    event_unix_ms=$(python3 - "$event_response" <<'PY'
import json
import sys
event = json.loads(sys.argv[1])["event_unix_ms"]
print("" if event is None else int(event))
PY
)
    [[ -z "$event_unix_ms" ]] || break
    (( $(date +%s) < deadline )) || return 124
    sleep 0.05
  done
  [[ "$event_unix_ms" =~ ^[1-9][0-9]*$ \
    && "$event_unix_ms" -ge "$due_unix_ms" \
    && "$event_unix_ms" -ge "$overdue_at_unix_ms" ]] || {
    echo "restored proactive start event is absent or predates the all-deadlines-overdue point" >&2
    return 1
  }
  printf 'after-restart-start-event %s\n' "$event_response" \
    >>"$destination/network-restart-latch.jsonl"

  while :; do
    if capture_network_restart_statuses "$successor_status_file" \
      && validate_network_restart_successor_statuses \
        "$source_status_file" "$successor_status_file" \
        >"$successor_evidence_file" \
        2>"$destination/network-restart-successor-last-error.txt"
    then
      break
    fi
    (( $(date +%s) < deadline )) || return 124
    sleep 0.1
  done
  successor_observed_at_unix_ms=$(
    python3 -c 'import time; print(time.time_ns() // 1_000_000)'
  )
  ((successor_observed_at_unix_ms >= restarted_at_unix_ms)) || {
    echo "common successor observation predates whole-network restart completion" >&2
    return 1
  }
  {
    printf 'restart_completed_at_unix_ms=%s\n' "$restarted_at_unix_ms"
    printf 'successor_observed_at_unix_ms=%s\n' "$successor_observed_at_unix_ms"
    printf 'proactive_start_event_unix_ms=%s\n' "$event_unix_ms"
  } >>"$successor_evidence_file"

  response=$(driver_latch_call "$latch_party" release proactive_deadline "$binding")
  validate_driver_latch_response \
    "$response" "$latch_party" released proactive_deadline "$binding" "$event_unix_ms"
  printf 'released-after-common-successor %s\n' "$response" \
    >>"$destination/network-restart-latch.jsonl"

  wait_for_process "$e2e_pid" "$deadline" "$log_file"
  record_required_e2e_marker "$log_file" "$held_evidence_marker" exact
  record_required_e2e_marker "$log_file" "$released_evidence_marker" exact
  require_terminal_contract "$log_file" "$destination" full
  require_marker_order \
    "$log_file" \
    "$AUTONOMOUS_GENESIS_MARKER" \
    "$held_evidence_marker" \
    "$released_evidence_marker" \
    "${SUCCESSOR_EPOCH_SIGNED_TRANSACTION_MARKER}5 " \
    "$SUCCESSOR_EPOCH_SIGNING_TERMINAL_MARKER" \
    "$ALL_EPOCHS_TERMINAL_MARKER"
  [[ -s "$destination/successor-epoch-signed-transactions/epoch-5/transaction.bin" \
    && -s "$destination/successor-epoch-signed-transactions/epoch-5/transaction.evidence.env" ]] || {
    echo "whole-network restart lacks its canonical post-restart epoch-5 transaction artifact" >&2
    return 1
  }
  printf 'transaction_artifact=successor-epoch-signed-transactions/epoch-5/transaction.bin\n' \
    >>"$successor_evidence_file"
  printf 'result=passed\n' >>"$successor_evidence_file"
  printf 'TM_RESILIENCE_NETWORK_RESTART_TERMINAL source_epoch=4 target_epoch=5 required_active=4 transaction_artifact=successor-epoch-signed-transactions/epoch-5/transaction.bin\n' \
    | tee "$destination/network-restart-terminal.txt"
  cat "$log_file"
}

run_consolidation_silent_e2e() {
  local case_name=$1
  local log_file="$artifact_root/$case_name/e2e.log"
  local destination="$artifact_root/$case_name"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  local marker_budget barrier_line fault_id fault_party latch_line binding txid response
  verify_consolidation_silent_acceptance_contract
  record_acceptance_contract "$case_name" full-with-consolidation-omission 1 1
  compose --profile acceptance run --rm --no-deps \
    -e TM_ACCEPTANCE_ENABLE_FAULT_HOOKS=1 \
    -e TM_ACCEPTANCE_REQUIRE_CONSOLIDATION_GATE=1 \
    e2e >"$log_file" 2>&1 &
  local pid=$!

  # DKG, real threshold funding, allocation, deposit mining, permanence, and maturity all precede
  # this barrier, so its wait receives the remaining whole-campaign budget.
  marker_budget=$(( deadline - $(date +%s) ))
  ((marker_budget > 0)) || {
    echo "consolidation-silent campaign exhausted its deadline before the pre-signing barrier" >&2
    return 124
  }
  wait_for_marker \
    "$pid" "$log_file" "$CONSOLIDATION_FAULT_BARRIER_MARKER" "$marker_budget"
  barrier_line=$(grep -F "$CONSOLIDATION_FAULT_BARRIER_MARKER" "$log_file" | tail -n 1)
  fault_id=$(sed -nE 's/.*fault_party=([0-9]+).*/\1/p' <<<"$barrier_line")
  [[ "$fault_id" =~ ^[1-8]$ ]] || {
    echo "invalid fault party in consolidation barrier: $barrier_line" >&2
    return 1
  }
  fault_party="p$fault_id"

  : >"$destination/consolidation-silent-peer.txt"
  : >"$destination/consolidation-silent-control.jsonl"
  record_party_peer_network "$destination" "$fault_party" before
  disconnect_party_from_peer_quic "$fault_party"
  record_party_peer_network "$destination" "$fault_party" after-disconnect
  assert_party_control_healthy "$destination" "$fault_party" after-disconnect
  release_consolidation_fault_gates "$destination"

  # The runner emits this only after a different n-f ROAST subset has threshold-signed a real
  # sweep, monerod accepted it, a block mined it, and n-f replicas agreed on final settlement.
  marker_budget=$(( deadline - $(date +%s) ))
  ((marker_budget > 0)) || {
    echo "consolidation-silent campaign exhausted its deadline before settlement" >&2
    return 124
  }
  wait_for_marker \
    "$pid" "$log_file" "$CONSOLIDATION_FAULT_SETTLED_MARKER" "$marker_budget"
  wait_for_marker \
    "$pid" "$log_file" "$CONSOLIDATION_RECONNECT_LATCH_HELD_MARKER" 10
  [[ $(grep -Fc "$CONSOLIDATION_RECONNECT_LATCH_HELD_MARKER" "$log_file") -eq 1 ]] || {
    echo "consolidation reconnect latch emitted ambiguous held evidence" >&2
    return 1
  }
  latch_line=$(grep -F "$CONSOLIDATION_RECONNECT_LATCH_HELD_MARKER" "$log_file")
  read -r fault_id txid binding < <(
    python3 - "$latch_line" <<'PY'
import re
import sys
match = re.fullmatch(
    r"TM_ACCEPTANCE_CONSOLIDATION_PEER_RECONNECT_LATCH_HELD party=(\d+) "
    r"txid=([0-9a-f]{64}) confirmation_height=\d+ "
    r"confirmation_hash=[0-9a-f]{64} binding=([0-9a-f]{64})",
    sys.argv[1],
)
assert match
print(*match.groups())
PY
  )
  [[ "$fault_party" == "p$fault_id" && "$txid" =~ ^[0-9a-f]{64}$ \
    && "$binding" =~ ^[0-9a-f]{64}$ ]] || {
    echo "consolidation reconnect latch differs from the omitted signer: $latch_line" >&2
    return 1
  }
  response=$(driver_latch_call \
    "$fault_party" status consolidation_peer_reconnect "$binding")
  validate_driver_latch_response \
    "$response" "$fault_party" held consolidation_peer_reconnect "$binding" absent
  printf 'held txid=%s %s\n' "$txid" "$response" \
    >"$destination/consolidation-reconnect-latch.jsonl"
  assert_party_peer_quic_state "$fault_party" disconnected
  record_party_peer_network "$destination" "$fault_party" after-settlement
  assert_party_control_healthy "$destination" "$fault_party" after-settlement
  reconnect_party_to_peer_quic "$fault_party"
  record_party_peer_network "$destination" "$fault_party" after-reconnect
  record_reconnected_peer_dns "$destination" "$fault_party"
  response=$(driver_latch_call \
    "$fault_party" release consolidation_peer_reconnect "$binding")
  validate_driver_latch_response \
    "$response" "$fault_party" released consolidation_peer_reconnect "$binding" absent
  printf 'released-after-reconnect txid=%s %s\n' "$txid" "$response" \
    >>"$destination/consolidation-reconnect-latch.jsonl"

  wait_for_process "$pid" "$deadline" "$log_file"
  record_required_e2e_marker "$log_file" "$CONSOLIDATION_FAULT_BARRIER_MARKER"
  record_required_e2e_marker "$log_file" "$CONSOLIDATION_FAULT_SETTLED_MARKER"
  record_required_e2e_marker "$log_file" "$CONSOLIDATION_RECONNECT_LATCH_HELD_MARKER"
  record_required_e2e_marker "$log_file" "$CONSOLIDATION_RECONNECT_LATCH_RELEASED_MARKER"
  record_required_e2e_marker "$log_file" "$CONSOLIDATION_PEER_REJOINED_MARKER"
  record_required_e2e_marker "$log_file" "$CONSOLIDATION_FAULT_TERMINAL_MARKER"
  require_terminal_contract "$log_file" "$destination" full
  require_marker_order \
    "$log_file" \
    "$CONSOLIDATION_FAULT_BARRIER_MARKER" \
    "$CONSOLIDATION_FAULT_SETTLED_MARKER" \
    "$CONSOLIDATION_RECONNECT_LATCH_HELD_MARKER" \
    "$CONSOLIDATION_RECONNECT_LATCH_RELEASED_MARKER" \
    "$CONSOLIDATION_PEER_REJOINED_MARKER" \
    "$CONSOLIDATION_TRANSACTION_MARKER" \
    "$SIGNED_TRANSACTION_MARKER" \
    "$CONSOLIDATION_FAULT_TERMINAL_MARKER" \
    "$ALL_EPOCHS_TERMINAL_MARKER"
  cat "$log_file"
}

run_consolidation_bootstrap_silent_e2e() {
  local case_name=$1
  local log_file="$artifact_root/$case_name/e2e.log"
  local destination="$artifact_root/$case_name"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  local marker_budget barrier_line fault_id fault_party
  local before_container before_pid after_container after_pid
  verify_consolidation_bootstrap_silent_acceptance_contract
  record_acceptance_contract "$case_name" full-with-bootstrap-proposer-stop 1 1
  compose --profile acceptance run --rm --no-deps \
    -e TM_ACCEPTANCE_ENABLE_FAULT_HOOKS=1 \
    -e TM_ACCEPTANCE_REQUIRE_CONSOLIDATION_GATE=1 \
    -e TM_ACCEPTANCE_REQUIRE_CONSOLIDATION_BOOTSTRAP_GATE=1 \
    e2e >"$log_file" 2>&1 &
  local pid=$!

  marker_budget=$(( deadline - $(date +%s) ))
  ((marker_budget > 0)) || {
    echo "bootstrap campaign exhausted its deadline before the pre-BA barrier" >&2
    return 124
  }
  wait_for_marker \
    "$pid" "$log_file" "$CONSOLIDATION_BOOTSTRAP_BARRIER_MARKER" "$marker_budget"
  barrier_line=$(grep -F "$CONSOLIDATION_BOOTSTRAP_BARRIER_MARKER" "$log_file" | tail -n 1)
  fault_id=$(sed -nE 's/.*fault_party=([0-9]+).*/\1/p' <<<"$barrier_line")
  [[ "$fault_id" =~ ^[1-5]$ ]] || {
    echo "invalid epoch-0 bootstrap proposer in barrier: $barrier_line" >&2
    return 1
  }
  fault_party="p$fault_id"

  : >"$destination/consolidation-bootstrap-process.txt"
  : >"$destination/consolidation-silent-control.jsonl"
  record_bootstrap_party_process "$destination" "$fault_party" before-stop
  assert_party_control_healthy "$destination" "$fault_party" before-stop
  before_container=$(compose ps --all --quiet "$fault_party")
  before_pid=$(docker inspect --format '{{.State.Pid}}' "$before_container")
  compose stop --timeout 30 "$fault_party"
  assert_bootstrap_party_stopped "$fault_party"
  record_bootstrap_party_process "$destination" "$fault_party" after-stop
  release_consolidation_bootstrap_survivors "$destination" "$fault_party"

  # This marker proves the live n-f parties certified a different randomized intent in a nonzero
  # inner BA view and then stopped at the independent pre-nonce ROAST gate.
  marker_budget=$(( deadline - $(date +%s) ))
  ((marker_budget > 0)) || {
    echo "bootstrap campaign exhausted its deadline before replacement certification" >&2
    return 124
  }
  wait_for_marker \
    "$pid" "$log_file" "$CONSOLIDATION_BOOTSTRAP_CERTIFIED_MARKER" "$marker_budget"
  assert_bootstrap_party_stopped "$fault_party"
  record_bootstrap_party_process "$destination" "$fault_party" after-certification

  compose start "$fault_party" >/dev/null
  wait_for_party_healthy "$fault_party"
  after_container=$(compose ps --all --quiet "$fault_party")
  after_pid=$(docker inspect --format '{{.State.Pid}}' "$after_container")
  [[ "$after_container" == "$before_container" ]] || {
    echo "bootstrap proposer was replaced instead of restarted with its durable volume" >&2
    return 1
  }
  [[ "$after_pid" =~ ^[1-9][0-9]*$ && "$after_pid" != "$before_pid" ]] || {
    echo "bootstrap proposer restart did not produce a fresh process" >&2
    return 1
  }
  record_bootstrap_party_process "$destination" "$fault_party" after-restart
  assert_party_control_healthy "$destination" "$fault_party" after-restart
  record_reconnected_peer_dns "$destination" "$fault_party"
  release_consolidation_bootstrap_gate_for_party "$destination" "$fault_party"

  # The restarted proposer must ingest the certified intent over authenticated QUIC and reach the
  # exact same durable pre-nonce state before any party is allowed to create a FROST nonce.
  marker_budget=$(( deadline - $(date +%s) ))
  ((marker_budget > 0)) || {
    echo "bootstrap campaign exhausted its deadline before proposer catch-up" >&2
    return 124
  }
  wait_for_marker \
    "$pid" "$log_file" "$CONSOLIDATION_BOOTSTRAP_REJOINED_MARKER" "$marker_budget"
  assert_party_control_healthy "$destination" "$fault_party" after-quic-catchup
  release_consolidation_fault_gates "$destination"

  wait_for_process "$pid" "$deadline" "$log_file"
  record_required_e2e_marker "$log_file" "$CONSOLIDATION_BOOTSTRAP_BARRIER_MARKER"
  record_required_e2e_marker "$log_file" "$CONSOLIDATION_BOOTSTRAP_CERTIFIED_MARKER"
  record_required_e2e_marker "$log_file" "$CONSOLIDATION_BOOTSTRAP_REJOINED_MARKER"
  record_required_e2e_marker "$log_file" "$CONSOLIDATION_BOOTSTRAP_SETTLED_MARKER"
  record_required_e2e_marker "$log_file" "$CONSOLIDATION_BOOTSTRAP_TERMINAL_MARKER"
  require_terminal_contract "$log_file" "$destination" full
  require_marker_order \
    "$log_file" \
    "$CONSOLIDATION_BOOTSTRAP_BARRIER_MARKER" \
    "$CONSOLIDATION_BOOTSTRAP_CERTIFIED_MARKER" \
    "$CONSOLIDATION_BOOTSTRAP_REJOINED_MARKER" \
    "$CONSOLIDATION_BOOTSTRAP_SETTLED_MARKER" \
    "$CONSOLIDATION_TRANSACTION_MARKER" \
    "$SIGNED_TRANSACTION_MARKER" \
    "$CONSOLIDATION_BOOTSTRAP_TERMINAL_MARKER" \
    "$ALL_EPOCHS_TERMINAL_MARKER"
  cat "$log_file"
}

protocol_fault_gate_call() {
  local party=$1
  local action=$2
  local epoch=$3
  local boundary=$4
  local session_hex=$5
  local payload
  validate_party_service "$party"
  [[ "$action" == status || "$action" == release ]] || return 2
  [[ "$epoch" == 0 \
    && ( "$boundary" == dealer_started || "$boundary" == qual_round_zero ) ]] || return 2
  [[ "$session_hex" =~ ^[0-9a-f]{64}$ ]] || return 2
  payload=$(python3 - "$action" "$epoch" "$boundary" "$session_hex" <<'PY'
import json
import sys

action, epoch, boundary, session_hex = sys.argv[1:]
print(json.dumps({
    "action": action,
    "session": list(bytes.fromhex(session_hex)),
    "epoch": int(epoch),
    "boundary": boundary,
}, separators=(",", ":")))
PY
)
  compose exec -T -e "TM_PROTOCOL_FAULT_GATE_PAYLOAD=$payload" "$party" sh -eu -c '
    token=$(tr -d "\r\n" </run/secrets/admin_bearer_token)
    curl --fail --silent --show-error \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/json" \
      --data "$TM_PROTOCOL_FAULT_GATE_PAYLOAD" \
      http://127.0.0.1:8080/v1/acceptance/protocol-fault-gate
  '
}

driver_latch_call() {
  local party=$1
  local action=$2
  local kind=$3
  local binding_hex=$4
  local payload
  validate_party_service "$party"
  [[ "$action" == status || "$action" == release ]] || return 2
  [[ "$kind" == observer_fork || "$kind" == dynamic_rotation_omission \
    || "$kind" == proactive_deadline \
    || "$kind" == consolidation_peer_reconnect ]] || return 2
  [[ "$binding_hex" =~ ^[0-9a-f]{64}$ ]] || return 2
  payload=$(python3 - "$action" "$kind" "$binding_hex" <<'PY'
import json
import sys
action, kind, binding = sys.argv[1:]
print(json.dumps({
    "action": action,
    "kind": kind,
    "binding": list(bytes.fromhex(binding)),
}, separators=(",", ":")))
PY
)
  compose exec -T -e "TM_DRIVER_LATCH_PAYLOAD=$payload" "$party" sh -eu -c '
    token=$(tr -d "\r\n" </run/secrets/admin_bearer_token)
    curl --fail --silent --show-error \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/json" \
      --data "$TM_DRIVER_LATCH_PAYLOAD" \
      http://127.0.0.1:8080/v1/acceptance/driver-latch
  '
}

validate_driver_latch_response() {
  local response=$1
  local party=$2
  local expected_state=$3
  local kind=$4
  local binding_hex=$5
  local expected_event=${6:-any}
  python3 - \
    "$response" "${party#p}" "$expected_state" "$kind" "$binding_hex" "$expected_event" <<'PY'
import json
import sys
response, party, state, kind, binding, expected_event = sys.argv[1:]
value = json.loads(response)
assert value["party"] == int(party)
assert value["state"] == state
assert value["kind"] == kind
assert value["binding"] == list(bytes.fromhex(binding))
if expected_event == "absent":
    assert value["event_unix_ms"] is None
elif expected_event != "any":
    assert value["event_unix_ms"] == int(expected_event)
PY
}

deposit_checkpoint_gate_call() {
  local action=$1
  local transaction_hex=$2
  local output_index=$3
  local payload
  [[ "$action" == status || "$action" == release ]] || return 2
  [[ "$transaction_hex" =~ ^[0-9a-f]{64}$ ]] || return 2
  [[ "$output_index" =~ ^[0-9]+$ ]] || return 2
  payload=$(python3 - "$action" "$transaction_hex" "$output_index" <<'PY'
import json
import sys
action, transaction, output_index = sys.argv[1:]
print(json.dumps({
    "action": action,
    "output": {
        "transaction": list(bytes.fromhex(transaction)),
        "index_in_transaction": int(output_index),
    },
}, separators=(",", ":")))
PY
)
  compose exec -T -e "TM_DEPOSIT_CHECKPOINT_GATE_PAYLOAD=$payload" p2 sh -eu -c '
    token=$(tr -d "\r\n" </run/secrets/admin_bearer_token)
    curl --fail --silent --show-error \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/json" \
      --data "$TM_DEPOSIT_CHECKPOINT_GATE_PAYLOAD" \
      http://127.0.0.1:8080/v1/acceptance/deposit-checkpoint-gate
  '
}

canonical_deposit_checkpoint_gate_response() {
  local response=$1
  local expected_state=$2
  local transaction_hex=$3
  local output_index=$4
  python3 - "$response" "$expected_state" "$transaction_hex" "$output_index" <<'PY'
import json
import sys
response, state, transaction, output_index = sys.argv[1:]
value = json.loads(response)
assert value["party"] == 2
assert value["state"] == state
assert value["output"] == {
    "transaction": list(bytes.fromhex(transaction)),
    "index_in_transaction": int(output_index),
}
evidence = value["evidence"]
assert evidence is not None
assert evidence["output"]["output"] == value["output"]
for field in ("portable_index_digest", "checkpoint_statement_digest"):
    assert len(evidence[field]) == 32 and any(evidence[field])
assert evidence["checkpoint_sequence"] > 0
print(json.dumps(value, sort_keys=True, separators=(",", ":")))
PY
}

validate_protocol_fault_gate_response() {
  local response=$1
  local party=$2
  local expected_state=$3
  local epoch=$4
  local boundary=$5
  local session_hex=$6
  python3 - "$response" "${party#p}" "$expected_state" "$epoch" "$boundary" "$session_hex" <<'PY'
import json
import sys

response, party, state, epoch, boundary, session_hex = sys.argv[1:]
value = json.loads(response)
assert value["party"] == int(party)
assert value["state"] == state
assert value["session"] == list(bytes.fromhex(session_hex))
assert value["epoch"] == int(epoch)
assert value["boundary"] == boundary
if boundary == "dealer_started":
    assert value["dealer"] == int(party)
    assert value["qual_round"] is None
else:
    assert value["dealer"] is None
    assert value["qual_round"] == 0
PY
}

run_faulted_e2e() {
  local case_name=$1
  local contract=$2
  local fault_party=$3
  local boundary=$4
  local log_file="$artifact_root/$case_name/e2e.log"
  local destination="$artifact_root/$case_name"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  local before_container before_pid before_volumes
  local after_container after_pid after_volumes
  local marker marker_line session_hex response
  local -a contract_overrides=()
  [[ "$fault_party" == p3 ]] || {
    echo "invalid deterministic epoch-zero AVSS crash target contract" >&2
    return 2
  }
  case "$case_name:$contract:$boundary" in
    avss-crash:full:dealer_started|qual-crash-silent:protocol-only:qual_round_zero) ;;
    *)
      echo "unsupported deterministic AVSS crash schedule" >&2
      return 2
      ;;
  esac
  case "$contract" in
    full)
      verify_full_acceptance_contract
      record_acceptance_contract "$case_name" full 1 1
      ;;
    protocol-only)
      verify_protocol_only_acceptance_contract
      record_acceptance_contract "$case_name" protocol-only 0 0
      contract_overrides=("${PROTOCOL_ONLY_E2E_OVERRIDES[@]}")
      ;;
    *)
      echo "unsupported E2E contract: $contract" >&2
      return 2
      ;;
  esac
  printf 'epoch=0\nboundary=%s\nfault_party=%s\nmanual_genesis=true\n' \
    "$boundary" "$fault_party" \
    >"$destination/avss-fault-contract.env"
  compose --profile acceptance run --rm --no-deps \
    "${contract_overrides[@]}" \
    -e TM_ACCEPTANCE_ENABLE_FAULT_HOOKS=1 \
    -e "TM_ACCEPTANCE_PROTOCOL_FAULT_GATE=0:$boundary:${fault_party#p}" \
    e2e >"$log_file" 2>&1 &
  local pid=$!
  marker="TM_ACCEPTANCE_PROTOCOL_FAULT_GATE_HELD party=${fault_party#p} epoch=0 boundary=$boundary session="
  wait_for_marker "$pid" "$log_file" "$marker"
  marker_line=$(grep -F "$marker" "$log_file")
  [[ $(grep -Fc "$marker" "$log_file") -eq 1 ]] || {
    echo "protocol fault gate emitted an ambiguous held marker" >&2
    return 1
  }
  session_hex=${marker_line##*session=}
  [[ "$session_hex" =~ ^[0-9a-f]{64}$ ]] || {
    echo "protocol fault marker has an invalid session: $marker_line" >&2
    return 1
  }
  : >"$destination/protocol-fault-gate.jsonl"
  response=$(protocol_fault_gate_call "$fault_party" status 0 "$boundary" "$session_hex")
  validate_protocol_fault_gate_response \
    "$response" "$fault_party" held 0 "$boundary" "$session_hex"
  printf 'before-restart %s\n' "$response" >>"$destination/protocol-fault-gate.jsonl"

  : >"$destination/p3-restart.txt"
  record_p3_process "$destination" before
  before_container=$(compose ps --quiet "$fault_party")
  before_pid=$(docker inspect --format '{{.State.Pid}}' "$before_container")
  before_volumes=$(docker inspect --format \
    '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}};{{end}}{{end}}' \
    "$before_container")
  [[ -n "$before_volumes" ]] || {
    echo "$fault_party has no persistent volume before the AVSS crash" >&2
    return 1
  }
  compose kill --signal SIGKILL "$fault_party"
  compose up --detach --no-build --wait --wait-timeout 120 "$fault_party"
  record_p3_process "$destination" after
  after_container=$(compose ps --quiet "$fault_party")
  after_pid=$(docker inspect --format '{{.State.Pid}}' "$after_container")
  after_volumes=$(docker inspect --format \
    '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}};{{end}}{{end}}' \
    "$after_container")
  [[ "$after_container" == "$before_container" ]] || {
    echo "$fault_party was recreated instead of restarting its durable container" >&2
    return 1
  }
  [[ "$before_pid" =~ ^[1-9][0-9]*$ && "$after_pid" =~ ^[1-9][0-9]*$ \
    && "$after_pid" != "$before_pid" ]] || {
    echo "$fault_party did not restart with a fresh process after SIGKILL" >&2
    return 1
  }
  [[ "$after_volumes" == "$before_volumes" ]] || {
    echo "$fault_party persistent volume changed across the AVSS crash" >&2
    return 1
  }
  response=$(protocol_fault_gate_call "$fault_party" status 0 "$boundary" "$session_hex")
  validate_protocol_fault_gate_response \
    "$response" "$fault_party" held 0 "$boundary" "$session_hex"
  printf 'after-restart %s\n' "$response" >>"$destination/protocol-fault-gate.jsonl"
  response=$(protocol_fault_gate_call "$fault_party" release 0 "$boundary" "$session_hex")
  validate_protocol_fault_gate_response \
    "$response" "$fault_party" released 0 "$boundary" "$session_hex"
  printf 'released %s\n' "$response" >>"$destination/protocol-fault-gate.jsonl"

  wait_for_process "$pid" "$deadline" "$log_file"
  record_required_e2e_marker "$log_file" "$marker"
  local released_marker="TM_ACCEPTANCE_PROTOCOL_FAULT_GATE_RELEASED party=${fault_party#p} epoch=0 boundary=$boundary session=$session_hex"
  record_required_e2e_marker "$log_file" "$released_marker" exact
  require_terminal_contract "$log_file" "$destination" "$contract"
  require_marker_order \
    "$log_file" "$marker" "$released_marker" "$ALL_EPOCHS_TERMINAL_MARKER"
  cat "$log_file"
}

run_full_faulted_e2e() {
  run_faulted_e2e "$1" full "$2" "$3"
}

run_protocol_only_faulted_e2e() {
  run_faulted_e2e "$1" protocol-only "$2" "$3"
}

run_deposit_restart_e2e() {
  local case_name=$1
  local log_file="$artifact_root/$case_name/e2e.log"
  local destination="$artifact_root/$case_name"
  local deadline=$(( $(date +%s) + campaign_timeout ))
  local marker_budget
  local before_container before_started before_volumes
  local after_container after_started after_volumes
  local marker_line transaction_hex output_index before_gate after_gate released_gate
  verify_full_acceptance_contract
  record_acceptance_contract "$case_name" full 1 1
  compose --profile acceptance run --rm --no-deps \
    -e TM_ACCEPTANCE_ENABLE_FAULT_HOOKS=1 \
    -e TM_ACCEPTANCE_PAUSE_AFTER_DEPOSIT_FUNDING=1 \
    -e TM_ACCEPTANCE_DEPOSIT_FAULT_MODE=deposit_checkpoint \
    -e TM_ACCEPTANCE_REQUIRE_RECOVERED_PARTY=2 \
    e2e >"$log_file" 2>&1 &
  local pid=$!
  # This barrier follows DKG, coinbase maturity, allocation, signing, and mining, so its bounded
  # wait uses the whole campaign deadline rather than the early-round marker deadline.
  marker_budget=$(( deadline - $(date +%s) ))
  ((marker_budget > 0)) || {
    echo "deposit fault campaign exhausted its deadline before waiting for the barrier" >&2
    return 124
  }
  wait_for_marker \
    "$pid" "$log_file" "$DEPOSIT_CHECKPOINT_HELD_MARKER" "$marker_budget"
  marker_line=$(grep -F "$DEPOSIT_CHECKPOINT_HELD_MARKER" "$log_file")
  [[ $(grep -Fc "$DEPOSIT_CHECKPOINT_HELD_MARKER" "$log_file") -eq 1 ]] || {
    echo "deposit checkpoint gate emitted ambiguous held evidence" >&2
    return 1
  }
  transaction_hex=$(sed -nE 's/.* txid=([0-9a-f]{64}) .*/\1/p' <<<"$marker_line")
  output_index=$(sed -nE 's/.* output_index=([0-9]+) .*/\1/p' <<<"$marker_line")
  [[ "$transaction_hex" =~ ^[0-9a-f]{64}$ && "$output_index" =~ ^[0-9]+$ ]] || {
    echo "deposit checkpoint marker is malformed: $marker_line" >&2
    return 1
  }
  before_gate=$(deposit_checkpoint_gate_call status "$transaction_hex" "$output_index")
  before_gate=$(canonical_deposit_checkpoint_gate_response \
    "$before_gate" held "$transaction_hex" "$output_index")
  printf 'before-restart %s\n' "$before_gate" \
    >"$destination/deposit-checkpoint-gate.jsonl"

  before_container=$(compose ps --quiet p2)
  before_started=$(docker inspect --format '{{.State.StartedAt}}' "$before_container")
  before_volumes=$(docker inspect --format \
    '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}};{{end}}{{end}}' \
    "$before_container")
  [[ -n "$before_volumes" ]] || {
    echo "p2 has no persistent Docker volume before restart" >&2
    return 1
  }
  : >"$destination/p2-restart.txt"
  record_p2_process "$destination" before

  compose kill --signal SIGKILL p2
  compose up --detach --no-build --wait --wait-timeout 90 p2

  after_container=$(compose ps --quiet p2)
  after_started=$(docker inspect --format '{{.State.StartedAt}}' "$after_container")
  after_volumes=$(docker inspect --format \
    '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}};{{end}}{{end}}' \
    "$after_container")
  record_p2_process "$destination" after
  [[ "$before_started" != "$after_started" ]] || {
    echo "p2 start timestamp did not change across SIGKILL/restart" >&2
    return 1
  }
  [[ "$before_volumes" == "$after_volumes" ]] || {
    echo "p2 persistent volume changed across restart" >&2
    return 1
  }
  after_gate=$(deposit_checkpoint_gate_call status "$transaction_hex" "$output_index")
  after_gate=$(canonical_deposit_checkpoint_gate_response \
    "$after_gate" held "$transaction_hex" "$output_index")
  [[ "$after_gate" == "$before_gate" ]] || {
    echo "p2 restored a different durable deposit checkpoint record" >&2
    return 1
  }
  printf 'after-restart %s\n' "$after_gate" \
    >>"$destination/deposit-checkpoint-gate.jsonl"
  released_gate=$(deposit_checkpoint_gate_call release "$transaction_hex" "$output_index")
  released_gate=$(canonical_deposit_checkpoint_gate_response \
    "$released_gate" released "$transaction_hex" "$output_index")
  printf 'released %s\n' "$released_gate" \
    >>"$destination/deposit-checkpoint-gate.jsonl"

  wait_for_process "$pid" "$deadline" "$log_file"
  record_required_e2e_marker "$log_file" "$DEPOSIT_CHECKPOINT_HELD_MARKER"
  record_required_e2e_marker "$log_file" "$DEPOSIT_CHECKPOINT_RELEASED_MARKER"
  require_terminal_contract "$log_file" "$destination" full
  require_marker_order \
    "$log_file" \
    "$DEPOSIT_CHECKPOINT_HELD_MARKER" \
    "$DEPOSIT_CHECKPOINT_RELEASED_MARKER" \
    "$CONSOLIDATION_TRANSACTION_MARKER" \
    "$SIGNED_TRANSACTION_MARKER" \
    "$ALL_EPOCHS_TERMINAL_MARKER"
  require_terminal_party_health "$destination"
  cat "$log_file"
}

run_rust() {
  local destination="$artifact_root/rust"
  local log_file="$destination/rust.log"
  mkdir -p -- "$destination"
  printf 'case=rust\nstarted_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >"$destination/case-metadata.env"
  verify_vendored_monero_sources 2>&1 \
    | tee "$destination/vendor-monero-source-verification.log" "$log_file"
  # Several debug-only crash/restart fixtures retain complete bounded protocol snapshots across
  # await points. Give the single libtest worker enough stack for those generated state machines;
  # release signer processes retain Rust/Tokio's normal production stack configuration.
  RUST_MIN_STACK=16777216 \
    cargo test --locked --all-targets -j2 -- --test-threads=1 2>&1 | tee -a "$log_file"
  printf '%s\n' "$RUST_TERMINAL_MARKER" | tee -a "$log_file"
  grep -Fxq "$RUST_TERMINAL_MARKER" "$log_file"
  printf 'completed_at=%s\nresult=passed\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >>"$destination/case-metadata.env"
  printf 'TM_RESILIENCE_CASE_PASSED=rust\n' >"$destination/case-result.env"
}

run_preflight() {
  local overlay preflight_clock_dir
  select_case preflight 0
  compose --profile acceptance config --quiet
  verify_private_regtest_topology preflight
  select_case preflight-silent 1
  compose --profile acceptance config --quiet
  verify_private_regtest_topology preflight-silent
  select_case preflight 0
  for overlay in \
    compose.acceptance-consolidation-bootstrap-gate.yaml \
    compose.acceptance-consolidation-gate.yaml \
    compose.acceptance-manual-bootstrap.yaml \
    compose.acceptance-protocol-fault-gate.yaml \
    compose.byzantine-silent.yaml \
    compose.debug.yaml
  do
    docker compose \
      -p "$PROJECT" \
      -f compose.yaml \
      -f "$overlay" \
      --profile acceptance \
      config --quiet
  done
  preflight_clock_dir=$(mktemp -d \
    "${TMPDIR:-/tmp}/threshold-monero-deposit-clock-preflight.XXXXXX")
  TM_ACCEPTANCE_DEPOSIT_CLOCK_DIR=$preflight_clock_dir docker compose \
    -p "$PROJECT" \
    -f compose.yaml \
    -f compose.acceptance-deposit-clock.yaml \
    --profile acceptance \
    config --quiet
  export TM_ACCEPTANCE_DEPOSIT_CLOCK_DIR=$preflight_clock_dir
  select_case preflight-deposit-ttl 0
  COMPOSE_FILES+=(-f compose.acceptance-deposit-clock.yaml)
  compose --profile acceptance config --quiet
  verify_private_regtest_topology preflight-deposit-ttl
  unset TM_ACCEPTANCE_DEPOSIT_CLOCK_DIR
  rmdir "$preflight_clock_dir"
  select_case preflight 0
  "$script_dir/generate-demo-quic-pki.sh" --check
  printf '%s\n' \
    'TM_RESILIENCE_PREFLIGHT_PASSED current schema, QUIC fixtures, healthchecks, and persistent topology'
}

run_clean() {
  require_images
  select_case clean 0
  prepare_fresh_compose clean
  run_full_e2e clean
  finish_compose clean
}

run_observer_byzantine() {
  require_images
  select_case observer-byzantine 0
  prepare_fresh_compose observer-byzantine
  # p1's signer and QUIC endpoint remain live. Only its separately addressed observer is isolated
  # onto a valid competing fakechain, paused long enough to exceed ordinary polling cadence, then
  # explicitly stopped. The full n-f acceptance contract must still sign and settle a real sweep
  # and complete the configured/dynamic refresh chain.
  run_observer_byzantine_e2e observer-byzantine
  finish_compose observer-byzantine
}

run_avss_crash() {
  require_images
  select_case avss-crash 0
  COMPOSE_FILES+=(-f compose.acceptance-manual-bootstrap.yaml)
  COMPOSE_FILES+=(-f compose.acceptance-protocol-fault-gate.yaml)
  prepare_fresh_compose avss-crash
  # p3's canonical dealer state and complete encrypted outbox are authenticated and held before
  # the crash. Restart must report the same exact held evidence before admin release.
  run_full_faulted_e2e avss-crash p3 dealer_started
  finish_compose avss-crash
}

run_deposit_restart() {
  require_images
  select_case deposit-restart 0
  prepare_fresh_compose deposit-restart
  # p2 is an epoch-0 threshold signer. The barrier is emitted only after the deposit funding
  # transaction is mined and independently scanned, but before its remaining maturity blocks.
  # Restarting the same service preserves its named volume and forces durable state recovery before
  # the autonomous consolidation can become eligible.
  run_deposit_restart_e2e deposit-restart
  finish_compose deposit-restart
}

run_deposit_ttl() {
  require_images
  select_case deposit-ttl 0
  local destination="$artifact_root/deposit-ttl"
  prepare_deposit_ttl_clock_directory "$destination"
  COMPOSE_FILES+=(-f compose.acceptance-deposit-clock.yaml)
  prepare_fresh_compose deposit-ttl
  # The focused E2E branch writes six exact logical clock generations. Parties can only read the
  # shared directory; the one-shot client alone advances it. Consolidation remains disabled so the
  # evidence isolates unused expiry, non-reuse, and post-expiry retrieval of a funded used address.
  run_deposit_ttl_e2e deposit-ttl
  finish_compose deposit-ttl
  unset TM_ACCEPTANCE_DEPOSIT_CLOCK_DIR
}

run_consolidation_silent() {
  require_images
  select_case consolidation-silent 0
  COMPOSE_FILES+=(-f compose.acceptance-consolidation-gate.yaml)
  prepare_fresh_compose consolidation-silent
  # The E2E runner selects an initial n-f signer that the deterministic next ROAST subset omits.
  # Only that live party's peer-QUIC attachment is removed; control/status and every other process
  # remain available until the replacement subset broadcasts and settles the real sweep.
  run_consolidation_silent_e2e consolidation-silent
  finish_compose consolidation-silent
}

run_consolidation_bootstrap_silent() {
  require_images
  select_case consolidation-bootstrap-silent 0
  COMPOSE_FILES+=(-f compose.acceptance-consolidation-bootstrap-gate.yaml)
  prepare_fresh_compose consolidation-bootstrap-silent
  # Every party first persists an independently randomized prepared intent and stops before any
  # slot-zero BA traffic. The deterministic proposer is then stopped until another proposer has
  # certified its own value. The old proposer restarts from the same volume and catches up over
  # QUIC while the entire committee remains at the separate pre-nonce gate.
  run_consolidation_bootstrap_silent_e2e consolidation-bootstrap-silent
  finish_compose consolidation-bootstrap-silent
}

run_silent() {
  require_images
  select_case silent 1
  prepare_fresh_compose silent
  assert_silent_p1_isolated "$artifact_root/silent" before-e2e
  # p1 is deliberately unreachable over QUIC. This focused mode isolates
  # AVSS/QUAL/resharing/signing liveness; the adjacent fault modes exercise allocation.
  run_protocol_only_e2e silent
  assert_silent_p1_isolated "$artifact_root/silent" after-e2e
  finish_compose silent
}

run_deposit_silent() {
  require_images
  select_case deposit-silent 1
  prepare_fresh_compose deposit-silent
  assert_silent_p1_isolated "$artifact_root/deposit-silent" before-e2e
  # p1 cannot receive QUIC traffic. The client submits its one request to p2, forcing the
  # allocation consensus pacemaker to advance before the real deposit is funded and observed.
  # Consolidation remains outside this focused gate; `leader-down` separately covers whole-party
  # loss during full allocation and signing.
  run_allocation_only_e2e deposit-silent
  assert_silent_p1_isolated "$artifact_root/deposit-silent" after-e2e
  finish_compose deposit-silent
}

run_leader_down() {
  require_images
  select_case leader-down 0
  prepare_fresh_compose leader-down
  local destination="$artifact_root/leader-down"
  : >"$destination/p1-down.txt"
  record_p1_process "$destination" before
  # Stop the real container after the entire fresh stack is healthy. A zero-second grace period
  # makes this a process-loss fault, and Compose's explicit stop suppresses `unless-stopped`
  # recovery so p1 stays absent throughout allocation, handoff, refresh, and signing.
  compose stop --timeout 0 p1
  assert_p1_down
  record_p1_process "$destination" after-stop
  run_leader_down_e2e leader-down
  assert_p1_down
  record_p1_process "$destination" after-e2e
  finish_compose leader-down
}

run_rotation_silent() {
  require_images
  select_case rotation-silent 0
  prepare_fresh_compose rotation-silent
  # The E2E runner derives one actual member from the certified final 3-of-5 committee. Every party
  # participates normally through epoch-4 activation; only then does the driver remove the emitted
  # member's peer-QUIC attachment while retaining its process, control endpoint, and durable volume.
  run_rotation_silent_e2e rotation-silent
  finish_compose rotation-silent
}

run_network_restart() {
  require_images
  select_case network-restart 0
  prepare_fresh_compose network-restart
  # The full E2E path has already activated and signed under epoch four when it exposes the exact
  # persisted epoch-4-to-5 deadline. Stop every signer before that deadline, keep every named volume,
  # restart only after all eight deadlines are overdue, and require an n-f epoch-five activation
  # before the client may allocate and consolidate a fresh deposit.
  run_network_restart_e2e network-restart
  finish_compose network-restart
}

run_proactive_deadline() {
  require_images
  select_case proactive-deadline 0
  prepare_fresh_compose proactive-deadline
  run_proactive_deadline_e2e proactive-deadline
  finish_compose proactive-deadline
}

run_qual_crash_silent() {
  require_images
  select_case qual-crash-silent 1
  COMPOSE_FILES+=(-f compose.acceptance-manual-bootstrap.yaml)
  COMPOSE_FILES+=(-f compose.acceptance-protocol-fault-gate.yaml)
  prepare_fresh_compose qual-crash-silent
  assert_silent_p1_isolated "$artifact_root/qual-crash-silent" before-e2e
  # With p1 silent, p3 is frozen only after its authenticated reducer has durably entered
  # undecided QUAL round zero. Restart must preserve that exact round before admin release.
  run_protocol_only_faulted_e2e qual-crash-silent p3 qual_round_zero
  assert_silent_p1_isolated "$artifact_root/qual-crash-silent" after-e2e
  finish_compose qual-crash-silent
}

case "$mode" in
  preflight) run_preflight ;;
  rust) run_rust ;;
  clean) run_clean ;;
  observer-byzantine) run_observer_byzantine ;;
  avss-crash) run_avss_crash ;;
  deposit-restart) run_deposit_restart ;;
  deposit-ttl) run_deposit_ttl ;;
  consolidation-silent) run_consolidation_silent ;;
  consolidation-bootstrap-silent) run_consolidation_bootstrap_silent ;;
  silent) run_silent ;;
  deposit-silent) run_deposit_silent ;;
  leader-down) run_leader_down ;;
  rotation-silent) run_rotation_silent ;;
  network-restart) run_network_restart ;;
  proactive-deadline) run_proactive_deadline ;;
  qual-crash-silent) run_qual_crash_silent ;;
  all)
    run_preflight
    run_rust
    run_clean
    run_observer_byzantine
    run_avss_crash
    run_deposit_restart
    run_deposit_ttl
    run_consolidation_silent
    run_consolidation_bootstrap_silent
    run_silent
    run_deposit_silent
    run_leader_down
    run_rotation_silent
    run_network_restart
    run_proactive_deadline
    run_qual_crash_silent
    ;;
esac

if [[ "$mode" == preflight ]]; then
  printf 'TM_RESILIENCE_CAMPAIGN_PASSED mode=preflight\n'
else
  printf 'TM_RESILIENCE_CAMPAIGN_PASSED mode=%s evidence=%s\n' "$mode" "$artifact_root"
fi
