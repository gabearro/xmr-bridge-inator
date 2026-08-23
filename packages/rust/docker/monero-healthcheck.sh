#!/bin/sh
set -eu

kind="${1:-}"
url="${2:-http://127.0.0.1:18081/json_rpc}"
upstream_url="${3:-}"

case "${kind}" in
  daemon) ;;
  observer)
    if [ -z "${upstream_url}" ]; then
      echo "usage: monero-healthcheck observer local-json-rpc-url upstream-json-rpc-url" >&2
      exit 2
    fi
    ;;
  *)
    echo "usage: monero-healthcheck daemon [json-rpc-url]" >&2
    echo "       monero-healthcheck observer local-json-rpc-url upstream-json-rpc-url" >&2
    exit 2
    ;;
esac

payload='{"jsonrpc":"2.0","id":"health","method":"get_info"}'
expected='"status"[[:space:]]*:[[:space:]]*"OK"'

response="$(
  curl --fail --max-time 3 --show-error --silent \
    --header 'Content-Type: application/json' \
    --data "${payload}" \
    "${url}"
)"

printf '%s\n' "${response}" | grep -Eq "${expected}"

if [ "${kind}" = observer ]; then
  upstream="$(
    curl --fail --max-time 3 --show-error --silent \
      --header 'Content-Type: application/json' \
      --data "${payload}" \
      "${upstream_url}"
  )"
  printf '%s\n' "${upstream}" | grep -Eq "${expected}"
  local_height=$(printf '%s\n' "${response}" \
    | sed -nE 's/.*"height"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p')
  upstream_height=$(printf '%s\n' "${upstream}" \
    | sed -nE 's/.*"height"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p')
  case "${local_height}:${upstream_height}" in
    ''|:*|*:) exit 1 ;;
  esac
  [ "${local_height}" -ge "${upstream_height}" ]
fi
