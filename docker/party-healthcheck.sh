#!/bin/sh
set -eu

url="${1:-http://127.0.0.1:8080/v1/status}"
party_id="${TM_PARTY_ID:?TM_PARTY_ID is required}"
token_file="${TM_ADMIN_BEARER_TOKEN_FILE:?TM_ADMIN_BEARER_TOKEN_FILE is required}"
token=$(tr -d '\r\n' <"$token_file")
response=$(curl --fail --max-time 3 --show-error --silent \
  --header "Authorization: Bearer $token" "$url")
printf '%s' "$response" | grep -Eq \
  '"party"[[:space:]]*:[[:space:]]*'"$party_id"'([,}]).*"ready"[[:space:]]*:[[:space:]]*true'
