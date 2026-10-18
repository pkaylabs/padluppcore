#!/usr/bin/env bash
set -euo pipefail

# Calls scheduler-only API endpoints over the local Daphne listener.

BASE_URL="${PADLUPPCORE_CRON_BASE_URL:-http://127.0.0.1:8000/api-v1}"
TIMEOUT_SECONDS="${PADLUPPCORE_CRON_TIMEOUT_SECONDS:-60}"
CURL_BIN="${PADLUPPCORE_CRON_CURL_BIN:-/usr/bin/curl}"
ENV_FILE="${PADLUPPCORE_CRON_ENV_FILE:-/etc/padluppcore/cron.env}"

if [[ -r "${ENV_FILE}" ]]; then
  # shellcheck source=/dev/null
  source "${ENV_FILE}"
fi

CRON_SECRET="${PADLUPPCORE_CRON_SECRET:-}"

usage() {
  cat <<'EOF'
Usage:
  run_cron_endpoints.sh [all|nudge|checkin|community]

Environment:
  PADLUPPCORE_CRON_BASE_URL          Base URL (default: http://127.0.0.1:8000/api-v1)
  PADLUPPCORE_CRON_TIMEOUT_SECONDS  Curl timeout seconds (default: 60)
  PADLUPPCORE_CRON_CURL_BIN          Curl binary path (default: /usr/bin/curl)
  PADLUPPCORE_CRON_ENV_FILE          Secret env file (default: /etc/padluppcore/cron.env)
  PADLUPPCORE_CRON_SECRET            Value sent in X-Padlupp-Cron-Secret
EOF
}

log() {
  # ISO-8601 timestamp in UTC
  echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"
}

post_json() {
  local path="$1"
  local url="${BASE_URL%/}${path}"

  log "POST ${url}"

  local curl_fail_flag="--fail"
  # Prefer --fail-with-body when available, but fall back for older curl versions.
  if "${CURL_BIN}" --help all 2>/dev/null | grep -q -- '--fail-with-body'; then
    curl_fail_flag="--fail-with-body"
  fi

  # Print response body, and ensure non-2xx fails the script.
  local headers=()
  if [[ -n "${CRON_SECRET}" ]]; then
    headers=(-H "X-Padlupp-Cron-Secret: ${CRON_SECRET}")
  fi

  # Match the trusted local proxy's HTTPS scheme without following redirects.
  case "${BASE_URL}" in
    http://127.0.0.1:*|http://localhost:*)
      headers+=(-H 'X-Forwarded-Proto: https')
      ;;
  esac

  local response status
  response=$("${CURL_BIN}" \
    --silent --show-error \
    "${curl_fail_flag}" \
    --max-time "${TIMEOUT_SECONDS}" \
    -X POST \
    -H 'Content-Type: application/json' \
    "${headers[@]}" \
    --write-out $'\n%{http_code}' \
    "${url}")

  status="${response##*$'\n'}"
  printf '%s\n' "${response%$'\n'*}"
  if [[ ! "${status}" =~ ^2[0-9][0-9]$ ]]; then
    log "Unexpected HTTP status ${status}; scheduler request was not completed."
    return 1
  fi
}

main() {
  local mode="${1:-all}"

  case "${mode}" in
    -h|--help|help)
      usage
      exit 0
      ;;
    all)
      post_json "/cron/nudge-inactive-users/"
      post_json "/cron/checkin-reminders/"
      post_json "/cron/community-cycles/"
      ;;
    nudge)
      post_json "/cron/nudge-inactive-users/"
      ;;
    checkin)
      post_json "/cron/checkin-reminders/"
      post_json "/cron/community-cycles/"
      ;;
    community)
      post_json "/cron/community-cycles/"
      ;;
    *)
      log "Unknown mode: ${mode}"
      usage
      exit 2
      ;;
  esac
}

main "$@"
