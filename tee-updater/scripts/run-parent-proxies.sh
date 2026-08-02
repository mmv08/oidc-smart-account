#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:?AWS_REGION is required}"
if [[ ! "$AWS_REGION" =~ ^[a-z0-9-]+$ ]]; then
  printf 'Invalid AWS_REGION\n' >&2
  exit 2
fi
command -v vsock-proxy >/dev/null || {
  printf 'vsock-proxy is required (install aws-nitro-enclaves-cli)\n' >&2
  exit 2
}

# These are intentionally fixed destinations. Do not turn this script into a generic proxy.
vsock-proxy 8000 "kms.${AWS_REGION}.amazonaws.com" 443 &
kms_pid=$!
vsock-proxy 8443 www.googleapis.com 443 &
google_pid=$!
trap 'kill "$kms_pid" "$google_pid" 2>/dev/null || true' EXIT INT TERM
wait -n "$kms_pid" "$google_pid"
