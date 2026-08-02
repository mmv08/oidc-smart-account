#!/usr/bin/env bash
set -euo pipefail

if ! grep -q 'www.googleapis.com' /etc/hosts; then
  printf '127.0.0.2 www.googleapis.com\n' >> /etc/hosts
fi

/app/vsock-loopback \
  --listen-ip 127.0.0.2 \
  --listen-port 443 \
  --parent-cid 3 \
  --parent-port "${GOOGLE_VSOCK_PROXY_PORT:-8443}" &
relay_pid=$!
trap 'kill "$relay_pid" 2>/dev/null || true' EXIT INT TERM

exec "$@"
