#!/usr/bin/env bash
set -euo pipefail

SDK_COMMIT="cd61b6187c8b20867ba4368d1ae62c5790c0269a"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/../vendor"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

git clone --filter=blob:none https://github.com/aws/aws-nitro-enclaves-sdk-c.git "$WORK_DIR/sdk"
git -C "$WORK_DIR/sdk" checkout --detach "$SDK_COMMIT"
docker build \
  --file "$WORK_DIR/sdk/containers/Dockerfile.al2" \
  --target kmstool-enclave-cli \
  --tag tee-google-kmstool:"$SDK_COMMIT" \
  "$WORK_DIR/sdk"

container_id="$(docker create tee-google-kmstool:"$SDK_COMMIT")"
trap 'docker rm -f "$container_id" >/dev/null 2>&1 || true; rm -rf "$WORK_DIR"' EXIT
mkdir -p "$VENDOR_DIR"
docker cp "$container_id:/kmstool_enclave_cli" "$VENDOR_DIR/kmstool_enclave_cli"
docker cp "$container_id:/usr/lib64/libnsm.so" "$VENDOR_DIR/libnsm.so"
chmod 0755 "$VENDOR_DIR/kmstool_enclave_cli"
(
  cd "$VENDOR_DIR"
  sha256sum --check SHA256SUMS
)
printf 'Built pinned AWS kmstool artifacts in %s\n' "$VENDOR_DIR"
