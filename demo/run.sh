#!/usr/bin/env bash
# Runs the full flow on a local Anvil chain:
#   mock issuer -> TEE updater (local mode) -> JWKSRegistry -> JWT -> OIDCAccount -> transaction
# Necessary tools: Foundry (anvil, forge, cast), Rust (cargo), Node.js, and curl.
set -euo pipefail
cd "$(dirname "$0")/.."

RPC_URL=http://127.0.0.1:8545
ISSUER=https://issuer.example
AUDIENCE=demo-client
JWKS_URI=http://127.0.0.1:9000/jwks.json
SUB=alice
RECIPIENT=0x000000000000000000000000000000000000dEaD

# Anvil test keys. Never use them on a public chain.
OWNER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ATTESTOR_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
SIGNER_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
OWNER=$(cast wallet address "$OWNER_KEY")
ATTESTOR=$(cast wallet address "$ATTESTOR_KEY")
SIGNER=$(cast wallet address "$SIGNER_KEY")

step() { printf '\n\033[1m%s\033[0m\n' "$*"; }
deploy() {
  forge create --rpc-url "$RPC_URL" --private-key "$OWNER_KEY" --broadcast "$@" |
    awk '/Deployed to:/ { print $3 }'
}
send() { cast send --rpc-url "$RPC_URL" "$@" >/dev/null; }

# Stop if the ports are in use. Otherwise the demo can use another node or another issuer.
if cast chain-id --rpc-url "$RPC_URL" >/dev/null 2>&1 || curl -s "$JWKS_URI" >/dev/null; then
  echo "error: port 8545 or 9000 is in use" >&2 && exit 1
fi
forge build --quiet
cargo build --quiet --manifest-path tee-updater/Cargo.toml
anvil --silent &
ANVIL_PID=$!
node demo/mock-issuer.mjs >/dev/null &
ISSUER_PID=$!
trap 'kill "$ANVIL_PID" "$ISSUER_PID"' EXIT
sleep 2

step "1. Deploy the registry for the JWKS URI, and the verifier for the issuer and the audience"
REGISTRY=$(deploy src/JWKSRegistry.sol:JWKSRegistry --constructor-args "$OWNER" "$JWKS_URI")
VERIFIER=$(deploy src/JWTVerifier.sol:JWTVerifier --constructor-args "$REGISTRY" "$ISSUER" "$AUDIENCE")
echo "JWKSRegistry $REGISTRY"
echo "JWTVerifier  $VERIFIER"

step "2. The owner sets the attestor (with an enclave: after verify-attestation)"
send --private-key "$OWNER_KEY" "$REGISTRY" "setAttestor(address)" "$ATTESTOR"
echo "attestor $ATTESTOR"

step "3. The TEE updater gets the issuer JWKS and signs it. A relayer sends the snapshot."
SNAPSHOT=$(tee-updater/target/debug/tee-updater sign --jwks-uri "$JWKS_URI" --chain-id 31337 \
  --registry "$REGISTRY" --private-key "$ATTESTOR_KEY")
REGISTRY="$REGISTRY" SNAPSHOT="$SNAPSHOT" forge script script/UpdateKeys.s.sol --rpc-url "$RPC_URL" \
  --private-key "$OWNER_KEY" --broadcast --silent
KID_HASH=$(cast keccak mock-key-1)
echo "key mock-key-1: $(cast call --rpc-url "$RPC_URL" "$REGISTRY" "getKey(bytes32)(bytes)" "$KID_HASH" | cut -c1-20)..."

step "4. Deploy the account of the user '$SUB' and send 1 ETH to it"
ACCOUNT=$(deploy src/OIDCAccount.sol:OIDCAccount --constructor-args "$VERIFIER" "$(cast keccak "$SUB")")
send --private-key "$OWNER_KEY" --value 1ether "$ACCOUNT"
echo "OIDCAccount $ACCOUNT"

step "5. The user gets a JWT whose nonce approves the new signer. Anyone can send it."
NONCE=$(cast call --rpc-url "$RPC_URL" "$ACCOUNT" "jwtNonce(address)(string)" "$SIGNER" | tr -d '"')
JWT=$(curl -s "http://127.0.0.1:9000/token?sub=$SUB&nonce=$NONCE")
echo "nonce $NONCE"
echo "JWT   ${JWT:0:40}..."
TX=$(cast send --rpc-url "$RPC_URL" --private-key "$OWNER_KEY" --json "$ACCOUNT" \
  "setSigner(string,address)" "$JWT" "$SIGNER" | sed -E 's/.*"transactionHash":"([^"]+)".*/\1/')
echo "signer $(cast call --rpc-url "$RPC_URL" "$ACCOUNT" "signer()(address)")"
echo "setSigner gas $(cast receipt --rpc-url "$RPC_URL" "$TX" gasUsed)"

step "6. The signer sends 0.5 ETH from the account"
send --private-key "$SIGNER_KEY" "$ACCOUNT" "execute(address,uint256,bytes)" "$RECIPIENT" 0.5ether 0x
echo "account balance   $(cast balance --rpc-url "$RPC_URL" --ether "$ACCOUNT") ETH"
echo "recipient balance $(cast balance --rpc-url "$RPC_URL" --ether "$RECIPIENT") ETH"

step "7. The same JWT cannot set a signer again"
if cast send --rpc-url "$RPC_URL" --private-key "$OWNER_KEY" "$ACCOUNT" \
  "setSigner(string,address)" "$JWT" "$SIGNER" >/dev/null 2>&1; then
  echo "error: the JWT was used two times" && exit 1
fi
echo "replay rejected"
