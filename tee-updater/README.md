# TEE updater

The updater gets the JWKS of one OIDC issuer. It signs a key set for `JWKSRegistry`. A host sends the signed key set to the contract.

Use AWS Nitro Enclaves for the TEE path. Use local mode for the demo. **The enclave path has not run on a Nitro instance.**

## Security boundary

- TLS ends in the enclave. The parent instance forwards encrypted bytes.
- The Nitro Secure Module (NSM) supplies random bytes for the attestor key. The key stays in enclave memory.
- The registry owner verifies the AWS attestation signature, image measurements (PCRs), public key, and random challenge. Then the owner calls `setAttestor`.
- The NSM supplies the time for the TLS certificate check and the signed key set. The enclave reads the time before the HTTPS request. A delay makes the key set older.
- The signature binds the keys and time to one JWKS URI, chain, and registry.
- The parent instance can stop or delay updates.

Each key must have `kty: RSA`, `alg: RS256`, `use: sig`, exponent 65537, and an odd 2048-bit modulus. Key IDs must be nonempty and distinct. The updater rejects the full JWKS if a key fails these checks. An empty JWKS removes all keys from the registry.

The HTTP/1.0 client requires a `200` response. It checks `Content-Length` if present and requires complete JWKS JSON. It rejects transfer encoding and responses larger than 64 KiB, with headers. It does not follow redirects. URLs must use a DNS name or an IPv4 address, without credentials or a fragment.

## Local mode

Run these commands in the repository root.

```bash
cargo run --manifest-path tee-updater/Cargo.toml -- sign \
  --jwks-uri https://www.googleapis.com/oauth2/v3/certs \
  --chain-id 31337 \
  --registry "$REGISTRY" \
  --private-key "$ATTESTOR_KEY" > snapshot.json
```

Use a secp256k1 private key for `ATTESTOR_KEY`. Set its address as the registry attestor before the fetch. Local mode has no TEE protection.

Anyone can send the signed key set. Set `REGISTRY` to the contract address that you trust:

```bash
REGISTRY="$REGISTRY" SNAPSHOT="$(cat snapshot.json)" forge script script/UpdateKeys.s.sol \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
```

## Enclave mode

You need an EC2 instance with Nitro Enclaves, `nitro-cli`, `vsock-proxy`, Docker, Python 3, and Foundry. Use a trusted computer to verify the attestation. Run these commands in the repository root.

1. Build the Docker image and the enclave image file (EIF):

   ```bash
   docker build -t tee-updater tee-updater
   nitro-cli build-enclave --docker-uri tee-updater --output-file tee-updater.eif
   ```

   Record PCR0, PCR1, and PCR2 from a trusted build. Copy that EIF to the parent instance. Use the recorded PCRs for enrollment.

2. Start the proxy from the enclave to the JWKS host. The allowlist in [`vsock-proxy.yaml`](vsock-proxy.yaml) must contain the host.

   ```bash
   vsock-proxy 8443 www.googleapis.com 443 --config tee-updater/vsock-proxy.yaml &
   ```

3. Start the enclave without `--debug-mode`. The verifier rejects zero PCRs from a debug enclave.

   ```bash
   nitro-cli run-enclave --eif-path tee-updater.eif --cpu-count 2 --memory 512
   ```

   Set `CID` to the `EnclaveCID` in the output.

4. On the trusted computer, make a new random challenge:

   ```bash
   CHALLENGE=0x$(openssl rand -hex 32)
   ```

   Copy the challenge to the parent instance. Ask the enclave for an attestation:

   ```bash
   python3 tee-updater/scripts/request.py --cid "$CID" \
     "{\"operation\":\"attest\",\"challenge\":\"$CHALLENGE\"}" > attestation.json
   ```

   Copy `attestation.json` to the trusted computer and verify it there:

   ```bash
   ATTESTOR=$(cargo run --quiet --release --manifest-path tee-updater/Cargo.toml \
     --bin verify-attestation -- --response attestation.json \
     --challenge "$CHALLENGE" --pcr0 "$PCR0" --pcr1 "$PCR1" --pcr2 "$PCR2")
   ```

   The verifier checks the AWS signature, certificate chain, PCRs, challenge, and time. It prints the attestor address. On the trusted computer, set that address in the registry:

   ```bash
   cast send "$REGISTRY" "setAttestor(address)" "$ATTESTOR" --rpc-url "$RPC_URL" --private-key "$OWNER_KEY"
   ```

5. Fetch and send the JWKS. The fetch time must be later than `registry.fetchedAt()`, which `setAttestor` sets to its block time. Wait for the next second before the first fetch or a repeat fetch. The chain time must reach the fetch time before you send the transaction.

   ```bash
   python3 tee-updater/scripts/request.py --cid "$CID" \
     "{\"operation\":\"sign\",\"jwksUri\":\"https://www.googleapis.com/oauth2/v3/certs\",\"chainId\":$CHAIN_ID,\"registry\":\"$REGISTRY\"}" > snapshot.json
   REGISTRY="$REGISTRY" SNAPSHOT="$(cat snapshot.json)" forge script script/UpdateKeys.s.sol \
     --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
   ```

Send a new key set before `MAX_KEY_SET_AGE` (one day) expires. The registry rejects the use of stale keys.

An enclave restart makes a new key. Repeat step 4. `setAttestor` removes the old keys. Then fetch and send a new key set.

## Checks

```bash
cd tee-updater
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```
