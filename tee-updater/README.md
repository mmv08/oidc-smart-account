# TEE updater

The TEE updater gets the JWKS of an OIDC issuer and signs it for the `JWKSRegistry` contract. It runs in an AWS Nitro Enclave. For tests and demos, it can also run on a usual host (local mode).

**Status:** the local mode is tested, and the Docker image builds (tested with Podman on arm64). The enclave mode has not run on a Nitro instance.

## Security boundary

- TLS ends in the enclave. The parent instance only forwards encrypted bytes, so it cannot change the JWKS.
- The enclave makes the attestor key in its memory when it starts. The key never leaves the enclave.
- A Nitro attestation document shows the image measurements (PCRs) and the attestor public key. The registry owner examines it before `setAttestor`.
- The signed key set contains the JWKS URI, all keys, and the time from the Nitro Secure Module. The enclave reads the time before the HTTPS request, so a slow host can only make the key set look older.
- The parent instance can stop or delay updates. Nothing in this design prevents that.

The updater accepts a JWKS only if each key is an RS256 signature key (`kty` RSA, `use` sig) with the exponent 65537 and a 2048-bit modulus. Otherwise it rejects the full JWKS.

## Local mode

Run these commands in the repository root.

```bash
cargo run --manifest-path tee-updater/Cargo.toml -- sign \
  --jwks-uri https://www.googleapis.com/oauth2/v3/certs \
  --chain-id 31337 \
  --registry "$REGISTRY" \
  --private-key "$ATTESTOR_KEY" > snapshot.json
```

The private key is a usual secp256k1 key. Use this mode only for tests and demos. The output is the signed key set. Anyone can send it to the registry. The script takes the registry address from `REGISTRY`, not from the snapshot, because the snapshot is not trusted data:

```bash
REGISTRY="$REGISTRY" SNAPSHOT="$(cat snapshot.json)" forge script script/UpdateKeys.s.sol \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
```

## Enclave mode

You need an EC2 instance with Nitro Enclaves, `nitro-cli`, `vsock-proxy`, and Docker.

1. Build the Docker image and the enclave image file (EIF):

   ```bash
   docker build -t tee-updater tee-updater
   nitro-cli build-enclave --docker-uri tee-updater --output-file tee-updater.eif
   ```

   Write down PCR0, PCR1, and PCR2 from the output.

2. Start the proxy from the enclave to the JWKS host. The allowlist in [`vsock-proxy.yaml`](vsock-proxy.yaml) must contain the host.

   ```bash
   vsock-proxy 8443 www.googleapis.com 443 --config tee-updater/vsock-proxy.yaml &
   ```

3. Start the enclave. Do not use `--debug-mode`: a debug enclave has zero PCRs, and `verify-attestation` rejects it.

   ```bash
   nitro-cli run-enclave --eif-path tee-updater.eif --cpu-count 2 --memory 512
   ```

   Write down the `EnclaveCID`.

4. Enroll the attestor. Use a new random challenge each time.

   ```bash
   CHALLENGE=0x$(openssl rand -hex 32)
   python3 tee-updater/scripts/request.py --cid "$CID" \
     "{\"operation\":\"attest\",\"challenge\":\"$CHALLENGE\"}" > attestation.json
   cargo run --release --bin verify-attestation -- --response attestation.json \
     --challenge "$CHALLENGE" --pcr0 "$PCR0" --pcr1 "$PCR1" --pcr2 "$PCR2"
   ```

   `verify-attestation` verifies the AWS signature and the certificate chain of the document. Then it compares the PCRs, the challenge, and the time, and it shows the attestor address. Run it on a computer that you trust. Then the owner sets the attestor:

   ```bash
   cast send "$REGISTRY" "setAttestor(address)" "$ATTESTOR" --rpc-url "$RPC_URL" --private-key "$OWNER_KEY"
   ```

5. Send a new key set at least one time each day, because the registry rejects key sets that are older than `MAX_KEY_SET_AGE`:

   ```bash
   python3 tee-updater/scripts/request.py --cid "$CID" \
     "{\"operation\":\"sign\",\"jwksUri\":\"https://www.googleapis.com/oauth2/v3/certs\",\"chainId\":1,\"registry\":\"$REGISTRY\"}" > snapshot.json
   REGISTRY="$REGISTRY" SNAPSHOT="$(cat snapshot.json)" forge script script/UpdateKeys.s.sol \
     --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
   ```

When the enclave starts again, it has a new key. Do step 4 again.

## Code

| File | Function |
| --- | --- |
| [`src/lib.rs`](src/lib.rs) | JWKS checks, the EIP-712 digest of a key set, signatures, and attestation checks |
| [`src/http.rs`](src/http.rs) | HTTP/1.0 GET over a stream that the caller opens: TCP in local mode, vsock in the enclave |
| [`src/main.rs`](src/main.rs) | The `sign` command (local mode) and the `serve` command (enclave) |
| [`src/nitro.rs`](src/nitro.rs) | Attestation documents and time from the Nitro Secure Module |
| [`src/bin/verify-attestation.rs`](src/bin/verify-attestation.rs) | Verifies an attestation document outside the enclave |
| [`scripts/request.py`](scripts/request.py) | Sends one request to the enclave from the parent instance |

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```
