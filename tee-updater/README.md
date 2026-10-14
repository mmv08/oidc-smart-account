# TEE updater

The TEE updater gets the JWKS of an OIDC issuer and signs it for the `JWKSRegistry` contract. It runs in an AWS Nitro Enclave. For tests and demos, it can also run on a usual host (local mode).

**Status:** the local mode is tested, and the Docker image builds. The enclave mode has not run on a Nitro instance.

## Security boundary

- TLS ends in the enclave. The parent instance only forwards encrypted bytes, so it cannot change the JWKS.
- The enclave makes the attestor key from random bytes of the Nitro Secure Module (NSM) when it starts. The key never leaves the enclave memory.
- A Nitro attestation document shows the image measurements (PCRs) and the attestor public key. The registry owner examines it before `setAttestor`.
- The time comes from the NSM, not from the parent instance. The enclave uses this time for the TLS certificate check and for the signed key set. It reads the time before the HTTPS request, so a slow parent can only make the key set look older.
- The signature binds the keys and the time to one JWKS URI, one chain, and one registry.
- The parent instance can stop or delay updates. Nothing in this design prevents that.

The updater accepts a JWKS only if each key is an RS256 signature key (`kty` RSA, `use` sig) with the exponent 65537 and a 2048-bit modulus. Otherwise it rejects the full JWKS. An empty JWKS removes all keys from the registry.

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

You need an EC2 instance with Nitro Enclaves, `nitro-cli`, `vsock-proxy`, Docker, Python 3, and Foundry. You also need a second computer that you trust, because the parent instance is not trusted. Run the commands in the repository root.

1. Build the Docker image and the enclave image file (EIF):

   ```bash
   docker build -t tee-updater tee-updater
   nitro-cli build-enclave --docker-uri tee-updater --output-file tee-updater.eif
   ```

   The output shows PCR0, PCR1, and PCR2. For the enrollment, use PCR values from a build that you trust. For example, build the EIF on the trusted computer and copy it to the parent instance. Do not trust values that the parent instance shows.

2. Start the proxy from the enclave to the JWKS host. The allowlist in [`vsock-proxy.yaml`](vsock-proxy.yaml) must contain the host.

   ```bash
   vsock-proxy 8443 www.googleapis.com 443 --config tee-updater/vsock-proxy.yaml &
   ```

3. Start the enclave. Do not use `--debug-mode`: a debug enclave has zero PCRs, and `verify-attestation` rejects it.

   ```bash
   nitro-cli run-enclave --eif-path tee-updater.eif --cpu-count 2 --memory 512
   ```

   Write down the `EnclaveCID` as `CID`.

4. Enroll the attestor. On the trusted computer, make a new random challenge:

   ```bash
   CHALLENGE=0x$(openssl rand -hex 32)
   ```

   On the parent instance, ask the enclave for an attestation with this challenge:

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

   `verify-attestation` verifies the AWS signature and the certificate chain of the document. Then it compares the PCRs and the challenge, and it shows the attestor address. The new random challenge makes sure that the document is new. Then the owner sets the attestor:

   ```bash
   cast send "$REGISTRY" "setAttestor(address)" "$ATTESTOR" --rpc-url "$RPC_URL" --private-key "$OWNER_KEY"
   ```

5. Send a key set immediately after `setAttestor`, and then at least one time each day. The registry rejects key sets that are older than `MAX_KEY_SET_AGE` (one day). The time of each key set must be after the block time of `setAttestor` and after the current key set.

   ```bash
   python3 tee-updater/scripts/request.py --cid "$CID" \
     "{\"operation\":\"sign\",\"jwksUri\":\"https://www.googleapis.com/oauth2/v3/certs\",\"chainId\":$CHAIN_ID,\"registry\":\"$REGISTRY\"}" > snapshot.json
   REGISTRY="$REGISTRY" SNAPSHOT="$(cat snapshot.json)" forge script script/UpdateKeys.s.sol \
     --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
   ```

When the enclave starts again, it has a new key. Do step 4 and step 5 again. `setAttestor` removes the keys of the old attestor.

## Code

| File | Function |
| --- | --- |
| [`src/lib.rs`](src/lib.rs) | JWKS checks, the EIP-712 digest of a key set, signatures, and attestation checks |
| [`src/http.rs`](src/http.rs) | HTTP/1.0 GET over a stream that the caller opens: TCP in local mode, vsock in the enclave |
| [`src/main.rs`](src/main.rs) | The `sign` command (local mode) and the `serve` command (enclave) |
| [`src/nitro.rs`](src/nitro.rs) | Attestation documents, random bytes, and time from the Nitro Secure Module |
| [`src/bin/verify-attestation.rs`](src/bin/verify-attestation.rs) | Verifies an attestation document outside the enclave |
| [`scripts/request.py`](scripts/request.py) | Sends one request to the enclave from the parent instance |

```bash
cd tee-updater
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```
