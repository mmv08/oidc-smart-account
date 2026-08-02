# AWS Nitro Google-key updater

Status: experimental reference implementation. The host-tested parser, signing code, contract interoperability, enrollment-policy checks, Docker image, and KMS helper build are implemented and the Docker image has been built successfully in the development environment. A real Enclave Image File (EIF), genuine Nitro attestation, AWS KMS policy, parent-instance run, and live-chain relay have not yet been exercised.

An **EIF** is the bootable AWS Nitro Enclave image. Building it produces Platform Configuration Register (PCR) measurements: hashes that identify the image and related launch policy.

## Security boundary

The enclave handles only Google's public JWT-signing keys. It never receives user JWTs, Google subjects, identity salts, recovery requests, account signers, or wallet transactions.

```text
www.googleapis.com:443
        ^ raw TCP through fixed parent proxy
        | TLS owned by measured enclave
        v
strict JWKS parser -> canonical complete key set -> EIP-712 signature
                                                   |
                                                   v
                                      permissionless on-chain relay
```

**EIP-712** is Ethereum's structured-message signing format. The signed snapshot binds the complete ordered key set, observation time, updater epoch, nonce, chain, and exact updater contract.

The design minimizes trust; it does not eliminate trust. It trusts Google, Web Public Key Infrastructure (Web PKI), AWS Nitro hardware and attestation certificates, AWS KMS, the measured image, the build and enrollment processes, governance, and operational availability. Nitro attestation proves that an accepted measured program ran. It does not itself prove that a fresh Google request happened. TLS authenticates Google; snapshot timestamps, nonces, monotonic observations, and the on-chain freshness lease constrain replay and staleness.

## Components

- `tee-google-key-updater`: local CLI and production enclave request server.
- `vsock-loopback`: maps enclave-local `www.googleapis.com:443` connections to the parent Google byte proxy without moving TLS out of the enclave.
- `verify-enrollment`: off-enclave native-attestation verifier.
- `scripts/build-kmstool.sh`: builds AWS `kmstool_enclave_cli` from pinned SDK commit `cd61b6187c8b20867ba4368d1ae62c5790c0269a`.
- `scripts/run-parent-proxies.sh`: starts only the fixed KMS and Google byte proxies.
- `scripts/parent-client.py`: injects temporary EC2 role credentials and sends one bounded request over `AF_VSOCK`.

`AF_VSOCK` is the host/enclave socket transport supplied by Nitro. It does not provide ordinary Internet access; the parent proxies raw bytes to fixed remote destinations.

## Fetch policy

The measured client requests exactly:

```text
https://www.googleapis.com/oauth2/v3/certs
```

It uses HTTPS only, authenticates `www.googleapis.com` against its measured CA bundle, rejects redirects, requires exactly HTTP `200 OK`, bounds the body to 64 KiB, rejects duplicate security fields, and requires a nonempty set of at most eight keys. Every accepted key must have:

- a unique nonempty `kid`;
- `kty = RSA`;
- `alg = RS256`;
- `use = sig`;
- canonical unpadded Base64URL;
- exponent `AQAB`, meaning `65537`;
- exactly 256 modulus bytes;
- the high bit set and low bit odd.

Records are sorted strictly by `keccak256(kid)` before hashing and signing. Unknown JSON fields are ignored, while duplicate security-sensitive fields fail closed.

## Build and host verification

```bash
cd tee-updater
cargo fmt --all --check
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings

./scripts/build-kmstool.sh
docker build --pull=false -t tee-google-key-updater:local .
```

The Dockerfile pins the Linux/AMD64 Rust and Debian base-image manifests. `Cargo.lock` and the AWS SDK commit are pinned. `vendor/SHA256SUMS` fixes the exact expected `kmstool_enclave_cli` and `libnsm.so` bytes; both the build helper and Docker build fail if those security-critical artifacts differ. These controls improve repeatability but do not yet prove byte-for-byte reproducible Docker or EIF output, and changing either expected artifact hash requires a fresh source/build review.

On a Nitro-enabled EC2 parent with `nitro-cli`:

```bash
nitro-cli build-enclave \
  --docker-uri tee-google-key-updater:local \
  --output-file tee-google-key-updater.eif

nitro-cli describe-eif --eif-path tee-google-key-updater.eif
```

Publish the source commit, Dockerfile, lockfile, base-image digests, AWS SDK commit, EIF hash, PCR0/PCR1/PCR2 values, build logs, CA bundle hash, and verifier version. Rebuild independently before enrollment. Do not use debug-mode enclaves: debug PCRs are zero and must be rejected.

## KMS policy

Create one KMS data key per updater deployment. Never reuse one enclave application key across unrelated chains or updater contracts. Store only KMS ciphertext outside the enclave.

The EC2 role supplies temporary credentials over vsock. The enclave performs KMS TLS and calls KMS with a Nitro recipient attestation. The KMS key policy must require the approved measurements, for example:

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::ACCOUNT:role/TEEGoogleUpdaterParent" },
  "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
  "Resource": "*",
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:ImageSha384": "APPROVED_PCR0_SHA384"
    }
  }
}
```

Use the exact AWS condition appropriate to the measured policy (`ImageSha384` and/or named PCR conditions), include PCR3 when binding to an IAM role is required, and test both positive and negative cases. A request from outside an accepted enclave must fail. A request from a modified or debug enclave must fail. Separate provisioning and runtime permissions if `GenerateDataKey` is not needed after initial provisioning.

KMS measurement policies need an explicit upgrade plan. Adding a new PCR before removing the old one gives an overlap window. Removing the old PCR revokes future decrypts by that image but does not erase plaintext already held by a running enclave.

## Production enclave server

The image starts:

```text
tee-google-key-updater serve --port 5000
```

The server accepts only parent CID `3`, processes one bounded request at a time, and rejects unknown fields and development-key options. Supported operations are:

- `provision`: generate a KMS-protected secp256k1 application key;
- `enroll`: produce a native Nitro attestation document binding that key to deployment context;
- `fetchSign`: fetch Google, canonicalize the complete set, and sign one snapshot.

The parent starts fixed proxies:

```bash
export AWS_REGION=eu-central-1
sudo -E ./scripts/run-parent-proxies.sh
```

It starts only:

```text
vsock 8000 -> kms.${AWS_REGION}.amazonaws.com:443
vsock 8443 -> www.googleapis.com:443
```

Do not replace these with a general destination selected by the enclave request or caller.

Start the enclave with the CID, memory, and CPU allocation approved for the deployment. Supply the CID printed by `nitro-cli run-enclave` to `parent-client.py`. Requests should be JSON files with non-secret context; AWS credentials are injected from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and `AWS_REGION` at send time.

Provisioning request:

```json
{
  "operation": "provision",
  "kmsKeyId": "arn:aws:kms:eu-central-1:ACCOUNT:key/KEY_ID"
}
```

The reviewed policy manifest is `policy/google-jwks-policy-v1.json`. It explicitly binds the endpoint, exact HTTP status, redirect and timeout behavior, body/key bounds, duplicate rejection, canonical Base64URL, RSA shape, snapshot ordering, and attestation requirements. Its exact bytes are embedded in the measured binary, which derives `policyHash` itself rather than accepting a parent-supplied value. The current manifest hashes to `0x94df64d6933fd4990ee72349d2d2080002dfc89f543494e543d2a119dcf4d537`. Recompute rather than trusting copied documentation:

```bash
sha256sum policy/google-jwks-policy-v1.json
```

Enrollment request:

```json
{
  "operation": "enroll",
  "chainId": "1",
  "updater": "0xUPDATER",
  "attestorEpoch": 1,
  "challenge": "0xFRESH_32_BYTE_RANDOM_CHALLENGE",
  "kmsCiphertextFile": "/secure/path/application-key.ciphertext"
}
```

Snapshot request:

```json
{
  "operation": "fetchSign",
  "chainId": "1",
  "updater": "0xUPDATER",
  "attestorEpoch": 1,
  "nonce": "0",
  "kmsCiphertextFile": "/secure/path/application-key.ciphertext"
}
```

Send a request:

```bash
./scripts/parent-client.py --cid ENCLAVE_CID request.json
```

The returned snapshot may be relayed by anyone. The relay must read `attestorEpoch()` and `updateNonce()` immediately before asking the enclave to sign, submit the exact returned fields, wait for finality, and handle a competing successful relay as success rather than signing an arbitrary replacement snapshot.

## Enrollment ceremony

The official deployment starts with `attestor = address(0)` and `attestorEpoch = 0`. Key consumption therefore fails closed. The deployer cannot silently install the first attestor.

Use a threshold governance wallet, such as a reviewed multisignature Safe, as `TEE_GOVERNANCE`. The guardian must be a different key or threshold and has stop/cancel powers only.

For initial enrollment, target epoch `1`; for rotation, target `attestorEpoch() + 1`.

1. Freeze the source commit and build inputs.
2. Have at least two independent operators reproduce the image and compare the expected PCR policy.
3. Deploy the contracts and verify that:
   - `GoogleJWTVerifier.keyRegistry() == address(TEEGoogleKeyUpdater)`;
   - `TEEGoogleKeyUpdater.attestor() == address(0)` initially.
4. Generate a fresh unpredictable 32-byte challenge after the enclave is running. Never reuse it.
5. Provision the encrypted application key in the accepted enclave.
6. Request enrollment evidence binding the challenge, application public key, chain ID, updater address, target epoch, and published policy hash.
7. Verify the document independently. The verifier checks the AWS root and certificate chain, certificate validity, document signature, document timestamp, PCR allowlist, non-debug PCRs, exact challenge, public-key encoding, derived Ethereum attestor address, and typed enrollment struct-hash binding.

Example:

```bash
cargo run --release --features verifier --bin verify-enrollment -- \
  --document enrollment.json \
  --challenge 0x... \
  --chain-id 1 \
  --updater 0x... \
  --attestor-epoch 1 \
  --policy-hash 0x... \
  --pcr 0=0x... \
  --pcr 1=0x... \
  --pcr 2=0x... \
  --pcr 3=0x... \
  --max-age-seconds 300 \
  > verified-enrollment.json
```

8. Publish the raw attestation, challenge, verifier command/output, measurement manifest, application public key, derived address, KMS policy, and all reviewer approvals.
9. Independent reviewers must compare the same attestor address and deployment context.
10. Threshold governance calls `scheduleAttestor(verifiedAttestor)`.
11. Monitor the full delay. The guardian cancels if evidence, measurements, build provenance, or KMS policy are disputed.
12. After the delay, anyone calls `finalizeAttestorRotation()`.
13. Relay a fresh snapshot and verify an end-to-end Google JWT through `GoogleJWTVerifier` before enabling account creation or recovery.

The enrollment verifier is part of the trusted ceremony. It uses `nitro_attest` for AWS-rooted COSE and X.509 verification and then enforces repository-specific policy. Review and pin that dependency's source before production. **COSE** is the binary signature envelope used by Nitro; **X.509** is the certificate format anchoring it to AWS.

## Rotation, pause, and recovery

### Routine image or attestor rotation

- Build and publish the replacement image and PCR policy.
- Extend KMS policy only after review.
- Generate a new application key unless a reviewed continuity requirement explicitly justifies retaining the old one.
- Run the complete enrollment ceremony for the next epoch.
- Schedule the verified address through threshold governance.
- The guardian can cancel during the delay.
- Finalization increments the epoch; signatures from the previous epoch no longer authorize updates.
- After a successful snapshot from the new epoch, remove old PCR decrypt permissions.

### Emergency pause

Governance or guardian calls `pause()`. Pause makes `getKey` return no key, so verifier consumption fails closed. Signed snapshot submission intentionally remains available while paused so a post-scheduling heartbeat can satisfy delayed unpause. Pause does not block routine smart-account execution.

Investigate Google, TLS roots, AWS advisories, PCR/build compromise, KMS/IAM compromise, key exposure, and anomalous snapshots. Governance schedules unpause only after remediation. Final unpause requires both the immutable delay and a fresh signed snapshot observed at or after the unpause-ready time. The guardian cannot unpause or manufacture keys.

### Lost key or KMS outage

- Pause if integrity is uncertain.
- If only availability is affected, installed account signers continue working; OIDC creation and recovery stop.
- Build/provision a replacement and enroll it through the delayed ceremony.
- Do not deploy or wire an owner-managed registry as an alternative key path.

### Clone and rollback

Anyone with the ciphertext, suitable role credentials, and an accepted measured enclave may be able to run another copy of the same signer. That copy still executes the same measured fetch policy, so this is primarily a race and availability risk, not permission to sign arbitrary keys. Use least-privilege IAM, protect ciphertext, consider PCR3 role binding, monitor nonce races, and run one active publisher. Old snapshots fail through nonce, epoch, observation-age, and monotonic-time checks. Old signer ciphertext fails after attestor rotation.

## Monitoring

Alert on:

- `KeySetApplied`, attestor rotation, pause, and unpause events;
- nonce gaps or repeated failed relays;
- `lastFetchedAt` approaching `maxRegistryStaleness`;
- unexpected Google key count or key-ID churn;
- changed key material under an existing `kid`;
- KMS decrypt failures or calls from unexpected role/session context;
- Nitro, AWS attestation-root, KMS, Web PKI, Rust dependency, and Google endpoint advisories.

A malicious parent can always stop, delay, replay, or selectively relay bytes. No part of this design guarantees liveness.

## Remaining production gates

Before real funds:

- reproduce Docker and EIF builds on independent systems;
- run on a real Nitro-capable EC2 instance;
- verify genuine attestation with independently reviewed tooling;
- test positive and negative KMS measurement policies;
- test parent proxies and SNI/hostname behavior inside the EIF;
- implement and test a production transaction relayer with reorg handling;
- run full contract, Rust, and TypeScript verification, static analysis, and independent audits;
- approve values for key count, observation age, registry staleness, rotation delay, and clock skew;
- document AWS account break-glass, KMS deletion protection, role rotation, backup, and incident ownership.
