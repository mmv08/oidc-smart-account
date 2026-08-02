# Direct Google RS256 JWT verifier

Status: implemented reference adapter; unaudited and not suitable for real funds.

## 1. Trust model

`GoogleJWTVerifier` authenticates Google ID tokens directly on-chain. It reads keys through `TEEGoogleKeyUpdater`, which combines signed-snapshot updates, key storage, pause, and freshness gating behind one `getKey` interface.

A measured AWS Nitro Enclave fetches Google's exact JSON Web Key Set (JWKS), terminates and authenticates TLS inside the enclave, validates the complete Google RS256 key set, canonicalizes it, and signs a narrow EIP-712 snapshot with an enclave-controlled application key. Anyone may relay the snapshot. **JWKS** is the document containing Google's current token-signing public keys; **EIP-712** is Ethereum's structured-message signing format.

The updater is still an explicit recovery trust root. A compromised accepted image or application key can publish an attacker modulus and enable forged Google claims. The recovery delay and current-signer cancellation remain useful defenses, but do not make compromise harmless.

The trust assumptions are Google, Web Public Key Infrastructure, AWS Nitro hardware and attestation roots, AWS KMS, the measured image and build, the enrollment verifier and ceremony, threshold governance, the guardian, and operational availability. Nitro attestation proves that accepted measured code ran. It does not prove a fresh Google fetch. TLS authenticates the endpoint, while nonce, epoch, time, monotonicity, and freshness-lease rules constrain replay and staleness.

Ethereum cannot fetch HTTPS itself. The enclave pins this endpoint policy:

```text
https://www.googleapis.com/oauth2/v3/certs
```

The parent instance may proxy raw TCP bytes but must not terminate TLS or provide decoded JSON. It can censor, delay, replay, or stop traffic; the design makes no liveness guarantee. See the [TEE updater operations guide](../tee-updater/README.md).

## 2. Contracts

```text
OIDCAccountFactory / OIDCRecoveryController
                    |
                    v
          IOIDCClaimVerifier
                    |
                    v
          GoogleJWTVerifier
                    |
                    v
         TEEGoogleKeyUpdater
          |              |
          | gated getKey | internal key lifecycle
          v              v
      verifier     kid hash -> RSA modulus + issue interval
```

- `TEEGoogleKeyUpdater` accepts only 256-byte, mathematically 2048-bit, odd, big-endian modulus encodings. `GoogleJWTVerifier` fixes exponent `65537` (`0x010001`).
- `GoogleJWTVerifier.keyRegistry()` must be the updater, which is the only key store in the TEE deployment.
- The updater accepts only a nonempty, bounded, strictly sorted complete snapshot signed by the current attestor for the exact chain, updater, epoch, nonce, and observation time.
- Reads fail closed before the first accepted snapshot, while paused, or after `maxRegistryStaleness`.
- Keys are indexed by `keccak256(bytes(kid))`; the raw key identifier is not stored.
- `validAfter <= token.iat` must hold.
- `validUntil == 0` means no configured end. Otherwise `token.iat < validUntil` must hold.
- A key omitted from a newer complete snapshot is retired at that observation time. A retired key that reappears starts a new interval rather than reopening the old interval.

Key intervals describe when the key may have issued a token. They do not replace the token's own `iat`, `nbf`, and `exp` checks or the factory/controller's `maxClaimAge`. The updater currently retains one interval per `kidHash`; reappearance overwrites the old interval, so historical verification across multiple disjoint appearances is not preserved.

## 3. Proof encoding

The verifier accepts:

```solidity
abi.encode(bytes(compactGoogleIdToken), bytes32(identitySalt))
```

The TypeScript helper produces exactly this encoding:

```ts
import { directGoogleJWTProof } from 'oidc-onchain-identity-model';

const oidcProof = directGoogleJWTProof(idToken, identitySalt);
```

The compact token must retain the exact three signed Base64URL segments:

```text
base64url(header).base64url(payload).base64url(signature)
```

Do not decode and reconstruct the header or payload off-chain. The RSA signature covers their original encoded bytes.

## 4. On-chain validation

The verifier:

1. bounds the entire proof and token length;
2. requires exactly three nonempty compact-JWT segments;
3. strictly decodes unpadded canonical Base64URL;
4. parses the protected header and requires exactly one `alg` and one `kid`;
5. pins `alg` to `RS256`;
6. loads the 256-byte RSA modulus encoding selected by `kid`;
7. verifies PKCS#1 v1.5 SHA-256 over the exact `header.payload` bytes with OpenZeppelin `RSA.sol` and Ethereum's modular-exponentiation precompile;
8. strictly parses the signed payload;
9. rejects duplicate protected claims, escaped protected member names, malformed JSON, invalid UTF-8 and surrogate escapes, noninteger timestamps, excessive nesting, unsupported audience forms, and trailing content;
10. validates Google's issuer, exact configured audience, optional/exact `azp`, nonempty bounded subject, bytes32 nonce, `iat`, optional `nbf`, `exp`, and key issue interval;
11. derives `providerPolicyId` from the immutable verifier configuration;
12. derives `identityCommitment` from the signed `sub`, that policy, and the supplied identity salt;
13. returns the normalized `VerifiedOIDCClaim`.

The factory or recovery controller then independently checks that the returned nonce equals the exact EIP-712 management-action digest and that claim age is within its immutable maximum.

The parser intentionally accepts a strict subset of JSON for security-sensitive names and string values: they must be ordinary unescaped strings. Google's normal ID tokens use this representation. Unsupported representations fail closed rather than being interpreted differently by competing parsers.

## 5. Audience and authorized party

For an ordinary web client, deploy with:

```text
GOOGLE_CLIENT_ID=<web-client-id>
GOOGLE_AUTHORIZED_PARTY=
```

The signed `aud` must contain that client ID. If `aud` is a single value, `azp` may be absent; if supplied, it must equal that client ID. Multiple audiences require a matching `azp`.

For a hybrid application:

```text
GOOGLE_CLIENT_ID=<server/web-client-id>
GOOGLE_AUTHORIZED_PARTY=<android-or-ios-client-id>
```

The server client ID must appear in `aud`, and `azp` must exactly equal the configured mobile client ID. Both become immutable parts of `providerPolicyId`.

## 6. Deploy and enroll

```bash
cp .env.example .env
# Set DEPLOYER_PRIVATE_KEY, TEE_GOVERNANCE, TEE_GUARDIAN,
# timing policy, GOOGLE_CLIENT_ID, and optional GOOGLE_AUTHORIZED_PARTY.

set -a
source .env
set +a

forge script script/DeployGoogleJWT.s.sol:DeployGoogleJWT \
  --rpc-url "$RPC_URL" --broadcast
```

The script deploys:

1. `TEEGoogleKeyUpdater`, owned by threshold governance and initially uninitialized;
2. `GoogleJWTVerifier`, immutably configured to read that updater.

Verify those relationships on-chain before proceeding. The updater intentionally starts with `attestor = address(0)` and epoch `0`; the deployer cannot supply an initial attestor through the official script.

Build the EIF, publish and independently review its measurements, provision a KMS-protected application key inside an accepted enclave, obtain a fresh native Nitro attestation for epoch `1`, and independently verify its AWS chain, timestamp, PCR policy, challenge, application key, chain, updater, epoch, and policy hash. Threshold governance then calls `scheduleAttestor(verifiedAddress)`, waits the immutable delay, and anyone finalizes. Follow the complete [enrollment ceremony](../tee-updater/README.md#enrollment-ceremony).

After enrollment, relay a fresh signed complete snapshot. Verify `lastFetchedAt`, `updateNonce`, and every emitted key-set event. Then use the resulting `GoogleJWTVerifier` as `OIDC_CLAIM_VERIFIER` in `script/Deploy.s.sol`.

Do not deploy a separate owner-managed `GoogleKeyRegistry` for the TEE path or construct another verifier against one. Doing so recreates arbitrary key-insertion and freshness-bypass paths that the single-store topology removes.

## 7. Privacy and cost

A direct proof is public transaction calldata. It reveals the full Google ID token, including stable `sub`, audience, timestamps, nonce, any optional claims Google included, and the identity salt. The contracts do not store or emit the token, but calldata remains permanently observable.

Use only the `openid` scope for this identity-only flow. Do not request email or profile scopes unless their public disclosure is explicitly acceptable.

RSA and strict JSON/Base64URL processing are relatively expensive. The current public-fixture unit test uses roughly 1.6 million gas for successful verification under this repository's Foundry configuration. Measure the complete creation and recovery transaction on every target chain before deployment.

## 8. Residual risks

- Enrolled image, application-key, KMS/IAM, build, attestation-verifier, or governance compromise can forge Google identity evidence.
- Missed Google rotation, stale snapshots, pause, KMS/AWS outage, or malicious parent censorship stop OIDC creation and recovery.
- Nitro attestation does not prove a fresh Google fetch; replay controls bound staleness but cannot supply liveness.
- Native attestation is verified off-chain, so the threshold enrollment ceremony must not collapse to one trusted operator.
- The one-interval store loses the old interval if the same `kidHash` disappears and later reappears.
- Google account or provider compromise can still produce a genuinely signed recovery token.
- `prompt=select_account` does not prove recent password, passkey, or multifactor authentication.
- Parser, RSA integration, and target-chain precompile behavior require independent audit and chain-specific testing.
- An immutable verifier or registry bug can permanently remove recovery availability for accounts wired to it.
- The direct adapter provides no identity privacy.

Routine account execution remains independent of Google, the updater, and the verifier.