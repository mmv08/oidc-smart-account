# Direct Google RS256 JWT verifier

Status: implemented reference adapter; unaudited and not suitable for real funds.

## 1. Trust model

`GoogleJWTVerifier` authenticates Google ID tokens directly on-chain. It depends on `GoogleKeyRegistry`, whose owner is one project-controlled updater.

That updater is an explicit recovery trust root. It can replace a Google RSA modulus with an attacker key and then create tokens that the verifier accepts. The recovery delay and current-signer cancellation remain useful defenses, but they do not make updater compromise harmless.

Ethereum cannot fetch Google's HTTPS JSON Web Key Set (JWKS). A JWKS is the document containing Google's current token-signing public keys. The updater must monitor Google's pinned endpoint and publish rotations before users need the new keys:

```text
https://www.googleapis.com/oauth2/v3/certs
```

This simple updater model is deliberate. Threshold governance, automated fetch proofs, and timelocks are outside this reference adapter.

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
          GoogleKeyRegistry
                    |
                    v
     kid hash -> RSA exponent/modulus + issue interval
```

- `GoogleKeyRegistry` accepts only 2048-bit moduli and exponent `65537` (`0x010001`).
- Keys are indexed by `keccak256(bytes(kid))`; the raw key identifier is not stored.
- `validAfter <= token.iat` must hold.
- `validUntil == 0` means no configured end. Otherwise `token.iat < validUntil` must hold.
- `removeKey` disables a key immediately. During normal rotation, retain an old key long enough for already-issued, still-fresh tokens, then remove it.

Key intervals describe when the key may have issued a token. They do not replace the token's own `iat`, `nbf`, and `exp` checks or the factory/controller's `maxClaimAge`.

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
6. loads the 2048-bit RSA key selected by `kid`;
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

## 6. Deploy

```bash
cp .env.example .env
# Set DEPLOYER_PRIVATE_KEY, GOOGLE_KEY_UPDATER, GOOGLE_CLIENT_ID,
# and optionally GOOGLE_AUTHORIZED_PARTY.

set -a
source .env
set +a

forge script script/DeployGoogleJWT.s.sol:DeployGoogleJWT \
  --rpc-url "$RPC_URL" --broadcast
```

Populate current Google keys from the pinned JWKS endpoint. Each RSA JWK provides:

- `kid`: hash its UTF-8 bytes with Keccak-256;
- `e`: Base64URL-decode to `0x010001`;
- `n`: Base64URL-decode to the 256-byte modulus.

Then submit from the configured updater:

```solidity
GoogleKeyRegistry.setKey(
    kidHash,
    exponent,
    modulus,
    validAfter,
    validUntil
)
```

Use a real observation timestamp for `validAfter`; do not backdate keys casually. Set `validUntil` when Google retires a key, allowing only the reviewed overlap needed for tokens that remain within `maxClaimAge`. Use `removeKey` for immediate emergency disablement.

After populating keys, deploy the core with the resulting verifier address as `OIDC_CLAIM_VERIFIER` using `script/Deploy.s.sol`.

## 7. Privacy and cost

A direct proof is public transaction calldata. It reveals the full Google ID token, including stable `sub`, audience, timestamps, nonce, any optional claims Google included, and the identity salt. The contracts do not store or emit the token, but calldata remains permanently observable.

Use only the `openid` scope for this identity-only flow. Do not request email or profile scopes unless their public disclosure is explicitly acceptable.

RSA and strict JSON/Base64URL processing are relatively expensive. The current public-fixture unit test uses roughly 1.6 million gas for successful verification under this repository's Foundry configuration. Measure the complete creation and recovery transaction on every target chain before deployment.

## 8. Residual risks

- Updater compromise can forge Google identity evidence.
- Missed Google key rotation stops creation and recovery for newly signed tokens.
- Immediate old-key removal can reject otherwise fresh tokens already in flight.
- Google account or provider compromise can still produce a genuinely signed recovery token.
- `prompt=select_account` does not prove recent password, passkey, or multifactor authentication.
- Parser, RSA integration, and target-chain precompile behavior require independent audit and chain-specific testing.
- An immutable verifier or registry bug can permanently remove recovery availability for accounts wired to it.
- The direct adapter provides no identity privacy.

Routine account execution remains independent of Google, the updater, and the verifier.