# Google/Apple OIDC claim model

This small TypeScript package mirrors the Solidity identity and action schemas and encodes proofs for the included direct Google JWT verifier. It contains no attestor, oracle, or key custody.

## What it does

- derives canonical Google and Apple provider identifiers;
- derives audience-specific provider policy identifiers;
- derives a salted commitment to the stable OIDC `sub` (subject) claim;
- normalizes already-authenticated Google or Apple claims into `IOIDCClaimVerifier.VerifiedOIDCClaim` fields;
- computes the exact EIP-712 account-creation and recovery digests used as OIDC `nonce` values;
- ABI-encodes a compact Google ID token and identity salt for `GoogleJWTVerifier`;
- tests Solidity/TypeScript golden vectors so the two implementations cannot silently diverge.

## What it does not do

`normalizeGoogleOrAppleClaims` does **not** verify a JSON Web Token (JWT) signature. A JWT is the signed token format commonly used for OIDC ID tokens. The included Solidity `GoogleJWTVerifier` performs direct on-chain Google RS256 verification; other providers still require a concrete `IOIDCClaimVerifier` adapter.

For Google and Apple, that adapter must at minimum:

1. accept only the configured signing algorithm and verification keys;
2. validate the provider issuer;
3. validate the exact OAuth client ID in `aud` (audience);
4. validate `azp` (authorized party) when required, especially for multi-audience Google tokens;
5. validate `exp`, `iat`, optional `nbf` (not before), and the exact action-bound `nonce`;
6. use `sub`, never email, as the stable provider identity;
7. reject malformed, duplicated, oversized, or ambiguous claims;
8. handle provider key rotation and revocation according to its own trust model.

The Solidity controller independently checks the returned policy, identity commitment, nonce, issue time, expiry, and maximum claim age. It does not trust the adapter to decide which account action is authorized.

## Install and verify

```bash
npm ci
npm test
npm run typecheck
npm run build
```

`test:e2e` starts an in-process OpenID Certified `oidc-provider`, completes an Authorization Code + PKCE flow, exchanges the code, verifies an RS256 ID token through the provider's discovery/JWKS endpoints, and confirms that the signed nonce equals the exact recovery digest. Negative paths reject a wrong PKCE verifier and a mismatched action nonce. Unit tests also reject malicious Google discovery endpoints and oversized metadata. The suite uses only ephemeral test keys and an in-memory test adapter.

For a live Google Cloud web client, see [`examples/google/README.md`](examples/google/README.md). The runnable server shares its Google discovery, PKCE, token verification, and normalization code with the simulated-provider test.

## Identity derivation

```text
providerId = keccak256(canonical issuer)
providerPolicyId = keccak256(
  typed providerId + keccak256(audience/client ID) + authorizedPartyHash
)
identityCommitment = keccak256(typed policyId + keccak256(sub) + identity salt)
```

`authorizedPartyHash` is zero for Apple and ordinary Google policies. Google hybrid apps set it to `keccak256(expected azp client ID)`, allowing a server audience and a distinct Android or iOS authorized party without weakening the immutable policy.

The package exports its public API from its root after `npm run build`:

```ts
import {
  directGoogleJWTProof,
  normalizeGoogleOrAppleClaims,
  recoveryDigest,
} from 'oidc-onchain-identity-model';
```

Canonical issuers:

- Google: `https://accounts.google.com` (`accounts.google.com` is accepted and normalized)
- Apple: `https://appleid.apple.com`

The client ID is part of the policy because OIDC subjects and acceptable token audiences are defined in a provider/client context. The salt should be independently generated for the account. The account contract does not store raw tokens, subjects, email addresses, or salts, but a direct-JWT transaction exposes the token, subject, and salt in public calldata.

## Action-bound nonce

The exact EIP-712 action digest is sent as the OIDC authorization request's lowercase `0x`-prefixed, 32-byte `nonce` string. The provider returns that same string in the authenticated ID token. This makes a normal login token insufficient to authorize a different account action.
