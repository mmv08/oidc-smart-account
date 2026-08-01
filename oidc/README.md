# Google/Apple OIDC claim model

This small TypeScript package mirrors the Solidity identity and action schemas. It deliberately contains no server, attestor, oracle, custody, or on-chain transport mechanism.

## What it does

- derives canonical Google and Apple provider identifiers;
- derives audience-specific provider policy identifiers;
- derives a salted commitment to the stable OIDC `sub` (subject) claim;
- normalizes already-authenticated Google or Apple claims into `IOIDCClaimVerifier.VerifiedOIDCClaim` fields;
- computes the exact EIP-712 account-creation and recovery digests used as OIDC `nonce` values;
- tests Solidity/TypeScript golden vectors so the two implementations cannot silently diverge.

## What it does not do

`normalizeGoogleOrAppleClaims` does **not** verify a JSON Web Token (JWT) signature. A JWT is the signed token format commonly used for OIDC ID tokens. A concrete `IOIDCClaimVerifier` adapter must authenticate the token or proof before using these helpers.

For Google and Apple, that adapter must at minimum:

1. accept only the configured signing algorithm and verification keys;
2. validate the provider issuer;
3. validate the exact OAuth client ID in `aud` (audience);
4. validate `azp` (authorized party) when required, especially for multi-audience Google tokens;
5. validate `exp`, `iat`, and the exact action-bound `nonce`;
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

## Identity derivation

```text
providerId = keccak256(canonical issuer)
providerPolicyId = keccak256(typed providerId + keccak256(client ID))
identityCommitment = keccak256(typed policyId + keccak256(sub) + identity salt)
```

Canonical issuers:

- Google: `https://accounts.google.com` (`accounts.google.com` is accepted and normalized)
- Apple: `https://appleid.apple.com`

The client ID is part of the policy because OIDC subjects and acceptable token audiences are defined in a provider/client context. The salt should be independently generated for the account. Raw tokens, subjects, email addresses, and salts do not need to be stored by the account contract.

## Action-bound nonce

The exact EIP-712 action digest is sent as the OIDC authorization request's lowercase `0x`-prefixed, 32-byte `nonce` string. The provider returns that same string in the authenticated ID token. This makes a normal login token insufficient to authorize a different account action.
