# Architecture decision: OIDC-assisted smart-account bootstrap and recovery

Status: implemented reference design; not audited for production deployment.

## 1. Security objective

A Google or Apple login is used only to authorize one narrowly defined account-management intent:

- create a particular account with a particular initial signer;
- add one particular signer; or
- replace one particular signer.

It is never accepted by the account's ordinary transaction-validation path. Ordinary account operations use independent cryptographic signers represented in the ERC-7913 format. ERC-7913 is an Ethereum standard that represents a signer as `verifier address || public key`, allowing Ethereum ECDSA addresses, ERC-1271 contract signers, P-256/passkey keys, and other verifier/key pairs to use one interface.

## 2. Considered architectures

### A. Verify raw Google/Apple JSON Web Tokens on-chain

A JSON Web Token (JWT) is a signed text token containing claims such as issuer, audience, subject, issue time, and expiry. The contract could verify the provider's RSA signature using public keys copied on-chain.

Rejected for v1 because:

- the complete token and its claims become public calldata, exposing a stable provider subject and often email/profile data;
- safe JSON parsing and strict JWT validation add substantial contract complexity;
- provider-key rotation can cause brittle on-chain availability;
- a valid login still does not show that the user understood the blockchain action.

### B. One off-chain verifier signs an on-chain authorization

This avoids publishing the JWT, but one compromised verifier can manufacture recoveries. That is too much custody-like power for a production design.

### C. Threshold off-chain OIDC verifiers plus constrained on-chain recovery — selected

Independent verifier services validate the same OIDC login and exact action request. A threshold, intended to be 2-of-3, signs a short-lived EIP-712 attestation. EIP-712 is Ethereum's typed-data signing format; it binds signatures to named fields, the chain, and a verifying contract.

The chain receives only:

- an opaque, per-account identity commitment;
- exact account-management fields;
- a provider-policy identifier and provider-key thumbprint;
- verifier signatures.

The JWT, provider subject, authorization code, email, and profile never go on-chain.

This design does not make Google, Apple, or the verifier set trustless. It makes their authority narrow, visible, delayed for recovery, and independent from normal transaction signing.

### D. Zero-knowledge proof of a provider token

A zero-knowledge proof can prove selected JWT claims without exposing the token. It can reduce trust in off-chain attestors, as systems such as Sui zkLogin demonstrate. It was not selected because the requested first version does not require it and a correct circuit, prover, key-rotation mechanism, and audit would dominate the implementation.

## 3. Components and data flow

### 3.1 IndependentKeyAccount

The account uses OpenZeppelin's ERC-7913 multisigner support with two small execution paths. A 20-byte address signer can submit `execute` directly. An address-less signer, such as a passkey, signs an EIP-712 `Execution` request that any untrusted relayer can submit through `executeSigned`.

Properties:

- ordinary operations validate only installed cryptographic signers;
- signed executions bind target, value, calldata hash, execution nonce, deadline, chain, and exact account deployment;
- the execution nonce is consumed atomically with the external call, preventing successful replay while allowing a reverted call to be retried until its deadline;
- signer threshold is one in this deliberately small design;
- address signers can manage signers directly, while address-less signers use an authorized signed self-call;
- relayers are optional, untrusted transports and receive no account authority;
- OIDC contracts are not called during ordinary validation or execution;
- the recovery manager can only add or replace a signer;
- the account can permanently disable OIDC recovery;
- contracts are not proxies and contain no upgrade hook.

### 3.2 IdentityAccountFactory

The factory uses CREATE2, an Ethereum instruction for deterministic contract addresses. The creation attestation binds:

- the predicted account address;
- chain ID;
- factory address;
- random per-account identity commitment;
- exact initial signer hash;
- one-time intent nonce.

The new signer must also prove possession by signing the exact intent digest. A transaction observer may submit the same deployment first, but cannot substitute a signer or account. The resulting account remains controlled by the intended key, so front-running is harmless apart from relayer/payment policy outside this repository.

### 3.3 IdentityIntentVerifier

The verifier contract checks a threshold of registered attestor signatures over an EIP-712 `Intent`. The common intent includes action, account, controller, current and new signer hashes, account recovery nonce, random intent nonce, provider policy, issuance/validity times, chain ID, and attestor-set epoch.

Each packed attestation separately binds the common intent digest, the exact provider-key hash, and the ID-token `iat` observed by that attestor. This allows independent logins to aggregate if they occur in different seconds or straddle a provider-key rotation. The legacy common `Intent.providerKeyHash` field is required to be zero; on-chain submission uses `abi.encode(providerKeyHash, tokenIssuedAt, signature)` for each attestor. Quorum members must use the same provider policy ID, issuer, and OIDC audience.

It checks and consumes each digest once. Domain separation, explicit chain ID, controller, account, action, recovery nonce, and intent nonce stop ordinary replay, cross-contract reuse, cross-chain reuse, and reuse for another account-management action.

### 3.4 IdentityRecoveryManager

Recovery has two on-chain phases:

1. **Schedule:** verify/consume the OIDC attestation and new-key proof, increment the recovery nonce immediately, and store only the constrained signer change.
2. **Finalize:** after the immutable delay and before the immutable execution window expires, recheck new-key possession and perform exactly the stored add/replace operation.

An existing account signer can cancel during the delay. Cancellation does not restore the nonce, so the cancelled authorization cannot be replayed. An expired request cannot finalize and is automatically cleared when a newer authorized recovery is scheduled. The manager cannot transfer funds, call arbitrary account targets, change account threshold, or enable recovery after the account disables it. The reference environment template uses a seven-day delay and a seven-day execution window; production policy should normally evaluate a 7–14 day delay.

### 3.5 ProviderKeyRegistry

Verifier services fetch Google/Apple JSON Web Key Sets (JWKS). A JWKS is a provider-published list of current public signing keys. The registry records canonical public JWK material, key identifiers, validity windows, and emergency revocation.

The attestation names the SHA-256 thumbprint of the exact provider key that signed the ID token. On-chain verification accepts it only inside the recorded validity window and while not emergency-revoked. Rotation is handled by publishing a new key before or alongside activation, retaining the old key for a short overlap, then retiring it. An unknown `kid` causes each off-chain verifier to refresh JWKS once rather than blindly accepting or permanently caching failure.

The registry is a transparency and policy boundary, not an on-chain JWT verifier. The attestor threshold still asserts that the named key actually validated the token.

### 3.6 OIDC verifier services

Each independent service:

1. accepts an exact action request;
2. derives the OIDC `nonce` from that request;
3. starts Authorization Code flow with PKCE and a random `state` value;
4. exchanges the one-time code server-side;
5. accepts only an ID token, never an access token, as identity evidence;
6. validates signature, exact issuer, exact audience, fixed algorithm, nonce, issue/expiry/authentication time, and provider key;
7. checks the opaque account identity binding;
8. renders a confirmation page on the verifier's own origin;
9. requires the user to type the displayed key-fingerprint suffix;
10. signs the exact short-lived common intent plus its own provider-key and token-issuance evidence once.

PKCE, or Proof Key for Code Exchange, binds the authorization request to the code exchange and makes a stolen authorization code less useful. `state` binds the browser callback to the initiating session. Neither replaces the typed action binding.

## 4. User-intent design

Authentication and intent are separate facts.

A provider login answers: “Did Google or Apple authenticate this provider account for this OIDC client?” It does not answer: “Did the person understand that key X will control account Y on chain Z?”

The design therefore uses several independent checks:

- the OIDC nonce is derived from all action-changing fields, preventing a token for one action from being substituted into another;
- the attestation signs exact typed fields, not an ambiguous text blob;
- a verifier-owned confirmation page independently displays the action, chain, account, controller, verifying contract, provider policy, identity commitment, intent and recovery nonces, full signer encoding and fingerprint, current signer state, validity window, attestor epoch, and recovery delay;
- typed fingerprint confirmation requires a small amount of active user attention;
- the new key proves possession of the same intent;
- recovery waits on-chain and can be cancelled by an existing signer;
- production monitoring must notify the user through a channel independent of the initiating frontend.

This reduces substitution and inattentive approval risk. It cannot cryptographically prove comprehension. A user can still approve a malicious but accurately displayed recovery, and a compromised confirmation origin can lie. High-value deployments should add a second factor or guardian independent of the identity provider.

## 5. Availability property

Google, Apple, verifier services, their databases, and the provider-key publication process may all become unavailable. In that state:

- existing account signers still validate and execute ordinary operations;
- existing signers still manage the signer set through ordinary account operations;
- funds are not frozen by OIDC downtime;
- only new OIDC-assisted creation and recovery are unavailable.

The underlying chain and an ordinary transaction sender remain operational dependencies. The sender may be the installed address signer or any chosen relayer; no specialized protocol contract is required.

## 6. Governance and upgrades

The account, factory, verifier, recovery manager, and provider registry are deliberately non-upgradeable.

Attestor-set rotation, provider-key publication/revocation, and recovery-verifier allowlisting are administrative functions. In production, ownership must be transferred to a separately deployed, audited timelock controlled by a geographically and organizationally diverse multisignature. The reference project does not pretend that an externally owned deployment key is production-safe.

A malicious governance authority can cause denial of recovery and, by replacing the attestor set, can eventually authorize signer changes after the recovery delay. Users can permanently disable recovery, but should do so only after establishing another tested recovery method.

## 7. Standards and prior systems

Primary references:

- OpenID Connect Core 1.0, including ID-token validation and nonce requirements: https://openid.net/specs/openid-connect-core-1_0.html
- OAuth 2.0 Security Best Current Practice, RFC 9700: https://www.rfc-editor.org/rfc/rfc9700.html
- JWT Best Current Practices, RFC 8725: https://www.rfc-editor.org/rfc/rfc8725.html
- JWK thumbprints, RFC 7638: https://www.rfc-editor.org/rfc/rfc7638.html
- Google OpenID Connect documentation: https://developers.google.com/identity/openid-connect/openid-connect
- Apple Sign in verification: https://developer.apple.com/documentation/signinwithapple/verifying-a-user
- EIP-712 typed structured data: https://eips.ethereum.org/EIPS/eip-712
- ERC-1271 contract signatures: https://eips.ethereum.org/EIPS/eip-1271
- ERC-7913 signature verifiers: https://eips.ethereum.org/EIPS/eip-7913
- W3C WebAuthn Level 3: https://www.w3.org/TR/webauthn-3/
- Sui zkLogin as a privacy-preserving comparison: https://docs.sui.io/concepts/cryptography/zklogin
- Safe social recovery/module background: https://docs.safe.global/learn/safe-core/safe-core-protocol/social-recovery-module
