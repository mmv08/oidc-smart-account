# OIDC identity-bound smart account

A small Solidity reference implementation for binding a smart account to a Google, Apple, or other OpenID Connect (OIDC) identity and authorizing narrowly defined account-management actions from fresh provider claims.

OIDC is the identity layer commonly used by “Sign in with Google” and “Sign in with Apple.” An OIDC provider issues a signed ID token containing claims such as issuer, audience, stable subject, nonce, issue time, and expiry.

**Security status:** unaudited research/reference code. It is not production-ready and must not hold real value as-is.

## Main design objective

The project implements the stable part of the protocol:

```text
account-management policy
        depends on
normalized authenticated OIDC claims
        supplied by
IOIDCClaimVerifier
```

`IOIDCClaimVerifier` is the explicit boundary for the open proof-transport problem. A concrete implementation could verify a JWT directly, read an oracle-fed registry, verify a zero-knowledge proof, or use another mechanism. This repository intentionally does not select or implement one of those mechanisms.

No attestor set, quorum, provider-key registry, oracle protocol, or proof-packing scheme appears in the core contracts.

## On-chain identity model

The account stores two immutable values:

```text
providerPolicyId
identityCommitment
```

For the included Google/Apple model:

```text
providerId = keccak256(canonical issuer)
providerPolicyId = keccak256(typed providerId + keccak256(client ID))
identityCommitment = keccak256(typed policyId + keccak256(sub) + salt)
```

`sub` is the stable OIDC subject claim. Email, name, and profile fields are deliberately excluded because they can change. A short-lived ID token is evidence about the identity; it is not the permanent identity itself.

The initial canonical issuers are:

- Google: `https://accounts.google.com`
- Apple: `https://appleid.apple.com`

The core remains provider-agnostic. Google and Apple policy derivation and claim normalization live in `src/OIDCIdentity.sol` and `oidc/`.

## Contracts

- `src/IOIDCClaimVerifier.sol` — minimal normalized claim-verification boundary.
- `src/OIDCIdentity.sol` — canonical Google/Apple identifiers and typed policy/identity commitments.
- `src/OIDCAccount.sol` — identity-bound account with one independent ERC-7913 signer.
- `src/OIDCAccountFactory.sol` — OIDC-authorized deterministic account creation.
- `src/OIDCRecoveryController.sol` — delayed, cancellable, replacement-only recovery.
- `oidc/` — TypeScript Google/Apple normalization and matching EIP-712 action-digest helpers.
- `test/` — unit, adversarial, cross-language golden-vector, fuzz, and invariant tests.

ERC-7913 is an Ethereum signer format represented as `verifier contract address || key bytes`. It supports ordinary Ethereum addresses, ERC-1271 contract signers, passkeys, and other address-less key formats without requiring ERC-4337.

## Protocol flows

### Account creation

1. Generate an independent account signer, an identity-commitment salt, and a separate CREATE2 deployment salt.
2. Derive the provider policy and identity commitment from the provider issuer, exact OAuth client ID, stable `sub`, and identity salt.
3. Predict the account address from the deployment salt and complete constructor configuration.
4. Construct an exact `CreateAccount` EIP-712 digest binding the account, factory, chain, identity, signer, deployment salt, and validity interval.
5. Send that lowercase `0x`-prefixed digest as the OIDC `nonce`.
6. Supply a proof to the configured `IOIDCClaimVerifier`.
7. The factory checks the returned policy, identity, nonce, claim freshness, exact account, and initial-key proof of possession before deploying.

Anyone may relay the exact creation transaction. A transaction-ordering attacker cannot substitute another identity, signer, account, factory, or chain.

**First-enrollment prerequisite:** the commitment must be known before constructing the action-bound OIDC nonce. An application can use an already authenticated provider session, or perform an identity-discovery login followed by a second action-bound authorization. The discovery token alone must not authorize creation. The identity salt must remain recoverable by the client or proof adapter for future recovery; losing it can make the stored commitment unusable.

### Normal operation

- A 20-byte Ethereum-address signer calls `execute` directly.
- A passkey or other ERC-7913 signer signs an EIP-712 `Execution`; any untrusted ordinary transaction sender relays it through `executeSigned`.
- The signature binds target, value, calldata hash, account execution nonce, deadline, exact account, and chain.
- Routine execution never calls the identity controller or proof verifier.

OIDC cannot authorize arbitrary account calls or routine transactions.

### Recovery

1. Construct an exact `Recovery` digest binding the account, controller, chain, current signer hash, complete new-signer hash, recovery nonce, and validity interval.
2. Use that digest as the OIDC `nonce` and obtain a matching authenticated claim.
3. The new signer proves possession of the same digest.
4. The controller schedules only the exact signer replacement and immediately consumes the account recovery nonce.
5. The current signer can cancel during the delay.
6. Anyone may finalize after the delay and before the execution window expires.
7. Finalization rechecks the expected current signer, so ordinary signer rotation makes a pending recovery stale.

Recovery supports **replacement only**. OIDC cannot silently expand signer authority by adding another key.

## Proof-verifier trust boundary

The configured verifier is immutable for each controller. If it fabricates a matching claim, it can schedule account recovery, subject to the delay and cancellation window. If it fails or disappears, creation and recovery stop, but installed signers continue ordinary operation.

The core checks action authorization independently. The verifier should answer only:

- was the provider proof cryptographically valid under the expected provider/client policy?
- which stable identity did it authenticate?
- what exact nonce did the provider sign?
- when was the claim issued and when does it expire?

A direct-JWT adapter would put token material in public calldata. A privacy-preserving adapter could return the same normalized claim without exposing the token or subject. Privacy therefore depends partly on the selected adapter.

## Build and test

Pinned contract toolchain:

- Foundry 1.7.1
- Solidity 0.8.36
- OpenZeppelin Contracts 5.7.0
- forge-std 1.16.2

```bash
cd /home/mmv/oidc-smart-account
forge fmt --check
forge build --sizes
forge test -vv

cd oidc
npm ci
npm test
npm run typecheck
npm run build
npm audit --audit-level=high
```

The tests use a deterministic in-contract claim-verifier mock. They prove the behavior of the protocol boundary, not authentic Google or Apple signature verification.

## Reference deployment

`script/Deploy.s.sol` expects:

```text
DEPLOYER_PRIVATE_KEY
OIDC_CLAIM_VERIFIER
RECOVERY_DELAY
RECOVERY_WINDOW
MAX_CLAIM_AGE
```

`OIDC_CLAIM_VERIFIER` must already be deployed and independently reviewed. See `.env.example`.

## Deliberate exclusions

- no ERC-4337 EntryPoint, bundler, paymaster, or UserOperation;
- no oracle or attestor network;
- no provider-key governance or JSON Web Key Set (JWKS) registry;
- no direct JWT parser or signature verifier;
- no raw token or email as permanent identity;
- no OIDC authorization of routine execution;
- no proxy or upgrade authority;
- no claim that a successful login proves user comprehension.

See [architecture](docs/ARCHITECTURE.md) and [threat model](docs/THREAT_MODEL.md) for exact assumptions and residual risks.
