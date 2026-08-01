# OIDC-assisted smart account

A reference implementation in which a familiar Google or Apple identity can establish or recover a smart account, while ordinary account operations remain controlled by independent cryptographic signing keys.

**Security status:** research/reference implementation. It has automated tests and independent adversarial review, but it has not received a professional external audit or production deployment review. Do not place real value in it as-is.

## What this project does

- Creates a deterministic ERC-4337 smart account after a threshold of independent services verify a Google or Apple OpenID Connect login.
- Installs an independent ERC-7913-formatted signer as the account's real transaction authority.
- Supports ECDSA addresses, ERC-1271 contract signers, P-256/WebAuthn passkeys through compatible verifier contracts, and future verifier/key formats.
- Allows OIDC-assisted signer addition or replacement only through a delayed, cancellable recovery path.
- Expires pending recovery after a bounded finalization window so stale requests cannot execute indefinitely.
- Keeps Google/Apple tokens, provider subjects, emails, and profile claims off-chain.
- Continues normal account execution and signer management if Google, Apple, or all identity-verification services are offline.

## What it deliberately does not do

- It never accepts OAuth or OIDC as an ordinary transaction signature.
- It does not make Google, Apple, the verifier threshold, or governance trustless.
- It does not prove that a human understood an action merely because login succeeded.
- It does not implement zero-knowledge JWT verification in v1.
- It does not provide a production database, hardened browser session layer, notification service, or audited deployment governance.

## Repository layout

- `src/ProviderKeyRegistry.sol` — provider-key transparency, rotation windows, and emergency revocation.
- `src/IdentityIntentVerifier.sol` — EIP-712 typed intent and threshold attestor verification.
- `src/IndependentKeyAccount.sol` — ERC-4337 account controlled by independent ERC-7913 signers.
- `src/IdentityRecoveryManager.sol` — delayed/cancellable ADD or REPLACE signer recovery.
- `src/IdentityAccountFactory.sol` — CREATE2 account bootstrap bound to exact signer and account.
- `test/` — Foundry unit, fuzz, replay, cross-chain, timing, and adversarial tests.
- `verifier/` — TypeScript OIDC verifier/attestor service with mock-provider integration tests.
- `docs/ARCHITECTURE.md` — architecture choices and protocol flow.
- `docs/THREAT_MODEL.md` — assets, adversaries, trust boundaries, invariants, and residual risks.

## Toolchain

Versions were checked against their official package/release sources when the project was created:

- Foundry 1.7.1
- Solidity 0.8.36
- OpenZeppelin Contracts 5.7.0
- forge-std 1.16.2
- Node.js 24 or newer for the verifier
- exact JavaScript dependency versions are pinned in `verifier/package.json`

## Build and test

```bash
cd /home/mmv/oidc-smart-account
forge fmt --check
forge build
forge test -vv

cd verifier
npm ci
npm test
npm run typecheck
npm run build
```

The OIDC tests use a local mock issuer and generated RSA keys. Real Google/Apple credentials are not required for the test suite.

## Protocol summary

### Creation

1. The browser generates or selects an independent signer.
2. The factory predicts the CREATE2 account address.
3. The client constructs an exact CREATE action request.
4. Independent OIDC services bind the provider login nonce to that request and validate the ID token.
5. Each service shows its own exact confirmation page and signs the common short-lived EIP-712 intent plus its independently observed provider-key evidence only after explicit fingerprint confirmation.
6. The new signer proves possession by signing the same intent digest.
7. The factory verifies the attestor threshold and key proof, consumes the intent, and deploys the exact account.

### Normal operation

The account validates ERC-4337 user operations using installed ERC-7913 cryptographic signers. No OIDC component is called.

### Recovery

1. Independent OIDC services authorize one exact ADD or REPLACE action.
2. The recovery manager verifies the attestor threshold and new-key possession, consumes the intent, increments the account recovery nonce, and schedules the exact change.
3. The existing account can cancel during the immutable delay.
4. After the delay and before the execution window expires, finalization rechecks new-key possession and performs only the stored signer change.

## User intent

Provider authentication does not prove blockchain intent. The design binds the login nonce to exact action fields, uses a verifier-owned confirmation page, requires typing a key-fingerprint suffix, checks new-key possession, and delays recovery so an existing signer can cancel. These controls reduce substitution and inattentive approval; they cannot prove comprehension.

## Production requirements

Before production use, at minimum:

- professional audits of contracts and verifier services;
- a real 2-of-3 or stronger organizationally independent attestor set;
- audited timelock/multisignature governance and monitored key rotation;
- durable transactional identity/challenge storage with encrypted backups;
- HTTPS, hardened cookies, CSRF protection, rate limiting, anti-automation controls, and strict logging redaction;
- independent recovery notifications and monitoring;
- target-chain ERC-4337 and P-256/WebAuthn compatibility testing;
- operational exercises for provider key rotation, verifier loss, governance compromise, cancellation, and account recovery.

See [architecture](docs/ARCHITECTURE.md) and [threat model](docs/THREAT_MODEL.md) for the complete reasoning and limitations.
