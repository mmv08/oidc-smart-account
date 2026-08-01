# Threat model and trust assumptions

## 1. Protected assets

- funds and authorities held by the smart account;
- installed transaction-signing keys;
- the ability to add, remove, or replace signers;
- the mapping between a blockchain account and a Google/Apple subject;
- OIDC authorization codes, ID tokens, PKCE verifiers, and attestor private keys;
- availability of ordinary account operations.

## 2. Adversaries

The design considers:

- a network observer or transaction-ordering attacker who copies pending transactions;
- a malicious relayer or bundler;
- a malicious or compromised application frontend;
- theft of an OIDC authorization code or ID token;
- compromise of a Google/Apple account or the provider itself;
- compromise of one verifier service or attestor key;
- compromise of the attestor threshold;
- stale, substituted, or malicious provider signing keys;
- compromise of registry/attestor governance;
- loss or compromise of an installed blockchain signing key;
- a user who approves an accurately displayed but harmful action without understanding it.

## 3. Trust boundaries

### Google or Apple

Trusted to authenticate the intended provider account and issue correct OpenID Connect claims. Not trusted to sign transactions. Provider compromise or provider-account takeover can satisfy the identity portion of recovery and is a residual takeover risk.

### OIDC verifier/attestor services

Each service sees the ID token and stable provider subject. A threshold is trusted to:

- validate tokens according to OIDC and JWT rules;
- bind the OIDC nonce to the exact account-management request;
- maintain the correct opaque identity mapping;
- show the exact confirmation content;
- sign only after successful confirmation;
- protect its attestor key and state.

One compromised attestor must not meet the production threshold. Threshold compromise can authorize a malicious signer after the delay.

### Provider-key publication mechanism

Trusted for availability and accurate key transparency. It can suppress a new key and cause recovery outage. Adding a fake key is not sufficient by itself because the attestor threshold must still sign, but registry governance and attestor-threshold compromise together defeat recovery authentication.

### Frontend

Not trusted to describe intent accurately. It may start a malicious request or show a benign key while sending another. Security therefore depends on a separately originated verifier confirmation page, exact typed action binding, new-key proof, and delayed cancellation. A frontend can still cause denial of service or socially engineer an accurately displayed malicious request.

### Smart contracts

Trusted to enforce typed fields, threshold, nonce, chain/contract domain, delay, cancellation, and capability limits exactly. Contracts are non-upgradeable. A contract bug can defeat every higher layer.

### Account signers

Installed signers are root transaction authority. Compromise of any signer is account compromise in the threshold-one reference account. Users needing stronger protection should use a threshold account policy after independent audit rather than assuming recovery makes a hot key safe.

### Governance

Administrative power rotates attestors, publishes/revokes provider keys, and approves address-less recovery verifier contracts. Production governance must be a delayed multisignature. A threshold governance compromise can eventually subvert recovery. It cannot directly sign an ordinary account operation unless it first succeeds through the constrained recovery path.

### ERC-4337 EntryPoint and chain

Trusted as account-execution infrastructure. The account pins a configured EntryPoint. Chain consensus failures, same-chain-ID forks, or EntryPoint bugs are outside OIDC recovery's protection.

## 4. Required security invariants

1. No OIDC token, provider signature, attestor signature, or recovery-manager call is accepted by ordinary transaction validation.
2. Every create/recovery authorization binds action, account, chain, controller, identity commitment, current signer where relevant, new signer hash, recovery nonce, and random intent nonce.
3. A consumed or cancelled authorization cannot be reused.
4. A new signer proves possession of the exact authorized intent before creation/scheduling and again before recovery finalization.
5. Recovery performs only ADD or REPLACE signer; it cannot execute arbitrary calls or transfer value.
6. Recovery cannot complete before the delay and can be cancelled by an existing signer.
7. Provider signing keys are algorithm-pinned, issuer/audience-pinned, time-bounded, rotation-aware, and emergency-revocable.
8. Raw JWTs and personally identifying OIDC claims never enter blockchain calldata, logs, or storage.
9. Ordinary operation does not depend on Google, Apple, verifier availability, verifier databases, or provider-key refresh.
10. Recovery disabled by the account cannot be re-enabled by recovery or governance.
11. Pending recovery expires after a bounded execution window; an expired request cannot finalize or permanently block a newer recovery.
12. Independent attestors may use different valid provider keys and token issuance times, but cannot alter the common action or validity window.

## 5. Attack analysis

| Attack | Required defense / outcome |
|---|---|
| Replay same attestation | Consumed digest and recovery nonce reject it. |
| Use on another chain | EIP-712 domain plus explicit `chainId` reject it. |
| Use with another factory/manager | Typed `controller` and EIP-712 verifying contract reject it. |
| Turn CREATE into REPLACE | Typed action rejects it. |
| Substitute attacker's key | Typed new-signer hash and key proof reject it. |
| Front-run CREATE | Same deterministic account and same signer are deployed; no control is gained. |
| Front-run recovery schedule/finalize | Only the already authorized exact signer change occurs. |
| Steal authorization code | PKCE, one-time code use, state, and server-side exchange limit use. |
| Reuse ID token for another action | Exact action-derived OIDC nonce rejects it. |
| Stale provider key | Key window, token time checks, refresh-on-unknown-kid, and revocation reject it. |
| One malicious attestor | Does not reach the intended 2-of-3 threshold. |
| Malicious frontend | Independent confirmation origin exposes exact action; key proof/delay prevent silent substitution, but social engineering remains. |
| OIDC outage | Creation/recovery stop; installed signers continue ordinary operation. |
| Governance instant takeover | Production timelock gives monitoring/cancellation time; reference deployment without timelock is not production-ready. |

## 6. Privacy

On-chain observers learn:

- that the account has OIDC-assisted recovery;
- the provider policy identifier, which may reveal Google versus Apple;
- signer hashes, action type, timing, and attestor set;
- whether recovery was scheduled, cancelled, or completed.

They do not receive the ID token, authorization code, provider subject, email, name, or profile. The identity commitment is random and per-account, preventing direct dictionary attacks and cross-account linkage. Verifier services still know the provider subject and account binding; their logs, databases, backups, and legal access are privacy boundaries.

## 7. Residual risks and production blockers

- No external smart-contract audit or formal verification has been performed.
- Human comprehension cannot be proven. Trusted confirmation UI and typed fingerprint entry only reduce risk.
- Provider-account takeover or provider coercion remains a recovery risk.
- Threshold attestor compromise remains a delayed account-takeover risk.
- A reference in-memory verifier store is not durable, distributed, transactional, or suitable for production.
- Production needs HTTPS, hardened cookies, CSRF protection, rate limits, anti-automation controls, encrypted durable storage, secret-management hardware, independent monitoring, and notification channels.
- Provider OAuth client registration loss or audience changes can break identity recovery.
- Same-chain-ID contentious forks may allow the same pre-fork authorization/state on both branches.
- ERC-4337 EntryPoint/bundler compatibility, gas griefing, and chain-specific P-256 behavior require target-chain testing.
- Address-less verifier contracts, especially proxies, require audit and code-hash policy; an always-valid verifier destroys key proof.
- The reference threshold-one account means any installed signer has full authority.
- Governance must be transferred to an audited delayed multisignature before value is deposited.
