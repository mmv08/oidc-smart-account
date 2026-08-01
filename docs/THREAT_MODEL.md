# Threat model and trust assumptions

## 1. Protected assets

- funds and authorities held by each `OIDCAccount`;
- the installed independent transaction signer;
- the immutable provider policy and user identity binding;
- the ability to schedule, cancel, and finalize identity recovery;
- OIDC ID tokens, authorization codes, stable subjects, and identity salts handled outside the core;
- availability of routine account execution when identity infrastructure is offline.

## 2. Adversaries

The design considers:

- a transaction observer or ordering attacker that copies pending creation, execution, or recovery transactions;
- an untrusted execution relayer;
- a malicious application frontend;
- theft or replay of an OIDC token or proof;
- compromise of the user's Google or Apple account;
- compromise, coercion, or failure of the OIDC provider;
- a malicious, compromised, incorrectly configured, or unavailable `IOIDCClaimVerifier`;
- a malicious ERC-7913 signer-verifier contract;
- loss or compromise of the installed independent signer;
- stale recovery after ordinary signer rotation;
- a user who completes provider authentication for a harmful action without understanding it.

Chain consensus failure, cryptographic primitive failure, and same-chain-ID fork policy are outside the protocol's guarantees.

## 3. Trust boundaries

### 3.1 Google or Apple

The selected provider is trusted to authenticate its account and issue correct claims. Provider-account takeover or provider compromise can satisfy the identity part of recovery. The provider is never an ordinary transaction signer.

### 3.2 `IOIDCClaimVerifier`

The immutable verifier is the most important external trust boundary. It is trusted to:

- authenticate the proof under the intended Google, Apple, or other provider policy;
- enforce algorithm and verification-key policy;
- enforce issuer, audience, authorized-party, subject, nonce, and provider-specific token rules;
- derive the correct salted identity commitment;
- return truthful issue and expiry times;
- reject malformed, ambiguous, oversized, revoked, or otherwise invalid evidence.

A verifier that fabricates claims can schedule arbitrary signer replacement for accounts using its controller. The on-chain delay and current-signer cancellation remain defenses, but they do not make a compromised verifier harmless.

A verifier outage stops new creation and identity recovery. It does not stop installed signers from executing or rotating normally.

### 3.3 Smart contracts

The contracts are trusted to compare normalized claims with immutable account state, bind claims to exact actions, enforce nonces/timing, verify new-key possession, and constrain recovery to signer replacement. A contract bug can defeat every higher layer.

The contracts are non-upgradeable and have no administrative owner. This removes governance takeover but also removes verifier migration.

### 3.4 Independent account signer

The installed ERC-7913 signer is full routine account authority. Its compromise is immediate account compromise. The reference account intentionally has threshold one.

For an address-less signer, the selected verifier contract defines signature validity. A mutable, upgradeable, or always-valid verifier can destroy signer security. The account checks that an address-less verifier has code, but it does not impose code-hash governance or certify that code.

### 3.5 Frontend and user interface

The contracts do not know what a user interface displayed. A frontend can construct a harmful but correctly bound recovery and ask the user to authenticate. The action-bound nonce prevents silent field substitution after authentication; it cannot prove that the user understood the fields.

Production clients should independently display the exact account, chain, controller/factory, current signer fingerprint, new signer fingerprint, validity window, and recovery delay before beginning the provider flow.

### 3.6 Relayers

Relayers are optional and untrusted. They can copy, submit, delay, reorder, or withhold exact signed operations. They cannot change bound fields without invalidating the signer proof or OIDC nonce.

## 4. Required invariants

1. OIDC evidence is never accepted by routine `execute`, `executeSigned`, or ERC-1271 validation.
2. Every account has one immutable controller, provider policy, and identity commitment.
3. Creation binds the predicted account, deployment salt, complete initial signer, identity, validity interval, chain, and exact factory.
4. Recovery binds the account, exact controller, current signer hash, complete new signer, per-account recovery nonce, validity interval, and chain.
5. The provider-authenticated nonce equals the exact EIP-712 action digest.
6. The controller, not the proof verifier, decides which account state transition is permitted.
7. A new signer proves possession of the exact create or recovery digest before deployment or scheduling.
8. Recovery only replaces a signer. It cannot call arbitrary targets, transfer value, or add parallel authority.
9. Recovery cannot finalize before its delay and can be cancelled by the current signer.
10. A cancelled recovery nonce remains consumed.
11. Finalization rechecks current signer state; stale recovery cannot overwrite a later ordinary signer rotation.
12. Pending recovery expires and cannot permanently block a replacement request.
13. Recovery disabled by an account cannot be re-enabled.
14. Routine signatures cannot replay across accounts, chains, nonces, targets, values, calldata, or deadlines.
15. Failure of an ordinary target call rolls back execution-nonce consumption atomically.
16. Ordinary execution remains independent of the provider and claim verifier.

## 5. Attack analysis

| Attack | Defense and remaining outcome |
|---|---|
| Copy/front-run account creation | Only the exact deterministic account with the exact identity and signer can deploy. The copier gains no authority. |
| Substitute initial signer | Initial-signer hash, predicted address, and proof of possession fail. |
| Use a creation proof on another chain or factory | EIP-712 domain changes the authenticated nonce and signer digest. |
| Replay exact creation | CREATE2 cannot deploy a second contract at the occupied address. |
| Reuse a normal login token | Its nonce does not equal the exact create/recovery action digest. |
| Reuse proof for another identity | Account policy/identity comparison fails. |
| Reuse proof for another recovery | Current recovery nonce and action digest differ. |
| Cancel then replay recovery | Cancellation leaves the incremented recovery nonce consumed. |
| Replace signer before recovery finalizes | Expected-signer recheck makes pending recovery stale. |
| Front-run recovery schedule/finalize | Only the already authenticated exact replacement occurs. |
| Finalize very old recovery | Bounded execution window rejects it. |
| Malicious relayer edits routine execution | EIP-712 signature binds target, value, calldata hash, nonce, deadline, account, and chain. |
| Replay routine signed execution | Sequential execution nonce rejects it. |
| Target call reverts | Whole transaction, including nonce increment, reverts. |
| Google/Apple outage | Creation/recovery unavailable; routine signer operations continue. |
| Claim verifier outage | Same availability result; installed accounts remain usable. |
| Claim verifier compromise | Forged recovery can be scheduled; delay, monitoring, cancellation, or prior permanent disablement are the remaining defenses. |
| Provider-account takeover | Attacker can satisfy provider identity and may schedule recovery; delay and cancellation are the remaining defenses. |
| Malicious frontend | Cannot substitute fields after a bound claim, but can socially engineer authentication for a harmful exact action. |
| Always-valid ERC-7913 verifier | Proof of possession and later account signatures become meaningless for that selected signer. Only use reviewed immutable signer verifiers. |
| Identity commitment collision | Relies on Keccak-256 collision resistance and unambiguous typed encoding. |

## 6. Timing and replay assumptions

The factory and controller require:

```text
request.validAfter <= block.timestamp < request.validUntil
claim.issuedAt <= block.timestamp < claim.expiresAt
block.timestamp - claim.issuedAt <= maxClaimAge
```

The concrete proof adapter remains responsible for token-level clock tolerance and authentication-session policy. For example, if a provider flow uses OIDC `max_age`, the adapter must validate the corresponding `auth_time` claim where supported and required. The on-chain `issuedAt` age check prevents submission of an old normalized claim; it does not independently prove password re-entry or user comprehension.

Recovery replay state belongs to `OIDCRecoveryController`, not the verifier. `verifyClaim` is therefore `view`: the adapter authenticates facts, while the component performing the state transition consumes the action nonce.

## 7. Privacy

The core reveals:

- provider policy identifier;
- opaque identity commitment;
- account/controller relationship;
- signer hashes and recovery timing through calls and events;
- arbitrary proof bytes supplied in transaction calldata.

The core does not itself decode or store a raw JWT, subject, email, name, or profile. That does **not** guarantee privacy. A direct-token proof places those values in public calldata. Privacy depends on the concrete verifier and proof encoding.

A private identity salt can reduce linkability only if the proof mechanism does not reveal it. The public CREATE2 deployment salt is separate and provides no identity privacy.

## 8. Residual risks and production blockers

- No professional audit, formal verification, or live-chain deployment review has been completed.
- No concrete Google or Apple proof verifier is included, so the repository does not independently authenticate real provider tokens.
- Provider-account takeover and provider coercion remain recovery-takeover risks.
- An immutable verifier failure can permanently remove OIDC recovery availability for existing accounts.
- There is no identity migration for Apple developer-team transfers, provider client-ID changes, or subject-policy changes.
- First enrollment needs a previously discovered stable subject before constructing the exact action-bound nonce; a new user may therefore need a discovery login followed by an action-bound authorization.
- Losing a private identity salt can make future recovery proofs impossible unless the chosen adapter has a recoverable copy.
- There is no independent notification or monitoring system for pending recovery.
- Human comprehension cannot be proven by nonce binding.
- Threshold-one signer policy means one compromised installed signer has full authority.
- Address-less verifier contracts require separate review and lifecycle policy.
- Direct-JWT, registry, oracle, and zero-knowledge adapters each introduce additional unmodeled threats.
- Same-chain-ID forks may reproduce pre-fork state and signatures.
- Gas behavior, P-256/WebAuthn support, and precompile behavior require testing on every target chain.

This repository demonstrates a constrained protocol boundary, not a complete custody or identity product.
