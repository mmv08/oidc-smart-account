# Architecture: provider identity and claim-bound account management

Status: implemented reference design; not audited or production-ready.

## 1. Objective

The protocol records a stable OpenID Connect (OIDC) identity commitment on an account and verifies fresh authenticated claims against it before allowing one exact account-management action.

The core dependency direction is:

```text
OIDCAccountFactory / OIDCRecoveryController
                    ↓
          IOIDCClaimVerifier
                    ↓
 GoogleJWTVerifier | proof registry | oracle | zero-knowledge proof | other adapter
```

The account-policy core remains adapter-independent. This repository includes a direct Google JSON Web Token (JWT) adapter and a deliberately simple updater-owned Google key registry. Oracle membership, attestor thresholds, other providers, and zero-knowledge circuits remain separate adapter concerns.

## 2. Four distinct objects

### 2.1 Provider policy

A provider policy identifies the provider and exact OIDC client context accepted for an account:

```text
providerId = keccak256(canonical issuer)
providerPolicyId = keccak256(
    typed OIDCPolicy(
        providerId,
        keccak256(audience/client ID),
        authorizedPartyHash
    )
)
```

`authorizedPartyHash` is zero for Apple and ordinary Google policies. A Google hybrid policy uses `keccak256(expected azp client ID)`, so its server audience and Android/iOS authorized party are both immutable parts of the policy.

The initial canonical issuers are Google (`https://accounts.google.com`) and Apple (`https://appleid.apple.com`). The TypeScript helper accepts Google's historical `accounts.google.com` issuer form and normalizes it to the canonical provider identifier.

The OAuth client ID is part of the policy. It prevents a claim issued for another application from identifying the user under this account's policy.

### 2.2 Stable user identity

OIDC identifies a user through `sub`, the provider's subject claim, interpreted under the issuer/client policy. Email is not identity: it may change, be reassigned, or be hidden behind Apple's private relay.

The account stores:

```text
identityCommitment = keccak256(
    typed OIDCIdentity(providerPolicyId, keccak256(sub), identitySalt)
)
```

The account never needs the raw subject. The proof adapter must establish that its authenticated claim maps to the stored commitment. The identity salt is separate from the public CREATE2 deployment salt.

The protocol does not enforce one-account-per-identity. A provider identity may intentionally control several separately salted accounts without a global linkable registry.

### 2.3 Fresh provider claim

`IOIDCClaimVerifier.verifyClaim(proof)` returns only:

```solidity
struct VerifiedOIDCClaim {
    bytes32 providerPolicyId;
    bytes32 identityCommitment;
    bytes32 nonce;
    uint64 issuedAt;
    uint64 expiresAt;
}
```

The result states: this provider/client policy authenticated this committed identity, with this provider-signed nonce, during this time interval.

The adapter authenticates token or proof syntax and cryptography. The factory/controller independently compares every returned field needed for authorization and enforces on-chain freshness.

### 2.4 Authorized action

A valid login is not account-management intent. The exact EIP-712 action digest is used as the OIDC authorization request's `nonce` string. EIP-712 is Ethereum's typed structured-data hashing scheme; here it binds a nonce to named fields, chain ID, and an exact contract.

The provider-authenticated chain becomes:

```text
provider-authenticated nonce
        = exact EIP-712 action digest
        ↓
matching registered identity and provider policy
        ↓
constrained on-chain state transition
```

## 3. Contract responsibilities

### 3.1 `IOIDCClaimVerifier`

This is a read-only fact-verification boundary. It does not:

- consume recovery nonces;
- choose account actions;
- mutate account signers;
- implement recovery delays;
- define oracle, attestor, or governance policy.

A verifier is trusted to return claims only for authentic provider evidence under its stated policy. A state-backed proof registry, direct cryptographic verifier, or zero-knowledge verifier can all implement the same interface.

### 3.2 `OIDCAccount`

Each account has immutable:

- `identityController`;
- `providerPolicyId`;
- `identityCommitment`.

It has exactly one independent ERC-7913 signer. This is a deliberate simplification: the first implementation solves identity binding and signer replacement rather than embedding a general multisignature policy.

Routine execution has two paths:

```solidity
execute(address target, uint256 value, bytes data)
```

A 20-byte installed Ethereum-address signer may call directly.

```solidity
executeSigned(
    address target,
    uint256 value,
    bytes data,
    uint256 nonce,
    uint64 deadline,
    bytes signature
)
```

Any sender may relay an EIP-712 authorization from the installed ERC-7913 signer. The signature binds target, value, calldata hash, monotonic signer epoch, sequential execution nonce, deadline, chain, and exact account. The epoch changes on every signer replacement, so returning to an earlier signer cannot revive its old signatures. Nonce consumption and the target call are atomic: a reverted target call rolls the entire transaction back.

The current signer can rotate normally. Address-less signers do so through a signed self-call. Only the immutable identity controller may call `replaceSignerFromIdentity`, and it must provide the exact current signer hash and epoch. The account can permanently disable identity recovery.

### 3.3 `OIDCAccountFactory`

The factory performs OIDC-gated account creation. The `CreateAccount` digest binds:

- predicted account address;
- CREATE2 deployment salt;
- provider policy;
- identity commitment;
- complete initial-signer hash;
- validity interval;
- chain ID and exact factory through the EIP-712 domain.

Creation succeeds only when:

1. the request recomputes to the exact predicted address;
2. the complete supplied signer hashes to the request's signer hash;
3. the configured claim verifier returns the same policy, identity, and digest nonce;
4. the claim is issued, unexpired, and no older than `maxClaimAge`;
5. the new signer proves possession by signing the same digest.

The factory keeps no replay mapping. CREATE2 itself prevents the exact deployment from being repeated. A third party may front-run the same creation, but deploys the same code, identity, controller, and signer.

Because the identity commitment is part of the create digest, first enrollment needs the stable provider subject before the action-bound authorization begins. A product can use an existing authenticated session or perform a discovery login followed by a second action-bound authorization. Treating the discovery token as creation approval would remove the exact-intent guarantee. The identity salt is operational recovery material: the client or selected proof adapter must keep it recoverable without publishing the raw subject.

### 3.4 `OIDCRecoveryController`

Recovery is replacement-only and has two phases.

**Schedule** verifies:

- exact account/controller wiring;
- recovery is enabled;
- request nonce equals the account's current controller nonce;
- expected signer hash and monotonic signer epoch equal current signer state;
- complete new-signer encoding and proof of possession;
- request validity interval;
- matching, current normalized OIDC claim.

It increments the recovery nonce immediately and stores only the exact pending replacement. Cancellation does not restore the nonce.

**Finalize** is permissionless after the immutable delay and through the end of the immutable execution window. The caller supplies a current replacement-key proof of possession. Finalization rechecks that proof plus the expected signer hash and monotonic signer epoch through `OIDCAccount`; rotating away and later back to the same signer cannot revive stale recovery. Expired pending recovery cannot finalize and does not block a newer request.

The signer makes the account itself call `cancel()`: an address signer can use direct `execute`, while any supported signer can authorize relayed `executeSigned`.

### 3.5 Direct Google JWT adapter and TEE key provenance

`GoogleJWTVerifier` implements `IOIDCClaimVerifier` for compact Google RS256 ID tokens. RS256 means RSA PKCS#1 v1.5 signatures over a SHA-256 digest. The verifier strictly decodes the original signed token, selects a 256-byte RSA modulus by protected `kid`, verifies the signature with OpenZeppelin's RSA implementation, parses security-relevant signed claims, and returns the normalized claim.

The verifier reads keys only through `TEEGoogleKeyUpdater`, which implements the unchanged `IGoogleKeyRegistry.getKey(bytes32)` boundary and stores the key intervals internally. There is no separate raw registry in the TEE deployment, so pause and staleness cannot be bypassed through another storage address.

A measured AWS Nitro Enclave fetches exactly Google's HTTPS JWKS endpoint, terminates and authenticates TLS inside the enclave, strictly validates the complete RS256 key set, sorts it by `kidHash`, and signs an EIP-712 snapshot with an enclave-controlled secp256k1 application key. The untrusted parent may proxy only raw KMS and Google TLS bytes. Anyone may relay the resulting snapshot.

The updater verifies the current attestor, epoch, nonce, observation time, canonical order, modulus shape, and complete-set lifecycle. New keys begin at the observation time; omitted keys retire at the newer observation time; reappearing keys start a new interval. Reads fail closed before initial enrollment/snapshot, while paused, or when the last snapshot is stale. Normal account execution never reads this path.

The contract starts with no attestor. Threshold governance schedules the first verified enclave address and later rotations through an observable delay. A separate guardian can pause and cancel but cannot enroll a key, publish keys, or unpause. Native Nitro attestation is verified during the published enrollment ceremony, not in Solidity; implementing COSE/CBOR and X.509 chain policy on-chain would add a larger and more fragile trust component than the updater.

This changes, but does not remove, the trust root. Google, Web Public Key Infrastructure, AWS Nitro hardware/attestation, AWS KMS, the measured image and build, enrollment reviewers/governance, and availability remain trusted. Nitro attestation proves that an accepted measured program ran; it does not prove a fresh Google fetch. TLS establishes endpoint authenticity, while signed time, nonce, monotonic observation, submission age, and read-time freshness constrain replay and staleness.

`TEEGoogleKeyUpdater` stores `keccak256(bytes(kid))`, a 256-byte modulus, and one issue-time interval. `GoogleJWTVerifier` fixes exponent `65537`. Because only one interval is stored per `kidHash`, a rare disappearance followed by reappearance overwrites the old interval; production policy must determine whether the bounded JWT lifetime makes this acceptable or whether interval history is required.

The adapter accepts `abi.encode(bytes(compactJwt), bytes32(identitySalt))`. Issuer, audience, authorized party, subject, nonce, and timestamps come from the exact signed payload; policy inputs come from immutable verifier configuration. The identity salt is a caller-supplied commitment-opening witness: changing it changes `identityCommitment` rather than substituting a signed claim. See [direct Google JWT verification](DIRECT_GOOGLE_JWT.md) and the [TEE updater operations guide](../tee-updater/README.md).

## 4. Google and Apple policy

The initial helpers optimize the shared core for two providers without pretending their complete validation rules are identical.

### Google

A concrete adapter must check at least:

- issuer is `https://accounts.google.com` or the documented equivalent `accounts.google.com`, normalized canonically;
- exact configured client ID appears in `aud`;
- if an immutable Google hybrid authorized party is configured, `azp` equals that Android/iOS client ID while `aud` contains the server client ID;
- otherwise, a supplied or multi-audience-required `azp` equals the configured audience client ID;
- fixed acceptable signature algorithm and current Google verification key;
- non-empty stable `sub`;
- exact action-bound `nonce`;
- token issue and expiry times;
- any required authentication-age policy for the selected login flow.

### Apple

A concrete adapter must check at least:

- issuer is exactly `https://appleid.apple.com`;
- exact Service ID or bundle/client ID in `aud`;
- fixed acceptable signature algorithm and current Apple verification key;
- stable `sub`, not email or private-relay email;
- exact action-bound `nonce`;
- token issue and expiry times;
- Apple-specific account-transfer subject migration where operationally required.

Apple can provide a transfer subject when an application changes developer teams. Identity migration is intentionally not implemented in this minimal account protocol; a production adapter and account migration design must address that lifecycle before such a transfer.

## 5. Replay and timing model

There is no general token-hash replay registry.

- Creation replay is stopped by the exact counterfactual address and CREATE2 deployment.
- Recovery replay is stopped by the monotonically increasing per-account recovery nonce, including after cancellation.
- Routine execution replay is stopped by the account execution nonce.
- Cross-chain and cross-contract replay are stopped by EIP-712 domains.
- Token reuse for a different action fails because its authenticated `nonce` is a different action digest.
- Claim issue time, expiry, and maximum age prevent an old proof from scheduling a current action.

This keeps replay state where the state transition occurs instead of inside the proof adapter.

## 6. Immutability and availability

Accounts, factory, and controller are not proxies. The account's controller and identity binding cannot be changed.

This gives a clear trust boundary but creates an availability trade-off: if the selected verifier becomes permanently unavailable, OIDC recovery for those accounts cannot be migrated. Installed signers still execute and rotate normally, and can permanently disable the dead recovery path. Production deployments should choose verifier lifecycle and migration strategy before funding accounts.

## 7. Privacy

The account-policy core stores only opaque hashes and does not log raw OIDC fields. It cannot guarantee proof privacy:

- the included direct JWT adapter exposes the token, subject, and identity salt in public calldata;
- an oracle-backed registry may expose only a claim commitment;
- a zero-knowledge adapter may hide the subject and token.

The selected proof adapter therefore controls part of the privacy model. Identity salts should not be confused with the public CREATE2 deployment salt, and raw ID tokens should never be treated as permanent identity records.

## 8. Deliberate omissions

- no direct Apple JWT verifier;
- no native on-chain Nitro COSE/CBOR/X.509 attestation verifier;
- no claim that one measured enclave or threshold governance is a decentralized oracle;
- no generic oracle protocol;
- no identity-update or provider-migration action;
- no OIDC signer addition;
- no multiple installed signer policy;
- no ERC-4337 transaction infrastructure;
- no proxy upgrades or governance authority.

Each omitted feature can be added only when its threat and operational owner are concrete.

## 9. References

- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- OAuth 2.0 Security Best Current Practice, RFC 9700: https://www.rfc-editor.org/rfc/rfc9700.html
- JWT Best Current Practices, RFC 8725: https://www.rfc-editor.org/rfc/rfc8725.html
- Google OpenID Connect: https://developers.google.com/identity/openid-connect/openid-connect
- Sign in with Apple: https://developer.apple.com/sign-in-with-apple/
- EIP-712: https://eips.ethereum.org/EIPS/eip-712
- ERC-1271: https://eips.ethereum.org/EIPS/eip-1271
- ERC-7913: https://eips.ethereum.org/EIPS/eip-7913
- WebAuthn: https://www.w3.org/TR/webauthn-3/
