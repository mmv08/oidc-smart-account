# OIDC verifier and attestor

This service validates Google or Apple OpenID Connect (OIDC) authentication and emits one narrowly scoped Ethereum typed-data attestation. It never signs ordinary account transactions.

**Status:** runnable reference service, not a production deployment. The included server intentionally uses volatile in-memory storage and refuses to start unless that risk is explicitly acknowledged.

## Security model

One service contributes one attestor signature. A client should collect signatures from at least two independently operated services before submitting an intent on-chain.

The service:

- uses Authorization Code flow with Proof Key for Code Exchange (PKCE);
- separately validates OAuth `state` and OIDC `nonce`;
- pins issuer, audience, client, and the `RS256` signing algorithm;
- checks `iat`, `exp`, `auth_time`, nonce, and token replay;
- caches JSON Web Key Sets (JWKS), refreshes once for an unknown key identifier, and fails closed;
- requests only the `openid` scope;
- binds login to the exact action, account, signer hash, chain, contracts, policy, and nonce;
- requires an explicit signer-fingerprint confirmation;
- does not return JWTs, authorization codes, subjects, email addresses, or access tokens.

## Install and verify

```bash
cd /home/mmv/oidc-smart-account/verifier
npm ci
npm test
npm run typecheck
npm run build
npm audit --audit-level=high
```

The tests run against a local mock issuer with real RSA signatures and signing-key rotation. Google and Apple credentials are not needed for tests.

## Local reference server

```bash
cp .env.example .env
# Fill the blank values with non-production credentials and deployed test addresses.
set -a; . ./.env; set +a
npm run dev
```

After a build, use `npm start`. The health endpoint is `GET /healthz`.

`ALLOW_IN_MEMORY_STORAGE=true` is deliberately required. The included `InMemoryStorage` loses all identity bindings and anti-replay state on restart and is unsuitable for custody. Production operators must instantiate `createVerifierApp` with a durable, transactional implementation of `VerifierStorage` rather than using `src/server.ts`.

## API flow

1. `POST /v1/challenges` with a provider and exact action request.
2. Redirect the browser to the returned `authorizationUrl`.
3. The provider returns to `/v1/oidc/callback`.
4. The browser follows the redirect to `/v1/confirm/:challengeId`.
5. The user checks the independently rendered action and types the final eight hexadecimal characters of the signer fingerprint.
6. `POST /v1/confirm/:challengeId` returns the common typed intent, this service's provider-key evidence, and `packedAttestation` ready for the Solidity `bytes[]` quorum input.

The request includes both:

- `newSigner`: the complete ERC-7913 signer encoding;
- `newSignerHash`: `keccak256(newSigner)`, which is included in the OIDC-bound and on-chain typed action.

The request also supplies decimal-string `issuedAt`, `attestationTtl`, and `attestorEpoch`. They define the common login-bound validity window that every independent attestor must share. Each response separately binds the provider-key hash and ID-token issuance time that this particular service observed, so normal JWKS rotation does not make otherwise honest quorum signatures incompatible.

The service rejects a mismatch. It also pins CREATE requests to `FACTORY_ADDRESS`, recovery requests to `RECOVERY_MANAGER_ADDRESS`, and recovery delay to `RECOVERY_DELAY_SECONDS`.

All unsigned integer fields in JSON are decimal strings. Addresses use Ethereum hexadecimal notation; byte strings use `0x`-prefixed hexadecimal.

## Production requirements

Before deployment:

- replace in-memory storage with a transactional database that atomically claims callbacks and confirmations;
- encrypt identity mappings and backups;
- store attestor keys in a hardware security module or isolated signing service;
- use HTTPS behind a hardened reverse proxy;
- add request-rate limits, anti-automation controls, abuse monitoring, and independent recovery notifications;
- prevent request and query logging at every proxy layer because callback URLs contain authorization codes;
- use independent attestor operators and audited multisignature/timelock contract governance;
- synchronize provider-key publication and revocation with the on-chain registry;
- test provider outages, signing-key rotation, database failover, verifier loss, and recovery cancellation;
- obtain independent audits of contracts, service, client, deployment, and operations.

Apple client secrets are short-lived signed JWTs and require an external rotation procedure. Provider-policy identifiers must change when issuer/audience/security policy meaning changes.
