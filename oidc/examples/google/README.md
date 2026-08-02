# Live Google OIDC recovery example

This example runs a local web server, sends an exact recovery-action digest as Google's OIDC `nonce`, exchanges the authorization code with PKCE, verifies Google's RS256 ID-token signature against Google's published keys, and normalizes the authenticated claim.

The implementation pins Google's discovery URL, authorization endpoint, token endpoint, and JWKS endpoint to their documented values. Discovery and token requests reject redirects, enforce timeouts, and bound response sizes. The JWKS resolver is reused so its cache and unknown-key cooldown survive across callbacks.

It also encodes the authenticated token for the included `GoogleJWTVerifier` and returns only the proof hash to the browser. The raw ID token and proof stay server-side. Transaction submission and replacement-signer custody remain application-specific.

## 1. Register a Google application

Use Google's current [OpenID Connect setup guide](https://developers.google.com/identity/openid-connect/openid-connect) and the [Google Auth Platform Clients page](https://console.cloud.google.com/auth/clients).

1. Create or select a Google Cloud project.
2. Open **Google Auth Platform**.
3. Under **Branding**, enter the application name, support email, and developer contact.
4. Under **Audience**, choose:
   - **Internal** for users in one Google Workspace organization; or
   - **External** for ordinary Google accounts. While the app is in testing, add the Google accounts that should be allowed as test users.
5. The example requests only the `openid` scope. Do not add Gmail, Drive, or other API scopes for this identity-only flow.
6. Open **Clients** and choose **Create client**.
7. Select **Web application**.
8. Add this exact authorized redirect URI:

   ```text
   http://127.0.0.1:8787/callback
   ```

9. Save the client and copy its **Client ID** and **Client secret**.

Google requires the redirect URI in the request to exactly match a registered URI. If you change `PORT`, register the corresponding callback and set `GOOGLE_REDIRECT_URI` to the same value.

## 2. Prepare the account values

This is a **recovery** example, so the account must already be bound to:

- Google's canonical issuer;
- this exact Google OAuth client ID;
- the stable Google `sub` and the original identity salt.

Read current state from the deployed contracts:

```bash
cast call "$ACCOUNT_ADDRESS" 'signerHash()(bytes32)'
cast call "$ACCOUNT_ADDRESS" 'signerEpoch()(uint256)'
cast call "$RECOVERY_CONTROLLER_ADDRESS" 'recoveryNonces(address)(uint256)' "$ACCOUNT_ADDRESS"
```

`NEW_SIGNER_HASH` is `keccak256` of the complete ERC-7913 signer encoding—not merely an address unless the signer encoding is exactly 20 address bytes:

```bash
cast keccak 0x<complete-new-signer-bytes>
```

Use the **same `IDENTITY_SALT` used when the account's identity commitment was created**. Losing that salt can make recovery impossible for adapters that require it.

## 3. Configure and run

From `oidc/`:

```bash
cp examples/google/.env.example examples/google/.env
# Edit examples/google/.env with your values.

set -a
source examples/google/.env
set +a

npm ci
npx tsx examples/google/server.ts
```

Then open:

```text
http://127.0.0.1:8787/login
```

After Google redirects back, the server returns:

- the exact `RecoveryRequest`;
- its EIP-712 action digest;
- the authenticated normalized claim;
- the hash of the server-held direct-JWT proof;
- the next integration step.

EIP-712 is Ethereum's typed-signature format. Here its digest is also the OIDC nonce, so the Google login authenticates one exact account, signer state, replacement signer, nonce, validity interval, chain, and controller.

## 4. Submit to `GoogleJWTVerifier`

The callback creates the exact proof expected by the included adapter:

```ts
directGoogleJWTProof(authenticated.idToken, identitySalt)
```

This is Solidity `abi.encode(bytes(compactJwt), bytes32(identitySalt))`. Keep it server-side until transaction construction because its calldata reveals the complete token, stable subject, and salt.

To schedule recovery you still need to:

1. populate `GoogleKeyRegistry` with the current public Google signing key selected by the token's `kid`;
2. obtain the replacement signer's proof over the same recovery digest;
3. have the trusted server/relayer call:

   ```solidity
   schedule(request, newSignerBytes, replacementProof, oidcProof)
   ```

4. wait for the recovery delay;
5. call `finalize(account, currentReplacementProof)` with a still-valid replacement proof.

Do not return the raw token/proof from a production callback, write it to logs, or store it longer than necessary. See [`docs/DIRECT_GOOGLE_JWT.md`](../../../docs/DIRECT_GOOGLE_JWT.md) for registry deployment, key rotation, exact validation, gas, trust, and privacy details.

## Flow scope

This runnable server implements only an ordinary web Authorization Code flow. Its verifier policy must therefore leave the authorized-party hash unset: the web client ID is the token audience and no distinct native presenter is expected.

Google's hybrid native-to-server flow is a separate integration. In that flow, an Android or iOS application obtains evidence for the server audience and the signed `azp` identifies the native client. Implement a dedicated native handoff endpoint before configuring a nonzero authorized-party hash; this web server cannot produce or redeem that token shape.

## Security notes

The example:

- uses Authorization Code flow with PKCE;
- uses a random, one-time OAuth `state` value;
- binds Google's signed `nonce` to the exact recovery digest;
- verifies issuer, audience, RS256 signature, expiry, issue time, optional not-before time, nonce, and claim freshness;
- never uses email as stable identity;
- does not return the raw ID token to the browser;
- keeps state only in memory and is intended for local development, not production.

Google's documented `prompt=select_account` option is used to force an account-choice screen. This is **not** proof of fresh password, passkey, or multi-factor authentication: an older Google browser session can still issue a new ID token with a fresh `iat`. The on-chain delay, current-signer cancellation path, replacement-key proof, and independent monitoring are therefore still important. A production recovery product should require an additional recovery factor when recent provider reauthentication cannot be proven.

The in-memory `state` map is one-use and expiring but is not bound to a browser session cookie. That is acceptable only for this single-user loopback demonstration. A multi-user service must bind each transaction to an `HttpOnly`, `Secure`, `SameSite=Lax` session cookie and use durable, expiring server-side storage.
