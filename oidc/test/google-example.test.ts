import assert from 'node:assert/strict';
import test from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import {
  discoverGoogleOIDC,
  redeemGoogleAuthorizationCode,
} from '../examples/google/oidc.js';

const canonical = {
  issuer: 'https://accounts.google.com',
  authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  token_endpoint: 'https://oauth2.googleapis.com/token',
  jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
};

test('Google discovery accepts only the pinned canonical metadata', async (t) => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    assert.equal(input.toString(), 'https://accounts.google.com/.well-known/openid-configuration');
    assert.equal(init?.redirect, 'manual');
    assert.ok(init?.signal);
    return Response.json(canonical);
  };
  t.after(() => { globalThis.fetch = originalFetch; });

  const endpoints = await discoverGoogleOIDC();
  assert.equal(endpoints.authorizationEndpoint.toString(), canonical.authorization_endpoint);
  assert.equal(endpoints.tokenEndpoint.toString(), canonical.token_endpoint);
  assert.equal(endpoints.jwksUri.toString(), canonical.jwks_uri);
});

test('Google discovery rejects attacker endpoints even when issuer is canonical', async (t) => {
  let requestInit: RequestInit | undefined;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_input, init) => {
    requestInit = init;
    return Response.json({
      ...canonical,
      token_endpoint: 'https://attacker.example/token',
      jwks_uri: 'https://attacker.example/jwks',
    });
  };
  t.after(() => { globalThis.fetch = originalFetch; });

  await assert.rejects(discoverGoogleOIDC(), /unexpected Google token endpoint/);
  assert.equal(requestInit?.redirect, 'manual');
});

test('Google discovery rejects oversized metadata', async (t) => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify(canonical), {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'content-length': '1000000',
    },
  });
  t.after(() => { globalThis.fetch = originalFetch; });

  await assert.rejects(discoverGoogleOIDC(), /too large/);
});

test('Google token redemption accepts the documented legacy issuer', async (t) => {
  const clientId = 'web.apps.googleusercontent.com';
  const nonce = `0x${'11'.repeat(32)}` as const;
  const identitySalt = `0x${'22'.repeat(32)}` as const;
  const now = Math.floor(Date.now() / 1000);
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = 'legacy-issuer-test';
  publicJwk.alg = 'RS256';
  publicJwk.use = 'sig';
  const idToken = await new SignJWT({ nonce })
    .setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid, typ: 'JWT' })
    .setIssuer('accounts.google.com')
    .setAudience(clientId)
    .setSubject('subject-123')
    .setIssuedAt(now)
    .setExpirationTime(now + 600)
    .sign(privateKey);

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const url = input.toString();
    if (url.endsWith('/.well-known/openid-configuration')) return Response.json(canonical);
    if (url === canonical.token_endpoint) {
      assert.equal(init?.redirect, 'manual');
      return Response.json({ id_token: idToken });
    }
    if (url === canonical.jwks_uri) return Response.json({ keys: [publicJwk] });
    throw new Error(`unexpected test URL: ${url}`);
  };
  t.after(() => { globalThis.fetch = originalFetch; });

  const endpoints = await discoverGoogleOIDC();
  const authenticated = await redeemGoogleAuthorizationCode({
    endpoints,
    clientId,
    clientSecret: 'test-secret',
    redirectUri: 'http://127.0.0.1:8787/callback',
    code: 'test-code',
    codeVerifier: 'test-verifier',
    expectedNonce: nonce,
    identitySalt,
    maxClaimAgeSeconds: 600,
  });
  assert.equal(authenticated.claims.iss, 'accounts.google.com');
  assert.equal(authenticated.normalizedClaim.nonce, nonce);
});
