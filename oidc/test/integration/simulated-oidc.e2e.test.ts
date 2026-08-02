import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { recoveryDigest, type RecoveryRequest } from '../../src/actions.js';
import {
  GOOGLE_PROVIDER,
  providerPolicyId,
} from '../../src/claims.js';
import {
  createGoogleAuthorizationRequest,
  discoverLoopbackGoogleOIDCForTests,
  redeemGoogleAuthorizationCode,
} from '../../examples/google/oidc.js';
import { startSimulatedOIDCProvider } from './support/simulated-oidc-provider.js';

const clientId = 'e2e-client.apps.googleusercontent.com';
const clientSecret = randomBytes(32).toString('base64url');
const redirectUri = 'http://127.0.0.1:49001/callback';
const subject = 'simulated-stable-google-subject';
const identitySalt = `0x${'77'.repeat(32)}` as const;

const recovery: RecoveryRequest = {
  account: '0x1111111111111111111111111111111111111111',
  expectedSignerHash: `0x${'22'.repeat(32)}`,
  expectedSignerEpoch: 3n,
  newSignerHash: `0x${'33'.repeat(32)}`,
  nonce: 4n,
  validAfter: 1_700_000_000n,
  validUntil: 1_700_000_600n,
};

test('authorization-code login from a simulated OIDC server authenticates the exact recovery action', async (t) => {
  const provider = await startSimulatedOIDCProvider({
    issuer: 'https://accounts.google.com',
    clientId,
    clientSecret,
    redirectUri,
    subject,
  });
  t.after(async () => provider.close());

  const endpoints = await discoverLoopbackGoogleOIDCForTests(
    provider.localEndpoint(`${provider.issuer}/.well-known/openid-configuration`),
  );
  const expectedNonce = recoveryDigest(
    recovery,
    1n,
    '0x3333333333333333333333333333333333333333',
  );
  const authorization = await createGoogleAuthorizationRequest({
    endpoints,
    clientId,
    redirectUri,
    nonce: expectedNonce,
  });

  const callback = await provider.completeAuthorization(authorization.url);
  assert.equal(callback.origin + callback.pathname, redirectUri);
  assert.equal(callback.searchParams.get('state'), authorization.state);
  const code = callback.searchParams.get('code');
  assert.ok(code);

  const authenticated = await redeemGoogleAuthorizationCode({
    endpoints,
    clientId,
    clientSecret,
    redirectUri,
    code,
    codeVerifier: authorization.codeVerifier,
    expectedNonce,
    identitySalt,
    maxClaimAgeSeconds: 600,
  });

  assert.equal(authenticated.normalizedClaim.providerId, GOOGLE_PROVIDER);
  assert.equal(
    authenticated.normalizedClaim.providerPolicyId,
    providerPolicyId(GOOGLE_PROVIDER, clientId),
  );
  assert.equal(authenticated.normalizedClaim.nonce, expectedNonce);
  assert.equal(authenticated.claims.sub, subject);
  assert.ok(authenticated.idToken.length > 100);

  const wrongPkceAuthorization = await createGoogleAuthorizationRequest({
    endpoints,
    clientId,
    redirectUri,
    nonce: expectedNonce,
  });
  const wrongPkceCallback = await provider.completeAuthorization(wrongPkceAuthorization.url);
  const wrongPkceCode = wrongPkceCallback.searchParams.get('code');
  assert.ok(wrongPkceCode);
  await assert.rejects(redeemGoogleAuthorizationCode({
    endpoints,
    clientId,
    clientSecret,
    redirectUri,
    code: wrongPkceCode,
    codeVerifier: `${wrongPkceAuthorization.codeVerifier}x`,
    expectedNonce,
    identitySalt,
    maxClaimAgeSeconds: 600,
  }), /token exchange failed/);

  const wrongNonceAuthorization = await createGoogleAuthorizationRequest({
    endpoints,
    clientId,
    redirectUri,
    nonce: expectedNonce,
  });
  const wrongNonceCallback = await provider.completeAuthorization(wrongNonceAuthorization.url);
  const wrongNonceCode = wrongNonceCallback.searchParams.get('code');
  assert.ok(wrongNonceCode);
  await assert.rejects(redeemGoogleAuthorizationCode({
    endpoints,
    clientId,
    clientSecret,
    redirectUri,
    code: wrongNonceCode,
    codeVerifier: wrongNonceAuthorization.codeVerifier,
    expectedNonce: `0x${'44'.repeat(32)}`,
    identitySalt,
    maxClaimAgeSeconds: 600,
  }), /action nonce mismatch/);
});
