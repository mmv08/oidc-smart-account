import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import type { JWK } from 'jose';
import type { ProviderConfig } from '../src/config.js';
import { providerPolicyId } from '../src/intent.js';
import { describeProviderKey } from '../src/jwk.js';
import { OidcIdTokenValidator } from '../src/oidc.js';
import { MockOidcProvider } from './mock-oidc.js';

const mock = new MockOidcProvider();
let provider: ProviderConfig;

before(async () => {
  await mock.start();
  await mock.addKey('old');
  await mock.addKey('next');
  mock.publish('old');
  provider = {
    name: 'google', issuer: mock.issuer, audience: mock.audience, clientId: mock.audience,
    clientSecret: 'secret', authorizationEndpoint: `${mock.issuer}/authorize`,
    tokenEndpoint: `${mock.issuer}/token`, jwksUri: `${mock.issuer}/jwks`,
    allowedAlgorithms: ['RS256'], policy: 'mock-policy', providerId: providerPolicyId('mock-policy'),
    revokedKeyThumbprints: new Set(),
  };
});
after(async () => mock.stop());

test('unknown kid triggers exactly one JWKS refresh and overlapping keys continue to validate', async () => {
  const validator = new OidcIdTokenValidator({ jwksCacheSeconds: 60, maxAuthAgeSeconds: 600, clockToleranceSeconds: 0 });
  const now = 1_900_000_000;
  const oldToken = await mock.issueToken('old', { iat: now, auth_time: now, exp: now + 300 });
  const first = await validator.validate(oldToken, provider, 'expected-nonce', now);
  assert.equal(first.identity.subject, 'private-subject');
  assert.equal(mock.jwksRequests, 1);
  assert.equal(first.tokenDigest.includes(oldToken), false);

  mock.publish('old', 'next');
  const nextToken = await mock.issueToken('next', { iat: now, auth_time: now, exp: now + 300 });
  const next = await validator.validate(nextToken, provider, 'expected-nonce', now);
  assert.equal(mock.jwksRequests, 2, 'unknown kid must refresh once');
  assert.match(next.providerKeyHash, /^0x[0-9a-f]{64}$/);

  await validator.validate(oldToken, provider, 'expected-nonce', now);
  assert.equal(mock.jwksRequests, 2, 'overlapping cached key must not force another fetch');

  const unknownHeaderToken = await mock.issueToken('old', { iat: now, auth_time: now, exp: now + 300 });
  const [header, payload, signature] = unknownHeaderToken.split('.');
  const changedHeader = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'never-published', typ: 'JWT' })).toString('base64url');
  await assert.rejects(() => validator.validate(`${changedHeader}.${payload}.${signature}`, provider, 'expected-nonce', now), /unknown signing key/);
  assert.equal(mock.jwksRequests, 3, 'a validation attempt may refresh only once');
});

test('cache expiry observes retired keys and a local emergency revocation always wins', async () => {
  mock.publish('old', 'next');
  const now = 1_900_000_100;
  const oldToken = await mock.issueToken('old', { iat: now, auth_time: now, exp: now + 300 });
  const validator = new OidcIdTokenValidator({ jwksCacheSeconds: 1, maxAuthAgeSeconds: 600, clockToleranceSeconds: 0 });
  await validator.validate(oldToken, provider, 'expected-nonce', now);
  mock.publish('next');
  await assert.rejects(() => validator.validate(oldToken, provider, 'expected-nonce', now + 2), /unknown signing key/);

  mock.publish('old', 'next');
  const oldJwkResponse = await fetch(`${mock.issuer}/jwks`).then((response) => response.json()) as { keys: JWK[] };
  const oldJwk = oldJwkResponse.keys.find((key) => key.kid === 'old')!;
  const revokedProvider = { ...provider, revokedKeyThumbprints: new Set([describeProviderKey(oldJwk).thumbprint]) };
  const revokedValidator = new OidcIdTokenValidator({ jwksCacheSeconds: 60, maxAuthAgeSeconds: 600, clockToleranceSeconds: 0 });
  await assert.rejects(() => revokedValidator.validate(oldToken, revokedProvider, 'expected-nonce', now), /revoked/);
});

test('validation rejects unsupported algorithm and exact claim mismatches or stale authentication', async () => {
  mock.publish('old');
  const now = 1_900_001_000;
  const validator = new OidcIdTokenValidator({ jwksCacheSeconds: 60, maxAuthAgeSeconds: 600, clockToleranceSeconds: 5 });
  const unsupportedAlgorithmToken = mock.issueToken('old', { iat: now, auth_time: now, exp: now + 100 }).then((token) => {
    const [, payload, signature] = token.split('.');
    const header = Buffer.from(JSON.stringify({ alg: 'RS384', kid: 'old', typ: 'JWT' })).toString('base64url');
    return `${header}.${payload}.${signature}`;
  });
  const cases: Array<[string, Promise<string>, RegExp]> = [
    ['algorithm', unsupportedAlgorithmToken, /algorithm/],
    ['issuer', mock.issueToken('old', { iat: now, auth_time: now, exp: now + 100, iss: 'https://evil.example' }), /issuer/],
    ['audience', mock.issueToken('old', { iat: now, auth_time: now, exp: now + 100, aud: 'other-client' }), /audience/],
    ['nonce', mock.issueToken('old', { iat: now, auth_time: now, exp: now + 100, nonce: 'other' }), /nonce/],
    ['stale auth', mock.issueToken('old', { iat: now, auth_time: now - 601, exp: now + 100 }), /authentication is stale/],
    ['future iat', mock.issueToken('old', { iat: now + 6, auth_time: now, exp: now + 100 }), /issued in the future/],
    ['expired', mock.issueToken('old', { iat: now - 100, auth_time: now - 100, exp: now - 6 }), /expired/],
  ];
  for (const [label, tokenPromise, expected] of cases) {
    const token = await tokenPromise;
    await assert.rejects(() => validator.validate(token, provider, 'expected-nonce', now), expected, label);
  }
});

test('multiple audiences require this OIDC client as authorized party', async () => {
  mock.publish('old');
  const now = 1_900_002_000;
  const validator = new OidcIdTokenValidator({
    jwksCacheSeconds: 60, maxAuthAgeSeconds: 600, clockToleranceSeconds: 0,
  });
  const claims = {
    iat: now, auth_time: now, exp: now + 100, aud: [provider.audience, 'other-client'],
  };
  await assert.rejects(
    () => mock.issueToken('old', claims).then((token) =>
      validator.validate(token, provider, 'expected-nonce', now)),
    /authorized party/,
  );
  await assert.rejects(
    () => mock.issueToken('old', { ...claims, azp: 'other-client' }).then((token) =>
      validator.validate(token, provider, 'expected-nonce', now)),
    /authorized party/,
  );
  const valid = await mock.issueToken('old', { ...claims, azp: provider.clientId });
  await validator.validate(valid, provider, 'expected-nonce', now);
});
