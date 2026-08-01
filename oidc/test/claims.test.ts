import assert from 'node:assert/strict';
import test from 'node:test';
import {
  APPLE_PROVIDER,
  GOOGLE_PROVIDER,
  identityCommitment,
  normalizeGoogleOrAppleClaims,
  providerPolicyId,
} from '../src/claims.js';

const nonce = `0x${'11'.repeat(32)}` as const;
const salt = `0x${'22'.repeat(32)}` as const;

for (const issuer of ['https://accounts.google.com', 'accounts.google.com']) {
  test(`normalizes Google issuer ${issuer} and ignores mutable profile claims`, () => {
    const result = normalizeGoogleOrAppleClaims({
      claims: {
        iss: issuer,
        aud: 'google-client.apps.googleusercontent.com',
        sub: 'stable-google-subject',
        nonce,
        iat: 1_700_000_000,
        exp: 1_700_003_600,
        email: 'mutable@example.com',
      },
      provider: 'google',
      clientId: 'google-client.apps.googleusercontent.com',
      identitySalt: salt,
      now: 1_700_000_100,
      maxClaimAgeSeconds: 600,
    });

    assert.equal(result.providerId, GOOGLE_PROVIDER);
    assert.equal(result.nonce, nonce);
    assert.equal(result.issuedAt, 1_700_000_000);
    assert.equal(result.expiresAt, 1_700_003_600);
  });
}

test('normalizes an Apple claim using the stable subject rather than email', () => {
  const result = normalizeGoogleOrAppleClaims({
    claims: {
      iss: 'https://appleid.apple.com',
      aud: 'com.example.web',
      sub: 'stable-apple-subject',
      nonce,
      iat: 1_700_000_000,
      exp: 1_700_003_600,
      email: 'private-relay@privaterelay.appleid.com',
    },
    provider: 'apple',
    clientId: 'com.example.web',
    identitySalt: salt,
    now: 1_700_000_100,
    maxClaimAgeSeconds: 600,
  });

  assert.equal(result.providerId, APPLE_PROVIDER);
  assert.equal(
    result.providerPolicyId,
    '0xe3c5dbf05f1a583c83a9570ac37062708e7d6b2e6c115b15b1b85cdaf6340f74',
  );
  assert.equal(
    result.providerPolicyId,
    providerPolicyId(APPLE_PROVIDER, 'com.example.web'),
  );
  assert.equal(
    result.identityCommitment,
    '0xc401ed12736235e53dd81955260dc3ac300bea63dd01e496fe23c370387650ba',
  );
  assert.equal(
    result.identityCommitment,
    identityCommitment(result.providerPolicyId, 'stable-apple-subject', salt),
  );
});

test('accepts an explicitly configured Google hybrid authorized party and binds it into policy', () => {
  const result = normalizeGoogleOrAppleClaims({
    claims: {
      iss: 'https://accounts.google.com',
      aud: 'server.apps.googleusercontent.com',
      azp: 'android.apps.googleusercontent.com',
      sub: 'stable-google-subject', nonce, iat: 1_700_000_000, exp: 1_700_003_600,
    },
    provider: 'google',
    clientId: 'server.apps.googleusercontent.com',
    authorizedParty: 'android.apps.googleusercontent.com',
    identitySalt: salt,
    now: 1_700_000_100,
    maxClaimAgeSeconds: 600,
  });

  assert.equal(
    result.providerPolicyId,
    providerPolicyId(
      GOOGLE_PROVIDER,
      'server.apps.googleusercontent.com',
      'android.apps.googleusercontent.com',
    ),
  );
  assert.notEqual(
    result.providerPolicyId,
    providerPolicyId(GOOGLE_PROVIDER, 'server.apps.googleusercontent.com'),
  );
});

test('requires azp for a multi-audience Google token', () => {
  assert.throws(
    () => normalizeGoogleOrAppleClaims({
      claims: {
        iss: 'https://accounts.google.com',
        aud: ['google-client.apps.googleusercontent.com', 'other-client'],
        sub: 'stable-google-subject', nonce, iat: 1_700_000_000, exp: 1_700_003_600,
      },
      provider: 'google', clientId: 'google-client.apps.googleusercontent.com',
      identitySalt: salt, now: 1_700_000_100, maxClaimAgeSeconds: 600,
    }),
    /authorized party/,
  );
});

test('rejects invalid clocks and timing values instead of relying on JavaScript coercion', () => {
  const base = {
    iss: 'https://appleid.apple.com', aud: 'com.example.web', sub: 'stable-apple-subject',
    nonce, iat: 1_700_000_000, exp: 1_700_003_600,
  };
  const input = {
    claims: base, provider: 'apple' as const, clientId: 'com.example.web', identitySalt: salt,
    now: 1_700_000_100, maxClaimAgeSeconds: 600,
  };

  assert.throws(
    () => normalizeGoogleOrAppleClaims({ ...input, now: Number.NaN }),
    /clock configuration/,
  );
  assert.throws(
    () => normalizeGoogleOrAppleClaims({ ...input, maxClaimAgeSeconds: Number.NaN }),
    /clock configuration/,
  );
  assert.throws(
    () => normalizeGoogleOrAppleClaims({
      ...input,
      claims: { ...base, iat: Number.MAX_SAFE_INTEGER + 1 },
    }),
    /timing/,
  );
});

test('rejects wrong issuer audience nonce timing and missing subject', () => {
  const base = {
    iss: 'https://appleid.apple.com', aud: 'com.example.web', sub: 'stable-apple-subject',
    nonce, iat: 1_700_000_000, exp: 1_700_003_600,
  };
  const normalize = (claims: Record<string, unknown>) => normalizeGoogleOrAppleClaims({
    claims, provider: 'apple', clientId: 'com.example.web', identitySalt: salt,
    now: 1_700_000_100, maxClaimAgeSeconds: 600,
  });

  assert.throws(() => normalize({ ...base, iss: 'https://attacker.example' }), /issuer/);
  assert.throws(() => normalize({ ...base, aud: 'other-client' }), /audience/);
  assert.throws(() => normalize({ ...base, nonce: 'not-a-digest' }), /nonce/);
  assert.throws(() => normalize({ ...base, iat: 1_699_000_000 }), /stale/);
  assert.throws(() => normalize({ ...base, exp: 1_700_000_100 }), /expired/);
  assert.throws(() => normalize({ ...base, sub: '' }), /subject/);
});
