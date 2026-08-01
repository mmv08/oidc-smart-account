import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getAddress, keccak256 } from 'viem';
import { canonicalRsaJwk, describeProviderKey } from '../src/jwk.js';
import { materializeIntent, providerPolicyId, type ActionRequest } from '../src/intent.js';
import { InMemoryStorage, sha256Hex, type Identity } from '../src/storage.js';

const account = getAddress('0x000000000000000000000000000000000000aAaA');
const identity: Identity = { issuer: 'https://issuer.example', audience: 'client-id', subject: 'private-subject' };
const baseRequest: ActionRequest = {
  version: 1,
  account,
  chainId: 1n,
  controller: getAddress('0x000000000000000000000000000000000000bBbB'),
  action: 'CREATE',
  currentSignerHash: `0x${'00'.repeat(32)}`,
  newSigner: '0x000000000000000000000000000000000000dEaD',
  newSignerHash: keccak256('0x000000000000000000000000000000000000dEaD'),
  recoveryNonce: 0n,
  intentNonce: `0x${'34'.repeat(32)}`,
  identityCommitment: `0x${'56'.repeat(32)}`,
  providerId: providerPolicyId('test-policy'),
  recoveryDelay: 0n,
  issuedAt: 1000n,
  attestationTtl: 7200n,
  attestorEpoch: 1n,
};

function challenge(request: ActionRequest = baseRequest, id = 'challenge-1', state = 'state') {
  return {
    id, provider: 'google' as const, request,
    stateHash: sha256Hex(state), pkceVerifier: 'pkce', oidcNonce: 'oidc-nonce',
    createdAt: 1000, expiresAt: 1300, status: 'pending' as const,
  };
}

test('RSA JWK thumbprint and provider key hash use RFC 7638 canonical public material', () => {
  const jwk = { n: 'abc123', use: 'sig', e: 'AQAB', kid: 'rotating-kid', alg: 'RS256', kty: 'RSA' };
  assert.equal(canonicalRsaJwk(jwk), '{"e":"AQAB","kty":"RSA","n":"abc123"}');
  assert.deepEqual(describeProviderKey(jwk), {
    canonicalJwk: '{"e":"AQAB","kty":"RSA","n":"abc123"}',
    thumbprint: 'LFauQ0kmRyfDV3dEgm-Vq2uelUMZmw92C5bzcUrfkE8',
    providerKeyHash: '0x2c56ae4349264727c3577744826f95ab6b9e9543199b0f760b96f3714adf904f',
  });
  assert.throws(() => canonicalRsaJwk({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }), /RSA/);
});

test('CREATE atomically binds an opaque account commitment while recovery requires exact identity', async () => {
  const storage = new InMemoryStorage();
  await storage.createChallenge(challenge());
  const claimed = await storage.claimCallback(sha256Hex('state'), 1100);
  assert.equal(claimed.id, 'challenge-1');
  await storage.completeAuthentication({
    challengeId: claimed.id,
    identity,
    tokenDigest: sha256Hex('jwt-one'),
    providerKeyHash: `0x${'78'.repeat(32)}`,
    providerKeyThumbprint: 'thumbprint', tokenIssuedAt: 1100,
    confirmationSecretHash: sha256Hex('confirmation-secret'),
    csrfHash: sha256Hex('csrf'),
    authenticatedAt: 1100,
    intent: materializeIntent(baseRequest),
  });

  const binding = await storage.getIdentityBinding(account, baseRequest.identityCommitment);
  assert.deepEqual(binding, identity);
  const stored = await storage.getChallengeForConfirmation('challenge-1', sha256Hex('confirmation-secret'), 1101);
  assert.equal(stored.status, 'authenticated');
  assert.equal('identity' in stored, false, 'confirmation records must not expose subject/identity');

  const recovery = { ...baseRequest, action: 'REPLACE' as const, intentNonce: `0x${'57'.repeat(32)}` as const };
  await storage.createChallenge(challenge(recovery, 'challenge-2', 'state-2'));
  await storage.claimCallback(sha256Hex('state-2'), 1100);
  await storage.completeAuthentication({
    challengeId: 'challenge-2', identity,
    tokenDigest: sha256Hex('jwt-two'), providerKeyHash: `0x${'78'.repeat(32)}`,
    providerKeyThumbprint: 'thumbprint', tokenIssuedAt: 1100, confirmationSecretHash: sha256Hex('second-secret'),
    csrfHash: sha256Hex('second-csrf'), authenticatedAt: 1100,
    intent: materializeIntent(recovery),
  });

  const wrongIdentity = { ...identity, subject: 'another-subject' };
  const wrongRecovery = { ...recovery, intentNonce: `0x${'58'.repeat(32)}` as const };
  await storage.createChallenge(challenge(wrongRecovery, 'challenge-3', 'state-3'));
  await storage.claimCallback(sha256Hex('state-3'), 1100);
  await assert.rejects(() => storage.completeAuthentication({
    challengeId: 'challenge-3', identity: wrongIdentity,
    tokenDigest: sha256Hex('jwt-three'), providerKeyHash: `0x${'78'.repeat(32)}`,
    providerKeyThumbprint: 'thumbprint', tokenIssuedAt: 1100, confirmationSecretHash: sha256Hex('third-secret'),
    csrfHash: sha256Hex('third-csrf'), authenticatedAt: 1100,
    intent: materializeIntent(wrongRecovery),
  }), /identity binding mismatch/);
});

test('storage enforces exact state, expiry, token replay, and single-use callback and confirmation', async () => {
  const storage = new InMemoryStorage();
  await storage.createChallenge(challenge());
  await assert.rejects(() => storage.claimCallback(sha256Hex('wrong-state'), 1100), /invalid state/);
  await assert.rejects(() => storage.claimCallback(sha256Hex('state'), 1301), /expired/);

  const fresh = challenge(baseRequest, 'challenge-fresh', 'fresh-state');
  await storage.createChallenge(fresh);
  await storage.claimCallback(fresh.stateHash, 1100);
  await assert.rejects(() => storage.claimCallback(fresh.stateHash, 1100), /already used/);
  const authentication = {
    challengeId: fresh.id, identity, tokenDigest: sha256Hex('replayed-jwt'),
    providerKeyHash: `0x${'78'.repeat(32)}` as const, providerKeyThumbprint: 'thumbprint', tokenIssuedAt: 1100,
    confirmationSecretHash: sha256Hex('secret'), csrfHash: sha256Hex('csrf'), authenticatedAt: 1100,
    intent: materializeIntent(baseRequest),
  };
  await storage.completeAuthentication(authentication);
  await storage.consumeConfirmation(fresh.id, sha256Hex('secret'), sha256Hex('csrf'), 1101);
  await assert.rejects(() => storage.consumeConfirmation(fresh.id, sha256Hex('secret'), sha256Hex('csrf'), 1101), /already confirmed/);

  const another = challenge(baseRequest, 'challenge-2', 'state-2');
  await storage.createChallenge(another);
  await storage.claimCallback(another.stateHash, 1100);
  await assert.rejects(() => storage.completeAuthentication({ ...authentication, challengeId: another.id }), /token replay/);
});
