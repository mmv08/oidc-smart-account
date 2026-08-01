import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getAddress, hashTypedData, keccak256 } from 'viem';
import { loadConfig } from '../src/config.js';
import {
  actionRequestDigest, actionRequestOidcNonce, intentDigest, intentTypes, materializeIntent,
  providerPolicyId, type ActionRequest,
} from '../src/intent.js';

const privateKey = `0x${'11'.repeat(32)}` as const;
const verifier = getAddress('0x000000000000000000000000000000000000CcCC');
const baseEnv = {
  PUBLIC_ORIGIN: 'https://attestor.example', ATTESTOR_PRIVATE_KEY: privateKey,
  CHALLENGE_TTL_SECONDS: '300', MAX_AUTH_AGE_SECONDS: '600',
  CHAIN_ID: '31337', EIP712_VERIFYING_CONTRACT: verifier, ATTESTOR_EPOCH: '7',
  FACTORY_ADDRESS: '0x000000000000000000000000000000000000bBbB',
  RECOVERY_MANAGER_ADDRESS: '0x000000000000000000000000000000000000dDdD',
  RECOVERY_DELAY_SECONDS: '86400',
  MAX_ATTESTATION_TTL_SECONDS: '3600',
  GOOGLE_CLIENT_ID: 'google-client', GOOGLE_CLIENT_SECRET: 'google-secret',
  APPLE_CLIENT_ID: 'com.example.web', APPLE_CLIENT_SECRET: 'apple-client-secret',
};
const request: ActionRequest = {
  version: 1,
  account: getAddress('0x000000000000000000000000000000000000aAaA'), chainId: 31337n,
  controller: getAddress('0x000000000000000000000000000000000000bBbB'), action: 'CREATE',
  currentSignerHash: `0x${'00'.repeat(32)}`,
  newSigner: '0x000000000000000000000000000000000000dEaD',
  newSignerHash: keccak256('0x000000000000000000000000000000000000dEaD'),
  recoveryNonce: 0n, intentNonce: `0x${'34'.repeat(32)}`,
  identityCommitment: `0x${'56'.repeat(32)}`, providerId: providerPolicyId('google-client-policy-v1'),
  recoveryDelay: 0n, issuedAt: 1_900_000_000n,
  attestationTtl: 3600n, attestorEpoch: 7n,
};

test('configuration pins Google and Apple plus the deployed EIP-712 verifier policy', () => {
  const config = loadConfig(baseEnv);
  assert.equal(config.providers.google.issuer, 'https://accounts.google.com');
  assert.equal(config.providers.google.audience, 'google-client');
  assert.equal(config.providers.google.authorizationEndpoint, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.equal(config.providers.apple.issuer, 'https://appleid.apple.com');
  assert.equal(config.providers.apple.audience, 'com.example.web');
  assert.deepEqual(config.providers.google.allowedAlgorithms, ['RS256']);
  assert.equal(config.providers.google.providerId, providerPolicyId('google-client-policy-v1'));
  assert.equal(config.scope, 'openid');
  assert.equal(config.verifyingContract, verifier);
  assert.equal(config.chainId, 31337n);
  assert.equal(config.attestorEpoch, 7n);
});

test('configuration rejects HTTP production origins and missing provider secrets', () => {
  assert.throws(() => loadConfig({ ...baseEnv, PUBLIC_ORIGIN: 'http://attestor.example' }), /HTTPS/);
  assert.throws(() => loadConfig({ ...baseEnv, GOOGLE_CLIENT_SECRET: '' }), /GOOGLE_CLIENT_SECRET/);
});

test('OIDC nonce binds every on-chain action field and provider policy', () => {
  const digest = actionRequestDigest(request, verifier);
  const nonce = actionRequestOidcNonce(request, verifier);
  assert.match(digest, /^0x[0-9a-f]{64}$/);
  assert.equal(digest, '0x1fcaaf4f7325eb077e92f3d9f39ba6a2331582b223e1ceecae10a093f52118f0');
  assert.match(nonce, /^[A-Za-z0-9_-]{43}$/);
  for (const changed of [
    { ...request, chainId: 1n }, { ...request, action: 'ADD' as const },
    { ...request, providerId: providerPolicyId('other') },
    { ...request, newSignerHash: `0x${'13'.repeat(32)}` as const },
  ]) {
    assert.notEqual(actionRequestDigest(changed, verifier), digest);
    assert.notEqual(actionRequestOidcNonce(changed, verifier), nonce);
  }
  // Controller delay is immutable deployment metadata. The common validity window and
  // attestor epoch must be identical across independent attestors and login-bound.
  assert.equal(actionRequestDigest({ ...request, recoveryDelay: 1n }, verifier), digest);
  assert.notEqual(actionRequestDigest({ ...request, attestationTtl: 1n }, verifier), digest);
  assert.notEqual(actionRequestDigest({ ...request, attestorEpoch: 99n }, verifier), digest);
  assert.notEqual(actionRequestDigest({ ...request, issuedAt: request.issuedAt + 1n }, verifier), digest);
});

test('typed intent exactly matches IdentityIntentVerifier Solidity field order and domain', () => {
  const intent = materializeIntent(request);
  const expected = hashTypedData({
    domain: { name: 'OIDC Identity Intent', version: '1', chainId: 31337n, verifyingContract: verifier },
    types: intentTypes,
    primaryType: 'Intent',
    message: { ...intent, action: 0 },
  });
  assert.equal(intentDigest(intent, verifier), expected);
  assert.deepEqual(Object.keys(intent), [
    'version', 'action', 'identityCommitment', 'account', 'controller', 'currentSignerHash',
    'newSignerHash', 'recoveryNonce', 'intentNonce', 'providerId', 'providerKeyHash',
    'issuedAt', 'validAfter', 'validUntil', 'chainId', 'attestorEpoch',
  ]);
  assert.equal(intent.validAfter, 1_900_000_000n);
  assert.equal(intent.validUntil, 1_900_003_600n);
  assert.equal(intent.providerKeyHash, `0x${'00'.repeat(32)}`);
});
