import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createDigest,
  createOidcNonce,
  recoveryDigest,
  recoveryOidcNonce,
  type CreateRequest,
  type RecoveryRequest,
} from '../src/actions.js';

const create: CreateRequest = {
  account: '0x1111111111111111111111111111111111111111',
  salt: `0x${'01'.repeat(32)}`,
  providerPolicyId: `0x${'02'.repeat(32)}`,
  identityCommitment: `0x${'03'.repeat(32)}`,
  initialSignerHash: `0x${'04'.repeat(32)}`,
  validAfter: 1_700_000_000n,
  validUntil: 1_700_000_600n,
};

const recovery: RecoveryRequest = {
  account: create.account,
  expectedSignerHash: `0x${'05'.repeat(32)}`,
  newSignerHash: `0x${'06'.repeat(32)}`,
  nonce: 7n,
  validAfter: create.validAfter,
  validUntil: create.validUntil,
};

test('OIDC nonce is the exact chain-and-controller-bound create digest', () => {
  const digest = createDigest(create, 1n, '0x2222222222222222222222222222222222222222');
  assert.equal(
    digest,
    '0x677f32e974fe77dca8ebabcec5fba3568dcc4dc151a979517fc1879e1321365a',
  );
  assert.equal(
    createOidcNonce(create, 1n, '0x2222222222222222222222222222222222222222'),
    digest,
  );
  assert.notEqual(
    digest,
    createDigest({ ...create, initialSignerHash: `0x${'ff'.repeat(32)}` }, 1n, '0x2222222222222222222222222222222222222222'),
  );
  assert.notEqual(digest, createDigest(create, 10n, '0x2222222222222222222222222222222222222222'));
});

test('OIDC nonce is the exact recovery digest and binds current signer state', () => {
  const controller = '0x3333333333333333333333333333333333333333';
  const digest = recoveryDigest(recovery, 1n, controller);
  assert.equal(
    digest,
    '0xd11febaa9f236538b9c92fec125317bacdec3c19430b67bb1ffde4c55d3ff2fb',
  );
  assert.equal(recoveryOidcNonce(recovery, 1n, controller), digest);
  assert.notEqual(
    digest,
    recoveryDigest({ ...recovery, expectedSignerHash: `0x${'ff'.repeat(32)}` }, 1n, controller),
  );
  assert.notEqual(digest, recoveryDigest({ ...recovery, nonce: 8n }, 1n, controller));
});
