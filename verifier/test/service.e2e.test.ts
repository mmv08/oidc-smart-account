import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { getAddress, keccak256, recoverTypedDataAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import type { VerifierConfig } from '../src/config.js';
import {
  actionRequestDigest, attestationTypedData, intentDigest, providerPolicyId,
  type ActionRequest, type Intent,
} from '../src/intent.js';
import { createVerifierApp } from '../src/service.js';
import { InMemoryStorage } from '../src/storage.js';
import { MockOidcProvider } from './mock-oidc.js';

const now = 1_900_100_000;
const attestorPrivateKey = `0x${'11'.repeat(32)}` as const;
const verifyingContract = getAddress('0x000000000000000000000000000000000000CcCC');
const mock = new MockOidcProvider();
let config: VerifierConfig;

before(async () => {
  await mock.start();
  await mock.addKey('e2e-key');
  mock.publish('e2e-key');
  mock.now = now;
  const common = {
    issuer: mock.issuer, audience: mock.audience, clientId: mock.audience, clientSecret: 'secret',
    authorizationEndpoint: `${mock.issuer}/authorize`, tokenEndpoint: `${mock.issuer}/token`,
    jwksUri: `${mock.issuer}/jwks`, allowedAlgorithms: ['RS256'] as const,
    revokedKeyThumbprints: new Set<string>(),
  };
  config = {
    publicOrigin: 'https://attestor.example', attestorPrivateKey, chainId: 31337n,
    factoryAddress: getAddress('0x000000000000000000000000000000000000bBbB'),
    recoveryManagerAddress: getAddress('0x000000000000000000000000000000000000dDdD'),
    recoveryDelaySeconds: 86400,
    verifyingContract, attestorEpoch: 1n, maxAttestationTtlSeconds: 172800,
    challengeTtlSeconds: 300, maxAuthAgeSeconds: 600, jwksCacheSeconds: 60,
    clockToleranceSeconds: 0, scope: 'openid',
    providers: {
      google: { ...common, name: 'google', policy: 'google-test-policy', providerId: providerPolicyId('google-test-policy') },
      apple: { ...common, name: 'apple', policy: 'apple-test-policy', providerId: providerPolicyId('apple-test-policy') },
    },
  };
});
after(async () => mock.stop());

function requestIntent(policy = 'google-test-policy'): Record<string, string | number> {
  return {
    version: 1,
    account: getAddress('0x000000000000000000000000000000000000aAaA'),
    chainId: '31337',
    controller: getAddress('0x000000000000000000000000000000000000bBbB'),
    action: 'CREATE',
    currentSignerHash: `0x${'00'.repeat(32)}`,
    newSigner: '0x000000000000000000000000000000000000dEaD',
    newSignerHash: keccak256('0x000000000000000000000000000000000000dEaD'),
    recoveryNonce: '0',
    intentNonce: `0x${'34'.repeat(32)}`,
    identityCommitment: `0x${'56'.repeat(32)}`,
    providerId: providerPolicyId(policy),
    recoveryDelay: '0',
    issuedAt: String(now),
    attestationTtl: '3600',
    attestorEpoch: '1',
  };
}

function parseActionRequest(value: Record<string, string | number>): ActionRequest {
  return {
    ...value,
    account: getAddress(String(value.account)),
    controller: getAddress(String(value.controller)),
    chainId: BigInt(value.chainId!),
    version: Number(value.version) as 1,
    action: value.action as ActionRequest['action'],
    recoveryNonce: BigInt(value.recoveryNonce!),
    recoveryDelay: BigInt(value.recoveryDelay!), issuedAt: BigInt(value.issuedAt!),
    attestationTtl: BigInt(value.attestationTtl!),
    attestorEpoch: BigInt(value.attestorEpoch!),
  } as ActionRequest;
}

function parseIntent(value: Record<string, string>): Intent {
  return {
    ...value, version: Number(value.version), account: getAddress(value.account!), controller: getAddress(value.controller!),
    action: value.action as Intent['action'], recoveryNonce: BigInt(value.recoveryNonce!),
    issuedAt: BigInt(value.issuedAt!), validAfter: BigInt(value.validAfter!), validUntil: BigInt(value.validUntil!),
    chainId: BigInt(value.chainId!), attestorEpoch: BigInt(value.attestorEpoch!),
  } as Intent;
}

test('authorization-code + PKCE login, explicit confirmation, and typed attestation work end to end', async () => {
  const storage = new InMemoryStorage();
  const app = createVerifierApp({ config, storage, clock: () => now, logger: false });
  const challengeResponse = await app.inject({
    method: 'POST', url: '/v1/challenges', payload: { provider: 'google', request: requestIntent() },
  });
  assert.equal(challengeResponse.statusCode, 201, challengeResponse.body);
  const challenge = challengeResponse.json() as { challengeId: string; authorizationUrl: string; expiresAt: number; requestHash: string };
  assert.equal(challenge.requestHash, actionRequestDigest(parseActionRequest(requestIntent()), verifyingContract));
  const authorizationUrl = new URL(challenge.authorizationUrl);
  assert.equal(authorizationUrl.searchParams.get('scope'), 'openid');
  assert.equal(authorizationUrl.searchParams.get('response_type'), 'code');
  assert.equal(authorizationUrl.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authorizationUrl.searchParams.get('max_age'), String(config.maxAuthAgeSeconds));
  assert.equal(authorizationUrl.searchParams.has('email'), false);
  assert.equal(authorizationUrl.searchParams.has('profile'), false);
  assert.match(authorizationUrl.searchParams.get('nonce')!, /^[A-Za-z0-9_-]{43}$/);

  const authorization = await fetch(challenge.authorizationUrl, { redirect: 'manual' });
  assert.equal(authorization.status, 302);
  const callbackUrl = new URL(authorization.headers.get('location')!);
  const callback = await app.inject({ method: 'GET', url: `${callbackUrl.pathname}${callbackUrl.search}` });
  assert.equal(callback.statusCode, 303, callback.body);
  assert.equal(callback.headers.location, `/v1/confirm/${challenge.challengeId}`);
  const cookie = String(callback.headers['set-cookie']).split(';')[0]!;
  assert.match(cookie, /^oidc_confirmation=/);
  assert.equal(callback.body.includes('private-subject'), false);

  const confirmation = await app.inject({
    method: 'GET', url: callback.headers.location!, headers: { cookie },
  });
  assert.equal(confirmation.statusCode, 200, confirmation.body);
  assert.match(confirmation.headers['content-security-policy']!, /default-src 'none'/);
  assert.match(confirmation.body, /CREATE/);
  assert.match(confirmation.body, /31337/);
  assert.match(confirmation.body, /Address signer/);
  assert.match(confirmation.body, new RegExp(String(requestIntent().newSignerHash)));
  assert.match(confirmation.body, new RegExp(String(requestIntent().newSigner)));
  assert.match(confirmation.body, new RegExp(String(requestIntent().providerId)));
  assert.match(confirmation.body, new RegExp(String(requestIntent().intentNonce)));
  assert.match(confirmation.body, new RegExp(String(requestIntent().identityCommitment)));
  assert.match(confirmation.body, new RegExp(verifyingContract));
  assert.match(confirmation.body, /1900100000/);
  assert.match(confirmation.body, /1900103600/);
  assert.match(confirmation.body, /not applicable/);
  const csrf = confirmation.body.match(/name="csrf" value="([A-Za-z0-9_-]+)"/)?.[1];
  assert.ok(csrf);

  const wrong = await app.inject({
    method: 'POST', url: callback.headers.location!, headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ csrf, fingerprintSuffix: 'deadbeef' }).toString(),
  });
  assert.equal(wrong.statusCode, 400);

  const confirmed = await app.inject({
    method: 'POST', url: callback.headers.location!, headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ csrf, fingerprintSuffix: String(requestIntent().newSignerHash).slice(-8) }).toString(),
  });
  assert.equal(confirmed.statusCode, 200, confirmed.body);
  const attestation = confirmed.json() as {
    intent: Record<string, string>; intentDigest: `0x${string}`; signature: `0x${string}`;
    packedAttestation: `0x${string}`; attestor: `0x${string}`;
    providerKeyHash: `0x${string}`; tokenIssuedAt: number; providerKeyThumbprint: string;
  };
  const signedIntent = parseIntent(attestation.intent);
  assert.equal(attestation.intentDigest, intentDigest(signedIntent, verifyingContract));
  assert.equal(attestation.attestor, privateKeyToAccount(attestorPrivateKey).address);
  assert.equal(
    await recoverTypedDataAddress({
      ...attestationTypedData(
        attestation.intentDigest,
        attestation.providerKeyHash,
        BigInt(attestation.tokenIssuedAt),
        signedIntent,
        verifyingContract,
      ),
      signature: attestation.signature,
    }),
    attestation.attestor,
  );
  assert.match(attestation.providerKeyHash, /^0x[0-9a-f]{64}$/);
  assert.match(attestation.packedAttestation, /^0x[0-9a-f]+$/);
  assert.equal(signedIntent.providerKeyHash, `0x${'00'.repeat(32)}`);
  const publicJson = JSON.stringify(attestation);
  for (const forbidden of ['private-subject', 'access_token', 'id_token', 'authorization_code', 'email']) {
    assert.equal(publicJson.includes(forbidden), false, `public response leaked ${forbidden}`);
  }

  const duplicate = await app.inject({
    method: 'POST', url: callback.headers.location!, headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ csrf, fingerprintSuffix: String(requestIntent().newSignerHash).slice(-8) }).toString(),
  });
  assert.equal(duplicate.statusCode, 409);
  await app.close();
});

test('challenge rejects provider-policy mismatch and Apple authorization remains configuration driven', async () => {
  const app = createVerifierApp({ config, storage: new InMemoryStorage(), clock: () => now, logger: false });
  const mismatch = await app.inject({ method: 'POST', url: '/v1/challenges', payload: { provider: 'google', request: requestIntent('wrong-policy') } });
  assert.equal(mismatch.statusCode, 400);
  const apple = await app.inject({
    method: 'POST', url: '/v1/challenges',
    payload: { provider: 'apple', request: requestIntent('apple-test-policy') },
  });
  assert.equal(apple.statusCode, 201, apple.body);
  const url = new URL((apple.json() as { authorizationUrl: string }).authorizationUrl);
  assert.equal(url.origin, mock.issuer);
  assert.equal(url.searchParams.get('client_id'), mock.audience);
  assert.equal(url.searchParams.get('scope'), 'openid');
  await app.close();
});

test('challenge pins signer preimage, action controller, and immutable recovery delay', async () => {
  const app = createVerifierApp({ config, storage: new InMemoryStorage(), clock: () => now, logger: false });
  const recovery = {
    ...requestIntent(),
    action: 'ADD',
    controller: config.recoveryManagerAddress,
    currentSignerHash: `0x${'99'.repeat(32)}`,
    recoveryNonce: '1',
    recoveryDelay: String(config.recoveryDelaySeconds),
  };
  const accepted = await app.inject({
    method: 'POST', url: '/v1/challenges', payload: { provider: 'google', request: recovery },
  });
  assert.equal(accepted.statusCode, 201, accepted.body);

  for (const invalid of [
    { ...recovery, controller: config.factoryAddress },
    { ...recovery, recoveryDelay: '1' },
    { ...recovery, newSignerHash: `0x${'13'.repeat(32)}` },
  ]) {
    const response = await app.inject({
      method: 'POST', url: '/v1/challenges', payload: { provider: 'google', request: invalid },
    });
    assert.equal(response.statusCode, 400, response.body);
  }
  await app.close();
});

test('health endpoint is public but never cacheable', async () => {
  const app = createVerifierApp({ config, storage: new InMemoryStorage(), clock: () => now, logger: false });
  const response = await app.inject({ method: 'GET', url: '/healthz' });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { status: 'ok' });
  assert.equal(response.headers['cache-control'], 'no-store');
  await app.close();
});

test('callback rejects state mismatch without reflecting authorization codes', async () => {
  const app = createVerifierApp({ config, storage: new InMemoryStorage(), clock: () => now, logger: false });
  const response = await app.inject({ method: 'GET', url: '/v1/oidc/callback?state=wrong&code=super-secret-code' });
  assert.equal(response.statusCode, 400);
  assert.equal(response.body.includes('super-secret-code'), false);
  await app.close();
});
