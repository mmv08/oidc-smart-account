import { createServer } from 'node:http';
import { getAddress, keccak256, type Address, type Hex } from 'viem';
import { recoveryDigest, type RecoveryRequest } from '../../src/actions.js';
import { directGoogleJWTProof } from '../../src/proofs.js';
import {
  createGoogleAuthorizationRequest,
  discoverGoogleOIDC,
  redeemGoogleAuthorizationCode,
  type GoogleAuthorizationRequest,
} from './oidc.js';

interface PendingLogin extends GoogleAuthorizationRequest {
  request: RecoveryRequest;
  actionDigest: Hex;
  createdAt: number;
}

const config = readConfig(process.env);
const endpoints = await discoverGoogleOIDC();
const pending = new Map<string, PendingLogin>();

const server = createServer((request, response) => {
  void handleRequest(request.url ?? '/').catch((error: unknown) => {
    response.statusCode = 400;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({
      error: error instanceof Error ? error.message : 'request failed',
    }));
  });

  async function handleRequest(rawUrl: string): Promise<void> {
    const url = new URL(rawUrl, config.localOrigin);
    if (url.pathname === '/') {
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.end('<h1>Google OIDC recovery example</h1><p><a href="/login">Authorize recovery</a></p>');
      return;
    }

    if (url.pathname === '/login') {
      const now = Math.floor(Date.now() / 1000);
      const recoveryRequest: RecoveryRequest = {
        account: config.account,
        expectedSignerHash: config.expectedSignerHash,
        expectedSignerEpoch: config.expectedSignerEpoch,
        newSignerHash: config.newSignerHash,
        nonce: config.recoveryNonce,
        validAfter: BigInt(now),
        validUntil: BigInt(now + config.requestLifetimeSeconds),
      };
      const actionDigest = recoveryDigest(
        recoveryRequest,
        config.chainId,
        config.recoveryController,
      );
      const authorization = await createGoogleAuthorizationRequest({
        endpoints,
        clientId: config.googleClientId,
        redirectUri: config.redirectUri,
        nonce: actionDigest,
      });
      pending.set(authorization.state, {
        ...authorization,
        request: recoveryRequest,
        actionDigest,
        createdAt: now,
      });
      response.statusCode = 302;
      response.setHeader('location', authorization.url.toString());
      response.end();
      return;
    }

    if (url.pathname === '/callback') {
      const oauthError = url.searchParams.get('error');
      if (oauthError) throw new Error(`Google authorization failed: ${oauthError}`);
      const state = url.searchParams.get('state');
      const code = url.searchParams.get('code');
      if (!state || !code) throw new Error('callback is missing code or state');
      const login = pending.get(state);
      pending.delete(state);
      if (!login) throw new Error('unknown or already consumed OAuth state');
      if (Math.floor(Date.now() / 1000) - login.createdAt > 600) {
        throw new Error('OAuth state expired');
      }

      const authenticated = await redeemGoogleAuthorizationCode({
        endpoints,
        clientId: config.googleClientId,
        clientSecret: config.googleClientSecret,
        redirectUri: config.redirectUri,
        code,
        codeVerifier: login.codeVerifier,
        expectedNonce: login.actionDigest,
        identitySalt: config.identitySalt,
        maxClaimAgeSeconds: config.maxClaimAgeSeconds,
      });

      // The raw token and direct proof remain server-side. Returning their hash demonstrates the
      // exact GoogleJWTVerifier encoding without leaking reusable identity material to the browser.
      const directProof = directGoogleJWTProof(authenticated.idToken, config.identitySalt);
      response.setHeader('content-type', 'application/json');
      response.end(stringifyJson({
        recoveryRequest: login.request,
        actionDigest: login.actionDigest,
        normalizedClaim: authenticated.normalizedClaim,
        directJWTProofHash: keccak256(directProof),
        nextStep:
          'Submit the server-held direct proof plus the replacement-signer proof to schedule(); do not expose the raw proof in browser output or logs.',
      }));
      return;
    }

    response.statusCode = 404;
    response.end('not found');
  }
});

server.listen(config.port, '127.0.0.1', () => {
  console.log(`Google recovery example listening on ${config.localOrigin}`);
  console.log(`Registered callback must be exactly ${config.redirectUri}`);
});

function readConfig(env: NodeJS.ProcessEnv) {
  const port = readInteger(env, 'PORT', 8787);
  const localOrigin = `http://127.0.0.1:${port}`;
  const redirectUri = env.GOOGLE_REDIRECT_URI ?? `${localOrigin}/callback`;
  if (redirectUri !== `${localOrigin}/callback`) {
    throw new Error(`GOOGLE_REDIRECT_URI must equal ${localOrigin}/callback for this example`);
  }
  return {
    port,
    localOrigin,
    redirectUri,
    googleClientId: required(env, 'GOOGLE_CLIENT_ID'),
    googleClientSecret: required(env, 'GOOGLE_CLIENT_SECRET'),
    chainId: BigInt(required(env, 'CHAIN_ID')),
    recoveryController: readAddress(env, 'RECOVERY_CONTROLLER_ADDRESS'),
    account: readAddress(env, 'ACCOUNT_ADDRESS'),
    expectedSignerHash: readBytes32(env, 'EXPECTED_SIGNER_HASH'),
    expectedSignerEpoch: BigInt(required(env, 'EXPECTED_SIGNER_EPOCH')),
    newSignerHash: readBytes32(env, 'NEW_SIGNER_HASH'),
    recoveryNonce: BigInt(required(env, 'RECOVERY_NONCE')),
    identitySalt: readBytes32(env, 'IDENTITY_SALT'),
    requestLifetimeSeconds: readInteger(env, 'REQUEST_LIFETIME_SECONDS', 600),
    maxClaimAgeSeconds: readInteger(env, 'MAX_CLAIM_AGE_SECONDS', 600),
  };
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value) throw new Error(`missing ${name}`);
  return value;
}


function readInteger(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const text = env[name];
  const value = text === undefined ? fallback : Number(text);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`invalid ${name}`);
  return value;
}

function readAddress(env: NodeJS.ProcessEnv, name: string): Address {
  return getAddress(required(env, name));
}

function readBytes32(env: NodeJS.ProcessEnv, name: string): Hex {
  const value = required(env, name);
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${name} must be bytes32 hex`);
  return value.toLowerCase() as Hex;
}

function stringifyJson(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) =>
    typeof item === 'bigint' ? item.toString() : item, 2);
}
