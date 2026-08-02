import { createHash, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, customFetch, jwtVerify, type JWTPayload } from 'jose';
import type { Hex } from 'viem';
import {
  normalizeGoogleOrAppleClaims,
  type NormalizedOIDCClaim,
} from '../../src/claims.js';

const GOOGLE_ISSUER = 'https://accounts.google.com' as const;
const GOOGLE_LEGACY_ISSUER = 'accounts.google.com' as const;
const GOOGLE_DISCOVERY = `${GOOGLE_ISSUER}/.well-known/openid-configuration`;
const GOOGLE_AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const GOOGLE_JWKS_URI = 'https://www.googleapis.com/oauth2/v3/certs';
const NETWORK_TIMEOUT_MS = 10_000;
const MAX_METADATA_BYTES = 64 * 1024;
const MAX_TOKEN_RESPONSE_BYTES = 128 * 1024;
const MAX_JWKS_BYTES = 256 * 1024;
const trustedEndpoints = Symbol('trusted Google OIDC endpoints');

export interface GoogleOIDCEndpoints {
  issuer: typeof GOOGLE_ISSUER;
  authorizationEndpoint: URL;
  tokenEndpoint: URL;
  jwksUri: URL;
  readonly mode: 'google' | 'loopback-test';
  readonly [trustedEndpoints]: true;
}

export interface GoogleAuthorizationRequest {
  url: URL;
  state: string;
  codeVerifier: string;
}

export interface AuthenticatedGoogleClaim {
  normalizedClaim: NormalizedOIDCClaim;
  claims: JWTPayload;
  /** Keep server-side. Use directGoogleJWTProof for the included on-chain adapter. */
  idToken: string;
}

const jwksResolvers = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

/** Discover Google while pinning every security-sensitive endpoint to its audited value. */
export async function discoverGoogleOIDC(): Promise<GoogleOIDCEndpoints> {
  const metadata = await fetchMetadata(new URL(GOOGLE_DISCOVERY));
  assertMetadataIssuer(metadata);
  assertExactMetadataEndpoint(metadata, 'authorization_endpoint', GOOGLE_AUTHORIZATION_ENDPOINT);
  assertExactMetadataEndpoint(metadata, 'token_endpoint', GOOGLE_TOKEN_ENDPOINT);
  assertExactMetadataEndpoint(metadata, 'jwks_uri', GOOGLE_JWKS_URI);
  return trustedGoogleEndpoints();
}

/**
 * Test-only transport for an in-process provider. Every network endpoint must use the same
 * 127.0.0.1 origin; production code must use discoverGoogleOIDC().
 */
export async function discoverLoopbackGoogleOIDCForTests(
  discoveryUrl: URL,
): Promise<GoogleOIDCEndpoints> {
  assertLoopbackUrl(discoveryUrl);
  const metadata = await fetchMetadata(discoveryUrl);
  assertMetadataIssuer(metadata);
  const authorizationEndpoint = readEndpoint(metadata, 'authorization_endpoint');
  const tokenEndpoint = readEndpoint(metadata, 'token_endpoint');
  const jwksUri = readEndpoint(metadata, 'jwks_uri');
  for (const endpoint of [authorizationEndpoint, tokenEndpoint, jwksUri]) {
    assertLoopbackUrl(endpoint);
    if (endpoint.origin !== discoveryUrl.origin) {
      throw new Error('test OIDC endpoints must share one loopback origin');
    }
  }
  return {
    issuer: GOOGLE_ISSUER,
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri,
    mode: 'loopback-test',
    [trustedEndpoints]: true,
  };
}

export async function createGoogleAuthorizationRequest(input: {
  endpoints: GoogleOIDCEndpoints;
  clientId: string;
  redirectUri: string;
  nonce: Hex;
}): Promise<GoogleAuthorizationRequest> {
  assertTrustedEndpoints(input.endpoints);
  if (!input.clientId || !input.redirectUri) throw new Error('missing Google client configuration');
  if (!/^0x[0-9a-f]{64}$/.test(input.nonce)) throw new Error('OIDC nonce must be a lowercase bytes32');

  const state = randomBytes(32).toString('base64url');
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  const url = new URL(input.endpoints.authorizationEndpoint);
  url.search = new URLSearchParams({
    client_id: input.clientId,
    redirect_uri: input.redirectUri,
    response_type: 'code',
    scope: 'openid',
    state,
    nonce: input.nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    // Google documents select_account; it forces an account-choice UI but is not proof of
    // fresh credential entry. The simulated provider omits it because its interaction model
    // has no account chooser.
    ...(input.endpoints.mode === 'google' ? { prompt: 'select_account' } : {}),
  }).toString();
  return { url, state, codeVerifier };
}

export async function redeemGoogleAuthorizationCode(input: {
  endpoints: GoogleOIDCEndpoints;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  code: string;
  codeVerifier: string;
  expectedNonce: Hex;
  identitySalt: Hex;
  maxClaimAgeSeconds: number;
}): Promise<AuthenticatedGoogleClaim> {
  assertTrustedEndpoints(input.endpoints);
  if (!input.clientId || !input.clientSecret || !input.code || !input.codeVerifier) {
    throw new Error('missing Google token-exchange input');
  }
  const response = await fetch(input.endpoints.tokenEndpoint, {
    method: 'POST',
    redirect: 'manual',
    signal: AbortSignal.timeout(NETWORK_TIMEOUT_MS),
    headers: {
      accept: 'application/json',
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: input.code,
      redirect_uri: input.redirectUri,
      client_id: input.clientId,
      client_secret: input.clientSecret,
      code_verifier: input.codeVerifier,
    }),
  });
  if (response.status !== 200) {
    throw new Error(`Google token exchange failed with HTTP ${response.status}`);
  }
  const tokenSet = await readBoundedJson(response, MAX_TOKEN_RESPONSE_BYTES, 'Google token response');
  if (typeof tokenSet.id_token !== 'string') throw new Error('Google token response has no ID token');

  const verified = await jwtVerify(
    tokenSet.id_token,
    getJwksResolver(input.endpoints.jwksUri),
    {
      issuer: [input.endpoints.issuer, GOOGLE_LEGACY_ISSUER],
      audience: input.clientId,
      algorithms: ['RS256'],
    },
  );
  if (verified.protectedHeader.alg !== 'RS256') throw new Error('unexpected Google ID-token algorithm');

  const normalizedClaim = normalizeGoogleOrAppleClaims({
    claims: verified.payload,
    provider: 'google',
    clientId: input.clientId,
    identitySalt: input.identitySalt,
    now: Math.floor(Date.now() / 1000),
    maxClaimAgeSeconds: input.maxClaimAgeSeconds,
  });
  if (normalizedClaim.nonce !== input.expectedNonce) throw new Error('Google action nonce mismatch');

  return {
    normalizedClaim,
    claims: verified.payload,
    idToken: tokenSet.id_token,
  };
}

function trustedGoogleEndpoints(): GoogleOIDCEndpoints {
  return {
    issuer: GOOGLE_ISSUER,
    authorizationEndpoint: new URL(GOOGLE_AUTHORIZATION_ENDPOINT),
    tokenEndpoint: new URL(GOOGLE_TOKEN_ENDPOINT),
    jwksUri: new URL(GOOGLE_JWKS_URI),
    mode: 'google',
    [trustedEndpoints]: true,
  };
}

async function fetchMetadata(discoveryUrl: URL): Promise<Record<string, unknown>> {
  const response = await fetch(discoveryUrl, {
    redirect: 'manual',
    signal: AbortSignal.timeout(NETWORK_TIMEOUT_MS),
    headers: { accept: 'application/json' },
  });
  if (response.status !== 200) {
    throw new Error(`Google OIDC discovery failed with HTTP ${response.status}`);
  }
  return readBoundedJson(response, MAX_METADATA_BYTES, 'Google OIDC metadata');
}

async function readBoundedJson(
  response: Response,
  maxBytes: number,
  label: string,
): Promise<Record<string, unknown>> {
  const contentLength = response.headers.get('content-length');
  if (contentLength !== null && Number(contentLength) > maxBytes) {
    throw new Error(`${label} is too large`);
  }
  if (!response.body) throw new Error(`${label} has no body`);

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`${label} is too large`);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('not an object');
    }
    return parsed as Record<string, unknown>;
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function getJwksResolver(uri: URL): ReturnType<typeof createRemoteJWKSet> {
  const key = uri.toString();
  let resolver = jwksResolvers.get(key);
  if (!resolver) {
    resolver = createRemoteJWKSet(uri, {
      timeoutDuration: NETWORK_TIMEOUT_MS,
      cooldownDuration: 30_000,
      cacheMaxAge: 10 * 60_000,
      [customFetch]: async (url, options) => {
        if (url !== key) throw new Error('unexpected JWKS request URL');
        const response = await fetch(url, {
          ...options,
          redirect: 'manual',
        });
        if (response.status !== 200) {
          throw new Error(`Google JWKS fetch failed with HTTP ${response.status}`);
        }
        const jwks = await readBoundedJson(response, MAX_JWKS_BYTES, 'Google JWKS response');
        return Response.json(jwks);
      },
    });
    jwksResolvers.set(key, resolver);
  }
  return resolver;
}

function assertMetadataIssuer(metadata: Record<string, unknown>): void {
  if (metadata.issuer !== GOOGLE_ISSUER) throw new Error('unexpected Google discovery issuer');
}

function assertExactMetadataEndpoint(
  metadata: Record<string, unknown>,
  key: string,
  expected: string,
): void {
  const endpoint = readEndpoint(metadata, key);
  if (endpoint.toString() !== expected) {
    const label = key.replace('_endpoint', '').replace('_uri', '').replaceAll('_', ' ');
    throw new Error(`unexpected Google ${label} endpoint`);
  }
}

function readEndpoint(metadata: Record<string, unknown>, key: string): URL {
  const value = metadata[key];
  if (typeof value !== 'string') throw new Error(`Google discovery has no ${key}`);
  return new URL(value);
}

function assertTrustedEndpoints(endpoints: GoogleOIDCEndpoints): void {
  if (endpoints[trustedEndpoints] !== true) throw new Error('untrusted Google OIDC endpoints');
  if (endpoints.mode === 'google') {
    if (
      endpoints.issuer !== GOOGLE_ISSUER
      || endpoints.authorizationEndpoint.toString() !== GOOGLE_AUTHORIZATION_ENDPOINT
      || endpoints.tokenEndpoint.toString() !== GOOGLE_TOKEN_ENDPOINT
      || endpoints.jwksUri.toString() !== GOOGLE_JWKS_URI
    ) throw new Error('Google OIDC endpoints are not pinned');
    return;
  }
  const origin = endpoints.authorizationEndpoint.origin;
  for (const endpoint of [endpoints.authorizationEndpoint, endpoints.tokenEndpoint, endpoints.jwksUri]) {
    assertLoopbackUrl(endpoint);
    if (endpoint.origin !== origin) throw new Error('test OIDC endpoints must share one loopback origin');
  }
}

function assertLoopbackUrl(url: URL): void {
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') {
    throw new Error('test OIDC endpoint is not 127.0.0.1 loopback HTTP');
  }
}
