import { decodeProtectedHeader, importJWK, jwtVerify, errors, type JWK } from 'jose';
import type { ProviderConfig } from './config.js';
import { describeProviderKey } from './jwk.js';
import { sha256Hex, type Identity } from './storage.js';
import type { Hex } from 'viem';

export interface OidcValidatorOptions {
  jwksCacheSeconds: number;
  maxAuthAgeSeconds: number;
  clockToleranceSeconds: number;
  fetch?: typeof globalThis.fetch;
}

export interface ValidatedIdToken {
  identity: Identity;
  tokenDigest: Hex;
  providerKeyHash: Hex;
  providerKeyThumbprint: string;
  issuedAt: number;
  authenticationTime: number;
}

interface JwksCacheEntry {
  fetchedAt: number;
  keys: Map<string, JWK>;
}

function claimError(error: unknown): Error {
  if (error instanceof errors.JWTExpired) return new Error('ID token expired');
  if (error instanceof errors.JWTClaimValidationFailed) {
    if (error.claim === 'iss') return new Error('ID token issuer mismatch');
    if (error.claim === 'aud') return new Error('ID token audience mismatch');
    return new Error(`ID token ${error.claim ?? 'claim'} validation failed`);
  }
  if (error instanceof errors.JOSEError) return new Error(`ID token validation failed: ${error.code}`);
  return error instanceof Error ? error : new Error('ID token validation failed');
}

function cacheKey(provider: ProviderConfig): string {
  return `${provider.issuer}\n${provider.audience}\n${provider.jwksUri}`;
}

export class OidcIdTokenValidator {
  readonly #options: Omit<OidcValidatorOptions, 'fetch'>;
  readonly #fetch: typeof globalThis.fetch;
  readonly #cache = new Map<string, JwksCacheEntry>();

  constructor(options: OidcValidatorOptions) {
    this.#options = options;
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  async #refresh(provider: ProviderConfig, now: number): Promise<JwksCacheEntry> {
    const response = await this.#fetch(provider.jwksUri, {
      headers: { accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) throw new Error(`JWKS fetch failed (${response.status})`);
    const body = await response.json() as { keys?: unknown };
    if (!Array.isArray(body.keys) || body.keys.length > 20) throw new Error('invalid JWKS response');
    const keys = new Map<string, JWK>();
    for (const candidate of body.keys) {
      if (candidate === null || typeof candidate !== 'object') throw new Error('invalid JWKS key');
      const jwk = candidate as JWK;
      if (jwk.kty !== 'RSA' || jwk.alg !== 'RS256' || typeof jwk.kid !== 'string' || jwk.kid.length === 0) {
        throw new Error('JWKS contains an unsupported key');
      }
      if (jwk.use !== undefined && jwk.use !== 'sig') throw new Error('JWKS key is not for signatures');
      if (keys.has(jwk.kid)) throw new Error('JWKS contains duplicate kid');
      // Canonicalization also checks required RSA public parameters.
      describeProviderKey(jwk);
      keys.set(jwk.kid, jwk);
    }
    const entry = { fetchedAt: now, keys };
    this.#cache.set(cacheKey(provider), entry);
    return entry;
  }

  async #selectJwk(provider: ProviderConfig, kid: string, now: number): Promise<JWK> {
    let cache = this.#cache.get(cacheKey(provider));
    const stale = cache === undefined || now - cache.fetchedAt > this.#options.jwksCacheSeconds;
    if (stale) cache = await this.#refresh(provider, now);
    let jwk = cache!.keys.get(kid);
    if (jwk === undefined && !stale) {
      // Rotation: an unknown kid gets one immediate refresh, never an unbounded retry loop.
      cache = await this.#refresh(provider, now);
      jwk = cache.keys.get(kid);
    }
    if (jwk === undefined) throw new Error('unknown signing key kid after JWKS refresh');
    return jwk;
  }

  async validate(token: string, provider: ProviderConfig, expectedNonce: string, now: number): Promise<ValidatedIdToken> {
    if (typeof token !== 'string' || token.length === 0 || token.length > 32_768) throw new Error('invalid ID token');
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new Error('malformed ID token');
    }
    if (header.alg !== 'RS256' || !provider.allowedAlgorithms.includes(header.alg)) {
      throw new Error('unsupported ID token algorithm');
    }
    if (header.typ !== undefined && header.typ !== 'JWT') throw new Error('token is not an ID token JWT');
    if (typeof header.kid !== 'string' || header.kid.length === 0) throw new Error('ID token has no kid');

    const jwk = await this.#selectJwk(provider, header.kid, now);
    const keyDescription = describeProviderKey(jwk);
    if (provider.revokedKeyThumbprints.has(keyDescription.thumbprint)) {
      throw new Error('provider signing key is locally revoked');
    }

    let key: CryptoKey | Uint8Array;
    try {
      key = await importJWK(jwk, 'RS256');
    } catch {
      throw new Error('invalid provider signing key');
    }

    let payload;
    try {
      ({ payload } = await jwtVerify(token, key, {
        algorithms: ['RS256'],
        issuer: provider.issuer,
        audience: provider.audience,
        currentDate: new Date(now * 1000),
        clockTolerance: this.#options.clockToleranceSeconds,
        requiredClaims: ['iss', 'aud', 'sub', 'exp', 'iat', 'nonce', 'auth_time'],
      }));
    } catch (error) {
      throw claimError(error);
    }

    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (
      (audiences.length > 1 && typeof payload.azp !== 'string')
      || (payload.azp !== undefined && payload.azp !== provider.clientId)
    ) {
      throw new Error('ID token authorized party mismatch');
    }
    if (typeof payload.nonce !== 'string' || payload.nonce !== expectedNonce) throw new Error('ID token nonce mismatch');
    if (typeof payload.sub !== 'string' || payload.sub.length === 0 || payload.sub.length > 255) throw new Error('invalid ID token subject');
    if (typeof payload.iat !== 'number' || !Number.isInteger(payload.iat)) throw new Error('invalid ID token iat');
    if (payload.iat > now + this.#options.clockToleranceSeconds) throw new Error('ID token issued in the future');
    if (typeof payload.auth_time !== 'number' || !Number.isInteger(payload.auth_time)) throw new Error('invalid ID token auth_time');
    if (payload.auth_time > now + this.#options.clockToleranceSeconds) throw new Error('authentication is in the future');
    if (now - payload.auth_time > this.#options.maxAuthAgeSeconds) throw new Error('authentication is stale');

    return {
      identity: { issuer: provider.issuer, audience: provider.audience, subject: payload.sub },
      tokenDigest: sha256Hex(token),
      providerKeyHash: keyDescription.providerKeyHash,
      providerKeyThumbprint: keyDescription.thumbprint,
      issuedAt: payload.iat,
      authenticationTime: payload.auth_time,
    };
  }
}
