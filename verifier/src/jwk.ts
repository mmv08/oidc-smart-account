import { createHash } from 'node:crypto';
import type { JWK } from 'jose';
import type { Hex } from 'viem';

export interface ProviderKeyDescription {
  canonicalJwk: string;
  thumbprint: string;
  providerKeyHash: Hex;
}

export function canonicalRsaJwk(jwk: JWK): string {
  if (jwk.kty !== 'RSA' || typeof jwk.e !== 'string' || typeof jwk.n !== 'string') {
    throw new Error('provider key must be an RSA public JWK');
  }
  return JSON.stringify({ e: jwk.e, kty: 'RSA', n: jwk.n });
}

export function describeProviderKey(jwk: JWK): ProviderKeyDescription {
  const canonicalJwk = canonicalRsaJwk(jwk);
  const digest = createHash('sha256').update(canonicalJwk).digest();
  return {
    canonicalJwk,
    thumbprint: digest.toString('base64url'),
    providerKeyHash: `0x${digest.toString('hex')}`,
  };
}
