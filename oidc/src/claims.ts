import {
  encodeAbiParameters,
  keccak256,
  stringToHex,
  type Hex,
} from 'viem';

export type InitialOIDCProvider = 'google' | 'apple';

export const GOOGLE_ISSUER = 'https://accounts.google.com';
export const APPLE_ISSUER = 'https://appleid.apple.com';
export const GOOGLE_PROVIDER = keccak256(stringToHex(GOOGLE_ISSUER));
export const APPLE_PROVIDER = keccak256(stringToHex(APPLE_ISSUER));

const POLICY_TYPEHASH = keccak256(
  stringToHex(
    'OIDCPolicy(bytes32 providerId,bytes32 audienceHash,bytes32 authorizedPartyHash)',
  ),
);
const NO_AUTHORIZED_PARTY = `0x${'00'.repeat(32)}` as Hex;
const IDENTITY_TYPEHASH = keccak256(
  stringToHex('OIDCIdentity(bytes32 policyId,bytes32 subjectHash,bytes32 salt)'),
);

export interface NormalizedOIDCClaim {
  providerId: Hex;
  providerPolicyId: Hex;
  identityCommitment: Hex;
  nonce: Hex;
  issuedAt: number;
  expiresAt: number;
}

export interface NormalizeClaimsInput {
  /** Claims from a JWT whose signature has already been verified by a proof adapter. */
  claims: Record<string, unknown>;
  provider: InitialOIDCProvider;
  clientId: string;
  /** Google hybrid-app client ID expected in azp. Omit for ordinary web/native tokens. */
  authorizedParty?: string;
  identitySalt: Hex;
  now: number;
  maxClaimAgeSeconds: number;
}

export function providerPolicyId(
  providerId: Hex,
  audience: string,
  authorizedParty?: string,
): Hex {
  if (audience.length === 0) throw new Error('OIDC audience is empty');
  if (authorizedParty !== undefined && authorizedParty.length === 0) {
    throw new Error('OIDC authorized party is empty');
  }
  const audienceHash = keccak256(stringToHex(audience));
  const authorizedPartyHash = authorizedParty === undefined
    ? NO_AUTHORIZED_PARTY
    : keccak256(stringToHex(authorizedParty));
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'bytes32' },
      ],
      [POLICY_TYPEHASH, providerId, audienceHash, authorizedPartyHash],
    ),
  );
}

export function identityCommitment(policyId: Hex, subject: string, salt: Hex): Hex {
  if (subject.length === 0 || new TextEncoder().encode(subject).length > 255) {
    throw new Error('invalid OIDC subject');
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(salt)) throw new Error('identity salt must be bytes32');
  const subjectHash = keccak256(stringToHex(subject));
  return keccak256(
    encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes32' }],
      [IDENTITY_TYPEHASH, policyId, subjectHash, salt],
    ),
  );
}

export function normalizeGoogleOrAppleClaims(input: NormalizeClaimsInput): NormalizedOIDCClaim {
  const {
    claims, provider, clientId, authorizedParty, identitySalt, now, maxClaimAgeSeconds,
  } = input;
  if (
    !Number.isSafeInteger(now) || now < 0
    || !Number.isSafeInteger(maxClaimAgeSeconds) || maxClaimAgeSeconds <= 0
  ) {
    throw new Error('invalid OIDC clock configuration');
  }
  if (provider === 'apple' && authorizedParty !== undefined) {
    throw new Error('Apple policy does not use an authorized party');
  }
  const providerId = validateIssuer(provider, claims.iss);
  validateAudience(claims.aud, claims.azp, clientId, authorizedParty);

  if (
    typeof claims.sub !== 'string' || claims.sub.length === 0
    || new TextEncoder().encode(claims.sub).length > 255
  ) {
    throw new Error('invalid OIDC subject');
  }
  if (typeof claims.nonce !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(claims.nonce)) {
    throw new Error('OIDC nonce must be a bytes32 hex digest');
  }
  if (
    !Number.isSafeInteger(claims.iat) || (claims.iat as number) < 0
    || !Number.isSafeInteger(claims.exp) || (claims.exp as number) < 0
  ) {
    throw new Error('invalid OIDC token timing');
  }
  const issuedAt = claims.iat as number;
  const expiresAt = claims.exp as number;
  if (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || (claims.nbf as number) < 0)) {
    throw new Error('invalid OIDC token timing');
  }
  if (claims.nbf !== undefined && (claims.nbf as number) > now) {
    throw new Error('OIDC claim is not active yet');
  }
  if (issuedAt > now) throw new Error('OIDC claim was issued in the future');
  if (expiresAt <= now || expiresAt <= issuedAt) throw new Error('OIDC claim is expired');
  if (now - issuedAt > maxClaimAgeSeconds) throw new Error('OIDC claim is stale');

  const policy = providerPolicyId(providerId, clientId, authorizedParty);
  return {
    providerId,
    providerPolicyId: policy,
    identityCommitment: identityCommitment(policy, claims.sub, identitySalt),
    nonce: claims.nonce.toLowerCase() as Hex,
    issuedAt,
    expiresAt,
  };
}

function validateIssuer(provider: InitialOIDCProvider, issuer: unknown): Hex {
  if (provider === 'google') {
    if (issuer !== GOOGLE_ISSUER && issuer !== 'accounts.google.com') {
      throw new Error('Google OIDC issuer mismatch');
    }
    return GOOGLE_PROVIDER;
  }
  if (issuer !== APPLE_ISSUER) throw new Error('Apple OIDC issuer mismatch');
  return APPLE_PROVIDER;
}

function validateAudience(
  audience: unknown,
  tokenAuthorizedParty: unknown,
  clientId: string,
  expectedAuthorizedParty?: string,
): void {
  const audiences = typeof audience === 'string'
    ? [audience]
    : Array.isArray(audience) && audience.every((value) => typeof value === 'string')
      ? audience
      : [];
  if (!audiences.includes(clientId)) throw new Error('OIDC audience mismatch');
  const expected = expectedAuthorizedParty ?? clientId;
  if (
    ((audiences.length > 1 || expectedAuthorizedParty !== undefined)
      && typeof tokenAuthorizedParty !== 'string')
    || (tokenAuthorizedParty !== undefined && tokenAuthorizedParty !== expected)
  ) {
    throw new Error('OIDC authorized party mismatch');
  }
}
