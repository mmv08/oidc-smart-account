import { getAddress, type Address, type Hex } from 'viem';
import { z } from 'zod';
import { providerPolicyId } from './intent.js';

export type ProviderName = 'google' | 'apple';

export interface ProviderConfig {
  name: ProviderName;
  issuer: string;
  audience: string;
  clientId: string;
  clientSecret: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  allowedAlgorithms: readonly ['RS256'];
  policy: string;
  providerId: Hex;
  revokedKeyThumbprints: ReadonlySet<string>;
}

export interface VerifierConfig {
  publicOrigin: string;
  attestorPrivateKey: `0x${string}`;
  chainId: bigint;
  verifyingContract: Address;
  factoryAddress: Address;
  recoveryManagerAddress: Address;
  recoveryDelaySeconds: number;
  attestorEpoch: bigint;
  maxAttestationTtlSeconds: number;
  challengeTtlSeconds: number;
  maxAuthAgeSeconds: number;
  jwksCacheSeconds: number;
  clockToleranceSeconds: number;
  scope: 'openid';
  providers: Record<ProviderName, ProviderConfig>;
}

const envSchema = z.object({
  PUBLIC_ORIGIN: z.url(),
  ATTESTOR_PRIVATE_KEY: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  CHALLENGE_TTL_SECONDS: z.coerce.number().int().positive().max(3600).default(300),
  MAX_AUTH_AGE_SECONDS: z.coerce.number().int().positive().max(86400).default(600),
  JWKS_CACHE_SECONDS: z.coerce.number().int().nonnegative().max(86400).default(300),
  CLOCK_TOLERANCE_SECONDS: z.coerce.number().int().nonnegative().max(120).default(10),
  CHAIN_ID: z.string().regex(/^[1-9][0-9]*$/),
  EIP712_VERIFYING_CONTRACT: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  FACTORY_ADDRESS: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  RECOVERY_MANAGER_ADDRESS: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  RECOVERY_DELAY_SECONDS: z.coerce.number().int().positive().max(2_592_000),
  ATTESTOR_EPOCH: z.string().regex(/^[1-9][0-9]*$/),
  MAX_ATTESTATION_TTL_SECONDS: z.coerce.number().int().positive().max(31_536_000),
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  GOOGLE_ISSUER: z.url().default('https://accounts.google.com'),
  GOOGLE_AUTHORIZATION_ENDPOINT: z.url().default('https://accounts.google.com/o/oauth2/v2/auth'),
  GOOGLE_TOKEN_ENDPOINT: z.url().default('https://oauth2.googleapis.com/token'),
  GOOGLE_JWKS_URI: z.url().default('https://www.googleapis.com/oauth2/v3/certs'),
  GOOGLE_POLICY: z.string().min(1).default('google-client-policy-v1'),
  GOOGLE_REVOKED_KEY_THUMBPRINTS: z.string().default(''),
  APPLE_CLIENT_ID: z.string().min(1),
  APPLE_CLIENT_SECRET: z.string().min(1),
  APPLE_ISSUER: z.url().default('https://appleid.apple.com'),
  APPLE_AUTHORIZATION_ENDPOINT: z.url().default('https://appleid.apple.com/auth/authorize'),
  APPLE_TOKEN_ENDPOINT: z.url().default('https://appleid.apple.com/auth/token'),
  APPLE_JWKS_URI: z.url().default('https://appleid.apple.com/auth/keys'),
  APPLE_POLICY: z.string().min(1).default('apple-client-policy-v1'),
  APPLE_REVOKED_KEY_THUMBPRINTS: z.string().default(''),
  ALLOW_INSECURE_HTTP: z.enum(['true', 'false']).default('false'),
});

function revokedSet(csv: string): ReadonlySet<string> {
  return new Set(csv.split(',').map((value) => value.trim()).filter(Boolean));
}

function requireHttps(url: string, label: string, insecureAllowed: boolean): void {
  if (!insecureAllowed && new URL(url).protocol !== 'https:') {
    throw new Error(`${label} must use HTTPS`);
  }
}

export function loadConfig(environment: Record<string, string | undefined> = process.env): VerifierConfig {
  const parsed = envSchema.parse(environment);
  const insecureAllowed = parsed.ALLOW_INSECURE_HTTP === 'true';
  const urls: Array<[string, string]> = [
    [parsed.PUBLIC_ORIGIN, 'PUBLIC_ORIGIN'],
    [parsed.GOOGLE_ISSUER, 'GOOGLE_ISSUER'],
    [parsed.GOOGLE_AUTHORIZATION_ENDPOINT, 'GOOGLE_AUTHORIZATION_ENDPOINT'],
    [parsed.GOOGLE_TOKEN_ENDPOINT, 'GOOGLE_TOKEN_ENDPOINT'],
    [parsed.GOOGLE_JWKS_URI, 'GOOGLE_JWKS_URI'],
    [parsed.APPLE_ISSUER, 'APPLE_ISSUER'],
    [parsed.APPLE_AUTHORIZATION_ENDPOINT, 'APPLE_AUTHORIZATION_ENDPOINT'],
    [parsed.APPLE_TOKEN_ENDPOINT, 'APPLE_TOKEN_ENDPOINT'],
    [parsed.APPLE_JWKS_URI, 'APPLE_JWKS_URI'],
  ];
  for (const [url, label] of urls) requireHttps(url, label, insecureAllowed);

  const makeProvider = (
    name: ProviderName,
    issuer: string,
    audience: string,
    clientSecret: string,
    authorizationEndpoint: string,
    tokenEndpoint: string,
    jwksUri: string,
    policy: string,
    revoked: string,
  ): ProviderConfig => ({
    name,
    issuer,
    audience,
    clientId: audience,
    clientSecret,
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri,
    allowedAlgorithms: ['RS256'],
    policy,
    providerId: providerPolicyId(policy),
    revokedKeyThumbprints: revokedSet(revoked),
  });

  return {
    publicOrigin: parsed.PUBLIC_ORIGIN.replace(/\/$/, ''),
    attestorPrivateKey: parsed.ATTESTOR_PRIVATE_KEY as `0x${string}`,
    chainId: BigInt(parsed.CHAIN_ID),
    verifyingContract: getAddress(parsed.EIP712_VERIFYING_CONTRACT),
    factoryAddress: getAddress(parsed.FACTORY_ADDRESS),
    recoveryManagerAddress: getAddress(parsed.RECOVERY_MANAGER_ADDRESS),
    recoveryDelaySeconds: parsed.RECOVERY_DELAY_SECONDS,
    attestorEpoch: BigInt(parsed.ATTESTOR_EPOCH),
    maxAttestationTtlSeconds: parsed.MAX_ATTESTATION_TTL_SECONDS,
    challengeTtlSeconds: parsed.CHALLENGE_TTL_SECONDS,
    maxAuthAgeSeconds: parsed.MAX_AUTH_AGE_SECONDS,
    jwksCacheSeconds: parsed.JWKS_CACHE_SECONDS,
    clockToleranceSeconds: parsed.CLOCK_TOLERANCE_SECONDS,
    scope: 'openid',
    providers: {
      google: makeProvider('google', parsed.GOOGLE_ISSUER, parsed.GOOGLE_CLIENT_ID, parsed.GOOGLE_CLIENT_SECRET, parsed.GOOGLE_AUTHORIZATION_ENDPOINT, parsed.GOOGLE_TOKEN_ENDPOINT, parsed.GOOGLE_JWKS_URI, parsed.GOOGLE_POLICY, parsed.GOOGLE_REVOKED_KEY_THUMBPRINTS),
      apple: makeProvider('apple', parsed.APPLE_ISSUER, parsed.APPLE_CLIENT_ID, parsed.APPLE_CLIENT_SECRET, parsed.APPLE_AUTHORIZATION_ENDPOINT, parsed.APPLE_TOKEN_ENDPOINT, parsed.APPLE_JWKS_URI, parsed.APPLE_POLICY, parsed.APPLE_REVOKED_KEY_THUMBPRINTS),
    },
  };
}
