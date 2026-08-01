import { createHash, randomBytes } from 'node:crypto';
import Fastify, { type FastifyInstance } from 'fastify';
import { encodeAbiParameters, getAddress, keccak256, type Address, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { z } from 'zod';
import type { VerifierConfig } from './config.js';
import {
  actionRequestDigest, actionRequestOidcNonce, attestationTypedData, intentDigest,
  materializeIntent,
  type ActionRequest, type Intent,
} from './intent.js';
import { OidcIdTokenValidator } from './oidc.js';
import { sha256Hex, type VerifierStorage } from './storage.js';

export interface CreateVerifierAppOptions {
  config: VerifierConfig;
  storage: VerifierStorage;
  clock?: () => number;
  logger?: boolean;
  fetch?: typeof globalThis.fetch;
}

const bytes32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/).transform((value) => value.toLowerCase() as Hex);
const signerEncoding = z.string().regex(/^0x(?:[0-9a-fA-F]{2}){20,1024}$/).transform((value) => value.toLowerCase() as Hex);
const uint = z.string().regex(/^(0|[1-9][0-9]*)$/).transform((value) => BigInt(value));
const address = z.string().transform((value, context) => {
  try { return getAddress(value) as Address; }
  catch { context.addIssue({ code: 'custom', message: 'invalid address' }); return z.NEVER; }
});
const actionRequestSchema = z.object({
  version: z.literal(1),
  account: address,
  chainId: uint.refine((value) => value > 0n, 'chainId must be positive'),
  controller: address,
  action: z.enum(['CREATE', 'ADD', 'REPLACE']),
  currentSignerHash: bytes32,
  newSigner: signerEncoding,
  newSignerHash: bytes32,
  recoveryNonce: uint,
  intentNonce: bytes32,
  identityCommitment: bytes32,
  providerId: bytes32,
  recoveryDelay: uint,
  issuedAt: uint,
  attestationTtl: uint,
  attestorEpoch: uint,
}).strict();
const challengeSchema = z.object({ provider: z.enum(['google', 'apple']), request: actionRequestSchema }).strict();
const callbackSchema = z.object({ state: z.string().min(20).max(200), code: z.string().min(1).max(4096) });
const confirmationSchema = z.object({
  csrf: z.string().regex(/^[A-Za-z0-9_-]{20,200}$/),
  fingerprintSuffix: z.string().regex(/^[0-9a-fA-F]{8}$/),
});

const zeroBytes32 = `0x${'00'.repeat(32)}`;

function randomOpaque(bytes = 32): string { return randomBytes(bytes).toString('base64url'); }
function pkceChallenge(verifier: string): string { return createHash('sha256').update(verifier).digest('base64url'); }
function callbackUri(config: VerifierConfig): string { return `${config.publicOrigin}/v1/oidc/callback`; }

function serializeIntent(intent: Intent): Record<string, string> {
  return {
    version: intent.version.toString(),
    action: intent.action,
    identityCommitment: intent.identityCommitment,
    account: intent.account,
    controller: intent.controller,
    currentSignerHash: intent.currentSignerHash,
    newSignerHash: intent.newSignerHash,
    recoveryNonce: intent.recoveryNonce.toString(),
    intentNonce: intent.intentNonce,
    providerId: intent.providerId,
    providerKeyHash: intent.providerKeyHash,
    issuedAt: intent.issuedAt.toString(),
    validAfter: intent.validAfter.toString(),
    validUntil: intent.validUntil.toString(),
    chainId: intent.chainId.toString(),
    attestorEpoch: intent.attestorEpoch.toString(),
  };
}

function cookieValues(cookieHeader: string | undefined): { confirmation: string; csrf: string } | undefined {
  if (cookieHeader === undefined) return undefined;
  for (const part of cookieHeader.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name !== 'oidc_confirmation') continue;
    const [confirmation, csrf] = rest.join('=').split('.');
    if (confirmation && csrf) return { confirmation, csrf };
  }
  return undefined;
}

function confirmationCookie(secret: string, csrf: string, challengeId: string, maxAge: number): string {
  return `oidc_confirmation=${secret}.${csrf}; HttpOnly; Secure; SameSite=Strict; Path=/v1/confirm/${challengeId}; Max-Age=${Math.max(0, maxAge)}`;
}

function htmlEscape(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

function signerDescription(signer: Hex): string {
  const verifier = getAddress(`0x${signer.slice(2, 42)}`);
  return signer.length === 42
    ? `Address signer ${verifier}`
    : `ERC-7913 verifier ${verifier}; public key bytes ${signer.slice(42).length / 2}`;
}

function confirmationPage(
  intent: Intent,
  request: ActionRequest,
  csrf: string,
  verifyingContract: Address,
): string {
  const delay = request.action === 'CREATE' ? 'not applicable' : `${request.recoveryDelay} seconds`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Confirm account action</title></head>
<body><main><h1>Confirm ${htmlEscape(intent.action)}</h1>
<dl><dt>Chain</dt><dd>${intent.chainId}</dd><dt>Account</dt><dd>${htmlEscape(intent.account)}</dd>
<dt>Controller</dt><dd>${htmlEscape(intent.controller)}</dd>
<dt>Verifying contract</dt><dd>${htmlEscape(verifyingContract)}</dd>
<dt>Provider policy</dt><dd>${htmlEscape(intent.providerId)}</dd>
<dt>Identity commitment</dt><dd>${htmlEscape(intent.identityCommitment)}</dd>
<dt>Intent nonce</dt><dd>${htmlEscape(intent.intentNonce)}</dd>
<dt>Signer encoding</dt><dd>${htmlEscape(signerDescription(request.newSigner))}</dd>
<dt>Full signer bytes</dt><dd>${htmlEscape(request.newSigner)}</dd>
<dt>New key fingerprint</dt><dd>${htmlEscape(intent.newSignerHash)}</dd>
<dt>Current signer/set fingerprint</dt><dd>${htmlEscape(intent.currentSignerHash)}</dd>
<dt>Recovery nonce</dt><dd>${intent.recoveryNonce}</dd>
<dt>Valid after</dt><dd>${intent.validAfter}</dd>
<dt>Valid until</dt><dd>${intent.validUntil}</dd>
<dt>Attestor epoch</dt><dd>${intent.attestorEpoch}</dd>
<dt>Recovery delay</dt><dd>${delay}</dd></dl>
<p>Type the final 8 hexadecimal characters of the new key fingerprint to attest this exact action.</p>
<form method="post"><input type="hidden" name="csrf" value="${htmlEscape(csrf)}"><label>Fingerprint suffix <input name="fingerprintSuffix" pattern="[0-9a-fA-F]{8}" minlength="8" maxlength="8" autocomplete="off" required></label><button type="submit">Confirm</button></form>
</main></body></html>`;
}

function validateActionRequest(
  request: ActionRequest,
  config: VerifierConfig,
  expectedProviderId: Hex,
  now: number,
): void {
  if (request.providerId.toLowerCase() !== expectedProviderId.toLowerCase()) throw new Error('provider policy mismatch');
  if (request.chainId !== config.chainId || request.attestorEpoch !== config.attestorEpoch) throw new Error('chain or epoch mismatch');
  if (request.intentNonce === zeroBytes32 || request.identityCommitment === zeroBytes32 || request.newSignerHash === zeroBytes32) {
    throw new Error('nonce, commitment, and new signer hash must be nonzero');
  }
  if (keccak256(request.newSigner).toLowerCase() !== request.newSignerHash.toLowerCase()) {
    throw new Error('new signer encoding does not match fingerprint');
  }
  const signerVerifier = BigInt(`0x${request.newSigner.slice(2, 42)}`);
  if (signerVerifier <= 0xffn) throw new Error('reserved signer verifier');
  const expectedController = request.action === 'CREATE' ? config.factoryAddress : config.recoveryManagerAddress;
  if (request.controller !== expectedController) throw new Error('controller mismatch');
  if (request.action !== 'CREATE' && request.currentSignerHash === zeroBytes32) throw new Error('recovery requires current signer hash');
  if (request.attestationTtl === 0n || request.attestationTtl > BigInt(config.maxAttestationTtlSeconds)) {
    throw new Error('invalid attestation TTL');
  }
  if (request.issuedAt > BigInt(now) || request.issuedAt + request.attestationTtl <= BigInt(now)) {
    throw new Error('invalid common intent time');
  }
  if (request.action === 'CREATE') {
    if (request.currentSignerHash !== zeroBytes32 || request.recoveryNonce !== 0n || request.recoveryDelay !== 0n) {
      throw new Error('invalid create request');
    }
  } else if (request.recoveryDelay !== BigInt(config.recoveryDelaySeconds)) {
    throw new Error('recovery delay mismatch');
  }
}

async function exchangeCode(
  fetcher: typeof globalThis.fetch,
  config: VerifierConfig,
  providerName: 'google' | 'apple',
  code: string,
  pkceVerifier: string,
): Promise<string> {
  const provider = config.providers[providerName];
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
    redirect_uri: callbackUri(config),
    code_verifier: pkceVerifier,
  });
  const response = await fetcher(provider.tokenEndpoint, {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
    body,
    redirect: 'error',
    signal: AbortSignal.timeout(5_000),
  });
  const text = await response.text();
  if (!response.ok || text.length > 65_536) throw new Error('OIDC token exchange failed');
  let result: unknown;
  try { result = JSON.parse(text); } catch { throw new Error('OIDC token endpoint returned invalid JSON'); }
  const idToken = (result as { id_token?: unknown }).id_token;
  if (typeof idToken !== 'string') throw new Error('OIDC token response has no ID token');
  return idToken;
}

export function createVerifierApp(options: CreateVerifierAppOptions): FastifyInstance {
  const { config, storage } = options;
  const clock = options.clock ?? (() => Math.floor(Date.now() / 1000));
  const fetcher = options.fetch ?? globalThis.fetch;
  const validator = new OidcIdTokenValidator({
    jwksCacheSeconds: config.jwksCacheSeconds,
    maxAuthAgeSeconds: config.maxAuthAgeSeconds,
    clockToleranceSeconds: config.clockToleranceSeconds,
    fetch: fetcher,
  });
  const attestor = privateKeyToAccount(config.attestorPrivateKey);
  // Request logging is deliberately disabled: callback URLs contain authorization codes.
  const app = Fastify({ logger: false, bodyLimit: 32_768 });
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_request, body, done) => {
    done(null, Object.fromEntries(new URLSearchParams(body as string)));
  });
  app.addHook('onSend', async (_request, reply, payload) => {
    reply.header('cache-control', 'no-store');
    reply.header('pragma', 'no-cache');
    reply.header('referrer-policy', 'no-referrer');
    reply.header('x-content-type-options', 'nosniff');
    return payload;
  });

  app.get('/healthz', async () => ({ status: 'ok' }));

  app.post('/v1/challenges', async (request, reply) => {
    const parsed = challengeSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_challenge' });
    const now = clock();
    const provider = config.providers[parsed.data.provider];
    const actionRequest = parsed.data.request as ActionRequest;
    try { validateActionRequest(actionRequest, config, provider.providerId, now); }
    catch { return reply.code(400).send({ error: 'invalid_challenge' }); }

    const id = randomOpaque(18);
    const state = randomOpaque();
    const verifier = randomOpaque();
    const expiresAt = now + config.challengeTtlSeconds;
    await storage.createChallenge({
      id,
      provider: parsed.data.provider,
      request: actionRequest,
      stateHash: sha256Hex(state),
      pkceVerifier: verifier,
      oidcNonce: actionRequestOidcNonce(actionRequest, config.verifyingContract),
      createdAt: now,
      expiresAt,
      status: 'pending',
    });
    const authorizationUrl = new URL(provider.authorizationEndpoint);
    authorizationUrl.search = new URLSearchParams({
      client_id: provider.clientId,
      redirect_uri: callbackUri(config),
      response_type: 'code',
      scope: config.scope,
      state,
      nonce: actionRequestOidcNonce(actionRequest, config.verifyingContract),
      max_age: String(config.maxAuthAgeSeconds),
      code_challenge: pkceChallenge(verifier),
      code_challenge_method: 'S256',
    }).toString();
    return reply.code(201).send({
      challengeId: id, authorizationUrl: authorizationUrl.toString(), expiresAt,
      requestHash: actionRequestDigest(actionRequest, config.verifyingContract),
    });
  });

  app.get('/v1/oidc/callback', async (request, reply) => {
    const parsed = callbackSchema.safeParse(request.query);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_callback' });
    const now = clock();
    try {
      const challenge = await storage.claimCallback(sha256Hex(parsed.data.state), now);
      const provider = config.providers[challenge.provider];
      const idToken = await exchangeCode(fetcher, config, challenge.provider, parsed.data.code, challenge.pkceVerifier);
      const validated = await validator.validate(idToken, provider, challenge.oidcNonce, now);
      const intent = materializeIntent(challenge.request);
      const confirmationSecret = randomOpaque();
      const csrf = randomOpaque();
      await storage.completeAuthentication({
        challengeId: challenge.id,
        identity: validated.identity,
        tokenDigest: validated.tokenDigest,
        providerKeyHash: validated.providerKeyHash,
        tokenIssuedAt: validated.issuedAt,
        providerKeyThumbprint: validated.providerKeyThumbprint,
        confirmationSecretHash: sha256Hex(confirmationSecret),
        csrfHash: sha256Hex(csrf),
        authenticatedAt: validated.authenticationTime,
        intent,
      });
      reply.header('set-cookie', confirmationCookie(confirmationSecret, csrf, challenge.id, challenge.expiresAt - now));
      return reply.redirect(`/v1/confirm/${challenge.id}`, 303);
    } catch (error) {
      const conflict = error instanceof Error && /already used/.test(error.message);
      return reply.code(conflict ? 409 : 400).send({ error: conflict ? 'callback_already_used' : 'invalid_callback' });
    }
  });

  app.get('/v1/confirm/:challengeId', async (request, reply) => {
    const { challengeId } = request.params as { challengeId: string };
    const secrets = cookieValues(request.headers.cookie);
    if (secrets === undefined) return reply.code(401).send({ error: 'confirmation_unauthorized' });
    try {
      const challenge = await storage.getChallengeForConfirmation(challengeId, sha256Hex(secrets.confirmation), clock());
      reply.type('text/html; charset=utf-8');
      reply.header('content-security-policy', "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
      return reply.send(
        confirmationPage(
          challenge.intent,
          challenge.request,
          secrets.csrf,
          config.verifyingContract,
        ),
      );
    } catch {
      return reply.code(401).send({ error: 'confirmation_unauthorized' });
    }
  });

  app.post('/v1/confirm/:challengeId', async (request, reply) => {
    const parsed = confirmationSchema.safeParse(request.body);
    const { challengeId } = request.params as { challengeId: string };
    const secrets = cookieValues(request.headers.cookie);
    if (!parsed.success || secrets === undefined || parsed.data.csrf !== secrets.csrf) {
      return reply.code(400).send({ error: 'invalid_confirmation' });
    }
    try {
      const challenge = await storage.getChallengeForConfirmation(challengeId, sha256Hex(secrets.confirmation), clock());
      const expectedSuffix = challenge.intent.newSignerHash.slice(-8).toLowerCase();
      if (parsed.data.fingerprintSuffix.toLowerCase() !== expectedSuffix) {
        return reply.code(400).send({ error: 'fingerprint_mismatch' });
      }
      const consumed = await storage.consumeConfirmation(
        challengeId,
        sha256Hex(secrets.confirmation),
        sha256Hex(parsed.data.csrf),
        clock(),
      );
      const commonDigest = intentDigest(consumed.intent, config.verifyingContract);
      const tokenIssuedAt = BigInt(consumed.tokenIssuedAt);
      const signature = await attestor.signTypedData(
        attestationTypedData(
          commonDigest,
          consumed.providerKeyHash,
          tokenIssuedAt,
          consumed.intent,
          config.verifyingContract,
        ),
      );
      const packedAttestation = encodeAbiParameters(
        [{ type: 'bytes32' }, { type: 'uint64' }, { type: 'bytes' }],
        [consumed.providerKeyHash, tokenIssuedAt, signature],
      );
      return reply.send({
        intent: serializeIntent(consumed.intent),
        intentDigest: commonDigest,
        signature,
        packedAttestation,
        attestor: attestor.address,
        providerKeyHash: consumed.providerKeyHash,
        tokenIssuedAt: consumed.tokenIssuedAt,
        providerKeyThumbprint: consumed.providerKeyThumbprint,
      });
    } catch (error) {
      const conflict = error instanceof Error && /already confirmed/.test(error.message);
      return reply.code(conflict ? 409 : 400).send({ error: conflict ? 'confirmation_already_used' : 'invalid_confirmation' });
    }
  });

  return app;
}
