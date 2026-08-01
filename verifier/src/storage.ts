import { createHash, timingSafeEqual } from 'node:crypto';
import type { Address, Hex } from 'viem';
import type { ProviderName } from './config.js';
import type { ActionRequest, Intent } from './intent.js';

export interface Identity { issuer: string; audience: string; subject: string }

export interface PendingChallenge {
  id: string;
  provider: ProviderName;
  request: ActionRequest;
  stateHash: Hex;
  pkceVerifier: string;
  oidcNonce: string;
  createdAt: number;
  expiresAt: number;
  status: 'pending';
}

interface CallbackClaimedChallenge extends Omit<PendingChallenge, 'status'> {
  status: 'callback_claimed';
}

export interface AuthenticatedChallenge extends Omit<PendingChallenge, 'status'> {
  status: 'authenticated' | 'attested';
  intent: Intent;
  providerKeyHash: Hex;
  tokenIssuedAt: number;
  providerKeyThumbprint: string;
  confirmationSecretHash: Hex;
  csrfHash: Hex;
  authenticatedAt: number;
}

type StoredChallenge = PendingChallenge | CallbackClaimedChallenge | AuthenticatedChallenge;

export interface CompleteAuthenticationInput {
  challengeId: string;
  identity: Identity;
  tokenDigest: Hex;
  providerKeyHash: Hex;
  tokenIssuedAt: number;
  providerKeyThumbprint: string;
  confirmationSecretHash: Hex;
  csrfHash: Hex;
  authenticatedAt: number;
  intent: Intent;
}

export interface VerifierStorage {
  createChallenge(record: PendingChallenge): Promise<void>;
  claimCallback(stateHash: Hex, now: number): Promise<PendingChallenge>;
  completeAuthentication(input: CompleteAuthenticationInput): Promise<void>;
  getIdentityBinding(account: Address, commitment: Hex): Promise<Identity | undefined>;
  getChallengeForConfirmation(id: string, secretHash: Hex, now: number): Promise<AuthenticatedChallenge>;
  consumeConfirmation(id: string, secretHash: Hex, csrfHash: Hex, now: number): Promise<AuthenticatedChallenge>;
}

export function sha256Hex(value: string | Uint8Array): Hex {
  return `0x${createHash('sha256').update(value).digest('hex')}`;
}

function secureHexEqual(left: Hex, right: Hex): boolean {
  const a = Buffer.from(left.slice(2), 'hex');
  const b = Buffer.from(right.slice(2), 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

function sameIdentity(left: Identity, right: Identity): boolean {
  return left.issuer === right.issuer && left.audience === right.audience && left.subject === right.subject;
}

function bindingKey(account: Address, commitment: Hex): string {
  return `${account.toLowerCase()}:${commitment.toLowerCase()}`;
}

function publicAuthenticated(record: AuthenticatedChallenge): AuthenticatedChallenge {
  return structuredClone(record);
}

/**
 * Safe only for tests and single-process demos. Methods contain no awaits, so each transition is
 * atomic within one JavaScript event loop. A production adapter must provide equivalent database
 * uniqueness constraints and transactions across challenge, replay, and identity-binding writes.
 */
export class InMemoryStorage implements VerifierStorage {
  readonly #challenges = new Map<string, StoredChallenge>();
  readonly #stateToChallenge = new Map<Hex, string>();
  readonly #tokenDigests = new Set<Hex>();
  readonly #bindings = new Map<string, Identity>();

  async createChallenge(record: PendingChallenge): Promise<void> {
    if (this.#challenges.has(record.id) || this.#stateToChallenge.has(record.stateHash)) {
      throw new Error('challenge already exists');
    }
    const copy = structuredClone(record);
    this.#challenges.set(copy.id, copy);
    this.#stateToChallenge.set(copy.stateHash, copy.id);
  }

  async claimCallback(stateHash: Hex, now: number): Promise<PendingChallenge> {
    const id = this.#stateToChallenge.get(stateHash);
    if (id === undefined) throw new Error('invalid state');
    const record = this.#challenges.get(id);
    if (record === undefined) throw new Error('invalid state');
    if (record.expiresAt < now) throw new Error('challenge expired');
    if (record.status !== 'pending') throw new Error('callback already used');
    this.#challenges.set(id, { ...record, status: 'callback_claimed' });
    return structuredClone(record);
  }

  async completeAuthentication(input: CompleteAuthenticationInput): Promise<void> {
    const record = this.#challenges.get(input.challengeId);
    if (record === undefined || record.status !== 'callback_claimed') {
      throw new Error('challenge is not awaiting authentication');
    }
    if (this.#tokenDigests.has(input.tokenDigest)) throw new Error('ID token replay');

    const key = bindingKey(record.request.account, record.request.identityCommitment);
    const existing = this.#bindings.get(key);
    if (record.request.action === 'CREATE') {
      if (existing !== undefined) throw new Error('identity commitment already bound');
    } else if (existing === undefined || !sameIdentity(existing, input.identity)) {
      throw new Error('identity binding mismatch');
    }

    // These writes are one synchronous critical section. Production storage must transact them.
    if (record.request.action === 'CREATE') this.#bindings.set(key, structuredClone(input.identity));
    this.#tokenDigests.add(input.tokenDigest);
    this.#challenges.set(record.id, {
      ...record,
      status: 'authenticated',
      intent: structuredClone(input.intent),
      providerKeyHash: input.providerKeyHash,
      tokenIssuedAt: input.tokenIssuedAt,
      providerKeyThumbprint: input.providerKeyThumbprint,
      confirmationSecretHash: input.confirmationSecretHash,
      csrfHash: input.csrfHash,
      authenticatedAt: input.authenticatedAt,
    });
  }

  async getIdentityBinding(account: Address, commitment: Hex): Promise<Identity | undefined> {
    const binding = this.#bindings.get(bindingKey(account, commitment));
    return binding === undefined ? undefined : structuredClone(binding);
  }

  async getChallengeForConfirmation(id: string, secretHash: Hex, now: number): Promise<AuthenticatedChallenge> {
    const record = this.#challenges.get(id);
    if (record === undefined || (record.status !== 'authenticated' && record.status !== 'attested')) {
      throw new Error('confirmation unavailable');
    }
    if (record.expiresAt < now || record.intent.validUntil < BigInt(now)) throw new Error('challenge expired');
    if (!secureHexEqual(record.confirmationSecretHash, secretHash)) throw new Error('invalid confirmation secret');
    return publicAuthenticated(record);
  }

  async consumeConfirmation(id: string, secretHash: Hex, csrfHash: Hex, now: number): Promise<AuthenticatedChallenge> {
    const record = await this.getChallengeForConfirmation(id, secretHash, now);
    if (record.status === 'attested') throw new Error('challenge already confirmed');
    if (!secureHexEqual(record.csrfHash, csrfHash)) throw new Error('invalid CSRF token');
    const consumed = { ...record, status: 'attested' as const };
    this.#challenges.set(id, consumed);
    return publicAuthenticated(consumed);
  }
}
