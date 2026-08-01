import { createHash } from 'node:crypto';
import { getAddress, hashTypedData, keccak256, stringToHex, type Address, type Hex } from 'viem';

export type Action = 'CREATE' | 'ADD' | 'REPLACE';

/** Client-known management request. Every field is covered by the OIDC nonce. */
export interface ActionRequest {
  version: 1;
  account: Address;
  chainId: bigint;
  controller: Address;
  action: Action;
  currentSignerHash: Hex;
  /** Full ERC-7913 signer encoding. Its keccak256 must equal newSignerHash. */
  newSigner: Hex;
  newSignerHash: Hex;
  recoveryNonce: bigint;
  intentNonce: Hex;
  identityCommitment: Hex;
  providerId: Hex;
  recoveryDelay: bigint;
  issuedAt: bigint;
  attestationTtl: bigint;
  attestorEpoch: bigint;
}

/** Exact IdentityIntentVerifier.Intent struct signed by each attestor. */
export interface Intent {
  version: number;
  action: Action;
  identityCommitment: Hex;
  account: Address;
  controller: Address;
  currentSignerHash: Hex;
  newSignerHash: Hex;
  recoveryNonce: bigint;
  intentNonce: Hex;
  providerId: Hex;
  providerKeyHash: Hex;
  issuedAt: bigint;
  validAfter: bigint;
  validUntil: bigint;
  chainId: bigint;
  attestorEpoch: bigint;
}

export const intentTypes = {
  Intent: [
    { name: 'version', type: 'uint8' },
    { name: 'action', type: 'uint8' },
    { name: 'identityCommitment', type: 'bytes32' },
    { name: 'account', type: 'address' },
    { name: 'controller', type: 'address' },
    { name: 'currentSignerHash', type: 'bytes32' },
    { name: 'newSignerHash', type: 'bytes32' },
    { name: 'recoveryNonce', type: 'uint256' },
    { name: 'intentNonce', type: 'bytes32' },
    { name: 'providerId', type: 'bytes32' },
    { name: 'providerKeyHash', type: 'bytes32' },
    { name: 'issuedAt', type: 'uint64' },
    { name: 'validAfter', type: 'uint64' },
    { name: 'validUntil', type: 'uint64' },
    { name: 'chainId', type: 'uint256' },
    { name: 'attestorEpoch', type: 'uint64' },
  ],
} as const;

const actionRequestTypes = {
  ActionRequest: [
    { name: 'version', type: 'uint8' },
    { name: 'action', type: 'uint8' },
    { name: 'identityCommitment', type: 'bytes32' },
    { name: 'account', type: 'address' },
    { name: 'controller', type: 'address' },
    { name: 'currentSignerHash', type: 'bytes32' },
    { name: 'newSignerHash', type: 'bytes32' },
    { name: 'recoveryNonce', type: 'uint256' },
    { name: 'intentNonce', type: 'bytes32' },
    { name: 'providerId', type: 'bytes32' },
    { name: 'issuedAt', type: 'uint64' },
    { name: 'validAfter', type: 'uint64' },
    { name: 'validUntil', type: 'uint64' },
    { name: 'chainId', type: 'uint256' },
    { name: 'attestorEpoch', type: 'uint64' },
  ],
} as const;

export const attestationTypes = {
  Attestation: [
    { name: 'intentDigest', type: 'bytes32' },
    { name: 'providerKeyHash', type: 'bytes32' },
    { name: 'tokenIssuedAt', type: 'uint64' },
  ],
} as const;

export function providerPolicyId(policy: string): Hex { return keccak256(stringToHex(policy)); }
export function actionCode(action: Action): number { return { CREATE: 0, ADD: 1, REPLACE: 2 }[action]; }

export function intentTypedData(intent: Intent, verifyingContract: Address) {
  return {
    domain: {
      name: 'OIDC Identity Intent',
      version: '1',
      chainId: intent.chainId,
      verifyingContract: getAddress(verifyingContract),
    },
    types: intentTypes,
    primaryType: 'Intent' as const,
    message: { ...intent, account: getAddress(intent.account), controller: getAddress(intent.controller), action: actionCode(intent.action) },
  } as const;
}

export function intentDigest(intent: Intent, verifyingContract: Address): Hex {
  return hashTypedData(intentTypedData(intent, verifyingContract));
}

export function actionRequestTypedData(request: ActionRequest, verifyingContract: Address) {
  return {
    domain: {
      name: 'OIDC Identity Intent', version: '1', chainId: request.chainId,
      verifyingContract: getAddress(verifyingContract),
    },
    types: actionRequestTypes,
    primaryType: 'ActionRequest' as const,
    message: {
      version: request.version,
      action: actionCode(request.action),
      identityCommitment: request.identityCommitment,
      account: getAddress(request.account),
      controller: getAddress(request.controller),
      currentSignerHash: request.currentSignerHash,
      newSignerHash: request.newSignerHash,
      recoveryNonce: request.recoveryNonce,
      intentNonce: request.intentNonce,
      providerId: request.providerId,
      issuedAt: request.issuedAt,
      validAfter: request.issuedAt,
      validUntil: request.issuedAt + request.attestationTtl,
      chainId: request.chainId,
      attestorEpoch: request.attestorEpoch,
    },
  } as const;
}

export function actionRequestDigest(request: ActionRequest, verifyingContract: Address): Hex {
  return hashTypedData(actionRequestTypedData(request, verifyingContract));
}

export function actionRequestOidcNonce(request: ActionRequest, verifyingContract: Address): string {
  const digestBytes = Buffer.from(actionRequestDigest(request, verifyingContract).slice(2), 'hex');
  return createHash('sha256').update(digestBytes).digest('base64url');
}

export function materializeIntent(request: ActionRequest): Intent {
  return {
    version: request.version,
    action: request.action,
    identityCommitment: request.identityCommitment,
    account: request.account,
    controller: request.controller,
    currentSignerHash: request.currentSignerHash,
    newSignerHash: request.newSignerHash,
    recoveryNonce: request.recoveryNonce,
    intentNonce: request.intentNonce,
    providerId: request.providerId,
    // Each packed attestation carries its own provider key and token issuance time.
    providerKeyHash: `0x${'00'.repeat(32)}`,
    issuedAt: request.issuedAt,
    // Recovery delay is enforced once by IdentityRecoveryManager after the intent is consumed.
    validAfter: request.issuedAt,
    validUntil: request.issuedAt + request.attestationTtl,
    chainId: request.chainId,
    attestorEpoch: request.attestorEpoch,
  };
}

export function attestationTypedData(
  commonIntentDigest: Hex,
  providerKeyHash: Hex,
  tokenIssuedAt: bigint,
  intent: Intent,
  verifyingContract: Address,
) {
  return {
    domain: {
      name: 'OIDC Identity Intent',
      version: '1',
      chainId: intent.chainId,
      verifyingContract: getAddress(verifyingContract),
    },
    types: attestationTypes,
    primaryType: 'Attestation' as const,
    message: { intentDigest: commonIntentDigest, providerKeyHash, tokenIssuedAt },
  } as const;
}
