import {
  getAddress,
  hashTypedData,
  type Address,
  type Hex,
} from 'viem';

export interface CreateRequest {
  account: Address;
  salt: Hex;
  providerPolicyId: Hex;
  identityCommitment: Hex;
  initialSignerHash: Hex;
  validAfter: bigint;
  validUntil: bigint;
}

export interface RecoveryRequest {
  account: Address;
  expectedSignerHash: Hex;
  expectedSignerEpoch: bigint;
  newSignerHash: Hex;
  nonce: bigint;
  validAfter: bigint;
  validUntil: bigint;
}

const createTypes = {
  CreateAccount: [
    { name: 'account', type: 'address' },
    { name: 'salt', type: 'bytes32' },
    { name: 'providerPolicyId', type: 'bytes32' },
    { name: 'identityCommitment', type: 'bytes32' },
    { name: 'initialSignerHash', type: 'bytes32' },
    { name: 'validAfter', type: 'uint64' },
    { name: 'validUntil', type: 'uint64' },
  ],
} as const;

const recoveryTypes = {
  Recovery: [
    { name: 'account', type: 'address' },
    { name: 'expectedSignerHash', type: 'bytes32' },
    { name: 'expectedSignerEpoch', type: 'uint256' },
    { name: 'newSignerHash', type: 'bytes32' },
    { name: 'nonce', type: 'uint256' },
    { name: 'validAfter', type: 'uint64' },
    { name: 'validUntil', type: 'uint64' },
  ],
} as const;

export function createDigest(request: CreateRequest, chainId: bigint, factory: Address): Hex {
  return hashTypedData({
    domain: {
      name: 'OIDC Account Factory',
      version: '1',
      chainId,
      verifyingContract: getAddress(factory),
    },
    types: createTypes,
    primaryType: 'CreateAccount',
    message: { ...request, account: getAddress(request.account) },
  });
}

export function recoveryDigest(
  request: RecoveryRequest,
  chainId: bigint,
  controller: Address,
): Hex {
  return hashTypedData({
    domain: {
      name: 'OIDC Identity Recovery',
      version: '1',
      chainId,
      verifyingContract: getAddress(controller),
    },
    types: recoveryTypes,
    primaryType: 'Recovery',
    message: { ...request, account: getAddress(request.account) },
  });
}

/** The OIDC authorization request sends this exact lowercase bytes32 digest as its nonce string. */
export function createOidcNonce(
  request: CreateRequest,
  chainId: bigint,
  factory: Address,
): Hex {
  return createDigest(request, chainId, factory);
}

/** The OIDC authorization request sends this exact lowercase bytes32 digest as its nonce string. */
export function recoveryOidcNonce(
  request: RecoveryRequest,
  chainId: bigint,
  controller: Address,
): Hex {
  return recoveryDigest(request, chainId, controller);
}
