import { encodeAbiParameters, stringToHex, type Hex } from 'viem';

export function directGoogleJWTProof(compactJwt: string, identitySalt: Hex): Hex {
  const segments = compactJwt.split('.');
  if (
    compactJwt.length === 0 || compactJwt.length > 4_096
    || segments.length !== 3
    || segments.some((segment) => segment.length === 0 || !/^[A-Za-z0-9_-]+$/.test(segment))
  ) {
    throw new Error('invalid compact JWT');
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(identitySalt)) {
    throw new Error('identity salt must be bytes32');
  }
  return encodeAbiParameters(
    [{ type: 'bytes' }, { type: 'bytes32' }],
    [stringToHex(compactJwt), identitySalt],
  );
}
