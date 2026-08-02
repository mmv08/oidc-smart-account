import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeAbiParameters, type Hex } from 'viem';
import { directGoogleJWTProof } from '../src/proofs.js';

test('encodes the compact Google ID token and identity salt for GoogleJWTVerifier', () => {
  const jwt = 'header.payload.signature';
  const salt = `0x${'77'.repeat(32)}` as Hex;
  const proof = directGoogleJWTProof(jwt, salt);
  const [decodedJwt, decodedSalt] = decodeAbiParameters(
    [{ type: 'bytes' }, { type: 'bytes32' }],
    proof,
  );
  assert.equal(Buffer.from(decodedJwt.slice(2), 'hex').toString(), jwt);
  assert.equal(decodedSalt, salt);
});

test('rejects malformed JWT and salt inputs before ABI encoding', () => {
  const salt = `0x${'77'.repeat(32)}` as Hex;
  assert.throws(() => directGoogleJWTProof('not-a-jwt', salt), /compact JWT/);
  assert.throws(() => directGoogleJWTProof('a.b.c=', salt), /compact JWT/);
  assert.throws(() => directGoogleJWTProof('a.b.é', salt), /compact JWT/);
  assert.throws(() => directGoogleJWTProof('a.b.c', '0x12' as Hex), /bytes32/);
});
