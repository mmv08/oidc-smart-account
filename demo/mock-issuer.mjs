// Mock OIDC issuer for the demo. It makes an RSA key, serves the JWKS, and signs ID tokens.
// It does not authenticate the user. Use it only for the local demo.
//
//   node demo/mock-issuer.mjs                    listens on http://127.0.0.1:9000
//   GET /jwks.json                               returns the JWKS
//   GET /token?sub=alice&nonce=0x...             returns an ID token for `sub` with `nonce`

import { generateKeyPairSync, sign } from 'node:crypto';
import { createServer } from 'node:http';

const PORT = 9000;
const ISSUER = 'https://issuer.example';
const AUDIENCE = 'demo-client';
const KID = 'mock-key-1';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const { n, e } = publicKey.export({ format: 'jwk' });
const jwks = { keys: [{ kty: 'RSA', kid: KID, alg: 'RS256', use: 'sig', n, e }] };

function idToken(sub, nonce) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', kid: KID, typ: 'JWT' };
  const claims = { iss: ISSUER, aud: AUDIENCE, sub, nonce, iat: now, exp: now + 600 };
  const signingInput = `${base64url(header)}.${base64url(claims)}`;
  const signature = sign('sha256', Buffer.from(signingInput), privateKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}

function base64url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function reply(response, contentType, body) {
  response.writeHead(200, {
    'content-type': contentType,
    'content-length': Buffer.byteLength(body),
  }).end(body);
}

createServer((request, response) => {
  const url = new URL(request.url, 'http://localhost');
  const sub = url.searchParams.get('sub');
  const nonce = url.searchParams.get('nonce');
  if (url.pathname === '/jwks.json') {
    reply(response, 'application/json', JSON.stringify(jwks));
  } else if (url.pathname === '/token' && sub && nonce) {
    reply(response, 'text/plain', idToken(sub, nonce));
  } else {
    response.writeHead(404).end();
  }
}).listen(PORT, '127.0.0.1', () => {
  console.log(`Mock issuer ${ISSUER} is on http://127.0.0.1:${PORT}`);
});
