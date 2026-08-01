import { createHash, randomBytes } from 'node:crypto';
import Fastify, { type FastifyInstance } from 'fastify';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';

interface SigningKey { kid: string; privateKey: CryptoKey; publicJwk: JWK }

export class MockOidcProvider {
  readonly app: FastifyInstance;
  issuer = '';
  readonly audience = 'mock-client';
  readonly codes = new Map<string, Record<string, string>>();
  #keys = new Map<string, SigningKey>();
  #publishedKids: string[] = [];
  jwksRequests = 0;
  now = Math.floor(Date.now() / 1000);

  constructor() {
    this.app = Fastify({ logger: false });
    this.app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_request, body, done) => {
      done(null, Object.fromEntries(new URLSearchParams(body as string)));
    });
    this.app.get('/jwks', async () => {
      this.jwksRequests += 1;
      return { keys: this.#publishedKids.map((kid) => this.#keys.get(kid)!.publicJwk) };
    });
    this.app.get('/authorize', async (request, reply) => {
      const query = request.query as Record<string, string>;
      if (query.response_type !== 'code' || query.scope !== 'openid' || query.code_challenge_method !== 'S256') {
        return reply.code(400).send({ error: 'invalid_request' });
      }
      const code = randomBytes(24).toString('base64url');
      this.codes.set(code, { ...query });
      const callback = new URL(query.redirect_uri!);
      callback.searchParams.set('code', code);
      callback.searchParams.set('state', query.state!);
      return reply.redirect(callback.toString(), 302);
    });
    this.app.post('/token', async (request, reply) => {
      const body = request.body as Record<string, string>;
      const authorization = this.codes.get(body.code!);
      if (authorization === undefined) return reply.code(400).send({ error: 'invalid_grant' });
      this.codes.delete(body.code!);
      const expectedChallenge = createHash('sha256').update(body.code_verifier ?? '').digest('base64url');
      if (body.grant_type !== 'authorization_code' || body.client_id !== this.audience || body.client_secret !== 'secret' ||
          body.redirect_uri !== authorization.redirect_uri || expectedChallenge !== authorization.code_challenge) {
        return reply.code(400).send({ error: 'invalid_grant' });
      }
      const idToken = await this.issueToken(this.#publishedKids.at(-1)!, {
        iat: this.now, auth_time: this.now, exp: this.now + 300, nonce: authorization.nonce,
      });
      return { id_token: idToken, access_token: 'must-never-be-used-as-identity', token_type: 'Bearer', expires_in: 300 };
    });
  }

  async start(): Promise<void> {
    await this.app.listen({ host: '127.0.0.1', port: 0 });
    const address = this.app.server.address();
    if (address === null || typeof address === 'string') throw new Error('mock issuer did not bind TCP');
    this.issuer = `http://127.0.0.1:${address.port}`;
  }

  async stop(): Promise<void> { await this.app.close(); }

  async addKey(kid: string): Promise<JWK> {
    const pair = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
    const publicJwk = await exportJWK(pair.publicKey);
    Object.assign(publicJwk, { kid, alg: 'RS256', use: 'sig' });
    this.#keys.set(kid, { kid, privateKey: pair.privateKey, publicJwk });
    return publicJwk;
  }

  publish(...kids: string[]): void { this.#publishedKids = [...kids]; }

  async thumbprint(kid: string): Promise<string> {
    return calculateJwkThumbprint(this.#keys.get(kid)!.publicJwk, 'sha256');
  }

  async issueToken(kid: string, claims: Record<string, unknown> = {}, algorithm = 'RS256'): Promise<string> {
    const now = typeof claims.iat === 'number' ? claims.iat : Math.floor(Date.now() / 1000);
    const key = this.#keys.get(kid);
    if (key === undefined) throw new Error(`unknown mock key ${kid}`);
    return new SignJWT({
      nonce: 'expected-nonce',
      auth_time: now,
      ...claims,
    })
      .setProtectedHeader({ alg: algorithm, kid, typ: 'JWT' })
      .setIssuer(typeof claims.iss === 'string' ? claims.iss : this.issuer)
      .setAudience(
        typeof claims.aud === 'string' || Array.isArray(claims.aud)
          ? claims.aud as string | string[]
          : this.audience,
      )
      .setSubject(typeof claims.sub === 'string' ? claims.sub : 'private-subject')
      .setIssuedAt(now)
      .setExpirationTime(typeof claims.exp === 'number' ? claims.exp : now + 300)
      .sign(key.privateKey);
  }
}
