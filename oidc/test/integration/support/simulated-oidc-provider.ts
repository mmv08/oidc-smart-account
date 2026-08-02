import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { generateKeyPair, exportJWK } from 'jose';
// oidc-provider is an OpenID Certified test/authorization server but does not publish TypeScript declarations.
// @ts-expect-error -- package intentionally ships JavaScript only
import { Provider } from 'oidc-provider';

interface SimulatedProviderOptions {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  subject: string;
}

export interface SimulatedOIDCProvider {
  issuer: string;
  localEndpoint(providerUrl: string): URL;
  completeAuthorization(authorizationUrl: URL): Promise<URL>;
  close(): Promise<void>;
}

interface StoredArtifact {
  payload: Record<string, unknown>;
  expiresAt: number | undefined;
}

const artifactStores = new Map<string, Map<string, StoredArtifact>>();

class TestMemoryAdapter {
  private readonly store: Map<string, StoredArtifact>;

  constructor(name: string) {
    this.store = new Map();
    artifactStores.set(name, this.store);
  }

  async upsert(id: string, payload: Record<string, unknown>, expiresIn: number): Promise<void> {
    this.store.set(id, {
      payload,
      expiresAt: expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : undefined,
    });
  }

  async find(id: string): Promise<Record<string, unknown> | undefined> {
    const artifact = this.store.get(id);
    if (!artifact) return undefined;
    if (artifact.expiresAt && artifact.expiresAt <= Math.floor(Date.now() / 1000)) {
      this.store.delete(id);
      return undefined;
    }
    return artifact.payload;
  }

  async findByUid(uid: string): Promise<Record<string, unknown> | undefined> {
    return this.findBy('uid', uid);
  }

  async findByUserCode(userCode: string): Promise<Record<string, unknown> | undefined> {
    return this.findBy('userCode', userCode);
  }

  async destroy(id: string): Promise<void> {
    this.store.delete(id);
  }

  async consume(id: string): Promise<void> {
    const artifact = this.store.get(id);
    if (artifact) artifact.payload.consumed = Math.floor(Date.now() / 1000);
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    for (const [id, artifact] of this.store) {
      if (artifact.payload.grantId === grantId) this.store.delete(id);
    }
  }

  private async findBy(
    property: 'uid' | 'userCode',
    value: string,
  ): Promise<Record<string, unknown> | undefined> {
    for (const [id, artifact] of this.store) {
      if (artifact.payload[property] === value) return this.find(id);
    }
    return undefined;
  }
}

export async function startSimulatedOIDCProvider(
  options: SimulatedProviderOptions,
): Promise<SimulatedOIDCProvider> {
  let requestHandler: (request: IncomingMessage, response: ServerResponse) => void = (_request, response) => {
    response.statusCode = 503;
    response.end('provider is starting');
  };
  const server = createServer((request, response) => requestHandler(request, response));
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });

  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('missing provider address');
  const localOrigin = `http://127.0.0.1:${address.port}`;
  const issuer = options.issuer;

  const { privateKey } = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  const signingKey = await exportJWK(privateKey);
  signingKey.kid = 'simulated-rs256-key';
  signingKey.use = 'sig';
  signingKey.alg = 'RS256';

  const provider = new Provider(issuer, {
    adapter: TestMemoryAdapter,
    clients: [{
      client_id: options.clientId,
      client_secret: options.clientSecret,
      redirect_uris: [options.redirectUri],
      response_types: ['code'],
      grant_types: ['authorization_code'],
      token_endpoint_auth_method: 'client_secret_post',
      id_token_signed_response_alg: 'RS256',
    }],
    claims: { openid: ['sub'] },
    cookies: { keys: [randomBytes(32).toString('hex')] },
    features: { devInteractions: { enabled: false } },
    jwks: { keys: [signingKey] },
    ttl: {
      AccessToken: 600,
      Grant: 600,
      IdToken: 600,
      Interaction: 600,
      Session: 600,
    },
    async findAccount(_context: unknown, accountId: string) {
      return {
        accountId,
        async claims() {
          return { sub: accountId };
        },
      };
    },
    interactions: {
      url(_context: unknown, interaction: { uid: string }) {
        return `/interaction/${interaction.uid}`;
      },
    },
  });

  const oidcHandler = provider.callback();
  requestHandler = (request, response) => {
    void (async () => {
      const requestUrl = new URL(request.url ?? '/', localOrigin);
      if (requestUrl.pathname.startsWith('/interaction/')) {
        const details = await provider.interactionDetails(request, response);
        if (details.prompt.name === 'login') {
          await provider.interactionFinished(
            request,
            response,
            { login: { accountId: options.subject } },
            { mergeWithLastSubmission: false },
          );
          return;
        }
        if (details.prompt.name === 'consent') {
          let grantId = details.grantId;
          if (!grantId) {
            const grant = new provider.Grant({
              accountId: details.session.accountId,
              clientId: details.params.client_id,
            });
            if (details.prompt.details.missingOIDCScope) {
              grant.addOIDCScope(details.prompt.details.missingOIDCScope.join(' '));
            }
            if (details.prompt.details.missingOIDCClaims) {
              grant.addOIDCClaims(details.prompt.details.missingOIDCClaims);
            }
            grantId = await grant.save();
          }
          await provider.interactionFinished(
            request,
            response,
            { consent: { grantId } },
            { mergeWithLastSubmission: true },
          );
          return;
        }
        throw new Error(`unsupported simulated interaction: ${details.prompt.name}`);
      }
      oidcHandler(request, response);
    })().catch((error: unknown) => {
      if (!response.headersSent) response.statusCode = 500;
      response.end(error instanceof Error ? error.message : String(error));
    });
  };

  return {
    issuer,
    localEndpoint(providerUrl: string): URL {
      const endpoint = new URL(providerUrl);
      if (endpoint.origin === localOrigin) return endpoint;
      if (endpoint.origin !== new URL(issuer).origin) {
        throw new Error(`endpoint is outside simulated issuer: ${providerUrl}`);
      }
      return new URL(`${endpoint.pathname}${endpoint.search}`, localOrigin);
    },
    async completeAuthorization(authorizationUrl: URL): Promise<URL> {
      let current = authorizationUrl;
      const cookies = new Map<string, string>();
      for (let redirects = 0; redirects < 12; redirects += 1) {
        const response = await fetch(current, {
          redirect: 'manual',
          ...(cookies.size === 0
            ? {}
            : {
                headers: {
                  cookie: [...cookies.entries()]
                    .map(([name, value]) => `${name}=${value}`)
                    .join('; '),
                },
              }),
        });
        for (const cookie of response.headers.getSetCookie()) {
          const [pair] = cookie.split(';', 1);
          if (!pair) continue;
          const separator = pair.indexOf('=');
          if (separator > 0) cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
        }
        const location = response.headers.get('location');
        if (!location) {
          throw new Error(`authorization stopped with HTTP ${response.status}: ${await response.text()}`);
        }
        let next = new URL(location, current);
        if (next.origin + next.pathname === options.redirectUri) return next;
        if (next.origin === new URL(issuer).origin) {
          next = new URL(`${next.pathname}${next.search}`, localOrigin);
        }
        current = next;
      }
      throw new Error('too many simulated authorization redirects');
    },
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => {
        artifactStores.clear();
        error ? reject(error) : resolve();
      });
    }),
  };
}
