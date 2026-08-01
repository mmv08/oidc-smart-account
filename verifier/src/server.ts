import { pathToFileURL } from 'node:url';
import { loadConfig } from './config.js';
import { createVerifierApp } from './service.js';
import { InMemoryStorage } from './storage.js';

export interface ServerOptions {
  host: string;
  port: number;
}

export function parseServerOptions(environment: Record<string, string | undefined>): ServerOptions {
  if (environment.ALLOW_IN_MEMORY_STORAGE !== 'true') {
    throw new Error(
      'Reference server uses volatile storage; set ALLOW_IN_MEMORY_STORAGE=true only for local evaluation',
    );
  }
  const host = environment.HOST?.trim() || '127.0.0.1';
  const portText = environment.PORT ?? '3000';
  if (!/^[1-9][0-9]*$/.test(portText)) throw new Error('PORT must be an integer from 1 to 65535');
  const port = Number(portText);
  if (!Number.isSafeInteger(port) || port > 65_535) {
    throw new Error('PORT must be an integer from 1 to 65535');
  }
  return { host, port };
}

export async function runReferenceServer(
  environment: Record<string, string | undefined> = process.env,
): Promise<void> {
  const options = parseServerOptions(environment);
  const config = loadConfig(environment);
  const app = createVerifierApp({ config, storage: new InMemoryStorage() });
  await app.listen(options);
  process.stdout.write(`OIDC verifier listening on ${options.host}:${options.port}\n`);
}

const entryPath = process.argv[1];
if (entryPath !== undefined && import.meta.url === pathToFileURL(entryPath).href) {
  runReferenceServer().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : 'unknown startup error';
    process.stderr.write(`Verifier startup failed: ${message}\n`);
    process.exitCode = 1;
  });
}
