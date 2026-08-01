import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseServerOptions } from '../src/server.js';

test('reference server refuses accidental in-memory production storage', () => {
  assert.throws(() => parseServerOptions({}), /ALLOW_IN_MEMORY_STORAGE=true/);
});

test('reference server validates host and port after explicit unsafe opt-in', () => {
  assert.deepEqual(parseServerOptions({ ALLOW_IN_MEMORY_STORAGE: 'true' }), {
    host: '127.0.0.1',
    port: 3000,
  });
  assert.deepEqual(
    parseServerOptions({ ALLOW_IN_MEMORY_STORAGE: 'true', HOST: '0.0.0.0', PORT: '8443' }),
    { host: '0.0.0.0', port: 8443 },
  );
  assert.throws(
    () => parseServerOptions({ ALLOW_IN_MEMORY_STORAGE: 'true', PORT: '70000' }),
    /PORT/,
  );
});
