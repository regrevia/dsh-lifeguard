import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const require = createRequire(import.meta.url);

async function text(name) {
  return readFile(path.join(root, name), 'utf8');
}

test('client bundle parses and registers the health ring in the composer dock', async () => {
  const source = await text('client.js');
  assert.doesNotThrow(() => new Function(source));
  assert.match(source, /__ModuleLoader__\.load\(/);
  assert.match(source, /id: 'dsh-lifeguard'/);
  assert.match(source, /conversation\.composer\.dock/);
  assert.match(source, /\/lifeguard\/health/);
  assert.match(source, /inject: \['slots'\]/);
});

test('the manifest exposes the client half and points the loader at it', async () => {
  const manifest = require(path.join(root, 'package.json'));
  assert.equal(manifest.exports['./client'], './client.js');
  assert.ok(manifest.files.includes('client.js'), 'client.js 必须进 npm 包，否则装完没有状态圈');
  assert.equal(manifest.dsh.client.platform, 'web');
  assert.ok(Array.isArray(manifest.dsh.client.inject) && manifest.dsh.client.inject.length > 0);
});

test('the ring counts against the crash wall, not the nominal limit', async () => {
  const { heapPressure } = await import('../watchdog.mjs');
  const status = { samples: 3, heapMB: 2647, limitMB: 4192 };
  const pressure = heapPressure(status, { crashMB: 3529 });
  assert.equal(pressure.basis, 'crash');
  assert.equal(pressure.wallMB, 3529);
  assert.equal(pressure.pct, 75);
  const limit = heapPressure(status, { crashMB: 0 });
  assert.equal(limit.basis, 'limit');
  assert.equal(limit.wallMB, 4192, '没有崩溃点时，死点就是上限本身');
  assert.ok(heapPressure({ samples: 0 }, {}) && heapPressure({ samples: 0 }, {}).basis === 'none');
});
