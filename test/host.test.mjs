import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { apply } from '../index.js';
import {
  defenseRuntime,
  defenseState,
  describeStatus,
  explicitMode,
  modeOfConfig,
  normalizeMode,
  resetDefenseState,
  snapshot,
} from '../state.mjs';

function tmp(prefix = 'lifeguard-host-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function write(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
}

/** A profile with one linked plugin, so a losing write has a live surface to land on. */
function fixtureProfile() {
  const root = tmp();
  const profile = path.join(root, 'profiles', 'desktop');
  const linked = path.join(root, 'dev-plugin');
  write(path.join(linked, 'package.json'), JSON.stringify({ name: 'dev-plugin', version: '1.0.0', type: 'module' }));
  write(path.join(linked, 'index.js'), 'export function apply() {}\n');
  write(path.join(profile, 'package.json'), JSON.stringify({
    name: 'profile',
    dependencies: { 'dev-plugin': `link:${linked}` },
  }));
  write(path.join(profile, 'cordis.patch.yml'), '- insert:\n    - id: a\n      name: dev-plugin\n');
  return { root, profile, linked };
}

function badCandidate(root) {
  const dir = path.join(root, 'bad-plugin');
  write(path.join(dir, 'package.json'), JSON.stringify({ name: 'bad-plugin', version: '1.0.0', type: 'module' }));
  write(path.join(dir, 'index.js'), "throw new Error('boom at import');\n");
  return dir;
}

/** A host context with just enough surface for the plugin: effects, events, tools, services. */
function makeContext(services = {}) {
  const registered = [];
  const guards = [];
  const listeners = new Map();
  const disposers = [];
  const tools = {
    registered,
    guards,
    register(tool) {
      registered.push(tool);
      return () => {
        const index = registered.indexOf(tool);
        if (index >= 0) registered.splice(index, 1);
      };
    },
    guard(fn) {
      guards.push(fn);
      return () => {
        const index = guards.indexOf(fn);
        if (index >= 0) guards.splice(index, 1);
      };
    },
  };
  const ctx = {
    tools,
    effect(factory) {
      const dispose = factory();
      disposers.push(dispose);
      return dispose;
    },
    on(event, handler) {
      const list = listeners.get(event) ?? [];
      list.push(handler);
      listeners.set(event, list);
      return () => {
        const index = list.indexOf(handler);
        if (index >= 0) list.splice(index, 1);
      };
    },
    get(key) {
      return services[key];
    },
    listeners,
    dispose() {
      while (disposers.length) {
        const dispose = disposers.pop();
        if (typeof dispose === 'function') dispose();
      }
      listeners.clear();
    },
  };
  if (services.tools) ctx.tools = services.tools;
  /* 真实宿主有 ctx.inject(keys, scope => …) 用来等可选服务就绪；这里给个同形实现，
   * 好让「服务在 apply 之后才出现」这个时序也能被测到。 */
  if (typeof services.deferInject === 'function') ctx.inject = services.deferInject;
  return ctx;
}

function guardTool(ctx) {
  return ctx.tools.registered.find((tool) => tool.name === 'lifeguard_guard');
}

function listener(ctx, event) {
  return (ctx.listeners.get(event) ?? [])[0];
}

const next = () => Promise.resolve('next');

async function withProfile(fn) {
  const fixture = fixtureProfile();
  const before = process.env.DSH_PROFILE_DIR;
  process.env.DSH_PROFILE_DIR = fixture.profile;
  try {
    return await fn(fixture);
  } finally {
    if (before === undefined) delete process.env.DSH_PROFILE_DIR;
    else process.env.DSH_PROFILE_DIR = before;
  }
}

beforeEach(() => {
  resetDefenseState();
});

test('the three mode names map one-to-one onto the user choice, legacy switches included', () => {
  assert.equal(modeOfConfig({}), 'protect');
  assert.equal(modeOfConfig({ mode: 'observe' }), 'observe');
  assert.equal(modeOfConfig({ mode: 'off', guard: true }), 'off');
  assert.equal(modeOfConfig({ guard: false }), 'off');
  assert.equal(modeOfConfig({ monitorOnly: true }), 'observe');
  assert.equal(normalizeMode('bogus', 'observe'), 'observe');
  assert.equal(normalizeMode('关闭', 'protect'), 'off');
  assert.equal(explicitMode({}), null);
  assert.equal(explicitMode({ mode: 'off' }), 'off');
  /* A live-editable field reaches the plugin as a ref, not as a plain string. */
  assert.equal(modeOfConfig({ mode: { get: () => 'observe' } }), 'observe');
  assert.equal(explicitMode({ mode: { get: () => 'bogus' } }), null);
});

test('protect denies the losing write and keeps one record per denial, not one per dump', async () => {
  await withProfile(async ({ linked }) => {
    const ctx = makeContext();
    apply(ctx, {});
    assert.equal(ctx.tools.guards.length, 1);
    assert.ok(listener(ctx, 'tools/pre-execute'));

    const exec = {
      name: 'write',
      callId: 'call-1',
      arguments: { file_path: path.join(linked, 'index.js'), content: "throw new Error('boom');\n" },
    };
    const first = ctx.tools.guards[0](exec);
    assert.match(String(first), /^\[LIFEGUARD_BLOCKED\]/);

    const info = defenseState();
    assert.equal(info.mode, 'protect');
    assert.equal(info.capability, 'normal');
    assert.equal(info.denialCount, 1);
    assert.equal(info.denials[0].rule, 'P014');
    assert.equal(info.lastResult.verdict, 'deny');

    const at = info.denials[0].at;
    ctx.tools.guards[0](exec);
    ctx.tools.guards[0](exec);
    const after = defenseState();
    assert.equal(after.denialCount, 1, 'the same call must not add a second record');
    assert.equal(after.denials[0].hits, 3);
    assert.equal(after.denials[0].at, at, 'the first record is never overwritten');
    ctx.dispose();
  });
});

test('observe mode sees the same risk, records it, and never refuses', async () => {
  await withProfile(async ({ linked }) => {
    const ctx = makeContext();
    apply(ctx, { mode: 'observe' });
    assert.equal(ctx.tools.guards.length, 1, 'monitoring still needs the hook to see anything');

    const outcome = ctx.tools.guards[0]({
      name: 'write',
      callId: 'call-observe',
      arguments: { file_path: path.join(linked, 'index.js'), content: "throw new Error('boom');\n" },
    });
    assert.equal(outcome, undefined, 'observe mode must not deny');

    const info = defenseState();
    assert.equal(info.mode, 'observe');
    assert.equal(info.monitorOnly, true);
    assert.equal(info.capability, 'normal');
    assert.equal(info.denialCount, 1);
    assert.equal(info.denials[0].verdict, 'observe');
    assert.equal(info.lastResult.verdict, 'observe');
    ctx.dispose();
  });
});

test("status card says whether the install check is on", () => {
  const on = describeStatus(undefined, { installCheck: true }).join("\n");
  assert.match(on, /安装体检 开/);
  const off = describeStatus(undefined, { installCheck: false }).join("\n");
  assert.match(off, /安装体检 关/);
});

test('off mode installs no hook and reports 已关闭, never 保护中', async () => {
  const ctx = makeContext();
  apply(ctx, { mode: 'off' });
  assert.equal(ctx.tools.guards.length, 0);
  assert.equal(listener(ctx, 'tools/pre-execute'), undefined);
  const info = defenseState();
  assert.equal(info.modeLabel, '关闭');
  assert.equal(info.capabilityLabel, '已关闭');
  assert.equal(info.enabled, false);
  assert.ok(!describeStatus().join('\n').includes('保护中'));
  ctx.dispose();
});

test('a live-editable config ref drives the mode without a restart', async () => {
  await withProfile(async ({ linked }) => {
    let value = 'observe';
    const ref = { get: () => value };
    const ctx = makeContext();
    apply(ctx, { mode: ref });
    assert.equal(defenseState().mode, 'observe');
    assert.equal(ctx.tools.guards.length, 1, 'a monitoring run still needs the hook');

    /* The app commits the new value in place: same ref, new snapshot, no second apply. */
    value = 'off';
    const off = await guardTool(ctx).execute({});
    assert.match(off.text, /模式 关闭/);
    assert.equal(defenseState().mode, 'off');
    assert.equal(ctx.tools.guards.length, 0, '关闭 takes the hooks back out, it does not leave them dormant');

    /* And back on again, still without a second apply(). */
    value = 'protect';
    await guardTool(ctx).execute({});
    assert.equal(ctx.tools.guards.length, 1, '开启 mounts exactly one hook');
    const outcome = ctx.tools.guards[0]({
      name: 'write',
      callId: 'call-ref',
      arguments: { file_path: path.join(linked, 'index.js'), content: "throw new Error('boom');\n" },
    });
    assert.match(String(outcome), /^\[LIFEGUARD_BLOCKED\]/);
    ctx.dispose();
  });
});

test('a host without the tools service reports 不可用 instead of claiming protection', () => {
  const ctx = makeContext();
  delete ctx.tools;
  apply(ctx, {});
  const info = defenseState();
  assert.equal(info.capability, 'unavailable');
  assert.equal(info.capabilityLabel, '不可用');
  const text = describeStatus().join('\n');
  assert.match(text, /实际状态 不可用/);
  assert.match(text, /重启/);
  assert.ok(!text.includes('保护中'));
  ctx.dispose();
});

test('a hot reload keeps the denial history and never doubles the hooks', async () => {
  await withProfile(async ({ linked }) => {
    const ctx = makeContext();
    apply(ctx, {});
    const refuse = () => ctx.tools.guards[0]({
      name: 'write',
      callId: 'call-hot',
      arguments: { file_path: path.join(linked, 'index.js'), content: "throw new Error('boom');\n" },
    });
    assert.match(String(refuse()), /LIFEGUARD_BLOCKED/);

    ctx.dispose();
    assert.equal(ctx.tools.guards.length, 0, 'disposing removes the hook');

    apply(ctx, {});
    assert.equal(ctx.tools.guards.length, 1, 're-apply installs exactly one hook');
    /* 第 1 个是崩溃防线，第 2 个是安装体检的 passive listener */
    assert.equal((ctx.listeners.get('tools/pre-execute') ?? []).length, 2);
    assert.equal(defenseState().denialCount, 1, 'a reload must not clear the denials');
    ctx.dispose();
  });
});

test('the guard card renders from the live snapshot and nothing else', async () => {
  await withProfile(async ({ linked }) => {
    const ctx = makeContext();
    apply(ctx, {});
    ctx.tools.guards[0]({
      name: 'write',
      callId: 'call-card',
      arguments: { file_path: path.join(linked, 'index.js'), content: "throw new Error('boom');\n" },
    });
    const value = await guardTool(ctx).execute({ limit: 5 });
    const info = defenseState();
    assert.match(value.text, /模式 开启/);
    assert.match(value.text, /实际状态 正常/);
    assert.match(value.text, /最近拒绝 1 条/);
    assert.equal(value.capability, info.capability);
    assert.equal(value.denials.length, info.denialCount);
    assert.ok(!value.text.includes('保护中'));
    await guardTool(ctx).execute({ limit: 5 });
    assert.equal(defenseState().denialCount, 1, 'a read-only call must not write anything');
    ctx.dispose();
  });
});

test('a denial inside a PTC subcall reaches the originating session exactly once', async () => {
  await withProfile(async ({ root }) => {
    const bad = badCandidate(root);
    const ctx = makeContext();
    apply(ctx, {});
    const exec = {
      name: 'plugin_manager',
      callId: 'sub-1',
      rootCallId: 'root-1:ptc:1',
      arguments: { action: 'install_bundle', target: bad },
    };
    const decision = await listener(ctx, 'tools/pre-execute')(exec, next);
    assert.equal(decision.kind, 'deny');
    assert.equal(defenseState().denialCount, 1);

    const first = await listener(ctx, 'tools/post-execute')(exec, { isError: true }, next);
    assert.equal(first.kind, 'accept');
    assert.equal(first.additionalContexts.length, 1);
    const message = first.additionalContexts[0];
    assert.equal(message.source.kind, 'ptc-mode');
    const text = message.content[0].text;
    assert.match(text, /会话可以继续/);
    assert.match(text, /P014/);
    assert.match(text, /未执行：plugin_manager/);

    let passthrough = 0;
    const second = await listener(ctx, 'tools/post-execute')(exec, { isError: true }, async () => {
      passthrough += 1;
      return 'next';
    });
    assert.equal(passthrough, 1, 'the same subcall is reported once');
    assert.equal(second, 'next');

    const direct = { name: 'write', callId: 'top-1', rootCallId: 'top-1', arguments: {} };
    let top = 0;
    await listener(ctx, 'tools/post-execute')(direct, { isError: true }, async () => {
      top += 1;
      return 'next';
    });
    assert.equal(top, 1, 'a direct call is left to the host, not duplicated into the session');
    ctx.dispose();
  });
});

test('the mode is written through the config editor and takes effect before the restart', async () => {
  const edits = [];
  const services = {
    configEditor: {
      configuration: () => [{ entry: { options: { id: 'lifeguard', name: 'dsh-lifeguard' } } }],
      edit: async (entry, change) => {
        edits.push(change({ mode: 'protect', home: '/tmp/home', guard: false }));
      },
    },
  };
  await withProfile(async ({ linked }) => {
    const ctx = makeContext(services);
    apply(ctx, {});
    const before = await guardTool(ctx).execute({});
    assert.equal(edits.length, 0, 'a plain read writes nothing');

    const after = await guardTool(ctx).execute({ mode: 'off' });
    assert.equal(edits.length, 1);
    assert.equal(edits[0].mode, 'off');
    assert.equal('guard' in edits[0], false, 'the old switch is replaced, not left behind');
    assert.match(after.note, /模式已切到 关闭/);
    assert.equal(defenseState().mode, 'off');
    assert.equal(defenseState().capabilityLabel, '已关闭');

    assert.equal(ctx.tools.guards.length, 0, '关闭 unmounts the hook, so nothing can deny');

    await guardTool(ctx).execute({ mode: 'protect' });
    assert.equal(edits.length, 2);
    assert.equal(ctx.tools.guards.length, 1, '开启 mounts it again without a restart');
    const outcome = ctx.tools.guards[0]({
      name: 'write',
      callId: 'call-after-on',
      arguments: { file_path: path.join(linked, 'index.js'), content: "throw new Error('boom');\n" },
    });
    assert.match(String(outcome), /^\[LIFEGUARD_BLOCKED\]/);

    await guardTool(ctx).execute({});
    assert.equal(edits.length, 2, 'cancel persists nothing');
    ctx.dispose();
  });
});

test('a missing config editor says so and leaves the mode alone', async () => {
  const ctx = makeContext();
  apply(ctx, {});
  const value = await guardTool(ctx).execute({ mode: 'observe' });
  assert.match(value.note, /没有保存/);
  assert.equal(defenseState().mode, 'protect');
  ctx.dispose();
});

test('the snapshot carries the three layers as separate values', () => {
  const state = defenseRuntime();
  assert.deepEqual(Object.keys(snapshot()).sort(), [
    'capability',
    'capabilityLabel',
    'coverage',
    'denialCount',
    'denials',
    'enabled',
    'hooks',
    'lastError',
    'lastResult',
    'mode',
    'modeLabel',
    'monitorOnly',
  ].sort());
  state.lastError = null;
  assert.equal(defenseState().mode, 'protect');
});


test('the memory ring route is mounted when webServer already exists', async () => {
  await withProfile(async () => {
    const routes = [];
    const server = { register: (route) => { routes.push(route); return () => {}; } };
    const ctx = makeContext({ webServer: server });
    apply(ctx, {});
    /* 圈和构成各一条路由：圈常驻，构成只在点开时才被请求。 */
    assert.equal(routes.length, 2);
    const health = routes.find((route) => route.path === '/lifeguard/health');
    const memory = routes.find((route) => route.path === '/lifeguard/memory');
    assert.ok(health && memory, '两条路由都要挂上');
    assert.equal(memory.kind, 'exact');
    const body = await new Promise((resolve) => {
      const chunks = [];
      health.handler({}, { writeHead: () => {}, end: (chunk) => resolve(String(chunk)) });
      void chunks;
    });
    const payload = JSON.parse(body);
    assert.equal(payload.enabled, true);
    assert.ok(Number.isFinite(payload.pct));
  });
});

test('a webServer that only shows up after apply still gets the route', async () => {
  await withProfile(async () => {
    const routes = [];
    const server = { register: (route) => { routes.push(route); return () => {}; } };
    let injected = null;
    /* 服务此刻还不在：apply 时 ctx.get('webServer') 是 undefined，正是圈静默消失的那种时序。 */
    const ctx = makeContext({ deferInject: (keys, scopeFactory) => { injected = { keys, scopeFactory }; } });
    apply(ctx, {});
    assert.equal(routes.length, 0);
    assert.deepEqual(injected.keys, ['webServer']);
    ctx.get = (key) => (key === 'webServer' ? server : undefined);
    injected.scopeFactory(ctx);
    assert.equal(routes.length, 2);
    assert.deepEqual(routes.map((route) => route.path).sort(), ['/lifeguard/health', '/lifeguard/memory']);
  });
});
