import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { apply } from '../index.js';

const events = [
  { type: 'turn/start', time: 1, data: { turn: 1 } },
  { type: 'request/header', time: 2, data: { header: { config: { provider: 'deepseek', model: 'v4' } } } },
  { type: 'user/message', time: 3, data: { message: { content: [{ type: 'text', text: '把底部状态圈换成圆环' }] } } },
  { type: 'tool/call', time: 4, data: { name: 'read', arguments: '{"path":"/a/b.mjs"}' } },
  { type: 'tool/result', time: 5, data: { message: { content: [{ type: 'text', text: '文件内容' }] } } },
  { type: 'assistant/message', time: 6, data: { message: { content: [{ type: 'text', text: '改完了' }] } } },
];

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lifeguard-handoff-'));
}

/** 假宿主：记录会话服务每次调用，llm 由用例自己给。 */
function fakeHost({ llm } = {}) {
  const calls = {
    inspect: [],
    create: [],
    rename: [],
    prompt: [],
    archive: [],
    prepare: [],
    stream: [],
  };
  const sessionController = {
    async list() {
      return { items: [{ sessionId: 'parent-1', running: false }] };
    },
    async inspect(sessionId) {
      calls.inspect.push(sessionId);
      return { events, meta: { cwd: '/tmp' } };
    },
    async create(seed) {
      calls.create.push(seed);
      return { sessionId: 'child-1' };
    },
    async rename(args) {
      calls.rename.push(args);
    },
    async prompt(args) {
      calls.prompt.push(args);
    },
    async archiveSession(args) {
      calls.archive.push(args);
    },
  };
  const workspaceController = {
    async archiveSession(args) {
      calls.archive.push(args);
    },
  };
  const services = { sessionController, workspaceController };
  if (llm) {
    services.llm = {
      async prepareCall(request, signal) {
        calls.prepare.push({ request, signal });
        return {
          config: { provider: request.provider, model: request.model, maxTokens: request.maxTokens },
          stream: llm.stream,
        };
      },
    };
  }
  return { calls, services };
}

function makeContext(services) {
  const registered = [];
  const tools = {
    registered,
    register(tool) {
      registered.push(tool);
      return () => {};
    },
    guard() {
      return () => {};
    },
  };
  const disposers = [];
  const ctx = {
    tools,
    effect(factory) {
      const dispose = factory();
      if (typeof dispose === 'function') disposers.push(dispose);
      return dispose;
    },
    on() {
      return () => {};
    },
    get(key) {
      return services[key];
    },
    dispose() {
      while (disposers.length) disposers.pop()();
    },
  };
  return ctx;
}

function handoffTool(ctx) {
  return ctx.tools.registered.find((tool) => tool.name === 'lifeguard_handoff');
}

async function run({ llm, args = {}, services: given } = {}) {
  const home = tmp();
  const host = fakeHost({ llm });
  const ctx = makeContext({ ...host.services, ...given });
  apply(ctx, { home });
  const tool = handoffTool(ctx);
  assert.ok(tool, 'lifeguard_handoff 应该注册上');
  const signal = new AbortController().signal;
  const result = await tool.execute({ sessionId: 'parent-1', ...args }, { signal });
  ctx.dispose();
  return { result, calls: host.calls, home };
}

const goodStream = async function* () {
  yield { type: 'text-delta', text: '## 当前目标\n把底部状态圈换成圆环\n\n' };
  yield { type: 'text-delta', text: '## 持续约束\n不要动 index.js\n\n## 未完成 / 下一步\n跑一遍测试' };
  yield { type: 'finish', reason: { kind: 'stop' } };
};

test('模型给了完整交接单时，新会话收到的是模型写的那份', async () => {
  const { result, calls } = await run({ llm: { stream: goodStream } });
  assert.equal(calls.prepare.length, 1);
  assert.equal(calls.prepare[0].request.provider, 'deepseek');
  assert.equal(calls.prepare[0].request.model, 'v4');
  assert.equal(calls.prompt.length, 1);
  const text = calls.prompt[0].content[0].text;
  assert.match(text, /【化龙妙法 · 交接单】/);
  assert.match(text, /## 当前目标\n把底部状态圈换成圆环/);
  assert.match(text, /## 持续约束\n不要动 index\.js/);
  assert.match(text, /整理：deepseek\/v4/);
  assert.equal(result.llm, 'deepseek/v4');
  assert.match(result.text, /交接单由 deepseek\/v4 整理/);
  assert.equal(calls.archive.length, 0);
  assert.equal(calls.rename[0].title.endsWith(' · 转世'), true);
});

test('模型失败时退回自动摘要，转世照样完成', async () => {
  const boom = async function* () {
    throw new Error('upstream 502');
  };
  const { result, calls } = await run({ llm: { stream: boom } });
  assert.equal(calls.prompt.length, 1);
  const text = calls.prompt[0].content[0].text;
  assert.match(text, /【化龙妙法 · 交接单】/);
  assert.match(text, /把底部状态圈换成圆环/);
  assert.equal(result.llm, '');
  assert.match(result.text, /自动摘要/);
  assert.match(result.text, /upstream 502/);
  assert.equal(calls.archive.length, 0);
});

test('模型收到非正常收尾也算失败，不把它当交接单', async () => {
  const cut = async function* () {
    yield { type: 'text-delta', text: '话说一半' };
    yield { type: 'finish', reason: { kind: 'max-tokens' } };
  };
  const { result, calls } = await run({ llm: { stream: cut } });
  assert.equal(calls.prompt.length, 1);
  assert.doesNotMatch(calls.prompt[0].content[0].text, /话说一半/);
  assert.match(result.text, /max-tokens/);
});

test('llm:false 完全不调模型，省资源但照样转世', async () => {
  const { result, calls } = await run({ llm: { stream: goodStream }, args: { llm: false } });
  assert.equal(calls.prepare.length, 0);
  assert.equal(calls.prompt.length, 1);
  assert.match(calls.prompt[0].content[0].text, /把底部状态圈换成圆环/);
  assert.match(result.text, /关掉了模型整理/);
});

test('原会话没记下用的模型时不猜，直接自动摘要', async () => {
  const home = tmp();
  const host = fakeHost({ llm: { stream: goodStream } });
  host.services.sessionController.inspect = async () => ({
    events: events.filter((event) => event.type !== 'request/header'),
    meta: {},
  });
  const ctx = makeContext(host.services);
  apply(ctx, { home });
  const result = await handoffTool(ctx).execute({ sessionId: 'parent-1' }, { signal: new AbortController().signal });
  assert.equal(host.calls.prepare.length, 0);
  assert.match(result.text, /没有记录用的模型/);
  ctx.dispose();
});

test('交接单与血缘都落盘，转世记录能查回来', async () => {
  const { calls, home, result } = await run({ llm: { stream: goodStream } });
  const rows = fs
    .readFileSync(path.join(home, 'lifeguard', 'lineage.jsonl'), 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  assert.equal(rows.length, 1);
  assert.equal(rows[0].parent, 'parent-1');
  assert.equal(rows[0].child, 'child-1');
  assert.match(result.text, /转世完成/);
  assert.equal(calls.prompt[0].sessionId, 'child-1');
  assert.equal(calls.prompt[0].mode, 'queue');
});

test('会话还在跑就拒绝，什么都不改', async () => {
  const host = fakeHost({ llm: { stream: goodStream } });
  host.services.sessionController.list = async () => ({ items: [{ sessionId: 'parent-1', running: true }] });
  const ctx = makeContext(host.services);
  apply(ctx, { home: tmp() });
  const result = await handoffTool(ctx).execute({ sessionId: 'parent-1' }, { signal: new AbortController().signal });
  const said = typeof result === 'string' ? result : result.text;
  assert.match(said, /还在跑/);
  assert.equal(host.calls.create.length, 0);
  assert.equal(host.calls.archive.length, 0);
  ctx.dispose();
});

/** 批量转世用的假宿主：会话清单自己给，子会话 id 递增。 */
function batchHost(items) {
  const host = fakeHost();
  const calls = host.calls;
  let seq = 0;
  host.services.sessionController.list = async () => ({ items });
  host.services.sessionController.create = async (seed) => {
    calls.create.push(seed);
    seq += 1;
    return { sessionId: `child-${seq}` };
  };
  return host;
}

async function runBatch({ items, args = {} }) {
  const home = tmp();
  const host = batchHost(items);
  const ctx = makeContext(host.services);
  apply(ctx, { home });
  const tool = handoffTool(ctx);
  const result = await tool.execute({ all: true, ...args }, { signal: new AbortController().signal });
  ctx.dispose();
  return { result, text: result.text, calls: host.calls, home };
}

test('批量默认只列清单：一个会话都不动', async () => {
  const items = [
    { sessionId: 's-1', title: '会话一', running: false },
    { sessionId: 's-2', title: '会话二', running: false },
    { sessionId: 'busy', title: '还在跑', running: true },
  ];
  const { result, calls } = await runBatch({ items });
  assert.match(result.text, /可以转世 2 个会话/);
  assert.match(result.text, /s-1/);
  assert.match(result.text, /s-2/);
  assert.doesNotMatch(result.text, /busy/);
  assert.equal(calls.create.length, 0);
  assert.equal(calls.archive.length, 0);
});

test('要真转世必须点名，批量不建任何会话', async () => {
  const items = [
    { sessionId: 's-1', title: '会话一', running: false },
    { sessionId: 's-2', title: '会话二', running: false },
    { sessionId: 'busy', title: '还在跑', running: true },
  ];
  const { result, calls } = await runBatch({ items, args: { dryRun: false, limit: 2 } });
  assert.equal(calls.create.length, 0, '批量不替用户决定转哪个');
  assert.equal(calls.archive.length, 0);
  assert.match(result.text, /批量不自己动手/);
  assert.match(result.text, /sessionId/);
  assert.match(result.text, /s-1/);
  assert.doesNotMatch(result.text, /busy/);
});

test('新会话建不起来时，失败话说清楚，不会漏出 undefined', async () => {
  const home = tmp();
  const host = fakeHost();
  host.services.sessionController.create = async () => {
    throw new Error('工作区写不进去');
  };
  const ctx = makeContext(host.services);
  apply(ctx, { home });
  const result = await handoffTool(ctx).execute({ sessionId: 'parent-1' }, { signal: new AbortController().signal });
  assert.match(result.text, /新会话没建起来/);
  assert.match(result.text, /工作区写不进去/);
  assert.match(result.text, /原会话没动/);
  assert.doesNotMatch(result.text, /undefined/);
  ctx.dispose();
});

test('dryRun 只把交接单写到磁盘，不建会话、不改原会话', async () => {
  const { result, calls, home } = await run({ llm: { stream: goodStream }, args: { dryRun: true } });
  const preview = path.join(home, 'lifeguard', 'handoff', 'preview-parent-1.md');
  assert.ok(fs.existsSync(preview), '演练应该留下 preview 文件');
  assert.match(fs.readFileSync(preview, 'utf8'), /把底部状态圈换成圆环/);
  assert.equal(result.ok, true);
  assert.equal(result.dryRun, true);
  assert.equal(result.briefPath, preview);
  assert.equal(result.briefChars, fs.readFileSync(preview, 'utf8').length);
  assert.match(result.text, /演练/);
  assert.equal(calls.create.length, 0);
  assert.equal(calls.archive.length, 0);
  assert.equal(calls.rename.length, 0);
  assert.equal(calls.prompt.length, 0);
  assert.equal(fs.existsSync(path.join(home, 'lifeguard', 'lineage.jsonl')), false);
});

test('真转世时交接单在硬盘上且长度一致，ok 才为真', async () => {
  const { result, home } = await run({ llm: { stream: goodStream } });
  const briefPath = path.join(home, 'lifeguard', 'handoff', 'child-1.md');
  assert.ok(fs.existsSync(briefPath), '交接单应该落盘');
  assert.equal(fs.readFileSync(briefPath, 'utf8').length, result.briefChars);
  assert.equal(result.ok, true);
  assert.equal(result.delivered, 'message');
  assert.equal(result.briefPath, briefPath);
});

test('交接单写不进硬盘时明说这次不算数，并把正文带回结果里', async () => {
  const home = tmp();
  const host = fakeHost({ llm: { stream: goodStream } });
  const ctx = makeContext(host.services);
  apply(ctx, { home });
  /* 把 handoff 目录占成一个文件：再往里写必然失败，模拟磁盘不可写。 */
  fs.mkdirSync(path.join(home, 'lifeguard'), { recursive: true });
  fs.writeFileSync(path.join(home, 'lifeguard', 'handoff'), '');
  const result = await handoffTool(ctx).execute({ sessionId: 'parent-1' }, { signal: new AbortController().signal });
  assert.equal(result.ok, false);
  assert.equal(result.briefPath, undefined);
  assert.match(result.text, /不算数|没写成功/);
  assert.match(result.text, /把底部状态圈换成圆环/, '落盘失败时正文必须回填到工具结果');
  ctx.dispose();
});
