/**
 * dsh-lifeguard Host plugin: on activation scan new crash artifacts, keep the compact
 * rule set as a resident prompt section, and offer tools to scan / inspect / record / preflight / heal.
 *
 * Every service read is guarded: an undeclared property read on a Cordis context throws,
 * and a plugin whose job is preventing crashes must not become one.
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { randomUUID } from 'node:crypto';
import { compactRules, DEFAULT_HOME, importCorpus, maxCrashHeapMB, migrateLegacyStore, PROMPT_HEADER, readIncidents, readRules, readState, renderLorePrompt, scan, seedRules, storeDir, summarizeIncident, upsertRule } from './core.mjs';
import { guardWrite, guardShell, preExecute, liveSurfaces, denial } from './defense.mjs';
import { heapLine, heapPressure, noteCrashMB, startWatchdog, stopWatchdog, watchdogStatus } from './watchdog.mjs';
import { DEFAULT_BUDGET_MB, SWEEP_EVERY_MS, maybeSweep } from './tmp.mjs';
import { admit, readLive, wallFor } from './pressure.mjs';
import { footprintLines, oomEvidenceLines, sessionFootprint } from './lib/sessions.mjs';
import { crashLoops, loopLines } from './lib/attribute.mjs';
import {
  MODE_LABELS,
  MODES,
  claimFeedback,
  clearHooks,
  defenseRuntime,
  defenseState,
  denialFor,
  describeStatus,
  explicitMode,
  modeOfConfig,
  normalizeMode,
  recentDenials,
  recordCheck,
  recordError,
  recordFinding,
  setHook,
  setMode,
} from './state.mjs';
import { apply as applyInstallCheck } from './install-check/index.mjs';
import {
  appendLineage,
  buildBrief,
  buildEvidence,
  buildLlmBrief,
  clip,
  generationOf,
  handoffInput,
  handoffSystemPrompt,
  lineageChain,
  normalizeHandoffBody,
  readLineage,
  requestRoute,
} from './handoff.mjs';

export const name = 'dsh-lifeguard';
/* 旧版插件 id 只用于读取旧 profile 里已存在的 entry，不再注册第二份。 */
const LEGACY_ID = 'crash-lore';
/* Harness ≥ the 2026-09 tool contract: every tool must declare an output shape and a renderer.
 * Keep the payload object and render its `text` field. */
const TOOL_OUTPUT = {
  schema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'], additionalProperties: true },
  render: (_args, value) => [{ type: 'text', text: String(value?.text ?? '') }],
};

function withOutput(tool) {
  const execute = tool.execute;
  return {
    ...tool,
    output: TOOL_OUTPUT,
    execute: async (...rest) => {
      const value = await execute(...rest);
      return typeof value === 'string' ? { text: value } : { ...value, text: String(value?.text ?? '') };
    },
  };
}

/* 让模型整理交接单：一次调用、有超时、有输出上限、失败就退回自动摘要。
 * 内存已经很高的时候就不跑这次调用：整理交接单不该再占一大块内存。 */
const HANDOFF_TIMEOUT_MS = 180000;
const HANDOFF_MAX_TOKENS = 8000;
const HANDOFF_TEXT_MAX = 40000;
const HANDOFF_LLM_MAX_PCT = 85;
/* 批量转世做到这个占用率就停：转世自己也要读记录、建会话，堆越满越不值得再叠。 */
const BATCH_STOP_PCT = 92;

/** 优先用自带的构造器（带 id 和来源），解析不到就用最小结构。 */
function userMessage(text) {
  const content = [{ type: 'text', text }];
  try {
    const base = process.env.DSH_PROFILE_DIR ? path.join(process.env.DSH_PROFILE_DIR, 'package.json') : import.meta.url;
    const mod = createRequire(base)('@deepseek-ai/dsh-llm');
    const create = propOf(mod, 'createUserMessage');
    if (typeof create === 'function') return create({ content, source: { kind: 'dsh-lifeguard' } });
  } catch {
    /* 解析不到就自己拼，adapter 认 role/content 就够了 */
  }
  return { role: 'user', content };
}

/** 跑一次单发调用，收完整文本；非 stop 收尾算失败，交给上层退回自动摘要。 */
async function generateHandoffBody({ llm, route, events, parentId, parentTitle, sessionId, ancestors, signal }) {
  const evidence = buildEvidence({ events });
  const input = handoffInput({ parentId, parentTitle, evidence: evidence.text, ancestors });
  const controller = new AbortController();
  const timer = setTimeout(() => {
    try {
      controller.abort();
    } catch {
      /* 已经放弃 */
    }
  }, HANDOFF_TIMEOUT_MS);
  try {
    const deadline = typeof AbortSignal.any === 'function' ? AbortSignal.any([signal, controller.signal]) : controller.signal;
    const prepared = await llm.prepareCall({ provider: route.provider, model: route.model, maxTokens: HANDOFF_MAX_TOKENS }, deadline);
    const options = {
      ...propOf(prepared, 'config'),
      messages: [userMessage(input)],
      system: handoffSystemPrompt(),
      sessionId,
      purpose: 'lifeguard-handoff',
      signal: deadline,
    };
    let text = '';
    let finish;
    let truncated = false;
    for await (const chunk of prepared.stream(options)) {
      if (!chunk || typeof chunk !== 'object') continue;
      if (chunk.type === 'text-delta' && typeof chunk.text === 'string') {
        text += chunk.text;
        if (text.length > HANDOFF_TEXT_MAX) {
          truncated = true;
          break;
        }
      } else if (chunk.type === 'finish') finish = chunk.reason;
    }
    const kind = propOf(finish, 'kind');
    if (kind !== undefined && kind !== 'stop') {
      const failure = propOf(propOf(finish, 'failure'), 'message');
      throw new Error(`模型没给出完整交接单（${kind}${failure ? `：${failure}` : ''}）`);
    }
    return { text, evidence, truncated };
  } finally {
    clearTimeout(timer);
  }
}

export const inject = ['tools'];

/* The live-editable mode needs a real schemastery schema, but this package is normally
 * mounted through a symlink whose realpath has no node_modules: a bare import would fail to
 * resolve and take boot down with it. Resolve through the running profile, and stay silent
 * when that fails — the mode is then only reachable through the tool, never through a crash. */
function schemaFactory() {
  const bases = [];
  if (process.env.DSH_PROFILE_DIR) bases.push(path.join(process.env.DSH_PROFILE_DIR, 'package.json'));
  bases.push(import.meta.url);
  for (const base of bases) {
    try {
      const load = createRequire(base);
      const loaded = load('@deepseek-ai/schemastery');
      const z = loaded?.default ?? loaded;
      if (z && typeof z.object === 'function' && typeof z.string === 'function') return z;
    } catch {
      /* try the next base */
    }
  }
  return undefined;
}

function makeConfig() {
  const z = schemaFactory();
  if (!z) return undefined;
  try {
    /* A live-editable field is a volatile ref: the app swaps the value in place instead of
     * restarting the plugin. Older schema packages have no such marking, and boot must not fail. */
    const mode = z.string().default('protect').description('崩溃防护模式：protect 开启，observe 仅监测，off 关闭');
    const marked = typeof mode.volatile === 'function' ? mode.volatile() : mode;
    return z.object({
      mode: marked,
      home: z.string().description('崩溃日志与规则所在目录'),
      promptChars: z.number().default(0).description('提示词里规则的字数上限；0 表示不写进提示词，只在面板里看'),
      guard: z.boolean().description('旧开关，等价于 mode=off'),
      monitorOnly: z.boolean().description('旧开关，等价于 mode=observe'),
      installCheck: z.boolean().default(true).description('装插件前先跟已装的比一遍：重名、缺依赖、版本、skill 撞车'),
      overlapCheck: z.boolean().default(true).description('装插件时提示和已装插件的功能重叠（同一个位置、同一类能力）'),
      implCheck: z.boolean().default(true).description('装插件前读一遍候选源码：会不会一激活就带走宿主'),
      healthBadge: z.boolean().default(true).description('输入框下方显示内存占用状态圈，接近崩溃上限时变红'),
    });
  } catch {
    return undefined;
  }
}

export const Config = makeConfig();

function propOf(target, key) {
  try {
    return target?.[key];
  } catch {
    return undefined;
  }
}

function serviceOf(ctx, key) {
  const direct = propOf(ctx, key);
  if (direct !== undefined && direct !== null) return direct;
  const get = propOf(ctx, 'get');
  try {
    const value = typeof get === 'function' ? get.call(ctx, key) : undefined;
    return value ?? null;
  } catch {
    return null;
  }
}

function log(message) {
  try {
    console.log(`[lifeguard] ${message}`);
  } catch {
    /* console gone during shutdown */
  }
}

/* 工作区成员是「记录里的 id」再过一遍 cwd 索引，两步都可能没认下新会话：这里只认回读结果。 */
function workspaceHasSession(ws, sessionId) {
  try {
    const ids = propOf(ws, 'sessionIds');
    return Array.isArray(ids) && ids.includes(sessionId);
  } catch {
    return false;
  }
}

/* 新会话的表头：活的会话进程里就有，没有就去会话服务要一次，都拿不到返回 null。 */
function liveHeaderOf(ctx, sessionId) {
  const sessions = serviceOf(ctx, 'sessions');
  if (!sessions) return null;
  try {
    const session = typeof sessions.get === 'function' ? sessions.get(sessionId) : undefined;
    if (session && session.header) return session.header;
  } catch {
    /* fall through */
  }
  try {
    const list = typeof sessions.list === 'function' ? sessions.list() : [];
    const found = list.find((item) => item?.header?.id === sessionId);
    return found?.header ?? null;
  } catch {
    return null;
  }
}

/* The wall that actually kills this machine, read from its own crash log: V8 dies in old space
 * before the nominal limit, so the badge counts against the observed death heap, not the limit. */
let crashWallCache = null;
/* 崩溃点必须自己跟着日志变：文件没动就复用（一次 stat，不读盘），动了或超过一分钟就重算。
 * 换了机器、换了崩溃记录、或另一个宿主刚写进新的一条，圈最多一分钟就跟上。 */
const CRASH_WALL_TTL_MS = 60_000;
let crashWallStamp = -1;
let crashWallAt = 0;
/* 底部状态圈的自检：路由到底挂上没有，只有这里知道。不进 prompt，只在 lifeguard_guard 里显示，
 * 免得「圈没数据」和「圈坏了」永远分不出来。 */
const badgeState = { mounted: false, path: '/lifeguard/health', error: '' };
/* 跨平台：Windows/Linux/macOS 都只看 mtimeMs；读不到（文件还没建、权限）就当没有。 */
function statMtime(file) {
  try {
    return fs.statSync(file).mtimeMs;
  } catch {
    return 0;
  }
}

function crashWallMB(home) {
  let stamp = 0;
  try {
    stamp = statMtime(paths(home).incidents);
  } catch {
    stamp = 0;
  }
  const fresh = crashWallCache !== null && stamp === crashWallStamp && Date.now() - crashWallAt < CRASH_WALL_TTL_MS;
  if (fresh) return crashWallCache;
  let wall = 0;
  try {
    wall = maxCrashHeapMB(readIncidents(home));
  } catch {
    /* an unreadable store must not take down the badge */
  }
  crashWallCache = wall;
  crashWallStamp = stamp;
  crashWallAt = Date.now();
  return wall;
}

/* Is there room to read a large session at all? 90% of the wall is the point where the read
 * itself can be the allocation that kills the host. */
const HANDOFF_STOP_RATIO = 0.9;
function handoffRoom(home) {
  const live = readLive();
  const { wallMB, basis } = wallFor({ limitMB: live.limitMB, crashMB: crashWallMB(home) });
  const ratio = wallMB > 0 ? live.heapMB / wallMB : 0;
  return { ok: ratio < HANDOFF_STOP_RATIO, ratio, wallMB, basis, live };
}

/* One allocation-free reading for the composer badge. The figure stays out of prompts. */
function healthPayload(home) {
  try {
    const status = watchdogStatus();
    /* 状态行和这里必须是同一把尺子：读完历史先告诉观测层，100% 才始终等于「死过一次的堆」。 */
    noteCrashMB(crashWallMB(home));
    const pressure = heapPressure(status, { limitMB: status?.limitMB, crashMB: crashWallMB(home) });
    const row = { enabled: true, pct: pressure.pct, wallMB: pressure.wallMB, basis: pressure.basis };
    Object.assign(row, { heapMB: status?.heapMB ?? 0, peakMB: status?.peakMB ?? 0, limitMB: status?.limitMB ?? 0 });
    return row;
  } catch {
    return { enabled: true, pct: 0, wallMB: 0, basis: 'none', heapMB: 0, peakMB: 0, limitMB: 0 };
  }
}

/* 转世一个会话：读记录 → 写交接单 → 建子会话 → 改名 → 发交接单 → 归档原会话 → 记血缘。
 * 单次转世和批量转世共用这一份；失败返回 { ok:false, text }，由调用方原样上屏。 */
/** 读一个会话当前的标题（日志里折出来的那份）；读不到返回空串，由事件推。 */
async function readSessionTitle(ctx, sessionId, signal) {
  const query = serviceOf(ctx, 'sessionQuery');
  if (!query || typeof query.readTitle !== 'function') return '';
  try {
    const snapshot = await query.readTitle(sessionId, signal);
    const title = typeof snapshot === 'string' ? snapshot : snapshot?.title;
    return typeof title === 'string' ? clip(title.trim(), 60) : '';
  } catch (error) {
    log(`读不到 ${sessionId} 的标题：${error?.message ?? error}`);
    return '';
  }
}

async function handoffOne(ctx, { home, state, sessions, call, sourceId, current, knownIdle = false, args }) {
  /* 转世的前提是原会话已经收尾。别人还在跑的时候转世，旧回合会和接手的新会话同时写同一份
   * 工作，旧回合还会在归档后被腰斩（可能留下悬空 tool_calls）。自己转自己例外：当前这一轮
   * 就是收尾动作本身。查不到状态不算「在跑」，但要把结果说清楚。 */
  if (!knownIdle && sourceId !== current && args?.force !== true) {
    let busy = false;
    if (typeof sessions.list === 'function') {
      try {
        const page = await sessions.list({}, call);
        const items = Array.isArray(page?.items) ? page.items : [];
        busy = items.some((item) => item?.sessionId === sourceId && item?.running === true);
      } catch (error) {
        recordError(state, error);
        return { ok: false, text: `查不到会话 ${sourceId} 是否还在跑，没敢动它。确认它已经停下后重试，或传 force: true。什么都没改。` };
      }
    }
    if (busy) {
      return { ok: false, text: `会话 ${sourceId} 还在跑，不能转世：先让它跑完或手动停掉，再来一次。现在就转的话，旧回合会在归档后被腰斩，新会话也会和它抢同一份工作。确认要强行转世就传 force: true。什么都没改。` };
    }
  }
  /* 先量内存再读记录：读一份大会话是转世最贵的动作，等读到一半才发现放不下去就晚了。
   * 这里只挡「已经在墙边」的情况，正常水位不打扰转世。 */
  const room = handoffRoom(home);
  if (!room.ok) {
    return {
      ok: false,
      text: [
        `内存不够，先别转世：堆 ${room.live.heapMB} MB，墙 ${room.wallMB} MB（${room.basis === 'crash' ? '崩溃点校准' : '按上限留余量'}）。`,
        '转世本身要读旧会话的记录，这时候读会把宿主推过去。什么都没改。',
        '改法：现在就把要交接的进展写进工作区文件，然后 ⌘Q 退出 DSH 重开；重开后一次只恢复一个会话。',
      ].join('\n'),
    };
  }
  let inspection;
  try {
    inspection = await sessions.inspect(sourceId, call);
  } catch (error) {
    return { ok: false, text: `读不到会话 ${sourceId}：${error?.message ?? error}。什么都没改。` };
  }
  const events = inspection?.events;
  /* 确定性那份先算：模型没答上来、堆太高不敢调、或者用户关掉 llm 时，转世也必须有交接单。 */
  /* 标题得从会话自己的日志里折出来：事件流里没有标题行，只按事件推会退成「未命名会话」，
   * 子会话就跟着叫「未命名会话 · 转世」。 */
  const parentTitle = await readSessionTitle(ctx, sourceId, call);
  const fallback = buildBrief({ parentId: sourceId, parentTitle, events });
  /* 参数里点了标题就用它：0.6.8 之前这里只认原标题，传了也白传。 */
  const asked = typeof args?.title === 'string' ? clip(args.title.trim(), 40) : '';
  const childTitle = asked || clip(`${fallback.title} · 转世`, 40);
  /* 演练：现在的水位还宽裕，就先把交接单写到磁盘；真到要退出的那一刻不用再读一遍记录。
   * 不建子会话、不动原会话，可以反复跑，每次都覆盖同一份 preview。 */
  if (args?.dryRun === true) {
    let previewPath = '';
    let saved = false;
    try {
      previewPath = path.join(storeDir(home), 'handoff', `preview-${sourceId}.md`);
      fs.mkdirSync(path.dirname(previewPath), { recursive: true });
      fs.writeFileSync(previewPath, fallback.text, { mode: 0o600 });
      saved = fs.readFileSync(previewPath, 'utf8').length === fallback.text.length;
    } catch (error) {
      recordError(state, error);
    }
    const facts = fallback.facts ?? {};
    return {
      ok: saved,
      text: [
        saved ? `演练完成：交接单已写到 ${previewPath}（${fallback.text.length} 字）。` : `演练没写成功（${previewPath || '写文件失败'}）。`,
        `里面收了 ${(facts.messages ?? 0)} 条消息、${(facts.tools ?? 0)} 次工具调用。`,
        '没有建新会话，也没有动原会话。要真转世就去掉 dryRun 再跑一次；只想退出重开，也可以留着这份单子手动接着干。',
      ].join('\n'),
      dryRun: true,
      briefPath: previewPath,
      briefChars: fallback.text.length,
    };
  }
  const cwd = inspection?.meta?.cwd;
  let child;
  try {
    child = await sessions.create(cwd ? { cwd } : {}, call);
  } catch (first) {
    /* 老会话的 cwd 可能已经不在任何工作区里；建不出来就退回默认工作区，别让转世卡在参数上。 */
    try {
      child = await sessions.create({}, call);
    } catch (error) {
      return { ok: false, text: `新会话没建起来：${error?.message ?? first?.message ?? error}。原会话没动，可以重试。` };
    }
  }
  const childId = child?.sessionId;
  if (typeof childId !== 'string' || !childId) return { ok: false, text: '没有拿到新会话 id，原会话没动，可以重试。' };
  /* 新会话默认不进左侧列表：建出来就挂到它 cwd 所属的工作区，转世完就能直接点开。
   * 挂不上不算转世失败，只是要告诉人一声。 */
  let attached = false;
  let attachNote = cwd ? '没有对应的工作区' : '原会话没有 cwd';
  try {
    const registry = serviceOf(ctx, 'workspaceRegistry');
    const ws = registry && typeof registry.resolveByPath === 'function' && cwd ? await registry.resolveByPath(cwd) : null;
    if (ws && typeof ws.attachSession === 'function') {
      await ws.attachSession(childId);
      /* attachSession 落盘成功不等于列表里能看见：工作区的 sessionIds 会用启动时建的
       * cwd 索引再过滤一遍，新会话还没进那张表时会被静默滤掉。回读一次，不认就补索引。 */
      attached = workspaceHasSession(ws, childId);
      if (!attached && typeof registry.indexHeader === 'function') {
        const header = liveHeaderOf(ctx, childId);
        if (header) {
          try {
            await registry.indexHeader(header);
          } catch (error) {
            log(`新会话的 cwd 索引没补上：${error?.message ?? error}`);
          }
          attached = workspaceHasSession(ws, childId);
        }
      }
      attachNote = attached ? '' : '工作区的 cwd 索引里没有它，列表会把它滤掉';
      if (!attached) log(`新会话 ${childId} 挂上了但列表里看不到：${attachNote}`);
    }
  } catch (error) {
    attachNote = String(error?.message ?? error);
    log(`新会话没挂进工作区：${attachNote}`);
  }
  /* 交接单由模型读懂原会话后写；调用记在新会话名下（它已经建好），原会话的记录不被改写。
   * 任何一步失败都退回确定性那份——转世本身不能因为整理失败而失败。 */
  let brief = fallback;
  let model = null;
  let llmNote = '';
  if (args?.llm !== false) {
    const llm = serviceOf(ctx, 'llm');
    const route = requestRoute(events);
    const pct = healthPayload(home).pct;
    if (!llm || typeof llm.prepareCall !== 'function') llmNote = '模型服务没接上，用的是自动摘要';
    else if (!route) llmNote = '原会话没有记录用的模型，用的是自动摘要';
    else if (pct >= HANDOFF_LLM_MAX_PCT) llmNote = `内存已到 ${pct.toFixed(0)}%，没让模型整理，用的是自动摘要`;
    else {
      try {
        const ancestors = lineageChain(readLineage(home), sourceId).filter((row) => row.child !== sourceId);
        const result = await generateHandoffBody({
          llm,
          route,
          events,
          parentId: sourceId,
          parentTitle: fallback.title,
          sessionId: childId,
          ancestors,
          signal: call,
        });
        const body = normalizeHandoffBody(result.text);
        if (body) {
          brief = buildLlmBrief({ parentId: sourceId, parentTitle: fallback.title, body, facts: fallback.facts, model: route, ancestors });
          model = route;
          if (result.truncated) llmNote = '交接单太长，写到上限就收了';
        } else {
          llmNote = '模型返回的是空的，用的是自动摘要';
        }
      } catch (error) {
        recordError(state, error);
        llmNote = `模型没答上来（${error?.message ?? error}），用的是自动摘要`;
      }
    }
  } else {
    llmNote = '按你的要求关掉了模型整理，用的是自动摘要';
  }
  if (typeof sessions.rename === 'function') {
    try {
      await sessions.rename({ sessionId: childId, title: childTitle }, call);
    } catch (error) {
      recordError(state, error);
    }
  }
  /* 交接单先落盘、回读确认，再谈通知子会话：重启流程的前提是单子确实在硬盘上，不是「发过一次
   * 请求」。发消息成功但磁盘上没有，这次转世在重启后就等于没交接。 */
  let briefPath = '';
  let briefSaved = false;
  try {
    briefPath = path.join(storeDir(home), 'handoff', `${childId}.md`);
    fs.mkdirSync(path.dirname(briefPath), { recursive: true });
    fs.writeFileSync(briefPath, brief.text, { mode: 0o600 });
    const back = fs.readFileSync(briefPath, 'utf8');
    briefSaved = back.length > 0 && back.length === brief.text.length;
  } catch (error) {
    recordError(state, error);
  }
  let delivered = briefSaved ? 'message' : 'none';
  if (briefSaved && args?.brief !== false && typeof sessions.prompt === 'function') {
    try {
      await sessions.prompt({
        requestId: `handoff-${randomUUID()}`,
        sessionId: childId,
        mode: 'queue',
        content: [{ type: 'text', text: brief.text }],
      }, call);
    } catch (error) {
      /* 发不出去不影响落盘：单子已经在磁盘上，重开时照样能接着干。 */
      delivered = 'file';
      recordError(state, error);
    }
  } else if (briefSaved) {
    delivered = 'file';
  }
  let archived = false;
  const workspaces = serviceOf(ctx, 'workspaceController');
  if (workspaces && typeof workspaces.archiveSession === 'function') {
    try {
      await workspaces.archiveSession({ sessionId: sourceId }, call);
      archived = true;
    } catch (error) {
      recordError(state, error);
    }
  }
  let generation = 1;
  try {
    generation = generationOf(readLineage(home), sourceId);
    appendLineage(home, {
      child: childId,
      parent: sourceId,
      parentTitle: brief.title,
      title: childTitle,
      generation,
      at: new Date().toISOString(),
      briefChars: brief.text.length,
    });
  } catch (error) {
    recordError(state, error);
  }
  const lines = [
    `转世完成：新会话 ${childId}（第 ${generation} 代）`,
    `标题：${childTitle}`,
    !briefSaved ? `交接单没落盘（${briefPath || '写文件失败'}）：这次交接在重启后不算数，先解决磁盘问题再退出。` : '',
    briefSaved && delivered === 'message' ? '交接单已经发到新会话里，它会先回一句「收到」等你下一步。' : briefSaved ? `交接单已经写入 ${briefPath}，下次打开新会话时按它接着干。` : '',
    model ? `交接单由 ${model.provider}/${model.model} 整理，${brief.text.length} 字。` : `交接单是自动摘要，${brief.text.length} 字：${llmNote || '没开模型整理'}。`,
    archived ? `原会话 ${sourceId} 已归档，需要细节时取消归档回看，不会删。` : `原会话 ${sourceId} 没有归档成功（工作区服务没接上），但记录都还在。`,
    attached ? '' : `新会话没挂进左侧列表（${attachNote}），重启后在列表里看不到它，要手动打开。`,
    '内存只有重启才拿得回来：重启前新会话可能有一个未完成回合，重启后打开它再发一句「继续」。',
    '血缘记在插件自己的记录里，改标题不会丢；要看链条用 lifeguard_lineage。',
  ];
  if (!briefSaved && brief.text.length) {
    lines.push('');
    lines.push(brief.text);
  }
  return {
    ok: briefSaved,
    text: lines.filter(Boolean).join('\n'),
    childId,
    parentId: sourceId,
    generation,
    delivered,
    archived,
    /* 没写下去就不报路径：路径存在感会让人以为硬盘上有东西。 */
    briefPath: briefSaved ? briefPath : undefined,
    briefChars: brief.text.length,
    llm: model ? `${model.provider}/${model.model}` : '',
  };
}

/* 批量转世：先把可转的会话列出来（默认只看不动），确认后再一个个做。
 * 只挑已经停下、还没归档、又不是当前会话的那些；跑着的会话转世会被腰斩，一律跳过。 */
async function handoffMany(ctx, { home, state, sessions, call, current, args }) {
  const limit = Math.min(Math.max(Math.trunc(Number(args?.limit)) || 5, 1), 10);
  let items;
  try {
    const page = await sessions.list({}, call);
    items = Array.isArray(page?.items) ? page.items : [];
  } catch (error) {
    return `读不到会话清单：${error?.message ?? error}。什么都没改。`;
  }
  const rows = items.filter((item) => item
    && typeof item.sessionId === 'string' && item.sessionId
    && item.sessionId !== current
    && item.running !== true
    && item.archived !== true);
  if (!rows.length) return '没有可转世的会话：除了当前这个，其余都在跑或已经归档。';
  const picked = rows.slice(0, limit);
  const listed = picked.map((item) => `- ${item.sessionId}${item.title ? `（${clip(String(item.title), 30)}）` : ''}`);
  if (args?.dryRun !== false) {
    return [
      `可以转世 ${rows.length} 个会话，这次先只列不动，挑前 ${picked.length} 个：`,
      ...listed,
      '确认要转世就再调一次，带 all: true、dryRun: false。',
      '批量默认用自动摘要，省 token 也省堆；想让模型读懂再写交接单，就单独给那个会话传 sessionId。',
      '内存只有重启才拿得回来：转世不会当场把堆降下来。',
    ].join('\n');
  }
  const done = [];
  const failed = [];
  for (const item of picked) {
    const pct = healthPayload(home).pct;
    if (pct >= BATCH_STOP_PCT) {
      failed.push(`剩下的没做：内存已到 ${pct.toFixed(0)}%，再转世只会更冒险。`);
      break;
    }
    const one = await handoffOne(ctx, {
      home,
      state,
      sessions,
      call,
      sourceId: item.sessionId,
      current,
      knownIdle: true,
      args: { ...args, llm: args?.llm === true, title: undefined },
    });
    if (one.ok) done.push(`- ${one.childId} ← ${item.sessionId}（第 ${one.generation} 代）${one.archived ? '' : '，原会话没归档'}`);
    else failed.push(`- ${item.sessionId}：${one.text}`);
  }
  const summary = [`批量转世：做成 ${done.length} 个${failed.length ? `，没做 ${failed.length} 个` : ''}。`, ...done];
  if (failed.length) { summary.push('没做的：'); summary.push(...failed); }
  summary.push('内存只有重启才拿得回来：重启前新会话可能各有一个未完成回合，重启后逐个打开发一句「继续」。');
  return summary.join('\n');
}

export function apply(ctx, config = {}) {
  const home = typeof config.home === 'string' && config.home ? config.home : DEFAULT_HOME;
  /* 0 = 不注入提示词：规则清单本身是给面板看的，塞进每一轮请求只会吃掉上下文。 */
  const promptBudget = Number.isFinite(config.promptChars) ? Math.max(0, Math.min(2000, config.promptChars)) : 0;

  /* One live object per process, so a hot reload keeps the denial history and the
   * "already told the origin session" ledger instead of resetting them. */
  const state = defenseRuntime();
  state.override = null;
  setMode(state, modeOfConfig(config));
  clearHooks(state);

  /* Boot scan: never throws, never blocks activation. A crash during the last run left an
   * artifact on disk; this is the boot where it gets turned into lore. */
  let lastScan = { at: 0, added: [], unknown: [], error: null };
  ctx.effect(() => {
    let alive = true;
    Promise.resolve()
      .then(() => {
        /* Ship the checked-in rules on every boot: the merge keeps local hit counts and adds rules
         * that a newer build knows about, so an upgrade does not need a clean store. */
        /* 先把旧版数据目录并进来，再写任何新文件：否则新文件会挡住旧数据，迁移就白做了。 */
        migrateLegacyStore(home);
        seedRules(home);
        importCorpus(home);
        return scan({ home });
      })
      .then((result) => {
        if (!alive) return;
        lastScan = { at: Date.now(), added: result.added, unknown: result.unknown, error: null };
        if (result.added.length) {
          log(`新崩溃 ${result.added.length} 条：${result.added.map(summarizeIncident).join('；')}`);
        }
        if (result.unknown.length) log(`有 ${result.unknown.length} 条崩溃没有对应规则，用 lifeguard_record 补一条`);
      })
      .catch((error) => {
        lastScan = { at: Date.now(), added: [], unknown: [], error: String(error?.message ?? error) };
        log(`扫描失败：${error?.message ?? error}`);
      });
    return () => {
      alive = false;
    };
  }, 'lifeguard: boot scan');

  /* Heap watchdog: passive, unref'd, never blocks. It cannot stop a V8 death, but it turns
   * "the host vanished" into "the heap was at 2.9 GB and climbing" while the session is still alive. */
  ctx.effect(() => {
    try {
      noteCrashMB(crashWallMB(home));
      startWatchdog(home);
    } catch (error) {
      log(`内存观测未启动：${error?.message ?? error}`);
    }
    return () => stopWatchdog();
  }, 'lifeguard: heap watchdog');

  /* 会话快照落在临时目录，几百 MB 一份；启动清一次，之后按半小时一次兜着，预算默认 5 GB（config.tmpBudgetMB 可改）。 */
  ctx.effect(() => {
    const budgetMB = Number.isFinite(config.tmpBudgetMB) ? Math.max(256, Math.min(102400, config.tmpBudgetMB)) : DEFAULT_BUDGET_MB;
    const ttlMs = (Number.isFinite(config.tmpTtlHours) ? Math.max(1, Math.min(168, config.tmpTtlHours)) : 6) * 60 * 60 * 1000;
    const sweep = () => {
      const result = maybeSweep({ budgetMB, ttlMs });
      if (result?.removed) log(`清理临时会话快照 ${result.removed} 份，释放 ${result.freedMB} MB（上限 ${budgetMB} MB）`);
    };
    sweep();
    let timer = null;
    try {
      timer = setInterval(sweep, SWEEP_EVERY_MS);
      timer.unref?.();
    } catch {
      /* no timer service */
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, 'lifeguard: temp janitor');

  /* Health badge route: the composer ring polls it, so the same reading reaches the person as an
   * always-visible indicator instead of a line in every prompt. Turning the badge off removes the
   * route too — an off switch on the screen should not leave a live endpoint behind. */
  if (config.healthBadge !== false) {
    /* webServer 是可选服务，apply 时它不一定已经就绪：直接 ctx.get 会拿到 undefined，路由就
     * 永远不注册，圈在界面上静默消失。这里能动态注入就等它出现，只有拿不到注入能力时才退回。 */
    const mountHealth = (scope) => scope.effect(() => {
      const server = serviceOf(scope, 'webServer');
      if (!server || typeof server.register !== 'function') {
        badgeState.mounted = false;
        badgeState.error = '没有 webServer 服务';
        log('没有 webServer 服务，本轮不提供内存状态圈');
        return () => {};
      }
      let dispose;
      badgeState.path = '/lifeguard/health';
      badgeState.error = '';
      try {
        dispose = server.register({
          kind: 'exact',
          path: '/lifeguard/health',
          handler: (req, res) => {
            let body = '{"enabled":false}';
            try {
              body = JSON.stringify(healthPayload(home));
            } catch {
              /* keep the disabled body */
            }
            try {
              res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
              res.end(body);
            } catch {
              /* the socket went away before we answered */
            }
          },
        });
      } catch (error) {
        badgeState.mounted = false;
        badgeState.error = String(error?.message ?? error);
        log(`内存状态圈未挂上：${error?.message ?? error}`);
        return () => {};
      }
      badgeState.mounted = true;
      return () => {
        try {
          if (typeof dispose === 'function') dispose();
        } catch {
          /* already released */
        }
      };
    }, 'lifeguard: health badge');

    if (typeof ctx.inject === 'function') {
      ctx.inject(['webServer'], mountHealth);
    } else {
      mountHealth(ctx);
    }
  }

  /* Resident section: the compact lore, re-read on every step so a rule recorded mid-session
   * takes effect without a restart. */
  const prompt = serviceOf(ctx, 'systemPrompt');
  if (promptBudget > 0 && prompt && typeof prompt.context === 'function') {
    ctx.effect(() => prompt.context({
      name: 'lifeguard: rules',
      order: 42,
      interpolate: false,
      required: false,
      text: () => {
        try {
          const rules = readRules(home);
          return renderLorePrompt(rules, { maxChars: promptBudget });
        } catch {
          return '';
        }
      },
    }), 'lifeguard: prompt section');
  }

  const tools = serviceOf(ctx, 'tools');
  if (!tools || typeof tools.register !== 'function') {
    clearHooks(state);
    log('没有 tools 服务，本次只做扫描和提示词注入');
    return;
  }

  ctx.effect(() => tools.register(withOutput({
    name: 'lifeguard_scan',
    description: '扫描本机新的 DSH 崩溃日志（宿主崩溃、web 启动失败、启动诊断），转成条目并按已知规则归因；返回这次新增的崩溃和还没有规则的未知项。发现 harness 崩过、或怀疑某个插件把进程搞死时先调它。',
    parameters: {
      type: 'object',
      properties: {
        force: { type: 'boolean', description: '连已扫过的日志也重新解析' },
      },
      additionalProperties: false,
    },
    execute: async (args) => {
      const result = scan({ home, force: args?.force === true });
      const lines = [];
      const incidents = readIncidents(home);
      if (!result.harvested) {
        /* Nothing unparsed this call, but a boot scan may already have logged the last crash;
         * saying only "没有新的崩溃日志" hides that the machine just died. Show the newest row. */
        const newest = [...incidents].sort((a, b) => String(b.ts).localeCompare(String(a.ts)))[0];
        lines.push(newest ? `没有未解析的日志。最近一条：${summarizeIncident(newest)}（证据 ${newest.artifact}）` : '没有新的崩溃日志。');
      }
      for (const incident of result.added) {
        const rule = incident.ruleIds?.length ? ` 已知规则 ${incident.ruleIds.join(',')}` : ' 无对应规则';
        lines.push(`- ${summarizeIncident(incident)}${rule}`);
        lines.push(`  证据 ${incident.artifact}`);
      }
      if (!result.added.length && result.harvested) lines.push(`解析了 ${result.harvested} 个日志，没有新条目（与已有条目重复）。`);
      if (result.unknown.length) lines.push('未知形态先调 lifeguard_record 补规则，再调 lifeguard_export 写进长期记忆。');
      if (result.correlated) lines.push(`关联归因 ${result.correlated} 条：堆耗尽日志里没有插件栈，标成同一次运行前一条插件崩溃的来源。`);
      for (const row of result.oomEvidence ?? []) {
        for (const line of oomEvidenceLines(row.evidence)) lines.push(`  ${row.signature} — ${line}`);
      }
      for (const line of loopLines(result.loops ?? [])) lines.push(line);
      lines.push(heapLine(watchdogStatus()));
      const footprint = sessionFootprint(home);
      for (const line of footprintLines(footprint)) lines.push(line);
      return {
        text: lines.join('\n'),
        added: result.added.length,
        unknown: result.unknown.length,
        total: incidents.length,
        correlated: result.correlated ?? 0,
        loops: result.loops ?? [],
        heap: watchdogStatus(),
        sessions: footprint,
      };
    },
  })), 'lifeguard: lifeguard_scan');

  ctx.effect(() => tools.register(withOutput({
    name: 'lifeguard_rules',
    description: '查本机沉淀的 DSH 崩溃规则（标题 / 成因 / 改法 / 命中次数）。写插件、改 profile 配置前先查一遍要遵守什么。',
    parameters: {
      type: 'object',
      properties: {
        query: { type: 'string', description: '按关键词过滤，例如 activate、config、client' },
        limit: { type: 'integer', description: '最多几条，默认 20' },
      },
      additionalProperties: false,
    },
    execute: async (args) => {
      const rules = compactRules(readRules(home), { query: args?.query, limit: Math.max(1, Math.min(60, Number(args?.limit) || 20)) });
      if (!rules.length) return { text: '还没有规则。先 lifeguard_scan 扫日志。', rules: [] };
      const lines = rules.map((rule) => `[${rule.id}] ${rule.title}${rule.severity === 'fatal' ? '（致命）' : rule.severity === 'boot' ? '（阻断启动）' : ''} 命中${rule.hits}\n  成因 ${rule.cause}\n  改法 ${rule.fix}`);
      return { text: lines.join('\n'), rules };
    },
  })), 'lifeguard: lifeguard_rules');

  ctx.effect(() => tools.register(withOutput({
    name: 'lifeguard_record',
    description: '把一次崩溃或一条踩坑经验沉淀成规则（标题 + 成因 + 改法 + 可选静态守卫），写进本机规则库，下一步起生效。修完导致崩溃的插件后调用，把这次的教训留下。',
    parameters: {
      type: 'object',
      properties: {
        title: { type: 'string', description: '一句话命令式约束，≤40 字，例如「事件回调里不要抛未捕获异常」' },
        cause: { type: 'string', description: '触发原因，≤120 字' },
        fix: { type: 'string', description: '怎么改，≤120 字' },
        signature: { type: 'string', description: '匹配崩溃信息的正则；不写则按标题去重更新' },
        severity: { type: 'string', enum: ['fatal', 'boot', 'lint'], description: 'fatal 杀进程 / boot 阻断启动 / lint 局部异常' },
        guardPattern: { type: 'string', description: '可选：能在插件源码里静态命中的正则，用于 lifeguard_check 预检' },
        guardMessage: { type: 'string', description: '命中守卫时给作者看的一句话' },
        evidence: { type: 'string', description: '证据：日志路径或现象描述' },
      },
      required: ['title'],
      additionalProperties: false,
    },
    execute: async (args) => {
      const guard = args?.guardPattern
        ? { kind: 'source-regex', pattern: String(args.guardPattern), message: String(args.guardMessage ?? args.cause ?? args.title) }
        : null;
      if (guard) {
        try {
          new RegExp(guard.pattern, 'i');
        } catch {
          return { text: `守卫正则无效，未写入：${guard.pattern}` };
        }
      }
      const rule = upsertRule({
        title: String(args.title).slice(0, 40),
        cause: String(args.cause ?? '').slice(0, 120),
        fix: String(args.fix ?? '').slice(0, 120),
        signature: args.signature ? String(args.signature) : '',
        severity: ['fatal', 'boot', 'lint'].includes(args.severity) ? args.severity : 'lint',
        guard,
        tags: args.evidence ? [String(args.evidence).slice(0, 80)] : [],
      }, home);
      return { text: `已记下 [${rule.id}] ${rule.title}；下一步起出现在提示词里。同步长期记忆用 lifeguard_export。`, rule };
    },
  })), 'lifeguard: lifeguard_record');

  ctx.effect(() => tools.register(withOutput({
    name: 'lifeguard_check',
    description: '安装前静态预检插件源码目录（不执行代码）：先按 loader 的真实要求检查包结构、patch、工具注册契约、ESM 语法，再套本机崩溃规则。改完插件、准备装进 profile 前调它；有 fatal/boot 就是装上去会崩。',
    parameters: {
      type: 'object',
      properties: {
        dir: { type: 'string', description: '插件源码目录绝对路径' },
      },
      required: ['dir'],
      additionalProperties: false,
    },
    execute: async (args) => {
      const dir = String(args?.dir ?? '');
      if (!path.isAbsolute(dir)) return { text: '需要绝对路径。' };
      const { checkSource, preflight, renderAll } = await import('./guard.mjs');
      const findings = [...preflight(dir), ...checkSource(dir, readRules(home))];
      const blocking = findings.filter((item) => item.severity === 'fatal' || item.severity === 'boot').length;
      return { text: renderAll(findings, dir), findings: findings.length, blocking };
    },
  })), 'lifeguard: lifeguard_check');

  ctx.effect(() => tools.register(withOutput({
    name: 'lifeguard_export',
    description: '把本机崩溃规则导出：memory 写进 dsh-lite-memory 长期记忆（跨会话、按标题更新），markdown 输出一段精简清单。规则稳定后调一次。',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string', enum: ['markdown', 'memory'], description: '默认 markdown：只在对话里给清单；memory 才写长期记忆（会进召回，慎用）' },
        dryRun: { type: 'boolean', description: '只演练不写盘' },
        scope: { type: 'string', enum: ['global', 'project'], description: '默认 global：崩溃约束跨项目通用；project 只在当前项目可见' },
      },
      additionalProperties: false,
    },
    execute: async (args) => {
      const rules = readRules(home);
      if (!rules.length) return { text: '还没有规则可导出。' };
      const target = args?.target === 'memory' ? 'memory' : 'markdown';
      const mod = await import('./memory.mjs').catch(() => null);
      if (!mod) return { text: '缺少 memory.mjs，导出暂不可用。' };
      if (target === 'markdown') {
        return { text: mod.exportMarkdown(rules, { home, projectDir: process.env.DSH_PROFILE_DIR || path.join(home, 'profiles', 'desktop') }) };
      }
      const dryRun = args?.dryRun === true;
      const scope = args?.scope === 'project' ? 'project' : 'global';
      const result = await mod.exportRules(rules, { home, dryRun, scope, projectDir: process.env.DSH_PROFILE_DIR || path.join(home, 'profiles', 'desktop') });
      const written = result?.exported?.length ?? 0;
      return {
        text: dryRun ? `演练：会写入 ${written} 条到长期记忆，未改动。` : `已写入 ${written} 条到长期记忆。`,
        result,
      };
    },
  })), 'lifeguard: lifeguard_export');

  ctx.effect(() => tools.register(withOutput({
    name: 'lifeguard_heal',
    description: '当 harness 起不来时用的自愈：找出最近一次致命崩溃的元凶插件并给停用计划。apply=true 直接停用；auto=true 只在确认是崩溃循环（24h 内同元凶 ≥3 次）时才停用，否则只报告。改动前备份，可 doctor --restore 撤销，重启 harness 生效。',
    parameters: {
      type: 'object',
      properties: {
        apply: { type: 'boolean', description: '真的执行停用；不写只给计划' },
        auto: { type: 'boolean', description: '仅在确认是崩溃循环（24h 内同元凶 ≥3 次）时自动停用，否则只给结果' },
      },
      additionalProperties: false,
    },
    execute: async (args) => {
      const mod = await import('./doctor.mjs').catch(() => null);
      if (!mod) return { text: '缺少 doctor.mjs，自愈暂不可用。' };
      const profileDir = process.env.DSH_PROFILE_DIR || path.join(home, 'profiles', 'desktop');
      const result = mod.runDoctor({ home, profileDir, yes: args?.apply === true, auto: args?.auto === true });
      const lines = [...(result?.lines ?? [])];
      if (result?.conclusion) lines.push(result.conclusion);
      return { text: lines.length ? lines.join('\n') : '没有找到可停用的元凶。', result };
    },
  })), 'lifeguard: lifeguard_heal');

  /* ---- live defense ----------------------------------------------------------------
   * Three layers stay separate on purpose: the user's mode (开启 / 仅监测 / 关闭), what the
   * DSH actually wired (正常 / 部分覆盖 / 不可用 / 检查异常), and what the last check did
   * (放行 / 观察到风险 / 已阻止). Only the first is a choice; the other two are read from
   * reality, so a missing interface can never be reported as 保护中.
   * Two host mechanisms carry the refusal: a sync `tools.guard()` for text a write/edit
   * would put into a file the running host loads, and the async `tools/pre-execute`
   * waterfall for installs/enables, where the whole candidate can be preflighted.
   * Both fail open: a defense plugin must not become the crash. */
  const profileDir = process.env.DSH_PROFILE_DIR || path.join(home, 'profiles', 'desktop');
  let surfaces;
  try {
    surfaces = liveSurfaces(profileDir);
  } catch (error) {
    recordError(state, error);
    surfaces = { profileDir, plugins: [], patchFile: '', pkgFile: '' };
  }
  const targetLabel = (surface, file) => (surface?.name && surface.name !== 'profile' ? `${surface.name} · ${file}` : String(file ?? 'profile'));

  /* Read the mode from the config the fiber currently holds, not from the closure: a live
   * config edit and a restart both have to be visible to hooks registered earlier. */
  const liveMode = () => {
    let current = null;
    try {
      const fiber = propOf(ctx, 'fiber');
      current = fiber && typeof fiber === 'object' ? fiber.config : null;
    } catch {
      current = null;
    }
    const fromFiber = current && typeof current === 'object' ? explicitMode(current) : null;
    if (fromFiber) return fromFiber;
    if (state.override && MODES.includes(state.override)) return normalizeMode(state.override, state.mode);
    const fromClosure = explicitMode(config);
    return fromClosure ?? normalizeMode(modeOfConfig(config), state.mode);
  };

  const record = (finding, surface, file, reason, verdict, callId) => {
    const target = targetLabel(surface, file);
    const done = recordFinding(state, {
      callId,
      rule: finding?.ruleId ?? finding?.rule,
      title: finding?.title,
      target,
      reason,
    }, verdict);
    if (!done.duplicate) log(`崩溃防护${verdict === 'observe' ? '发现风险' : '拦截'} ${done.entry.rule} @ ${target}`);
    return done;
  };

  /* Hooks follow the live mode, not the value read once at apply() time. A config write can
   * commit between apply() and the first tool call, and a card that reports 开启 while no hook
   * exists is worse than having no card. Installing is idempotent; turning the defense off
   * really takes the hooks back out instead of leaving dormant ones behind. */
  const hookDisposers = [];
  /* A hook can be taken back out by a mode change and again by plugin unload; both paths run
   * the same idempotent wrapper so the second call never touches a disposed hook. */
  const track = (disposer) => {
    if (typeof disposer !== 'function') return () => {};
    let used = false;
    const call = () => {
      if (used) return;
      used = true;
      disposer();
    };
    hookDisposers.push(call);
    return call;
  };

  const installHooks = () => {
    if (state.hooks.write || state.hooks.preExecute) return;

    if (typeof tools.guard === 'function') {
      ctx.effect(() => {
        const disposer = tools.guard((exec) => {
          try {
            const mode = liveMode();
            if (mode === 'off') return undefined;
            const onDeny = (finding, surface, file, reason) => {
              record(finding, surface, file, reason, mode === 'observe' ? 'observe' : 'deny', exec?.callId);
            };
            const outcome = guardWrite(exec, { surfaces, onDeny }) ?? guardShell(exec, { surfaces, onDeny });
            const target = exec?.arguments?.path ?? exec?.arguments?.file ?? exec?.arguments?.target;
            if (!outcome && typeof target === 'string' && target) recordCheck(state, { target: targetLabel(null, target) });
            return mode === 'observe' ? undefined : outcome;
          } catch (error) {
            recordError(state, error);
            return undefined;
          }
        });
        return track(disposer);
      }, 'lifeguard: write guard');
      setHook(state, 'write', 'sync');
    } else {
      log('本机没有写前守卫接口，这一层没接上');
    }

    if (typeof ctx.on === 'function') {
      ctx.effect(() => {
        const disposer = ctx.on('tools/pre-execute', async (exec, next) => {
          try {
            const mode = liveMode();
            if (mode === 'off') return next();
            const decision = await preExecute(exec, {
              surfaces,
              profileDir,
              onDeny: (finding, surface, file, reason) => {
                record(finding, surface, file, reason, mode === 'observe' ? 'observe' : 'deny', exec?.callId);
              },
            });
            if (decision && mode !== 'observe') return decision;
            /* A rule wasn't broken — there is simply no room left. The sampler reports this, the
             * gate is what stops the next expensive step from crossing the wall. */
            if (config.heapGate !== false) {
              const verdict = admit(readLive(), exec, { crashMB: crashWallMB(home) });
              if (!verdict.ok) {
                record({ rule: verdict.rule, title: verdict.title }, 'pre-execute', '', verdict.reason, mode === 'observe' ? 'observe' : 'deny', exec?.callId);
                if (mode !== 'observe') return denial(verdict.reason, { ruleId: verdict.rule, title: verdict.title });
              }
            }
            if (!decision && exec?.name === 'plugin_manager') recordCheck(state, { target: targetLabel(null, exec?.arguments?.target) });
          } catch (error) {
            recordError(state, error);
          }
          return next();
        });
        return track(disposer);
      }, 'lifeguard: install guard');
      setHook(state, 'preExecute', 'async');
    } else {
      log('本机没有安装前预检接口，这一层没接上');
    }
  };

  const removeHooks = () => {
    while (hookDisposers.length) {
      const disposer = hookDisposers.pop();
      try {
        disposer();
      } catch (error) {
        recordError(state, error);
      }
    }
    clearHooks(state);
  };

  if (state.mode === 'off') removeHooks();
  else installHooks();

  /* ---- feedback to the originating session -----------------------------------------
   * A PTC subcall's denied result is swallowed by run_code, so the agent that asked for it
   * never sees why. Hand the reason back as one supplemental context on the same session,
   * keyed by the subcall id: a re-dump of the same denial is never delivered twice, nothing
   * is broadcast, and the session keeps running. */
  if (typeof ctx.on === 'function') {
    ctx.effect(() => ctx.on('tools/post-execute', async (exec, result, next) => {
      try {
        if (!result?.isError) return next();
        const callId = exec?.callId ? String(exec.callId) : '';
        const rootId = exec?.rootCallId ? String(exec.rootCallId) : callId;
        if (!callId || rootId === callId) return next();
        const entry = denialFor(state, callId);
        if (!entry || !claimFeedback(state, callId)) return next();
        const step = String(exec?.name ?? '子调用');
        const target = [exec?.arguments?.target, exec?.arguments?.path, exec?.arguments?.file, entry.target]
          .map((value) => (typeof value === 'string' ? value : ''))
          .find(Boolean) ?? '';
        const text = [
          `DSH 守护阻止了一次子调用（${step}）。会话可以继续。`,
          `规则 ${entry.rule}${entry.title ? `：${entry.title}` : ''}`,
          `原因：${entry.reason || entry.title || '目标文件会被下一次启动加载，写坏会让宿主起不来'}`,
          `未执行：${step}${target ? ` → ${target}` : ''}`,
          '改法：按上面的原因改掉再重试这一步；哪条规则不清楚就先跑 lifeguard_check 看致命项。',
        ].join('\n');
        const message = {
          id: randomUUID(),
          role: 'user',
          content: [{ type: 'text', text }],
          source: { kind: 'ptc-mode' },
        };
        return { kind: 'accept', additionalContexts: [message] };
      } catch (error) {
        recordError(state, error);
        return next();
      }
    }), 'lifeguard: ptc feedback');
  }

  /* 静态安装体检：装之前跟已装的比一遍（只加备注，不拦安装）。关掉防御时一并关闭。 */
  if (config.installCheck !== false && modeOfConfig(config) !== 'off') {
    ctx.effect(() => applyInstallCheck(ctx, { overlap: config.overlapCheck !== false, impl: config.implCheck !== false }), 'lifeguard: install check');
  }

  /* Mode is the only writable knob, and it is written through the DSH config editor, so
   * the choice lands in the profile patch DSH itself owns: no config pass-through, no
   * hand-edited file, and an unchanged value leaves no row behind. */
  const persistMode = async (value) => {
    if (!MODES.includes(value)) return '模式只认 protect / observe / off，这一项没有保存';
    const editor = serviceOf(ctx, 'configEditor');
    if (!editor || typeof editor.configuration !== 'function' || typeof editor.edit !== 'function') {
      return '本机没有提供配置接口，模式没有保存';
    }
    let rows = [];
    try {
      rows = editor.configuration();
    } catch (error) {
      recordError(state, error);
      return '读配置入口失败，模式没有保存';
    }
    const row = Array.isArray(rows)
      ? rows.find((item) => item?.entry?.options?.name === name || item?.entry?.options?.id === 'lifeguard' || item?.entry?.options?.id === LEGACY_ID)
      : null;
    if (!row) return 'profile 里找不到这个插件的配置入口，模式没有保存';
    try {
      await editor.edit(row.entry, (current) => {
        const next = current && typeof current === 'object' ? { ...current } : {};
        delete next.guard;
        delete next.monitorOnly;
        next.mode = value;
        return next;
      });
    } catch (error) {
      recordError(state, error);
      return `模式没有保存：${error?.message ?? error}`;
    }
    state.override = value;
    setMode(state, value);
    return `模式已切到 ${MODE_LABELS[value]}`;
  };

  /* 化龙妙法：把一个大会话转世成新会话。不碰别的插件、不恢复旧会话（恢复旧会话本身就要吃
   * 几 GB 堆），只读事件、写交接单、建一个空会话、归档旧会话。内存仍旧只有重启才还。 */
  ctx.effect(() => tools.register(withOutput({
    name: 'lifeguard_handoff',
    description: '把一个已停下的会话转世成新会话：读懂原会话记录后写一份交接单，新建子会话并改名，原会话归档，血缘记在插件自己名下。会话还在跑会拒绝转世（force 可强行）；内存只有重启才能拿回来。',
    parameters: {
      type: 'object',
      properties: {
        sessionId: { type: 'string', description: '要转世的会话 id，默认当前会话' },
        title: { type: 'string', description: '新会话标题，默认「原标题 · 转世」' },
        brief: { type: 'boolean', description: '把交接单发给新会话，默认发；关掉只建空会话并把单子写盘' },
        force: { type: 'boolean', description: '会话还在跑也强行转世，默认拒绝' },
        llm: { type: 'boolean', description: '默认让模型读懂原会话再写交接单；关掉只做自动摘要，省资源但会丢判断' },
        all: { type: 'boolean', description: '批量：把已经停下的会话一次转世，默认先只列清单不动' },
        dryRun: { type: 'boolean', description: '演练：只把交接单写到磁盘，不建新会话、不动原会话；用在内存还宽裕的时候' },
        limit: { type: 'number', description: '配合 all：一次最多做几个，默认 5，上限 10' },
      },
      additionalProperties: false,
    },
    execute: async (args, exec) => {
      const sessions = serviceOf(ctx, 'sessionController');
      if (!sessions || typeof sessions.inspect !== 'function' || typeof sessions.create !== 'function') {
        return '会话服务没接上，转世没做，什么都没改。';
      }
      const signal = propOf(exec, 'signal');
      /* 第二个参数是中断信号，不能传空对象。 */
      const call = signal instanceof AbortSignal ? signal : new AbortController().signal;
      const current = propOf(propOf(propOf(exec, 'agent'), 'session'), 'id');
      const me = typeof current === 'string' ? current : '';
      /* 批量也回 { text }：工具返回值统一，调用方只认 text 那一栏。 */
      if (args?.all === true) return { text: await handoffMany(ctx, { home, state, sessions, call, current: me, args }) };
      const asked = typeof args?.sessionId === 'string' ? args.sessionId.trim() : '';
      const sourceId = asked || me;
      if (!sourceId) return '不知道要转世哪个会话：请传 sessionId。什么都没改。';
      const one = await handoffOne(ctx, { home, state, sessions, call, sourceId, current: me, args });
      /* ok 只认硬盘：交接单真的写下去且回读一致才是 true。失败的正文已经回填在 text 里。 */
      const out = { text: one.text, ok: one.ok === true, briefPath: one.briefPath, briefChars: one.briefChars, delivered: one.delivered };
      if (one.dryRun) return { ...out, dryRun: true };
      if (!one.ok) return out;
      return { ...out, childId: one.childId, parentId: one.parentId, generation: one.generation, archived: one.archived, llm: one.llm };
    },
  })), 'lifeguard: lifeguard_handoff');

  ctx.effect(() => tools.register(withOutput({
    name: 'lifeguard_lineage',
    description: '看一个会话的转世血缘：第几代、从哪个会话转来、中间经过几代。标题被改过也不影响。',
    parameters: {
      type: 'object',
      properties: {
        sessionId: { type: 'string', description: '会话 id，默认当前会话' },
      },
      additionalProperties: false,
    },
    execute: async (args, exec) => {
      const current = propOf(propOf(propOf(exec, 'agent'), 'session'), 'id');
      const asked = typeof args?.sessionId === 'string' ? args.sessionId.trim() : '';
      const sessionId = asked || (typeof current === 'string' ? current : '');
      if (!sessionId) return '请传 sessionId。';
      const rows = readLineage(home);
      if (!rows.length) return '还没有转世记录。用 lifeguard_handoff 转世一次就会记下来。';
      const chain = lineageChain(rows, sessionId);
      const lines = [];
      if (chain.length) {
        lines.push(`当前会话 ${sessionId} 的血缘链（从远到近）：`);
        for (const row of chain) lines.push(`- 第 ${row.generation} 代 ${row.child} ← ${row.parent}${row.title ? `（${row.title}）` : ''}`);
      } else {
        lines.push(`当前会话 ${sessionId} 不是别人转世来的。`);
      }
      const children = rows.filter((row) => row.parent === sessionId);
      if (children.length) {
        lines.push(`从这里转出去的后代 ${children.length} 个：`);
        for (const row of children) lines.push(`- ${row.child}（第 ${row.generation} 代，${row.at ?? ''}）`);
      }
      return lines.join('\n');
    },
  })), 'lifeguard: lifeguard_lineage');

  ctx.effect(() => tools.register(withOutput({
    name: 'lifeguard_guard',
    description: '看崩溃防护现在是什么模式、DSH 实际接上了哪几层检查、最近一次检查和拒绝记录。传 mode 可以把防护切成 开启 / 仅监测 / 关闭，写进配置，刷新和重启后保留。',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'integer', description: '最近几条拒绝记录，默认 5' },
        mode: { type: 'string', enum: ['protect', 'observe', 'off'], description: 'protect 开启，observe 仅监测，off 关闭' },
      },
      additionalProperties: false,
    },
    execute: async (args) => {
      const limit = Math.max(1, Math.min(20, Number(args?.limit) || 5));
      const note = typeof args?.mode === 'string' ? await persistMode(args.mode) : null;
      /* The mode can also change through a config write that does not restart the plugin, so the
       * card re-reads it instead of trusting whatever the last apply() saw. */
      setMode(state, liveMode());
      /* Keep the hooks and the mode in step even when the value changed without a restart. */
      if (state.mode === 'off') removeHooks();
      else installHooks();
      const info = defenseState();
      const lines = describeStatus(undefined, { installCheck: config.installCheck !== false && state.mode !== "off" });
      const recent = recentDenials(state, limit);
      if (recent.length) {
        lines.push(`最近拒绝 ${recent.length} 条`);
        for (const entry of recent) lines.push(`- ${entry.at} ${entry.rule} ${entry.title} → ${entry.target}`);
      } else if (info.capability !== 'off') {
        lines.push('最近没有拒绝记录');
      }
      /* Runtime picture next to the write gate: a heap that is already at the edge and a plugin
       * that already died repeatedly are the two facts the write gate cannot see. */
      const loops = crashLoops(readIncidents(home), { now: Date.now() });
      for (const line of loopLines(loops)) lines.push(line);
      noteCrashMB(crashWallMB(home));
      const heap = watchdogStatus();
      lines.push(heapLine(heap));
      lines.push(badgeState.mounted ? `内存状态圈 已挂载 ${badgeState.path}` : `内存状态圈 未挂载${badgeState.error ? `（${badgeState.error}）` : ''}`);
      for (const line of footprintLines(sessionFootprint(home))) lines.push(line);
      lines.push('覆盖不到：命令行直接写文件、外部编辑器保存、DSH 自身升级、已经装进去的代码在运行时崩。');
      if (note) lines.push(note);
      return { text: lines.join('\n'), ...info, denials: recent, note, heap, loops };
    },
  })), 'lifeguard: lifeguard_guard');

  /* Surface the newest unresolved incident once per session, so an agent knows *why* the
   * previous run died without being told. */
  ctx.effect(() => {
    const rules = readRules(home);
    const incidents = readIncidents(home);
    const last = incidents[incidents.length - 1];
    if (!last) return () => {};
    const state = readState(home);
    const quarantined = new Set((state.quarantine ?? []).map((entry) => entry.name));
    if (last.culprit?.name && quarantined.has(last.culprit.name)) return () => {};
    log(`最近一次崩溃：${summarizeIncident(last)}（${last.ts}）`);
    return () => {};
  }, 'lifeguard: last incident log');

  return { scan: () => lastScan, header: PROMPT_HEADER, badge: () => ({ ...badgeState }) };
}
