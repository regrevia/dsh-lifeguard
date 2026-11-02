/* Heap admission: the ring only reports, it never stops the next allocation.
 *
 * A turn that resumes a huge session, or a tool that pulls a large record into memory, can cross
 * the wall in one step — before the 20 s sampler ever looks again. So this module answers one
 * question at the moment a tool is about to run: given the heap now and the cost this step is
 * likely to add, does it still fit under the wall?
 *
 * The wall is not the raw heap limit. A heap limit is what V8 allows; the wall is where this host
 * has actually died, when a crash log from this same regime proved that point, otherwise the heap
 * limit itself: a step is stopped only when it would really cross into a crash.
 */

import v8 from 'node:v8';

const MEGABYTE = 1024 * 1024;

export function megabytes(bytes) {
  const value = Number(bytes);
  return Number.isFinite(value) && value > 0 ? Math.round(value / MEGABYTE) : 0;
}

/** A recorded crash point describes this runtime only if it died close to its own limit. */
export const WALL_CLOSENESS = 0.75;

/**
 * The wall is the point where the process really dies, which for V8 is the heap limit itself: at
 * that size it cannot grow and aborts. Stopping earlier than that stops work that would have
 * finished, so a guessed margin is only used when the limit is unknown.
 *
 * @param {{limitMB?: number, crashMB?: number}} options
 * @returns {{wallMB: number, limitMB: number, basis: 'crash'|'limit'|'none'}}
 */
export function wallFor(options = {}) {
  const limitMB = Math.max(0, Math.round(Number(options.limitMB) || 0));
  const crashMB = Math.max(0, Math.round(Number(options.crashMB) || 0));
  if (limitMB > 0) {
    const crashCounts = crashMB > 0 && crashMB <= limitMB && crashMB >= limitMB * WALL_CLOSENESS;
    return { wallMB: crashCounts ? crashMB : limitMB, limitMB, basis: crashCounts ? 'crash' : 'limit' };
  }
  if (crashMB > 0) return { wallMB: crashMB, limitMB: 0, basis: 'crash' };
  return { wallMB: 0, limitMB: 0, basis: 'none' };
}

/**
 * Warning lines are fractions of the wall and only ever colour a panel: they must never stop a
 * step. Under a raised limit the old fixed 1800/2800 MB lines were crossed on every normal run, so
 * the alarm latched forever and contradicted the numbers printed next to it.
 */
export function thresholdsFor(limitMB = 0, options = {}) {
  const wallMB = wallFor({ limitMB, crashMB: options.crashMB ?? 0 }).wallMB;
  const warnMB = options.warnMB ?? (wallMB ? Math.round(wallMB * 0.75) : 1800);
  const criticalMB = options.criticalMB ?? (wallMB ? Math.round(wallMB * 0.9) : 2800);
  return { warnMB, criticalMB, wallMB };
}

/** Tools that must keep working while the heap is full: they are how a person inspects and fixes it. */
const EXEMPT = [
  /^lifeguard_(guard|heal|check|scan|export|rules|lineage|recall|relieve)$/,
  /^(todo_write|todo_read)$/,
  /^(ask_user_question|list_agents|send_message|wait_agent|interrupt_agent)$/,
  /^schedule_(list|create|update|delete)$/,
];

/* Estimated added heap, in MB. Deliberately coarse: an order of magnitude is enough to decide
 * whether a step fits, and a table that pretends to be precise would age badly. */
const COSTS = [
  [/handoff|transmigrat/i, 600],
  [/resume|mount|restore/i, 500],
  [/^(lifeguard_scan|doctor|preflight)|^(plugin_manager)$/i, 150],
  [/^(bash|shell|exec|run_code)$/i, 150],
  [/^(read|grep|glob|web_fetch|browser_read|envoy_read|adb_)/i, 40],
  [/^(edit|write)$/i, 25],
];
const DEFAULT_COST_MB = 25;

export function costOf(name) {
  const text = String(name ?? '');
  if (!text) return DEFAULT_COST_MB;
  for (const [pattern, mb] of COSTS) if (pattern.test(text)) return mb;
  return DEFAULT_COST_MB;
}

export function isExempt(name) {
  const text = String(name ?? '');
  return EXEMPT.some((pattern) => pattern.test(text));
}

/**
 * One instant read, no sampler in between: heapUsed is what the next allocation grows, the limit
 * is what V8 will enforce right now, rss is what the OS sees.
 * @param {{sample?: () => any, readLimit?: () => number}} options
 */
export function readLive(options = {}) {
  const sample = typeof options.sample === 'function' ? options.sample : () => process.memoryUsage();
  const readLimit = typeof options.readLimit === 'function' ? options.readLimit : defaultLimit;
  let usage = null;
  try {
    usage = sample();
  } catch {
    usage = null;
  }
  let limitMB = 0;
  try {
    limitMB = megabytes(readLimit());
  } catch {
    limitMB = 0;
  }
  return {
    heapMB: megabytes(usage?.heapUsed),
    rssMB: megabytes(usage?.rss),
    limitMB,
    at: new Date().toISOString(),
  };
}

function defaultLimit() {
  return v8.getHeapStatistics().heap_size_limit;
}

/**
 * @param {{heapMB?: number, limitMB?: number}} reading
 * @param {{wallMB?: number, level?: number}} options
 */
export function levelOf(reading, options = {}) {
  const heapMB = Math.max(0, Number(reading?.heapMB) || 0);
  const wallMB = Math.max(1, Number(options.wallMB) || 1);
  const ratio = heapMB / wallMB;
  if (ratio >= 0.95) return { level: 'stop', ratio };
  if (ratio >= 0.85) return { level: 'high', ratio };
  if (ratio >= 0.7) return { level: 'watch', ratio };
  return { level: 'ok', ratio };
}

/**
 * Should this step run? Deny only when the step is expensive and it would land on the wall.
 * @param {{heapMB?: number, limitMB?: number, rssMB?: number}} reading
 * @param {{name?: string, arguments?: any}} exec
 * @param {{crashMB?: number}} options
 * @returns {{ok: true, exempt?: boolean} | {ok: false, rule: string, reason: string, numbers: object}}
 */
export function admit(reading, exec, options = {}) {
  const name = String(exec?.name ?? '');
  if (isExempt(name)) return { ok: true, exempt: true };
  const { wallMB, limitMB, basis } = wallFor({
    limitMB: reading?.limitMB || options.limitMB,
    crashMB: options.crashMB,
  });
  if (!wallMB) return { ok: true };
  const heapMB = Math.max(0, Number(reading?.heapMB) || 0);
  const costMB = costOf(name);
  const projected = heapMB + costMB;
  const crosses = projected > wallMB;
  /* Deny only the step whose own estimate lands past the point where the process would die. Any
   * earlier line stops work that would have finished, and it stops it for every session on the
   * host, including the ones that caused no memory pressure at all. */
  if (!crosses) return { ok: true };

  const headroom = Math.max(0, wallMB - heapMB);
  const reason = [
    `堆 ${heapMB} MB，上限 ${limitMB || '未知'} MB，墙 ${wallMB} MB（${basis === 'crash' ? '崩溃点校准' : '这就是上限，越过去进程就死'}）。`,
    `这一步（${name || '未命名工具'}）预计还要 ${costMB} MB，落地后约 ${projected} MB，会比墙还高。`,
    `现在只剩 ${headroom} MB 余量，跑它就压在墙上。`,
    '改法：先把当前进展写成交接单（lifeguard_handoff 的 dryRun 先看清要交接什么），确认落盘后再退出 DSH 重开；重开后一次只恢复一个会话。',
    '要只是看一眼数字，lifeguard_guard、lifeguard_scan 这类诊断工具不会被拦。',
  ].join('\n');
  return {
    ok: false,
    rule: 'H001',
    title: '内存不够时不要启动新的重操作',
    reason,
    numbers: { heapMB, costMB, projected, wallMB, limitMB, headroom, basis },
  };
}
