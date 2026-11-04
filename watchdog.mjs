/**
 * Passive heap watchdog: the one pre-crash signal this plugin can produce.
 *
 * A host heap death gives no plugin stack and no chance to react, but memory climbs for minutes
 * before the ceiling. This samples the host heap on a slow timer and keeps a tiny ring, so the
 * status card can say "heap 2.9 GB, +180 MB/min" while the process is still alive. It never exits,
 * never throws, and never blocks a tool: the timer is unref'd, samples are best effort, and a failed
 * sample is dropped. Crossing the critical line records one alarm that survives the crash, so the
 * next run knows this plugin set has already been to the edge.
 */
import fs from 'node:fs';
import v8 from 'node:v8';
import { appendJsonl, paths, DEFAULT_HOME } from './core.mjs';
import { recordFootprint } from './lib/sessions.mjs';
import { thresholdsFor, wallFor } from './pressure.mjs';

const DEFAULTS = {
  intervalMs: 20_000,
  warnMB: null,
  criticalMB: null,
  releaseRatio: 0.6,
  keep: 180,
  persistEveryMs: 60_000,
  /* A directory walk over every session is ~100 ms on a large tree: sample it on a slow cadence
   * instead of every heap tick, so the watchdog stays a rounding error in the host. */
  footprintEveryMs: 5 * 60_000,
  keepPersisted: 1200,
};

function megabytes(value) {
  return Math.round((Number(value) || 0) / (1024 * 1024));
}

/**
 * Pure-ish sampler core: no timer, no IO unless `persist` is passed. Tests drive it directly.
 * @param {object} options
 */
export function createWatchdog(options = {}) {
  const config = { ...DEFAULTS, ...options };
  const sample = typeof config.sample === 'function' ? config.sample : () => process.memoryUsage();
  const clock = typeof config.now === 'function' ? config.now : () => Date.now();
  const ring = [];
  const startedAt = clock();
  let lastTick = startedAt;
  let lastPersist = startedAt;
  let lastFootprint = startedAt;
  let peakMB = 0;
  let alarm = null;
  let picks = 0;

  function sampleOnce() {
    try {
      const usage = sample();
      const heapMB = megabytes(usage?.heapUsed);
      const rssMB = megabytes(usage?.rss);
      // The ceiling itself, so a raised heap limit is verifiable at runtime instead of assumed.
      const limitMB = megabytes(v8.getHeapStatistics().heap_size_limit);
      const stamp = clock();
      picks += 1;
      peakMB = Math.max(peakMB, heapMB);
      ring.push({ t: new Date(stamp).toISOString(), heapMB, rssMB, limitMB });
      if (ring.length > config.keep) ring.splice(0, ring.length - config.keep);
      const limits = thresholdsFor(limitMB, { warnMB: config.warnMB, criticalMB: config.criticalMB });
      if (heapMB >= limits.criticalMB) {
        if (!alarm || alarm.released) alarm = { at: new Date(stamp).toISOString(), heapMB, released: false };
        else alarm.heapMB = Math.max(alarm.heapMB, heapMB);
      } else if (alarm && heapMB < limits.warnMB * config.releaseRatio) {
        alarm = { ...alarm, released: true };
      }
      lastTick = stamp;
      if (typeof config.persist === 'function' && stamp - lastPersist >= config.persistEveryMs) {
        lastPersist = stamp;
        config.persist({ t: new Date(stamp).toISOString(), heapMB, rssMB, limitMB, peakMB });
        /* Written while the host is still alive, so a later OOM row can quote how loaded the
         * machine was; the scan never invents this number after the fact. */
        if (typeof config.footprint === 'function' && stamp - lastFootprint >= config.footprintEveryMs) {
          lastFootprint = stamp;
          config.footprint(stamp);
        }
      }
      return { heapMB, rssMB, limitMB };
    } catch {
      return null;
    }
  }

  function status() {
    const latest = ring[ring.length - 1] ?? null;
    const first = ring[0] ?? null;
    const spanMs = latest && first ? Date.parse(latest.t) - Date.parse(first.t) : 0;
    const trendMBPerMin = spanMs > 0 ? Math.round(((latest.heapMB - first.heapMB) / spanMs) * 60_000) : 0;
    return {
      running: Boolean(config.running),
      samples: picks,
      heapMB: latest?.heapMB ?? 0,
      rssMB: latest?.rssMB ?? 0,
      peakMB,
      limitMB: latest?.limitMB ?? 0,
      trendMBPerMin,
      since: new Date(startedAt).toISOString(),
      ...thresholdsFor(latest?.limitMB ?? 0, { warnMB: config.warnMB, criticalMB: config.criticalMB }),
      alarm: alarm ? { ...alarm } : null,
      lastTick: picks ? new Date(lastTick).toISOString() : null,
    };
  }

  return { sampleOnce, status, get alarm() { return alarm; }, config };
}

let active = null;

/**
 * Keep the on-disk sample log bounded. It is a debugging aid: at one sample a minute it would
 * otherwise grow without limit on a machine that never restarts. `keepPersisted` decides the size.
 */
function trimHeapLog(home, keep) {
  const limit = Math.max(200, Math.round(Number(keep) || 0));
  try {
    const file = paths(home).heap;
    const body = fs.readFileSync(file, 'utf8').split('\n').filter((line) => line.trim() !== '');
    if (body.length <= limit * 2) return 0;
    const kept = body.slice(-limit);
    fs.writeFileSync(file, `${kept.join('\n')}\n`);
    return body.length - kept.length;
  } catch {
    return 0;
  }
}

function persistSample(home, sample) {
  try {
    appendJsonl(paths(home).heap, sample);
  } catch {
    /* a watchdog that breaks the host would be worse than no watchdog */
  }
}

/**
 * Start the singleton sampler for this profile. Safe to call twice.
 * @param {string} home
 * @param {object} options
 */
export function startWatchdog(home = DEFAULT_HOME, options = {}) {
  if (active?.running) return active;
  const watcher = createWatchdog({
    ...options,
    running: true,
    persist: (sample) => persistSample(home, sample),
    footprint: (stamp) => recordFootprint(home, { now: stamp }),
  });
  active = watcher;
  trimHeapLog(home, watcher.config.keepPersisted);
  /* First sample immediately: a restart after a crash should show the new baseline in the card. */
  watcher.sampleOnce();
  /* One baseline footprint right away: a crash inside the first sampling minute still has a
   * number to quote, and an idle machine costs one directory walk. */
  try {
    recordFootprint(home);
  } catch {
    /* best effort */
  }
  try {
    /* 一分钟一次在快满的时候会漏掉最后一截（实测峰值少记三百兆）：过 70% 就十秒一次，
     * 退回低位再放慢，采样开销只在真正要死的时候多花一点。 */
    const baseMs = Math.max(5_000, Number(watcher.config.intervalMs) || 60_000);
    const hotMs = Math.min(baseMs, 10_000);
    const tick = () => {
      try {
        watcher.sampleOnce();
      } catch {
        /* 采样失败不能把定时器带停 */
      }
      const status = watcher.status();
      const hot = status.limitMB > 0 && (status.heapMB / status.limitMB) >= 0.7;
      watcher.timer = setTimeout(tick, hot ? hotMs : baseMs);
      watcher.timer.unref?.();
    };
    watcher.timer = setTimeout(tick, baseMs);
    watcher.timer.unref?.();
  } catch {
    /* no timer service: keep the single baseline sample */
  }
  return watcher;
}

function watched() {
  active?.sampleOnce?.();
}

/** Latest host heap picture for the status card; all zeros when the timer never started. */
/* 本机实测过的死亡堆（来自自己的崩溃日志）。状态行和百分比都按它算，不另外藏一份。 */
let knownCrashMB = 0;
export function noteCrashMB(mb) {
  const n = Number(mb);
  knownCrashMB = Number.isFinite(n) && n > 0 ? Math.round(n) : 0;
}

export function watchdogStatus() {
  const status = active ? active.status() : createWatchdog({ running: false }).status();
  return { ...status, crashMB: knownCrashMB };
}

export function stopWatchdog() {
  if (active?.timer) clearInterval(active.timer);
  active = null;
}

/**
 * The long-form alarm sentence, kept for callers that want it in a panel or a report. The plugin
 * no longer puts it in the prompt: the composer badge and `lifeguard_guard` carry it, and a line
 * that repeats in every request costs context on the machine that least has room for it.
 * Empty below the warning line, so a healthy machine pays nothing.
 */
export function heapWarning(status = watchdogStatus(), options = {}) {
  if (!status?.samples) return '';
  const derived = thresholdsFor(status.limitMB ?? 0, { warnMB: options.warnMB ?? status.warnMB, criticalMB: options.criticalMB ?? status.criticalMB });
  const warnMB = derived.warnMB;
  const criticalMB = derived.criticalMB;
  const alarmMB = status.alarm && !status.alarm.released ? status.alarm.heapMB : 0;
  const hot = Math.max(status.heapMB ?? 0, alarmMB);
  if (hot < warnMB) return '';
  const trend = status.trendMBPerMin > 0 ? `，最近每分钟 +${status.trendMBPerMin} MB` : '';
  return `【内存告警】本进程堆 ${status.heapMB} MB（峰值 ${status.peakMB} MB${trend}，${warnMB} MB 记警、约 ${criticalMB} MB 逼近上限）：先把还没完的会话收尾、重启宿主把内存拿回来，再继续；这时不要恢复大会话，也不要新开长会话。`;
}

/**
 * How close this process is to the wall that actually kills, in percent. `heap_size_limit` is only
 * the point where it dies: V8 aborts when it cannot grow past its own limit, so the reported limit
 * is the wall unless a crash log from the same regime recorded an earlier death. 100% therefore
 * means "dies here", not "close enough to worry".
 */
export function heapPressure(status = watchdogStatus(), options = {}) {
  if (!status?.samples) return { pct: 0, wallMB: 0, basis: 'none' };
  /* The wall follows the runtime it is measured in: a crash point recorded under another heap
   * limit says nothing about this process, so it only counts while it still sits near that limit. */
  const { wallMB, basis } = wallFor({
    limitMB: Number(options.limitMB ?? status.limitMB ?? 0),
    crashMB: Number(options.crashMB ?? status.crashMB ?? 0),
  });
  const pct = wallMB > 0 ? Math.round(((status.heapMB ?? 0) / wallMB) * 100) : 0;
  return { pct, wallMB, basis };
}

/** One status line: heap now, growth per minute, and the last alarm if any. */
export function heapLine(status = watchdogStatus()) {
  if (!status?.samples) return '内存观测 未开始采样';
  const trend = status.trendMBPerMin > 0 ? `，+${status.trendMBPerMin} MB/min` : '';
  const alarm = status.alarm && !status.alarm.released ? `；上次运行到过 ${status.alarm.heapMB} MB（${status.alarm.at}）` : '';
  const pressure = heapPressure(status);
  const over = pressure.pct >= 100 ? '\n注意随时可能崩溃' : '';
  /* Only when the wall is inside half an hour: earlier than that the number is noise, and a line
   * repeated in every status card has to earn its length. */
  const rate = Number(status.trendMBPerMin) || 0;
  let eta = '';
  if (!over && rate > 0 && pressure.pct < 100) {
    const left = Math.ceil((pressure.wallMB - (status.heapMB ?? 0)) / rate);
    if (left > 0 && left <= 30) eta = `\n按这个增速约 ${left} 分钟到 ${pressure.wallMB} MB，先把会话收尾重启`;
  }
  /* The 3.5–4 GB deaths were not a heap wall but a process started without the 8 GB wrapper:
   * its own default ceiling ended it. The limit is measurable, so say it instead of guessing. */
  const launcher = status.limitMB > 0 && status.limitMB < 6000
    ? `\n这次堆上限 ${status.limitMB} MB，不是启动器的 8 GB，到 4 GB 左右就会死：重启用 启动DSH-6G.command`
    : '';
  return `内存观测 ${status.heapMB} MB（峰值 ${status.peakMB} MB${trend}，上限 ${status.limitMB} MB）${alarm}${over}${eta}${launcher}`;
}
