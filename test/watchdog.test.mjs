/**
 * Watchdog: a passive sampler. These tests drive it with fixed values, so they assert behaviour
 * (alarm, release, trend, silence on failure) rather than timing.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createWatchdog, heapLine, heapPressure, heapWarning } from '../watchdog.mjs';
import { thresholdsFor } from '../pressure.mjs';

function driven(values, stepMs = 20_000) {
  let index = 0;
  let clock = Date.parse('2026-10-29T00:00:00.000Z');
  const watcher = createWatchdog({
    sample: () => {
      const heapMB = values[Math.min(index, values.length - 1)];
      return { heapUsed: heapMB * 1024 * 1024, rss: (heapMB + 400) * 1024 * 1024 };
    },
    now: () => clock,
    /* Fixed lines, so the latch mechanics are asserted without depending on the runner's own
     * heap limit; the limit-derived thresholds get their own test below. */
    warnMB: 1800,
    criticalMB: 2800,
  });
  return {
    watcher,
    tick() {
      const result = watcher.sampleOnce();
      index += 1;
      clock += stepMs;
      return result;
    },
  };
}

test('samples accumulate and the trend is reported per minute', () => {
  const run = driven([1000, 1300, 1600]);
  run.tick(); run.tick(); run.tick();
  const status = run.watcher.status();
  assert.equal(status.samples, 3);
  assert.equal(status.heapMB, 1600);
  assert.equal(status.peakMB, 1600);
  /* Three samples span 40 s, so +600 MB is +900 MB/min. */
  assert.equal(status.trendMBPerMin, 900);
  assert.equal(status.alarm, null);
  assert.match(heapLine(status), /1600 MB/);
});

test('crossing the critical line records one alarm and keeps the peak', () => {
  const run = driven([2000, 2900, 3100]);
  run.tick(); run.tick(); run.tick();
  const status = run.watcher.status();
  assert.equal(status.alarm.heapMB, 3100);
  assert.equal(status.alarm.at, '2026-10-29T00:00:20.000Z');
  assert.match(heapLine(status), /上次运行到过 3100 MB/);
});

test('dropping well under the warning line releases the alarm', () => {
  const run = driven([2900, 1000]);
  run.tick(); run.tick();
  const status = run.watcher.status();
  assert.equal(status.alarm.released, true);
  assert.doesNotMatch(heapLine(status), /上次运行到过/);
});

test('a failing sampler never throws and never fakes a sample', () => {
  const watcher = createWatchdog({ sample: () => { throw new Error('gone'); } });
  assert.equal(watcher.sampleOnce(), null);
  assert.equal(watcher.status().samples, 0);
  assert.match(heapLine(watcher.status()), /未开始采样/);
});

test('scrollback stays bounded', () => {
  const run = driven([500]);
  for (let index = 0; index < 400; index += 1) run.tick();
  const status = run.watcher.status();
  assert.equal(status.samples, 400);
  assert.equal(run.watcher.config.keep, 180);
});

test('footprint is sampled on its own slow cadence, not on every heap tick', () => {
  let clock = Date.parse('2026-10-29T00:00:00.000Z');
  let footprintCalls = 0;
  const watcher = createWatchdog({
    sample: () => ({ heapUsed: 500 * 1024 * 1024, rss: 900 * 1024 * 1024 }),
    now: () => clock,
    persist: () => {},
    footprint: () => { footprintCalls += 1; },
    persistEveryMs: 20_000,
  });
  /* Six minutes of ticks: the first sample at the zero mark is inside the initial window, so the
   * walk happens on the following tick that crosses the 5-minute line, not every minute. */
  for (let at = 0; at <= 6 * 60_000; at += 20_000) { watcher.sampleOnce(); clock += 20_000; }
  assert.ok(footprintCalls >= 1 && footprintCalls <= 2, `footprint walks: ${footprintCalls}`);
  assert.ok(footprintCalls < 7, 'a minute-by-minute walk would be 7 calls');
});

test('below the warning line the prompt stays clean', () => {
  const run = driven([900, 1200]);
  run.tick(); run.tick();
  assert.equal(heapWarning(run.watcher.status()), '');
});

test('crossing the warning line puts one sentence into the prompt', () => {
  const run = driven([1900, 2100]);
  run.tick(); run.tick();
  const line = heapWarning(run.watcher.status());
  assert.match(line, /内存告警/);
  assert.match(line, /2100 MB/);
  assert.match(line, /重启宿主/);
});

test('an alarm keeps warning even after the heap drops back', () => {
  const run = driven([2900, 2600]);
  run.tick(); run.tick();
  assert.equal(run.watcher.status().alarm.released, false);
  assert.match(heapWarning(run.watcher.status()), /内存告警/);
});

test('warning lines follow the running limit instead of fixed MB', () => {
  const big = thresholdsFor(8384);
  assert.equal(big.wallMB, 8384);
  assert.equal(big.warnMB, 6288);
  assert.equal(big.criticalMB, 7546);
  const small = thresholdsFor(4096);
  assert.equal(small.wallMB, 4096);
  assert.equal(small.warnMB, 3072);
  assert.equal(small.criticalMB, 3686);
  assert.equal(thresholdsFor(0).warnMB, 1800, 'no limit known keeps the old conservative line');
});

test('percent is against the wall that kills, not the nominal limit', () => {
  const run = driven([2698, 3529]);
  run.tick();
  const live = run.watcher.status();
  /* A crash point only counts for the runtime it was measured in: heap limit 3600 here. */
  assert.equal(heapPressure(live, { crashMB: 3529, limitMB: 3600 }).pct, 76);
  assert.equal(heapPressure({ ...live, heapMB: 3529 }, { crashMB: 3529, limitMB: 3600 }).pct, 100);
  /* 别的上限下的崩溃点不适用于这个进程：死点就是这次的上限。 */
  assert.equal(heapPressure({ ...live, heapMB: 3529 }, { crashMB: 3529, limitMB: 8192 }).basis, 'limit');
  assert.equal(heapPressure({ ...live, heapMB: 3529 }, { crashMB: 3529, limitMB: 8192 }).wallMB, 8192);
  const guess = heapPressure(live, { limitMB: 4192 });
  assert.equal(guess.basis, 'limit');
  assert.equal(guess.wallMB, 4192);
});

/* 100% 必须始终等于「死过一次的堆」：状态行和百分比共用同一个 crashMB，不各算一套。 */
test('死亡堆进了状态行：正常时不写崩溃点，越过 100% 才提醒', async () => {
  const { noteCrashMB } = await import('../watchdog.mjs');
  const run = driven([3600, 3600]);
  run.tick();
  const watcher = run.watcher;
  noteCrashMB(3566);
  /* Limit recorded with the crash: the wall is this runtime's own death heap. */
  const status = { ...watcher.status(), crashMB: 3566, limitMB: 4189 };
  assert.equal(heapPressure(status).pct, 101);
  assert.equal(heapPressure(status).basis, 'crash');
  assert.doesNotMatch(heapLine(status), /崩溃点|按上限/);
  assert.match(heapLine(status), /注意随时可能崩溃/);
  const calm = { ...status, heapMB: 1800 };
  assert.doesNotMatch(heapLine(calm), /注意随时可能崩溃/);
  noteCrashMB(0);
});

test('a host started without the 8 GB wrapper says so', () => {
  const line = heapLine({ samples: 3, heapMB: 900, peakMB: 950, limitMB: 4096, wallMB: 3482, crashMB: 0 });
  assert.match(line, /这次堆上限 4096 MB，不是启动器的 8 GB/);
  assert.match(heapLine({ samples: 3, heapMB: 900, peakMB: 950, limitMB: 8384 }), /上限 8384 MB/);
  assert.doesNotMatch(heapLine({ samples: 3, heapMB: 900, peakMB: 950, limitMB: 8384 }), /不是启动器/);
});
