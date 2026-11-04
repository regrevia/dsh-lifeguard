/**
 * 崩溃点只认「同一档上限」下死过的记录：上限换过之后旧档的死亡点对新档没有意义。
 * 宿主的崩溃日志不带 limitMB，这类记录用「离当前上限不到 10%」当同档证据；明显低一档的不采信。
 * 纯函数：签名文本解析、取最大、脏数据不吃掉整个读数；日志变动由 index 的 stat 缓存负责。
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { maxCrashHeapMB } from '../core.mjs';

test('取同一档上限下最高的致命堆，不是最近一次也不是平均', () => {
  const rows = [
    { signature: 'out-of-memory · heap 3529 MB', limitMB: 4096 },
    { signature: 'out-of-memory · heap 4037 MB', limitMB: 4096 },
    { signature: 'out-of-memory · heap 3654 MB', limitMB: 4096 },
  ];
  assert.equal(maxCrashHeapMB(rows, { limitMB: 4096 }), 4037);
  assert.equal(maxCrashHeapMB(rows), 4037);
});

test('换了上限，旧档的死亡点不作数', () => {
  const rows = [
    { signature: 'out-of-memory · heap 4037 MB', limitMB: 4096 },
    { signature: 'out-of-memory · heap 8300 MB', limitMB: 8384 },
  ];
  assert.equal(maxCrashHeapMB(rows, { limitMB: 8384 }), 8300);
  assert.equal(maxCrashHeapMB(rows, { limitMB: 4096 }), 4037);
});

test('记录没写上限：落在当前上限 90% 以上就算同一档', () => {
  const rows = [{ signature: 'out-of-memory · heap 8197 MB' }];
  assert.equal(maxCrashHeapMB(rows, { limitMB: 8384 }), 8197, '8 GB 档死在 8.2 GB，正是同一档');
  assert.equal(maxCrashHeapMB(rows, { limitMB: 4096 }), 0, '4 GB 档不可能死在 8 GB，不采信');
  assert.equal(maxCrashHeapMB([{ signature: 'out-of-memory · heap 3917 MB' }], { limitMB: 8384 }), 0, '低一档不采信');
  assert.equal(maxCrashHeapMB(rows), 0, '没有当前上限就无从对档');
});

test('没有可采信的崩溃记录就是 0：墙就退回上限本身', () => {
  assert.equal(maxCrashHeapMB([]), 0);
  assert.equal(maxCrashHeapMB(undefined), 0);
  assert.equal(maxCrashHeapMB([{ signature: 'SyntaxError · Unexpected token' }]), 0);
});

test('脏条目不影响读数', () => {
  const rows = [{ signature: null }, {}, { signature: 'heap abc MB' }, { signature: 'heap 3900 MB', limitMB: 4096 }];
  assert.equal(maxCrashHeapMB(rows, { limitMB: 4096 }), 3900);
  assert.equal(maxCrashHeapMB(rows), 3900);
});
