import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMemory, estimateOf, RESTORE_FACTOR } from '../lib/memory.mjs';

const base = { enabled: true, pct: 74, heapMB: 6249, wallMB: 8384, peakMB: 6392, basis: 'limit' };

test('记录体积折成估堆占用', () => {
  assert.equal(estimateOf(10), Math.round(10 * RESTORE_FACTOR));
  assert.equal(estimateOf(0), 0);
  assert.equal(estimateOf(undefined), 0);
  assert.equal(estimateOf('x'), 0);
});

test('按估算从大到小排，并截到 limit', () => {
  const footprint = {
    open: [
      { id: 'a', project: 'p', estimateMB: 40, packedMB: 6, ageMs: 60000 },
      { id: 'b', project: 'p', estimateMB: 900, packedMB: 145, ageMs: 120000 },
      { id: 'c', project: 'p', estimateMB: 10, packedMB: 2, ageMs: 0 },
    ],
    openCount: 3,
    staleCount: 7,
  };
  const body = buildMemory({ base, footprint, titles: new Map(), jobsOf: () => [], limit: 2 });
  assert.deepEqual(body.sessions.map((row) => row.id), ['b', 'a']);
  assert.equal(body.estimatedMB, 940);
  assert.equal(body.openCount, 3);
  assert.equal(body.staleCount, 7);
  assert.equal(body.heapMB, 6249);
  assert.equal(body.basis, 'limit');
});

test('清单只给压缩体积时自己折，标题缺了留空', () => {
  const body = buildMemory({
    base,
    footprint: { open: [{ id: 'x', project: 'proj', packedMB: 10, ageMs: 3 * 60000 }], openCount: 1, staleCount: 0 },
    titles: new Map([['other', '不该出现的标题']]),
    jobsOf: () => [],
  });
  const row = body.sessions[0];
  assert.equal(row.estimateMB, Math.round(10 * RESTORE_FACTOR));
  assert.equal(row.title, '');
  assert.equal(row.project, 'proj');
  assert.equal(row.ageMin, 3);
});

test('标题按会话对上，任务原样带上', () => {
  const jobs = [{ label: 'bash', status: 'running', retained: 2048, since: 1 }];
  const body = buildMemory({
    base,
    footprint: { open: [{ id: 's1', project: 'p', estimateMB: 12, packedMB: 2, ageMs: 0 }], openCount: 1, staleCount: 0 },
    titles: new Map([['s1', '修内存占比']]),
    jobsOf: (id) => (id === 's1' ? jobs : []),
  });
  assert.equal(body.sessions[0].title, '修内存占比');
  assert.equal(body.sessions[0].jobs.length, 1);
  assert.equal(body.sessions[0].jobs[0].retained, 2048);
});

test('没有任何会话时是一张空表，不是错误', () => {
  const body = buildMemory({ base, footprint: null, titles: new Map(), jobsOf: () => [] });
  assert.deepEqual(body.sessions, []);
  assert.equal(body.estimatedMB, 0);
  assert.equal(body.openCount, 0);
  assert.equal(body.enabled, true);
});

test('拿不到基础读数时字段归零，不编数字', () => {
  const body = buildMemory({ base: null, footprint: null, titles: new Map(), jobsOf: () => [] });
  assert.equal(body.pct, 0);
  assert.equal(body.heapMB, 0);
  assert.equal(body.wallMB, 0);
  assert.equal(body.basis, 'none');
});

test('会话清单没有估算面积时不参与占比分母', () => {
  const body = buildMemory({
    base,
    footprint: { open: [{ id: 'z', project: 'p', packedMB: 0, ageMs: 0 }], openCount: 1, staleCount: 0 },
    titles: new Map(),
    jobsOf: () => [],
  });
  assert.equal(body.estimatedMB, 0);
  assert.equal(body.sessions.length, 1);
});
