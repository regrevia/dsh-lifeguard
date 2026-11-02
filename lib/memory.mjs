/**
 * 把读数、会话体积、标题和任务排成界面那张表。
 * 不读盘、不碰服务，纯映射，好测也好换数据源。
 */

const round = (value) => Math.round(value);

/** 记录体积折成占用的系数，来自本机实测。 */
export const RESTORE_FACTOR = 6.2;

/** 记录体积 → 估占用 MB；缺省按 0，不编数字。 */
export function estimateOf(packedMB) {
  const value = Number(packedMB);
  return Number.isFinite(value) && value > 0 ? round(value * RESTORE_FACTOR) : 0;
}

/**
 * @param {object} input
 * @param {object} input.base       healthPayload 的读数：heapMB/wallMB/pct/peakMB/basis
 * @param {object} input.footprint  sessionFootprint 的结果：open/stale/openCount/staleCount
 * @param {Map<string,string>} input.titles  会话 id → 标题
 * @param {(id: string) => Array} input.jobsOf 会话 id → 后台任务行
 * @param {number} [input.limit]    最多列几个会话，默认 14
 */
export function buildMemory({ base, footprint, titles, jobsOf, limit = 14 }) {
  const open = Array.isArray(footprint?.open) ? footprint.open : [];
  const rows = open
    .map((row) => ({
      id: String(row.id ?? ''),
      title: titles instanceof Map ? titles.get(row.id) || '' : String(titles?.[row.id] ?? ''),
      project: String(row.project ?? ''),
      /* 体积优先用清单里的估算；清单只给 packed 时自己折一次。 */
      estimateMB: Number.isFinite(row.estimateMB) ? row.estimateMB : estimateOf(row.packedMB),
      packedMB: Number.isFinite(row.packedMB) ? row.packedMB : 0,
      ageMin: Math.max(0, round((Number(row.ageMs) || 0) / 60000)),
      jobs: typeof jobsOf === 'function' ? jobsOf(String(row.id ?? '')) : [],
    }))
    /* 大的在前：点开这张表是为了找谁占着。 */
    .sort((a, b) => b.estimateMB - a.estimateMB)
    .slice(0, Math.max(1, limit));

  const estimatedMB = rows.reduce((sum, row) => sum + row.estimateMB, 0);
  return {
    enabled: base?.enabled !== false,
    pct: Number.isFinite(base?.pct) ? base.pct : 0,
    heapMB: Number(base?.heapMB) || 0,
    wallMB: Number(base?.wallMB) || 0,
    peakMB: Number(base?.peakMB) || 0,
    basis: String(base?.basis ?? 'none'),
    sessions: rows,
    estimatedMB,
    openCount: Number(footprint?.openCount) || rows.length,
    staleCount: Number(footprint?.staleCount) || 0,
  };
}
