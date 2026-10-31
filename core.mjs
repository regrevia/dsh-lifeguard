/**
 * dsh-lifeguard core: harvest DSH crash artifacts, normalize them into incidents,
 * keep a compact rule set ("lore"), and render the resident prompt section.
 *
 * Pure Node, zero dependencies, no side effects at import. Used by:
 * - index.js (Host plugin: tools + systemPrompt section + boot scan)
 * - cli.mjs   (outside DSH: scan / check / export / doctor)
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

/* URL.pathname 在 Windows 上带前导斜杠，拼出来是 \D:\...；fileURLToPath 才是可用的本地路径。 */
const HERE = path.dirname(fileURLToPath(import.meta.url));
import { correlateIncidents, crashLoops } from './lib/attribute.mjs';
import { footprintBefore } from './lib/sessions.mjs';

export const VERSION = '0.7.2';
export const DEFAULT_HOME = process.env.DSH_HOME || path.join(os.homedir(), '.dsh');

/* 新数据目录；旧版目录名只用于一次性迁移与读取回退。 */
export const DATA_DIR = 'lifeguard';
export const LEGACY_DIR = 'crash-lore';

const migratedHomes = new Set();

function copyTree(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const src = path.join(from, entry.name);
    const dst = path.join(to, entry.name);
    if (entry.isDirectory()) copyTree(src, dst);
    else if (!fs.existsSync(dst)) fs.copyFileSync(src, dst);
  }
}

/* 旧版把数据写在 $DSH_HOME/crash-lore、$DSH_HOME/lineage.jsonl、$DSH_HOME/handoff/；
 * 这里一次性复制进新目录。只复制不删除：旧目录原样留着，中途失败或回退旧版本都还能读。
 * 迁移失败不抛错：插件自己的存储故障不能拖垮宿主。 */
export function migrateLegacyStore(home = DEFAULT_HOME) {
  const root = path.resolve(home);
  if (migratedHomes.has(root)) return;
  migratedHomes.add(root);
  const dir = path.join(root, DATA_DIR);
  const legacyDir = path.join(root, LEGACY_DIR);
  const legacyLineage = path.join(root, 'lineage.jsonl');
  const legacyHandoff = path.join(root, 'handoff');
  const exists = (file) => { try { return fs.existsSync(file); } catch { return false; } };
  if (!exists(legacyDir) && !exists(legacyLineage) && !exists(legacyHandoff)) return;
  const copy = (from, to) => {
    if (!exists(from) || exists(to)) return;
    try {
      fs.mkdirSync(path.dirname(to), { recursive: true });
      fs.copyFileSync(from, to);
    } catch {
      /* 读不到旧数据就当没有；读取端另有回退 */
    }
  };
  try {
    if (exists(legacyDir)) copyTree(legacyDir, dir);
    else fs.mkdirSync(dir, { recursive: true });
    copy(legacyLineage, path.join(dir, 'lineage.jsonl'));
    if (exists(legacyHandoff)) copyTree(legacyHandoff, path.join(dir, 'handoff'));
  } catch {
    /* 迁移失败不抛错；旧目录保持原样可读 */
  }
}

export function storeDir(home = DEFAULT_HOME) {
  return path.join(home, DATA_DIR);
}

/* 读旧位置：新位置缺文件时退回旧目录读，写路径永远只写新位置。 */
function storeReadFile(file, home) {
  try {
    if (fs.existsSync(file)) return file;
    const legacy = path.join(path.resolve(home), LEGACY_DIR, path.relative(path.join(path.resolve(home), DATA_DIR), file));
    return fs.existsSync(legacy) ? legacy : file;
  } catch {
    return file;
  }
}

export function paths(home = DEFAULT_HOME) {
  const dir = storeDir(home);
  return {
    dir,
    incidents: path.join(dir, 'incidents.jsonl'),
    rules: path.join(dir, 'rules.json'),
    state: path.join(dir, 'state.json'),
    quarantine: path.join(dir, 'quarantine.jsonl'),
    heap: path.join(dir, 'heap.jsonl'),
    footprint: path.join(dir, 'footprint.jsonl'),
  };
}

export function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

export function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

export function writeJson(file, value) {
  ensureDir(path.dirname(file));
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`);
  fs.renameSync(tmp, file);
}

export function appendJsonl(file, value) {
  ensureDir(path.dirname(file));
  fs.appendFileSync(file, `${JSON.stringify(value)}\n`);
}

/* 行尾统一：Windows 检出/日志常用 CRLF，解析器只认 \n 就会漏判整份文件。读盘边界统一一次。 */
export function normalizeNewlines(text) {
  return String(text ?? '').replace(/\r\n?/g, '\n');
}

export function readJsonl(file) {
  let text = '';
  try {
    text = normalizeNewlines(fs.readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
  const out = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed));
    } catch {
      /* a torn line is not worth failing the whole store over */
    }
  }
  return out;
}

export function shortHash(text, len = 12) {
  return crypto.createHash('sha1').update(String(text)).digest('hex').slice(0, len);
}

export function sha256(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}

/** Mask the shapes that actually leak: api keys, bearer tokens, key=value secrets. */
export function redact(text) {
  return String(text ?? '')
    .replace(/\bsk-[A-Za-z0-9_-]{8,}/g, 'sk-***')
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/-]{8,}/g, '$1***')
    .replace(/\b((?:api[_-]?key|apikey|token|secret|password|passwd)\s*[:=]\s*['"]?)[^\s'",]{5,}/gi, '$1***');
}

/* ------------------------------------------------------------------ artifacts */

export function artifactDirs(home = DEFAULT_HOME) {
  const dirs = [];
  if (process.platform === 'darwin') {
    const logs = path.join(os.homedir(), 'Library', 'Logs');
    dirs.push(path.join(logs, 'DeepSeek Harness'));
    try {
      for (const name of fs.readdirSync(logs)) {
        if (/^(deepseek|dsh)/i.test(name)) dirs.push(path.join(logs, name));
      }
    } catch {
      /* no Logs dir on this box */
    }
  } else if (process.platform === 'win32') {
    dirs.push(path.join(process.env.APPDATA || '', 'DeepSeek Harness', 'logs'));
  } else {
    dirs.push(path.join(os.homedir(), '.config', 'DeepSeek Harness', 'logs'));
  }
  dirs.push(path.join(home, 'logs'));
  return [...new Set(dirs)].filter((dir) => {
    try {
      return fs.statSync(dir).isDirectory();
    } catch {
      return false;
    }
  });
}

const ARTIFACT_RE = /^(crash-.*\.log|startup-.*\.log)$/;

export function fetchArtifacts(home = DEFAULT_HOME, dirs) {
  const out = [];
  const seen = new Set();
  const search = Array.isArray(dirs) && dirs.length ? dirs : artifactDirs(home);
  for (const dir of search) {
    let names = [];
    try {
      names = fs.readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of names) {
      if (!ARTIFACT_RE.test(name)) continue;
      const file = path.join(dir, name);
      if (seen.has(file)) continue;
      seen.add(file);
      let stat;
      try {
        stat = fs.statSync(file);
      } catch {
        continue;
      }
      if (!stat.isFile()) continue;
      out.push({ path: file, mtimeMs: stat.mtimeMs, size: stat.size, source: name.startsWith('startup-') ? 'startup-diag' : /web-boot/.test(name) ? 'web-boot-crash' : 'host-crash' });
    }
  }
  return out.sort((a, b) => a.mtimeMs - b.mtimeMs);
}

const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;

export function readArtifact(file) {
  const stat = fs.statSync(file);
  if (stat.size > MAX_ARTIFACT_BYTES) {
    const fd = fs.openSync(file, 'r');
    try {
      const buf = Buffer.alloc(MAX_ARTIFACT_BYTES);
      fs.readSync(fd, buf, 0, MAX_ARTIFACT_BYTES, 0);
      return normalizeNewlines(buf.toString('utf8'));
    } finally {
      fs.closeSync(fd);
    }
  }
  return normalizeNewlines(fs.readFileSync(file, 'utf8'));
}

/* ------------------------------------------------------------------ parsing */

function headerOf(text) {
  const head = normalizeNewlines(text).split('\n--- ')[0] || '';
  const out = {};
  for (const line of head.split('\n')) {
    const m = /^([a-z][a-z0-9 ]*):\s?(.*)$/.exec(line);
    if (m) out[m[1].trim()] = m[2].trim();
  }
  return out;
}

function sectionOf(text, title) {
  const start = text.indexOf(`--- ${title} ---`);
  if (start < 0) return '';
  const body = text.slice(start + `--- ${title} ---`.length);
  const end = body.search(/\n--- [a-z]/);
  return (end < 0 ? body : body.slice(0, end)).trim();
}

function frameLocation(raw) {
  /* `at Fn (file:///x.js:10:2)`, `at file:///x.js:10:2`, `at async Fn (/x.js:10:2)` all end the same:
   * take the last parenthesised group, else the bare token, then split off :line:col. */
  let token = String(raw ?? '').trim();
  const paren = /\(([^()]*)\)\s*$/.exec(token);
  if (paren) token = paren[1].trim();
  token = token.replace(/^async\s+/, '').replace(/^new\s+/, '');
  if (!token) return null;
  const m = /^(.*?):(\d+)(?::(\d+))?$/.exec(token);
  let file = (m ? m[1] : token).trim();
  if (!file) return null;
  if (file.startsWith('file://')) {
    try {
      file = decodeURIComponent(file.slice('file://'.length));
    } catch {
      file = file.slice('file://'.length);
    }
  }
  file = file.replace(/[?#].*$/, '');
  /* Only frames that name a real source location: `at resolveConfig` alone is a function, not a file. */
  if (!/[/\\]/.test(file) && !/^[A-Za-z]:\\/.test(file) && !/\.(?:mjs|cjs|js|jsx|ts|tsx)$/.test(file) && !/^node:/.test(file)) return null;
  return { file, line: m ? Number(m[2]) : null, col: m?.[3] ? Number(m[3]) : null };
}

function firstFrame(text) {
  for (const line of String(text ?? '').split('\n')) {
    const m = /^\s+at\s+(.+)$/.exec(line);
    if (!m) continue;
    const frame = frameLocation(m[1]);
    if (frame) return frame;
  }
  return null;
}

/** Plugin packages installed in a profile, resolved to their on-disk roots. */
export function pluginIndex(profileDir = process.env.DSH_PROFILE_DIR || '') {
  const index = [];
  if (!profileDir) return index;
  const pkg = readJson(path.join(profileDir, 'package.json'), null);
  const deps = pkg?.dependencies;
  if (!deps || typeof deps !== 'object') return index;
  for (const [name, spec] of Object.entries(deps)) {
    const raw = String(spec ?? '');
    let dir = null;
    const local = /^(?:link|file):(.+)$/.exec(raw);
    if (local) dir = path.resolve(profileDir, local[1]);
    else dir = path.join(profileDir, 'node_modules', name);
    index.push({ name, dir, raw: local ? local[1] : null });
  }
  return index;
}

/* 崩溃日志里的帧路径是 POSIX 写法，Windows 上 path.resolve/sep 会把它们对比错，统一按 / 比较。 */
function slashed(value) {
  return String(value ?? '').replace(/\\/g, '/').replace(/\/+$/, '');
}

function culpritFromFrame(frame, profileDir, home) {
  if (!frame?.file) return null;
  const file = slashed(frame.file);
  for (const entry of pluginIndex(profileDir)) {
    const dirs = [entry.dir, entry.raw].filter(Boolean).map(slashed);
    for (const dir of dirs) {
      if (file === dir || file.startsWith(`${dir}/`)) {
        return { type: 'plugin', name: entry.name, evidence: `${file.slice(dir.length + 1) || path.basename(file)}:${frame.line ?? '?'}` };
      }
    }
  }
  if (file.includes('/app.asar/') || (file.includes('/deepseek') && file.includes('node_modules'))) {
    return { type: 'core', name: 'deepseek-harness', evidence: file.split('/').pop() };
  }
  const homeDir = slashed(home || os.homedir());
  if (file.startsWith(`${homeDir}/`)) {
    const rel = file.slice(homeDir.length + 1).split('/');
    const known = rel.findIndex((part) => part === 'node_modules');
    const name = known >= 0 ? rel[known + 1] : rel[rel.length - 2];
    return { type: 'plugin', name: name || null, evidence: rel[rel.length - 1] };
  }
  return null;
}

function clientCulprit(rendererText) {
  for (const line of rendererText.split('\n')) {
    const m = /dsh-app:\/\/app\/plugins\/\?\?([^/,&]+)\/client\.js/.exec(line);
    if (m) return { type: 'plugin', name: m[1], evidence: 'client.js' };
  }
  return null;
}

function classifyCrash(errorText, rendererText, source) {
  if (/fatal uncaught exception|uncaughtException/i.test(errorText)) return 'uncaught-exception';
  if (/startup failed/i.test(errorText)) return 'plugin-activation';
  if (/ValidationError: invalid config/i.test(errorText)) return 'config-validation';
  if (/Maximum call stack size exceeded/i.test(errorText)) return 'stack-overflow';
  /* Heap death arrives as a V8 GC diary, not as a JS exception: the host reports
   * `dsh desktop host stopped: <--- Last few GCs --->` and the process is gone. */
  if (/<--- Last few GCs --->|JavaScript heap out of memory|FATAL ERROR: .*(heap|Allocation failed)/i.test(errorText)) return 'out-of-memory';
  if (/web boot:/.test(errorText)) return 'web-boot';
  if (/did not activate/i.test(errorText)) return 'plugin-activation';
  if (/Uncaught SyntaxError/i.test(rendererText) && !errorText.trim()) return 'client-error';
  return source === 'web-boot-crash' ? 'web-boot' : 'unknown';
}

function parseCrash(file, text) {
  const header = headerOf(text);
  const errorText = sectionOf(text, 'error');
  const rendererText = sectionOf(text, 'renderer console (error level, oldest first)');
  const source = /web-boot/.test(file) ? 'web-boot-crash' : 'host-crash';
  const kind = classifyCrash(errorText, rendererText, source);

  let signature = 'unknown';
  let message = '';
  let culprit = null;
  /* A stack overflow names its own site: `Exception in PromiseRejectCallback: file:///...:1309`
   * is the innermost frame, while the `at` list only carries the host's stop path. */
  let stackFrame = null;

  if (kind === 'uncaught-exception') {
    const m = /fatal uncaught exception:\s*([^\n]+)/i.exec(errorText);
    const raw = (m?.[1] ?? errorText.split('\n').find((line) => /Error|Exception/.test(line)) ?? '').trim();
    const parts = /^([A-Za-z_$][\w$.]*(?:Error|Exception)?)\s*:\s*([\s\S]*)$/.exec(raw);
    const name = parts?.[1] ?? 'Error';
    const detail = (parts?.[2] ?? raw).split('\n')[0].trim();
    const normDetail = detail.replace(/0x[0-9a-f]+/gi, '#').replace(/\b\d{3,}\b/g, '#').slice(0, 140);
    signature = `${name} · ${normDetail}`;
    message = raw.slice(0, 400);
  } else if (kind === 'web-boot') {
    const failed = [...errorText.matchAll(/^\s*([@\w./-]+):\s*failed\s*$/gm)].map((m) => m[1]);
    const detail = /web boot:\s*([^\n]+)/.exec(errorText)?.[1]?.trim() ?? 'web boot failed';
    signature = `web boot · ${detail}${failed.length ? `: ${failed.join(' + ')}: failed` : ''}`;
    message = errorText.slice(0, 400);
    if (failed.length === 1) culprit = { type: 'plugin', name: failed[0], evidence: 'boot entry' };
  } else if (kind === 'plugin-activation') {
    const failed = [...errorText.matchAll(/^\s*([@\w./-]+):\s*failed\s*$/gm)].map((m) => m[1]);
    signature = failed.length ? `activation · ${failed.join(' + ')} failed` : `activation · ${(errorText.split('\n')[0] || 'entry failed').slice(0, 120)}`;
    message = errorText.slice(0, 400);
    if (failed.length === 1) culprit = { type: 'plugin', name: failed[0], evidence: 'boot entry' };
  } else if (kind === 'config-validation') {
    const bullet = /^\s*-\s+(.+)$/m.exec(errorText)?.[1]?.trim();
    const name = /([A-Za-z_$][\w$.]*(?:Error|Exception)):/.exec(errorText)?.[1] ?? 'ValidationError';
    signature = bullet ? `${name} · ${bullet}` : `${name} · invalid config`;
    message = errorText.slice(0, 400);
  } else if (kind === 'stack-overflow') {
    const deep = /file:\/\/([^\s:]+):(\d+)/.exec(errorText);
    /* Cache-busted client modules import as `plugin.js?v=12`; the version is not part of the
     * crash shape, so it must not split one bug into three incidents. */
    if (deep) stackFrame = { file: deep[1].split('?')[0], line: Number(deep[2]), raw: `file://${deep[1]}:${deep[2]}` };
    const where = stackFrame ? `${path.basename(stackFrame.file)}:${stackFrame.line}` : 'Maximum call stack size exceeded';
    signature = `stack-overflow · ${where}`;
    message = errorText.slice(0, 400);
    culprit = stackFrame ? culpritFromFrame(stackFrame, process.env.DSH_PROFILE_DIR || '', DEFAULT_HOME) : null;
  } else if (kind === 'out-of-memory') {
    /* The diary names the ceiling it kept hitting; that number is the shape of the bug,
     * while the 4000 ms / address noise around it is not. */
    /* `Scavenge 3701.7 (3758.6) -> 3687.2 (3764.9) MB` — the number inside the parens is the
     * committed heap, i.e. how close the process got to its ceiling. */
    const sized = [...errorText.matchAll(/(\d+(?:\.\d+)?)\s*\(\s*(\d+(?:\.\d+)?)\s*\)\s*->\s*\d/g)]
      .map((m) => Number(m[2]));
    const peak = sized.length ? Math.max(...sized) : null;
    signature = `out-of-memory · heap ${peak === null ? 'exhausted' : `${Math.round(peak)} MB`}`;
    message = errorText.slice(0, 400);
  } else {
    signature = `${kind} · ${redact(errorText.split('\n')[0] ?? '').slice(0, 140)}`;
    message = errorText.slice(0, 400);
  }

  const frame = stackFrame ?? firstFrame(errorText);
  if (!culprit) culprit = culpritFromFrame(frame, process.env.DSH_PROFILE_DIR || '', DEFAULT_HOME) ?? clientCulprit(rendererText);

  const app = /(\d+\.\d+\.\d+[\w.-]*)/.exec(header.app ?? '')?.[1] ?? null;
  return {
    ts: header.time ?? new Date(fs.statSync(file).mtimeMs).toISOString(),
    source,
    phase: header.phase ?? 'running',
    app,
    profile: header.profile ?? null,
    kind,
    signature: redact(signature).slice(0, 200),
    frame: frame ? `${path.basename(frame.file)}:${frame.line ?? '?'}` : null,
    frameFile: frame?.file ?? null,
    message: redact(message),
    stack: redact(errorText).slice(0, 3000),
    culprit,
    artifact: file,
  };
}

function parseStartup(file, text) {
  const ts = /timestamp:\s*'([^']+)'/.exec(text)?.[1] ?? new Date(fs.statSync(file).mtimeMs).toISOString();
  const app = /dshVersion:\s*'([^']+)'/.exec(text)?.[1] ?? null;
  const profile = /profile:\s*'([^']+)'/.exec(text)?.[1] ?? null;
  const failure = /startup failed:.*$/m.exec(text)?.[0]?.trim() ?? 'startup failed';
  const body = text.slice(text.indexOf('error: '));
  const entries = [...body.matchAll(/^\s{4}([\w@/.-]+)\s*$\n\s{6}Package:\s*([\w@/.-]+)\s*$/gm)]
    .map((m) => ({ id: m[1], pkg: m[2] }));
  const firstError = /^\s{6}([A-Za-z_$][\w$.]*(?:Error|Exception)):\s*([^\n]*)/m.exec(body);
  const bullet = /^\s{6,}-\s+(.+)$/m.exec(body)?.[1]?.trim();
  const valid = /ValidationError:\s*invalid config/.test(body);
  const kind = valid ? 'config-validation' : 'plugin-activation';
  const names = entries.map((entry) => entry.id);
  const signature = kind === 'config-validation'
    ? `ValidationError · ${bullet ?? 'invalid config'}`
    : `startup · ${names.length ? names.join(' + ') : 'plugin'} failed to activate`;
  const frame = firstFrame(body);
  return {
    ts,
    source: 'startup-diag',
    phase: 'boot',
    app,
    profile,
    kind,
    signature: redact(signature).slice(0, 200),
    frame: frame ? `${path.basename(frame.file)}:${frame.line ?? '?'}` : null,
    frameFile: frame?.file ?? null,
    message: redact(`${failure}\n${firstError ? `${firstError[1]}: ${firstError[2]}` : ''}`).slice(0, 400),
    stack: redact(body).slice(0, 3000),
    culprit: entries[0] ? { type: 'package', name: entries[0].pkg, evidence: `entry ${entries[0].id}` } : null,
    artifact: file,
  };
}

/**
 * A single artifact can hold more than one crash shape: the desktop host log also records the
 * renderer console, so a client bundle that fails to parse shows up next to the host exception.
 */
export function parseArtifacts(file) {
  const primary = parseArtifact(file);
  if (!primary) return [];
  const out = [primary];
  const extra = parseRendererIncident(file);
  if (extra && extra.fingerprint !== primary.fingerprint) out.push(extra);
  return out;
}

function parseRendererIncident(file) {
  let text;
  try {
    text = readArtifact(file);
  } catch {
    return null;
  }
  const section = sectionOf(text, 'renderer console (error level, oldest first)');
  if (!section) return null;
  const entry = section.split('\n').find((line) => /Uncaught (SyntaxError|TypeError|ReferenceError)/.test(line));
  if (!entry) return null;
  const name = /Uncaught ([A-Za-z]+Error)/.exec(entry)?.[1] ?? 'Error';
  /* The console line often carries a `dsh-app://…/client.js:1497` prefix before the real message. */
  const detail = (entry.split(/Uncaught\s+\w*Error:\s*/).pop() ?? '')
    .replace(/\s+at\s+.*$/, '')
    .trim();
  const plugin = /dsh-app:\/\/app\/plugins\/\?\?([^/&#]+)\//.exec(section)?.[1] ?? null;
  const signature = redact(`${name} · ${detail || 'renderer error'}`).slice(0, 200);
  const kind = 'plugin-activation';
  const frame = 'client.js';
  const fingerprint = sha256(`${kind}|${signature}|${frame}`).slice(0, 12);
  const header = headerOf(text);
  return {
    id: `inc_${fingerprint}`,
    ts: header.time ?? new Date(fs.statSync(file).mtimeMs).toISOString(),
    source: /web-boot/.test(file) ? 'web-boot-crash' : 'host-crash',
    phase: header.phase ?? 'running',
    kind,
    app: /(\d+\.\d+\.\d+[\w.-]*)/.exec(header.app ?? '')?.[1] ?? null,
    profile: header.profile ?? null,
    signature,
    fingerprint,
    frame,
    message: redact(entry).slice(0, 400),
    stack: redact(session_lines(section)).slice(0, 3000),
    culprit: plugin ? { type: 'plugin', name: plugin, evidence: 'client.js' } : null,
    artifact: file,
    ruleIds: [],
    reportedToMemory: false,
  };
}

function session_lines(section) {
  return section.split('\n').slice(0, 40).join('\n');
}

export function parseArtifact(file) {
  let text;
  try {
    text = readArtifact(file);
  } catch {
    return null;
  }
  if (!text.trim()) return null;
  try {
    const incident = /startup-.*\.log$/.test(file) || text.startsWith('WARNING: Raw diagnostics') ? parseStartup(file, text) : parseCrash(file, text);
    /* Fingerprint is kind|signature|frame with no absolute path and no pid: the same crash shape
     * on a later boot must land on the same incident, or every restart invents a new one. */
    const fingerprint = sha256(`${incident.kind}|${incident.signature}|${incident.frame}`).slice(0, 12);
    return {
      id: `inc_${fingerprint}`,
      ts: incident.ts,
      source: incident.source,
      phase: incident.phase,
      kind: incident.kind,
      app: incident.app,
      profile: incident.profile,
      signature: incident.signature,
      fingerprint,
      frame: incident.frame,
      frameFile: incident.frameFile ?? null,
      message: incident.message,
      stack: incident.stack,
      culprit: incident.culprit,
      artifact: file,
      ruleIds: [],
      reportedToMemory: false,
    };
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ store */

export function readIncidents(home = DEFAULT_HOME) {
  return readJsonl(storeReadFile(paths(home).incidents, home));
}

/* 本机最高的一次致命堆：崩溃日志里所有 OOM 的 heap 取最大。纯函数，横竖都能测；
 * Windows/Linux/macOS 只依赖签名文本，不碰路径分隔符。 */
export function maxCrashHeapMB(incidents = []) {
  let wall = 0;
  for (const incident of incidents) {
    const match = /heap\s+(\d+)\s*MB/.exec(String(incident?.signature ?? ''));
    const heap = match ? Number(match[1]) : 0;
    if (heap > wall) wall = heap;
  }
  return wall;
}

export function appendIncident(incident, home = DEFAULT_HOME) {
  appendJsonl(paths(home).incidents, incident);
}

/** Rewrite the whole incidents log (used when repeating crashes bump an existing entry). */
export function rewriteIncidents(incidents, home = DEFAULT_HOME) {
  const file = paths(home).incidents;
  const body = incidents.map((incident) => JSON.stringify(incident)).join('\n');
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, body ? `${body}\n` : '');
}

export function readRules(home = DEFAULT_HOME) {
  const doc = readJson(storeReadFile(paths(home).rules, home), null);
  return Array.isArray(doc?.rules) ? doc.rules : [];
}

export function writeRules(rules, home = DEFAULT_HOME) {
  writeJson(paths(home).rules, { version: 1, rules });
}

export function readState(home = DEFAULT_HOME) {
  const state = readJson(storeReadFile(paths(home).state, home), null);
  return { scanned: {}, quarantine: [], ...(state && typeof state === 'object' ? state : {}) };
}

export function writeState(state, home = DEFAULT_HOME) {
  writeJson(paths(home).state, state);
}

export function nextRuleId(rules) {
  let max = 0;
  for (const rule of rules) {
    const m = /^R(\d+)$/.exec(String(rule?.id ?? ''));
    if (m) max = Math.max(max, Number(m[1]));
  }
  return `R${String(max + 1).padStart(3, '0')}`;
}

export function upsertRule(rule, home = DEFAULT_HOME) {
  const rules = readRules(home);
  const title = String(rule?.title ?? '').trim();
  if (!title) throw new Error('rule needs a title');
  if (rule.signature) {
    try {
      new RegExp(rule.signature, 'i');
    } catch {
      throw new Error(`rule.signature is not a valid RegExp: ${rule.signature}`);
    }
  }
  const at = rules.findIndex((item) => item.id === rule.id || (rule.signature && item.signature === rule.signature) || item.title === title);
  const now = new Date().toISOString();
  if (at >= 0) {
    const merged = { ...rules[at], ...rule, id: rules[at].id, firstSeen: rules[at].firstSeen ?? now, lastSeen: rule.lastSeen ?? rules[at].lastSeen ?? now };
    rules[at] = merged;
    writeRules(rules, home);
    return merged;
  }
  const created = { id: rule.id || nextRuleId(rules), title, signature: rule.signature ?? '', cause: rule.cause ?? '', fix: rule.fix ?? '', guard: rule.guard ?? null, severity: rule.severity ?? 'lint', tags: rule.tags ?? [], hits: rule.hits ?? 0, firstSeen: rule.firstSeen ?? now, lastSeen: rule.lastSeen ?? now, incidentIds: rule.incidentIds ?? [], memoryId: rule.memoryId ?? null };
  rules.push(created);
  writeRules(rules, home);
  return created;
}

/**
 * Import the checked-in seed rules (`rules.seed.json`, produced from the corpus) into the store.
 * Existing rules keep their hit counts and memoryId; the seed only fills what is missing.
 */
export function seedRules(home = DEFAULT_HOME, seedFile) {
  const file = seedFile ?? path.join(HERE, 'rules.seed.json');
  const doc = readJson(file, null);
  const list = Array.isArray(doc?.rules) ? doc.rules : Array.isArray(doc) ? doc : [];
  if (!list.length) return { seeded: 0, file };
  const rules = readRules(home);
  let seeded = 0;
  for (const incoming of list) {
    const at = rules.findIndex((rule) => rule.id === incoming.id || rule.title === incoming.title);
    if (at >= 0) {
      const merged = { ...incoming, ...rules[at], guard: rules[at].guard ?? incoming.guard ?? null };
      merged.hits = rules[at].hits ?? incoming.hits ?? 0;
      merged.incidentIds = [...new Set([...(incoming.incidentIds ?? []), ...(rules[at].incidentIds ?? [])])].slice(-20);
      rules[at] = merged;
    } else {
      rules.push({ ...incoming, hits: incoming.hits ?? 0, incidentIds: incoming.incidentIds ?? [], memoryId: incoming.memoryId ?? null });
      seeded += 1;
    }
  }
  writeRules(rules, home);
  return { seeded, total: rules.length, file };
}

/**
 * The shipped corpus also carries crash shapes whose artifact is not present on this machine
 * (a session transcript kept only survives as a fixture). Import those so rules can point at them.
 */
export function importCorpus(home = DEFAULT_HOME, corpusFile) {
  const file = corpusFile ?? path.join(HERE, 'corpus', 'incidents.normalized.jsonl');
  const list = readJsonl(file);
  if (!list.length) return { imported: 0, file };
  const stored = readIncidents(home);
  const known = new Map(stored.map((incident) => [incident.fingerprint, incident]));
  let imported = 0;
  for (const incident of list) {
    if (!incident?.fingerprint || known.has(incident.fingerprint)) continue;
    appendIncident({ ...incident, reportedToMemory: false }, home);
    known.set(incident.fingerprint, incident);
    imported += 1;
  }
  return { imported, file };
}

const compiled = new Map();
function regexOf(pattern) {
  if (compiled.has(pattern)) return compiled.get(pattern);
  let re = null;
  try {
    re = new RegExp(pattern, 'i');
  } catch {
    re = null;
  }
  compiled.set(pattern, re);
  return re;
}

export function matchRules(incident, rules) {
  const hay = `${incident.signature}\n${incident.message}\n${incident.stack}`;
  return rules.filter((rule) => {
    if (!rule?.signature) return false;
    const re = regexOf(rule.signature);
    return re ? re.test(hay) : false;
  });
}

/* ------------------------------------------------------------------ scan */

const SEVERITY_RANK = { fatal: 0, boot: 1, lint: 2 };

export function rankRules(rules) {
  return [...rules].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3) || (b.hits ?? 0) - (a.hits ?? 0) || String(a.id).localeCompare(String(b.id)));
}

const OCCURRENCE_CAP = 100;

/** Identity of one real crash event: same artifact + timestamp = the same event, never counted twice. */
const OCCURRENCE_BLOOM_BITS = 2048;
const OCCURRENCE_BLOOM_HASHES = 3;

function bloomHash(id, seed) {
  let hash = 2166136261 ^ seed;
  for (let at = 0; at < id.length; at += 1) {
    hash ^= id.charCodeAt(at);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) % OCCURRENCE_BLOOM_BITS;
}

/** Compact, bounded memory of every event id already counted for a row: identity lists are capped
 * for display, but a force rescan must not mistake an evicted id for a new event. */
function bloomFrom(ids = [], offset = 0) {
  const bits = new Uint8Array(OCCURRENCE_BLOOM_BITS / 8);
  for (const id of ids) bloomAdd(bits, String(id), offset);
  return Buffer.from(bits).toString('base64');
}

function bloomBits(encoded) {
  if (typeof encoded !== 'string' || !encoded) return null;
  const buffer = Buffer.from(encoded, 'base64');
  return buffer.length === OCCURRENCE_BLOOM_BITS / 8 ? new Uint8Array(buffer) : null;
}

function bloomAdd(bits, id, offset = 0) {
  for (let seed = 0; seed < OCCURRENCE_BLOOM_HASHES; seed += 1) {
    const at = bloomHash(id, seed + offset * 0x9e3779b9);
    bits[at >> 3] |= 1 << (at & 7);
  }
}

function bloomHas(bits, id, offset = 0) {
  for (let seed = 0; seed < OCCURRENCE_BLOOM_HASHES; seed += 1) {
    const at = bloomHash(id, seed + offset * 0x9e3779b9);
    if ((bits[at >> 3] & (1 << (at & 7))) === 0) return false;
  }
  return true;
}

export function occurrenceId(incident) {
  return shortHash(`${incident.fingerprint}|${incident.artifact}|${incident.ts}`);
}

/** Keep per-event identity alongside the aggregate, so force-rescan is idempotent. */
export function normalizeOccurrence(incident) {
  const ts = incident.lastTs || incident.ts || new Date(0).toISOString();
  const count = Math.max(1, Number(incident.count) || 1);
  const realIds = Array.isArray(incident.occurrenceIds) && incident.occurrenceIds.length;
  const occurrenceIds = realIds
    ? incident.occurrenceIds.slice(-OCCURRENCE_CAP)
    /* Legacy aggregate rows carry no per-event list: synthesize `count` anonymous events so a
     * migrated row keeps meaning "happened count times" instead of collapsing to one. The `legacy:`
     * prefix marks them as synthesized, so a later parse of the real artifact can replace them
     * instead of stacking real events on top of fabricated ones. */
    : Array.from({ length: Math.min(count, OCCURRENCE_CAP) }, (_, at) => `legacy:${shortHash(`${incident.fingerprint}|${incident.artifact}|${ts}|legacy|${at}`)}`);
  const occurrenceTimes = Array.isArray(incident.occurrenceTimes) && incident.occurrenceTimes.length
    ? incident.occurrenceTimes.slice(-OCCURRENCE_CAP)
    : Array.from({ length: Math.min(count, OCCURRENCE_CAP) }, () => ts);
  /* Synthesized occurrences (no ids at all, `legacy:` ids, or rows migrated by an older build that
   * repeated one timestamp `count` times) are placeholders, never evidence. Only a real artifact
   * parse may turn them into counted events. */
  const synthesized = !realIds
    || occurrenceIds.every((id) => String(id).startsWith('legacy:'))
    || (count > 1 && new Set(occurrenceTimes).size === 1);
  /* A row without a per-event list can never be real, whatever flag it carries: an older build may
   * have written `occurrenceSynthetic: false` next to stripped ids. */
  const occurrenceSynthetic = !realIds ? true : Boolean(incident.occurrenceSynthetic ?? synthesized);
  /* Bounded memory of every counted event id (see bloomFrom): rebuilt from the visible ids when absent. */
  const storedSeen = bloomBits(incident.occurrenceSeen);
  const occurrenceSeen = storedSeen ? incident.occurrenceSeen : realIds ? bloomFrom(occurrenceIds) : null;
  /* A second, independently seeded filter of the same ids. Membership needs both to agree, so one
   * bit collision can no longer mark a brand-new event as "already counted": `count` stays exact
   * while memory stays bounded. Rows written before 0.2.1 have only one filter; the second one is
   * seeded from the visible ids, so evicted ids counted by an older build are the only ones that may
   * be re-counted once after the upgrade. */
  const storedSeen2 = bloomBits(incident.occurrenceSeen2);
  const occurrenceSeen2 = storedSeen2 ? incident.occurrenceSeen2 : realIds ? bloomFrom(occurrenceIds, 1) : null;
  return { ...incident, occurrenceIds, occurrenceTimes, count, lastTs: occurrenceTimes[occurrenceTimes.length - 1], occurrenceSynthetic, occurrenceSeen, occurrenceSeen2 };
}

export function scan(options = {}) {
  const home = options.home ?? DEFAULT_HOME;
  /* 升级后第一次扫描前把旧版数据目录并进来；只搬不删，失败也只是继续用旧目录读。 */
  migrateLegacyStore(home);
  const state = readState(home);
  const rules = readRules(home);
  const rawStored = readIncidents(home);
  const stored = rawStored.map(normalizeOccurrence);
  const known = new Map(stored.map((incident) => [incident.fingerprint, incident]));
  const artifacts = fetchArtifacts(home, options.dirs);
  const added = [];
  const unknown = [];
  const bumped = new Map();
  const observed = new Map();
  /* Live bitset per fingerprint: the visible id list is capped, so membership must come from the
   * bloom (which remembers evicted ids) instead of the list, or a force rescan re-adds the whole
   * bucket and inflates `count`. */
  const seenBits = new Map();
  const bitsFor = (fingerprint, seen) => {
    let pair = seenBits.get(fingerprint);
    if (!pair) {
      const a = bloomBits(seen?.occurrenceSeen) ?? new Uint8Array(OCCURRENCE_BLOOM_BITS / 8);
      const b = bloomBits(seen?.occurrenceSeen2) ?? new Uint8Array(OCCURRENCE_BLOOM_BITS / 8);
      /* Older rows: seed both filters with the ids they still carry. */
      for (const id of seen?.occurrenceIds ?? []) {
        bloomAdd(a, String(id));
        bloomAdd(b, String(id), 1);
      }
      pair = { a, b };
      seenBits.set(fingerprint, pair);
    }
    return pair;
  };
  const hasSeen = (pair, id) => bloomHas(pair.a, id) && bloomHas(pair.b, id, 1);
  const addSeen = (pair, id) => {
    bloomAdd(pair.a, id);
    bloomAdd(pair.b, id, 1);
  };
  const syncSeen = (seen, pair) => {
    seen.occurrenceSeen = Buffer.from(pair.a).toString('base64');
    seen.occurrenceSeen2 = Buffer.from(pair.b).toString('base64');
  };
  let harvested = 0;

  for (const artifact of artifacts) {
    const fresh = options.force || state.scanned[artifact.path] !== artifact.mtimeMs;
    if (!fresh) continue;
    harvested += 1;
    const parsed = parseArtifacts(artifact.path);
    state.scanned[artifact.path] = artifact.mtimeMs;
    for (const incident of parsed) {
      if (known.has(incident.fingerprint)) {
        /* Same crash shape again: a new event counts, re-parsing the same artifact does not. Collect
         * the real per-event identity first; merging happens once per fingerprint after this artifact
         * loop, so a synthetic legacy count can be replaced instead of incremented. */
        const seen = known.get(incident.fingerprint);
        const id = occurrenceId(incident);
        const bucket = observed.get(incident.fingerprint) ?? new Map();
        bucket.set(id, incident.ts);
        observed.set(incident.fingerprint, bucket);
        const bits = bitsFor(incident.fingerprint, seen);
        if (!seen.occurrenceSynthetic && !hasSeen(bits, id)) {
          addSeen(bits, id);
          syncSeen(seen, bits);
          seen.occurrenceIds = [...seen.occurrenceIds, id].slice(-OCCURRENCE_CAP);
          seen.occurrenceTimes = [...seen.occurrenceTimes, incident.ts].sort().slice(-OCCURRENCE_CAP);
          seen.lastTs = seen.occurrenceTimes[seen.occurrenceTimes.length - 1];
          seen.count = Math.max((seen.count ?? 1) + 1, seen.occurrenceIds.length);
          if (seen.id) bumped.set(seen.id, (bumped.get(seen.id) ?? 0) + 1);
        }
        continue;
      }
      const matched = matchRules(incident, rules);
      incident.ruleIds = matched.map((rule) => rule.id);
      for (const rule of matched) {
        rule.hits = (rule.hits ?? 0) + 1;
        rule.lastSeen = incident.ts;
        rule.incidentIds = [...new Set([...(rule.incidentIds ?? []), incident.id])].slice(-20);
      }
      const freshIncident = normalizeOccurrence({ ...incident, count: 1, occurrenceIds: [occurrenceId(incident)], occurrenceTimes: [incident.ts] });
      appendIncident(freshIncident, home);
      known.set(freshIncident.fingerprint, freshIncident);
      added.push(freshIncident);
      if (!matched.length) unknown.push(freshIncident);
    }
  }

  /* One merge per fingerprint: a row whose occurrences were synthesized (legacy migration) is
   * replaced by the real events just observed, so a force rescan can only ever converge. Rows that
   * already hold real events gain the newly observed ones. */
  for (const [fingerprint, bucket] of observed) {
    const seen = known.get(fingerprint);
    if (!seen) continue;
    const entries = [...bucket].sort((a, b) => String(a[1]).localeCompare(String(b[1])));
    if (seen.occurrenceSynthetic) {
      const before = JSON.stringify(seen.occurrenceIds);
      const ids = entries.map(([id]) => id);
      const times = entries.map(([, ts]) => ts);
      seen.occurrenceIds = ids.slice(-OCCURRENCE_CAP);
      seen.occurrenceTimes = times.slice(-OCCURRENCE_CAP);
      seen.count = seen.occurrenceIds.length;
      seen.lastTs = seen.occurrenceTimes[seen.occurrenceTimes.length - 1];
      seen.occurrenceSynthetic = false;
      const a = Uint8Array.from(Buffer.from(bloomFrom(seen.occurrenceIds), 'base64'));
      const b = Uint8Array.from(Buffer.from(bloomFrom(seen.occurrenceIds, 1), 'base64'));
      seen.occurrenceSeen = Buffer.from(a).toString('base64');
      seen.occurrenceSeen2 = Buffer.from(b).toString('base64');
      seenBits.set(fingerprint, { a, b });
      if (seen.id && JSON.stringify(seen.occurrenceIds) !== before) bumped.set(seen.id, (bumped.get(seen.id) ?? 0) + 1);
      continue;
    }
    const bits = bitsFor(fingerprint, seen);
    for (const [id, ts] of entries) {
      if (hasSeen(bits, id)) continue;
      addSeen(bits, id);
      syncSeen(seen, bits);
      seen.occurrenceIds = [...seen.occurrenceIds, id].slice(-OCCURRENCE_CAP);
      seen.occurrenceTimes = [...seen.occurrenceTimes, ts].sort().slice(-OCCURRENCE_CAP);
      seen.lastTs = seen.occurrenceTimes[seen.occurrenceTimes.length - 1];
      seen.count = Math.max((seen.count ?? 1) + 1, seen.occurrenceIds.length);
      if (seen.id) bumped.set(seen.id, (bumped.get(seen.id) ?? 0) + 1);
    }
  }

  if (added.length) writeRules(rules, home);
  const migrated = stored.some((incident, at) => JSON.stringify(incident) !== JSON.stringify(rawStored[at] ?? {}));
  /* Attribution pass over the whole store, not just this run's rows: a heap death that carried no
   * plugin stack learns its plugin from a plugin crash minutes earlier. Rows already correlated are
   * left as they are, so repeated scans converge instead of re-labelling. */
  const persisted = readIncidents(home).map(normalizeOccurrence);
  const byId = new Map(persisted.map((incident) => [incident.id, incident]));
  /* Mutated rows may be freshly added in this run (not yet reflected in the file read above) or
   * already-stored rows; `known` holds the live object for both, so persist from there. */
  for (const incident of known.values()) {
    if (!incident?.id || !bumped.has(incident.id)) continue;
    byId.set(incident.id, incident);
  }
  const attributed = correlateIncidents([...byId.values()]);
  if (bumped.size || migrated || attributed.correlated) rewriteIncidents(attributed.incidents, home);
  writeState(state, home);
  const loops = crashLoops(attributed.incidents, { now: options.now ?? Date.now() });
  /* An OOM row can only say how loaded the machine was if a footprint was written before the death;
   * the watchdog writes one each tick, so quote the newest sample older than the row itself. */
  const oomEvidence = [];
  for (const incident of attributed.incidents) {
    if (incident.kind !== 'out-of-memory') continue;
    let evidence = null;
    try {
      evidence = footprintBefore(home, incident.lastTs ?? incident.ts);
    } catch {
      evidence = null;
    }
    oomEvidence.push({ signature: incident.signature, ts: incident.ts, evidence });
  }
  return {
    artifacts: artifacts.length,
    harvested,
    added,
    unknown,
    bumped: bumped.size,
    known: added.length - unknown.length,
    rules: rules.length,
    correlated: attributed.correlated,
    loops,
    oomEvidence,
  };
}

/* ------------------------------------------------------------------ render */

export const PROMPT_HEADER = '【DSH 守护】本机真实崩溃日志沉淀的硬约束，写插件/改配置时先遵守：';

export function renderLorePrompt(rules, options = {}) {
  const maxChars = options.maxChars ?? 1000;
  const limit = options.limit ?? 40;
  const ranked = rankRules(rules).slice(0, limit);
  if (!ranked.length) return '';
  const lines = [];
  let used = PROMPT_HEADER.length;
  for (const rule of ranked) {
    const line = `- ${rule.title}`;
    if (used + line.length + 1 > maxChars) break;
    lines.push(line);
    used += line.length + 1;
  }
  if (!lines.length) return '';
  const known = new Set(rules.filter((rule) => (rule.hits ?? 0) > 0).map((rule) => rule.id));
  const fresh = rules.filter((rule) => !known.has(rule.id)).length;
  const tail = `\n改插件/装插件前先用 lifeguard_check <源码目录> 预检，致命项清零再装${fresh ? '' : ''}；起不来用 lifeguard_heal。`;
  return `${PROMPT_HEADER}\n${lines.join('\n')}${tail}`;
}

/* ------------------------------------------------------------------ helpers */

export function summarizeIncident(incident) {
  const culprit = incident.culprit?.name ? ` @${incident.culprit.name}${incident.inferred ? '（关联归因）' : ''}` : '';
  return `${incident.kind}${culprit} · ${incident.signature}${incident.frame ? ` (${incident.frame})` : ''}`;
}

export function compactRules(rules, options = {}) {
  const limit = options.limit ?? 40;
  const query = String(options.query ?? '').toLowerCase();
  const filtered = query
    ? rules.filter((rule) => `${rule.id} ${rule.title} ${rule.cause} ${rule.fix} ${(rule.tags ?? []).join(' ')}`.toLowerCase().includes(query))
    : rules;
  return rankRules(filtered).slice(0, limit).map((rule) => ({ id: rule.id, title: rule.title, cause: rule.cause, fix: rule.fix, severity: rule.severity, hits: rule.hits ?? 0 }));
}
