#!/usr/bin/env node
// Detects (and optionally fixes) exposure to the Node.js 2026-10-21 security release.
// Zero dependencies. Usage: node check.mjs [dir] [--fix] [--json] [--target-major N]
import fs from 'node:fs';
import path from 'node:path';

const PATCHED = { 22: '22.23.4', 24: '24.22.1', 26: '26.12.1' };
const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const opt = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const root = path.resolve(args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--target-major') || '.');
const FIX = flag('--fix');
const JSON_OUT = flag('--json');
const TARGET_MAJOR = opt('--target-major') ? Number(opt('--target-major')) : null;
if (TARGET_MAJOR && !PATCHED[TARGET_MAJOR]) { console.error(`--target-major must be one of ${Object.keys(PATCHED).join(', ')}`); process.exit(2); }

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', '.turbo', '.cache', 'vendor', '.claude', 'tmp', 'temp']);
// Plain directory names in the root .gitignore (`temp/`, `.docs`) are skipped too; globs and negations are ignored.
try {
  for (const l of fs.readFileSync(path.join(root, '.gitignore'), 'utf8').split('\n')) {
    const m = l.trim().match(/^\/?([A-Za-z0-9_.-]+)\/?$/);
    if (m) SKIP_DIRS.add(m[1]);
  }
} catch { /* no .gitignore */ }
const DOC_EXT = /\.(md|markdown|txt)$/i;
const findings = []; // {severity, file, line, kind, message, fixable, fixed, codeHit, runtime}
const add = (f) => findings.push(f);

const parse = (v) => {
  const m = String(v).trim().replace(/^v/, '').match(/^(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?/);
  if (!m) return null;
  const n = (x) => (x === undefined || x === 'x' || x === '*' ? null : Number(x));
  return { major: Number(m[1]), minor: n(m[2]), patch: n(m[3]) };
};
const cmp = (a, b) => (a.major - b.major) || ((a.minor ?? 0) - (b.minor ?? 0)) || ((a.patch ?? 0) - (b.patch ?? 0));
const patchedOf = (major) => (PATCHED[major] ? parse(PATCHED[major]) : null);

// status: 'ok' | 'vulnerable' | 'eol' | 'floating' | 'unknown'
function assess(version) {
  const v = parse(version);
  if (!v) return { status: 'unknown' };
  const p = patchedOf(v.major);
  if (!p) return { status: 'eol', v };
  if (v.minor === null || v.patch === null) return { status: 'floating', v };
  return { status: cmp(v, p) >= 0 ? 'ok' : 'vulnerable', v };
}
const targetFor = (major) => (TARGET_MAJOR ? PATCHED[TARGET_MAJOR] : PATCHED[major]);

function walk(dir, out = []) {
  let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(path.join(dir, e.name), out); }
    else out.push(path.join(dir, e.name));
  }
  return out;
}
const rel = (f) => path.relative(root, f) || path.basename(f);

function report(file, line, version, kind, rewrite) {
  const a = assess(version);
  if (a.status === 'ok' || a.status === 'unknown') return;
  const major = a.v.major;
  if (a.status === 'floating') {
    add({ severity: 'info', file: rel(file), line, kind, message: `floating version "${version}": fixed only after rebuild/refresh (run with --pull / clear cache)` });
    return;
  }
  if (a.status === 'eol' && !TARGET_MAJOR) {
    add({ severity: 'high', file: rel(file), line, kind, message: `Node ${version} is on an unsupported line with no fix; move to 24.x LTS (rerun with --fix --target-major 24)`, fixable: false });
    return;
  }
  const to = targetFor(major);
  const f = { severity: 'high', file: rel(file), line, kind, message: `Node ${version} is vulnerable; patched is ${to}`, fixable: !!rewrite, to };
  add(f);
  if (FIX && rewrite) { f.fixed = rewrite(to); }
}

// Replace the version at a given 1-based line in a file, using a regex with one capture group for the version.
function lineRewrite(file, lineNo, re) {
  return (to) => {
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    const before = lines[lineNo - 1];
    const after = before.replace(re, (m, ver) => m.replace(ver, to));
    if (after === before) return false;
    lines[lineNo - 1] = after;
    fs.writeFileSync(file, lines.join('\n'));
    return true;
  };
}

// ---------- 1. Running Node ----------
// Reported for the operator's benefit; it is not a project pin, so it never affects the exit code.
{
  const a = assess(process.version);
  if (a.status === 'vulnerable' || a.status === 'eol') {
    add({ severity: 'high', runtime: true, file: '(runtime)', kind: 'runtime', message: `Node running this check is ${process.version}; ${a.status === 'eol' ? 'unsupported line' : 'upgrade to ' + PATCHED[a.v.major]}. Use nvm/fnm/volta/n or your installer` });
  }
}

const files = walk(root);

// ---------- 2. Version pin files ----------
for (const file of files) {
  const base = path.basename(file);
  const text = (() => { try { return fs.readFileSync(file, 'utf8'); } catch { return null; } })();
  if (text === null || text.length > 2_000_000) continue;
  const lines = text.split('\n');

  if (base === '.nvmrc' || base === '.node-version') {
    const m = lines[0].trim().match(/^v?(\d+(?:\.\d+){0,2})\s*$/);
    if (m) report(file, 1, m[1], 'version-file', lineRewrite(file, 1, new RegExp(`v?(${m[1].replace(/\./g, '\\.')})`)));
    else if (/lts|latest|node|stable/i.test(lines[0])) add({ severity: 'info', file: rel(file), line: 1, kind: 'version-file', message: `floating alias "${lines[0].trim()}": make sure installed Node is >= patched` });
  }

  if (base === '.tool-versions') {
    lines.forEach((l, i) => { const m = l.match(/^\s*nodejs\s+(\d+(?:\.\d+){0,2})/); if (m) report(file, i + 1, m[1], 'tool-versions', lineRewrite(file, i + 1, /nodejs\s+(\d+(?:\.\d+){0,2})/)); });
  }

  if (base === 'package.json') {
    try {
      const pkg = JSON.parse(text);
      const volta = pkg.volta?.node;
      if (volta) {
        const i = lines.findIndex((l) => l.includes('"node"') && l.includes(volta));
        report(file, i + 1, volta, 'volta', i >= 0 ? lineRewrite(file, i + 1, new RegExp(`"node"\\s*:\\s*"(${volta.replace(/\./g, '\\.')})"`)) : null);
      }
      const eng = pkg.engines?.node;
      if (eng) {
        const m = String(eng).match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
        const lower = m ? parse(m[0]) : null;
        if (lower && /^[\s>=^~v\d.x*|]+$/.test(eng)) {
          const p = patchedOf(lower.major);
          if (!p || cmp(lower, p) < 0) add({ severity: 'info', file: rel(file), kind: 'engines', message: `engines.node "${eng}" still allows vulnerable versions; consider ">=${targetFor(lower.major) || PATCHED[24]}" (not auto-edited: it is a requirement, not the running version)` });
        }
      }
    } catch { /* ignore invalid json */ }
  }

  // Dockerfiles / compose / CI (a `dockerfile.md` reference doc is not a Dockerfile)
  const isDocker = /^(Dockerfile|.*\.Dockerfile|Dockerfile\..*)$/i.test(base) && !DOC_EXT.test(base);
  const isYaml = /\.(ya?ml)$/i.test(base);
  if (isDocker || isYaml) {
    lines.forEach((l, i) => {
      // image: node:22.10.0-alpine, FROM node:22.10.0, FROM --platform=x node:22 AS build, container: node:22
      const img = l.match(/(?:^\s*FROM\s+(?:--\S+\s+)?|(?:image|container):\s*['"]?)(?:docker\.io\/library\/|library\/)?node:v?(\d+(?:\.\d+){0,2}|lts|current|latest)/i);
      if (img) {
        if (/^(lts|current|latest)$/i.test(img[1])) add({ severity: 'info', file: rel(file), line: i + 1, kind: 'docker', message: `floating tag node:${img[1]}: rebuild with --pull to receive the fix` });
        else report(file, i + 1, img[1], 'docker', lineRewrite(file, i + 1, /node:v?(\d+(?:\.\d+){0,2})/i));
      }
      // GitHub Actions / generic: node-version: 22.10.0 or '22.x'
      const nv = l.match(/node-version:\s*['"]?v?(\d+(?:\.(?:\d+|x))*)['"]?/i);
      if (nv) report(file, i + 1, nv[1], 'ci', lineRewrite(file, i + 1, /node-version:\s*['"]?v?(\d+(?:\.\d+){0,2})/i));
      // node-version-file: is covered by the .nvmrc check
      // CircleCI orb / cimg images
      const cimg = l.match(/cimg\/node:(\d+(?:\.\d+){0,2})/i);
      if (cimg) report(file, i + 1, cimg[1], 'ci', lineRewrite(file, i + 1, /cimg\/node:(\d+(?:\.\d+){0,2})/i));
    });
  }
}

// ---------- 3. undici in lockfiles (npm, yarn v1/berry, pnpm) ----------
const LOCKS = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml']);
for (const file of files) {
  const base = path.basename(file);
  if (!LOCKS.has(base)) continue;
  let text; try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
  const seen = new Set();
  if (base === 'yarn.lock') {
    for (const m of text.matchAll(/^"?undici@[^\n]*:\n\s+version:?\s+"?(\d+\.\d+\.\d+)/gm)) seen.add(m[1]);
  } else if (base === 'pnpm-lock.yaml') {
    for (const m of text.matchAll(/^\s*\/?undici@(\d+\.\d+\.\d+)[:(]/gm)) seen.add(m[1]);
  } else {
    try {
      for (const [k, v] of Object.entries(JSON.parse(text).packages || {})) if (/(^|\/)node_modules\/undici$/.test(k) && v.version) seen.add(v.version);
    } catch { continue; }
  }
  if (seen.size) add({ severity: 'medium', file: rel(file), kind: 'undici', message: `undici ${[...seen].join(', ')} installed from npm. The release updated Undici; run "npm update undici" (or bump the dependent) and review undici advisories for the exact fixed version` });
}

// ---------- 4. Source scan ----------
const RISKY = [
  { id: 'brotli', sev: 'high', re: /\b(brotliDecompress(Sync)?|createBrotliDecompress|zlib\.brotli\w*|BrotliDecompress)\b|['"]br['"]\s*[,)\]]|accept-encoding[^\n]*\bbr\b/i, msg: 'Brotli decoding (CVE-2026-111497, RCE). Upgrade Node; cap input size meanwhile' },
  { id: 'dns', sev: 'medium', re: /\bdns(\.promises)?\.(resolve\w*|lookup)\s*\(/, msg: 'dns.resolve/lookup (CVE-2026-105482). Reject hostnames containing "\\0" if input is untrusted' },
  { id: 'tls', sev: 'medium', re: /\b(tls\.connect|checkServerIdentity|tls\.checkServerIdentity)\b/, msg: 'TLS hostname verification (CVE-2026-105483/106069/106072). Validate host is canonical ASCII hostname or IP' },
  { id: 'tls-off', sev: 'high', re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/, msg: 'TLS verification disabled: makes hostname bugs moot but is unsafe; remove it' },
  { id: 'keepalive', sev: 'low', re: /keepAlive\s*:\s*true/, msg: 'keep-alive agent (CVE-2026-105481). Fixed by upgrading Node' },
  { id: 'snapshot', sev: 'medium', re: /--build-snapshot|\bsea-config\.json\b|\bnode:sea\b|"useSnapshot"\s*:\s*true/, msg: 'Snapshot/SEA build (CVE-2026-106074): randomUUID/randomInt may repeat; do not call them at build time' },
  { id: 'permission', sev: 'low', re: /--permission\b|--allow-fs-(read|write)|process\.permission|realpathSync/, msg: 'Permission Model / realpathSync (CVE-2026-106071/106073). Avoid wildcards; do not use realpathSync as the only containment check' },
];
const SRC = /\.(c|m)?(j|t)sx?$|\.json$|\.sh$|Dockerfile.*$|\.ya?ml$/i;
for (const file of files) {
  const base = path.basename(file);
  if (DOC_EXT.test(base)) continue;
  if (!SRC.test(file) && !/Dockerfile/i.test(base)) continue;
  if (/^(package-lock|npm-shrinkwrap|pnpm-lock|yarn\.lock|tsconfig.*)\.?/.test(base) && base !== 'sea-config.json') continue;
  let text; try { const st = fs.statSync(file); if (st.size > 1_000_000) continue; text = fs.readFileSync(file, 'utf8'); } catch { continue; }
  if (/\.d\.ts$/.test(file)) continue;
  text.split('\n').forEach((l, i) => {
    for (const r of RISKY) {
      if (r.re.test(l)) {
        add({ severity: r.sev, file: rel(file), line: i + 1, kind: `code:${r.id}`, message: r.msg, codeHit: true });
      }
    }
  });
}

// ---------- Output ----------
const versionIssues = findings.filter((f) => !f.codeHit && !f.runtime && f.severity === 'high');
const unresolved = versionIssues.filter((f) => !f.fixed);
const summary = {
  patched: PATCHED,
  scanned: root,
  versionIssues: versionIssues.length,
  fixed: findings.filter((f) => f.fixed).length,
  unresolved: unresolved.length,
  codeHits: findings.filter((f) => f.codeHit).length,
};

if (JSON_OUT) {
  console.log(JSON.stringify({ summary, findings }, null, 2));
} else {
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
  const versionPart = sorted.filter((f) => !f.codeHit);
  const codePart = sorted.filter((f) => f.codeHit);
  console.log(`Node.js 2026-10-21 security check: ${root}`);
  console.log(`Patched versions: ${Object.values(PATCHED).join(', ')}\n`);
  console.log('== Version pins ==');
  if (!versionPart.length) console.log('  none found / all OK');
  for (const f of versionPart) {
    const tag = f.fixed ? 'FIXED' : f.runtime ? 'RUNTIME' : f.severity.toUpperCase();
    console.log(`  [${tag}] ${f.file}${f.line ? ':' + f.line : ''}  ${f.message}${f.fixed ? ` -> ${f.to}` : ''}`);
  }
  console.log('\n== Code using affected APIs (review, upgrade is the real fix) ==');
  if (!codePart.length) console.log('  none');
  for (const f of codePart) console.log(`  [${f.severity.toUpperCase()}] ${f.file}:${f.line}  ${f.message}`);
  console.log(`\nSummary: ${summary.versionIssues} vulnerable pin(s), ${summary.fixed} fixed, ${summary.unresolved} unresolved, ${summary.codeHits} code hit(s).`);
  if (unresolved.length) console.log('Unresolved items need a manual runtime upgrade or an explicit --target-major.');
}
process.exit(unresolved.length ? 1 : 0);
