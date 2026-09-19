// Load configs from files/dirs/URLs/stdin; detect raw / plain-sub / base64-sub format; dedupe.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const HTTP_URL_RE = /^https?:\/\/\S+$/i;

export function isHttpUrl(s) {
  return HTTP_URL_RE.test(String(s || '').trim());
}

// Schemes we recognize. ssr/socks/https/juicity/wireguard are accepted but currently
// pass through as "unsupported" entries so the report shows why they were skipped.
export const URI_SCHEME_RE =
  /^(vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic|socks|https?|juicity|wireguard):\/\//i;

export const CHECKABLE_SCHEMES = new Set(['vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'hy2', 'tuic']);

export function schemeOf(line) {
  const m = String(line || '').trim().match(URI_SCHEME_RE);
  return m ? m[1].toLowerCase() : null;
}

export function isConfigLine(line) {
  return URI_SCHEME_RE.test(String(line || '').trim());
}

export function collectInputFiles(inputs) {
  const files = [];
  for (const input of inputs || []) {
    if (input === '-') continue;
    if (isHttpUrl(input)) continue; // handled separately (fetched, not read from disk)
    let st;
    try {
      st = fs.statSync(input);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      for (const name of fs.readdirSync(input)) {
        if (!/\.(txt|conf|list|log|text)$/i.test(name)) continue;
        const full = path.join(input, name);
        let s2;
        try {
          s2 = fs.statSync(full);
        } catch {
          continue;
        }
        if (s2.isFile()) files.push(full);
      }
      continue;
    }
    files.push(input);
  }
  return files;
}

export function readStdin() {
  try {
    return fs.readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

// Fetch a remote list over HTTP(S). Follows redirects; enforces a size cap so a
// giant/hungry URL can't OOM the process; returns '' on failure (caller warns).
export async function fetchRemoteText(url, { timeoutMs = 20000, maxBytes = 20 * 1024 * 1024 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { redirect: 'follow', signal: controller.signal });
    if (!resp.ok) throw new Error(`HTTP ${resp.status} for ${url}`);
    const len = Number(resp.headers.get('content-length') || 0);
    if (len > maxBytes) throw new Error(`response too large (${len} bytes) from ${url}`);
    const text = await resp.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
      throw new Error(`response too large from ${url}`);
    }
    return text;
  } finally {
    clearTimeout(timer);
  }
}

function tryDecodeBase64(text) {
  const compact = String(text || '').replace(/\s+/g, '');
  if (!compact || !/^[A-Za-z0-9+/=_-]+$/.test(compact)) return null;
  let out = '';
  try {
    out = Buffer.from(compact.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  } catch {
    return null;
  }
  if (out && isConfigLine(out)) return out;
  return null;
}

function decodeIfBase64Sub(text) {
  const trimmed = String(text || '').trim();
  if (!trimmed || /\s/.test(trimmed)) return null;
  if (!/^[A-Za-z0-9+/=_-]+$/.test(trimmed)) return null;
  let out = '';
  try {
    out = Buffer.from(trimmed.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  } catch {
    return null;
  }
  if (!out) return null;
  let lines = out.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  let cfgs = lines.filter(isConfigLine);
  if (cfgs.length === 0) {
    const once = tryDecodeBase64(out);
    if (once) {
      lines = once.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      cfgs = lines.filter(isConfigLine);
    }
  }
  return cfgs;
}

function pushLine(line, configs, skipped, seen) {
  const key = crypto.createHash('sha256').update(line).digest('hex').slice(0, 16);
  if (seen.has(key)) return;
  seen.add(key);
  const scheme = schemeOf(line);
  if (CHECKABLE_SCHEMES.has(scheme)) configs.push(line);
  else skipped.push({ line, reason: `unsupported scheme: ${scheme || 'unknown'}` });
}

export function loadConfigs(inputs, { stdinText } = {}) {
  const lines = [];
  for (const file of collectInputFiles(inputs)) {
    let text = '';
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    lines.push(...text.split(/\r?\n/));
  }
  if (stdinText) lines.push(...stdinText.split(/\r?\n/));

  const seen = new Set();
  const configs = [];
  const skipped = [];

  for (const rawLine of lines) {
    const line = String(rawLine || '').trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    if (isConfigLine(line)) {
      pushLine(line, configs, skipped, seen);
      continue;
    }
    const decoded = decodeIfBase64Sub(line);
    if (decoded && decoded.length > 0) {
      for (const cfg of decoded) pushLine(cfg, configs, skipped, seen);
    }
  }

  return { configs, skipped };
}

// Async wrapper: any input that looks like an http(s) URL is fetched first and its
// body merged with stdin text. Local files/dirs pass through untouched.
export async function loadConfigsAsync(inputs, { stdinText } = {}) {
  const urls = [];
  const locals = [];
  for (const input of inputs || []) {
    if (input === '-') continue;
    if (isHttpUrl(input)) urls.push(input);
    else locals.push(input);
  }
  const remoteTexts = await Promise.all(
    urls.map(async (u) => {
      try {
        return await fetchRemoteText(u);
      } catch (e) {
        process.stderr.write(`raysieve: WARNING could not fetch ${u}: ${e.message}\n`);
        return '';
      }
    })
  );
  const merged = [...remoteTexts, stdinText || ''].filter(Boolean).join('\n');
  return loadConfigs(locals, { stdinText: merged || undefined });
}
