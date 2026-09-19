// Download and unpack xray-core and sing-box release binaries without external tools.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import zlib from 'node:zlib';

const RELEASES = {
  xray: {
    repo: 'XTLS/Xray-core',
    asset: (p) => {
      const plat = p.os === 'linux' ? 'linux' : p.os === 'darwin' ? 'macos' : 'windows';
      const arch = p.arch === 'x64' ? '64' : p.arch === 'arm64' ? 'arm64-v8a' : '32';
      return `Xray-${plat}-${arch}.zip`;
    },
    pickBinary: 'xray',
  },
  'sing-box': {
    repo: 'SagerNet/sing-box',
    versioned: true, // assets embed the version, so resolve the latest tag first
    asset: (p, version) => {
      const plat = p.os === 'linux' ? 'linux' : p.os === 'darwin' ? 'darwin' : 'windows';
      const arch = p.arch === 'x64' ? 'amd64' : p.arch === 'arm64' ? 'arm64' : '386';
      const ext = p.os === 'win32' || p.os === 'windows' ? 'zip' : 'tar.gz';
      return `sing-box-${version}-${plat}-${arch}.${ext}`;
    },
    pickBinary: 'sing-box',
  },
};

export function binariesDir() {
  // Stable cache dir so re-runs skip the download. Kept outside the repo.
  // Override with RAYSIEVE_BIN_DIR (used by the Dockerfile to bake cores in).
  return process.env.RAYSIEVE_BIN_DIR || path.join(os.tmpdir(), 'raysieve-bin');
}

export function managedPath(core, binDir) {
  return path.join(binDir || binariesDir(), core);
}

export function isExecutable(p) {
  try {
    fs.accessSync(p, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function systemPathLookup(core) {
  try {
    execFileSync('which', [core], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

export async function ensureCore(core, { binDir } = {}) {
  if (systemPathLookup(core)) return { path: core, source: 'system' };
  const exeSuffix = process.platform === 'win32' ? '.exe' : '';
  const target = managedPath(core, binDir) + exeSuffix;
  if (isExecutable(target)) return { path: target, source: 'managed' };
  return downloadCore(core, { binDir });
}

export async function downloadCore(core, { binDir } = {}) {
  const meta = RELEASES[core];
  if (!meta) throw new Error(`unknown core: ${core}`);
  const dir = binDir || binariesDir();
  fs.mkdirSync(dir, { recursive: true });
  const plat = { os: process.platform, arch: os.arch() };
  let tag = null;
  if (meta.versioned) {
    const tagPath = path.join(dir, `.${core}-tag.json`);
    try {
      tag = JSON.parse(fs.readFileSync(tagPath, 'utf8')).tag;
    } catch {}
    if (!tag) {
      const api = await fetch(`https://api.github.com/repos/${meta.repo}/releases/latest`);
      if (!api.ok) throw new Error(`cannot resolve latest version of ${core} (github api ${api.status})`);
      tag = JSON.parse(await api.text()).tag_name;
      fs.writeFileSync(tagPath, JSON.stringify({ tag, fetchedAt: new Date().toISOString() }));
    }
  }
  const assetName = meta.asset(plat, String(tag || '').replace(/^v/, ''));
  let url;
  if (meta.versioned) {
    url = `https://github.com/${meta.repo}/releases/download/${tag}/${assetName}`;
  } else {
    url = `https://github.com/${meta.repo}/releases/latest/download/${assetName}`;
  }
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'raysieve-dl-'));
  const archivePath = path.join(tmpDir, assetName);
  process.stderr.write(`[raysieve] downloading ${core} (${assetName})...\n`);
  const resp = await fetch(url, { redirect: 'follow' });
  if (!resp.ok) throw new Error(`download failed ${resp.status} for ${url}`);
  const buf = Buffer.from(await resp.arrayBuffer());
  fs.writeFileSync(archivePath, buf);
  if (assetName.endsWith('.zip')) {
    unzipBuffer(buf, dir);
  } else if (assetName.endsWith('.tar.gz')) {
    tarGzExtract(buf, dir);
  } else {
    throw new Error(`unsupported archive format: ${assetName}`);
  }
  const exeSuffix = process.platform === 'win32' ? '.exe' : '';
  const binaryPath = findBinary(dir, meta.pickBinary + exeSuffix) || findBinary(dir, meta.pickBinary);
  if (!binaryPath) throw new Error(`binary ${meta.pickBinary} not found after extracting ${assetName}`);
  fs.chmodSync(binaryPath, 0o755);
  const managed = managedPath(core, dir) + exeSuffix;
  if (binaryPath !== managed) fs.renameSync(binaryPath, managed);
  fs.rmSync(tmpDir, { recursive: true, force: true });
  return { path: managed, source: 'downloaded' };
}

function findBinary(dir, name) {
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      const full = path.join(cur, ent.name);
      if (ent.isDirectory()) stack.push(full);
      else if (ent.name === name) return full;
    }
  }
  return null;
}

// Minimal ZIP reader: stored (method 0) and deflate (method 8) entries, no deps.
function unzipBuffer(buf, dir) {
  // Locate End Of Central Directory record (scan backwards for PK\x05\x06).
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0 && i > buf.length - 65558; i--) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x05 && buf[i + 3] === 0x06) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('zip: end of central directory not found');
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) throw new Error('zip: bad central directory entry');
    const method = buf.readUInt16LE(off + 10);
    const compSize = buf.readUInt32LE(off + 20);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const lho = buf.readUInt32LE(off + 42); // local header offset
    const name = buf.subarray(off + 46, off + 46 + nameLen).toString('utf8');
    off += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith('/')) continue;
    // Walk the local header to find where data starts.
    const lNameLen = buf.readUInt16LE(lho + 26);
    const lExtraLen = buf.readUInt16LE(lho + 28);
    const dataStart = lho + 30 + lNameLen + lExtraLen;
    const comp = buf.subarray(dataStart, dataStart + compSize);
    const data = method === 0 ? comp : zlib.inflateRawSync(comp);
    const out = path.join(dir, name);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, data);
    if (/[^/]$/.test(name) && /^(xray|sing-box|geoip|geosite)/.test(path.basename(name))) {
      try { fs.chmodSync(out, 0o755); } catch {}
    }
  }
}

// Minimal tar.gz reader: gunzip in memory, walk 512-byte ustar headers.
function tarGzExtract(buf, dir) {
  const tarBuf = zlib.gunzipSync(buf);
  let off = 0;
  while (off + 512 <= tarBuf.length) {
    const header = tarBuf.subarray(off, off + 512);
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '').trim();
    if (!name) break; // two zero blocks mark end of archive
    const size = parseInt(header.subarray(124, 136).toString('ascii').replace(/[\0 ]/g, ''), 8) || 0;
    const typeflag = String.fromCharCode(header[156] || 0x30);
    off += 512;
    const isFile = typeflag === '0' || typeflag === '\0';
    if (isFile && size > 0) {
      const data = tarBuf.subarray(off, off + size);
      const out = path.join(dir, name);
      fs.mkdirSync(path.dirname(out), { recursive: true });
      fs.writeFileSync(out, data);
      if (/^(xray|sing-box|mihomo)$/.test(path.basename(name))) {
        try { fs.chmodSync(out, 0o755); } catch {}
      }
    }
    off += Math.ceil(size / 512) * 512; // data blocks are padded to 512
  }
}
