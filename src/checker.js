// Checker pipeline: for each node, spawn a real proxy core (xray or sing-box) with
// a generated outbound config, then push HTTP traffic through it via a local SOCKS5
// judge. A node "works" only if real bytes came back through the tunnel.
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { httpProbeViaSocks } from './tester.js';
import { toXrayOutbound, toSingboxOutbound } from './builders.js';

export const TARGETS = [
  { host: 'www.gstatic.com', port: 80, path: '/generate_204', tls: false, label: 'gstatic/generate_204' },
  { host: 'www.google.com', port: 80, path: '/generate_204', tls: false, label: 'google/generate_204' },
];

export const GEO_PATH = '/json/?fields=status,message,country,countryCode,regionName,city,isp,query';

export function fmtMs(ms) {
  return ms >= 10000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.max(1, Math.round(ms))}ms`;
}

// Full xray / sing-box config for one node, fronted by a SOCKS5 "judge" inbound
// that the local test client dials through.
export function buildRunConfig(core, node, socksPort) {
  const outbound = core === 'xray' ? toXrayOutbound(node) : toSingboxOutbound(node);
  if (!outbound) return null;
  if (core === 'xray') {
    return {
      log: { loglevel: 'warning' },
      inbounds: [
        {
          tag: 'judge',
          port: socksPort,
          listen: '127.0.0.1',
          protocol: 'socks',
          settings: { auth: 'noauth', udp: false },
          sniffing: { enabled: false },
        },
      ],
      outbounds: [outbound, { protocol: 'freedom', tag: 'direct' }],
    };
  }
  return {
    log: { level: 'warn' },
    inbounds: [{ type: 'socks', tag: 'judge', listen: '127.0.0.1', listen_port: socksPort }],
    outbounds: [outbound],
  };
}

// Pick the right core(s) for a node. xray speaks vless/vmess/trojan/ss (+tcp/ws/...);
// sing-box additionally speaks hysteria2/tuic. Try order: native first.
export function coresForNode(node, requestedCores) {
  if (node.scheme === 'hysteria2' || node.scheme === 'hy2' || node.scheme === 'tuic') {
    return requestedCores.filter((c) => c === 'sing-box');
  }
  return requestedCores.slice();
}

// Run one node against one core. Resolves { ok, ms, via, geo, error }.
// geo is only populated when the node worked: it is looked up THROUGH the tunnel,
// so it reflects the proxy's real exit location, not the entry IP's.
export async function testWithCore(core, node, { binary, timeoutMs = 12000, geo = true } = {}) {
  const started = Date.now();
  const socksPort = await freePort();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'raysieve-run-'));
  const cfgPath = path.join(tmpDir, `${node.id}-${core}.json`);
  let child = null;
  try {
    const config = buildRunConfig(core, node, socksPort);
    if (!config) return { ok: false, ms: 0, via: null, geo: null, error: `no ${core} builder for ${node.scheme}` };
    fs.writeFileSync(cfgPath, JSON.stringify(config, null, 2));
    child = spawn(binary, ['run', '-c', cfgPath], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const grab = (d) => {
      output += String(d);
      if (output.length > 8000) output = output.slice(-8000);
    };
    child.stdout.on('data', grab);
    child.stderr.on('data', grab);
    await new Promise((r) => setTimeout(r, 350));
    if (child.exitCode !== null) {
      return { ok: false, ms: Date.now() - started, via: null, geo: null, error: `core exited: ${firstLine(output)}` };
    }
    let lastErr = null;
    for (const t of TARGETS) {
      try {
        await httpProbeViaSocks('127.0.0.1', socksPort, t.host, t.port, {
          path: t.path,
          tls: t.tls,
          timeoutMs,
        });
        const geoInfo = geo ? await lookupGeoViaSocks(socksPort, timeoutMs) : null;
        return { ok: true, ms: Date.now() - started, via: t.label, geo: geoInfo, error: null };
      } catch (e) {
        lastErr = e;
      }
    }
    return { ok: false, ms: Date.now() - started, via: null, geo: null, error: String(lastErr?.message || lastErr) };
  } finally {
    if (child && child.exitCode === null) {
      try { child.kill('SIGKILL'); } catch {}
    }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
}

// Grab a free loopback port for the core's inbound. Small TOCTOU window is fine.
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

function firstLine(s) {
  const lines = String(s || '').split(/\r?\n/).filter((l) => l.trim() && !/Xray \d|sing-box version|anti-censorship/i.test(l));
  return (lines[lines.length - 1] || 'no output').slice(0, 200);
}

// Fetch ip-api.com through the tunnel and parse the JSON body.
export async function lookupGeoViaSocks(socksPort, timeoutMs = 8000) {
  try {
    const res = await httpProbeViaSocks('127.0.0.1', socksPort, 'ip-api.com', 80, {
      path: GEO_PATH,
      tls: false,
      timeoutMs,
      minBytes: 60,
    });
    const bodyStart = res.body ? res.body : '';
    const j = JSON.parse(bodyStart);
    if (j && j.status === 'success') {
      return { country: j.country, countryCode: j.countryCode, region: j.regionName, city: j.city, isp: j.isp, ip: j.query };
    }
    return { error: j?.message || 'geo lookup failed' };
  } catch (e) {
    return { error: String(e?.message || e) };
  }
}
