// Output generation: raw txt, base64 subscription, sing-box client config, report.
import { toSingboxOutbound } from './builders.js';

// Build a ready-to-use sing-box client config from the working nodes.
export function buildSingboxConfig(working, { listenPort = 2080 } = {}) {
  const outbounds = [];
  const tags = [];
  working.forEach((entry, i) => {
    const ob = toSingboxOutbound(entry.node);
    if (!ob) return;
    ob.tag = `proxy-${i + 1}-${entry.node.scheme}`;
    outbounds.push(ob);
    tags.push(ob.tag);
  });
  if (outbounds.length === 0) return null;
  outbounds.push(
    { type: 'selector', tag: 'auto', outbounds: tags, default: tags[0] },
    { type: 'direct', tag: 'direct' }
  );
  return {
    log: { level: 'info', timestamp: true },
    inbounds: [{ type: 'socks', tag: 'socks-in', listen: '127.0.0.1', listen_port: listenPort }],
    outbounds,
    route: { final: 'auto', auto_detect_interface: true },
  };
}

export function buildPlainSubscription(renamed) {
  return renamed.map((e) => e.raw).join('\n') + '\n';
}

export function buildBase64Subscription(renamed) {
  return Buffer.from(buildPlainSubscription(renamed), 'utf8').toString('base64');
}

export function buildReport({ totals, working, skipped, dead, elapsedMs, noGeo }) {
  const L = [];
  const pct = totals.checkable ? Math.round((working.length / totals.checkable) * 100) : 0;
  L.push(`# raysieve report`);
  L.push('');
  L.push(`- input: **${totals.parsed}** parsed, **${totals.checkable}** checkable`);
  L.push(`- working: **${working.length}** (${pct}%)  |  dead: ${dead.length}  |  unsupported: ${skipped.length}`);
  L.push(`- elapsed: ${(elapsedMs / 1000).toFixed(1)}s`);
  L.push('');
  L.push('## Working nodes');
  if (working.length === 0) L.push('_(none)_');
  for (const w of working) {
    const geo =
      !noGeo && w.geo && !w.geo.error
        ? ` — ${w.geo.city || '?'}, ${w.geo.country || '?'} (${w.geo.isp || 'unknown isp'})`
        : '';
    L.push(`- ✅ **${w.name}** — ${w.node.scheme} · ${w.ms}ms${geo}`);
  }
  L.push('');
  L.push('## Dead nodes');
  if (dead.length === 0) L.push('_(none)_');
  for (const d of dead) {
    L.push(`- ❌ \`${d.node.host}:${d.node.port}\` — ${d.error}`);
  }
  L.push('');
  if (skipped.length > 0) {
    L.push('## Skipped (unsupported)');
    for (const s of skipped) {
      L.push(`- ⚠️ \`${s.line.slice(0, 90)}${s.line.length > 90 ? '…' : ''}\` — ${s.reason}`);
    }
    L.push('');
  }
  return L.join('\n');
}
