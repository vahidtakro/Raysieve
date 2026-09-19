// Parse proxy share-URIs (vless/vmess/trojan/ss/hysteria2/hy2/tuic) into a normalized
// node object. The node object is scheme-agnostic so the outbound builders don't care
// where the config came from.
import crypto from 'node:crypto';
import { schemeOf } from './config-load.js';

function b64decode(s) {
  try {
    return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  } catch {
    return null;
  }
}

function safeDecode(s) {
  try {
    return decodeURIComponent(String(s));
  } catch {
    return String(s);
  }
}

function truthy(v) {
  if (v === undefined || v === null) return false;
  const s = String(v).trim().toLowerCase();
  return !(s === '' || s === '0' || s === 'false' || s === 'none' || s === 'null');
}

function q(query) {
  const p = new URLSearchParams(query || '');
  const obj = {};
  for (const [k, v] of p) obj[k.toLowerCase()] = v;
  return obj;
}

// Split userinfo@host:port while tolerating the many malformed share-links in the wild.
function hostport(raw) {
  const m = String(raw).match(/^(?:\[([^\]]+)\]|([^:@]+)):([0-9]+)$/);
  if (!m) return { host: raw, port: NaN };
  return { host: m[1] || m[2], port: Number(m[3]) };
}

function baseNode(scheme, uri) {
  const schemeLower = scheme.toLowerCase();
  const withoutScheme = uri.slice(scheme.length);
  const hashIdx = withoutScheme.indexOf('#');
  const name = hashIdx >= 0 ? safeDecode(withoutScheme.slice(hashIdx + 1)).trim() : '';
  const body = hashIdx >= 0 ? withoutScheme.slice(0, hashIdx) : withoutScheme;
  const qIdx = body.indexOf('?');
  const main = qIdx >= 0 ? body.slice(0, qIdx) : body;
  const query = q(qIdx >= 0 ? body.slice(qIdx + 1) : '');
  return {
    id: crypto.createHash('sha256').update(uri).digest('hex').slice(0, 16),
    scheme: schemeLower,
    name,
    raw: uri,
    query,
    _main: main,
  };
}

function parseVlessTrojan(uri, scheme) {
  const node = baseNode(scheme, uri);
  // vless://uuid@host:port?...#name   |   trojan://password@host:port?...#name
  const m = node._main.match(/^:\/\/([^@]*)@(.+)$/);
  if (!m) return null;
  node.credential = safeDecode(m[1] || '');
  const hp = hostport(m[2]);
  node.host = hp.host;
  node.port = hp.port;
  const Q = node.query;
  node.security = (Q.security || '').toLowerCase();
  node.network = (Q.type || 'tcp').toLowerCase();
  node.sni = Q.sni || '';
  node.hostHeader = Q.host || '';
  node.path = Q.path ? safeDecode(Q.path) : '';
  node.alpn = Q.alpn || '';
  node.fp = Q.fp || '';
  node.flow = Q.flow || '';
  node.allowInsecure = truthy(Q.allowinsecure || Q.allow_insecure);
  node.packetEncoding = Q['packet-encoding'] || Q.packetencoding || '';
  if (scheme === 'trojan' && !node.security) node.security = 'tls'; // trojan implies TLS
  return node;
}

function parseVmess(uri) {
  const node = baseNode('vmess', uri);
  // Official style: vmess://base64(json). Some aggregators emit vmess://uuid@host:port?... too.
  const payload = uri.slice('vmess://'.length);
  const decoded = b64decode(payload);
  if (decoded) {
    try {
      const j = JSON.parse(decoded);
      node.credential = j.id || '';
      node.host = j.add || j.address || '';
      node.port = Number(j.port);
      node.name = String(j.ps || j.remarks || node.name || '').trim();
      node.security = truthy(j.tls) ? 'tls' : 'none';
      node.sni = j.sni || j.peer || j['Host'] || '';
      node.hostHeader = j.host || j['Host'] || '';
      node.network = (j.net || 'tcp').toLowerCase();
      node.path = j.path || '';
      node.alpn = j.alpn || '';
      node.fp = j.fp || '';
      node.encryption = 'auto';
      node.scy = j.scy || 'auto';
      node._main = null;
      return node;
    } catch {
      /* fall through to URI-style */
    }
  }
  const m = node._main.match(/^:\/\/([^@]*)@(.+)$/);
  if (!m) return null;
  node.credential = safeDecode(m[1] || '');
  const hp = hostport(m[2]);
  node.host = hp.host;
  node.port = hp.port;
  const Q = node.query;
  node.security = (Q.security || '').toLowerCase();
  node.network = (Q.type || 'tcp').toLowerCase();
  node.sni = Q.sni || '';
  node.hostHeader = Q.host || '';
  node.path = Q.path ? safeDecode(Q.path) : '';
  node.alpn = Q.alpn || '';
  node.fp = Q.fp || '';
  node.allowInsecure = truthy(Q.allowinsecure || Q.allow_insecure);
  node.encryption = 'auto';
  return node;
}

function parseShadowsocks(uri) {
  const node = baseNode('ss', uri);
  // Two common layouts:
  //  ss://base64(method:pass)@host:port#name   (SIP002)
  //  ss://base64(method:pass@host:port)#name   (legacy)
  let rest = uri.slice('ss://'.length);
  const hashIdx = rest.indexOf('#');
  if (hashIdx >= 0) rest = rest.slice(0, hashIdx);
  const qIdx = rest.indexOf('?');
  const query = q(qIdx >= 0 ? rest.slice(qIdx + 1) : '');
  if (qIdx >= 0) rest = rest.slice(0, qIdx);

  let method, password, host, port;
  if (rest.includes('@')) {
    const at = rest.lastIndexOf('@');
    const userInfo = rest.slice(0, at);
    const serverPart = rest.slice(at + 1);
    const decodedUser = b64decode(userInfo) || decodeURIComponent(userInfo);
    const cm = String(decodedUser).match(/^([^:]+):(.*)$/);
    if (!cm) return null;
    method = cm[1];
    password = cm[2];
    const hp = hostport(serverPart);
    host = hp.host;
    port = hp.port;
  } else {
    const decoded = b64decode(rest);
    if (!decoded) return null;
    const dm = decoded.match(/^([^:@]+):(.*)@(.+):([0-9]+)$/);
    if (!dm) return null;
    method = dm[1];
    password = dm[2];
    host = dm[3];
    port = Number(dm[4]);
  }
  node.method = method;
  node.credential = password;
  node.host = host;
  node.port = port;
  node.plugin = query.plugin ? safeDecode(query.plugin) : '';
  return node;
}

function parseHysteria2(uri) {
  const node = baseNode('hysteria2', uri);
  // hysteria2://auth@host:port?sni=...&insecure=1#name  (host may be host:port,port for port-hopping)
  const m = node._main.match(/^:\/\/([^@]*)@(.+)$/);
  if (!m) return null;
  node.credential = safeDecode(m[1] || '');
  const hp = hostport(m[2]);
  node.host = hp.host;
  node.port = hp.port;
  const Q = node.query;
  node.security = 'tls'; // hysteria2 is always TLS-based
  node.sni = Q.sni || '';
  node.allowInsecure = truthy(Q.insecure || Q.allowinsecure);
  node.obfs = Q.obfs || '';
  node.obfsPassword = Q['obfs-password'] || Q.obfspassword || '';
  node.alpn = Q.alpn || 'h3';
  return node;
}

function parseTuic(uri) {
  const node = baseNode('tuic', uri);
  // tuic://uuid:password@host:port?...#name
  const m = node._main.match(/^:\/\/([^@]*)@(.+)$/);
  if (!m) return null;
  const cred = safeDecode(m[1] || '');
  const ci = cred.indexOf(':');
  node.uuid = ci >= 0 ? cred.slice(0, ci) : cred;
  node.credential = ci >= 0 ? cred.slice(ci + 1) : '';
  const hp = hostport(m[2]);
  node.host = hp.host;
  node.port = hp.port;
  const Q = node.query;
  node.security = 'tls';
  node.sni = Q.sni || '';
  node.allowInsecure = truthy(Q.insecure || Q.allowinsecure || Q.allow_insecure);
  node.alpn = Q.alpn || 'h3';
  node.udpRelayMode = Q.udp_relay_mode || '';
  node.congestionControl = Q.congestion_control || '';
  return node;
}

export function parseConfig(uri) {
  const scheme = schemeOf(uri);
  if (!scheme) return null;
  switch (scheme) {
    case 'vless':
    case 'trojan':
      return parseVlessTrojan(uri, scheme);
    case 'vmess':
      return parseVmess(uri);
    case 'ss':
      return parseShadowsocks(uri);
    case 'hysteria2':
    case 'hy2':
      return parseHysteria2(uri);
    case 'tuic':
      return parseTuic(uri);
    default:
      return null;
  }
}

export function validateNode(node) {
  if (!node) return 'parse failed';
  if (!node.host) return 'missing host';
  if (!Number.isFinite(node.port) || node.port <= 0 || node.port > 65535) return 'invalid port';
  if ((node.scheme === 'vless' || node.scheme === 'vmess' || node.scheme === 'tuic') && !node.credential && !node.uuid) {
    return 'missing credential';
  }
  if (node.scheme === 'ss' && !node.method) return 'missing method';
  return null;
}

// Rewrite the URI's #fragment with a new display name. For base64-payload vmess
// links we re-encode the JSON so the new tag survives what clients read.
export function renameUri(node, newName) {
  if (node.scheme === 'vmess' && node._main === null) {
    try {
      const j = JSON.parse(Buffer.from(node.raw.slice('vmess://'.length), 'base64').toString('utf8'));
      j.ps = newName;
      const json = JSON.stringify(j);
      return 'vmess://' + Buffer.from(json, 'utf8').toString('base64');
    } catch {
      /* fall through to fragment rewrite */
    }
  }
  const body = node.raw.slice(0, node.raw.indexOf('#') === -1 ? node.raw.length : node.raw.indexOf('#'));
  return `${body}#${encodeURIComponent(newName)}`;
}
