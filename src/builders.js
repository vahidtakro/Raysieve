// Build real outbound objects for xray-core and sing-box from a parsed node.
// The tester spins up the actual cores with these configs, so "works" means the
// protocol/transport/params were really accepted, not just that the port is open.
import crypto from 'node:crypto';

function streamSettings(node) {
  const ss = { network: node.network || 'tcp' };
  if (node.network === 'ws') {
    ss.wsSettings = {
      path: node.path || '/',
      headers: node.hostHeader ? { Host: node.hostHeader } : {},
    };
  } else if (node.network === 'grpc') {
    ss.grpcSettings = { serviceName: (node.path || '').replace(/^\//, '') };
  } else if (node.network === 'httpupgrade') {
    ss.httpupgradeSettings = { path: node.path || '/', host: node.hostHeader || '' };
  } else if (node.network === 'http' || node.network === 'h2') {
    ss.network = 'http';
    ss.httpSettings = { path: node.path || '/', host: node.hostHeader ? [node.hostHeader] : [] };
  }
  if (node.security === 'tls' || node.security === 'reality') {
    ss.security = 'tls';
    // NOTE: modern xray removed allowInsecure (migrated to pinnedPeerCertSha256),
    // so we simply never emit it — configs with valid certs test fine, which is
    // the honest behavior anyway.
    const tls = {
      alpn: node.alpn ? node.alpn.split(',').map((s) => s.trim()).filter(Boolean) : undefined,
    };
    if (node.sni) tls.serverName = node.sni;
    else if (node.hostHeader) tls.serverName = node.hostHeader;
    if (node.fp) tls.fingerprint = node.fp;
    ss.tlsSettings = tls;
  } else if (node.security === 'xtls' || node.flow) {
    ss.security = 'tls';
    ss.tlsSettings = { ...(node.sni ? { serverName: node.sni } : {}) };
  }
  return ss;
}

export function toXrayOutbound(node) {
  const tag = 'proxy';
  const sendThrough = undefined;
  switch (node.scheme) {
    case 'vless':
      return {
        tag,
        protocol: 'vless',
        settings: {
          vnext: [
            {
              address: node.host,
              port: node.port,
              users: [
                {
                  id: node.credential,
                  encryption: 'none',
                  ...(node.flow ? { flow: node.flow } : {}),
                },
              ],
            },
          ],
        },
        streamSettings: streamSettings(node),
      };
    case 'vmess':
      return {
        tag,
        protocol: 'vmess',
        settings: {
          vnext: [
            {
              address: node.host,
              port: node.port,
              users: [{ id: node.credential, security: node.scy || 'auto', level: 0 }],
            },
          ],
        },
        streamSettings: streamSettings(node),
      };
    case 'trojan':
      return {
        tag,
        protocol: 'trojan',
        settings: { servers: [{ address: node.host, port: node.port, password: node.credential }] },
        streamSettings: streamSettings(node),
      };
    case 'ss':
      return {
        tag,
        protocol: 'shadowsocks',
        settings: { servers: [{ address: node.host, port: node.port, method: node.method, password: node.credential }] },
      };
    default:
      return null;
  }
}

function tlsBlock(node) {
  const t = { enabled: true, insecure: !!node.allowInsecure };
  if (node.sni) t.server_name = node.sni;
  else if (node.hostHeader) t.server_name = node.hostHeader;
  if (node.alpn) t.alpn = node.alpn.split(',').map((s) => s.trim()).filter(Boolean);
  return t;
}

function transportBlock(node) {
  switch (node.network) {
    case 'ws':
      return {
        type: 'ws',
        path: node.path || '/',
        ...(node.hostHeader ? { headers: { Host: node.hostHeader } } : {}),
        ...(node.path && /\bed=|\bEED=/i.test(node.path) ? { early_data_header_name: 'Sec-WebSocket-Protocol' } : {}),
      };
    case 'grpc':
      return { type: 'grpc', service_name: (node.path || '').replace(/^\//, '') };
    case 'httpupgrade':
      return { type: 'httpupgrade', path: node.path || '/', ...(node.hostHeader ? { host: node.hostHeader } : {}) };
    case 'http':
    case 'h2':
      return { type: 'http', path: node.path || '/', ...(node.hostHeader ? { host: [node.hostHeader] } : {}) };
    default:
      return undefined;
  }
}

export function toSingboxOutbound(node) {
  const tag = 'proxy';
  switch (node.scheme) {
    case 'vless':
      return {
        tag,
        type: 'vless',
        server: node.host,
        server_port: node.port,
        uuid: node.credential,
        flow: node.flow || '',
        packet_encoding: node.packetEncoding || 'xudp',
        ...(node.security === 'tls' || node.security === 'reality' ? { tls: tlsBlock(node) } : {}),
        ...(node.network !== 'tcp' ? { transport: transportBlock(node) } : {}),
      };
    case 'vmess':
      return {
        tag,
        type: 'vmess',
        server: node.host,
        server_port: node.port,
        uuid: node.credential,
        security: node.scy || 'auto',
        alter_id: 0,
        ...(node.security === 'tls' ? { tls: tlsBlock(node) } : {}),
        ...(node.network !== 'tcp' ? { transport: transportBlock(node) } : {}),
      };
    case 'trojan':
      return {
        tag,
        type: 'trojan',
        server: node.host,
        server_port: node.port,
        password: node.credential,
        tls: tlsBlock(node),
        ...(node.network !== 'tcp' ? { transport: transportBlock(node) } : {}),
      };
    case 'ss':
      return {
        tag,
        type: 'shadowsocks',
        server: node.host,
        server_port: node.port,
        method: node.method,
        password: node.credential,
      };
    case 'hysteria2':
      return {
        tag,
        type: 'hysteria2',
        server: node.host,
        server_port: node.port,
        password: node.credential,
        tls: tlsBlock(node),
        ...(node.obfs ? { obfs: { type: node.obfs, password: node.obfsPassword } } : {}),
      };
    case 'tuic':
      return {
        tag,
        type: 'tuic',
        server: node.host,
        server_port: node.port,
        uuid: node.uuid || node.credential,
        password: node.uuid ? node.credential : '',
        congestion_control: node.congestionControl || 'bbr',
        udp_relay_mode: node.udpRelayMode || 'native',
        tls: tlsBlock(node),
      };
    default:
      return null;
  }
}

export function builderTag(node, core) {
  return crypto.randomUUID().slice(0, 8) + '-' + core;
}
