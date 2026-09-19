import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseConfig, validateNode, renameUri } from '../src/parse.js';

test('parses vless ws with host header and encoded path', () => {
  const n = parseConfig(
    'vless://5a0028f9-c656-cec9-4b61-54678477a408@188.114.97.6:8080?security=none&type=ws&path=%2Fgame&host=green-credit-7e7b.vpnfreev2rayconfig-sale1.workers.dev&packetEncoding=xudp&encryption=none#[OpenRay] CA-29537'
  );
  assert.equal(n.scheme, 'vless');
  assert.equal(n.credential, '5a0028f9-c656-cec9-4b61-54678477a408');
  assert.equal(n.host, '188.114.97.6');
  assert.equal(n.port, 8080);
  assert.equal(n.network, 'ws');
  assert.equal(n.path, '/game');
  assert.equal(n.hostHeader, 'green-credit-7e7b.vpnfreev2rayconfig-sale1.workers.dev');
  assert.equal(n.security, 'none');
  assert.match(n.name, /CA-29537/);
});

test('parses vless with empty security param and garbage fp without throwing', () => {
  const n = parseConfig('vless://812b1aeb-c6f7-43cb-8d8b-981711fea21a@104.17.191.15:8880?path=/pyip&security=&encryption=none&host=dark-cake-4743.198-46c.workers.dev&type=ws#x');
  assert.equal(n.security, '');
  assert.equal(n.network, 'ws');
  assert.equal(n.path, '/pyip');
});

test('trojan defaults to tls', () => {
  const n = parseConfig('trojan://pass@1.2.3.4:443?type=ws&host=h.example#t');
  assert.equal(n.scheme, 'trojan');
  assert.equal(n.security, 'tls');
  assert.equal(n.credential, 'pass');
});

test('parses base64 vmess json', () => {
  const uri =
    'vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwibmV0Ijoid3MiLCJwYXRoIjoiL3YiLCJ0bHMiOiJ0bHMiLCJwcyI6Im15LXZtZXNzIn0=';
  const n = parseConfig(uri);
  assert.equal(n.scheme, 'vmess');
  assert.equal(n.host, '1.2.3.4');
  assert.equal(n.port, 443);
  assert.equal(n.credential, '11111111-2222-3333-4444-555555555555');
  assert.equal(n.network, 'ws');
  assert.equal(n.security, 'tls');
  assert.equal(n.name, 'my-vmess');
});

test('parses SIP002 shadowsocks', () => {
  const userInfo = Buffer.from('aes-256-gcm:secretpw').toString('base64');
  const n = parseConfig(`ss://${userInfo}@1.2.3.4:8388#ss-node`);
  assert.equal(n.scheme, 'ss');
  assert.equal(n.method, 'aes-256-gcm');
  assert.equal(n.credential, 'secretpw');
  assert.equal(n.port, 8388);
});

test('parses legacy shadowsocks (fully encoded)', () => {
  const body = Buffer.from('aes-128-gcm:pw@5.6.7.8:9999').toString('base64');
  const n = parseConfig(`ss://${body}#legacy`);
  assert.equal(n.method, 'aes-128-gcm');
  assert.equal(n.host, '5.6.7.8');
  assert.equal(n.port, 9999);
});

test('parses hysteria2 with insecure flag', () => {
  const n = parseConfig('hysteria2://letmein@example.com:443?sni=example.com&insecure=1#hy2');
  assert.equal(n.scheme, 'hysteria2');
  assert.equal(n.credential, 'letmein');
  assert.equal(n.port, 443);
  assert.equal(n.allowInsecure, true);
});

test('parses tuic uuid:password', () => {
  const n = parseConfig('tuic://uuid-here:pass-here@1.2.3.4:443?sni=s.example&alpn=h3#tuic');
  assert.equal(n.scheme, 'tuic');
  assert.equal(n.uuid, 'uuid-here');
  assert.equal(n.credential, 'pass-here');
  assert.equal(n.security, 'tls');
});

test('validateNode catches garbage', () => {
  assert.equal(validateNode(null), 'parse failed');
  assert.equal(validateNode({ scheme: 'vless', host: 'h', port: 0, credential: 'x' }), 'invalid port');
  assert.equal(validateNode({ scheme: 'vless', host: 'h', port: 443, credential: 'x' }), null);
});

test('renameUri rewrites fragment for vless', () => {
  const n = parseConfig('vless://uuid@1.2.3.4:80?type=tcp#old-name');
  const renamed = renameUri(n, '🇩🇪 DE · Berlin');
  assert.ok(renamed.startsWith('vless://uuid@1.2.3.4:80?type=tcp#'));
  assert.ok(renamed.includes(encodeURIComponent('🇩🇪 DE · Berlin')));
  assert.ok(!renamed.includes('old-name'));
});

test('renameUri re-encodes base64 vmess with new ps', () => {
  const uri =
    'vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwibmV0Ijoid3MiLCJwYXRoIjoiL3YiLCJ0bHMiOiIiLCJwcyI6Im9sZCJ9';
  const n = parseConfig(uri);
  const renamed = renameUri(n, 'new-name');
  const json = JSON.parse(Buffer.from(renamed.slice('vmess://'.length), 'base64').toString('utf8'));
  assert.equal(json.ps, 'new-name');
  assert.equal(json.add, '1.2.3.4');
});
