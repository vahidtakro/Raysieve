import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfigs, isConfigLine } from '../src/config-load.js';
import { flagOf, buildDisplayName, uniquifyNames } from '../src/geo.js';
import { buildSingboxConfig, buildPlainSubscription, buildBase64Subscription } from '../src/outputs.js';
import { parseConfig } from '../src/parse.js';
import { toXrayOutbound, toSingboxOutbound } from '../src/builders.js';

test('loadConfigs: dedupes, skips comments, decodes base64 subs', () => {
  const b64 = Buffer.from('vless://u@1.2.3.4:80?type=tcp#sub\n', 'utf8').toString('base64');
  const text = [
    '# comment line',
    'vless://u@1.2.3.4:80?type=tcp#a',
    'vless://u@1.2.3.4:80?type=tcp#a',
    '',
    b64,
    'https://not-a-proxy.example',
  ].join('\n');
  const { configs, skipped } = loadConfigs([], { stdinText: text });
  assert.equal(configs.length, 2);
  assert.equal(skipped.length, 1);
  assert.match(skipped[0].reason, /unsupported/);
});

test('isConfigLine accepts known schemes', () => {
  assert.ok(isConfigLine('vless://x'));
  assert.ok(isConfigLine('hysteria2://x'));
  assert.ok(isConfigLine('hy2://x'));
  assert.ok(!isConfigLine('ftp://x'));
  assert.ok(!isConfigLine('hello world'));
});

test('flagOf builds regional indicators', () => {
  assert.equal(flagOf('de'), '🇩🇪');
  assert.equal(flagOf('US'), '🇺🇸');
  assert.equal(flagOf(''), '');
  assert.equal(flagOf('D'), '');
});

test('buildDisplayName composes geo parts', () => {
  const node = { name: 'orig', host: 'h' };
  assert.equal(
    buildDisplayName(node, { country: 'Germany', countryCode: 'DE', city: 'Berlin', isp: 'ACME' }),
    '🇩🇪 · DE · Berlin'
  );
  assert.equal(buildDisplayName(node, { error: 'x' }), 'orig');
});

test('uniquifyNames appends counters on collision', () => {
  const entries = [{ name: 'X' }, { name: 'X' }, { name: 'X' }, { name: 'Y' }];
  uniquifyNames(entries);
  assert.deepEqual(entries.map((e) => e.name), ['X', 'X #2', 'X #3', 'Y']);
});

test('outbound builders produce sane structures', () => {
  const vless = parseConfig('vless://u@1.2.3.4:443?security=tls&type=ws&path=/p&host=h.example&sni=h.example#x');
  const x = toXrayOutbound(vless);
  assert.equal(x.protocol, 'vless');
  assert.equal(x.streamSettings.security, 'tls');
  assert.equal(x.streamSettings.wsSettings.path, '/p');
  const s = toSingboxOutbound(vless);
  assert.equal(s.type, 'vless');
  assert.equal(s.tls.enabled, true);
  assert.equal(s.transport.type, 'ws');

  const hy2 = parseConfig('hysteria2://pw@1.2.3.4:443#x');
  assert.equal(toXrayOutbound(hy2), null); // xray cannot do hysteria2
  assert.equal(toSingboxOutbound(hy2).type, 'hysteria2');
});

test('sing-box client config bundles all working nodes', () => {
  const a = { node: parseConfig('vless://u@1.2.3.4:80?type=tcp#a'), raw: 'x', name: 'A' };
  const b = { node: parseConfig('ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388#b'), raw: 'y', name: 'B' };
  const cfg = buildSingboxConfig([a, b]);
  assert.equal(cfg.outbounds.length, 4); // 2 proxies + selector + direct
  assert.deepEqual(cfg.outbounds[2].outbounds, ['proxy-1-vless', 'proxy-2-ss']);
});

test('subscriptions round-trip', () => {
  const entries = [{ node: {}, raw: 'vless://u@1.2.3.4:80?type=tcp#a' }];
  const plain = buildPlainSubscription(entries);
  assert.equal(plain, 'vless://u@1.2.3.4:80?type=tcp#a\n');
  const b64 = buildBase64Subscription(entries);
  assert.equal(Buffer.from(b64, 'base64').toString('utf8'), plain);
});
