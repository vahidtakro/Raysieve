import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { isHttpUrl, fetchRemoteText, loadConfigsAsync } from '../src/config-load.js';

let server;
let port;

beforeEach(async () => {
  if (server) return;
  server = http.createServer((req, res) => {
    if (req.url === '/list.txt') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('vless://u@1.2.3.4:80?type=tcp#remote-a\nvless://u@5.6.7.8:80?type=tcp#remote-b\n');
    } else if (req.url === '/sub.b64') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(Buffer.from('vless://u@9.9.9.9:80?type=tcp#remote-sub\n', 'utf8').toString('base64'));
    } else if (req.url === '/404') {
      res.writeHead(404);
      res.end('nope');
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', () => r()));
  port = server.address().port;
});

after(() => server?.close());

test('isHttpUrl detects urls and rejects the rest', () => {
  assert.ok(isHttpUrl('https://example.com/list.txt'));
  assert.ok(isHttpUrl('http://localhost:8080/x'));
  assert.ok(!isHttpUrl('vless://u@1.2.3.4:80'));
  assert.ok(!isHttpUrl('./local/file.txt'));
  assert.ok(!isHttpUrl('-'));
});

test('fetchRemoteText downloads a plain list', async () => {
  const text = await fetchRemoteText(`http://127.0.0.1:${port}/list.txt`);
  assert.match(text, /remote-a/);
});

test('loadConfigsAsync merges local files and URL inputs, decoding base64 subs', async () => {
  const local = 'vless://u@2.2.2.2:80?type=tcp#local\n';
  const res = await loadConfigsAsync(
    [`http://127.0.0.1:${port}/list.txt`, `http://127.0.0.1:${port}/sub.b64`],
    { stdinText: local }
  );
  const hosts = res.configs.map((c) => c.match(/@([0-9.]+):/)[1]);
  assert.ok(hosts.includes('1.2.3.4'));
  assert.ok(hosts.includes('5.6.7.8'));
  assert.ok(hosts.includes('9.9.9.9')); // from the base64 sub URL
  assert.ok(hosts.includes('2.2.2.2')); // from stdin
});

test('fetchRemoteText throws on 404 and loadConfigsAsync warns but continues', async () => {
  const res = await loadConfigsAsync([`http://127.0.0.1:${port}/404`, `http://127.0.0.1:${port}/list.txt`], {});
  assert.equal(res.configs.length, 2);
});
