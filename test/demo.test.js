import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { createDemoServer } from '../demo/server.js';

async function start(t) {
  const server = createDemoServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  return server.address().port;
}

// node:http instead of fetch so the test can send any Host header.
function call(port, { path = '/', method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers, agent: false }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, type: res.headers['content-type'], body: data }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

const api = (port, name, input = {}, headers = {}) =>
  call(port, { path: `/api/${name}`, method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(input) });

test('serves the demo page', async (t) => {
  const port = await start(t);
  const res = await call(port);
  assert.equal(res.status, 200);
  assert.match(res.type, /text\/html/);
  assert.match(res.body, /nodejs-http-hardening/);
});

test('every attack exploits the naive server and is blocked by server.js', async (t) => {
  const port = await start(t);
  // slowloris is checked separately below with a shorter watch window.
  for (const [name, input] of [['headers'], ['errors'], ['body'], ['body', { chunked: true }], ['ratelimit'], ['cors']]) {
    const res = await api(port, name, input);
    assert.equal(res.status, 200, name);
    const { unsafe, safe } = JSON.parse(res.body);
    assert.equal(unsafe.exploited, true, `${name} unsafe: ${JSON.stringify(unsafe).slice(0, 200)}`);
    assert.equal(safe.exploited, false, `${name} safe: ${JSON.stringify(safe).slice(0, 200)}`);
  }
});

test('slowloris: naive keeps the socket open, server.js drops it', async (t) => {
  const port = await start(t);
  const { unsafe, safe } = JSON.parse((await api(port, 'slowloris', { interval: 500, watchMs: 3000 })).body);
  assert.equal(unsafe.exploited, true);
  assert.equal(unsafe.closedAtMs, null);
  assert.equal(safe.exploited, false);
  assert.ok(safe.closedAtMs < 3500, `dropped at ${safe.closedAtMs} ms`);
});

test('local-only guards', async (t) => {
  const port = await start(t);
  assert.equal((await call(port, { headers: { Host: 'evil.example' } })).status, 403);
  assert.equal((await api(port, 'headers', {}, { Host: `evil.example:${port}` })).status, 403);
  assert.equal((await api(port, 'headers', {}, { Origin: 'https://evil.example' })).status, 403);
  assert.equal((await call(port, { path: '/api/headers', method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' })).status, 415);
  assert.equal((await api(port, 'headers', {}, { Origin: `http://localhost:${port}` })).status, 200);
  assert.equal((await api(port, 'headers', { path: 'no-slash' })).status, 400);
});
