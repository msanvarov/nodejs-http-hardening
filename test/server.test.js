import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from '../server.js';

async function start(t, options) {
  const server = createServer(options);
  server.listen(0);
  await once(server, 'listening');
  t.after(() => server.close());
  return `http://127.0.0.1:${server.address().port}`;
}

const postJson = (url, body, headers = {}) =>
  fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body });

test('sets security headers on every response', async (t) => {
  const base = await start(t);
  for (const path of ['/health', '/missing']) {
    const res = await fetch(base + path);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.match(res.headers.get('content-security-policy'), /default-src 'none'/);
    assert.match(res.headers.get('strict-transport-security'), /max-age=/);
    assert.equal(res.headers.get('x-powered-by'), null);
  }
});

test('errors never leak internals', async (t) => {
  t.mock.method(console, 'error', () => {});
  const base = await start(t);
  const res = await fetch(base + '/boom');
  assert.equal(res.status, 500);
  const text = await res.text();
  assert.equal(text, '{"error":"internal error"}');
  assert.doesNotMatch(text, /hunter2|at .*\.js/);
});

test('validates request bodies', async (t) => {
  const base = await start(t, { maxBodyBytes: 1024 });
  assert.equal((await postJson(base + '/echo', '{"a":1}')).status, 200);
  assert.equal((await postJson(base + '/echo', '{not json')).status, 400);
  assert.equal((await fetch(base + '/echo', { method: 'POST', body: 'a=1' })).status, 415);
  assert.equal((await postJson(base + '/echo', JSON.stringify({ big: 'x'.repeat(5000) }))).status, 413);
});

test('rejects oversized chunked bodies with no Content-Length', async (t) => {
  const base = await start(t, { maxBodyBytes: 1024 });
  const body = new ReadableStream({
    start(c) {
      c.enqueue(new TextEncoder().encode('"' + 'x'.repeat(5000) + '"'));
      c.close();
    },
  });
  // A stream body makes fetch use Transfer-Encoding: chunked.
  const res = await fetch(base + '/echo', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
    duplex: 'half',
  });
  assert.equal(res.status, 413);
});

test('rate limits per client', async (t) => {
  const base = await start(t, { rateLimit: 3 });
  const statuses = [];
  for (let i = 0; i < 5; i++) statuses.push((await fetch(base + '/health')).status);
  assert.deepEqual(statuses, [200, 200, 200, 429, 429]);
});

test('CORS only reflects allowlisted origins', async (t) => {
  const base = await start(t, { allowedOrigins: ['https://app.example.com'] });
  const good = await fetch(base + '/health', { headers: { Origin: 'https://app.example.com' } });
  assert.equal(good.headers.get('access-control-allow-origin'), 'https://app.example.com');
  const evil = await fetch(base + '/health', { headers: { Origin: 'https://evil.example' } });
  assert.equal(evil.headers.get('access-control-allow-origin'), null);
});
