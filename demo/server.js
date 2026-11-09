// Interactive demo: fires real attacks at a naive server and at ../server.js,
// side by side. Runs on 127.0.0.1 only.
//
//   npm run demo   ->  http://127.0.0.1:4102

import http from 'node:http';
import net from 'node:net';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';

import { createServer, SECURITY_HEADERS } from '../server.js';
import { createNaiveServer } from './naive-server.js';

const INDEX = new URL('./index.html', import.meta.url);
const KB = 1024;
const RATE_LIMIT = 20;
const ALLOWED_ORIGINS = ['http://localhost:3000']; // hardened server's default allowlist
const SLOWLORIS_CAP_MS = 5000;

// ---------- targets ----------

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const urlOf = (server) => `http://127.0.0.1:${server.address().port}`;

// Fresh targets per attack, so state (rate-limit counters) never leaks between runs.
async function withTargets(fn) {
  const naive = createNaiveServer();
  const hardened = createServer({ rateLimit: RATE_LIMIT });
  // Shorter than production so slowloris is visible in a few seconds.
  // Node only enforces these on its connection check, so check often too.
  hardened.headersTimeout = 2000;
  hardened.requestTimeout = 2000;
  hardened.connectionsCheckingInterval = 250;
  await Promise.all([listen(naive), listen(hardened)]);
  try {
    return await fn(urlOf(naive), urlOf(hardened));
  } finally {
    for (const s of [naive, hardened]) {
      s.closeAllConnections();
      s.close();
    }
  }
}

// Same attack at both servers in parallel. A failure on one side is a result, not a 500.
async function compare(attack) {
  return withTargets(async (naiveUrl, hardenedUrl) => {
    const run = (url) => attack(url).catch((err) => ({ error: err.code ?? err.message }));
    const [unsafe, safe] = await Promise.all([run(naiveUrl), run(hardenedUrl)]);
    return { unsafe, safe };
  });
}

// Raw HTTP client (fetch won't send Origin freely or stream chunked bodies as we need).
// Bodies go out the way a well-behaved client sends them: headers first, a short
// pause so the server can reject on headers alone, then 64 KB at a time, stopping
// as soon as the server answers. Blasting everything at once lets the server's
// connection reset arrive before we read its 413.
function request(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const start = performance.now();
    let answered = false;
    const req = http.request(url, { method, headers, agent: false }, (res) => {
      answered = true;
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('error', reject);
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
          ms: Math.round(performance.now() - start),
        });
        req.destroy(); // we may have stopped mid-body
      });
    });
    req.on('error', reject); // ignored once resolved
    if (!body) return req.end();
    req.flushHeaders();
    let offset = 0;
    const next = () => {
      if (answered) return;
      if (offset >= body.length) return req.end();
      req.write(body.subarray(offset, (offset += 64 * KB)), () => setImmediate(next));
    };
    setTimeout(next, 30);
  });
}

// ---------- attacks ----------

const clamp = (n, min, max, fallback) => (Number.isFinite(Number(n)) ? Math.min(max, Math.max(min, Number(n))) : fallback);

function checkPath(path, fallback) {
  const p = typeof path === 'string' && path ? path : fallback;
  if (!/^\/[\w\-./?=&%]{0,200}$/.test(p)) throw new BadInput('path must start with / and use URL-safe characters');
  return p;
}

class BadInput extends Error {}

const SILENT = () => {};

const attacks = {
  async headers({ path }) {
    const p = checkPath(path, '/health');
    return compare(async (url) => {
      const res = await request(url + p);
      const headers = Object.fromEntries(Object.keys(SECURITY_HEADERS).map((h) => [h, res.headers[h.toLowerCase()] ?? null]));
      const missing = Object.values(headers).filter((v) => v === null).length;
      return { request: `GET ${p}`, status: res.status, headers, missing, exploited: missing > 0 };
    });
  },

  async errors({ path }) {
    const p = checkPath(path, '/boom');
    const original = console.error;
    console.error = SILENT; // the hardened server logs the real error server-side
    try {
      return await compare(async (url) => {
        const res = await request(url + p);
        // Shown as ~ so screenshots and recordings don't publish your username.
        // The leak itself (stack trace, file paths, the secret) is unchanged.
        const body = res.body.split(homedir()).join('~');
        return { request: `GET ${p}`, status: res.status, body, exploited: /hunter2| at /.test(body) };
      });
    } finally {
      console.error = original;
    }
  },

  async body({ size, chunked }) {
    const bytes = clamp(size, KB, 5 * KB * KB, 2 * KB * KB);
    const isChunked = chunked === true;
    const prefix = '{"data":"';
    const body = Buffer.from(prefix + 'x'.repeat(Math.max(0, bytes - prefix.length - 2)) + '"}');
    return compare(async (url) => {
      const headers = { 'Content-Type': 'application/json', ...(isChunked ? {} : { 'Content-Length': body.length }) };
      const label = `POST /echo  ${body.length.toLocaleString('en-US')} bytes, ${isChunked ? 'chunked (no Content-Length)' : 'Content-Length'}`;
      let res;
      const t0 = performance.now();
      try {
        res = await request(url + '/echo', { method: 'POST', headers, body });
      } catch (err) {
        // A reset before we could read the reply still means the body was refused.
        if (err.code !== 'ECONNRESET' && err.code !== 'EPIPE') throw err;
        return { request: label, status: `connection closed by server (${err.code})`, body: '', bufferedBytes: 0, ms: Math.round(performance.now() - t0), exploited: false };
      }
      let accepted = 0;
      try {
        const parsed = JSON.parse(res.body);
        accepted = parsed.bytes ?? (parsed.received ? body.length : 0);
      } catch {}
      return {
        request: label,
        status: res.status,
        body: res.body.slice(0, 200),
        bufferedBytes: accepted,
        ms: res.ms,
        exploited: res.status === 200 && body.length > 100 * KB,
      };
    });
  },

  async ratelimit({ count }) {
    const n = clamp(count, 10, 100, 40);
    return compare(async (url) => {
      const statuses = [];
      for (let i = 0; i < n; i++) statuses.push((await request(url + '/health')).status);
      const counts = {};
      for (const s of statuses) counts[s] = (counts[s] ?? 0) + 1;
      return {
        request: `${n} × GET /health (limit ${RATE_LIMIT} per minute)`,
        statuses,
        counts,
        exploited: n > RATE_LIMIT && !statuses.includes(429),
        ...(n <= RATE_LIMIT && { okLabel: 'Not affected' }), // under the limit: nothing to block
      };
    });
  },

  async cors({ origin }) {
    const o = typeof origin === 'string' && origin ? origin : 'https://evil.example';
    if (o.length > 200 || /[\r\n]/.test(o)) throw new BadInput('origin must be one line, under 200 characters');
    return compare(async (url) => {
      const res = await request(url + '/health', { headers: { Origin: o } });
      const allowOrigin = res.headers['access-control-allow-origin'] ?? null;
      const allowCredentials = res.headers['access-control-allow-credentials'] ?? null;
      const exploited = allowOrigin === o && !ALLOWED_ORIGINS.includes(o);
      const meaning = exploited
        ? `${o} can read responses from this API${allowCredentials ? ", including logged-in users' data (cookies are sent)" : ''}.`
        : allowOrigin
          ? `${o} is on the allowlist, so it may read responses.`
          : `The browser blocks ${o} from reading the response.`;
      const okLabel = !exploited && allowOrigin ? 'Not affected' : undefined; // allowlisted origin
      return { request: `GET /health  Origin: ${o}`, allowOrigin, allowCredentials, meaning, exploited, okLabel };
    });
  },

  async slowloris({ interval, watchMs }) {
    const ms = clamp(interval, 100, 2000, 500);
    const cap = clamp(watchMs, 2500, SLOWLORIS_CAP_MS, SLOWLORIS_CAP_MS);
    return compare((url) => slowloris(url, ms, cap));
  },
};

// Open a socket, send an unfinished request, then trickle one byte every `intervalMs`.
function slowloris(url, intervalMs, capMs) {
  return new Promise((resolve) => {
    const { hostname, port } = new URL(url);
    const start = performance.now();
    const now = () => Math.round(performance.now() - start);
    const ticks = [];
    let response = null;
    let closedAtMs = null;
    let done = false;

    const socket = net.connect(Number(port), hostname, () => {
      socket.write('GET /health HTTP/1.1\r\nHost: x\r\n');
      ticks.push(now());
    });
    const trickle = setInterval(() => {
      if (!socket.destroyed && socket.writable) {
        socket.write('X');
        ticks.push(now());
      }
    }, intervalMs);
    socket.on('data', (d) => (response ??= d.toString('utf8').split('\r\n')[0]));
    socket.on('error', (err) => (response ??= err.code));
    socket.on('close', () => {
      closedAtMs ??= now();
      finish();
    });
    const cap = setTimeout(finish, capMs);

    function finish() {
      if (done) return;
      done = true;
      clearInterval(trickle);
      clearTimeout(cap);
      const stillOpen = closedAtMs === null;
      socket.destroy();
      resolve({
        request: `GET /health, then 1 header byte every ${intervalMs} ms, never finishing`,
        ticks,
        capMs,
        closedAtMs: stillOpen ? null : closedAtMs,
        response,
        bytesTrickled: ticks.length - 1,
        exploited: stillOpen,
      });
    }
  });
}

// ---------- demo server ----------

const PAGE_HEADERS = {
  'Content-Type': 'text/html; charset=utf-8',
  'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

function reply(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(body));
}

// Local-only guards. The demo really runs attacks, so random websites must not
// be able to drive it from the user's browser.
function guard(req, port) {
  const hosts = [`127.0.0.1:${port}`, `localhost:${port}`];
  if (!hosts.includes(req.headers.host)) return [403, 'forbidden host']; // DNS rebinding
  const origin = req.headers.origin;
  if (origin && !hosts.some((h) => origin === `http://${h}`)) return [403, 'forbidden origin'];
  if (req.method === 'POST' && !req.headers['content-type']?.startsWith('application/json')) {
    return [415, 'expected application/json']; // forces a CORS preflight we never answer
  }
  return null;
}

async function readBody(req, max = 64 * KB) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > max) throw new BadInput('body too large');
    chunks.push(chunk);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
}

export function createDemoServer() {
  return http.createServer(async (req, res) => {
    const blocked = guard(req, req.socket.localPort);
    if (blocked) return reply(res, blocked[0], { error: blocked[1] });

    const { pathname } = new URL(req.url, 'http://localhost');
    try {
      if (req.method === 'GET' && pathname === '/') {
        res.writeHead(200, PAGE_HEADERS);
        return res.end(await readFile(INDEX));
      }
      const name = pathname.startsWith('/api/') ? pathname.slice(5) : null;
      if (req.method === 'POST' && name && Object.hasOwn(attacks, name)) {
        let input;
        try {
          input = await readBody(req);
        } catch (err) {
          return reply(res, 400, { error: err instanceof BadInput ? err.message : 'invalid JSON' });
        }
        return reply(res, 200, await attacks[name](input ?? {}));
      }
      reply(res, 404, { error: 'not found' });
    } catch (err) {
      if (err instanceof BadInput) return reply(res, 400, { error: err.message });
      console.error(err);
      reply(res, 500, { error: 'demo failed, see terminal' });
    }
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 4102);
  createDemoServer().listen(port, '127.0.0.1', () => {
    console.log(`Demo running at http://127.0.0.1:${port}`);
    console.log('Warning: this fires real attacks at a deliberately naive server on your machine (127.0.0.1 only).');
  });
}
