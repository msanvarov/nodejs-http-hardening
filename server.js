import http from 'node:http';
import { fileURLToPath } from 'node:url';

// What helmet would set. Tune CSP for your app; this one is for a JSON API.
const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cache-Control': 'no-store',
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(body));
}

// Read a JSON body with a hard size cap. Without a cap, one client can make
// the process buffer gigabytes and crash.
async function readJson(req, maxBytes) {
  if (!req.headers['content-type']?.startsWith('application/json')) {
    throw new HttpError(415, 'expected application/json');
  }
  if (Number(req.headers['content-length'] ?? 0) > maxBytes) throw new HttpError(413, 'body too large');
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new HttpError(413, 'body too large'); // covers chunked bodies with no length
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'invalid JSON');
  }
}

export function createServer({
  rateLimit = 100,
  windowMs = 60_000,
  maxBodyBytes = 100 * 1024,
  allowedOrigins = ['http://localhost:3000'],
} = {}) {
  const origins = new Set(allowedOrigins);

  // ponytail: in-memory fixed window, per process. Move to Redis (or your
  // proxy/WAF) once you run more than one instance.
  const hits = new Map();
  const isRateLimited = (key, now = Date.now()) => {
    const entry = hits.get(key);
    if (!entry || now - entry.start >= windowMs) {
      hits.set(key, { start: now, count: 1 });
      return false;
    }
    return ++entry.count > rateLimit;
  };
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of hits) if (now - entry.start >= windowMs) hits.delete(key);
  }, windowMs).unref();

  const server = http.createServer(async (req, res) => {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) res.setHeader(name, value);

    // CORS: reflect only allowlisted origins. Never reflect any origin together
    // with Access-Control-Allow-Credentials.
    const origin = req.headers.origin;
    if (origin && origins.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
    }

    try {
      // Behind a proxy, use the client IP the proxy sets, but only if you trust
      // that proxy. Anyone can send their own X-Forwarded-For header.
      if (isRateLimited(req.socket.remoteAddress)) throw new HttpError(429, 'too many requests');

      const { pathname } = new URL(req.url, 'http://localhost');

      if (req.method === 'OPTIONS') {
        res.writeHead(204, { 'Access-Control-Allow-Methods': 'GET, POST', 'Access-Control-Allow-Headers': 'Content-Type' });
        return res.end();
      }
      if (req.method === 'GET' && pathname === '/health') return send(res, 200, { ok: true });
      if (req.method === 'POST' && pathname === '/echo') {
        return send(res, 200, { received: await readJson(req, maxBodyBytes) });
      }
      // Demo only: simulates an unexpected crash so you can see the error stays private.
      if (req.method === 'GET' && pathname === '/boom') throw new Error('database password is hunter2');
      throw new HttpError(404, 'not found');
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      // Full details go to your logs. The client only gets a generic message,
      // never a stack trace or internal error text.
      if (status === 500) console.error(err);
      const headers = status === 413 ? { Connection: 'close' } : status === 429 ? { 'Retry-After': String(Math.ceil(windowMs / 1000)) } : {};
      send(res, status, { error: status === 500 ? 'internal error' : err.message }, headers);
    }
  });

  // Slowloris / slow-body protection: drop clients that trickle data.
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  server.on('close', () => clearInterval(sweep));
  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 3000);
  createServer().listen(port, () => console.log(`listening on http://localhost:${port}`));
}
