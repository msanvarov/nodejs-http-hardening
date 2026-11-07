# nodejs-http-hardening

A hardened HTTP server in one file ([server.js](server.js)), built on `node:http` with no dependencies, so you can see exactly what each protection does. The same ideas map directly onto Express, Fastify, Koa, or Hono.

```bash
npm start        # http://localhost:3000
npm test         # proves each protection works
```

## What it does

| Risk | Mitigation in `server.js` | Express / Fastify equivalent |
| --- | --- | --- |
| Clickjacking, MIME sniffing, XSS, data leaks via Referer | Security headers on every response (CSP, HSTS, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, COOP/CORP, `Permissions-Policy`) | `helmet` / `@fastify/helmet` |
| Memory exhaustion from huge bodies | Hard byte cap, checked on `Content-Length` **and** while streaming (chunked bodies have no length) | `express.json({ limit: '100kb' })` / Fastify `bodyLimit` |
| Wrong content types reaching your parser | Reject anything that is not `application/json` with 415 | `express.json({ type })` |
| Slowloris (clients trickling headers or body) | `headersTimeout`, `requestTimeout`, `keepAliveTimeout`, `maxHeadersCount` | Same `http.Server` settings on the server Express returns |
| Brute force / scraping | Per-IP fixed-window rate limit with `429` + `Retry-After` | `express-rate-limit` / `@fastify/rate-limit` |
| Cross-origin data theft | CORS reflects only allowlisted origins, adds `Vary: Origin` | `cors({ origin: [...] })` / `@fastify/cors` |
| Leaking stack traces and secrets in errors | Generic `{"error":"internal error"}` to the client, full error to server logs | A final error handler that never sends `err.stack` |

## Things this repo deliberately leaves out

- **TLS.** Terminate HTTPS at a load balancer or reverse proxy (nginx, Caddy, your cloud's LB). HSTS only matters once you serve over HTTPS.
- **Distributed rate limiting.** The limiter here is in memory, per process. With more than one instance, use Redis or rate limit at the proxy/WAF.
- **Auth and sessions.** See `nodejs-crypto-secrets` for password hashing, tokens, and signing.

## Checklist for a production Node service

- [ ] Run a supported Node LTS and patch it. Most Node security releases fix HTTP parser bugs.
- [ ] `NODE_ENV=production` (Express hides error details and enables view caching).
- [ ] `app.disable('x-powered-by')` in Express. Plain `node:http` never sends it.
- [ ] Only trust `X-Forwarded-For` when you know the proxy sets it (`app.set('trust proxy', 1)`), otherwise clients can spoof their IP and dodge rate limits.
- [ ] Validate every request body against a schema (Zod, Ajv, TypeBox). Reject unknown fields.
- [ ] Cookies: `HttpOnly; Secure; SameSite=Lax` (or `Strict`). Use CSRF tokens if you rely on cookies for state-changing requests.
- [ ] Set timeouts on **outgoing** requests too (`fetch(url, { signal: AbortSignal.timeout(5000) })`). A slow upstream should not hang your server.
- [ ] Guard against SSRF: if users supply URLs you fetch, allowlist hosts and block private IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `169.254.169.254`, etc.), checking after DNS resolution.
- [ ] Run as a non-root user, with a read-only filesystem where possible.
- [ ] Handle `unhandledRejection` / `uncaughtException` by logging and exiting, then let your process manager restart. Don't keep running in an unknown state.
