// Builds the hosted (static) version of the demo.
//
//   node demo/static.mjs record   runs every preset attack for real (needs Google Chrome),
//                                 scrubs local details, and writes demo/recordings.json
//   node demo/static.mjs build    writes demo/dist/ (index.html + _headers) from those recordings
//
// The hosted page never executes attacks. It replays the recorded responses, because a
// public server running command injection or path traversal would be a real target.

import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.basename(path.dirname(here));
const RECORDINGS = path.join(here, 'recordings.json');
const DIST = path.join(here, 'dist');
const CHROME = process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const sortKeys = (v) =>
  Array.isArray(v) ? v.map(sortKeys)
  : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]))
  : v;
export const requestKey = (route, body) => `${route}\n${JSON.stringify(sortKeys(JSON.parse(body || '{}')))}`;

// Replace anything that identifies the machine the recording was made on.
function scrubber() {
  const pairs = [
    [os.homedir(), '/home/user'],
    ...new Set([os.tmpdir(), realpathSync(os.tmpdir())]).values().map((t) => [t, '/tmp']),
    [os.hostname(), 'demo-host'],
    [os.hostname().split('.')[0], 'demo-host'],
    [os.userInfo().username, 'user'],
  ].filter(([from]) => from && from.length > 2);
  return (text) => pairs.reduce((s, [from, to]) => s.split(from).join(to), text);
}

// Clicks Run for each card's default, then every preset chip, then reports done.
const DRIVER = `<script>
(async () => {
  const realFetch = window.fetch; let pending = 0;
  window.fetch = (...a) => { pending++; return realFetch(...a).finally(() => pending--); };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const idle = async () => { await sleep(80); while (pending) await sleep(50); await sleep(80); };
  await sleep(400);
  for (const card of document.querySelectorAll('section')) {
    if (card.hidden) continue;
    const run = card.querySelector('button.run, button[type=submit]') ||
      [...card.querySelectorAll('button')].find((b) => /^run\\b/i.test(b.textContent.trim()));
    if (!run) continue;
    const fire = (el) => ['input', 'change'].forEach((t) => el.dispatchEvent(new Event(t, { bubbles: true })));
    run.click(); await idle();
    for (const chip of card.querySelectorAll('.chip')) { chip.click(); await idle(); run.click(); await idle(); }
    // Sliders: min, max, and 5 points in between.
    for (const r of card.querySelectorAll('input[type=range]')) {
      const orig = r.value, min = +r.min, max = +r.max, step = +r.step || 1;
      const values = new Set([min, max, ...[1, 2, 3, 4, 5].map((i) => min + Math.round(((max - min) * i) / 6 / step) * step)]);
      for (const v of values) { r.value = v; fire(r); run.click(); await idle(); }
      r.value = orig; fire(r);
    }
    // Checkboxes: every combination, when there are only a few.
    const boxes = [...card.querySelectorAll('input[type=checkbox]')];
    if (boxes.length && boxes.length <= 4) {
      const orig = boxes.map((b) => b.checked);
      for (let mask = 0; mask < 1 << boxes.length; mask++) {
        boxes.forEach((b, i) => { b.checked = Boolean(mask & (1 << i)); fire(b); });
        run.click(); await idle();
      }
      boxes.forEach((b, i) => { b.checked = orig[i]; fire(b); });
    }
  }
  await realFetch('/__done', { method: 'POST' });
})();
</script>`;

async function record() {
  const { createDemoServer } = await import(path.join(here, 'server.js'));
  const demo = createDemoServer();
  await new Promise((r) => demo.listen(0, '127.0.0.1', r));
  const target = `http://127.0.0.1:${demo.address().port}`;
  const scrub = scrubber();
  const recordings = {};
  let finish;
  const done = new Promise((r) => (finish = r));

  const proxy = createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString('utf8');
    if (req.url === '/__done') { res.end(); return finish(); }
    const upstream = await fetch(target + req.url, {
      method: req.method,
      headers: { 'content-type': req.headers['content-type'] ?? 'application/json' },
      body: req.method === 'POST' ? body : undefined,
    });
    let text = await upstream.text();
    const route = req.url.match(/^\/api\/([\w-]+)/)?.[1];
    if (route && req.method === 'POST' && upstream.ok) {
      recordings[requestKey(route, body)] = JSON.parse(scrub(text));
    }
    if (req.url === '/' || req.url.startsWith('/?')) text = text.replace('</body>', `${DRIVER}</body>`);
    res.writeHead(upstream.status, { 'content-type': upstream.headers.get('content-type') ?? 'text/plain' });
    res.end(text);
  });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));

  const profile = mkdtempSync(path.join(os.tmpdir(), 'chrome-record-'));
  const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', `--user-data-dir=${profile}`, '--remote-debugging-port=0',
    `http://127.0.0.1:${proxy.address().port}/`], { stdio: 'ignore' });
  const timeout = setTimeout(() => finish('timeout'), 180_000);
  const result = await done;
  clearTimeout(timeout);
  const exited = new Promise((r) => chrome.once('exit', r));
  chrome.kill();
  await exited;
  proxy.close(); demo.close();
  rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  if (result === 'timeout') throw new Error('recording timed out after 3 minutes');

  const sorted = Object.fromEntries(Object.keys(recordings).sort().map((k) => [k, recordings[k]]));
  writeFileSync(RECORDINGS, JSON.stringify(sorted, null, 2) + '\n');
  const routes = Object.keys(sorted).map((k) => k.split('\n')[0]);
  console.log(`Recorded ${routes.length} responses: ${[...new Set(routes)].map((r) => `${r} ×${routes.filter((x) => x === r).length}`).join(', ')}`);
  console.log('Review demo/recordings.json before publishing it.');
  process.exit(0);
}

function build() {
  const recordings = JSON.parse(readFileSync(RECORDINGS, 'utf8'));
  const repoUrl = `https://github.com/msanvarov/${REPO}`;
  const shim = `<script>
(() => {
  const RECORDINGS = ${JSON.stringify(recordings).replace(/</g, '\\u003c')};
  const sortKeys = (v) => Array.isArray(v) ? v.map(sortKeys) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])])) : v;
  const json = (status, data) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
  window.fetch = async (url, opts = {}) => {
    const route = new URL(url, location.href).pathname.match(/^\\/api\\/([\\w-]+)/)?.[1];
    await new Promise((r) => setTimeout(r, 200));
    let key, body;
    try { body = sortKeys(JSON.parse(opts.body || '{}')); key = route + '\\n' + JSON.stringify(body); } catch {}
    if (key && Object.hasOwn(RECORDINGS, key)) return json(200, RECORDINGS[key]);
    // Slider values that weren't recorded: use the closest recorded run with the same other inputs.
    let best, bestDistance = Infinity;
    for (const k of Object.keys(RECORDINGS)) {
      const [r, b] = [k.slice(0, k.indexOf('\\n')), JSON.parse(k.slice(k.indexOf('\\n') + 1))];
      if (r !== route || !body) continue;
      const keys = new Set([...Object.keys(b), ...Object.keys(body)]);
      let distance = 0;
      for (const f of keys) {
        if (typeof b[f] === 'number' && typeof body[f] === 'number') distance += Math.abs(b[f] - body[f]) / Math.max(1, Math.abs(body[f]));
        else if (JSON.stringify(b[f]) !== JSON.stringify(body[f])) { distance = Infinity; break; }
      }
      if (distance < bestDistance) { best = k; bestDistance = distance; }
    }
    if (best) return json(200, RECORDINGS[best]);
    return json(404, { error: 'This hosted preview only replays recorded runs. Use the default input or one of the "Try" presets, or run it locally to try your own: git clone ${repoUrl} && npm run demo' });
  };
})();
</script>`;
  const banner = `<div style="background:#2b2410;color:#f5d48a;border-bottom:1px solid #5a4818;padding:10px 16px;font:14px/1.45 system-ui,sans-serif;text-align:center">
Hosted preview: results below were recorded from real runs of the demo on a local machine. Nothing runs on this server.
To try your own payloads, <a style="color:#ffe3a3" href="${repoUrl}#interactive-demo">run it locally</a> with <code>npm run demo</code>.</div>`;

  let html = readFileSync(path.join(here, 'index.html'), 'utf8')
    .replace(/<head>/i, `<head>\n${shim}`)
    .replace(/(<body[^>]*>)/i, `$1\n${banner}`)
    .replace('Runs deliberately vulnerable code locally · bound to 127.0.0.1', 'Recorded runs · nothing executes on this server');

  // Content-Security-Policy with a hash for each inline script, so nothing else can run.
  const hashes = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)]
    .map((m) => `'sha256-${createHash('sha256').update(m[1]).digest('base64')}'`);
  const csp = [`default-src 'none'`, `script-src ${hashes.join(' ')}`, `style-src 'unsafe-inline'`, `img-src 'self' data:`,
    `connect-src 'self'`, `base-uri 'none'`, `form-action 'none'`, `frame-ancestors 'none'`].join('; ');
  const headers = `/*
  Content-Security-Policy: ${csp}
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: no-referrer
  Cross-Origin-Opener-Policy: same-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
`;
  rmSync(DIST, { recursive: true, force: true });
  mkdirSync(DIST);
  writeFileSync(path.join(DIST, 'index.html'), html);
  writeFileSync(path.join(DIST, '_headers'), headers);
  console.log(`Built demo/dist/ with ${Object.keys(recordings).length} recorded responses and ${hashes.length} hashed scripts.`);
}

const mode = process.argv[2];
if (mode === 'record') await record();
else if (mode === 'build') build();
else { console.error('usage: node demo/static.mjs record|build'); process.exit(1); }
