import http from 'node:http';

// DELIBERATELY UNSAFE. This is what a plain node:http server looks like with no
// hardening, so the demo can attack it next to ../server.js. Never deploy this.
export function createNaiveServer() {
  return http.createServer(async (req, res) => {
    // Reflects ANY origin and allows credentials: any website can read
    // responses with the visitor's cookies attached.
    if (req.headers.origin) {
      res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    try {
      if (req.method === 'GET' && req.url === '/health') return json(res, 200, { ok: true });
      if (req.method === 'POST' && req.url === '/echo') {
        // No size limit and no content-type check: buffers whatever arrives.
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const raw = Buffer.concat(chunks);
        JSON.parse(raw.toString('utf8'));
        return json(res, 200, { ok: true, bytes: raw.length });
      }
      if (req.method === 'GET' && req.url === '/boom') throw new Error('database password is hunter2');
      json(res, 404, { error: 'not found' });
    } catch (err) {
      // Sends the stack trace, and any secret in the message, to the client.
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end(err.stack);
    }
  });
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}
