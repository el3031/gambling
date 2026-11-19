// Read-only CORS proxy for the Polymarket US API. Zero dependencies (Node 18+).
//
// Use this only if the browser blocks direct calls to https://api.polymarket.us.
// The page signs every request itself; this proxy never receives your secret key.
// It forwards GET requests under /v1/portfolio/ and refuses everything else,
// so it cannot be used to place or cancel orders.
//
//   node proxy.mjs
//   PORT=8787 ALLOW_ORIGIN=http://localhost:8000 UPSTREAM=https://api.polymarket.us node proxy.mjs

import http from 'node:http';

const PORT = Number(process.env.PORT || 8787);
const UPSTREAM = (process.env.UPSTREAM || 'https://api.polymarket.us').replace(/\/+$/, '');
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || 'http://localhost:8000';
const ALLOWED_PATH = /^\/v1\/portfolio\/[A-Za-z0-9/_-]+$/;
const FORWARD_HEADERS = ['x-pm-access-key', 'x-pm-timestamp', 'x-pm-signature', 'accept'];

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', ALLOW_ORIGIN);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'X-PM-Access-Key, X-PM-Timestamp, X-PM-Signature, Content-Type');
  res.setHeader('Access-Control-Max-Age', '600');
}

const server = http.createServer(async (req, res) => {
  cors(res);
  const origin = req.headers.origin;
  if (origin && origin !== ALLOW_ORIGIN) {
    res.writeHead(403).end('Origin not allowed');
    return;
  }
  if (req.method === 'OPTIONS') { res.writeHead(204).end(); return; }

  const url = new URL(req.url, 'http://localhost');
  if (req.method !== 'GET' || !ALLOWED_PATH.test(url.pathname)) {
    res.writeHead(405).end('This proxy only forwards GET /v1/portfolio/*');
    return;
  }

  const headers = {};
  for (const h of FORWARD_HEADERS) if (req.headers[h]) headers[h] = req.headers[h];

  try {
    const upstream = await fetch(UPSTREAM + url.pathname + url.search, { method: 'GET', headers });
    const body = Buffer.from(await upstream.arrayBuffer());
    res.writeHead(upstream.status, { 'Content-Type': upstream.headers.get('content-type') || 'application/json' });
    res.end(body);
    console.log(`${new Date().toISOString()} GET ${url.pathname} -> ${upstream.status}`);
  } catch (e) {
    console.error('Upstream error:', e.message);
    res.writeHead(502, { 'Content-Type': 'text/plain' }).end('Upstream request failed');
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Read-only proxy on http://localhost:${PORT} -> ${UPSTREAM} (allowing origin ${ALLOW_ORIGIN})`);
});
