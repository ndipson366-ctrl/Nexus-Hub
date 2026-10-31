// Netlify Function: runs the whole Nexus Hub API (everything under /api/*).
// It starts the same Node HTTP server used elsewhere on a private local port inside the function,
// then forwards each incoming request to it, so there is one copy of the app logic.
import '../lib/cjs-shim.mjs';        // must stay first: gives the CommonJS app code a working require() once bundled
import app from '../../server.js';

app.configure({ serverless: true });

const SKIP_RESPONSE_HEADERS = new Set(['transfer-encoding', 'connection', 'keep-alive', 'content-length', 'set-cookie']);

export default async (req, context) => {
  try {
    const port = await app.listenEphemeral();
    const url = new URL(req.url);

    const headers = new Headers(req.headers);
    for (const h of ['host', 'connection', 'content-length', 'transfer-encoding']) headers.delete(h);
    const ip = (context && context.ip) || req.headers.get('x-nf-client-connection-ip') || '';
    headers.set('x-forwarded-for', ip);
    headers.set('x-forwarded-proto', 'https');

    const hasBody = req.method !== 'GET' && req.method !== 'HEAD';
    const upstream = await fetch(`http://127.0.0.1:${port}${url.pathname}${url.search}`, {
      method: req.method,
      headers,
      body: hasBody ? Buffer.from(await req.arrayBuffer()) : undefined,
      redirect: 'manual'
    });

    const out = new Headers();
    for (const [k, v] of upstream.headers) if (!SKIP_RESPONSE_HEADERS.has(k.toLowerCase())) out.append(k, v);
    for (const c of upstream.headers.getSetCookie()) out.append('set-cookie', c);
    return new Response(await upstream.arrayBuffer(), { status: upstream.status, headers: out });
  } catch (err) {
    console.error('api function failed:', err);
    return new Response(JSON.stringify({ error: 'Server error.' }), { status: 502, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  }
};

export const config = { path: '/api/*' };
