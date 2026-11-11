// Mundora AI proxy (Vercel Edge Function).
// The API address and key live only in Vercel → Settings → Environment Variables:
//   AI_BASE = https://api.example.com/v1      AI_KEY = sk-...
// Only signed-in Mundora users (Firebase) can use it.
export const config = { runtime: 'edge' };

const FB_KEY = 'AIzaSyDl_HsF96Rz52BUISG6cYeXg_6joZkMxXk'; // public Firebase web key (not a secret)
const seen = new Map();

const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json' } });

async function signedIn(req) {
  const h = req.headers.get('authorization') || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!tok) return false;
  const until = seen.get(tok);
  if (until && until > Date.now()) return true;
  const r = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + FB_KEY, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ idToken: tok })
  });
  if (!r.ok) return false;
  const j = await r.json().catch(() => ({}));
  if (!j.users || !j.users.length) return false;
  if (seen.size > 1000) seen.clear();
  seen.set(tok, Date.now() + 10 * 60 * 1000);
  return true;
}

export default async function handler(req) {
  const base = (process.env.AI_BASE || '').trim().replace(/\/+$/, '');
  const key = (process.env.AI_KEY || '').trim();
  if (!base || !key) return json({ error: { message: 'Server is not configured: add AI_BASE and AI_KEY in Vercel settings' } }, 500);
  if (!(await signedIn(req))) return json({ error: { message: 'Sign in again' } }, 401);

  const p = new URL(req.url).searchParams.get('p');
  const auth = { authorization: 'Bearer ' + key };

  if (p === 'models' && req.method === 'GET') {
    const r = await fetch(base + '/models', { headers: auth });
    return new Response(r.body, { status: r.status, headers: { 'content-type': r.headers.get('content-type') || 'application/json' } });
  }

  if (p === 'chat' && req.method === 'POST') {
    let body;
    try { body = await req.json(); } catch (e) { return json({ error: { message: 'Bad request' } }, 400); }
    const model = String(body.model || '');
    if (!/^(claude|gpt|chatgpt)/i.test(model.split('/').pop())) return json({ error: { message: 'Model not allowed' } }, 400);
    const messages = (Array.isArray(body.messages) ? body.messages : [])
      .filter(m => m && /^(system|user|assistant)$/.test(m.role) && typeof m.content === 'string')
      .slice(-40);
    const r = await fetch(base + '/chat/completions', {
      method: 'POST',
      headers: { ...auth, 'content-type': 'application/json' },
      body: JSON.stringify({ model, messages, stream: true }),
      signal: req.signal
    });
    return new Response(r.body, { status: r.status, headers: { 'content-type': r.headers.get('content-type') || 'application/json', 'cache-control': 'no-cache' } });
  }

  return json({ error: { message: 'Not found' } }, 404);
      }
