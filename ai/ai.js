// Mundora AI server (Vercel Edge Function).
// Vercel → Settings → Environment Variables:
//   AI_BASE, AI_KEY                    — the model API (required)
//   KV_REST_API_URL, KV_REST_API_TOKEN — added automatically when Upstash Redis is connected (Storage tab)
//   ADMIN_EMAILS   (optional)          — e.g. "me@gmail.com"; these accounts get the Cosmos plan
//   BREVO_API_KEY, MAIL_FROM          — sending 6-digit email codes (MAIL_FROM = sender address confirmed in Brevo)
//   PROMO_CODES    (optional)          — e.g. "MUNDO-START=5000000,MUNDO-ORBIT=plan:orbit:30"
//                                        (number = bonus tokens, spent before the limits; plan:<id>:<days> = plan for N days)
// Tokens are counted by Mundora itself from the text of each question and answer (the API's own figures are not used).
export const config = { runtime: 'edge' };

const PROJECT = 'mundora-78';
const FB_KEY = 'AIzaSyDl_HsF96Rz52BUISG6cYeXg_6joZkMxXk'; // public Firebase web key

// Limits per plan: w = tokens per 5-hour window (0 = no window limit), m = tokens per month
const PLANS = {
  spark:  { w: 2e6, m: 15e6 },
  orbit:  { w: 0,   m: 30e6 },
  nova:   { w: 0,   m: 100e6 },
  cosmos: { w: 0,   m: 300e6 }
};
const INVITE_BONUS = { w: 250e3, m: 3e6 }; // for every confirmed invite after the first two
const WINDOW_SEC = 5 * 3600;

const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const err = (message, status, extra) => json({ error: Object.assign({ message }, extra || {}) }, status);

/* ---------- Firebase ID token check (local signature check, no extra round trip) ---------- */
let JWKS = null, JWKS_AT = 0;
async function jwks() {
  if (JWKS && Date.now() - JWKS_AT < 3600e3) return JWKS;
  const r = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
  const j = await r.json();
  const out = {};
  for (const k of j.keys || []) {
    out[k.kid] = await crypto.subtle.importKey('jwk', { kty: k.kty, n: k.n, e: k.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  }
  JWKS = out; JWKS_AT = Date.now();
  return out;
}
const b64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
async function verify(req) {
  const h = req.headers.get('authorization') || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  const parts = tok.split('.');
  if (parts.length !== 3) return null;
  try {
    const head = JSON.parse(new TextDecoder().decode(b64u(parts[0])));
    const p = JSON.parse(new TextDecoder().decode(b64u(parts[1])));
    if (head.alg !== 'RS256') return null;
    let keys = await jwks();
    if (!keys[head.kid]) { JWKS = null; keys = await jwks(); }
    const key = keys[head.kid];
    if (!key) return null;
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64u(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
    const now = Date.now() / 1000;
    if (!ok || p.aud !== PROJECT || p.iss !== 'https://securetoken.google.com/' + PROJECT || !p.sub || p.exp < now || p.iat > now + 300) return null;
    const provider = (p.firebase && p.firebase.sign_in_provider) || '';
    return { uid: p.sub, email: (p.email || '').toLowerCase(), verified: !!p.email_verified, provider, token: tok };
  } catch (e) { return null; }
}

/* ---------- storage (Upstash Redis REST) ---------- */
const R_URL = () => (process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '').trim().replace(/\/+$/, '');
const R_TOK = () => (process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '').trim();
const hasStore = () => !!(R_URL() && R_TOK());
async function redis(cmds) {
  const r = await fetch(R_URL() + '/pipeline', { method: 'POST', headers: { authorization: 'Bearer ' + R_TOK(), 'content-type': 'application/json' }, body: JSON.stringify(cmds) });
  if (!r.ok) throw new Error('store ' + r.status);
  return (await r.json()).map(x => x.result);
}
const ym = () => { const d = new Date(); return d.getUTCFullYear() + String(d.getUTCMonth() + 1).padStart(2, '0'); };
const nextMonth = () => { const d = new Date(); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1); };
async function refCodeOf(uid) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('mundora:' + uid)));
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = ''; for (let i = 0; i < 6; i++) s += A[h[i] % A.length];
  return 'MD-' + s;
}
const admins = () => (process.env.ADMIN_EMAILS || '').toLowerCase().split(/[\s,;]+/).filter(Boolean);

async function account(u) {
  const P = 'u:' + u.uid, M = ym();
  const [w, wttl, m, b, planRaw, inv, extra, bonus, ev] = await redis([
    ['GET', P + ':w'], ['PTTL', P + ':w'], ['GET', P + ':m:' + M], ['GET', P + ':b'],
    ['GET', P + ':plan'], ['SCARD', P + ':inv'], ['GET', P + ':x:' + M], ['GET', P + ':bonus'], ['GET', P + ':ev']
  ]);
  let plan = 'spark';
  try { const pr = planRaw ? JSON.parse(planRaw) : null; if (pr && PLANS[pr.id] && (!pr.until || pr.until > Date.now())) plan = pr.id; } catch (e) {}
  const verified = u.verified || ev === '1' || ev === 1;
  if (u.email && verified && admins().includes(u.email)) plan = 'cosmos';
  const L = PLANS[plan], over = Math.max(0, (+inv || 0) - 2);
  return {
    plan,
    w: { used: +w || 0, total: L.w ? L.w + over * INVITE_BONUS.w : 0, resetAt: wttl > 0 ? Date.now() + wttl : null },
    m: { used: +m || 0, total: L.m + over * INVITE_BONUS.m + (+extra || 0), resetAt: nextMonth() },
    builds: +b || 0, invites: +inv || 0, bonus: Math.max(0, +bonus || 0), verified
  };
}
async function charge(u, n, build) {
  if (!hasStore() || (!(n > 0) && !build)) return;
  const P = 'u:' + u.uid, M = ym(); n = Math.ceil(Math.max(0, n || 0));
  try {
    let rest = n;
    if (n > 0) {
      // bonus tokens are spent first, so the limits are not touched while they last
      const [left] = await redis([['DECRBY', P + ':bonus', n]]);
      if (left < 0) { rest = Math.min(n, -left); await redis([['INCRBY', P + ':bonus', -left]]); } else rest = 0;
    }
    const cmds = [];
    if (rest > 0) cmds.push(['SET', P + ':w', 0, 'EX', WINDOW_SEC, 'NX'], ['INCRBY', P + ':w', rest], ['SET', P + ':m:' + M, 0, 'EX', 40 * 86400, 'NX'], ['INCRBY', P + ':m:' + M, rest]);
    if (build) cmds.push(['INCR', P + ':b']);
    if (cmds.length) await redis(cmds);
  } catch (e) {}
}
// Our own token count: ~4 Latin letters, ~2.8 Cyrillic letters, ~2.5 digits per token; other symbols ~1.5 each
function countTokens(s) {
  if (!s) return 0;
  let lat = 0, cyr = 0, dig = 0, oth = 0;
  for (const ch of s) {
    if (/[a-z]/i.test(ch)) lat++;
    else if (/[Ѐ-ӿ]/.test(ch)) cyr++;
    else if (/\d/.test(ch)) dig++;
    else if (!/\s/.test(ch)) oth++;
  }
  return Math.ceil(lat / 4 + cyr / 2.8 + dig / 2.5 + oth / 1.5);
}
// Is this a quick, simple question? (then the answer is made fast and short)
function isSimple(text, mode) {
  if (mode && mode !== 'chat') return false;
  const t = (text || '').trim();
  if (!t || t.length > 180 || t.split('\n').length > 3 || t.includes('```')) return false;
  return !/(напиш|созда|сдела|код|сайт|программ|скрипт|подробн|проанализ|разбер|сравни|сочинени|эссе|статью|план |таблиц|переведи текст|write|create|build|make|code|script|program|website|detail|analy[sz]|compare|essay|article|table|step by step|по шагам)/i.test(t);
}
const NO_EFFORT = new Set(); // models whose API rejected reasoning_effort
const est = s => Math.ceil((s || '').length / 3);

/* ---------- model API ---------- */
async function upstream(base, key, payload, signal) {
  const send = p => fetch(base + '/chat/completions', { method: 'POST', headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' }, body: JSON.stringify(p), signal });
  let r = await send(payload);
  if (r.status === 400 && (payload.reasoning_effort || payload.max_tokens)) {
    const t = await r.text();
    if (/reasoning|max_tokens|unknown|unsupported|unrecognized|extra|not permitted/i.test(t)) {
      if (payload.reasoning_effort) NO_EFFORT.add(payload.model);
      const p2 = Object.assign({}, payload); delete p2.reasoning_effort; delete p2.max_tokens;
      r = await send(p2);
    } else return new Response(t, { status: 400, headers: { 'content-type': 'application/json' } });
  }
  return r;
}


/* ---------- email codes ---------- */
const hasMail = () => !!((process.env.BREVO_API_KEY || '').trim() && (process.env.MAIL_FROM || '').trim());
const needsCode = u => u.provider === 'password' && hasMail();
async function sha(s) { return [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, '0')).join(''); }
const MAIL_TXT = {
  en: { s: 'Your Mundora code: {c}', h: 'Confirm your email', p: 'Enter this code in Mundora to confirm your email. It works for 10 minutes.', f: 'If you didn’t sign up for Mundora, just ignore this email.' },
  ru: { s: 'Ваш код Mundora: {c}', h: 'Подтвердите почту', p: 'Введите этот код в Mundora, чтобы подтвердить почту. Он действует 10 минут.', f: 'Если вы не регистрировались в Mundora, просто проигнорируйте это письмо.' },
  uk: { s: 'Ваш код Mundora: {c}', h: 'Підтвердіть пошту', p: 'Введіть цей код у Mundora, щоб підтвердити пошту. Він діє 10 хвилин.', f: 'Якщо ви не реєструвалися в Mundora, просто проігноруйте цей лист.' }
};
async function sendCodeMail(to, code, lang) {
  const T = MAIL_TXT[lang] || MAIL_TXT.en;
  const digits = code.split('').map(d => `<td style="width:44px;height:56px;border-radius:12px;background:#1d1a29;color:#f6e9dc;font:700 28px/56px Arial,sans-serif;text-align:center">${d}</td>`).join('<td style="width:8px"></td>');
  const html = `<!doctype html><html><body style="margin:0;background:#0b0a12;padding:32px 12px;font-family:Arial,sans-serif">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td align="center">
<table role="presentation" width="440" cellspacing="0" cellpadding="0" style="max-width:440px;background:#13121c;border-radius:24px;padding:32px 28px;border:1px solid #272436">
<tr><td style="font:800 22px Arial,sans-serif;color:#f2eee8;letter-spacing:-.5px">mund<span style="color:#f2a8c4">ora</span></td></tr>
<tr><td style="padding-top:22px;font:700 24px Georgia,serif;color:#f2eee8">${T.h}</td></tr>
<tr><td style="padding-top:10px;font:15px/1.55 Arial,sans-serif;color:#a19dab">${T.p}</td></tr>
<tr><td style="padding-top:24px"><table role="presentation" cellspacing="0" cellpadding="0"><tr>${digits}</tr></table></td></tr>
<tr><td style="padding-top:26px;font:12.5px/1.5 Arial,sans-serif;color:#6f6b7a">${T.f}</td></tr>
</table></td></tr></table></body></html>`;
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': process.env.BREVO_API_KEY.trim(), 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ sender: { name: 'Mundora', email: process.env.MAIL_FROM.trim() }, to: [{ email: to }], subject: T.s.replace('{c}', code), htmlContent: html, textContent: T.h + ': ' + code })
  });
  if (!r.ok) throw new Error('mail ' + r.status + ' ' + (await r.text()).slice(0, 200));
}
const CONV_MAX = 300000;

export default async function handler(req) {
  const base = (process.env.AI_BASE || '').trim().replace(/\/+$/, '');
  const key = (process.env.AI_KEY || '').trim();
  const p = new URL(req.url).searchParams.get('p');
  if (!base || !key) return err('Server is not configured: add AI_BASE and AI_KEY in Vercel settings', 500);
  const u = await verify(req);
  if (!u) return err('Sign in again', 401);


  /* ---- email confirmation with a 6-digit code ---- */
  if (p === 'code-send' && req.method === 'POST') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    if (!hasMail()) return err('Email sending is not set up', 503, { code: 'nomail' });
    const P = 'u:' + u.uid;
    const [ev] = await redis([['GET', P + ':ev']]);
    if (u.verified || ev === '1') return json({ ok: true, already: true });
    if (!u.email) return err('No email on this account', 400);
    const [slot, wait, hour] = await redis([['SET', P + ':cs', 1, 'EX', 55, 'NX'], ['PTTL', P + ':cs'], ['INCR', P + ':ch']]);
    if (slot !== 'OK') return err('Wait before asking for a new code', 429, { code: 'wait', retryIn: Math.max(1000, +wait || 55000) });
    if (+hour === 1) redis([['EXPIRE', P + ':ch', 3600]]).catch(() => {});
    if (+hour > 6) return err('Too many codes — try again in an hour', 429, { code: 'hour' });
    const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
    const code = String(n).padStart(6, '0');
    await redis([['SET', P + ':code', await sha(u.uid + ':' + code), 'EX', 600], ['DEL', P + ':ca']]);
    const body = await req.json().catch(() => ({}));
    try { await sendCodeMail(u.email, code, String(body.lang || 'en')); }
    catch (e) { await redis([['DEL', P + ':cs']]).catch(() => {}); return err('Could not send the email: ' + e.message, 502, { code: 'mailfail' }); }
    return json({ ok: true, email: u.email, retryIn: 55000 });
  }
  if (p === 'code-check' && req.method === 'POST') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const P = 'u:' + u.uid;
    const body = await req.json().catch(() => ({}));
    const code = String(body.code || '').replace(/\D/g, '');
    const [tries, saved] = await redis([['INCR', P + ':ca'], ['GET', P + ':code'], ['EXPIRE', P + ':ca', 600]]);
    if (+tries > 5) return err('Too many attempts — ask for a new code', 429, { code: 'attempts' });
    if (!saved) return err('The code has expired — ask for a new one', 410, { code: 'expired' });
    if (code.length !== 6 || await sha(u.uid + ':' + code) !== saved) return json({ ok: false, left: Math.max(0, 5 - +tries) });
    await redis([['SET', P + ':ev', 1], ['DEL', P + ':code'], ['DEL', P + ':ca']]);
    return json({ ok: true });
  }

  /* ---- settings that follow the account: language, theme, model, speed, currency ---- */
  if (p === 'prefs' && req.method === 'GET') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const [v] = await redis([['GET', 'u:' + u.uid + ':prefs']]);
    return new Response(v || '{}', { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  }
  if (p === 'prefs' && req.method === 'POST') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const b = await req.json().catch(() => ({}));
    const o = { updated: +b.updated || Date.now() };
    if (/^(en|ru|uk)$/.test(b.lang)) o.lang = b.lang;
    if (/^(system|light|dark)$/.test(b.theme)) o.theme = b.theme;
    if (typeof b.model === 'string' && b.model.length < 120) o.model = b.model;
    if (/^(auto|fast|deep)$/.test(b.speed)) o.speed = b.speed;
    if (/^[a-z]{3}$/i.test(b.cur || '')) o.cur = String(b.cur).toLowerCase();
    await redis([['SET', 'u:' + u.uid + ':prefs', JSON.stringify(o)]]);
    return json({ ok: true });
  }

  /* ---- chat history, saved per account (works on every device) ---- */
  if (p === 'convs' && req.method === 'GET') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const [h] = await redis([['HGETALL', 'u:' + u.uid + ':convs']]);
    const list = [];
    if (Array.isArray(h)) for (let i = 0; i < h.length; i += 2) { try { list.push(JSON.parse(h[i + 1])); } catch (e) {} }
    else if (h && typeof h === 'object') for (const k in h) { try { list.push(JSON.parse(h[k])); } catch (e) {} }
    list.sort((a, b) => (b.updated || 0) - (a.updated || 0));
    return json({ list: list.slice(0, 200) });
  }
  if (p === 'conv' && req.method === 'GET') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const id = String(new URL(req.url).searchParams.get('id') || '').slice(0, 40);
    const [c] = await redis([['GET', 'u:' + u.uid + ':conv:' + id]]);
    if (!c) return err('Not found', 404);
    return new Response(c, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  }
  if (p === 'conv-save' && req.method === 'POST') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const c = await req.json().catch(() => null);
    if (!c || !/^[\w-]{4,40}$/.test(String(c.id || ''))) return err('Bad request', 400);
    const full = JSON.stringify({ id: c.id, title: String(c.title || '').slice(0, 80), mode: c.mode, model: c.model, created: +c.created || Date.now(), updated: +c.updated || Date.now(), messages: Array.isArray(c.messages) ? c.messages.slice(-120) : [] });
    if (full.length > CONV_MAX) return err('Conversation is too large', 413);
    const meta = JSON.stringify({ id: c.id, title: String(c.title || '').slice(0, 80), mode: c.mode, model: c.model, created: +c.created || Date.now(), updated: +c.updated || Date.now() });
    await redis([['SET', 'u:' + u.uid + ':conv:' + c.id, full], ['HSET', 'u:' + u.uid + ':convs', c.id, meta]]);
    return json({ ok: true });
  }
  if (p === 'conv-del' && req.method === 'POST') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const b = await req.json().catch(() => ({}));
    const id = String(b.id || '').slice(0, 40);
    await redis([['DEL', 'u:' + u.uid + ':conv:' + id], ['HDEL', 'u:' + u.uid + ':convs', id]]);
    return json({ ok: true });
  }

  if (p === 'models' && req.method === 'GET') {
    const r = await fetch(base + '/models', { headers: { authorization: 'Bearer ' + key } });
    return new Response(r.body, { status: r.status, headers: { 'content-type': r.headers.get('content-type') || 'application/json', 'cache-control': 'private, max-age=300' } });
  }

  if (p === 'usage' && req.method === 'GET') {
    const refCode = await refCodeOf(u.uid);
    if (!hasStore()) return json({ store: false, plan: 'spark', refCode, w: { used: 0, total: PLANS.spark.w, resetAt: null }, m: { used: 0, total: PLANS.spark.m, resetAt: nextMonth() }, builds: 0, invites: 0, bonus: 0 });
    redis([['SET', 'rc:' + refCode, u.uid, 'NX']]).catch(() => {});
    const acc = await account(u);
    return json(Object.assign({ store: true, refCode, provider: u.provider, needVerify: needsCode(u) && !acc.verified }, acc));
  }

  if (p === 'promo' && req.method === 'POST') {
    if (!hasStore()) return err('Storage is not connected', 503);
    const body = await req.json().catch(() => ({}));
    const code = String(body.code || '').trim().toUpperCase();
    const map = {};
    (process.env.PROMO_CODES || '').split(',').forEach(x => { const i = x.indexOf('='); if (i > 0) map[x.slice(0, i).trim().toUpperCase()] = x.slice(i + 1).trim(); });
    const val = map[code];
    if (!code || !val) return err('Code not found', 404, { code: 'promo_bad' });
    const P = 'u:' + u.uid;
    const [first] = await redis([['SET', P + ':promo:' + code, 1, 'NX']]);
    if (first !== 'OK') return err('Code already used', 409, { code: 'promo_used' });
    const pl = val.match(/^plan:(\w+):(\d+)$/i);
    if (pl && PLANS[pl[1].toLowerCase()]) {
      await redis([['SET', P + ':plan', JSON.stringify({ id: pl[1].toLowerCase(), until: Date.now() + (+pl[2]) * 86400e3 })]]);
      return json({ ok: true, plan: pl[1].toLowerCase(), days: +pl[2] });
    }
    const n = Math.max(0, parseInt(val, 10) || 0);
    if (!n) return err('Code not found', 404, { code: 'promo_bad' });
    await redis([['INCRBY', P + ':bonus', n]]);
    return json({ ok: true, tokens: n });
  }

  if (p === 'ref' && req.method === 'POST') {
    if (!hasStore()) return err('Storage is not connected', 503);
    const body = await req.json().catch(() => ({}));
    const code = String(body.code || '').trim().toUpperCase();
    const [inviter] 
