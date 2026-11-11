// Mundora AI server (Vercel Edge Function).
// Vercel → Settings → Environment Variables:
//   AI_BASE, AI_KEY                    — the model API (required)
//   KV_REST_API_URL, KV_REST_API_TOKEN — added automatically when Upstash Redis is connected (Storage tab)
//   ADMIN_EMAILS   (optional)          — e.g. "me@gmail.com"; these accounts get the Cosmos plan
//   BREVO_API_KEY, MAIL_FROM          — sending 6-digit email codes (MAIL_FROM = sender address confirmed in Brevo)
//   Admins get an admin panel on the site (#/admin): users, plans, bans, promo codes, sales.
//   PROMO_CODES    (optional)          — e.g. "MUNDO-START=5000000,MUNDO-ORBIT=plan:orbit:30"
//                                        (number = bonus tokens, spent before the limits; plan:<id>:<days> = plan for N days)
// Tokens are counted by Mundora itself from the text of each question and answer (the API's own figures are not used).
export const config = { runtime: 'edge' };

const PROJECT = 'mundora-78';
const FB_KEY = 'AIzaSyDl_HsF96Rz52BUISG6cYeXg_6joZkMxXk'; // public Firebase web key

// Limits per plan, like Claude: w = tokens per 5-hour window, m = tokens per week (7 days from the first request)
const PLANS = {
  spark:  { w: 30e3,  m: 180e3 },
  orbit:  { w: 500e3, m: 3.5e6 },
  nova:   { w: 1.5e6, m: 10e6 },
  cosmos: { w: 4e6,   m: 28e6 }
};
const WEEK_SEC = 7 * 86400;
// On the free plan every request costs at least 4 500 and at most 10 000 tokens:
// a short question ≈ 5–6 K, a big task (a site, long code) = 10 K → about 3–6 requests per 5 hours.
const costFor = (plan, tok) => plan === 'spark' ? Math.min(10000, 4500 + Math.max(0, tok)) : Math.max(0, tok);
const INVITE_BONUS = { w: 50e3, m: 300e3 }; // for every confirmed invite after the first two
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
    return { uid: p.sub, email: (p.email || '').toLowerCase(), name: p.name || '', verified: !!p.email_verified, provider, token: tok };
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
// Gmail ignores dots and "+tags", so pr.otakolov@gmail.com and protakolov@gmail.com are the same mailbox
function normEmail(e) {
  e = String(e || '').trim().toLowerCase().replace(/^["'<\s]+|["'>\s]+$/g, '');
  const i = e.lastIndexOf('@'); if (i < 1) return e;
  let local = e.slice(0, i), dom = e.slice(i + 1);
  if (dom === 'gmail.com' || dom === 'googlemail.com') { local = local.split('+')[0].replace(/\./g, ''); dom = 'gmail.com'; }
  return local + '@' + dom;
}
const admins = () => (process.env.ADMIN_EMAILS || '').split(/[\s,;]+/).map(normEmail).filter(x => x.includes('@'));
const isAdmin = (u, verified) => !!(u.email && verified && admins().includes(normEmail(u.email)));

async function account(u, extra) {
  const P = 'u:' + u.uid;
  const res = await redis([
    ['GET', P + ':w'], ['PTTL', P + ':w'], ['GET', P + ':wk'], ['GET', P + ':b'],
    ['GET', P + ':plan'], ['SCARD', P + ':inv'], ['PTTL', P + ':wk'], ['GET', P + ':bonus'], ['GET', P + ':ev']
  ].concat(extra || []));
  const [w, wttl, m, b, planRaw, inv, mttl, bonus, ev] = res;
  let plan = 'spark';
  try { const pr = planRaw ? JSON.parse(planRaw) : null; if (pr && PLANS[pr.id] && (!pr.until || pr.until > Date.now())) plan = pr.id; } catch (e) {}
  const verified = u.verified || ev === '1' || ev === 1;
  if (isAdmin(u, verified)) plan = 'cosmos';
  const L = PLANS[plan], over = Math.max(0, (+inv || 0) - 2);
  return {
    plan,
    w: { used: +w || 0, total: L.w + over * INVITE_BONUS.w, resetAt: wttl > 0 ? Date.now() + wttl : null },
    m: { used: +m || 0, total: L.m + over * INVITE_BONUS.m, resetAt: mttl > 0 ? Date.now() + mttl : null },
    builds: +b || 0, invites: +inv || 0, bonus: Math.max(0, +bonus || 0), verified, extra: res.slice(9)
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
    if (rest > 0) cmds.push(['SET', P + ':w', 0, 'EX', WINDOW_SEC, 'NX'], ['INCRBY', P + ':w', rest], ['SET', P + ':wk', 0, 'EX', WEEK_SEC, 'NX'], ['INCRBY', P + ':wk', rest]);
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
const needsCode = u => u.provider === 'password';
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
const SUPPORT = 'mundoraaiapp@gmail.com';
const ADMIN_ACTIONS = ['plan', 'tokens', 'freeze', 'delete', 'restore', 'reset', 'disc'];
const now = () => Date.now();
const parseJ = (v, d) => { try { return v ? JSON.parse(v) : d; } catch (e) { return d; } };
// Which models are only for paid plans (Orbit and higher). The admin can change this per model in the admin panel.
const IMAGE_RE = /(gpt-image|dall-e-3|imagen|flux|recraft|ideogram|seedream|nano-banana|image|stable-diffusion|sdxl|midjourney|kandinsky)/i;
const isImageModel = id => IMAGE_RE.test(String(id || '')) && !/dall-e-2/i.test(id);
// For now every model is free on every plan; the admin panel can still mark a model as paid.
const defaultPremium = id => false;
async function modelRules() { try { const [v] = await redis([['GET', 'cfg:models']]); return parseJ(v, {}) || {}; } catch (e) { return {}; } }
const isPremium = (id, rules) => rules && rules[id] ? rules[id] === 'premium' : defaultPremium(id);
const IMAGE_TOKENS = 10000; // one picture      // one generated image costs this many tokens from the limits
const ATTACH_MB = { spark: 25, orbit: 100, nova: 250, cosmos: 500 };
const activeSale = s => s && s.percent > 0 && (!s.until || s.until > now()) ? s : null;
const MODEL_CACHE = { at: 0, body: null };

/* ---------- picture generation through the model API ---------- */
// 1) /images/generations with an image model, 2) /responses with the image tool on a GPT model,
// 3) /chat/completions with image output on a GPT model
async function imageWays(base, key, chatModel, saved, all) {
  let ids = [];
  try {
    if (!(MODEL_CACHE.body && Date.now() - MODEL_CACHE.at < 600e3)) {
      const r = await fetch(base + '/models', { headers: { authorization: 'Bearer ' + key } });
      if (r.ok) { MODEL_CACHE.body = await r.text(); MODEL_CACHE.at = Date.now(); }
    }
    const j = parseJ(MODEL_CACHE.body, {});
    ids = (Array.isArray(j) ? j : (j.data || j.models || [])).map(m => typeof m === 'string' ? m : m && (m.id || m.name)).filter(Boolean);
  } catch (e) {}
  const imgIds = ids.filter(isImageModel).sort((a, b) => (/gpt-image/i.test(b) ? 1 : 0) - (/gpt-image/i.test(a) ? 1 : 0) || b.localeCompare(a, 'en', { numeric: true }));
  const gpts = ids.filter(id => /^(chat)?gpt-?\d/i.test(id.split('/').pop()) && !isImageModel(id) && !/(audio|realtime|tts|transcri|search)/i.test(id));
  gpts.sort((a, b) => b.localeCompare(a, 'en', { numeric: true }));
  const chat = chatModel && gpts.includes(chatModel) ? chatModel : (chatModel || gpts[0] || '');
  const list = [];
  imgIds.slice(0, all ? 4 : 2).forEach(m => list.push({ kind: 'images', model: m }));
  if (!imgIds.length) ['gpt-image-1', 'dall-e-3'].forEach(m => list.push({ kind: 'images', model: m }));
  if (chat) { list.push({ kind: 'responses', model: chat }); list.push({ kind: 'chat', model: chat }); }
  if (saved && saved.kind) list.unshift({ kind: saved.kind, model: saved.kind === 'images' ? saved.model : (chat || saved.model) });
  const seen = new Set();
  return list.filter(w => { const k = w.kind + w.model; if (seen.has(k)) return false; seen.add(k); return true; });
}
async function tryImageWay(base, key, w, prompt, signal, timeout) {
  const ctl = new AbortController();
  const tm = setTimeout(() => ctl.abort(), timeout || 90000);
  if (signal) signal.addEventListener('abort', () => ctl.abort());
  const post = (path, body) => fetch(base + path, { method: 'POST', headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' }, body: JSON.stringify(body), signal: ctl.signal });
  const fail = async (r, what) => ({ ok: false, detail: what + ' → HTTP ' + r.status + ' ' + (await r.text().catch(() => '')).slice(0, 160) });
  try {
    if (w.kind === 'images') {
      let r = await post('/images/generations', { model: w.model, prompt, n: 1, size: '1024x1024' });
      if (r.status === 400) r = await post('/images/generations', { model: w.model, prompt, n: 1 });
      if (!r.ok) return await fail(r, '/images/generations');
      const j = await r.json().catch(() => ({}));
      const images = (j.data || []).map(d => d.url ? { url: d.url } : d.b64_json ? { b64: d.b64_json } : null).filter(Boolean);
      return images.length ? { ok: true, images } : { ok: false, detail: 'no image in the answer' };
    }
    if (w.kind === 'responses') {
      const r = await post('/responses', { model: w.model, input: prompt, tools: [{ type: 'image_generation' }] });
      if (!r.ok) return await fail(r, '/responses');
      const j = await r.json().catch(() => ({}));
      const images = (j.output || []).filter(o => o && o.type === 'image_generation_call' && o.result).map(o => ({ b64: o.result }));
      return images.length ? { ok: true, images } : { ok: false, detail: '/responses answered without a picture' };
    }
    if (w.kind === 'chat') {
      const r = await post('/chat/completions', { model: w.model, modalities: ['image', 'text'], messages: [{ role: 'user', content: 'Generate an image: ' + prompt }] });
      if (!r.ok) return await fail(r, '/chat/completions');
      const j = await r.json().catch(() => ({}));
      const msg = j.choices && j.choices[0] && j.choices[0].message || {};
      const found = [];
      (msg.images || []).forEach(x => { const u = x && (x.image_url && x.image_url.url || x.url); if (u) found.push(u); });
      if (Array.isArray(msg.content)) msg.content.forEach(x => { const u = x && (x.image_url && x.image_url.url || (x.type === 'output_image' && (x.image_url || x.url))); if (u) found.push(u); if (x && x.b64_json) found.push('data:image/png;base64,' + x.b64_json); });
      if (typeof msg.content === 'string') { const m = msg.content.match(/(data:image\/[a-z]+;base64,[A-Za-z0-9+/=]{200,})|(https?:\/\/\S+\.(?:png|jpe?g|webp)(?:\?\S*)?)/i); if (m) found.push(m[0]); }
      const images = found.map(u => /^data:/.test(u) ? { b64: u.replace(/^data:image\/[a-z]+;base64,/i, '') } : { url: u });
      return images.length ? { ok: true, images } : { ok: false, detail: '/chat/completions answered with text only' };
    }
    return { ok: false, detail: 'unknown way' };
  } catch (e) { return { ok: false, detail: e && e.name === 'AbortError' ? 'timeout' : String(e && e.message || e) }; }
  finally { clearTimeout(tm); }
}
function streamJSON(work) {
  const enc = new TextEncoder();
  const stream = new ReadableStream({
    async start(ctrl) {
      const ping = setInterval(() => { try { ctrl.enqueue(enc.encode(' ')); } catch (e) {} }, 5000);
      let out;
      try { out = await work(); } catch (e) { out = { error: { message: String(e && e.message || e) } }; }
      clearInterval(ping);
      ctrl.enqueue(enc.encode(JSON.stringify(out))); ctrl.close();
    }
  });
  return new Response(stream, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
}


export default async function handler(req) {
  const base = (process.env.AI_BASE || '').trim().replace(/\/+$/, '');
  const key = (process.env.AI_KEY || '').trim();
  const p = new URL(req.url).searchParams.get('p');
  // open https://<site>/api/ai?p=health in a browser to check the server setup
  if (p === 'health') return json({ ok: true, version: 21, ai: !!(base && key), store: hasStore(), mail: hasMail(), admins: admins().length });
  if (!base || !key) return err('Server is not configured: add AI_BASE and AI_KEY in Vercel settings', 500);
  const u = await verify(req);
  if (!u) return err('Sign in again', 401);

  // account status (frozen / deleted) and admin rights
  let status = null, evFlag = null;
  if (hasStore() && p !== 'chat') {
    try { const [st, ev] = await redis([['GET', 'u:' + u.uid + ':status'], ['GET', 'u:' + u.uid + ':ev']]); status = parseJ(st, null); evFlag = ev; } catch (e) {}
  }
  const admin = isAdmin(u, u.verified || evFlag === '1');
  if (status && !admin && !['usage', 'prefs'].includes(p)) return err('Account ' + status.s, 403, { code: 'blocked', status: status.s, support: SUPPORT });



  if (p === 'status' && req.method === 'GET') return json({ blocked: status && !admin ? status : null, admin });

  /* ================= ADMIN PANEL ================= */
  if (p && p.startsWith('admin')) {
    if (!admin) return err('Not allowed', 403, { code: 'notadmin' });
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const userCard = async uid => {
      const [email, name, seen, st, inv] = await redis([['GET', 'u:' + uid + ':email'], ['GET', 'u:' + uid + ':name'], ['GET', 'u:' + uid + ':seen'], ['GET', 'u:' + uid + ':status'], ['GET', 'u:' + uid + ':disc']]);
      if (!email && !name && !seen) return null;
      const acc = await account({ uid, email: email || '', verified: true });
      const [pl] = await redis([['GET', 'u:' + uid + ':plan']]);
      return { uid, email, name, seen: +seen || 0, status: parseJ(st, null), disc: parseJ(inv, null), planInfo: parseJ(pl, null), ...acc };
    };

    if (p === 'admin-models' && req.method === 'GET') {
      const rules = await modelRules();
      let ids = [];
      try { const j = JSON.parse(MODEL_CACHE.body || 'null') || (await (await fetch(base + '/models', { headers: { authorization: 'Bearer ' + key } })).json()); ids = (Array.isArray(j) ? j : (j.data || j.models || [])).map(m => typeof m === 'string' ? m : m && m.id).filter(Boolean); } catch (e) {}
      return json({ list: ids.map(id => ({ id, image: isImageModel(id), premium: isPremium(id, rules), custom: !!rules[id] })) });
    }
    if (p === 'admin-models' && req.method === 'POST') {
      const b = await req.json().catch(() => ({}));
      const rules = await modelRules();
      if (b.reset) delete rules[b.id]; else rules[String(b.id)] = b.premium ? 'premium' : 'free';
      await redis([['SET', 'cfg:models', JSON.stringify(rules)]]);
      return json({ ok: true });
    }
    if (p === 'admin-stats' && req.method === 'GET') {
      const t0 = now();
      const [n, day, week, promos, sale, ids] = await redis([['SCARD', 'users'], ['ZCOUNT', 'users:seen', t0 - 86400e3, '+inf'], ['ZCOUNT', 'users:seen', t0 - 7 * 86400e3, '+inf'], ['HLEN', 'promos'], ['GET', 'cfg:sale'], ['ZREVRANGE', 'tks', 0, 200]]);
      let tickets = 0;
      if (ids && ids.length) { const ts = (await redis(ids.map(id => ['GET', 'tk:' + id]))).map(v => parseJ(v, null)); tickets = ts.filter(t => t && t.status === 'open' && (!t.claimedBy || t.claimedBy === u.uid)).length; }
      return json({ users: +n || 0, day: +day || 0, week: +week || 0, promos: +promos || 0, sale: activeSale(parseJ(sale, null)), tickets });
    }
    if (p === 'admin-recent' && req.method === 'GET') {
      const [ids] = await redis([['ZREVRANGE', 'users:seen', 0, 24]]);
      if (!ids || !ids.length) return json({ list: [] });
      const cmds = []; ids.forEach(id => cmds.push(['GET', 'u:' + id + ':email'], ['GET', 'u:' + id + ':name'], ['GET', 'u:' + id + ':seen'], ['GET', 'u:' + id + ':status'], ['GET', 'u:' + id + ':plan']));
      const r = await redis(cmds);
      const list = ids.map((id, i) => { const pl = parseJ(r[i * 5 + 4], null); return { uid: id, email: r[i * 5], name: r[i * 5 + 1], seen: +r[i * 5 + 2] || 0, status: parseJ(r[i * 5 + 3], null), plan: pl && PLANS[pl.id] && (!pl.until || pl.until > now()) ? pl.id : 'spark' }; });
      list.forEach(x => { if (x.email && admins().includes(normEmail(x.email))) x.plan = 'cosmos'; });
      return json({ list });
    }
    if (p === 'admin-find' && req.method === 'GET') {
      const q = String(new URL(req.url).searchParams.get('q') || '').trim();
      let uid = null;
      if (q.includes('@')) { const [x] = await redis([['GET', 'em:' + normEmail(q)]]); uid = x; }
      else if (q) uid = q;
      const card = uid ? await userCard(uid) : null;
      if (!card) return err('User not found', 404, { code: 'nouser' });
      return json(card);
    }
    if (p === 'admin-act' && req.method === 'POST') {
      const b = await req.json().catch(() => ({}));
      const uid = String(b.uid || ''); const P = 'u:' + uid;
      if (!uid || !ADMIN_ACTIONS.includes(b.action)) return err('Bad request', 400);
      if (b.action === 'plan') {
        if (b.plan === 'spark' || !PLANS[b.plan]) await redis([['DEL', P + ':plan']]);
        else { const days = Math.max(0, +b.days || 0); await redis([['SET', P + ':plan', JSON.stringify({ id: b.plan, until: days ? now() + days * 86400e3 : 0, by: 'admin' })]]); }
      }
      if (b.action === 'tokens') {
        const n = Math.round(+b.n || 0);
        const [v] = await redis([['INCRBY', P + ':bonus', n]]);
        if (+v < 0) await redis([['SET', P + ':bonus', 0]]);
      }
      if (b.action === 'disc') {
        const pc = Math.min(90, Math.max(0, +b.percent || 0)), days = Math.max(1, +b.days || 30);
        if (!pc) await redis([['DEL', P + ':disc']]);
        else await redis([['SET', P + ':disc', JSON.stringify({ percent: pc, plans: b.plans || 'all', until: now() + days * 86400e3, by: 'admin' })]]);
      }
      if (b.action === 'freeze' || b.action === 'delete') await redis([['SET', P + ':status', JSON.stringify({ s: b.action === 'freeze' ? 'frozen' : 'deleted', at: now(), reason: String(b.reason || '').slice(0, 200) })]]);
      if (b.action === 'restore') await redis([['DEL', P + ':status']]);
      if (b.action === 'reset') await redis([['DEL', P + ':w'], ['DEL', P + ':wk']]);
      return json(await userCard(uid));
    }
    if (p === 'admin-promos' && req.method === 'GET') {
      const [h] = await redis([['HGETALL', 'promos']]);
      const list = [];
      const pairs = Array.isArray(h) ? h : Object.entries(h || {}).flat();
      for (let i = 0; i < pairs.length; i += 2) { const v = parseJ(pairs[i + 1], null); if (v) list.push(Object.assign({ code: pairs[i] }, v)); }
      if (list.length) { const uses = await redis(list.map(x => ['GET', 'promo:uses:' + x.code])); list.forEach((x, i) => { x.uses = +uses[i] || 0; }); }
      list.sort((a, b) => (b.created || 0) - (a.created || 0));
      return json({ list });
    }
    if (p === 'admin-promo' && req.method === 'POST') {
      const b = await req.json().catch(() => ({}));
      const code = String(b.code || '').trim().toUpperCase().replace(/\s+/g, '');
      if (!/^[A-Z0-9_-]{3,32}$/.test(code)) return err('Code: 3–32 letters, digits, - or _', 400, { code: 'badcode' });
      const type = ['tokens', 'plan', 'discount'].includes(b.type) ? b.type : 'tokens';
      const v = { type, value: Math.max(0, +b.value || 0), plan: PLANS[b.plan] ? b.plan : 'orbit', days: Math.max(1, +b.days || 30), maxUses: Math.max(0, +b.maxUses || 0), expires: +b.expires || 0, plans: b.plans || 'all', note: String(b.note || '').slice(0, 120), created: now(), off: !!b.off };
      await redis([['HSET', 'promos', code, JSON.stringify(v)]]);
      return json({ ok: true, code });
    }
    if (p === 'admin-promo-del' && req.method === 'POST') {
      const b = await req.json().catch(() => ({}));
      const code = String(b.code || '').toUpperCase();
      await redis([['HDEL', 'promos', code], ['DEL', 'promo:uses:' + code]]);
      return json({ ok: true });
    }
    if (p === 'admin-sale' && req.method === 'GET') {
      const [v] = await redis([['GET', 'cfg:sale']]);
      return json({ sale: parseJ(v, null) });
    }
    if (p === 'admin-sale' && req.method === 'POST') {
      const b = await req.json().catch(() => ({}));
      const pc = Math.min(90, Math.max(0, +b.percent || 0));
      if (!pc) { await redis([['DEL', 'cfg:sale']]); return json({ sale: null }); }
      const sale = { percent: pc, plans: b.plans || 'all', until: +b.until || 0, text: { en: String(b.text_en || '').slice(0, 140), ru: String(b.text_ru || '').slice(0, 140), uk: String(b.text_uk || '').slice(0, 140) } };
      await redis([['SET', 'cfg:sale', JSON.stringify(sale)]]);
      return json({ sale });
    }
    return err('Not found', 404);
  }


  /* ================= SUPPORT TICKETS =================
     A user writes to support; every admin sees new tickets. The first admin who answers takes the ticket:
     after that only he sees it and writes in it. Admins change the status (in progress / answered / closed). */
  if (p && p.startsWith('tk-')) {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const b = req.method === 'POST' ? await req.json().catch(() => ({})) : {};
    const qid = String(new URL(req.url).searchParams.get('id') || b.id || '').slice(0, 40);
    const getT = async id => { const [v] = await redis([['GET', 'tk:' + id]]); return parseJ(v, null); };
    const putT = t => redis([['SET', 'tk:' + t.id, JSON.stringify(t)], ['ZADD', 'tks', t.updated, t.id], ['ZADD', 'u:' + t.uid + ':tks', t.updated, t.id]]);
    const meta = (t, forAdmin) => ({ id: t.id, subject: t.subject, status: t.status, created: t.created, updated: t.updated, last: t.messages.length ? t.messages[t.messages.length - 1].from : 'user',
      unread: forAdmin ? !t.seenAdmin : !t.seenUser, email: forAdmin ? t.email : undefined, name: forAdmin ? t.name : undefined, mine: forAdmin ? t.claimedBy === u.uid : undefined, claimed: forAdmin ? !!t.claimedBy : undefined, n: t.messages.length });
    const visibleToAdmin = t => admin && (!t.claimedBy || t.claimedBy === u.uid);
    const cleanText = x => String(x || '').trim().slice(0, 4000);
    const [myName] = await redis([['GET', 'u:' + u.uid + ':name']]);

    if (p === 'tk-new' && req.method === 'POST') {
      const subject = String(b.subject || '').trim().slice(0, 120), text = cleanText(b.text);
      if (!subject || !text) return err('Write a subject and a message', 400, { code: 'empty' });
      const [ids] = await redis([['ZREVRANGE', 'u:' + u.uid + ':tks', 0, 30]]);
      const open = ids && ids.length ? (await redis(ids.map(id => ['GET', 'tk:' + id]))).map(v => parseJ(v, null)).filter(t => t && t.status !== 'closed').length : 0;
      if (open >= 5) return err('Too many open tickets', 429, { code: 'toomany' });
      const id = 't' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      const t = { id, uid: u.uid, email: u.email, name: myName || u.name || '', subject, status: 'open', created: now(), updated: now(), claimedBy: null, claimedName: null, seenUser: true, seenAdmin: false,
        messages: [{ from: 'user', name: myName || u.name || '', text, at: now() }] };
      await putT(t);
      return json(t);
    }
    if (p === 'tk-mine' && req.method === 'GET') {
      const [ids] = await redis([['ZREVRANGE', 'u:' + u.uid + ':tks', 0, 99]]);
      const list = ids && ids.length ? (await redis(ids.map(id => ['GET', 'tk:' + id]))).map(v => parseJ(v, null)).filter(Boolean).map(t => meta(t, false)) : [];
      return json({ list });
    }
    if (p === 'tk-all' && req.method === 'GET') {
      if (!admin) return err('Not allowed', 403, { code: 'notadmin' });
      const [ids] = await redis([['ZREVRANGE', 'tks', 0, 299]]);
      const list = ids && ids.length ? (await redis(ids.map(id => ['GET', 'tk:' + id]))).map(v => parseJ(v, null)).filter(t => t && visibleToAdmin(t)).map(t => meta(t, true)) : [];
      return json({ list });
    }
    if (p === 'tk-get' && req.method === 'GET') {
      const t = await getT(qid);
      if (!t || !(t.uid === u.uid || visibleToAdmin(t))) return err('Not found', 404, { code: 'notfound' });
      const asAdmin = t.uid !== u.uid;
      if (asAdmin && !t.seenAdmin) { t.seenAdmin = true; await redis([['SET', 'tk:' + t.id, JSON.stringify(t)]]); }
      if (!asAdmin && !t.seenUser) { t.seenUser = true; await redis([['SET', 'tk:' + t.id, JSON.stringify(t)]]); }
      return json(Object.assign({}, t, { asAdmin, canWrite: !asAdmin || !t.claimedBy || t.claimedBy === u.uid }));
    }
    if (p === 'tk-msg' && req.method === 'POST') {
      const t = await getT(qid), text = cleanText(b.text);
      if (!t || !text) return err('Not found', 404, { code: 'notfound' });
      if (t.uid === u.uid && !(admin && b.asAdmin)) {
        t.messages.push({ from: 'user', name: myName || t.name, text, at: now() });
        t.status = 'open'; t.seenAdmin = false;
      } else {
        if (!admin) return err('Not allowed', 403, { code: 'notadmin' });
        if (t.claimedBy && t.claimedBy !== u.uid) return err('Another admin is answering this ticket', 409, { code: 'claimed' });
        if (!t.claimedBy) { t.claimedBy = u.uid; t.claimedName = myName || u.email; }
        t.messages.push({ from: 'admin', name: myName || 'Mundora', text, at: now() });
        t.status = 'answered'; t.seenUser = false; t.seenAdmin = true;
      }
      t.messages = t.messages.slice(-150); t.updated = now();
      await putT(t);
      return json(Object.assign({}, t, { asAdmin: t.uid !== u.uid, canWrite: true }));
    }
    if (p === 'tk-status' && req.method === 'POST') {
      if (!admin) return err('Not allowed', 403, { code: 'notadmin' });
      const t = await getT(qid);
      if (!t || !visibleToAdmin(t)) return err('Not found', 404, { code: 'notfound' });
      if (!['open', 'answered', 'closed'].includes(b.status)) return err('Bad status', 400);
      t.status = b.status; t.updated = now(); if (b.status !== 'open') t.seenUser = false;
      await putT(t);
      return json(Object.assign({}, t, { asAdmin: true, canWrite: !t.claimedBy || t.claimedBy === u.uid }));
    }
    if (p === 'tk-count' && req.method === 'GET') {
      const [mine] = await redis([['ZREVRANGE', 'u:' + u.uid + ':tks', 0, 50]]);
      const ts = mine && mine.length ? (await redis(mine.map(id => ['GET', 'tk:' + id]))).map(v => parseJ(v, null)).filter(Boolean) : [];
      let forAdmin = 0;
      if (admin) {
        const [ids] = await redis([['ZREVRANGE', 'tks', 0, 200]]);
        const all = ids && ids.length ? (await redis(ids.map(id => ['GET', 'tk:' + id]))).map(v => parseJ(v, null)).filter(t => t && visibleToAdmin(t) && t.uid !== u.uid) : [];
        forAdmin = all.filter(t => !t.seenAdmin && t.status !== 'closed').length;
      }
      return json({ user: ts.filter(t => !t.seenUser).length, admin: forAdmin });
    }
    return err('Not found', 404);
  }


  /* ---- long-term memory ---- */
  if (p === 'mem' && req.method === 'GET') {
    if (!hasStore()) return json({ text: '', on: false });
    const [m, off] = await redis([['GET', 'u:' + u.uid + ':mem'], ['GET', 'u:' + u.uid + ':memoff']]);
    return json({ text: m || '', on: off !== '1' });
  }
  if (p === 'mem-set' && req.method === 'POST') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const b = await req.json().catch(() => ({}));
    const cmds = [];
    if (typeof b.on === 'boolean') cmds.push(b.on ? ['DEL', 'u:' + u.uid + ':memoff'] : ['SET', 'u:' + u.uid + ':memoff', '1']);
    if (b.clear) cmds.push(['DEL', 'u:' + u.uid + ':mem']);
    if (cmds.length) await redis(cmds);
    return json({ ok: true });
  }
  if (p === 'mem-learn' && req.method === 'POST') {
    if (!hasStore()) return json({ ok: false });
    const b = await req.json().catch(() => ({}));
    const q = String(b.q || '').slice(0, 2000), a = String(b.a || '').slice(0, 2500);
    if (q.length < 12) return json({ ok: false });
    const P = 'u:' + u.uid;
    const [lock, off, cur] = await redis([['SET', P + ':memlock', 1, 'EX', 90, 'NX'], ['GET', P + ':memoff'], ['GET', P + ':mem']]);
    if (lock !== 'OK' || off === '1') return json({ ok: false });
    let ids = [];
    try { const j = parseJ(MODEL_CACHE.body, {}); ids = (Array.isArray(j) ? j : (j.data || [])).map(m => typeof m === 'string' ? m : m && m.id).filter(Boolean); } catch (e) {}
    const cheap = ids.find(id => /^(chat)?gpt.*(mini|nano)/i.test(id)) || ids.find(id => /haiku/i.test(id)) || ids.find(id => /sonnet/i.test(id)) || String(b.model || '');
    if (!cheap) return json({ ok: false });
    const ctl = new AbortController(); const tm = setTimeout(() => ctl.abort(), 25000);
    try {
      const r = await fetch(base + '/chat/completions', { method: 'POST', signal: ctl.signal, headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' }, body: JSON.stringify({ model: cheap, stream: false, max_tokens: 600, messages: [
        { role: 'system', content: 'You keep a short long-term memory about one user of an AI assistant. Keep only durable, useful facts: name, language, job or studies, preferences, ongoing projects, goals, important personal context. No secrets like passwords or card numbers. At most 14 short bullet points, at most 1300 characters, written in the user\'s language. If the new exchange adds nothing durable, return the memory unchanged. Output only the memory.' },
        { role: 'user', content: 'Current memory:\n' + (cur || '(empty)') + '\n\nNew exchange:\nUser: ' + q + '\nAssistant: ' + a } ] }) });
      if (!r.ok) return json({ ok: false });
      const j = await r.json().catch(() => ({}));
      const out = String((j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || '').trim().slice(0, 1600);
      if (out.length > 5 && !/^\(empty\)$/i.test(out)) await redis([['SET', P + ':mem', out]]);
      return json({ ok: true });
    } catch (e) { return json({ ok: false }); } finally { clearTimeout(tm); }
  }

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
    const full = JSON.stringify({ id: c.id, title: String(c.title || '').slice(0, 80), mode: c.mode, kind: c.kind || null, model: c.model, created: +c.created || Date.now(), updated: +c.updated || Date.now(), messages: Array.isArray(c.messages) ? c.messages.slice(-120) : [] });
    if (full.length > CONV_MAX) return err('Conversation is too large', 413);
    const lastQ = (Array.isArray(c.messages) ? [...c.messages].reverse().find(m => m && m.role === 'user' && m.text) : null);
    const meta = JSON.stringify({ id: c.id, title: String(c.title || '').slice(0, 80), mode: c.mode, model: c.model, created: +c.created || Date.now(), updated: +c.updated || Date.now(), last: lastQ ? String(lastQ.text).slice(0, 140) : '' });
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

  /* ---- projects (sites, code, games), saved per account ---- */
  if (p === 'projs' && req.method === 'GET') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const [h] = await redis([['HGETALL', 'u:' + u.uid + ':projs']]);
    const list = [], pairs = Array.isArray(h) ? h : Object.entries(h || {}).flat();
    for (let i = 0; i < pairs.length; i += 2) { const v = parseJ(pairs[i + 1], null); if (v) list.push(v); }
    list.sort((a, b) => (b.updated || 0) - (a.updated || 0));
    return json({ list: list.slice(0, 300) });
  }
  if (p === 'proj' && req.method === 'GET') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const id = String(new URL(req.url).searchParams.get('id') || '').slice(0, 48);
    const [c] = await redis([['GET', 'u:' + u.uid + ':proj:' + id]]);
    if (!c) return err('Not found', 404);
    return new Response(c, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  }
  if (p === 'proj-save' && req.method === 'POST') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const c = await req.json().catch(() => null);
    if (!c || !/^[\w-]{4,48}$/.test(String(c.id || ''))) return err('Bad request', 400);
    const meta = { id: c.id, type: String(c.type || 'code').slice(0, 10), title: String(c.title || '').slice(0, 80), conv: String(c.conv || '').slice(0, 48), created: +c.created || now(), updated: +c.updated || now(), n: Array.isArray(c.versions) ? c.versions.length : 0 };
    let versions = Array.isArray(c.versions) ? c.versions.slice(-8) : [];
    let full = JSON.stringify(Object.assign({}, meta, { versions }));
    while (full.length > CONV_MAX && versions.length > 1) { versions = versions.slice(1); full = JSON.stringify(Object.assign({}, meta, { versions })); }
    if (full.length > CONV_MAX) return err('Project is too large', 413);
    await redis([['SET', 'u:' + u.uid + ':proj:' + c.id, full], ['HSET', 'u:' + u.uid + ':projs', c.id, JSON.stringify(meta)]]);
    return json({ ok: true });
  }
  if (p === 'proj-del' && req.method === 'POST') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const b = await req.json().catch(() => ({}));
    const id = String(b.id || '').slice(0, 48);
    await redis([['DEL', 'u:' + u.uid + ':proj:' + id], ['HDEL', 'u:' + u.uid + ':projs', id]]);
    return json({ ok: true });
  }

  if (p === 'models' && req.method === 'GET') {
    // the list is kept in server memory for 10 minutes, so it comes back instantly
    if (!(MODEL_CACHE.body && Date.now() - MODEL_CACHE.at < 600e3)) {
      const r = await fetch(base + '/models', { headers: { authorization: 'Bearer ' + key } });
      const body = await r.text();
      if (r.ok) { MODEL_CACHE.body = body; MODEL_CACHE.at = Date.now(); }
      else if (!MODEL_CACHE.body) return new Response(body, { status: r.status, headers: { 'content-type': r.headers.get('content-type') || 'application/json' } });
    }
    const rules = hasStore() ? await modelRules() : {};
    const j = parseJ(MODEL_CACHE.body, {});
    const ids = (Array.isArray(j) ? j : (j.data || j.models || [])).map(m => typeof m === 'string' ? m : m && (m.id || m.name)).filter(Boolean);
    return json({ data: ids.map(id => ({ id, premium: isPremium(id, rules), image: isImageModel(id) })) });
  }

  if (p === 'usage' && req.method === 'GET') {
    const refCode = await refCodeOf(u.uid);
    if (!hasStore()) { const pl = isAdmin(u, u.verified) ? 'cosmos' : 'spark'; return json({ store: false, admin, attachMB: ATTACH_MB[pl], needVerify: needsCode(u) && !u.verified, plan: pl, refCode, w: { used: 0, total: PLANS[pl].w, resetAt: null }, m: { used: 0, total: PLANS[pl].m, resetAt: null }, builds: 0, invites: 0, bonus: 0 }); }
    const name = String(new URL(req.url).searchParams.get('n') || u.name || '').slice(0, 60);
    redis([['SET', 'rc:' + refCode, u.uid, 'NX'], ['SET', 'em:' + normEmail(u.email), u.uid], ['SET', 'u:' + u.uid + ':email', u.email], ['SET', 'u:' + u.uid + ':name', name], ['SET', 'u:' + u.uid + ':seen', now()], ['SADD', 'users', u.uid], ['ZADD', 'users:seen', now(), u.uid]]).catch(() => {});
    const acc = await account(u);
    const [saleRaw, discRaw] = await redis([['GET', 'cfg:sale'], ['GET', 'u:' + u.uid + ':disc']]);
    const disc = parseJ(discRaw, null);
    return json(Object.assign({ store: true, refCode, provider: u.provider, admin, support: SUPPORT, attachMB: ATTACH_MB[acc.plan] || 25,
      needVerify: needsCode(u) && !u.verified && !acc.verified,
      blocked: status && !admin ? status : null,
      sale: activeSale(parseJ(saleRaw, null)),
      disc: disc && disc.percent > 0 && (!disc.until || disc.until > now()) ? disc : null }, acc));
  }

  if (p === 'promo' && req.method === 'POST') {
    if (!hasStore()) return err('Storage is not connected', 503, { code: 'nostore' });
    const body = await req.json().catch(() => ({}));
    const code = String(body.code || '').trim().toUpperCase();
    const map = {};
    // PROMO_CODES is read leniently: commas, semicolons or new lines between codes; "=" or ":" after the code; quotes and spaces are ignored
    String(process.env.PROMO_CODES || '').replace(/^["']|["']$/g, '').split(/[,;\n]+/).forEach(x => {
      const m = x.trim().replace(/^["']|["']$/g, '').match(/^([A-Za-z0-9_-]+)\s*[=:]\s*(.+)$/);
      if (m) map[m[1].toUpperCase()] = m[2].trim().replace(/\s+/g, '').replace(/^["']|["']$/g, '');
    });
    const P = 'u:' + u.uid;
    const [pr] = await redis([['HGET', 'promos', code]]);
    const promo = parseJ(pr, null);
    if (promo) {
      if (promo.off) return err('Code not found', 404, { code: 'promo_bad' });
      if (promo.expires && promo.expires < now()) return err('Code expired', 410, { code: 'promo_expired' });
      const [uses] = await redis([['GET', 'promo:uses:' + code]]);
      if (promo.maxUses && +uses >= promo.maxUses) return err('Code is used up', 410, { code: 'promo_out' });
      const [first] = await redis([['SET', P + ':promo:' + code, 1, 'NX']]);
      if (first !== 'OK') return err('Code already used', 409, { code: 'promo_used' });
      await redis([['INCR', 'promo:uses:' + code]]);
      const days = Math.max(1, +promo.days || 30);
      if (promo.type === 'plan' && PLANS[promo.plan]) {
        await redis([['SET', P + ':plan', JSON.stringify({ id: promo.plan, until: now() + days * 86400e3 })]]);
        return json({ ok: true, plan: promo.plan, days });
      }
      if (promo.type === 'discount') {
        await redis([['SET', P + ':disc', JSON.stringify({ percent: Math.min(90, Math.max(1, +promo.value || 0)), plans: promo.plans || 'all', until: now() + days * 86400e3, code })]]);
        return json({ ok: true, discount: +promo.value, days });
      }
      const n = Math.max(0, Math.round(+promo.value || 0));
      await redis([['INCRBY', P + ':bonus', n]]);
      return json({ ok: true, tokens: n });
    }
    const val = map[code];
    if (!code || !val) return err('Code not found', 404, { code: 'promo_bad' });
    const [first] = await redis([['SET', P + ':promo:' + code, 1, 'NX']]);
    if (first !== 'OK') return err('Code already used', 409, { code: 'promo_used' });
    const pl = val.match(/^(?:plan:)?(orbit|nova|cosmos):(\d+)$/i);
    if (pl && PLANS[pl[1].toLowerCase()]) {
      await redis([['SET', P + ':plan', JSON.stringify({ id: pl[1].toLowerCase(), until: Date.now() + (+pl[2]) * 86400e3 })]]);
      return json({ ok: true, plan: pl[1].toLowerCase(), days: +pl[2] });
    }
    const n = Math.max(0, parseInt(String(val).replace(/[^\d]/g, ''), 10) || 0);
    if (!n) return err('Code not found', 404, { code: 'promo_bad' });
    await redis([['INCRBY', P + ':bonus', n]]);
    return json({ ok: true, tokens: n });
  }

  if (p === 'ref' && req.method === 'POST') {
    if (!hasStore()) return err('Storage is not connected', 503);
    const body = await req.json().catch(() => ({}));
    const code = String(body.code || '').trim().toUpperCase();
    const [inviter] = await redis([['GET', 'rc:' + code]]);
    if (!inviter || inviter === u.uid) return json({ ok: false, reason: 'invalid' });
    const [evr] = await redis([['GET', 'u:' + u.uid + ':ev']]);
    if (!u.verified && evr !== '1') return json({ ok: false, reason: 'verify' });
    // only accounts created in the last 7 days can be counted as invites
    const lr = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + FB_KEY, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ idToken: u.token }) });
    const lj = await lr.json().catch(() => ({}));
    const created = +((lj.users && lj.users[0] && lj.users[0].createdAt) || 0);
    if (!created || Date.now() - created > 7 * 86400e3) return json({ ok: false, reason: 'old' });
    const [set] = await redis([['SET', 'u:' + u.uid + ':refBy', inviter, 'NX']]);
    if (set !== 'OK') return json({ ok: false, reason: 'used' });
    await redis([['SADD', 'u:' + inviter + ':inv', u.uid]]);
    return json({ ok: true });
  }

  /* ---- pictures: every way your API might draw, tried in turn; the one that works is remembered ---- */
  if (p === 'image' && req.method === 'POST') {
    const b = await req.json().catch(() => ({}));
    const prompt = String(b.prompt || '').slice(0, 4000);
    const chatModel = String(b.chatModel || '');
    if (!prompt) return err('Bad request', 400);
    let acc = null;
    if (!hasStore() && needsCode(u) && !u.verified) return err('Confirm your email first', 403, { code: 'verify' });
    if (hasStore()) {
      try { acc = await account(u); } catch (e) {}
      if (acc && needsCode(u) && !u.verified && !acc.verified) return err('Confirm your email first', 403, { code: 'verify' });
      if (acc && !(acc.bonus > 0)) {
        if (acc.w.total && acc.w.used >= acc.w.total) return err('5-hour limit reached', 429, { code: 'limit', which: 'w', resetAt: acc.w.resetAt });
        if (acc.m.used >= acc.m.total) return err('Weekly limit reached', 429, { code: 'limit', which: 'm', resetAt: acc.m.resetAt });
      }
    }
    // the answer is streamed (spaces first, JSON at the end) so long drawings don't hit the 25-second limit
    return streamJSON(async () => {
      let way = null;
      if (hasStore()) { try { const [v] = await redis([['GET', 'cfg:imgway']]); way = parseJ(v, null); } catch (e) {} }
      const ways = await imageWays(base, key, chatModel, way);
      for (const w of ways) {
        const r = await tryImageWay(base, key, w, prompt, req.signal, 110000);
        if (r.ok) {
          if (hasStore() && (!way || way.kind !== w.kind || way.model !== w.model)) redis([['SET', 'cfg:imgway', JSON.stringify({ kind: w.kind, model: w.model, at: now() })]]).catch(() => {});
          await charge(u, IMAGE_TOKENS, false);
          return { images: r.images, via: w.kind + ':' + w.model };
        }
        if (way && way.kind === w.kind && way.model === w.model && hasStore()) redis([['DEL', 'cfg:imgway']]).catch(() => {});
      }
      return { error: { message: 'Your API could not draw this picture', code: 'noimg' } };
    });
  }
  if (p === 'imgtest' && req.method === 'POST') {
    if (!admin) return err('Not allowed', 403, { code: 'notadmin' });
    const b = await req.json().catch(() => ({}));
    const enc = new TextEncoder();
    const stream = new ReadableStream({
      async start(ctrl) {
        const line = o => ctrl.enqueue(enc.encode(JSON.stringify(o) + '\n'));
        const ping = setInterval(() => { try { ctrl.enqueue(enc.encode(' \n')); } catch (e) {} }, 5000);
        try {
          const ways = await imageWays(base, key, String(b.chatModel || ''), null, true);
          line({ type: 'plan', ways: ways.map(w => w.kind + ' · ' + w.model) });
          let first = null;
          for (const w of ways) {
            line({ type: 'try', way: w.kind + ' · ' + w.model });
            const t0 = Date.now();
            const r = await tryImageWay(base, key, w, 'a small red apple on a white table, photo', req.signal, 90000);
            line({ type: 'result', way: w.kind + ' · ' + w.model, ok: r.ok, ms: Date.now() - t0, detail: r.ok ? 'ok' : r.detail, image: r.ok ? (r.images[0].url || ('data:image/png;base64,' + r.images[0].b64)) : null });
            if (r.ok && !first) { first = w; if (hasStore()) await redis([['SET', 'cfg:imgway', JSON.stringify({ kind: w.kind, model: w.model, at: now() })]]).catch(() => {}); if (!b.all) break; }
          }
          line({ type: 'done', found: first ? first.kind + ' · ' + first.model : null });
        } catch (e) { line({ type: 'done', found: null, error: String(e && e.message || e) }); }
        clearInterval(ping); ctrl.close();
      }
    });
    return new Response(stream, { headers: { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store' } });
  }

  if (p === 'chat' && req.method === 'POST') {
    let body;
    try { body = await req.json(); } catch (e) { return err('Bad request', 400); }
    const model = String(body.model || '');
    if (!/^(claude|gpt|chatgpt)/i.test(model.split('/').pop())) return err('Model not allowed', 400);
    // a message is text, or (for attachments) a list of text and image parts
    const okPart = x => x && ((x.type === 'text' && typeof x.text === 'string') || (x.type === 'image_url' && x.image_url && /^(data:image\/|https:)/.test(String(x.image_url.url || ''))));
    let messages = (Array.isArray(body.messages) ? body.messages : [])
      .filter(m => m && /^(system|user|assistant)$/.test(m.role) && (typeof m.content === 'string' || (Array.isArray(m.content) && m.content.length && m.content.every(okPart)))).slice(-40);
    const textOf = m => typeof m.content === 'string' ? m.content : m.content.filter(x => x.type === 'text').map(x => x.text).join('\n');
    const imgCount = m => typeof m.content === 'string' ? 0 : m.content.filter(x => x.type === 'image_url').length;
    let total = 0;
    for (let i = messages.length - 1; i >= 0; i--) { total += JSON.stringify(messages[i].content).length; if (total > 4200000) { messages = messages.slice(i + 1); break; } }

    let acc = null, adminC = admin, plan = 'spark';
    if (!hasStore() && needsCode(u) && !u.verified) return err('Confirm your email first', 403, { code: 'verify' });
    if (hasStore()) {
      const P = 'u:' + u.uid;
      try { acc = await account(u, [['GET', P + ':status'], ['GET', 'cfg:models'], ['GET', P + ':mem'], ['GET', P + ':memoff'], ['HGETALL', P + ':convs']]); } catch (e) { acc = null; }
      if (acc) {
        plan = acc.plan;
        const [st, rules, mem, memoff, convs] = acc.extra;
        adminC = isAdmin(u, u.verified || acc.verified);
        const stat = parseJ(st, null);
        if (stat && !adminC) return err('Account ' + stat.s, 403, { code: 'blocked', status: stat.s, support: SUPPORT });
        if (needsCode(u) && !u.verified && !acc.verified) return err('Confirm your email first', 403, { code: 'verify' });
        if (!adminC && acc.plan === 'spark' && isPremium(model, parseJ(rules, {}) || {})) return err('This model is for paid plans', 403, { code: 'premium' });
        // memory: what the assistant knows about the user + the user's other recent chats
        if (memoff !== '1' && body.memory !== false) {
          let ctx = '';
          if (mem) ctx += 'What you remember about this user from earlier conversations (use it naturally when it helps; do not recite it unless asked):\n' + String(mem).slice(0, 2000);
          const pairs = Array.isArray(convs) ? convs : Object.entries(convs || {}).flat();
          const others = [];
          for (let i = 0; i < pairs.length; i += 2) { const v = parseJ(pairs[i + 1], null); if (v && v.id !== body.conv) others.push(v); }
          others.sort((x, y) => (y.updated || 0) - (x.updated || 0));
          const lines = others.slice(0, 8).map(c => '- ' + (c.title || '…') + (c.last && c.last !== c.title ? ' — last question: ' + c.last : ''));
          if (lines.length) ctx += (ctx ? '\n\n' : '') + 'The user\'s other recent chats with you (newest first):\n' + lines.join('\n');
          if (ctx) {
            if (messages[0] && messages[0].role === 'system' && typeof messages[0].content === 'string') messages[0] = { role: 'system', content: messages[0].content + '\n\n' + ctx };
            else messages.unshift({ role: 'system', content: ctx });
          }
        }
      }
      if (acc && !(acc.bonus > 0)) {
        if (acc.w.total && acc.w.used >= acc.w.total) return err('5-hour limit reached', 429, { code: 'limit', which: 'w', resetAt: acc.w.resetAt });
        if (acc.m.used >= acc.m.total) return err('Weekly limit reached', 429, { code: 'limit', which: 'm', resetAt: acc.m.resetAt });
      }
    }

    const stream = body.stream !== false;
    const payload = { model, messages, stream };
    const lastUser = [...messages].reverse().find(m => m.role === 'user');
    const question = lastUser ? textOf(lastUser) : '';
    const images = lastUser ? imgCount(lastUser) : 0;
    let effort = body.effort === 'fast' || body.effort === 'deep' ? body.effort : 'auto';
    const simple = !images && isSimple(question, body.mode);
    if (effort === 'auto') effort = simple ? 'fast' : 'normal';
    if (effort === 'fast' && !NO_EFFORT.has(model)) payload.reasoning_effort = 'low';
    if (effort === 'deep' && !NO_EFFORT.has(model)) payload.reasoning_effort = 'high';
    if (body.effort !== 'deep' && simple) payload.max_tokens = 1200;
    const build = body.mode === 'site' || body.mode === 'code';

    // tokens: everything the model reads (instructions, memory, the whole chat) + the answer
    const inTok = messages.reduce((n, m) => n + countTokens(textOf(m)) + imgCount(m) * 1000, 0);
    const pre = costFor(plan, inTok);
    const r = await upstream(base, key, payload, req.signal);
    if (!r.ok) return new Response(r.body, { status: r.status, headers: { 'content-type': r.headers.get('content-type') || 'application/json' } });

    const ct = r.headers.get('content-type') || '';
    if (!r.body || !/event-stream/.test(ct)) {
      const j = await r.json().catch(() => ({}));
      const c = j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content;
      await charge(u, costFor(plan, inTok + countTokens(typeof c === 'string' ? c : '')), build);
      return json(j);
    }

    // charge the input right away (so a stopped answer is still counted), the rest when the stream ends
    charge(u, pre, false);
    const dec = new TextDecoder();
    let buf = '', answer = '';
    const ts = new TransformStream({
      transform(chunk, ctrl) {
        ctrl.enqueue(chunk);
        buf += dec.decode(chunk, { stream: true });
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
          if (!line.startsWith('data:')) continue;
          const d = line.slice(5).trim(); if (d === '[DONE]') continue;
          try {
            const j = JSON.parse(d);
            const dl = (j.choices && j.choices[0] && j.choices[0].delta) || {};
            if (typeof dl.content === 'string') answer += dl.content;
            const rr = dl.reasoning_content || dl.reasoning || dl.thinking;
            if (typeof rr === 'string') answer += rr;
          } catch (e) {}
        }
      },
      async flush() {
        await charge(u, Math.max(0, costFor(plan, inTok + countTokens(answer)) - pre), build && answer.length > 0);
      }
    });
    return new Response(r.body.pipeThrough(ts), { status: 200, headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' } });
  }

  return err('Not found', 404);
}