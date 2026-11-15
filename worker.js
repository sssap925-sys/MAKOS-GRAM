// IGNAT SMART CONTROL — серверный OAuth-прокси (Cloudflare Workers + KV)
// Секреты (client secret, токены Яндекса, пароль владельца) живут ТОЛЬКО здесь, в Variables/Secrets Cloudflare.
// Привязка KV называется  KV.  Переменные: см. .env.example

const IOT = 'https://api.iot.yandex.net/v1.0';
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = u8 => btoa(String.fromCharCode(...u8));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = s => Uint8Array.from(s.match(/../g).map(h => parseInt(h, 16)));
const rnd = n => b64(crypto.getRandomValues(new Uint8Array(n))).replace(/[+/=]/g, '');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

// ---- шифрование токена Яндекса (AES-GCM) ----
const aesKey = env => crypto.subtle.importKey('raw', hex(env.TOKEN_ENCRYPTION_KEY), 'AES-GCM', false, ['encrypt', 'decrypt']);
async function seal(env, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(env), enc.encode(text)));
  return b64(iv) + '.' + b64(ct);
}
async function unseal(env, s) {
  const [i, c] = s.split('.');
  return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(i) }, await aesKey(env), unb64(c)));
}

// ---- пароли ----
async function pbkdf2(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, k, 256));
}
const sha = async s => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const same = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; };
const validUser = u => typeof u === 'string' && /^[A-Za-z0-9_]{3,24}$/.test(u);
const validPw = p => typeof p === 'string' && p.length >= 8 && p.length <= 128;

// ---- CORS / ответы ----
const allowed = env => (env.ALLOWED_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
function cors(req, env, extra) {
  const o = req.headers.get('Origin');
  const h = { 'Content-Type': 'application/json', Vary: 'Origin', 'Cache-Control': 'no-store' };
  if (o && allowed(env).includes(o)) {
    h['Access-Control-Allow-Origin'] = o; h['Access-Control-Allow-Credentials'] = 'true';
    h['Access-Control-Allow-Headers'] = 'Content-Type'; h['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS';
  }
  return { ...h, ...extra };
}
const json = (req, env, data, status = 200, extra) => new Response(JSON.stringify(data), { status, headers: cors(req, env, extra) });
const body = async req => { try { return await req.json(); } catch { return {}; } };

// ---- сессии сайта ----
async function session(req, env) {
  const m = (req.headers.get('Cookie') || '').match(/(?:^|;\s*)sid=([\w-]+)/);
  if (!m) return null;
  const s = await env.KV.get('sess:' + m[1], 'json');
  return s ? { ...s, sid: m[1] } : null;
}
async function startSession(env, username, role) {
  const sid = rnd(32);
  await env.KV.put('sess:' + sid, JSON.stringify({ username, role }), { expirationTtl: 604800 });
  return `sid=${sid}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=604800`;
}
async function limited(req, env, key, max) {
  const ip = req.headers.get('CF-Connecting-IP') || 'x';
  const k = `rl:${key}:${ip}:${Math.floor(Date.now() / 60000)}`;
  const n = +(await env.KV.get(k) || 0) + 1;
  await env.KV.put(k, String(n), { expirationTtl: 120 });
  return n > max;
}

// ---- токен Яндекса (хранится зашифрованным) ----
async function getToken(env) {
  const raw = await env.KV.get('ytoken'); if (!raw) return null;
  try { return JSON.parse(await unseal(env, raw)); } catch { return null; }
}
const saveToken = async (env, o) => env.KV.put('ytoken', await seal(env, JSON.stringify(o)));
async function refresh(env, t) {
  const r = await fetch('https://oauth.yandex.ru/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: t.refresh, client_id: env.YANDEX_CLIENT_ID, client_secret: env.YANDEX_CLIENT_SECRET }) });
  if (!r.ok) return null;
  const j = await r.json();
  const n = { access: j.access_token, refresh: j.refresh_token || t.refresh, exp: Date.now() + (j.expires_in || 0) * 1000 };
  await saveToken(env, n); return n;
}
async function yandex(env, path, init = {}) {
  let t = await getToken(env);
  if (!t) return { status: 403, body: { error: 'no_yandex_token' } };
  if (t.exp && t.refresh && t.exp < Date.now() + 60000) t = (await refresh(env, t)) || t;
  const r = await fetch(IOT + path, { ...init, headers: { Authorization: 'Bearer ' + t.access, 'Content-Type': 'application/json' } });
  let b = null; try { b = await r.json(); } catch {}
  if (r.status === 401 || r.status === 403) return { status: 403, body: { error: 'yandex_denied' } };
  return { status: r.status, body: b };
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url), p = url.pathname, m = req.method;
    try {
      if (m === 'OPTIONS') return new Response(null, { status: 204, headers: cors(req, env) });
      if (m !== 'GET' && !allowed(env).includes(req.headers.get('Origin') || '')) return json(req, env, { error: 'origin' }, 403);
      const ownerName = (env.OWNER_USERNAME || '').toLowerCase();

      // ===== вход на сайт =====
      if (p === '/site/register' && m === 'POST') {
        if (env.REGISTRATION_OPEN !== 'true') return json(req, env, { error: 'closed' }, 403);
        if (await limited(req, env, 'reg', 5)) return json(req, env, { error: 'rate' }, 429);
        const { username: u, password: pw } = await body(req);
        if (!validUser(u) || !validPw(pw)) return json(req, env, { error: 'bad' }, 400);
        const key = 'user:' + u.toLowerCase();
        if (u.toLowerCase() === ownerName || await env.KV.get(key)) return json(req, env, { error: 'taken' }, 409);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        await env.KV.put(key, JSON.stringify({ name: u, salt: b64(salt), hash: b64(await pbkdf2(pw, salt)) }));
        return json(req, env, { ok: true, username: u, role: 'user' }, 200, { 'Set-Cookie': await startSession(env, u, 'user') });
      }
      if (p === '/site/login' && m === 'POST') {
        if (await limited(req, env, 'login', 10)) return json(req, env, { error: 'rate' }, 429);
        const { username: u, password: pw } = await body(req);
        if (!validUser(u) || !validPw(pw)) return json(req, env, { error: 'bad' }, 400);
        if (u.toLowerCase() === ownerName) {
          if (!env.OWNER_PASSWORD || !same(await sha(pw), await sha(env.OWNER_PASSWORD))) return json(req, env, { error: 'auth' }, 401);
          return json(req, env, { ok: true, username: env.OWNER_USERNAME, role: 'owner' }, 200, { 'Set-Cookie': await startSession(env, env.OWNER_USERNAME, 'owner') });
        }
        const rec = await env.KV.get('user:' + u.toLowerCase(), 'json');
        if (!rec || !same(await pbkdf2(pw, unb64(rec.salt)), unb64(rec.hash))) return json(req, env, { error: 'auth' }, 401);
        return json(req, env, { ok: true, username: rec.name, role: 'user' }, 200, { 'Set-Cookie': await startSession(env, rec.name, 'user') });
      }
      if (p === '/site/me') {
        const s = await session(req, env);
        return s ? json(req, env, { username: s.username, role: s.role }) : json(req, env, { error: 'auth' }, 401);
      }
      if (p === '/site/logout' && m === 'POST') {
        const s = await session(req, env); if (s) await env.KV.delete('sess:' + s.sid);
        return json(req, env, { ok: true }, 200, { 'Set-Cookie': 'sid=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0' });
      }

      // ===== OAuth Яндекса (только владелец) =====
      if (p === '/auth/login' && m === 'GET') {
        const s = await session(req, env);
        if (!s || s.role !== 'owner') return new Response('Сначала войдите на сайте как владелец.', { status: 401 });
        const ret = url.searchParams.get('return') || '';
        let ok = false; try { ok = allowed(env).includes(new URL(ret).origin); } catch {}
        if (!ok) return new Response('Недопустимый адрес возврата.', { status: 400 });
        const state = rnd(16);
        await env.KV.put('st:' + state, JSON.stringify({ ret }), { expirationTtl: 600 });
        const q = new URLSearchParams({ response_type: 'code', client_id: env.YANDEX_CLIENT_ID, redirect_uri: env.OAUTH_REDIRECT_URI, state });
        return Response.redirect('https://oauth.yandex.ru/authorize?' + q, 302);
      }
      if (p === '/auth/callback' && m === 'GET') {
        const st = await env.KV.get('st:' + (url.searchParams.get('state') || ''), 'json');
        if (!st) return new Response('Устаревшая или неверная ссылка. Начните заново.', { status: 400 });
        await env.KV.delete('st:' + url.searchParams.get('state'));
        const code = url.searchParams.get('code');
        if (code) {
          const r = await fetch('https://oauth.yandex.ru/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ grant_type: 'authorization_code', code, client_id: env.YANDEX_CLIENT_ID, client_secret: env.YANDEX_CLIENT_SECRET }) });
          if (r.ok) { const j = await r.json(); await saveToken(env, { access: j.access_token, refresh: j.refresh_token, exp: Date.now() + (j.expires_in || 0) * 1000 }); }
        }
        return Response.redirect(st.ret, 302); // права проверит сайт запросом /api/devices
      }
      if (p === '/auth/token' && m === 'POST') {
        const s = await session(req, env);
        if (!s) return json(req, env, { error: 'auth' }, 401);
        if (s.role !== 'owner') return json(req, env, { error: 'forbidden' }, 403);
        if (await limited(req, env, 'token', 10)) return json(req, env, { error: 'rate' }, 429);
        const { token } = await body(req);
        if (typeof token !== 'string' || token.length < 20 || token.length > 400) return json(req, env, { error: 'bad' }, 400);
        const r = await fetch(IOT + '/user/info', { headers: { Authorization: 'Bearer ' + token } });
        if (!r.ok) return json(req, env, { error: 'bad_token' }, 401);
        await saveToken(env, { access: token });
        return json(req, env, { ok: true });
      }

      // ===== API умного дома (нужен вход на сайт) =====
      if (p.startsWith('/api/')) {
        const s = await session(req, env);
        if (!s) return json(req, env, { error: 'auth' }, 401);
        if (p === '/api/devices' && m === 'GET') {
          const r = await yandex(env, '/user/info');
          if (r.status !== 200) return json(req, env, r.body || { error: 'yandex' }, r.status);
          return json(req, env, { devices: (r.body.devices || []).map(d => ({ id: d.id, name: d.name, type: d.type, state: d.state })) });
        }
        if (p === '/api/scenarios' && m === 'GET') {
          const r = await yandex(env, '/user/info');
          if (r.status !== 200) return json(req, env, r.body || { error: 'yandex' }, r.status);
          return json(req, env, { scenarios: (r.body.scenarios || []).map(x => ({ id: x.id, name: x.name, is_active: x.is_active })) });
        }
        const run = p.match(/^\/api\/scenarios\/([^/]+)\/run$/);
        if (run && m === 'POST') {
          if (await limited(req, env, 'run', 30)) return json(req, env, { error: 'rate' }, 429);
          const id = decodeURIComponent(run[1]).match(UUID); // лишний суффикс «:2449274587» отбрасываем
          if (!id) return json(req, env, { error: 'bad_id' }, 400);
          const r = await yandex(env, `/scenarios/${id[0]}/actions`, { method: 'POST' });
          if (r.status !== 200) return json(req, env, r.body || { error: 'yandex' }, r.status);
          return json(req, env, { status: r.body && r.body.status === 'ok' ? 'ok' : 'error', request_id: r.body && r.body.request_id });
        }
      }
      return json(req, env, { error: 'not_found' }, 404);
    } catch (e) {
      return json(req, env, { error: 'server' }, 500);
    }
  }
};
