import { neon } from '@neondatabase/serverless';
import { randomBytes, scrypt as scryptCallback, timingSafeEqual, createHmac } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const COOKIE = 'trustshield_session';
const SESSION_SECONDS = 60 * 60 * 24 * 7; // Signed token expiry is a safety limit; the cookie itself is browser-session only.
const secureCookie = process.env.NODE_ENV === 'production' ? '; Secure' : '';

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}
function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map(v => v.trim()).filter(Boolean).map(v => {
    const i = v.indexOf('='); return [v.slice(0, i), decodeURIComponent(v.slice(i + 1))];
  }));
}
function sign(payload, secret) {
  const head = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const data = `${head}.${body}`;
  return `${data}.${createHmac('sha256', secret).update(data).digest('base64url')}`;
}
function verify(token, secret) {
  try {
    const [h, p, sig] = token.split('.');
    const expected = createHmac('sha256', secret).update(`${h}.${p}`).digest();
    const actual = Buffer.from(sig, 'base64url');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    return payload.exp > Math.floor(Date.now() / 1000) ? payload : null;
  } catch { return null; }
}
async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  let raw = ''; for await (const chunk of req) raw += chunk;
  return raw ? JSON.parse(raw) : {};
}

export default async function handler(req, res) {
  const secret = process.env.SESSION_SECRET;
  const dbUrl = process.env.DATABASE_URL;
  if (!secret || secret.length < 32 || !dbUrl) return json(res, 503, { error: 'Server is not configured. Set DATABASE_URL and a SESSION_SECRET of at least 32 characters.' });
  const sql = neon(dbUrl);
  const path = new URL(req.url, 'http://localhost').pathname.replace(/^\/api\/?/, '').replace(/\/$/, '');
  const method = req.method || 'GET';
  try {

    if (path === 'product-image' && method === 'POST') {
      const cookies = parseCookies(req.headers.cookie || '');
      const session = cookies[COOKIE] ? verify(cookies[COOKIE], secret) : null;
      if (!session) return json(res, 401, { error: 'Please sign in to scan product images.' });
      const body = await readBody(req);
      const image = String(body.image || '');
      const mimeType = String(body.mimeType || '');
      if (!['image/jpeg','image/png','image/webp'].includes(mimeType)) return json(res, 400, { error: 'Use a JPG, PNG or WEBP image.' });
      if (!image || image.length > 9_800_000) return json(res, 413, { error: 'Image is too large. Please use an image under 7 MB.' });
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) return json(res, 503, { error: 'Image scanning is not configured yet. Add GEMINI_API_KEY in Vercel environment variables.' });
      const prompt = `You are TrustShield, a cautious e-commerce scam risk assistant. Inspect the supplied product/listing/seller screenshot and optional user details. Look only for visible evidence: suspicious payment instructions, unrealistic discounts, inconsistent branding or packaging, misleading claims, contact details, suspicious URLs, counterfeit-like visual inconsistencies, or other scam warning signs. Do not claim an item is counterfeit or fraudulent based only on appearance. If the image is ambiguous, say so. Return ONLY valid JSON with keys productName (string), score (integer 0-100), level ("LOW"|"MEDIUM"|"HIGH"), summary (string), findings (array of objects with label, detail, severity "low"|"medium"|"high"). A clean image must not be described as guaranteed safe. User-provided details: ${String(body.details || '').slice(0,3000)}`;
      const aiResponse = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }, { inline_data: { mime_type: mimeType, data: image } }] }], generationConfig: { responseMimeType: 'application/json', temperature: 0.2 } })
      });
      const aiData = await aiResponse.json().catch(() => ({}));
      if (!aiResponse.ok) { console.error('Gemini image analysis failed:', aiData?.error?.message || aiResponse.status); return json(res, 502, { error: 'The image analysis provider could not process this image. Try again later.' }); }
      const output = aiData?.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('') || '';
      let result;
      try { result = JSON.parse(output); } catch { return json(res, 502, { error: 'The image analysis returned an unreadable result. Please try again.' }); }
      const score = Math.max(0, Math.min(100, Number(result.score) || 0));
      return json(res, 200, { productName: String(result.productName || 'Product image'), score, level: ['LOW','MEDIUM','HIGH'].includes(result.level) ? result.level : score >= 60 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW', summary: String(result.summary || ''), findings: Array.isArray(result.findings) ? result.findings.slice(0,8) : [] });
    }

    if (path === 'health' && method === 'GET') { const rows = await sql`SELECT current_database() AS database_name, NOW() AS checked_at`; return json(res, 200, { ok: true, database: 'connected', databaseName: rows[0]?.database_name }); }

    if (path === 'auth/register' && method === 'POST') {
      const { email, password } = await readBody(req);
      const normalized = String(email || '').trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) return json(res, 400, { error: 'Enter a valid email address.' });
      if (typeof password !== 'string' || password.length < 8 || password.length > 128) return json(res, 400, { error: 'Use a password between 8 and 128 characters.' });
      const salt = randomBytes(16);
      const hash = await scrypt(password, salt, 64);
      const encoded = `${salt.toString('hex')}:${Buffer.from(hash).toString('hex')}`;
      const rows = await sql`INSERT INTO app_users (email, password_hash) VALUES (${normalized}, ${encoded}) ON CONFLICT (email) DO NOTHING RETURNING id, email`;
      if (!rows.length) return json(res, 409, { error: 'An account with this email already exists. Please sign in.' });
      const user = rows[0];
      const token = sign({ sub: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS }, secret);
      res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(token)}; HttpOnly${secureCookie}; SameSite=Lax; Path=/`);
      return json(res, 201, { user: { id: user.id, email: user.email } });
    }

    if (path === 'auth/login' && method === 'POST') {
      const { email, password } = await readBody(req);
      const normalized = String(email || '').trim().toLowerCase();
      const rows = await sql`SELECT id, email, password_hash FROM app_users WHERE email = ${normalized} LIMIT 1`;
      if (!rows.length || typeof password !== 'string') return json(res, 401, { error: 'Email or password is incorrect.' });
      const [saltHex, hashHex] = rows[0].password_hash.split(':');
      const actual = Buffer.from(await scrypt(password, Buffer.from(saltHex, 'hex'), 64));
      const expected = Buffer.from(hashHex, 'hex');
      if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return json(res, 401, { error: 'Email or password is incorrect.' });
      const user = rows[0];
      const token = sign({ sub: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS }, secret);
      res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(token)}; HttpOnly${secureCookie}; SameSite=Lax; Path=/; Max-Age=${SESSION_SECONDS}`);
      return json(res, 200, { user: { id: user.id, email: user.email } });
    }

    if (path === 'auth/logout' && method === 'POST') {
      res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly${secureCookie}; SameSite=Lax; Path=/; Max-Age=0`);
      return json(res, 200, { ok: true });
    }

    const cookies = parseCookies(req.headers.cookie || '');
    const session = cookies[COOKIE] ? verify(cookies[COOKIE], secret) : null;
    if (path === 'auth/me' && method === 'GET') {
      if (!session) return json(res, 401, { error: 'Not signed in.' });
      return json(res, 200, { user: { id: session.sub, email: session.email } });
    }
    if (!session) return json(res, 401, { error: 'Please sign in again.' });

    if (path === 'data' && method === 'GET') {
      const [scanRows, caseRows, evidenceRows] = await Promise.all([
        sql`SELECT result FROM scan_history WHERE user_id = ${session.sub} ORDER BY created_at DESC LIMIT 500`,
        sql`SELECT title FROM investigation_cases WHERE user_id = ${session.sub} ORDER BY created_at DESC LIMIT 500`,
        sql`SELECT metadata FROM evidence_metadata WHERE user_id = ${session.sub} ORDER BY created_at DESC LIMIT 500`
      ]);
      return json(res, 200, { scans: scanRows.map(r => r.result), cases: caseRows.map(r => r.title), evidence: evidenceRows.map(r => r.metadata) });
    }
    if (path === 'data' && method === 'PUT') {
      const body = await readBody(req);
      const scans = Array.isArray(body.scans) ? body.scans.slice(0, 500) : [];
      const cases = Array.isArray(body.cases) ? body.cases.slice(0, 500) : [];
      const evidence = Array.isArray(body.evidence) ? body.evidence.slice(0, 500) : [];
      await sql`DELETE FROM scan_history WHERE user_id = ${session.sub}`;
      await sql`DELETE FROM investigation_cases WHERE user_id = ${session.sub}`;
      await sql`DELETE FROM evidence_metadata WHERE user_id = ${session.sub}`;
      for (const s of scans) await sql`INSERT INTO scan_history (user_id, scan_type, input_summary, result, risk_score) VALUES (${session.sub}, ${String(s.kind || 'UNKNOWN')}, ${String(s.target || '').slice(0, 500)}, ${JSON.stringify(s)}, ${Number(s.score) || 0})`;
      for (const c of cases) if (typeof c === 'string' && c.trim()) await sql`INSERT INTO investigation_cases (user_id, title) VALUES (${session.sub}, ${c.trim().slice(0, 255)})`;
      for (const e of evidence) if (e && typeof e === 'object') await sql`INSERT INTO evidence_metadata (user_id, file_name, file_hash, file_size, metadata) VALUES (${session.sub}, ${String(e.name || 'evidence').slice(0, 255)}, ${String(e.sha || '')}, ${Number(e.size) || 0}, ${JSON.stringify(e)})`;
      return json(res, 200, { ok: true });
    }
    return json(res, 404, { error: 'Not found.' });
  } catch (error) {
    console.error('TrustShield API failure:', { path, method, name: error?.name, code: error?.code, message: error?.message });
    if (error?.code === '23505') return json(res, 409, { error: 'That account already exists.' });
    return json(res, 500, { error: 'A server error occurred. Check the server logs.' });
  }
}