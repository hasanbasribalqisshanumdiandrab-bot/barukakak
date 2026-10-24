const crypto = require('crypto');

function secret() {
  const s = process.env.AUTH_SECRET;
  if (!s || s.length < 32) throw new Error('AUTH_SECRET belum diatur di Netlify (minimal 32 karakter).');
  return s;
}
const hmac = (data) => crypto.createHmac('sha256', secret()).update(data).digest();
const b64u = (b) => Buffer.from(b).toString('base64url');

function sign(payload, ttlSeconds) {
  const body = b64u(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds }));
  return body + '.' + b64u(hmac('tok:' + body));
}
function unsign(token) {
  if (!token || token.indexOf('.') < 1) return null;
  const [body, sig] = token.split('.');
  const expected = b64u(hmac('tok:' + body));
  if (!sig || sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() / 1000 ? p : null;
  } catch { return null; }
}

function cookies(event) {
  const out = {};
  String((event.headers && (event.headers.cookie || event.headers.Cookie)) || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}
const setCookie = (name, value, maxAge) =>
  `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

function allowedEmails() {
  return String(process.env.ALLOWED_EMAILS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
}
const isAllowed = (email) => allowedEmails().includes(String(email || '').trim().toLowerCase());

// Kunci TOTP per email diturunkan dari AUTH_SECRET (tanpa database).
// Kunci hanya ditampilkan setelah pemilik email membuka tautan konfirmasi.
function userKey(email) {
  return crypto.createHmac('sha256', secret()).update('totp:' + email.trim().toLowerCase()).digest().subarray(0, 20);
}
function base32(buf) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '', out = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
}
function hotp(key, counter) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(b).digest();
  const o = h[19] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}
function totpOk(key, code) {
  code = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(code)) return false;
  const c = Math.floor(Date.now() / 30000);
  let ok = false;
  for (let i = -1; i <= 1; i++) {
    if (crypto.timingSafeEqual(Buffer.from(hotp(key, c + i)), Buffer.from(code))) ok = true;
  }
  return ok;
}

module.exports = { sign, unsign, cookies, setCookie, isAllowed, userKey, base32, totpOk };
