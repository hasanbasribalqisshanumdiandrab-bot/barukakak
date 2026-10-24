const crypto = require('crypto');
const QRCode = require('qrcode');
const A = require('../lib/auth');

const ISSUER = 'Cari Jawaban Soal';
const SESSION_TTL = 60 * 60 * 24 * 7;   // 7 hari
const ENROLL_TTL = 60 * 30;             // 30 menit
const MSG_SENT = 'Jika email ini diizinkan, tautan pemasangan sudah dikirim. Cek kotak masuk (dan Spam), lalu buka tautannya.';

const json = (code, obj, cookies) => ({
  statusCode: code,
  headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  ...(cookies && cookies.length ? { multiValueHeaders: { 'Set-Cookie': cookies } } : {}),
  body: JSON.stringify(obj),
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function identity(origin, path, body) {
  const r = await fetch(`${origin}/.netlify/identity/${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  let data = {};
  try { data = JSON.parse(text); } catch { /* bukan JSON */ }
  return { ok: r.ok, status: r.status, data };
}
function emailFromIdentity(d) {
  if (d && d.email) return d.email;
  if (d && d.user && d.user.email) return d.user.email;
  if (d && d.access_token) {
    try { return JSON.parse(Buffer.from(d.access_token.split('.')[1], 'base64url').toString()).email || ''; } catch { /* abaikan */ }
  }
  return '';
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== 'POST') return json(405, { error: 'Metode tidak didukung.' });
    let b = {};
    try { b = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Permintaan tidak valid.' }); }
    const origin = `https://${event.headers.host}`;
    const jar = A.cookies(event);
    const session = A.unsign(jar.sid);
    const enrolling = A.unsign(jar.enr);
    const email = String(b.email || '').trim().toLowerCase();

    switch (b.action) {
      case 'status':
        return json(200, { ok: !!(session && session.t === 'sid') });

      case 'signup':
      case 'recovery': {
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json(400, { error: 'Alamat email tidak valid.' });
        if (A.isAllowed(email)) {
          let sent = false;
          if (b.action === 'signup') {
            const password = crypto.randomBytes(24).toString('base64url');
            const r = await identity(origin, 'signup', { email, password });
            sent = r.ok;
          }
          if (!sent) await identity(origin, 'recover', { email });
        }
        return json(200, { message: MSG_SENT });
      }

      case 'confirm':
      case 'recover': {
        const token = String(b.token || '');
        if (!token) return json(400, { error: 'Token kosong.' });
        const r = await identity(origin, 'verify', { token, type: b.action === 'confirm' ? 'signup' : 'recovery' });
        const em = String(emailFromIdentity(r.data)).toLowerCase();
        if (!r.ok || !em) return json(400, { error: 'Tautan tidak valid atau kedaluwarsa. Minta tautan baru.' });
        if (!A.isAllowed(em)) return json(403, { error: 'Email ini tidak diizinkan.' });
        return json(200, { ok: true }, [A.setCookie('enr', A.sign({ t: 'enr', e: em }, ENROLL_TTL), ENROLL_TTL)]);
      }

      case 'setup': {
        if (!enrolling || enrolling.t !== 'enr') return json(401, { error: 'Sesi pemasangan habis. Buka lagi tautan dari email.' });
        const key = A.userKey(enrolling.e);
        const secret = A.base32(key);
        const uri = `otpauth://totp/${encodeURIComponent(ISSUER + ':' + enrolling.e)}?secret=${secret}&issuer=${encodeURIComponent(ISSUER)}&algorithm=SHA1&digits=6&period=30`;
        const qr = await QRCode.toDataURL(uri, { margin: 2, width: 300 });
        return json(200, { enrolled: false, qr, uri, secret });
      }

      case 'verify': {
        if (!enrolling || enrolling.t !== 'enr') return json(401, { error: 'Sesi pemasangan habis. Buka lagi tautan dari email.' });
        if (!A.totpOk(A.userKey(enrolling.e), b.code)) { await sleep(500); return json(401, { error: 'Kode salah. Coba kode terbaru.' }); }
        return json(200, { ok: true }, [
          A.setCookie('sid', A.sign({ t: 'sid', e: enrolling.e }, SESSION_TTL), SESSION_TTL),
          A.setCookie('enr', '', 0),
        ]);
      }

      case 'otp-login': {
        const okEmail = A.isAllowed(email);
        const okCode = okEmail && A.totpOk(A.userKey(email), b.code);
        if (!okCode) { await sleep(500); return json(401, { error: 'Email atau kode salah.' }); }
        return json(200, { ok: true }, [A.setCookie('sid', A.sign({ t: 'sid', e: email }, SESSION_TTL), SESSION_TTL)]);
      }

      case 'logout':
        return json(200, { ok: true }, [A.setCookie('sid', '', 0), A.setCookie('enr', '', 0)]);

      default:
        return json(400, { error: 'Aksi tidak dikenal.' });
    }
  } catch (e) {
    return json(500, { error: e.message || 'Kesalahan server.' });
  }
};
