const fs = require('fs');
const path = require('path');
const A = require('../lib/auth');

exports.handler = async (event) => {
  let ok = false;
  try { const s = A.unsign(A.cookies(event).sid); ok = !!(s && s.t === 'sid'); } catch { ok = false; }
  if (!ok) return { statusCode: 302, headers: { Location: '/', 'Cache-Control': 'no-store' }, body: '' };
  const candidates = [
    path.join(process.env.LAMBDA_TASK_ROOT || '', 'private', 'app.html'),
    path.join(process.cwd(), 'private', 'app.html'),
    path.join(__dirname, '..', '..', 'private', 'app.html'),
  ];
  for (const f of candidates) {
    try {
      return { statusCode: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }, body: fs.readFileSync(f, 'utf8') };
    } catch { /* coba berikutnya */ }
  }
  return { statusCode: 500, headers: { 'Content-Type': 'text/plain' }, body: 'private/app.html tidak ditemukan.' };
};
