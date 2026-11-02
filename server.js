'use strict';
const crypto = require('crypto'), fs = require('fs'), path = require('path');
const ch = require('./lib/chain'), au = require('./lib/auth');
const PORT = process.env.PORT || 3000, DATA = process.env.DATA_DIR || path.join(__dirname, 'data'), PROD = process.env.NODE_ENV === 'production';
fs.mkdirSync(DATA, { recursive: true });
const DBF = path.join(DATA, 'db.json'), CAF = path.join(DATA, 'ca.json');

/* ---------- persistence (JSON file; swap for Postgres in a bigger deployment) ---------- */
let db = fs.existsSync(DBF) ? JSON.parse(fs.readFileSync(DBF, 'utf8')) : { chain: [], accounts: {}, blobs: {}, cosigs: {}, setupCode: null };
const save = () => { const t = DBF + '.tmp'; fs.writeFileSync(t, JSON.stringify(db)); fs.renameSync(t, DBF); };
if (!db.setupCode) db.setupCode = process.env.INSPECTOR_CODE || crypto.randomBytes(6).toString('hex');

/* ---------- Government CA (simulated root CA; use an HSM/KMS in production) ---------- */
let ca;
if (fs.existsSync(CAF)) { const j = JSON.parse(fs.readFileSync(CAF, 'utf8')); ca = { priv: crypto.createPrivateKey({ key: j.priv, format: 'jwk' }), pub: j.pub }; }
else { const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); ca = { priv: kp.privateKey, pub: kp.publicKey.export({ format: 'jwk' }) };
  fs.writeFileSync(CAF, JSON.stringify({ priv: kp.privateKey.export({ format: 'jwk' }), pub: ca.pub }), { mode: 0o600 }); }
ca.pub = { kty: ca.pub.kty, crv: ca.pub.crv, x: ca.pub.x, y: ca.pub.y }; ca.addr = ch.addrOf(ca.pub); ca.name = 'Govt Land Registry Root CA';

let state;
if (!db.chain.length) {
  const g = { type: 'GENESIS', payload: { caPub: ca.pub, caAddr: ca.addr, caName: ca.name }, from: 'system-genesis', ts: Date.now(), nonce: crypto.randomBytes(8).toString('hex') }; g.id = ch.txId(g);
  db.chain.push(ch.sealBlock([], [g]));
}
state = ch.rebuild(db.chain); save();

function sysTx(type, payload) { const tx = { type, payload, from: ca.addr, ts: Date.now(), nonce: crypto.randomBytes(8).toString('hex') }; tx.sig = ch.caSign(ca.priv, ch.signMsg(tx)); tx.id = ch.txId(tx); return tx; }
function issueCert(u) {
  const cert = { serial: crypto.randomBytes(6).toString('hex'), subject: u.name, role: u.role, issuer: ca.name, notBefore: Date.now() - 6e4, notAfter: Date.now() + 365 * 864e5, signPub: u.signPub, wrapPub: u.wrapPub, addr: u.addr };
  cert.caSig = ch.caSign(ca.priv, ch.certBody(cert));
  return ch.commit(db.chain, state, [sysTx('ISSUE_CERT', { cert })]);
}
function cleanTx(t) { const x = { type: t.type, payload: t.payload, from: t.from, ts: t.ts, nonce: t.nonce, sig: t.sig }; if (Array.isArray(t.cosigs)) x.cosigs = t.cosigs.map(c => ({ addr: c.addr, sig: c.sig })); x.id = ch.txId(x); return x; }

/* ---------- tiny HTTP layer (built-in http module: zero npm dependencies) ---------- */
const http = require('http');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.json': 'application/json' };
const routes = [];
const route = (method, p, ...h) => routes.push({ method, re: new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), h });
const SEC = { 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data: blob: https://api.qrserver.com; connect-src 'self'; frame-ancestors 'none'", 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' };
if (PROD) SEC['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
const cookie = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(a => a[0]));
const send = (res, code, body, extra = {}) => { res.writeHead(code, { ...SEC, 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extra }); res.end(JSON.stringify(body)); };
const fail = (res, e, code = 400) => send(res, code, { error: e });
const setCookie = (res, t) => res.appendHeader ? res.setHeader('Set-Cookie', `sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${PROD ? '; Secure' : ''}`) : 0;
const ip = req => (PROD && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress);
function readBody(req) { return new Promise((ok, no) => { let n = 0; const c = []; req.on('data', d => { n += d.length; if (n > 12e6) { no(new Error('too large')); req.destroy(); } else c.push(d); }); req.on('end', () => { try { ok(c.length ? JSON.parse(Buffer.concat(c).toString()) : {}); } catch (e) { no(new Error('bad json')); } }); }); }
function authed(req, res) { const s = au.getSession(cookie(req).sid); if (!s) { fail(res, 'not logged in', 401); return false; } req.acc = db.accounts[s.username]; req.user = state.users[req.acc.addr]; return true; }
function inspectorOnly(req, res) { if (!authed(req, res)) return false; if (req.user.role !== 'inspector') { fail(res, 'RBAC: registrar only', 403); return false; } return true; }
const validBlob = b => b && /^[0-9a-f]+$/.test(b.iv || '') && /^[0-9a-f]+$/.test(b.ct || '');

route('GET', '/api/meta', (req, res) => { const i = state.inspector && state.users[state.inspector];
  send(res, 200, { ca: { addr: ca.addr, pub: ca.pub, name: ca.name }, inspector: i ? { addr: i.addr, name: i.name, wrapPub: i.wrapPub } : null, inspectorExists: !!state.inspector, setupCode: state.inspector ? null : db.setupCode, validators: ch.VALIDATORS, height: db.chain.length, nextLand: state.nextLand }); });

route('POST', '/api/register', (req, res) => {
  if (!au.rateLimit('reg:' + ip(req), 10, 60000)) return fail(res, 'too many attempts', 429);
  const { username, password, tx, kycBlob, setupCode } = req.body || {};
  if (!/^[a-z0-9_]{3,24}$/.test(username || '')) return fail(res, 'username: 3-24 chars a-z 0-9 _');
  if (typeof password !== 'string' || password.length < 8 || password.length > 200) return fail(res, 'password must be at least 8 characters');
  if (db.accounts[username]) return fail(res, 'username taken');
  if (!tx || !tx.payload || tx.type !== 'REGISTER_USER') return fail(res, 'malformed registration');
  if (tx.payload.role === 'inspector') {
    if (state.inspector) return fail(res, 'a Land Inspector is already registered on this system', 403);
    const a = Buffer.from(String(setupCode || '')), b = Buffer.from(db.setupCode);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return fail(res, 'invalid registrar setup code', 403);
  }
  if (!validBlob(kycBlob) || ch.sha256(kycBlob.iv + kycBlob.ct) !== (tx.payload.kyc || {}).cid || kycBlob.ct.length > 40000) return fail(res, 'KYC package invalid');
  const t = cleanTx(tx), r = ch.commit(db.chain, state, [t]); if (!r.ok) return fail(res, r.error);
  const secret = crypto.randomBytes(20).toString('hex'), { salt, hash } = au.hashPassword(password);
  db.accounts[username] = { username, addr: t.from, role: t.payload.role, salt, hash, totp: secret, fails: 0, lockUntil: 0 };
  db.blobs[t.payload.kyc.cid] = { iv: kycBlob.iv, ct: kycBlob.ct };
  if (t.payload.role === 'inspector') issueCert(state.users[t.from]);
  save(); const b32 = au.base32(secret);
  send(res, 200, { ok: true, block: r.block.index, totpSecret: b32, otpauth: `otpauth://totp/LandChain:${username}?secret=${b32}&issuer=LandChain`, addr: t.from });
});
route('POST', '/api/login', (req, res) => {
  if (!au.rateLimit('login:' + ip(req), 20, 60000)) return fail(res, 'too many attempts', 429);
  const { username, password, code } = req.body || {}, a = db.accounts[String(username)], bad = () => fail(res, 'invalid credentials or code', 401);
  if (!a) { au.hashPassword('x'); return bad(); }
  if (a.lockUntil > Date.now()) return fail(res, 'account temporarily locked – try again in a few minutes', 429);
  if (!au.checkPassword(String(password), a.salt, a.hash) || !au.checkTotp(a.totp, code)) { if (++a.fails >= 5) { a.lockUntil = Date.now() + 5 * 60000; a.fails = 0; } save(); return bad(); }
  a.fails = 0; save(); const t = au.newSession(username); send(res, 200, { ok: true }, { 'Set-Cookie': `sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${PROD ? '; Secure' : ''}` });
});
route('POST', '/api/logout', (req, res) => { au.sessions.delete(cookie(req).sid); send(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; Max-Age=0; Path=/' }); });
route('GET', '/api/me', (req, res) => { if (!authed(req, res)) return; const u = req.user; send(res, 200, { username: req.acc.username, addr: u.addr, name: u.name, role: u.role, verified: u.verified || u.role === 'inspector', hasCert: !!u.cert, cert: u.cert, kyc: u.kyc }); });
route('GET', '/api/directory', (req, res) => { if (!authed(req, res)) return; send(res, 200, Object.values(state.users).filter(u => u.cert).map(u => ({ addr: u.addr, name: u.name, role: u.role, wrapPub: u.wrapPub, cert: u.cert }))); });
route('GET', '/api/pending', (req, res) => { if (!inspectorOnly(req, res)) return; send(res, 200, Object.values(state.users).filter(u => !u.verified && u.role !== 'inspector').map(u => ({ addr: u.addr, name: u.name, role: u.role, kyc: { cid: u.kyc.cid, iv: u.kyc.iv, wrap: u.kyc.wraps[req.user.addr] } }))); });
route('GET', '/api/blob/:cid', (req, res) => { if (!authed(req, res)) return; const b = db.blobs[req.params.cid]; b ? send(res, 200, b) : fail(res, 'not found', 404); });
route('GET', '/api/state', (req, res) => {
  if (!authed(req, res)) return; const me = req.user, insp = me.role === 'inspector', mine = r => insp || r.buyer === me.addr || r.seller === me.addr, reqs = Object.values(state.requests).filter(mine);
  send(res, 200, { lands: Object.values(state.lands).filter(l => l.verified || insp || l.owner === me.addr), requests: reqs, transfers: Object.values(state.transfers).filter(t => reqs.some(r => r.id === t.reqId)).map(t => ({ ...t, cosigs: db.cosigs[t.reqId] || {} })) });
});
route('POST', '/api/tx', (req, res) => {
  if (!authed(req, res)) return; const { tx, blob } = req.body || {}; if (!tx) return fail(res, 'malformed');
  if (tx.from !== req.user.addr) return fail(res, 'transaction sender does not match your session', 403);
  if (['ISSUE_CERT', 'GENESIS', 'REGISTER_USER'].includes(tx.type)) return fail(res, 'not allowed here', 403);
  if (tx.type === 'LIST_LAND') { if (!validBlob(blob) || ch.sha256(blob.iv + blob.ct) !== (tx.payload || {}).cid) return fail(res, 'encrypted document package missing/invalid'); if (blob.ct.length > 16e6) return fail(res, 'documents too large (max 8 MB)'); }
  const t = cleanTx(tx), r = ch.commit(db.chain, state, [t]); if (!r.ok) return fail(res, r.error);
  if (t.type === 'LIST_LAND') db.blobs[t.payload.cid] = { iv: blob.iv, ct: blob.ct };
  if (t.type === 'VERIFY_USER') issueCert(state.users[t.payload.addr]);
  if (t.type === 'TRANSFER') delete db.cosigs[t.payload.reqId];
  save(); send(res, 200, { ok: true, block: r.block.index });
});
route('POST', '/api/transfer/:reqId/cosign', (req, res) => {
  if (!authed(req, res)) return; const t = state.transfers[req.params.reqId], me = req.user; if (!t || t.done) return fail(res, 'no pending transfer');
  const land = state.lands[t.landId], role = me.role === 'inspector' ? 'inspector' : me.addr === land.owner ? 'seller' : me.addr === t.newOwner ? 'buyer' : null;
  if (!role) return fail(res, 'you are not a party to this transfer', 403);
  const sig = String((req.body || {}).sig || '');
  if (!ch.verifySig(me.cert.signPub, sig, ch.transferMsg(land.id, t.reqId, t.newOwner, land.owner))) return fail(res, 'signature invalid');
  (db.cosigs[t.reqId] = db.cosigs[t.reqId] || {})[role] = { addr: me.addr, sig }; save(); send(res, 200, { ok: true, role });
});
route('GET', '/api/chain', (req, res) => send(res, 200, db.chain));
route('GET', '/api/audit', (req, res) => { const r = ch.audit(db.chain); send(res, 200, { ok: r.every(x => x.ok), blocks: r }); });
route('GET', '/api/health', (req, res) => send(res, 200, { ok: true, height: db.chain.length }));

const PUB = path.join(__dirname, 'public');
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x'), p = url.pathname;
    if (p.startsWith('/api/')) {
      const r = routes.find(r => r.method === req.method && r.re.test(p));
      if (!r) return fail(res, 'not found', 404);
      if (req.method !== 'GET') { if (req.headers['x-requested-with'] !== 'landchain') return fail(res, 'missing X-Requested-With header'); try { req.body = await readBody(req); } catch (e) { return fail(res, e.message, 413); } }
      req.params = r.re.exec(p).groups || {}; return r.h[0](req, res);
    }
    let f = path.normalize(path.join(PUB, p === '/' ? 'index.html' : p));
    if (!f.startsWith(PUB) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404, SEC); return res.end('Not found'); }
    res.writeHead(200, { ...SEC, 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': 'no-cache' }); fs.createReadStream(f).pipe(res);
  } catch (e) { console.error(e); if (!res.headersSent) fail(res, 'server error', 500); }
});
if (require.main === module) server.listen(PORT, () => { console.log(`LandChain Secure listening on :${PORT}`); if (!state.inspector) console.log(`Registrar setup code: ${db.setupCode}  (needed once, to create the Land Inspector account)`); });
module.exports = { server, db: () => db };
