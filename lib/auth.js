'use strict';
const crypto = require('crypto');
const scrypt = (pw, salt) => crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
function hashPassword(pw) { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: scrypt(pw, salt) }; }
function checkPassword(pw, salt, hash) { const a = Buffer.from(scrypt(pw, salt), 'hex'), b = Buffer.from(hash, 'hex'); return a.length === b.length && crypto.timingSafeEqual(a, b); }
function totp(secretHex, t = Date.now()) {
  const buf = Buffer.alloc(8); buf.writeUInt32BE(Math.floor(t / 30000), 4);
  const h = crypto.createHmac('sha1', Buffer.from(secretHex, 'hex')).update(buf).digest(), o = h[19] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1e6)).padStart(6, '0');
}
function checkTotp(secretHex, code) { code = String(code || ''); if (!/^\d{6}$/.test(code)) return false; return [-1, 0, 1].some(d => { const a = Buffer.from(totp(secretHex, Date.now() + d * 30000)), b = Buffer.from(code); return crypto.timingSafeEqual(a, b); }); }
function base32(hex) { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '', out = ''; for (const b of Buffer.from(hex, 'hex')) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; }
const sessions = new Map();
function newSession(username) { const t = crypto.randomBytes(32).toString('hex'); sessions.set(t, { username, exp: Date.now() + 8 * 3600e3 }); return t; }
function getSession(t) { const s = sessions.get(t); if (!s) return null; if (s.exp < Date.now()) { sessions.delete(t); return null; } return s; }
const hits = new Map();
function rateLimit(key, max, windowMs) { const now = Date.now(), a = (hits.get(key) || []).filter(x => now - x < windowMs); a.push(now); hits.set(key, a); return a.length <= max; }
module.exports = { hashPassword, checkPassword, totp, checkTotp, base32, newSession, getSession, sessions, rateLimit };
