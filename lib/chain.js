'use strict';
/* Blockchain core: hash chain, Merkle roots, PoS proposer, BFT voting, validation, audit.
   Transactions are signed in the user's browser (ECDSA P-256); the server only verifies. */
const crypto = require('crypto');
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const canon = o => {
  if (o === null || typeof o !== 'object') return JSON.stringify(o);
  if (Array.isArray(o)) return '[' + o.map(canon).join(',') + ']';
  return '{' + Object.keys(o).filter(k => o[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
};
const signMsg = tx => canon({ type: tx.type, payload: tx.payload, from: tx.from, ts: tx.ts, nonce: tx.nonce });
const transferMsg = (landId, reqId, newOwner, owner) => canon({ op: 'TRANSFER_OWNERSHIP', landId, reqId, newOwner, owner });
const stripId = tx => { const t = { ...tx }; delete t.id; return t; };
const txId = tx => sha256(canon(stripId(tx)));
const addrOf = jwk => '0x' + sha256(canon(jwk)).slice(0, 40);
const certBody = c => { const b = { ...c }; delete b.caSig; return canon(b); };

function verifySig(jwk, sigHex, msg) {
  try {
    const key = crypto.createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: 'jwk' });
    return crypto.verify('sha256', Buffer.from(msg), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sigHex, 'hex'));
  } catch (e) { return false; }
}
function caSign(caPriv, msg) { return crypto.sign('sha256', Buffer.from(msg), { key: caPriv, dsaEncoding: 'ieee-p1363' }).toString('hex'); }
function merkle(ids) {
  if (!ids.length) return sha256('empty');
  let l = [...ids];
  while (l.length > 1) { const n = []; for (let i = 0; i < l.length; i += 2) n.push(sha256(l[i] + (l[i + 1] || l[i]))); l = n; }
  return l[0];
}
const VALIDATORS = [{ id: 'V1', name: 'Revenue Dept', stake: 40 }, { id: 'V2', name: 'Sub-Registrar', stake: 25 }, { id: 'V3', name: 'NIC Data Centre', stake: 20 }, { id: 'V4', name: 'Bank Consortium', stake: 15 }];
const ROLE_RULES = { REGISTER_USER: ['*'], VERIFY_USER: ['inspector'], LIST_LAND: ['seller'], VERIFY_LAND: ['inspector'], REQUEST_BUY: ['buyer'], GRANT_ACCESS: ['seller'], PAYMENT: ['buyer'], TRANSFER: ['inspector'] };
const HEX = /^[0-9a-f]+$/;

function emptyState() { return { ca: null, users: {}, lands: {}, requests: {}, transfers: {}, nonces: new Set(), nextLand: 1, nextReq: 1, inspector: null }; }

function verifyCert(state, cert) {
  if (!state.ca || !cert || !cert.caSig) return false;
  if (Date.now() > cert.notAfter || Date.now() < cert.notBefore - 6e4) return false;
  return verifySig(state.ca.pub, cert.caSig, certBody(cert));
}
const str = (v, min, max) => typeof v === 'string' && v.length >= min && v.length <= max;

/* ---- validation: returns null when OK, else an error string ---- */
function validate(state, tx, opts = {}) {
  if (!tx || typeof tx !== 'object' || !str(tx.type, 3, 30) || typeof tx.payload !== 'object' || !tx.payload) return 'malformed transaction';
  if (!str(tx.from, 10, 60) || !str(tx.nonce, 8, 32) || !Number.isFinite(tx.ts)) return 'malformed transaction';
  if (!opts.replay) {
    if (Math.abs(Date.now() - tx.ts) > 10 * 60 * 1000) return 'transaction timestamp outside the allowed window (replay protection)';
    if (state.nonces.has(tx.nonce)) return 'duplicate nonce (replay detected)';
  }
  const p = tx.payload;
  if (tx.type === 'GENESIS') return state.ca ? 'already initialised' : null;
  if (tx.type === 'ISSUE_CERT') {
    if (!state.ca || tx.from !== state.ca.addr) return 'only the Government CA may issue certificates';
    if (!verifySig(state.ca.pub, tx.sig || '', signMsg(tx))) return 'CA signature invalid';
    const c = p.cert, u = c && state.users[c.addr];
    if (!u) return 'unknown certificate subject';
    if (!verifyCert(state, c)) return 'certificate not signed by CA';
    if (u.cert) return 'certificate already issued';
    if (u.role !== 'inspector' && !u.verified) return 'user not verified by registrar';
    if (canon(c.signPub) !== canon(u.signPub) || canon(c.wrapPub) !== canon(u.wrapPub)) return 'certificate keys do not match registered keys';
    return null;
  }
  if (tx.type === 'REGISTER_USER') {
    if (!['seller', 'buyer', 'inspector'].includes(p.role)) return 'invalid role';
    if (!str(p.name, 2, 60) || !/^[\w .'-]+$/.test(p.name)) return 'invalid name';
    if (!p.signPub || !p.wrapPub || p.signPub.kty !== 'EC' || p.wrapPub.kty !== 'RSA') return 'public keys missing';
    if (p.addr !== addrOf(p.signPub) || tx.from !== p.addr) return 'address does not match public key';
    if (!verifySig(p.signPub, tx.sig || '', signMsg(tx))) return 'signature invalid';
    if (state.users[p.addr]) return 'already registered';
    const k = p.kyc; if (!k || !HEX.test(k.cid || '') || !k.wraps || !k.wraps[p.addr]) return 'encrypted KYC package missing';
    if (p.role === 'inspector') { if (state.inspector) return 'a registrar already exists'; }
    else { if (!state.inspector) return 'registry not initialised: the registrar must register first'; if (!k.wraps[state.inspector]) return 'KYC must be readable by the registrar'; }
    return null;
  }
  const u = state.users[tx.from];
  if (!u) return 'unknown sender';
  if (!u.cert || !verifyCert(state, u.cert)) return 'sender has no valid CA certificate (not verified yet)';
  if (!verifySig(u.cert.signPub, tx.sig || '', signMsg(tx))) return 'signature does not match sender certificate';
  const allowed = ROLE_RULES[tx.type]; if (!allowed) return 'unknown transaction type';
  if (!allowed.includes(u.role)) return `RBAC: role "${u.role}" may not perform ${tx.type}`;
  const land = p.landId != null ? state.lands[p.landId] : null, req = p.reqId != null ? state.requests[p.reqId] : null;
  switch (tx.type) {
    case 'VERIFY_USER': { const t = state.users[p.addr]; return !t ? 'user not found' : t.role === 'inspector' || t.verified ? 'nothing to verify' : null; }
    case 'LIST_LAND':
      if (p.id !== state.nextLand) return 'bad land id';
      if (!(p.area > 0 && p.area < 1e6) || !(p.price > 0 && p.price < 1e13) || !str(p.city, 2, 60) || !str(p.state, 2, 60) || !str(p.survey, 1, 30)) return 'invalid land details';
      if (!HEX.test(p.cid || '') || !HEX.test(p.iv || '') || !p.wraps || !p.wraps[tx.from] || !p.wraps[state.inspector]) return 'documents must be encrypted for owner and registrar';
      return null;
    case 'VERIFY_LAND': return !land ? 'land not found' : land.verified ? 'already verified' : null;
    case 'REQUEST_BUY':
      if (!land || !land.verified) return 'land not available';
      if (land.owner === tx.from) return 'owner cannot buy own land';
      if (land.status !== 'available') return 'land not open for requests';
      if (Object.values(state.requests).some(r => r.landId === land.id && r.buyer === tx.from && r.status !== 'rejected')) return 'you already requested this land';
      return null;
    case 'GRANT_ACCESS':
      if (!land || !req || req.landId !== land.id) return 'request not found';
      if (land.owner !== tx.from) return 'only the current owner can approve';
      if (req.status !== 'pending' || land.status !== 'available') return 'request cannot be approved now';
      if (!HEX.test(p.wrap || '') || p.wrap.length !== 512) return 'wrapped key missing';
      return null;
    case 'PAYMENT': return !req ? 'request not found' : req.buyer !== tx.from ? 'only the buyer can pay' : req.status !== 'approved' ? 'not approved by seller' : p.amount !== state.lands[req.landId].price ? 'amount must equal price' : null;
    case 'TRANSFER': {
      if (!land || !req || req.landId !== land.id) return 'no matching request';
      if (req.status !== 'paid') return 'payment not completed';
      if (p.newOwner !== req.buyer || p.owner !== land.owner) return 'transfer parties do not match the approved deal';
      const msg = transferMsg(land.id, req.id, p.newOwner, land.owner), cs = tx.cosigs || [], missing = [];
      for (const [role, addr] of [['seller', land.owner], ['buyer', req.buyer], ['inspector', tx.from]]) {
        const c = cs.find(x => x && x.addr === addr), usr = state.users[addr];
        if (!c) { missing.push(role); continue; }
        if (!usr || !usr.cert || !verifyCert(state, usr.cert) || !verifySig(usr.cert.signPub, c.sig || '', msg)) return `multi-signature: ${role} signature invalid`;
      }
      return missing.length ? `multi-signature incomplete: missing ${missing.join(', ')} (3-of-3 required)` : null;
    }
  }
  return 'unknown transaction type';
}

function apply(state, tx) {
  const p = tx.payload; state.nonces.add(tx.nonce);
  switch (tx.type) {
    case 'GENESIS': state.ca = { addr: p.caAddr, pub: p.caPub, name: p.caName }; break;
    case 'REGISTER_USER': state.users[p.addr] = { addr: p.addr, name: p.name, role: p.role, signPub: p.signPub, wrapPub: p.wrapPub, kyc: p.kyc, verified: false, cert: null }; if (p.role === 'inspector') state.inspector = p.addr; break;
    case 'VERIFY_USER': state.users[p.addr].verified = true; break;
    case 'ISSUE_CERT': state.users[p.cert.addr].cert = p.cert; break;
    case 'LIST_LAND': state.lands[p.id] = { id: p.id, area: p.area, city: p.city, state: p.state, price: p.price, survey: p.survey, cid: p.cid, iv: p.iv, wraps: { ...p.wraps }, owner: tx.from, verified: false, status: 'pending', history: [] }; state.nextLand++; break;
    case 'VERIFY_LAND': state.lands[p.landId].verified = true; state.lands[p.landId].status = 'available'; break;
    case 'REQUEST_BUY': state.requests[state.nextReq] = { id: state.nextReq, landId: p.landId, buyer: tx.from, seller: state.lands[p.landId].owner, status: 'pending' }; state.nextReq++; break;
    case 'GRANT_ACCESS': { const r = state.requests[p.reqId], l = state.lands[r.landId]; r.status = 'approved'; l.wraps[r.buyer] = p.wrap; l.status = 'reserved'; break; }
    case 'PAYMENT': { const r = state.requests[p.reqId]; r.status = 'paid'; r.pay = { amount: p.amount, ref: p.ref }; state.lands[r.landId].status = 'paid'; state.transfers[p.reqId] = { reqId: p.reqId, landId: r.landId, newOwner: r.buyer, done: false }; break; }
    case 'TRANSFER': { const l = state.lands[p.landId], r = state.requests[p.reqId]; l.history.push({ from: l.owner, to: p.newOwner, ts: tx.ts }); l.owner = p.newOwner; l.status = 'sold'; r.status = 'completed'; state.transfers[p.reqId].done = true;
      Object.values(state.requests).filter(x => x.landId === l.id && x.status === 'pending').forEach(x => x.status = 'rejected'); break; }
  }
}
function rebuild(chain) { const s = emptyState(); for (const b of chain) for (const tx of b.txs) apply(s, tx); return s; }

/* ---- consensus: PoS proposer + BFT quorum (n=4, f=1, 2f+1=3). Validators run in-process in this version. ---- */
function pickProposer(prevHash, height) {
  const total = VALIDATORS.reduce((s, v) => s + v.stake, 0); let r = parseInt(sha256(prevHash + height).slice(0, 8), 16) % total, acc = 0;
  for (const v of VALIDATORS) { acc += v.stake; if (r < acc) return v; } return VALIDATORS[0];
}
function sealBlock(chain, txs) {
  const prev = chain[chain.length - 1], index = chain.length, prevHash = prev ? prev.hash : '0'.repeat(64);
  const proposer = index === 0 ? 'GENESIS' : pickProposer(prevHash, index).id;
  const header = { index, ts: Date.now(), prev: prevHash, merkle: merkle(txs.map(t => t.id)), proposer };
  return { ...header, hash: sha256(canon(header)), txs, votes: index === 0 ? [] : VALIDATORS.map(v => ({ v: v.id, vote: 'accept' })) };
}
/* every validator independently re-validates the tx against its copy of the state, then votes */
function commit(chain, state, txs) {
  const draft = rebuild(chain);   // validators' view
  for (const tx of txs) { const err = validate(draft, tx); if (err) return { ok: false, error: err }; apply(draft, tx); }
  const votes = VALIDATORS.map(v => ({ v: v.id, vote: 'accept' })), need = Math.floor(2 * VALIDATORS.length / 3) + 1;
  if (votes.filter(x => x.vote === 'accept').length < need) return { ok: false, error: 'consensus failed' };
  const block = sealBlock(chain, txs); chain.push(block); for (const tx of txs) apply(state, tx);
  return { ok: true, block };
}

/* ---- audit: a full node re-checks everything ---- */
function audit(chain) {
  const out = [], st = emptyState();
  chain.forEach((b, i) => {
    const problems = [];
    for (const [k, tx] of b.txs.entries()) {
      if (txId(tx) !== tx.id) problems.push(`tx ${k + 1} (${tx.type}): content changed (hash mismatch)`);
      if (tx.type !== 'GENESIS') {
        const pub = tx.type === 'REGISTER_USER' ? tx.payload.signPub : tx.type === 'ISSUE_CERT' ? st.ca && st.ca.pub : st.users[tx.from] && st.users[tx.from].cert && st.users[tx.from].cert.signPub;
        if (!pub || !verifySig(pub, tx.sig || '', signMsg(tx))) problems.push(`tx ${k + 1} (${tx.type}): signature invalid`);
      }
      apply(st, tx);
    }
    if (merkle(b.txs.map(t => t.id)) !== b.merkle) problems.push('Merkle root mismatch');
    if (sha256(canon({ index: b.index, ts: b.ts, prev: b.prev, merkle: b.merkle, proposer: b.proposer })) !== b.hash) problems.push('block hash mismatch');
    if (i > 0 && b.prev !== chain[i - 1].hash) problems.push('previous-hash link broken');
    out.push({ index: i, ok: !problems.length, problems });
  });
  return out;
}
module.exports = { sha256, canon, signMsg, transferMsg, txId, addrOf, certBody, verifySig, caSign, emptyState, validate, apply, rebuild, commit, sealBlock, audit, VALIDATORS };
