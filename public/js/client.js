/* Browser-side logic: key generation, encryption, signing. Private keys NEVER leave the browser.
   Works in the browser and in Node (tests): LC.make({ fetch, storage }) */
const LC = (() => {
  const b64 = bytes => { let s = ''; bytes.forEach(b => s += String.fromCharCode(b)); return btoa(s); };
  const transferMsg = (landId, reqId, newOwner, owner) => C.canon({ op: 'TRANSFER_OWNERSHIP', landId, reqId, newOwner, owner });
  function make({ fetch: F, storage: store, base = '' }) {
    const cl = { wallet: null, me: null, meta: null };
    cl.api = async (method, path, body) => {
      const r = await F(base + path, { method, headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'landchain' }, body: body ? JSON.stringify(body) : undefined, credentials: 'same-origin' });
      const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status)); return j;
    };
    /* ---- wallet ---- */
    const wkey = u => 'landchain.wallet.' + u;
    async function sealWallet(username, password, w) {
      const salt = C.rnd(16), key = await C.pbkdfKey(password, salt), enc = await C.aesEnc(key, JSON.stringify(w));
      const rec = { v: 1, salt, ...enc }; store.setItem(wkey(username), JSON.stringify(rec)); return rec;
    }
    async function openWallet(rec, password) {
      const key = await C.pbkdfKey(password, rec.salt), w = JSON.parse(await C.aesDec(key, rec));
      cl.wallet = { addr: '0x' + (await C.sha256(C.canon(w.signPub))).slice(0, 40), signPub: w.signPub, wrapPub: w.wrapPub, signPriv: await C.importSignPriv(w.signPriv), wrapPriv: await C.importWrapPriv(w.wrapPriv) };
    }
    cl.exportWallet = username => store.getItem(wkey(username));
    cl.importWallet = async (username, password, json) => { const rec = JSON.parse(json); await openWallet(rec, password); store.setItem(wkey(username), json); };
    cl.hasWallet = username => !!store.getItem(wkey(username));
    cl.getMeta = async () => (cl.meta = await cl.api('GET', '/api/meta'));
    /* ---- signing ---- */
    cl.signTx = async (type, payload, extra = {}) => {
      const tx = { type, payload, from: cl.wallet.addr, ts: Date.now(), nonce: C.rnd(8) };
      tx.sig = await C.sign(cl.wallet.signPriv, C.canon({ type, payload, from: tx.from, ts: tx.ts, nonce: tx.nonce })); return { ...tx, ...extra };
    };
    cl.submit = async (type, payload, { blob, cosigs } = {}) => cl.api('POST', '/api/tx', { tx: await cl.signTx(type, payload, cosigs ? { cosigs } : {}), blob });
    /* ---- registration & login ---- */
    cl.register = async ({ username, password, name, role, kyc, setupCode }) => {
      const meta = await cl.getMeta(); if (role !== 'inspector' && !meta.inspector) throw new Error('Registry not initialised: the registrar must register first');
      const sk = await C.signGen(), wk = await C.wrapGen(), signPub = await C.exportJwk(sk.publicKey), wrapPub = await C.exportJwk(wk.publicKey);
      const addr = '0x' + (await C.sha256(C.canon(signPub))).slice(0, 40);
      const dek = await C.aesGen(), enc = await C.aesEnc(dek, JSON.stringify(kyc)), cid = await C.sha256(enc.iv + enc.ct);
      const wraps = { [addr]: await C.wrap(wrapPub, dek) }; if (meta.inspector) wraps[meta.inspector.addr] = await C.wrap(meta.inspector.wrapPub, dek);
      const w = { signPub, wrapPub, signPriv: await C.exportJwk(sk.privateKey), wrapPriv: await C.exportJwk(wk.privateKey) };
      cl.wallet = { addr, signPub, wrapPub, signPriv: sk.privateKey, wrapPriv: wk.privateKey };
      const tx = await cl.signTx('REGISTER_USER', { addr, name, role, signPub, wrapPub, kyc: { cid, iv: enc.iv, wraps } });
      const r = await cl.api('POST', '/api/register', { username, password, tx, kycBlob: enc, setupCode });
      await sealWallet(username, password, w); return r;
    };
    cl.login = async (username, password, code) => {
      await cl.api('POST', '/api/login', { username, password, code });
      const raw = store.getItem(wkey(username)); cl.wallet = null;
      if (raw) await openWallet(JSON.parse(raw), password);
      cl.me = await cl.api('GET', '/api/me'); await cl.getMeta();
      if (cl.wallet && cl.wallet.addr !== cl.me.addr) { cl.wallet = null; }
      return { needWallet: !cl.wallet };
    };
    cl.logout = async () => { await cl.api('POST', '/api/logout'); cl.wallet = null; cl.me = null; };
    /* ---- documents ---- */
    cl.fetchBlob = async cid => { const b = await cl.api('GET', '/api/blob/' + cid); if (await C.sha256(b.iv + b.ct) !== cid) throw new Error('Stored ciphertext does not match its on-chain hash'); return b; };
    cl.decryptLand = async land => {
      const w = land.wraps[cl.wallet.addr]; if (!w) throw new Error('ACCESS DENIED – no key was shared with you for this land');
      const dek = await C.unwrap(cl.wallet.wrapPriv, w); return JSON.parse(await C.aesDec(dek, await cl.fetchBlob(land.cid)));
    };
    cl.decryptKyc = async p => { const dek = await C.unwrap(cl.wallet.wrapPriv, p.kyc.wrap); return JSON.parse(await C.aesDec(dek, await cl.fetchBlob(p.kyc.cid))); };
    cl.approveUser = addr => cl.submit('VERIFY_USER', { addr });
    cl.listLand = async ({ area, city, state, price, survey, files, notes }) => {
      const meta = await cl.getMeta(); if (!meta.inspector) throw new Error('no registrar');
      const dek = await C.aesGen(), enc = await C.aesEnc(dek, JSON.stringify({ files, notes: notes || '' })), cid = await C.sha256(enc.iv + enc.ct);
      const wraps = { [cl.wallet.addr]: await C.wrap(cl.wallet.wrapPub, dek), [meta.inspector.addr]: await C.wrap(meta.inspector.wrapPub, dek) };
      return cl.submit('LIST_LAND', { id: meta.nextLand, area: +area, city, state, price: +price, survey, cid, iv: enc.iv, wraps }, { blob: enc });
    };
    cl.verifyLand = async land => { await cl.decryptLand(land); return cl.submit('VERIFY_LAND', { landId: land.id }); };
    cl.requestBuy = landId => cl.submit('REQUEST_BUY', { landId });
    cl.grant = async (req, land) => {
      const dir = await cl.api('GET', '/api/directory'), buyer = dir.find(d => d.addr === req.buyer); if (!buyer) throw new Error('buyer has no certificate');
      const dek = await C.unwrap(cl.wallet.wrapPriv, land.wraps[cl.wallet.addr]);
      return cl.submit('GRANT_ACCESS', { reqId: req.id, landId: land.id, buyer: req.buyer, wrap: await C.wrap(buyer.wrapPub, dek) });
    };
    cl.pay = (req, land) => cl.submit('PAYMENT', { reqId: req.id, amount: land.price, ref: 'SIM-UTR-' + C.rnd(5).toUpperCase() });
    cl.signTransfer = async (t, land) => cl.api('POST', `/api/transfer/${t.reqId}/cosign`, { sig: await C.sign(cl.wallet.signPriv, transferMsg(land.id, t.reqId, t.newOwner, land.owner)) });
    cl.finalizeTransfer = async (t, land) => {
      const cs = ['seller', 'buyer', 'inspector'].map(r => t.cosigs[r]); if (cs.some(x => !x)) throw new Error('waiting for all three signatures');
      return cl.submit('TRANSFER', { landId: land.id, reqId: t.reqId, newOwner: t.newOwner, owner: land.owner }, { cosigs: cs });
    };
    cl.state = () => cl.api('GET', '/api/state');
    return cl;
  }
  return { make, transferMsg, b64 };
})();
if (typeof module !== 'undefined') module.exports = LC;
