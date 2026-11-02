/* Real cryptography via the browser's WebCrypto API (no libraries, no network).
   AES-256-GCM, RSA-OAEP-2048, ECDSA P-256, SHA-256, HMAC-SHA1 (TOTP). */
const C = (() => {
  const te = new TextEncoder(), td = new TextDecoder(), S = crypto.subtle;
  const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
  const unhex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
  const short = (h, n = 8) => !h ? '' : (h.length <= n * 2 + 1 ? h : h.slice(0, n) + '…' + h.slice(-n));
  async function sha256(s) { return hex(await S.digest('SHA-256', typeof s === 'string' ? te.encode(s) : s)); }
  function canon(o) {
    if (o === null || typeof o !== 'object') return JSON.stringify(o);
    if (Array.isArray(o)) return '[' + o.map(canon).join(',') + ']';
    return '{' + Object.keys(o).filter(k => o[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
  }
  /* AES-256-GCM (confidentiality + integrity of documents) */
  const aesGen = () => S.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  async function aesEnc(key, text) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await S.encrypt({ name: 'AES-GCM', iv }, key, te.encode(text));
    return { iv: hex(iv), ct: hex(ct) };
  }
  async function aesDec(key, o) { return td.decode(await S.decrypt({ name: 'AES-GCM', iv: unhex(o.iv) }, key, unhex(o.ct))); }
  /* ECDSA P-256 (PKI digital identity / signatures) */
  const signGen = () => S.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const sign = async (priv, msg) => hex(await S.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, te.encode(msg)));
  async function verify(pubJwk, sig, msg) {
    try {
      const k = await S.importKey('jwk', pubJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
      return await S.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, unhex(sig), te.encode(msg));
    } catch (e) { return false; }
  }
  /* RSA-OAEP-2048 (key wrapping: only the intended person can unwrap the AES key) */
  const wrapGen = () => S.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['wrapKey', 'unwrapKey']);
  async function wrap(pubJwk, aes) {
    const k = await S.importKey('jwk', pubJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']);
    return hex(await S.wrapKey('raw', aes, k, { name: 'RSA-OAEP' }));
  }
  const unwrap = (priv, h) => S.unwrapKey('raw', unhex(h), priv, { name: 'RSA-OAEP' }, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const exportJwk = async k => { const j = await S.exportKey('jwk', k); delete j.ext; return j; };
  /* TOTP (RFC 6238, HMAC-SHA1) for the simulated multi-factor step */
  async function totp(secretHex, t = Date.now()) {
    const buf = new ArrayBuffer(8); new DataView(buf).setUint32(4, Math.floor(t / 30000));
    const k = await S.importKey('raw', unhex(secretHex), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const h = new Uint8Array(await S.sign('HMAC', k, buf)); const o = h[19] & 15;
    return String((((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6)).padStart(6, '0');
  }
  async function merkle(ids) {
    if (!ids.length) return await sha256('empty');
    let l = [...ids];
    while (l.length > 1) { const n = []; for (let i = 0; i < l.length; i += 2) n.push(await sha256(l[i] + (l[i + 1] || l[i]))); l = n; }
    return l[0];
  }
  /* wallet protection: password -> PBKDF2 -> AES-GCM key that encrypts the private keys stored in the browser */
  const pbkdfKey = async (pw, saltHex) => S.deriveKey({ name: 'PBKDF2', salt: unhex(saltHex), iterations: 250000, hash: 'SHA-256' }, await S.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveKey']), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const importSignPriv = j => S.importKey('jwk', j, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const importWrapPriv = j => S.importKey('jwk', j, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['unwrapKey']);
  const b32dec = s => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = ''; for (const ch of s.replace(/=+$/, '')) bits += A.indexOf(ch).toString(2).padStart(5, '0'); const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2).toString(16).padStart(2, '0')); return out.join(''); };
  const rnd = n => hex(crypto.getRandomValues(new Uint8Array(n)));
  return { hex, unhex, short, sha256, canon, aesGen, aesEnc, aesDec, signGen, sign, verify, wrapGen, wrap, unwrap, exportJwk, totp, merkle, rnd, pbkdfKey, importSignPriv, importWrapPriv, b32dec };
})();
if (typeof module !== 'undefined') module.exports = C;
