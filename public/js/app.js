/* LandChain Secure – browser UI. All secrets (private keys, document keys) stay in this browser. */
const cl = LC.make({ fetch: (...a) => fetch(...a), storage: window.localStorage });
const U = { tab: 'market', busy: false, authTab: 'login', st: null, dir: [], pend: [], audit: null, chain: null, modal: null, reg: null, inspectorExists: false };
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const inr = n => '₹ ' + Number(n).toLocaleString('en-IN');
const nameOf = a => (U.dir.find(d => d.addr === a) || {}).name || (a ? a.slice(0, 8) + '…' : '—');
const ROLE = { seller: 'Seller', buyer: 'Buyer', inspector: 'Land Inspector' };
const STATUS = { pending: ['awaiting inspector', 'a'], available: ['available', 'g'], reserved: ['reserved', 'a'], paid: ['paid – transfer pending', 'a'], sold: ['sold', ''] };

function toast(m, k) { const d = document.createElement('div'); d.className = 't ' + k; d.textContent = m; $('#toast').append(d); setTimeout(() => d.remove(), 4500); }
const pretty = o => JSON.stringify(o, (k, v) => typeof v === 'string' && v.length > 60 ? `${v.slice(0, 16)}…${v.slice(-6)} (${v.length >> 1} bytes)` : v, 2);

/* ---------- password show/hide (called after render, not inside html string) ---------- */
function attachPasswordToggles() {
  document.querySelectorAll('[data-pwfor]').forEach(btn => {
    btn.onclick = () => {
      const inp = document.getElementById(btn.dataset.pwfor);
      if (!inp) return;
      inp.type = inp.type === 'password' ? 'text' : 'password';
      btn.textContent = inp.type === 'password' ? 'Show' : 'Hide';
    };
  });
}

/* ---------- aadhaar: digits only, max 12 ---------- */
function attachAadhaarFormat() {
  const inp = document.getElementById('r_aad');
  if (!inp) return;
  inp.addEventListener('input', () => {
    inp.value = inp.value.replace(/\D/g, '').slice(0, 12);
  });
}

/* ---------- views ---------- */
function authView() {
  if (U.reg) {
    const uri = encodeURIComponent(`otpauth://totp/LandChain:${U.reg.username || 'user'}?secret=${U.reg.totpSecret}&issuer=LandChain`);
    const qrSrc = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${uri}`;
    return `<div class="card narrow">
      <h2>Account created</h2>
      <p>Scan this QR code with <b>Google Authenticator</b> or <b>Microsoft Authenticator</b>. You need the 6-digit code every time you log in.</p>
      <div style="text-align:center;margin:12px 0">
        <img src="${qrSrc}" width="200" height="200" alt="Scan QR" style="border:4px solid #e2e8f0;border-radius:8px"
          onerror="this.style.display='none';document.getElementById('qrFallback').style.display='block'">
      </div>
      <div id="qrFallback" style="display:none" class="banner a small">QR could not load. Enter the key manually in the app.</div>
      <p class="small" style="text-align:center">Or enter this key manually in the authenticator app:</p>
      <div class="otp" style="font-size:15px;letter-spacing:2px;text-align:center;user-select:all;word-break:break-all">${esc(U.reg.totpSecret)}</div>
      <div class="banner a small" style="margin-top:10px"><b>Live code right now:</b> <b class="mono" id="demoCode" style="font-size:18px;letter-spacing:3px">······</b></div>
      <p class="small">Download your key backup — it is the only way to log in from another browser or device.</p>
      <div class="row">
        <button data-act="backup">Download key backup</button>
        <button class="ghost" data-act="regdone">Continue to login</button>
      </div>
      ${U.reg.role !== 'inspector' ? '<p class="small mut">The Land Inspector must verify your KYC before you can transact.</p>' : ''}
    </div>`;
  }

  const reg = U.authTab === 'register';
  if (reg) {
    return `<div class="card narrow">
      <div class="row">
        <button class="ghost" data-act="authtab" data-k="login">Login</button>
        <button data-act="authtab" data-k="register">Register</button>
      </div>
      ${!U.inspectorExists ? `<div class="banner a small"><b>First time setup:</b> No Land Inspector registered yet. If you are the government registrar, select the Land Inspector role below and enter the setup code from the server terminal.</div>` : ''}
      <div class="banner g small">
        <b>Which role should I choose?</b><br>
        <b>Seller</b> — I own land and want to register or sell it.<br>
        <b>Buyer</b> — I want to search and purchase land.
        ${!U.inspectorExists ? '<br><b>Land Inspector</b> — I am the government registrar.' : ''}
      </div>
      <label>Username (a-z 0-9 _ only)</label>
      <input id="r_user" autocomplete="username">
      <label>Password (min 8 characters)</label>
      <div style="display:flex;gap:6px">
        <input id="r_pass" type="password" style="flex:1" autocomplete="new-password">
        <button type="button" class="ghost sm" data-pwfor="r_pass">Show</button>
      </div>
      <label>Full name</label>
      <input id="r_name">
      <label>Role</label>
      <select id="r_role">
        <option value="seller">Seller — I want to register / sell land</option>
        <option value="buyer">Buyer — I want to purchase land</option>
        ${!U.inspectorExists ? '<option value="inspector">Land Inspector — Government registrar (admin)</option>' : ''}
      </select>
      <div class="cols">
        <div>
          <label>Aadhaar (12 digits)</label>
          <div style="display:flex;gap:6px">
            <input id="r_aad" type="password" placeholder="Enter 12-digit Aadhaar" maxlength="12" inputmode="numeric" style="flex:1" autocomplete="off">
            <button type="button" class="ghost sm" data-pwfor="r_aad">Show</button>
          </div>
        </div>
        <div>
          <label>PAN</label>
          <input id="r_pan" placeholder="ABCDE1234F" maxlength="10" style="text-transform:uppercase">
        </div>
      </div>
      <label>Phone</label>
      <input id="r_phone" inputmode="tel">
      <label>Address</label>
      <input id="r_addr">
      <div id="r_setup" style="display:none">
        <label>Registrar setup code (from server terminal)</label>
        <input id="r_code" placeholder="paste the code from terminal">
      </div>
      <p class="small mut">Your KYC is <b>encrypted in your browser (AES-256-GCM)</b> before being sent. The server never sees your Aadhaar or PAN in plain text.</p>
      <button data-act="register">Create account</button>
    </div>`;
  }

  /* login form */
  return `<div class="card narrow">
    <div class="row">
      <button data-act="authtab" data-k="login">Login</button>
      <button class="ghost" data-act="authtab" data-k="register">Register</button>
    </div>
    <label>Username</label>
    <input id="l_user" autocomplete="username">
    <label>Password</label>
    <div style="display:flex;gap:6px">
      <input id="l_pass" type="password" style="flex:1" autocomplete="current-password">
      <button type="button" class="ghost sm" data-pwfor="l_pass">Show</button>
    </div>
    <label>Authenticator code (6 digits)</label>
    <input id="l_code" inputmode="numeric" maxlength="6">
    <p></p>
    <button data-act="login">Login</button>
  </div>`;
}

function landCard(l) {
  const [sl, sc] = STATUS[l.status] || ['', ''], me = cl.me, has = !!l.wraps[me.addr], myReq = (U.st.requests || []).find(r => r.landId === l.id && r.buyer === me.addr);
  return `<div class="card">
    <div class="row"><h3>Land #${l.id} · ${l.area} acres</h3><span class="sp"></span><span class="chip ${sc}">${sl}</span></div>
    <div class="kv"><span>Location</span><span>${esc(l.city)}, ${esc(l.state)}</span><span>Survey no.</span><span>${esc(l.survey)}</span><span>Price</span><b>${inr(l.price)}</b><span>Owner</span><span>${esc(nameOf(l.owner))}</span></div>
    <div class="vault"><b>Documents encrypted (AES-256-GCM)</b><div class="hex">CID ${esc(l.cid)}</div>
      <div class="small">Keys held by: ${Object.keys(l.wraps).map(a => esc(nameOf(a))).join(', ')}<br>
      ${has ? 'You hold a decryption key' : 'You have no key — the owner must approve you first'}</div>
    </div>
    <div class="row">
      ${has ? `<button class="sm ghost" data-act="open" data-id="${l.id}">Decrypt &amp; open documents</button>` : ''}
      ${me.role === 'buyer' && l.status === 'available' && !myReq && me.verified ? `<button class="sm green" data-act="buy" data-id="${l.id}">Request to buy</button>` : ''}
      ${myReq ? `<span class="chip a">your request: ${myReq.status}</span>` : ''}
    </div>
  </div>`;
}

function transfers() {
  const me = cl.me, ts = (U.st.transfers || []).filter(t => !t.done);
  if (!ts.length) return '';
  return `<div class="card"><h3>Ownership transfers (3-of-3 multi-signature)</h3>
    ${ts.map(t => {
      const l = U.st.lands.find(x => x.id === t.landId); if (!l) return '';
      const role = me.role === 'inspector' ? 'inspector' : me.addr === l.owner ? 'seller' : me.addr === t.newOwner ? 'buyer' : null;
      const all = ['seller', 'buyer', 'inspector'].every(r => t.cosigs[r]);
      return `<div class="tx"><b>Land #${l.id}</b>: ${esc(nameOf(l.owner))} → ${esc(nameOf(t.newOwner))} · ${inr(l.price)}
        <div class="row small">
          ${['seller', 'buyer', 'inspector'].map(r => `<span class="chip ${t.cosigs[r] ? 'g' : 'a'}">${r} ${t.cosigs[r] ? 'signed' : 'pending'}</span>`).join('')}
          ${role && !t.cosigs[role] ? `<button class="sm green" data-act="sign" data-r="${t.reqId}">Sign as ${role}</button>` : ''}
          ${me.role === 'inspector' && all ? `<button class="sm" data-act="final" data-r="${t.reqId}">Commit transfer to blockchain</button>` : ''}
        </div>
      </div>`;
    }).join('')}
  </div>`;
}

function dashView() {
  const me = cl.me, st = U.st; let h = '';
  if (me.role === 'seller') {
    h += `<div class="card"><h3>List a new land</h3>
      <div class="cols">
        <div><label>Area (acres)</label><input id="f_area" value="2.4"></div>
        <div><label>City</label><input id="f_city" value="Visakhapatnam"></div>
        <div><label>State</label><input id="f_state" value="Andhra Pradesh"></div>
        <div><label>Price (Rs)</label><input id="f_price" value="4800000"></div>
        <div><label>Survey no.</label><input id="f_survey" value="112/3A"></div>
      </div>
      <label>Documents (sale deed, survey sketch, encumbrance certificate) max 8 MB</label>
      <input id="f_files" type="file" multiple>
      <p class="small mut">Files are encrypted in your browser before upload. The server never sees them in plain text.</p>
      <button data-act="list">Encrypt &amp; list land</button>
    </div>`;
    const rq = st.requests.filter(r => r.seller === me.addr && r.status === 'pending');
    h += `<div class="card"><h3>Buy requests on my lands</h3>
      ${rq.map(r => `<div class="tx row"><span>Land #${r.landId} · <b>${esc(nameOf(r.buyer))}</b></span><span class="sp"></span><button class="sm green" data-act="grant" data-r="${r.id}">Approve &amp; share document key</button></div>`).join('') || '<p class="mut small">No pending requests.</p>'}
    </div>`;
  }
  if (me.role === 'buyer') {
    h += `<div class="card"><h3>My purchase requests</h3>
      ${st.requests.filter(r => r.buyer === me.addr).map(r => {
        const l = st.lands.find(x => x.id === r.landId) || {};
        return `<div class="tx row">
          <span>Land #${r.landId} · ${esc(l.city || '')} · ${inr(l.price || 0)}</span>
          <span class="chip a">${r.status}</span><span class="sp"></span>
          ${r.status === 'approved' ? `<button class="sm ghost" data-act="open" data-id="${r.landId}">Decrypt documents</button><button class="sm green" data-act="pay" data-r="${r.id}">Pay ${inr(l.price)} (simulated)</button>` : ''}
        </div>`;
      }).join('') || '<p class="mut small">No requests yet. Open the Marketplace to find land.</p>'}
    </div>`;
  }
  if (me.role === 'inspector') {
    h += `<div class="banner g small">
      <b>Inspector workflow:</b><br>
      Step 1 — Verify users (KYC) below<br>
      Step 2 — Verify listed lands<br>
      Step 3 — Sign ownership transfers<br>
      Step 4 — Commit transfer to blockchain once all 3 parties have signed
    </div>`;
    h += `<div class="card"><h3>Users awaiting KYC verification</h3>
      ${U.pend.map(p => `<div class="tx row"><span><b>${esc(p.name)}</b> <span class="chip">${esc(p.role)}</span></span><span class="sp"></span><button class="sm ghost" data-act="kyc" data-a="${esc(p.addr)}">Decrypt &amp; review KYC</button></div>`).join('') || '<p class="mut small">None pending.</p>'}
    </div>`;
    h += `<div class="card"><h3>Lands awaiting verification</h3>
      ${st.lands.filter(l => !l.verified).map(l => `<div class="tx row"><span>Land #${l.id} · ${esc(l.city)} · by ${esc(nameOf(l.owner))}</span><span class="sp"></span><button class="sm green" data-act="verifyland" data-id="${l.id}">Review &amp; verify</button></div>`).join('') || '<p class="mut small">None pending.</p>'}
    </div>`;
  }
  h += transfers();
  const mine = st.lands.filter(l => l.owner === me.addr);
  h += `<div class="card"><h3>${me.role === 'seller' ? 'My listed lands' : 'Lands I own'}</h3>
    ${mine.map(l => `<div class="tx"><b>Land #${l.id}</b> · ${esc(l.city)} · ${inr(l.price)} <span class="chip ${STATUS[l.status][1]}">${STATUS[l.status][0]}</span>
      ${l.history.length ? `<div class="small mut">History: ${l.history.map(x => esc(nameOf(x.from)) + ' to ' + esc(nameOf(x.to)) + ' (' + new Date(x.ts).toLocaleDateString() + ')').join(' → ')}</div>` : ''}
    </div>`).join('') || '<p class="mut small">None.</p>'}
  </div>`;
  return h;
}

function ledgerView() {
  const au = U.audit, ch = U.chain || [];
  return `<div class="card">
    <div class="row"><h2>Blockchain explorer</h2><span class="sp"></span><button data-act="audit">Audit whole chain</button></div>
    <p class="small mut">${ch.length} blocks · SHA-256 hash chain + Merkle roots · BFT 3-of-4 voting · every transaction ECDSA-signed.</p>
    ${au ? `<div class="banner ${au.ok ? 'g' : 'r'}">${au.ok ? 'Audit passed: every hash, Merkle root, link and signature is valid.' : 'Audit FAILED — the chain was tampered with.'}</div>` : ''}
  </div>
  ${[...ch].reverse().map(b => {
    const a = au && au.blocks[b.index];
    return `<div class="card block ${a ? (a.ok ? 'good' : 'bad') : ''}">
      <div class="row">
        <b>Block #${b.index}</b>
        <span class="mono small">${esc(b.hash.slice(0, 20))}…</span>
        <span class="sp"></span>
        ${a ? `<span class="chip ${a.ok ? 'g' : 'r'}">${a.ok ? 'valid' : 'INVALID'}</span>` : ''}
        <span class="chip">proposer ${esc(b.proposer)}</span>
        <span class="chip">${b.votes.length ? b.votes.filter(v => v.vote === 'accept').length + '/' + b.votes.length + ' votes' : 'genesis'}</span>
      </div>
      ${a && !a.ok ? `<div class="banner r small">${a.problems.map(esc).join('<br>')}</div>` : ''}
      ${b.txs.map(t => `<div class="tx">
        <span class="chip">${esc(t.type)}</span>
        ${t.sig ? `<span class="chip g">ECDSA ${esc(t.sig.slice(0, 8))}…</span>` : ''}
        ${t.cosigs ? `<span class="chip g">${t.cosigs.length}-of-3 multisig</span>` : ''}
        <details><summary>payload</summary><pre>${esc(pretty(t.payload))}</pre></details>
      </div>`).join('')}
    </div>`;
  }).join('')}`;
}

function secView() {
  const me = cl.me, c = me.cert;
  return `<div class="card"><h2>My digital identity</h2>
    ${c ? `<div class="banner g">Certificate issued by <b>${esc(c.issuer)}</b>, valid until ${new Date(c.notAfter).toLocaleDateString()}</div>
      <div class="kv">
        <span>Name</span><span>${esc(c.subject)}</span>
        <span>Role</span><span>${esc(c.role)}</span>
        <span>Address</span><span class="mono">${esc(c.addr)}</span>
        <span>Serial</span><span class="mono">${esc(c.serial)}</span>
        <span>CA signature</span><span class="mono">${esc(c.caSig.slice(0, 40))}…</span>
      </div>`
    : '<div class="banner a">No certificate yet. The Land Inspector must verify your KYC first.</div>'}
    <div class="row" style="margin-top:10px"><button class="ghost" data-act="backup">Download key backup</button></div>
  </div>
  <div class="card"><h3>Security features active on your account</h3><ul>
    <li><b>Password</b>: scrypt-hashed, never stored in plain text. Account locks after 5 failed attempts.</li>
    <li><b>MFA</b>: 6-digit TOTP code required at every login.</li>
    <li><b>Private keys</b>: generated in your browser, encrypted with your password (PBKDF2 + AES-GCM), never sent to the server.</li>
    <li><b>KYC and documents</b>: AES-256-GCM encrypted in your browser. The server only stores ciphertext.</li>
    <li><b>Every transaction</b>: ECDSA P-256 signed and verified against your CA-issued certificate.</li>
    <li><b>Ownership transfer</b>: requires signatures from seller + buyer + inspector (3-of-3).</li>
  </ul></div>`;
}

function render() {
  if (!cl.me) {
    $('#hdr').innerHTML = `<div class="brand">LandChain Secure<small>Blockchain land registration with cryptographic security</small></div>`;
    $('#app').innerHTML = authView();
    $('#modal').innerHTML = '';
    attachPasswordToggles();
    attachAadhaarFormat();
    const s = $('#r_role');
    if (s) s.onchange = () => { const d = $('#r_setup'); if (d) d.style.display = s.value === 'inspector' ? 'block' : 'none'; };
    return;
  }
  const me = cl.me, tabs = [['market', 'Land Marketplace'], ['dash', 'My Dashboard'], ['ledger', 'Blockchain Ledger'], ['sec', 'My Security']];
  $('#hdr').innerHTML = `<div class="brand">LandChain Secure<small>Blockchain land registration with cryptographic security</small></div>
    <div class="who"><b>${esc(me.name)}</b> · ${ROLE[me.role]}<br><code>${esc(me.addr.slice(0, 14))}…</code> <button class="ghost sm" data-act="logout">Logout</button></div>`;
  let body = '';
  if (!cl.wallet) body += `<div class="banner r"><b>Your private keys are not loaded.</b> Import your key backup to sign transactions:
    <input type="file" id="walletfile" style="width:auto">
    <input id="walletpw" type="password" placeholder="backup password" style="width:150px">
    <button class="sm" data-act="importwallet">Import</button>
  </div>`;
  if (!me.verified) body += `<div class="banner a">Your KYC is awaiting verification by the Land Inspector. You can log in but cannot transact yet.</div>`;
  body += `<nav class="tabs" style="margin:-16px -18px 14px">${tabs.map(([k, l]) => `<button class="${U.tab === k ? 'on' : ''}" data-act="tab" data-k="${k}">${l}</button>`).join('')}</nav>`;
  body += U.tab === 'market'
    ? `<div class="banner g small">Area, location, price and status are public. Documents and KYC stay encrypted until the owner approves you.</div><div class="grid">${U.st.lands.map(landCard).join('') || '<p>No lands listed yet.</p>'}</div>`
    : U.tab === 'dash' ? dashView()
    : U.tab === 'ledger' ? ledgerView()
    : secView();
  $('#app').innerHTML = body;
  const m = U.modal;
  $('#modal').innerHTML = m
    ? `<div class="ov"><div class="box">
        <div class="row"><h3>${esc(m.title)}</h3><span class="sp"></span><button class="ghost sm" data-act="close">X</button></div>
        ${m.html}
        ${m.onApprove ? `<button class="green" data-act="approve" style="margin-top:8px">Approve user</button>` : ''}
      </div></div>`
    : '';
}

async function refresh() {
  if (!cl.me) return;
  U.st = await cl.state();
  U.dir = await cl.api('GET', '/api/directory').catch(() => []);
  if (cl.me.role === 'inspector') U.pend = await cl.api('GET', '/api/pending').catch(() => []);
  cl.me = await cl.api('GET', '/api/me');
  if (U.tab === 'ledger') U.chain = await cl.api('GET', '/api/chain');
}

async function run(fn, ok) {
  if (U.busy) return;
  U.busy = true; document.body.classList.add('busy');
  try {
    const r = await fn();
    if (ok || (r && r.block !== undefined)) toast(ok || `Committed in block #${r.block}`, 'ok');
    await refresh();
  } catch (e) {
    if (e.message === 'not logged in' || (e.message && e.message.includes('401'))) {
      cl.me = null; cl.wallet = null; U.st = null;
    } else {
      toast(e.message, 'bad');
    }
  }
  U.busy = false; document.body.classList.remove('busy');
  render();
}

const val = id => ($('#' + id) || {}).value || '';
const readFile = f => new Promise((ok, no) => {
  const r = new FileReader();
  r.onload = () => ok({ name: f.name, type: f.type || 'application/octet-stream', data: String(r.result).split(',')[1] || '' });
  r.onerror = no; r.readAsDataURL(f);
});
function docsHtml(d) {
  return (d.files || []).map((f, i) => {
    let txt = '';
    if (f.type.startsWith('text/')) try { txt = decodeURIComponent(escape(atob(f.data))); } catch (e) { txt = atob(f.data); }
    return `<div class="doc"><h4>${esc(f.name)} <button class="sm ghost" data-act="dl" data-i="${i}">download</button></h4>
      ${txt ? `<pre>${esc(txt)}</pre>` : '<pre class="mut">(binary file — use download)</pre>'}
    </div>`;
  }).join('') || '<p class="mut">No files.</p>';
}

const ACT = {
  authtab: d => { U.authTab = d.k; render(); },
  register: () => run(async () => {
    const aad = val('r_aad').replace(/\s/g, '');
    const role = val('r_role');
    const r = await cl.register({
      username: val('r_user').trim(),
      password: val('r_pass'),
      name: val('r_name').trim(),
      role,
      setupCode: val('r_code'),
      kyc: { aadhaar: aad, pan: val('r_pan').toUpperCase(), phone: val('r_phone'), address: val('r_addr') }
    });
    U.reg = { ...r, role, username: val('r_user').trim() };
    setTimeout(demoCode, 50);
  }),
  regdone: () => { U.reg = null; U.authTab = 'login'; render(); },
  backup: () => {
    const u = U.reg ? U.reg.username : cl.me.username, raw = cl.exportWallet(u);
    if (!raw) return toast('No key found in this browser', 'bad');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([raw], { type: 'application/json' }));
    a.download = `landchain-keys-${u}.json`; a.click();
  },
  login: () => run(async () => { await cl.login(val('l_user').trim(), val('l_pass'), val('l_code').trim()); U.tab = 'market'; }),
  logout: async () => { await cl.logout(); U.st = null; render(); },
  tab: d => {
    U.tab = d.k; render();
    if (d.k === 'ledger') run(async () => { U.chain = await cl.api('GET', '/api/chain'); });
    else run(async () => {});
  },
  close: () => { U.modal = null; render(); },
  importwallet: () => run(async () => {
    const f = $('#walletfile').files[0]; if (!f) throw new Error('choose the backup file');
    await cl.importWallet(cl.me.username, val('walletpw'), await f.text());
    if (cl.wallet.addr !== cl.me.addr) { cl.wallet = null; throw new Error('this backup belongs to a different account'); }
  }, 'Keys imported'),
  open: d => run(async () => {
    const l = U.st.lands.find(x => x.id === +d.id), docs = await cl.decryptLand(l); U.docs = docs;
    U.modal = { title: `Land #${l.id} documents (decrypted in your browser)`, html: `<div class="banner g small">Decrypted locally with your private key. The server only holds ciphertext.</div>${docsHtml(docs)}` };
  }),
  dl: d => {
    const f = U.docs.files[+d.i], b = Uint8Array.from(atob(f.data), c => c.charCodeAt(0)), a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([b], { type: f.type })); a.download = f.name; a.click();
  },
  buy: d => run(() => cl.requestBuy(+d.id)),
  list: () => run(async () => {
    const files = await Promise.all([...($('#f_files').files || [])].map(readFile));
    if (files.reduce((s, f) => s + f.data.length, 0) > 8e6) throw new Error('documents too large (max 8 MB)');
    const r = await cl.listLand({ area: val('f_area'), city: val('f_city'), state: val('f_state'), price: val('f_price'), survey: val('f_survey'), files });
    U.tab = 'dash'; return r;
  }),
  grant: d => run(() => { const r = U.st.requests.find(x => x.id === +d.r); return cl.grant(r, U.st.lands.find(l => l.id === r.landId)); }),
  pay: d => run(() => { const r = U.st.requests.find(x => x.id === +d.r); return cl.pay(r, U.st.lands.find(l => l.id === r.landId)); }),
  verifyland: d => run(async () => {
    const l = U.st.lands.find(x => x.id === +d.id), docs = await cl.decryptLand(l); U.docs = docs;
    U.modal = { title: `Reviewing Land #${l.id}`, html: docsHtml(docs) + '<p class="small">Verify the documents above then close to confirm.</p>' };
    U.modal.onApprove = null; return cl.verifyLand(l);
  }),
  kyc: d => run(async () => {
    const p = U.pend.find(x => x.addr === d.a), k = await cl.decryptKyc(p);
    /* show only last 4 digits of Aadhaar */
    const digits = String(k.aadhaar || '').replace(/\D/g, '');
    const masked = { ...k, aadhaar: digits.length >= 4 ? 'XXXX XXXX ' + digits.slice(-4) : '—' };
    U.modal = {
      title: `KYC details — ${p.name}`,
      html: `<div class="doc"><h4>Decrypted with the Land Inspector private key</h4>
        <pre>${esc(Object.entries(masked).map(([a, b]) => a.padEnd(10) + ': ' + b).join('\n'))}</pre>
      </div>`,
      onApprove: p.addr
    };
  }),
  approve: () => run(async () => { const a = U.modal.onApprove; U.modal = null; return cl.approveUser(a); }),
  sign: d => run(async () => {
    const t = U.st.transfers.find(x => x.reqId === +d.r);
    await cl.signTransfer(t, U.st.lands.find(l => l.id === t.landId));
  }, 'Signature recorded'),
  final: d => run(() => { const t = U.st.transfers.find(x => x.reqId === +d.r); return cl.finalizeTransfer(t, U.st.lands.find(l => l.id === t.landId)); }),
  audit: () => run(async () => { U.chain = await cl.api('GET', '/api/chain'); U.audit = await cl.api('GET', '/api/audit'); })
};

async function demoCode() {
  const e = $('#demoCode'); if (!e || !U.reg) return;
  e.textContent = await C.totp(C.b32dec(U.reg.totpSecret));
  setTimeout(demoCode, 1000);
}

document.addEventListener('click', e => {
  const el = e.target.closest('[data-act]');
  if (el && ACT[el.dataset.act]) ACT[el.dataset.act](el.dataset);
});

document.addEventListener('change', e => {
  if (e.target.id === 'r_role') {
    const d = $('#r_setup');
    if (d) d.style.display = e.target.value === 'inspector' ? 'block' : 'none';
  }
});

/* load meta on startup */
fetch('/api/meta').then(r => r.json()).then(m => { U.inspectorExists = !!m.inspectorExists; render(); }).catch(() => {});
render();
