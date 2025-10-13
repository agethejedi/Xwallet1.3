// use the globals set in index.html
const { ethers } = window;
const XMTP = window.XMTP || window.xmtp;

/* ================================
   CONFIG
================================ */
const RPCS = {
  sep: 'https://eth-sepolia.g.alchemy.com/v2/kxHg5y9yBXWAb9cOcJsf0', // <-- replace
};

// IMPORTANT: point to your Cloudflare Worker /check endpoint
const SAFE_SEND_URL = 'https://xwalletv1dot2.agedotcom.workers.dev/check'; // <-- replace
const WORKER_BASE   = SAFE_SEND_URL.replace(/\/check$/, ''); // used for /market/price

/* ================================
   Tiny helpers
================================ */
const $  = (q) => document.querySelector(q);
const $$ = (q) => [...document.querySelectorAll(q)];

/* ================================
   AES-GCM + PBKDF2 vault
================================ */
async function aesEncrypt(password, plaintext){
  const enc  = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const km   = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const key  = await crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:100000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, false, ['encrypt']);
  const ct   = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(plaintext)));
  return { ct: Array.from(ct), iv: Array.from(iv), salt: Array.from(salt) };
}
async function aesDecrypt(password, payload){
  const dec = new TextDecoder();
  const { ct, iv, salt } = payload;
  const km   = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const key  = await crypto.subtle.deriveKey({name:'PBKDF2', salt:new Uint8Array(salt), iterations:100000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, false, ['decrypt']);
  const pt   = await crypto.subtle.decrypt({name:'AES-GCM', iv:new Uint8Array(iv)}, key, new Uint8Array(ct));
  return dec.decode(pt);
}

/* ================================
   State / storage / lock
================================ */
const state = {
  unlocked:false, wallet:null, xmtp:null, provider:null, signer:null,
  inactivityTimer:null, decryptedPhrase:null,
  watchlist: ['bitcoin','ethereum','solana','matic-network','usd-coin'],
};
const STORAGE_KEY = 'xwallet_vault_v1.2';
function getVault(){ const s = localStorage.getItem(STORAGE_KEY); return s ? JSON.parse(s) : null; }
function setVault(v){ localStorage.setItem(STORAGE_KEY, JSON.stringify(v)); }

function lock(){
  state.unlocked=false;
  state.wallet=null;
  state.xmtp=null;
  state.provider=null;
  state.signer=null;
  state.decryptedPhrase=null;
  if (window._xmtpStreamCancel) { window._xmtpStreamCancel(); window._xmtpStreamCancel = null; }
  $('#lockState').textContent='Locked';
}
function scheduleAutoLock(){ clearTimeout(state.inactivityTimer); state.inactivityTimer = setTimeout(()=>{ lock(); showLock(); }, 10*60*1000); }

/* ================================
   XMTP helpers (init + inbox)
================================ */
async function ensureXMTP() {
  if (state.xmtp) return state.xmtp;
  if (!state.wallet) throw new Error('Unlock first');
  state.xmtp = await XMTP.Client.create(state.wallet, { env: 'production' });
  return state.xmtp;
}

async function loadInbox() {
  const inboxEl = $('#inbox');
  if (!inboxEl) return;
  if (!state.xmtp) { inboxEl.textContent = 'Connect wallet (Unlock) first.'; return; }

  const convos = await state.xmtp.conversations.list();
  const latest = [];
  for (const c of convos.slice(0, 20)) {
    const msgs = await c.messages({ pageSize: 1, direction: 'descending' });
    if (msgs.length) latest.push({ peer: c.peerAddress, text: msgs[0].content, at: msgs[0].sent });
  }
  latest.sort((a,b)=> b.at - a.at);
  inboxEl.innerHTML =
    latest.map(m =>
      `<div class="kv"><div>${m.peer}</div><div>${new Date(m.at).toLocaleString()}</div></div>
       <div class="small">${m.text}</div><hr class="sep"/>`
    ).join('') || 'No messages yet.';
}

/* ================================
   Watchlist via Worker (/market/price)
================================ */
let _watchlistTimer = null;

async function fetchPrices(ids) {
  const u = new URL(WORKER_BASE + '/market/price');
  u.searchParams.set('ids', ids.join(','));   // e.g., "bitcoin,ethereum,solana,matic-network,usd-coin"
  u.searchParams.set('vs', 'usd');

  const r = await fetch(u.toString());
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    console.error('watchlist fetch failed', r.status, text);
    throw new Error('Worker market error');
  }
  return r.json(); // { bitcoin:{usd,...}, ... }
}


function ensureWatchlistRows() {
  const tbody = document.querySelector('#watchlist tbody');
  if (!tbody) return;
  if (tbody.children.length) return;
  tbody.innerHTML = state.watchlist.map(id=>`
    <tr data-id="${id}">
      <td class="mono">${id}</td>
      <td class="mono price">—</td>
      <td class="mono change">—</td>
    </tr>
  `).join('');
}

function updateWatchlistDOM(prices) {
  for (const id of state.watchlist) {
    const row = document.querySelector(`#watchlist tr[data-id="${id}"]`);
    if (!row) continue;
    const p = prices[id];
    const priceEl = row.querySelector('.price');
    const chEl    = row.querySelector('.change');

    if (!p) {
      if (priceEl) priceEl.textContent = '—';
      if (chEl) chEl.textContent = '—';
      continue;
    }
    const usd = p.usd ?? p.price ?? null;
    const ch  = p.usd_24h_change ?? p.change24h ?? null;

    if (priceEl && usd != null) {
      priceEl.textContent = Number(usd).toLocaleString(undefined, { style:'currency', currency:'USD' });
    }
    if (chEl && ch != null) {
      const pct = Number(ch).toFixed(2) + '%';
      chEl.textContent = pct;
      chEl.style.color = Number(ch) >= 0 ? 'limegreen' : 'crimson';
    }
  }
}

async function updateWatchlistOnce(){
  try {
    ensureWatchlistRows();
    const data = await fetchPrices(state.watchlist);
    updateWatchlistDOM(data);
  } catch (e) {
    console.warn('watchlist update failed', e);
  }
}

function startWatchlist(){
  clearInterval(_watchlistTimer);
  updateWatchlistOnce();
  _watchlistTimer = setInterval(updateWatchlistOnce, 60_000);
}

/* ================================
   Views
================================ */
const VIEWS = {
  dashboard(){ 
    const hasVault = !!getVault();
    const banner = hasVault
      ? `<div class="alert success">✅ Vault present on this device. <button class="btn" id="bannerUnlock">Unlock now</button></div>`
      : `<div class="alert warn">⚠️ No vault saved yet. Create or Import a wallet, then click <b>Save vault</b> to keep access after closing the browser.</div>`;
    return `
      <div class="label">Welcome</div>
      ${banner}
      <div class="alert">Create or import a wallet, then unlock to use Messaging, Send, and Watchlist. This wallet is non-custodial; your secret is encrypted locally.</div>
      <hr class="sep"/>
      <div class="grid-2">
        <div>
          <div class="label">Create wallet</div>
          <button class="btn" id="gen">Generate 12-word phrase</button>
          <div style="height:8px"></div>
          <textarea id="mnemonic" rows="3" readonly></textarea>
          <div style="height:8px"></div>
          <input id="password" type="password" placeholder="Password to encrypt (like MetaMask)"/>
          <div style="height:8px"></div>
          <button class="btn primary" id="save">Save vault</button>
        </div>
        <div>
          <div class="label">Import wallet</div>
          <textarea id="mnemonicIn" rows="3" placeholder="Enter your 12 or 24 words"></textarea>
          <div style="height:8px"></div>
          <input id="passwordIn" type="password" placeholder="Password to encrypt"/>
          <div style="height:8px"></div>
          <button class="btn" id="doImport">Import</button>
        </div>
      </div>
    `;
  },
  wallets(){ 
    const addr = state.wallet?.address || '—';
    return `
      <div class="label">Active wallet</div>
      <div class="kv"><div><b>Address</b></div><div class="mono">${addr}</div></div>
      <hr class="sep"/>
      <div class="label">Actions</div>
      <div class="flex"><button class="btn" id="copyAddr">Copy address</button><button class="btn" id="showPK">Show public key</button></div>
      <div id="out" class="small"></div>
    `;
  },
  send(){ 
    return `
      <div class="label">Send ETH (Sepolia)</div>
      <div class="small">Before each send, SafeSend will evaluate the recipient address and block if high risk.</div>
      <hr class="sep"/>
      <div class="send-form"><input id="sendTo" placeholder="0x recipient address"/><input id="sendAmt" placeholder="Amount (ETH)"/><button class="btn primary" id="doSend">Send</button></div>
      <div id="sendOut" class="small" style="margin-top:8px"></div>
      <div style="height:12px"></div>
      <div class="label">Recent transactions (testnet)</div>
      <div id="txList" class="small">—</div>
    `;
  },
  messaging(){ 
    return `
      <div class="label">XMTP Messaging</div>
      <div id="msgStatus" class="small">Status: ${state.xmtp ? 'Connected' : 'Disconnected'}</div>
      <hr class="sep"/>
      <div class="grid-2">
        <div>
          <div class="label">Start new chat</div>
          <input id="peer" placeholder="Recipient EVM address (0x...)"/>
          <div style="height:8px"></div>
          <div class="flex"><input id="msg" placeholder="Type a message" style="flex:1"/><button class="btn primary" id="send">Send</button></div>
          <div id="sendOut" class="small"></div>
        </div>
        <div>
          <div class="label">Inbox (live)</div>
          <div id="inbox" class="small">—</div>
        </div>
      </div>
    `;
  },
  markets(){ 
    // Table skeleton is in index.html hero block; this "Markets" view can reuse the same watchlist too.
    const rows = state.watchlist.map(id=>`
      <tr data-id="${id}">
        <td class="mono">${id}</td>
        <td class="mono price">—</td>
        <td class="mono change">—</td>
      </tr>
    `).join('');
    return `
      <div class="label">Watchlist</div>
      <div class="small">Prices via Cloudflare Worker → CoinGecko. Auto-refresh every 60s.</div>
      <hr class="sep"/>
      <table class="table small" id="watchlist">
        <thead><tr><th>Asset</th><th>Price (USD)</th><th>24h</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `;
  },
  settings(){ 
    const hasVault = !!getVault();
    return `
      <div class="label">Settings</div>
      <div class="kv"><div>Vault present</div><div>${hasVault ? '✅' : '❌'}</div></div>
      <div class="kv"><div>Auto-lock</div><div>10 minutes</div></div>
      <hr class="sep"/>
      <button class="btn" id="wipe">Delete vault (local)</button>
      <hr class="sep"/>
      <div class="label">Backup</div>
      <div class="flex" style="gap:8px;">
        <button class="btn" id="exportVault">Export vault (JSON)</button>
        <label class="btn">
          Import vault JSON
          <input type="file" id="importVaultFile" accept="application/json" style="display:none"/>
        </label>
      </div>
      <div class="small">Export this encrypted vault and import it on another device/origin to keep access.</div>
    `;
  }
};

/* ================================
   Render + handlers
================================ */
function render(view){
  if (view !== 'messaging' && window._xmtpStreamCancel) { window._xmtpStreamCancel(); window._xmtpStreamCancel = null; }

  const root = $('#view');
  root.innerHTML = VIEWS[view]();

  if (view==='dashboard'){
    $('#gen').onclick = ()=>{ $('#mnemonic').value = ethers.Mnemonic.fromEntropy(ethers.randomBytes(16)).phrase; };
    $('#save').onclick = async ()=>{ const m = $('#mnemonic').value.trim(); const pw = $('#password').value; if (!m||!pw) return alert('Mnemonic+password required'); const enc = await aesEncrypt(pw,m); setVault({version:1,enc}); alert('Vault saved. Click Unlock.'); };
    $('#doImport').onclick = async ()=>{ const m = $('#mnemonicIn').value.trim(); const pw = $('#passwordIn').value; if (!m||!pw) return alert('Mnemonic+password required'); const enc = await aesEncrypt(pw,m); setVault({version:1,enc}); alert('Imported & saved. Click Unlock.'); };
    $('#bannerUnlock')?.addEventListener('click', showLock);
  }

  if (view==='wallets'){
    $('#copyAddr').onclick = async ()=>{ if(!state.wallet) return; await navigator.clipboard.writeText(state.wallet.address); $('#out').textContent='Address copied.'; };
    $('#showPK').onclick = async ()=>{ if(!state.wallet) return; const pk = await state.wallet.getPublicKey(); $('#out').textContent='Public key: ' + pk; };
    if (state.wallet) $('#out').textContent = 'Current address: ' + state.wallet.address;
  }

  if (view==='send'){
    $('#doSend').onclick = async ()=>{
      const to = $('#sendTo').value.trim(); const amt = $('#sendAmt').value.trim();
      if (!ethers.isAddress(to)) return alert('Invalid address');
      const n = Number(amt); if (isNaN(n) || n<=0) return alert('Invalid amount');
      $('#sendOut').textContent='Checking SafeSend...';
      try{
        const check = await fetchSafeSend(to);
        if (check.score && check.score > 70) return $('#sendOut').textContent = 'Blocked by SafeSend: high risk ('+check.score+')';
        $('#sendOut').textContent='SafeSend OK — preparing tx...';
        const res = await sendEth({ to, amountEth: n, chain:'sep' });
        $('#sendOut').innerHTML = 'Broadcasted: <a target=_blank href="https://sepolia.etherscan.io/tx/'+res.hash+'">'+res.hash+'</a>';
        await loadRecentTxs();
      }catch(e){ $('#sendOut').textContent = 'Error: ' + (e.message||e); }
    };
    loadRecentTxs();
  }

  if (view==='messaging'){
    $('#msgStatus').textContent = 'Status: ' + (state.xmtp ? 'Connected' : 'Disconnected (unlock first)');
    $('#send').onclick = async ()=>{
      if (!state.xmtp) { $('#sendOut').textContent='Connect wallet (Unlock) first.'; return; }
      const peer = $('#peer').value.trim(); const txt = $('#msg').value.trim();
      if (!ethers.isAddress(peer)) { $('#sendOut').textContent='Enter valid 0x address'; return; }
      try {
        const convo = await state.xmtp.conversations.newConversation(peer);
        await convo.send(txt || '(no text)');
        $('#sendOut').textContent='Sent ✅';
        $('#msg').value='';
        await loadInbox();
      } catch(e){ $('#sendOut').textContent='Error: ' + (e.message||e); }
    };

    (async ()=>{
      if (!state.xmtp && state.wallet) { try { await ensureXMTP(); } catch {} }
      if (!state.xmtp) { $('#inbox').textContent = 'Unlock first.'; return; }
      $('#inbox').textContent = 'Loading…';
      await loadInbox();

      if (window._xmtpStreamCancel) { window._xmtpStreamCancel(); window._xmtpStreamCancel = null; }
      const stream = await state.xmtp.conversations.streamAllMessages();
      let cancelled = false;
      window._xmtpStreamCancel = () => { cancelled = true; try { stream.return?.(); } catch {} };
      (async () => { for await (const _msg of stream) { if (cancelled) break; await loadInbox(); } })();
    })();
  }

  if (view === 'markets') {
    startWatchlist();
  }

  if (view==='settings'){
    $('#wipe').onclick = ()=>{ if(confirm('Delete the local encrypted vault?')){ localStorage.removeItem(STORAGE_KEY); lock(); alert('Deleted.'); } };
    $('#exportVault').onclick = ()=>{
      const v = getVault(); if (!v) return alert('No vault to export.');
      const blob = new Blob([JSON.stringify(v,null,2)], {type:'application/json'});
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'xwallet_vault.json'; a.click();
    };
    $('#importVaultFile').onchange = async (e)=>{
      const f = e.target.files?.[0]; if (!f) return;
      try{
        const text = await f.text();
        const json = JSON.parse(text);
        if (!json?.enc?.ct) throw new Error('Invalid vault file.');
        setVault(json);
        alert('Vault imported. Click Unlock.');
      }catch(err){ alert('Import failed: ' + (err.message||err)); }
    };
  }
}

/* ================================
   Lock modal
================================ */
function showLock(){ $('#lockModal').classList.add('active'); $('#unlockPassword').value=''; $('#unlockMsg').textContent=''; }
function hideLock(){ $('#lockModal').classList.remove('active'); }
$('#btnLock').onclick = ()=>{ lock(); alert('Locked.'); };
$('#btnUnlock').onclick = ()=> showLock();
$('#cancelUnlock').onclick = ()=> hideLock();
$('#doUnlock').onclick = async ()=>{
  try{
    const v = getVault(); if (!v) { $('#unlockMsg').textContent='No vault found.'; return; }
    const pw = $('#unlockPassword').value; const phrase = await aesDecrypt(pw, v.enc);
    const wallet = ethers.HDNodeWallet.fromPhrase(phrase);

    state.decryptedPhrase = phrase;
    state.wallet = wallet; 
    state.unlocked = true; 
    $('#lockState').textContent='Unlocked'; 
    hideLock(); 
    scheduleAutoLock();

    state.provider = new ethers.JsonRpcProvider(RPCS.sep); 
    state.signer = state.wallet.connect(state.provider);

    try { await ensureXMTP(); } catch(e){ console.warn('XMTP init failed', e); }

    selectItem('wallets');
  }catch(e){ console.error(e); $('#unlockMsg').textContent = 'Wrong password (or corrupted vault).'; }
};

/* ================================
   Nav
================================ */
function selectItem(view){ $$('.sidebar .item').forEach(x=>x.classList.toggle('active', x.dataset.view===view)); render(view); }
$$('.sidebar .item').forEach(el=> el.onclick=()=> selectItem(el.dataset.view));
selectItem('dashboard');

// landing CTA
$('#ctaApp')?.addEventListener('click', ()=> window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' }));
$('#ctaLearn')?.addEventListener('click', ()=> window.scrollTo({ top: window.innerHeight, behavior: 'smooth' }));

// SafeSend backend call (resilient)
async function fetchSafeSend(address, { timeoutMs = 5000 } = {}) {
  const u = new URL(SAFE_SEND_URL);
  u.searchParams.set('address', address);
  // u.searchParams.set('chain','sepolia'); // if you support more, pass it

  // simple timeout wrapper so we don't hang the UI
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);

  try {
    const r = await fetch(u.toString(), { signal: ctrl.signal });
    clearTimeout(t);
    if (!r.ok) {
      // Instead of throwing, return a neutral/medium score so sending can proceed
      console.warn('SafeSend non-200:', r.status);
      return { score: 50, findings: ['SafeSend unreachable (' + r.status + ')'] };
    }
    return await r.json();
  } catch (e) {
    clearTimeout(t);
    console.warn('SafeSend fetch failed', e);
    // Fallback so user can still send
    return { score: 50, findings: ['SafeSend unreachable — using default'] };
  }
}


/* ================================
   Provider + send + history
================================ */
async function getProvider(chain='sep'){ if (!RPCS[chain]) throw new Error('RPC not configured for ' + chain); return new ethers.JsonRpcProvider(RPCS[chain]); }
async function connectWalletToProvider(chain='sep'){ if (!state.wallet) throw new Error('Unlock first'); const provider = await getProvider(chain); state.provider = provider; state.signer = state.wallet.connect(provider); return state.signer; }
async function sendEth({ to, amountEth, chain='sep' }){
  if (!state.signer) await connectWalletToProvider(chain);
  const tx = { to, value: ethers.parseEther(String(amountEth)) };
  try{
    const fee = await state.signer.getFeeData();
    if (fee?.maxFeePerGas) { tx.maxFeePerGas = fee.maxFeePerGas; tx.maxPriorityFeePerGas = fee.maxPriorityFeePerGas; }
    const est = await state.signer.estimateGas(tx);
    tx.gasLimit = est;
  }catch(e){ console.warn('Gas estimation failed', e); }
  const sent = await state.signer.sendTransaction(tx);
  await sent.wait(1);
  return { hash: sent.hash, receipt: sent };
}
async function loadRecentTxs(){
  try{
    if (!state.wallet || !state.provider) return;
    const addr = state.wallet.address;
    if (typeof state.provider.getHistory==='function'){
      const history = await state.provider.getHistory(addr);
      const recent = (history||[]).slice(-6).reverse();
      const el = document.getElementById('txList');
      if (el) el.innerHTML = recent.map(t=>`<div><a target=_blank href="https://sepolia.etherscan.io/tx/${t.hash}">${t.hash.slice(0,10)}…</a> • ${new Date(t.timestamp*1000).toLocaleString()}</div>`).join('') || 'No txs';
    } else {
      const el = document.getElementById('txList'); if (el) el.textContent='Recent txs unavailable for this provider.';
    }
  }catch(e){ console.warn(e); }
}
