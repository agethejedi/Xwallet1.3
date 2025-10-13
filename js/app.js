// use the globals set in index.html
const { ethers } = window;

/* ================================
   CONFIG
================================ */
const RPCS = {
  // Sepolia RPC (Alchemy example). Replace with your key.
  sep: 'https://eth-sepolia.g.alchemy.com/v2/REPLACE_WITH_YOUR_KEY'
};

// IMPORTANT: SafeSend Worker /check endpoint
// e.g. 'https://xwalletv1dot2.YOURSUBDOMAIN.workers.dev/check'
const SAFE_SEND_URL = 'https://xwalletv1dot2.agedotcom.workers.dev/check';

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
const STORAGE_KEY_VAULT = 'xwallet_vault_v1.2';   // keep v1.2 so existing users aren’t broken
const STORAGE_KEY_ACCTS = 'xwallet_accounts_n';   // # of derived wallets to load

const state = {
  unlocked:false,
  provider:null,
  decryptedPhrase:null,
  accounts:[],             // [{ index, wallet, address }]
  signerIndex:0            // which wallet we “send from”
};

function getVault(){ const s = localStorage.getItem(STORAGE_KEY_VAULT); return s ? JSON.parse(s) : null; }
function setVault(v){ localStorage.setItem(STORAGE_KEY_VAULT, JSON.stringify(v)); }
function getAccountCount(){ const n = Number(localStorage.getItem(STORAGE_KEY_ACCTS)||'0'); return Number.isFinite(n)&&n>0?n:0; }
function setAccountCount(n){ localStorage.setItem(STORAGE_KEY_ACCTS, String(Math.max(0, n))); }

function lock(){
  state.unlocked=false;
  state.provider=null;
  state.decryptedPhrase=null;
  state.accounts=[];
  state.signerIndex=0;
  $('#lockState')?.textContent='Locked';
}
function scheduleAutoLock(){
  clearTimeout(window._inactivityTimer);
  window._inactivityTimer = setTimeout(()=>{ lock(); showLock(); }, 10*60*1000);
}

/* ================================
   Derivation helpers (multi-wallet)
================================ */
function deriveAccountFromPhrase(phrase, index){
  const path = `m/44'/60'/0'/0/${index}`;
  return ethers.HDNodeWallet.fromPhrase(phrase, undefined, path);
}
function loadAccountsFromPhrase(phrase){
  state.accounts = [];
  const n = getAccountCount() || 1;
  for (let i=0;i<n;i++){
    const w = deriveAccountFromPhrase(phrase, i);
    state.accounts.push({ index:i, wallet:w, address:w.address });
  }
}

/* ================================
   Views
================================ */
const VIEWS = {
  // ===== Control Center (Dashboard) =====
  dashboard() {
    const hasVault = !!getVault();
    const unlocked = state.unlocked;

    const accRows = unlocked && state.accounts.length
      ? state.accounts.map(a => `
          <tr>
            <td>${a.index + 1}</td>
            <td class="mono">${a.address}</td>
          </tr>
        `).join('')
      : '<tr><td colspan="2">No wallets yet.</td></tr>';

    const createImport = !hasVault ? `
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
    ` : '';

    const manage = hasVault ? `
      <div class="label">Wallets under your seed</div>
      <div class="small">Add multiple derivation-path wallets from the same phrase.</div>
      <div style="height:8px"></div>
      <button class="btn" id="addAcct"${unlocked ? '' : ' disabled title="Unlock first"'}>Add Wallet</button>
      <div style="height:12px"></div>
      <table class="table small">
        <thead><tr><th>#</th><th>Address</th></tr></thead>
        <tbody>${accRows}</tbody>
      </table>
    ` : '';

    return `
      <div class="label">Control Center</div>
      <div class="small">Create/import a vault, unlock, and manage multiple wallets derived from one seed phrase.</div>
      <hr class="sep"/>
      ${createImport}
      ${manage}
    `;
  },

  // ===== Wallets (balances only, no USD) =====
  wallets() {
    const rows = state.accounts.map(a => `
      <tr>
        <td>${a.index + 1}</td>
        <td class="mono">${a.address}</td>
        <td id="bal-${a.index}">—</td>
      </tr>
    `).join('');
    return `
      <div class="label">Wallet Balances</div>
      <table class="table small">
        <thead><tr><th>#</th><th>Address</th><th>ETH</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div id="totalBal" class="small"></div>
    `;
  },

  // ===== Send (choose source wallet + SafeSend + 10 recent txs) =====
  send() {
    const acctOpts = state.accounts.map(a =>
      `<option value="${a.index}" ${a.index===state.signerIndex?'selected':''}>
        Wallet #${a.index+1} — ${a.address.slice(0,6)}…${a.address.slice(-4)}
       </option>`
    ).join('') || `<option value="-1" disabled>No wallets (unlock)</option>`;
    return `
      <div class="label">Send ETH (Sepolia)</div>
      <div class="small">SafeSend checks the recipient before broadcasting.</div>
      <div class="send-form" style="gap:8px;display:grid;grid-template-columns:1fr 2fr 1fr auto;">
        <select id="fromAccount">${acctOpts}</select>
        <input id="sendTo" placeholder="Recipient 0x address"/>
        <input id="sendAmt" placeholder="Amount (ETH)"/>
        <button class="btn primary" id="doSend">Send</button>
      </div>
      <div id="sendOut" class="small" style="margin-top:8px"></div>
      <hr class="sep"/>
      <div class="label">Last 10 Transactions (selected wallet)</div>
      <div id="txList" class="small">—</div>
    `;
  },

  // ===== Settings =====
  settings() {
    return `
      <div class="label">Settings</div>
      <div class="kv"><div>Auto-lock</div><div>10 minutes</div></div>
      <hr class="sep"/>
      <button class="btn" id="wipe">Delete vault (local)</button>
    `;
  }
};

/* ================================
   Render + handlers
================================ */
function render(view){
  const root = $('#view');
  root.innerHTML = VIEWS[view]();

  // ---- Control Center
  if (view === 'dashboard'){
    $('#gen')?.addEventListener('click', () => {
      $('#mnemonic').value = ethers.Mnemonic.fromEntropy(ethers.randomBytes(16)).phrase;
    });
    $('#save')?.addEventListener('click', async () => {
      const m = $('#mnemonic').value.trim();
      const pw = $('#password').value;
      if (!m || !pw) return alert('Mnemonic + password required');
      const enc = await aesEncrypt(pw, m);
      setVault({ version:1, enc });
      setAccountCount(1);
      alert('Vault saved. Click Unlock.');
      render('dashboard');
    });
    $('#doImport')?.addEventListener('click', async () => {
      const m = $('#mnemonicIn').value.trim();
      const pw = $('#passwordIn').value;
      if (!m || !pw) return alert('Mnemonic + password required');
      const enc = await aesEncrypt(pw, m);
      setVault({ version:1, enc });
      setAccountCount(1);
      alert('Imported. Click Unlock.');
      render('dashboard');
    });
    $('#addAcct')?.addEventListener('click', () => {
      if (!state.unlocked) return;
      const n = getAccountCount() + 1;
      setAccountCount(n);
      const w = deriveAccountFromPhrase(state.decryptedPhrase, n - 1);
      state.accounts.push({ index:n-1, wallet:w, address:w.address });
      render('dashboard');
    });
  }

  // ---- Wallets
  if (view === 'wallets'){
    loadWalletBalances().catch(console.warn);
  }

  // ---- Send
  if (view === 'send'){
    $('#fromAccount')?.addEventListener('change', async (e)=>{
      const idx = Number(e.target.value||'0');
      state.signerIndex = idx;
      await loadRecentTxs();
    });

    $('#doSend')?.addEventListener('click', async ()=>{
      if (!state.unlocked || !state.provider) { $('#sendOut').textContent='Unlock first.'; return; }
      const idx = state.signerIndex;
      const acct = state.accounts[idx];
      if (!acct) { $('#sendOut').textContent='No wallet selected.'; return; }

      const to = $('#sendTo').value.trim();
      const amt = $('#sendAmt').value.trim();
      if (!ethers.isAddress(to)) { $('#sendOut').textContent='Invalid recipient address'; return; }
      const n = Number(amt);
      if (!Number.isFinite(n) || n <= 0) { $('#sendOut').textContent='Invalid amount'; return; }

      $('#sendOut').textContent='Checking SafeSend…';
      try{
        const chk = await fetchSafeSend(to);
        if (chk.score && chk.score > 70){
          $('#sendOut').textContent = `Blocked by SafeSend: high risk (${chk.score}).`;
          return;
        }
        $('#sendOut').textContent = `SafeSend OK (score ${chk.score ?? '—'}). Sending…`;

        // connect signer for this account
        const signer = acct.wallet.connect(state.provider);
        const tx = { to, value: ethers.parseEther(String(n)) };
        try{
          const fee = await signer.getFeeData();
          if (fee?.maxFeePerGas) {
            tx.maxFeePerGas = fee.maxFeePerGas;
            tx.maxPriorityFeePerGas = fee.maxPriorityFeePerGas;
          }
          const est = await signer.estimateGas(tx);
          tx.gasLimit = est;
        }catch(e){ /* estimation can fail; continue with bare tx */ }

        const sent = await signer.sendTransaction(tx);
        $('#sendOut').innerHTML = `Broadcasted: <a target=_blank href="https://sepolia.etherscan.io/tx/${sent.hash}">${sent.hash}</a>`;
        await sent.wait(1);
        await loadRecentTxs();
      }catch(err){
        $('#sendOut').textContent = 'Error: ' + (err?.message || err);
      }
    });

    loadRecentTxs().catch(console.warn);
  }

  // ---- Settings
  if (view === 'settings'){
    $('#wipe')?.addEventListener('click', ()=>{
      if (confirm('Delete local encrypted vault?')){
        localStorage.removeItem(STORAGE_KEY_VAULT);
        localStorage.removeItem(STORAGE_KEY_ACCTS);
        lock();
        alert('Deleted. Reload the page.');
      }
    });
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
    const pw = $('#unlockPassword').value;
    const phrase = await aesDecrypt(pw, v.enc);

    // Provider
    state.provider = new ethers.JsonRpcProvider(RPCS.sep);

    // Accounts
    state.decryptedPhrase = phrase;
    if (!getAccountCount()) setAccountCount(1);
    loadAccountsFromPhrase(phrase);

    state.unlocked = true;
    $('#lockState').textContent='Unlocked';
    hideLock();
    scheduleAutoLock();

    selectItem('dashboard');
  }catch(e){
    console.error(e);
    $('#unlockMsg').textContent = 'Wrong password (or corrupted vault).';
  }
};

/* ================================
   Nav
================================ */
function selectItem(view){ $$('.sidebar .item').forEach(x=>x.classList.toggle('active', x.dataset.view===view)); render(view); }
$$('.sidebar .item').forEach(el=> el.onclick=()=> selectItem(el.dataset.view));
selectItem('dashboard'); // default view label “Control Center” in the UI

// landing CTA (optional smooth scroll)
$('#ctaApp')?.addEventListener('click', ()=> window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' }));
$('#ctaLearn')?.addEventListener('click', ()=> window.scrollTo({ top: window.innerHeight, behavior: 'smooth' }));

/* ================================
   SafeSend backend call
================================ */
async function fetchSafeSend(address){
  try{
    const u = new URL(SAFE_SEND_URL);
    u.searchParams.set('address', address);
    u.searchParams.set('chain', 'sepolia');
    const r = await fetch(u.toString());
    if (!r.ok) throw new Error('SafeSend backend error');
    return await r.json();
  }catch(e){
    console.warn('SafeSend fetch failed', e);
    return { score: 50, findings: ['SafeSend backend unreachable — default medium'] };
  }
}

/* ================================
   Balances + Tx history
================================ */
async function loadWalletBalances(){
  if (!state.unlocked || !state.provider) return;
  let total = 0n;
  for (const a of state.accounts){
    try{
      const bal = await state.provider.getBalance(a.address);
      total += bal;
      const el = document.getElementById(`bal-${a.index}`);
      if (el) el.textContent = ethers.formatEther(bal);
    }catch{}
  }
  const totalEl = $('#totalBal');
  if (totalEl) totalEl.textContent = 'Total (ETH): ' + ethers.formatEther(total);
}

async function loadRecentTxs(){
  const el = $('#txList'); if (!el) return;
  el.textContent = 'Loading…';
  try{
    if (!state.unlocked || !state.provider) { el.textContent='Unlock first.'; return; }
    const acct = state.accounts[state.signerIndex]; if (!acct) { el.textContent='No wallet selected.'; return; }

    if (typeof state.provider.getHistory !== 'function'){
      el.textContent = 'Recent txs unavailable for this provider.';
      return;
    }

    const hist = await state.provider.getHistory(acct.address);
    const recent = (hist || []).slice(-10).reverse();
    el.innerHTML = recent.map(t=>{
      const when = t.timestamp ? new Date(t.timestamp*1000).toLocaleString() : '';
      return `<div><a target=_blank href="https://sepolia.etherscan.io/tx/${t.hash}">${t.hash.slice(0,12)}…</a> • ${when}</div>`;
    }).join('') || 'No txs';
  }catch(e){
    console.warn(e);
    el.textContent = 'Could not load recent transactions.';
  }
}
