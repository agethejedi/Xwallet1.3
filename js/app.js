// ========================================================
// X-Wallet v1.3 — Control Center build by RiskXLabs
// Multi-wallet support + SafeSend + TX History (no USD values)
// ========================================================
const { ethers } = window;
const XMTP = window.XMTP || window.xmtp;

/* =============== CONFIG =============== */
const RPCS = {
  sep: 'https://eth-sepolia.g.alchemy.com/v2/REPLACE_WITH_YOUR_KEY',
};

const SAFE_SEND_URL = 'https://xwalletv1dot2.agedotcom.workers.dev/check';
const WORKER_BASE = SAFE_SEND_URL.replace(/\/check$/, '');

/* =============== Helpers =============== */
const $  = (q)=>document.querySelector(q);
const $$ = (q)=>[...document.querySelectorAll(q)];

/* =============== AES Vault =============== */
async function aesEncrypt(password, plaintext){
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const km = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:100000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(plaintext)));
  return { ct:Array.from(ct), iv:Array.from(iv), salt:Array.from(salt) };
}
async function aesDecrypt(password, payload){
  const dec = new TextDecoder();
  const { ct, iv, salt } = payload;
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt:new Uint8Array(salt), iterations:100000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:new Uint8Array(iv)}, key, new Uint8Array(ct));
  return dec.decode(pt);
}

/* =============== State =============== */
const STORAGE_KEY = 'xwallet_vault_v1.3';
const COUNT_KEY   = 'xwallet_account_count';

const state = {
  unlocked:false, decryptedPhrase:null,
  accounts:[], activeIndex:0,
  provider:null, signer:null,
  inactivityTimer:null,
};

function getVault(){ const s = localStorage.getItem(STORAGE_KEY); return s?JSON.parse(s):null; }
function setVault(v){ localStorage.setItem(STORAGE_KEY, JSON.stringify(v)); }
function getAccountCount(){ return Number(localStorage.getItem(COUNT_KEY) || 1); }
function setAccountCount(n){ localStorage.setItem(COUNT_KEY, String(n)); }

function lock(){
  state.unlocked=false; state.decryptedPhrase=null; state.accounts=[];
  state.signer=null; state.provider=null;
  $('#lockState').textContent='Locked';
}
function scheduleAutoLock(){
  clearTimeout(state.inactivityTimer);
  state.inactivityTimer=setTimeout(()=>{lock();showLock();},10*60*1000);
}

/* =============== Wallet Derivation =============== */
function deriveAccountFromPhrase(phrase,index){
  const path = `m/44'/60'/0'/0/${index}`;
  return ethers.HDNodeWallet.fromPhrase(phrase,undefined,path);
}

/* =============== SafeSend Fetch =============== */
async function fetchSafeSend(address){
  try{
    const u=new URL(SAFE_SEND_URL);
    u.searchParams.set('address',address);
    u.searchParams.set('chain','sepolia');
    const r=await fetch(u.toString());
    if(!r.ok) throw new Error('SafeSend backend error');
    return await r.json();
  }catch(e){
    console.warn('SafeSend fetch failed',e);
    return {score:50,findings:['SafeSend backend unreachable']};
  }
}

/* =============== Provider / Send =============== */
async function getProvider(chain='sep'){return new ethers.JsonRpcProvider(RPCS[chain]);}
function setActiveSigner(){
  const acc = state.accounts.find(a=>a.index===state.activeIndex);
  if(!acc) throw new Error('No active account');
  const provider = state.provider || new ethers.JsonRpcProvider(RPCS.sep);
  state.signer = acc.wallet.connect(provider);
}
async function sendEth({to,amountEth,chain='sep'}){
  if(!state.signer) setActiveSigner();
  const tx={to,value:ethers.parseEther(String(amountEth))};
  const fee=await state.signer.getFeeData();
  if(fee?.maxFeePerGas){tx.maxFeePerGas=fee.maxFeePerGas;tx.maxPriorityFeePerGas=fee.maxPriorityFeePerGas;}
  const est=await state.signer.estimateGas(tx); tx.gasLimit=est;
  const sent=await state.signer.sendTransaction(tx); await sent.wait(1);
  return {hash:sent.hash};
}

/* =============== Load TXs (via Worker) =============== */
async function loadRecentTxsForActive(){
  try{
    const acc=state.accounts.find(a=>a.index===state.activeIndex);
    if(!acc) return;
    const u=new URL(WORKER_BASE+'/account/txs');
    u.searchParams.set('address',acc.address);
    u.searchParams.set('chain','sepolia');
    const r=await fetch(u.toString());
    if(!r.ok) throw new Error('txs backend error');
    const j=await r.json();
    const list=(j.txs||[]).slice(0,10);
    $('#txList').innerHTML=list.map(t=>{
      const when=t.timeStamp?new Date(Number(t.timeStamp)*1000).toLocaleString():'';
      return `<div><a target=_blank href="https://sepolia.etherscan.io/tx/${t.hash}">${t.hash.slice(0,10)}…</a> • ${when}</div>`;
    }).join('')||'No txs';
  }catch(e){console.warn(e);$('#txList').textContent='Recent txs unavailable.';}
}

/* =============== Unlock Flow =============== */
function showLock(){ $('#lockModal').classList.add('active'); $('#unlockPassword').value=''; $('#unlockMsg').textContent=''; }
function hideLock(){ $('#lockModal').classList.remove('active'); }

$('#btnLock').onclick=()=>{lock();alert('Locked');};
$('#btnUnlock').onclick=()=>showLock();
$('#cancelUnlock').onclick=()=>hideLock();

$('#doUnlock').onclick=async()=>{
  try{
    const v=getVault(); if(!v){$('#unlockMsg').textContent='No vault found.';return;}
    const pw=$('#unlockPassword').value;
    const phrase=await aesDecrypt(pw,v.enc);
    state.decryptedPhrase=phrase; state.unlocked=true;
    $('#lockState').textContent='Unlocked'; hideLock(); scheduleAutoLock();

    // build accounts
    const n=getAccountCount();
    state.accounts=Array.from({length:n},(_,i)=>{
      const w=deriveAccountFromPhrase(phrase,i);
      return {index:i,wallet:w,address:w.address};
    });
    state.activeIndex=0;
    setActiveSigner();
    state.provider=await getProvider('sep');
    selectItem('control');
  }catch(e){console.error(e);$('#unlockMsg').textContent='Wrong password or vault corrupted.';}
};

/* =============== Views =============== */
const VIEWS={
  control(){ // Control Center
    const hasVault=!!getVault();
    const accRows=state.accounts.map(a=>`
      <tr><td>${a.index+1}</td><td class="mono">${a.address}</td></tr>`).join('')||'<tr><td colspan=2>No wallets yet.</td></tr>';
    return `
      <div class="label">Control Center</div>
      <div class="small">Manage wallets under your single seed phrase.</div>
      <hr class="sep"/>
      ${hasVault?
        `<button class="btn" id="addAcct">Add Wallet</button>`:
        `<div class="alert warn">Create or import a vault first.</div>`}
      <table class="table small"><thead><tr><th>#</th><th>Address</th></tr></thead><tbody>${accRows}</tbody></table>`;
  },
  wallets(){
    const rows=state.accounts.map(a=>`<tr><td>${a.index+1}</td><td class="mono">${a.address}</td><td id="bal-${a.index}">—</td></tr>`).join('');
    return `
      <div class="label">Wallet Balances</div>
      <table class="table small"><thead><tr><th>#</th><th>Address</th><th>ETH</th></tr></thead><tbody>${rows}</tbody></table>
      <div id="totalBal" class="small"></div>`;
  },
  send(){
    const acctOpts=state.accounts.map(a=>`<option value="${a.index}">Wallet #${a.index+1} — ${a.address.slice(0,6)}…${a.address.slice(-4)}</option>`).join('');
    return `
      <div class="label">Send ETH (Sepolia)</div>
      <div class="send-form">
        <label>From:</label><select id="fromAccount">${acctOpts}</select>
        <input id="sendTo" placeholder="Recipient 0x address"/>
        <input id="sendAmt" placeholder="Amount (ETH)"/>
        <button class="btn primary" id="doSend">Send</button>
      </div>
      <div id="sendOut" class="small"></div>
      <hr class="sep"/>
      <div class="label">Last 10 Transactions</div>
      <div id="txList" class="small">—</div>`;
  },
  settings(){
    return `
      <div class="label">Settings</div>
      <button class="btn" id="wipe">Delete vault (local)</button>`;
  }
};

/* =============== Render / Nav =============== */
function selectItem(view){$$('.sidebar .item').forEach(x=>x.classList.toggle('active',x.dataset.view===view));render(view);}
$$('.sidebar .item').forEach(el=>el.onclick=()=>selectItem(el.dataset.view));
selectItem('control');

function render(view){
  const root=$('#view');
  root.innerHTML=VIEWS[view]?VIEWS[view]():'<div>Not found</div>';

  if(view==='control'){
    $('#addAcct')?.addEventListener('click',()=>{
      const n=getAccountCount()+1; setAccountCount(n);
      const w=deriveAccountFromPhrase(state.decryptedPhrase,n-1);
      state.accounts.push({index:n-1,wallet:w,address:w.address});
      render('control');
    });
  }

  if(view==='wallets'){
    (async()=>{
      const provider=await getProvider('sep');
      let total=0;
      for(const a of state.accounts){
        try{
          const wei=await provider.getBalance(a.address);
          const eth=Number(ethers.formatEther(wei));
          total+=eth;
          $(`#bal-${a.index}`).textContent=eth.toFixed(4);
        }catch(e){$(`#bal-${a.index}`).textContent='—';}
      }
      $('#totalBal').textContent=`Total: ${total.toFixed(4)} ETH`;
    })();
  }

  if(view==='send'){
    $('#fromAccount').onchange=()=>{state.activeIndex=Number($('#fromAccount').value);setActiveSigner();loadRecentTxsForActive();};
    $('#doSend').onclick=async()=>{
      const to=$('#sendTo').value.trim(), amt=$('#sendAmt').value.trim();
      if(!ethers.isAddress(to)) return alert('Invalid recipient');
      const n=Number(amt); if(isNaN(n)||n<=0) return alert('Invalid amount');
      $('#sendOut').textContent='Checking SafeSend…';
      const check=await fetchSafeSend(to);
      $('#sendOut').innerHTML=`SafeSend Score: ${check.score}<br>${(check.findings||[]).join(' • ')}`;
      if(check.score>70) return $('#sendOut').innerHTML+='<div class="alert warn">Blocked: high risk</div>';
      $('#sendOut').textContent='Sending…';
      try{
        const res=await sendEth({to,amountEth:n});
        $('#sendOut').innerHTML=`Broadcasted: <a target=_blank href="https://sepolia.etherscan.io/tx/${res.hash}">${res.hash}</a>`;
        loadRecentTxsForActive();
      }catch(e){$('#sendOut').textContent='Error: '+(e.message||e);}
    };
    loadRecentTxsForActive();
  }

  if(view==='settings'){
    $('#wipe').onclick=()=>{if(confirm('Delete vault?')){localStorage.clear();lock();alert('Deleted.');}};
  }
}
