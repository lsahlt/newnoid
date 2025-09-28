// static/app.js
let token = null;
let username = null;
let ws = null;

// Disable login button until Kyber JS is loaded
let kyberReady = false;
document.getElementById('enter').disabled = true;
window.addEventListener('DOMContentLoaded', () => {
  if (window.kyber && window.kyber.KeyGen1024) {
    kyberReady = true;
    document.getElementById('enter').disabled = false;
  } else {
    const checkKyber = setInterval(() => {
      if (window.kyber && window.kyber.KeyGen1024) {
        kyberReady = true;
        document.getElementById('enter').disabled = false;
        clearInterval(checkKyber);
      }
    }, 100);
  }
});

document.getElementById('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!kyberReady) {
    document.getElementById('loginMsg').innerText = 'Kyber JS not loaded. Please refresh or check script order.';
    document.getElementById('loginMsg').style.color = 'red';
    alert('Crypto module not loaded yet. Please wait.');
    return;
  }
  username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();
  if (!username) { alert('enter username'); return; }
  const res = await fetch('/login', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ username, password })
  });
  const j = await res.json();
  if (j.ok && j.token) {
    token = j.token;
    // Generate Kyber keypair and store with username and token
    const kp = window.kyber.KeyGen1024();
    const kyberPublicKey = kp[0];
    const kyberSecretKey = kp[1];
    localStorage.setItem('noid.user', JSON.stringify({ name: username, token, kyberPublicKey, kyberSecretKey }));
    document.getElementById('login').style.display = 'none';
    document.getElementById('chatUi').style.display = 'block';
    document.getElementById('me').innerText = username;
    connectWs();
  } else {
    document.getElementById('loginMsg').innerText = j.msg || 'login failed';
  }
});

function connectWs() {
  // ws path
  const p = (location.protocol === 'https:') ? 'wss' : 'ws';
  ws = new WebSocket(`${p}://${location.host}/ws`);

  ws.onopen = () => {
    // send hello with token
    const hello = { type: 'hello', username, token };
    console.log('[WS] Sending hello:', hello);
    ws.send(JSON.stringify(hello));
  };

  ws.onmessage = (ev) => {
    console.log('[WS] Raw incoming event.data:', ev.data);
    try {
      const obj = JSON.parse(ev.data);
      console.log('[WS] Parsed incoming data:', obj);
      if (obj.type === 'system') {
        appendSystem(obj.msg);
      } else if (obj.type === 'ciphertext' || obj.type === 'pubkey' || obj.type === 'encap' || obj.type === 'ipfs' || obj.type === 'pubkey') {
        appendMsg(obj.from, `[${obj.type}] ${obj.data || obj.cid || ''}`);
      } else if (obj.user && obj.text) {
        appendMsg(obj.user, obj.text);
      } else {
        appendSystem(JSON.stringify(obj));
      }
    } catch (e) {
      console.error('[WS] JSON parse error:', e, ev.data);
      appendSystem(ev.data);
    }
  };
}

// --- Kyber-1024 JS E2EE integration ---
// On login, generate Kyber keypair if not present
// Kyber keypair is now only generated and stored after login

document.getElementById('btnSend').onclick = async () => {
  const text = document.getElementById('msg').value;
  if (!text) return;
  const recipient = document.getElementById('recipient').value.trim();
  let payload;
  if (recipient && recipient !== username) {
    // Encrypt message for the recipient using Kyber-1024 and AES-GCM
    const user = JSON.parse(localStorage.getItem('noid.user'));
    const recipientKyberPublicKey = localStorage.getItem('kyber.' + recipient + '.publicKey');
    if (!recipientKyberPublicKey) {
      console.error('[Kyber] Recipient Kyber public key not found!');
      appendSystem('Recipient public key not found.');
      return;
    }
    const enc = await encryptForRecipient(recipientKyberPublicKey, text);
    payload = {
      type: 'ciphertext',
      from: username,
      to: recipient,
      kyber_ct: enc.kyber_ct,
      nonce: enc.nonce,
      aes_ciphertext: enc.aes_ciphertext
    };
    console.log('[WS] Sending encrypted payload:', payload);
    ws.send(JSON.stringify(payload));
    appendMsg(username, '[encrypted] ' + text);
  } else {
    // Fallback: plaintext to self or broadcast
    payload = { type: 'plaintext', from: username, to: null, data: text };
    console.log('[WS] Sending plaintext payload:', payload);
    ws.send(JSON.stringify(payload));
    appendMsg(username, text);
  }
  document.getElementById('msg').value = '';
};

function appendMsg(user, text) {
  const chat = document.getElementById('chat');
  const div = document.createElement('div');
  div.className = (user === username) ? 'me' : 'other';
  div.innerText = `${user}: ${text}`;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

function appendSystem(text) {
  const chat = document.getElementById('chat');
  const div = document.createElement('div');
  div.style.color = 'gray';
  div.innerText = `* ${text}`;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

// Kyber-1024 keypair generation (browser)
// Kyber keypair is only generated and stored after login, inside noid.user

// Encrypt message for recipient using Kyber-1024 and AES-GCM
async function encryptForRecipient(recipientPublicKey, message) {
  // Kyber encapsulation
  const c_ss = kyber.Encrypt1024(recipientPublicKey);
  const ciphertext = c_ss[0];
  const sharedSecret = c_ss[1];
  // AES-GCM encryption
  const enc = new TextEncoder().encode(message);
  const key = await window.crypto.subtle.importKey('raw', sharedSecret, 'AES-GCM', false, ['encrypt']);
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertextAes = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, enc);
  return {
    kyber_ct: ciphertext,
    nonce: Array.from(nonce),
    aes_ciphertext: Array.from(new Uint8Array(ciphertextAes))
  };
}

// Decrypt message from sender using Kyber-1024 and AES-GCM
async function decryptFromSender(kyber_ct, nonce, aes_ciphertext) {
  const secretKey = localStorage.getItem('kyber.secretKey');
  const sharedSecret = kyber.Decrypt1024(kyber_ct, secretKey);
  const key = await window.crypto.subtle.importKey('raw', sharedSecret, 'AES-GCM', false, ['decrypt']);
  const ciphertextAes = new Uint8Array(aes_ciphertext);
  const iv = new Uint8Array(nonce);
  const plaintext = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertextAes);
  return new TextDecoder().decode(plaintext);
}
