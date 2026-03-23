/* =====================================================================
   CasaID — app.js  |  Web Crypto + IndexedDB  |  No server required
   ===================================================================== */

// ── IndexedDB ──────────────────────────────────────────────────────────
const DB_NAME = 'casaid_db', DB_VER = 1;
let db;

function initDB() {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB_NAME, DB_VER);
    r.onupgradeneeded = e => {
      const d = e.target.result;
      if (!d.objectStoreNames.contains('users')) {
        d.createObjectStore('users', { keyPath: 'id' })
         .createIndex('username', 'username', { unique: true });
      }
      if (!d.objectStoreNames.contains('documents')) {
        d.createObjectStore('documents', { keyPath: 'id' })
         .createIndex('userId', 'userId');
      }
    };
    r.onsuccess = e => { db = e.target.result; res(db); };
    r.onerror   = e => rej(e.target.error);
  });
}
const tx  = (s, m) => db.transaction(s, m).objectStore(s);
const dbGet = (s, k) => new Promise((r, j) => { const q = tx(s,'readonly').get(k);       q.onsuccess=()=>r(q.result); q.onerror=()=>j(q.error); });
const dbIdx = (s, i, v) => new Promise((r, j) => { const q = tx(s,'readonly').index(i).get(v); q.onsuccess=()=>r(q.result); q.onerror=()=>j(q.error); });
const dbAll = (s, i, v) => new Promise((r, j) => { const q = tx(s,'readonly').index(i).getAll(v); q.onsuccess=()=>r(q.result); q.onerror=()=>j(q.error); });
const dbPut = (s, d) => new Promise((r, j) => { const q = tx(s,'readwrite').put(d); q.onsuccess=()=>r(q.result); q.onerror=()=>j(q.error); });
const dbDel = (s, k) => new Promise((r, j) => { const q = tx(s,'readwrite').delete(k); q.onsuccess=()=>r(); q.onerror=()=>j(q.error); });

// ── Web Crypto (PBKDF2 + AES-256-GCM) ─────────────────────────────────
const VERIFIER_PLAIN = new TextEncoder().encode('CasaID-verifier-v1');

async function deriveKey(password, salt) {
  const raw = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
    raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
async function aesEncrypt(key, data) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const buf = data instanceof ArrayBuffer ? data : await new Response(data).arrayBuffer();
  return { iv, data: await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buf) };
}
async function aesDecrypt(key, iv, data) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
}

// ── Session ────────────────────────────────────────────────────────────
let session = null; // { id, username, fullName, key }

// ── Auth ───────────────────────────────────────────────────────────────
async function registerUser(fullName, username, password) {
  username = username.trim().toLowerCase();
  if (username.length < 3) throw new Error('Usuario: mínimo 3 caracteres.');
  if (password.length  < 6) throw new Error('Contraseña: mínimo 6 caracteres.');
  if (await dbIdx('users', 'username', username)) throw new Error('Ese usuario ya existe.');

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key  = await deriveKey(password, salt);
  const { iv, data } = await aesEncrypt(key, VERIFIER_PLAIN.buffer);

  await dbPut('users', {
    id: crypto.randomUUID(), username, fullName: fullName.trim(),
    salt, verIv: iv, verData: data, createdAt: new Date().toISOString()
  });
}

async function loginUser(username, password) {
  username = username.trim().toLowerCase();
  const user = await dbIdx('users', 'username', username);
  if (!user) throw new Error('Usuario o contraseña incorrectos.');

  const key = await deriveKey(password, user.salt);
  try { await aesDecrypt(key, user.verIv, user.verData); }
  catch { throw new Error('Usuario o contraseña incorrectos.'); }

  session = { id: user.id, username: user.username, fullName: user.fullName, key };
}

function logoutUser() { session = null; }

// ── Documents ──────────────────────────────────────────────────────────
const ALLOWED_TYPES = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp'];

async function saveDoc(file) {
  if (!session) throw new Error('No autenticado.');
  if (!ALLOWED_TYPES.includes(file.type)) throw new Error(`Tipo no permitido: ${file.type}`);
  if (file.size > 20 * 1024 * 1024) throw new Error('Máximo 20 MB por archivo.');

  const { iv, data } = await aesEncrypt(session.key, file);
  await dbPut('documents', {
    id: crypto.randomUUID(), userId: session.id,
    origName: file.name, mimeType: file.type,
    sizeBytes: file.size, uploadedAt: new Date().toISOString(),
    iv, encData: data
  });
}

async function listDocs() {
  if (!session) return [];
  const docs = await dbAll('documents', 'userId', session.id);
  return docs.sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt));
}

async function loadDocBlob(doc) {
  const buf = await aesDecrypt(session.key, doc.iv, doc.encData);
  return new Blob([buf], { type: doc.mimeType });
}

async function deleteDoc(id) { await dbDel('documents', id); }

// ── Utils ──────────────────────────────────────────────────────────────
const fmtSize = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n/1024).toFixed(1)} KB` : `${(n/1048576).toFixed(1)} MB`;
const fmtDate = s => s.slice(0, 10);

let toastTmr;
function toast(msg, type = 'ok') {
  const el = document.getElementById('toast');
  el.textContent = (type === 'ok' ? '✅ ' : '❌ ') + msg;
  el.className = 'show ' + type;
  clearTimeout(toastTmr);
  toastTmr = setTimeout(() => el.className = '', 3000);
}

function setMsg(id, html, cls = 'err') {
  document.getElementById(id).innerHTML = `<div class="msg ${cls}">${html}</div>`;
}

// ── PWA Install ────────────────────────────────────────────────────────
let deferredPrompt = null;
window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault(); deferredPrompt = e;
  document.getElementById('install-btn').style.display = 'flex';
});
window.installPWA = async () => {
  if (!deferredPrompt) return;
  deferredPrompt.prompt();
  await deferredPrompt.userChoice;
  deferredPrompt = null;
  document.getElementById('install-btn').style.display = 'none';
};

// ── UI helpers ─────────────────────────────────────────────────────────
function show(id)  { document.getElementById(id).style.display = ''; }
function hide(id)  { document.getElementById(id).style.display = 'none'; }
function val(id)   { return document.getElementById(id).value.trim(); }

window.toggleSidebar = () => document.getElementById('sidebar').classList.toggle('open');
window.closeSidebar  = () => document.getElementById('sidebar').classList.remove('open');

function renderLoggedIn() {
  hide('auth-panel'); show('user-panel');
  hide('view-hero');  show('view-dashboard');
  document.getElementById('user-fullname').textContent = session.fullName;
  document.getElementById('user-username').textContent = '@' + session.username;
  document.getElementById('greeting-name').textContent = session.fullName.split(' ')[0];
  renderGallery();
}

function renderLoggedOut() {
  show('auth-panel'); hide('user-panel');
  show('view-hero');  hide('view-dashboard');
  closeSidebar();
}

// ── Auth UI ────────────────────────────────────────────────────────────
window.switchTab = tab => {
  ['login', 'register'].forEach(t => {
    document.getElementById('form-' + t).style.display  = t === tab ? '' : 'none';
    document.getElementById('tab-'  + t).classList.toggle('active', t === tab);
  });
  document.getElementById('login-msg').innerHTML = '';
  document.getElementById('reg-msg').innerHTML   = '';
};

window.handleLogin = async () => {
  const username = val('login-username'), password = val('login-password');
  if (!username || !password) { setMsg('login-msg', 'Completa todos los campos.'); return; }
  const btn = document.getElementById('btn-login');
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Verificando…';
  try {
    await loginUser(username, password);
    renderLoggedIn(); closeSidebar();
    document.getElementById('login-msg').innerHTML = '';
  } catch (e) { setMsg('login-msg', e.message); }
  finally { btn.disabled = false; btn.textContent = 'Entrar →'; }
};

window.handleRegister = async () => {
  const fullName = val('reg-fullname'), username = val('reg-username'),
        pw1 = val('reg-pw1'), pw2 = val('reg-pw2');
  if (!fullName || !username || !pw1 || !pw2) { setMsg('reg-msg', 'Completa todos los campos.'); return; }
  if (pw1 !== pw2) { setMsg('reg-msg', 'Las contraseñas no coinciden.'); return; }
  const btn = document.getElementById('btn-register');
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Creando cuenta…';
  try {
    await registerUser(fullName, username, pw1);
    setMsg('reg-msg', 'Cuenta creada. Ya puedes iniciar sesión.', 'ok');
    setTimeout(() => switchTab('login'), 1500);
    ['reg-fullname','reg-username','reg-pw1','reg-pw2'].forEach(id => document.getElementById(id).value = '');
  } catch (e) { setMsg('reg-msg', e.message); }
  finally { btn.disabled = false; btn.textContent = 'Registrarse →'; }
};

window.handleLogout = () => { logoutUser(); renderLoggedOut(); };

// ── Upload UI ──────────────────────────────────────────────────────────
let pendingFile = null;

window.triggerUpload = () => document.getElementById('fileInput').click();

window.handleDragOver = e => { e.preventDefault(); document.getElementById('upload-area').classList.add('over'); };
window.handleDragLeave = () => document.getElementById('upload-area').classList.remove('over');
window.handleDrop = e => {
  e.preventDefault();
  document.getElementById('upload-area').classList.remove('over');
  const f = e.dataTransfer.files[0];
  if (f) setPendingFile(f);
};

window.handleFileSelect = e => { if (e.target.files[0]) setPendingFile(e.target.files[0]); };

function setPendingFile(f) {
  pendingFile = f;
  document.getElementById('upload-info').innerHTML = `
    <div class="file-bar">
      <span class="ficon">${f.type === 'application/pdf' ? '📄' : '🖼️'}</span>
      <div class="fmeta"><div class="fname">${f.name}</div><div class="fsize">${fmtSize(f.size)}</div></div>
      <button class="btn-upload" onclick="doUpload()">⬆️ Subir</button>
    </div>`;
}

window.doUpload = async () => {
  if (!pendingFile) return;
  const bar = document.getElementById('upload-info');
  bar.innerHTML = `<div class="progress"><div class="progress-fill" id="pfill"></div></div><p style="text-align:center;font-size:.8rem;color:var(--muted);margin-top:.5rem">Cifrando y guardando…</p>`;
  let p = 0;
  const iv = setInterval(() => { p = Math.min(p + 10, 90); document.getElementById('pfill').style.width = p + '%'; }, 200);
  try {
    await saveDoc(pendingFile);
    clearInterval(iv);
    document.getElementById('pfill').style.width = '100%';
    setTimeout(() => {
      bar.innerHTML = '';
      pendingFile = null;
      document.getElementById('fileInput').value = '';
      renderGallery();
      toast('Documento guardado y cifrado.');
    }, 400);
  } catch (e) {
    clearInterval(iv);
    bar.innerHTML = `<div class="msg err">${e.message}</div>`;
  }
};

// ── Gallery UI ─────────────────────────────────────────────────────────
async function renderGallery() {
  const docs = await listDocs();
  document.getElementById('doc-count').textContent = docs.length;
  const g = document.getElementById('gallery');

  if (!docs.length) {
    g.innerHTML = `
      <div class="empty-state">
        <div class="estate-icon">📂</div>
        <h3>Aún no tienes documentos</h3>
        <p>Haz clic en la zona de subida para añadir tu primer DNI.</p>
      </div>`;
    return;
  }

  g.innerHTML = docs.map(doc => `
    <div class="doc-card" id="card-${doc.id}">
      <div class="doc-head">
        <span class="doc-icon">${doc.mimeType === 'application/pdf' ? '📄' : '🖼️'}</span>
        <div class="doc-info">
          <div class="doc-name">${doc.origName}</div>
          <div class="doc-meta">${fmtSize(doc.sizeBytes)} · ${fmtDate(doc.uploadedAt)}</div>
        </div>
      </div>
      <div class="doc-actions">
        <button class="btn-act" onclick="previewDoc('${doc.id}')">👁️ Ver</button>
        <button class="btn-act" onclick="downloadDoc('${doc.id}')">⬇️ Descargar</button>
        <button class="btn-act wa" onclick="shareWA('${doc.origName}')">🟢 WhatsApp</button>
        <button class="btn-act danger" onclick="confirmDelete('${doc.id}')">🗑️ Borrar</button>
      </div>
      <div id="del-${doc.id}"></div>
    </div>`).join('');
}

// cache of loaded docs by id for gallery ops
async function getDocFromDB(id) {
  return dbGet('documents', id);
}

window.previewDoc = async id => {
  const doc = await getDocFromDB(id);
  const blob = await loadDocBlob(doc);
  const url  = URL.createObjectURL(blob);
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <span>${doc.origName}</span>
        <button class="modal-close" onclick="this.closest('.modal-overlay').remove();URL.revokeObjectURL('${url}')">✖</button>
      </div>
      <div class="modal-body">
        ${doc.mimeType === 'application/pdf'
          ? `<iframe src="${url}"></iframe>`
          : `<img src="${url}" alt="${doc.origName}">`
        }
      </div>
    </div>`;
  document.body.appendChild(modal);
};

window.downloadDoc = async id => {
  const doc = await getDocFromDB(id);
  const blob = await loadDocBlob(doc);
  const a = Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(blob), download: doc.origName
  });
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
};

window.shareWA = name => {
  const text = `Te comparto mi documento "${name}" desde CasaID.\n📥 Descárgalo en la app.`;
  window.open('https://wa.me/?text=' + encodeURIComponent(text), '_blank');
};

window.confirmDelete = id => {
  const el = document.getElementById('del-' + id);
  el.innerHTML = `
    <div class="confirm-del">
      <span>¿Eliminar permanentemente?</span>
      <button class="btn-act danger" onclick="doDelete('${id}')">Sí, borrar</button>
      <button class="btn-act" onclick="document.getElementById('del-${id}').innerHTML=''">Cancelar</button>
    </div>`;
};

window.doDelete = async id => {
  await deleteDoc(id);
  toast('Documento eliminado.');
  renderGallery();
};

// ── Boot ───────────────────────────────────────────────────────────────
(async () => {
  await initDB();
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js');
  renderLoggedOut();
})();
