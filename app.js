// ─── SecureVault app.js ───────────────────────────────────────────────────────
'use strict';

// ─── AUTH HELPERS ─────────────────────────────────────────────────────────────
function logout() {
  localStorage.removeItem('sv_token');
  window.location.href = 'index.html';
}

function getToken() {
  return localStorage.getItem('sv_token');
}

function decodeToken(token) {
  try {
    const parts = token.split('.');
    return JSON.parse(atob(parts[1]));
  } catch { return null; }
}

// ─── THREAT FEED (dashboard) ──────────────────────────────────────────────────
const THREATS = [
  { id: 'T-8821', type: 'MALWARE',   severity: 'HIGH',     desc: 'Polymorphic dropper detected on subnet 10.3.x' },
  { id: 'T-8820', type: 'PHISHING',  severity: 'MEDIUM',   desc: 'Credential harvest campaign targeting ops staff' },
  { id: 'T-8819', type: 'RECON',     severity: 'LOW',      desc: 'Port scan from 185.220.x.x — TOR exit node' },
  { id: 'T-8818', type: 'EXFIL',     severity: 'CRITICAL', desc: 'Anomalous data transfer: 4.7GB outbound on port 443' },
  { id: 'T-8817', type: 'LATERAL',   severity: 'HIGH',     desc: 'SMB relay attempt on DC01 — blocked' },
  { id: 'T-8816', type: 'IMPLANT',   severity: 'CRITICAL', desc: 'C2 beacon to 104.21.x.x — quarantined' },
];

function renderFeed() {
  const grid = document.getElementById('feedGrid');
  if (!grid) return;
  grid.innerHTML = THREATS.map(t => `
    <div class="feed-card sev-${t.severity.toLowerCase()}">
      <div class="feed-header">
        <span class="feed-id">${t.id}</span>
        <span class="feed-sev">${t.severity}</span>
      </div>
      <div class="feed-type">${t.type}</div>
      <div class="feed-desc">${t.desc}</div>
    </div>
  `).join('');
}

// ─── THREAT SEARCH — VULN #2: DOM XSS via innerHTML ──────────────────────────
function searchThreats() {
  const raw   = document.getElementById('searchInput')?.value || '';
  const query = raw;

  const results = THREATS.filter(t =>
    t.type.toLowerCase().includes(query.toLowerCase()) ||
    t.desc.toLowerCase().includes(query.toLowerCase())
  );

  const el = document.getElementById('searchResults');
  if (!el) return;

  if (!query) { el.innerHTML = ''; return; }

  const html = results.length > 0
    ? `<p class="results-label">Results for: <em>${query}</em></p>` +
      results.map(t => `
        <div class="result-row">
          <span class="feed-id">${t.id}</span>
          <span class="feed-type">${t.type}</span>
          <span class="feed-desc">${t.desc}</span>
        </div>`).join('')
    : `<p class="results-label">No results for: <em>${query}</em></p>`;

  el.innerHTML = html;
}

// ─── ALERT HELPER ─────────────────────────────────────────────────────────────
function showAlert(msg, type) {
  const existing = document.getElementById('svalert');
  if (existing) existing.remove();
  const el = document.createElement('div');
  el.id = 'svalert';
  el.className = `sv-alert sv-alert-${type || 'info'}`;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ─── HIDDEN CRYPTO CHALLENGE — VULN #10 ───────────────────────────────────────
const _buildManifest = {
  integrity: 'RkxBR3tyMHQxM19lbmMwZDNkX2luX3NvdXJjM19qczJlfQ==',
  channel: 'stable',
  rev: '4f9a2c',
};

// ─── FLAG SUBMISSION ──────────────────────────────────────────────────────────
const WORKER_URL = 'https://vulnerioc.qzz.io/api/validate';
const validatedFlags = new Set();
let liveCheckTimers = {};

function buildFlagInputs() {
  const grid = document.getElementById('flagsGrid');
  if (!grid) return;
  grid.innerHTML = Array.from({length: 10}, (_, i) => `
    <div class="flag-row" id="flagRow${i}">
      <span class="flag-num">${String(i+1).padStart(2,'0')}</span>
      <input class="flag-input" id="flagInput${i}" type="text"
        placeholder="FLAG{...}" spellcheck="false" autocomplete="off"
        oninput="scheduleLiveCheck(${i})" />
      <span class="flag-indicator" id="flagInd${i}"></span>
    </div>`).join('');
}

function scheduleLiveCheck(i) {
  clearTimeout(liveCheckTimers[i]);
  const val = document.getElementById(`flagInput${i}`).value.trim();
  const row = document.getElementById(`flagRow${i}`);
  const ind = document.getElementById(`flagInd${i}`);

  if (!val) {
    row.className = 'flag-row';
    ind.textContent = '';
    return;
  }

  ind.textContent = '…';
  liveCheckTimers[i] = setTimeout(() => validateFlag(i, val), 600);
}

async function validateFlag(i, flag) {
  const row = document.getElementById(`flagRow${i}`);
  const ind = document.getElementById(`flagInd${i}`);

  if (validatedFlags.has(flag)) {
    row.className = 'flag-row correct';
    ind.textContent = '✓';
    updateProgress();
    return;
  }

  try {
    const res = await fetch(WORKER_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ flag })
    });
    const data = await res.json();

    if (data.valid) {
      validatedFlags.add(flag);
      row.className = 'flag-row correct';
      ind.textContent = '✓';
    } else {
      row.className = 'flag-row wrong';
      ind.textContent = '✗';
    }
  } catch {
    ind.textContent = '?';
  }

  updateProgress();
}

function updateProgress() {
  const entered = Array.from({length:10}, (_,i) =>
    document.getElementById(`flagInput${i}`)?.value.trim()
  ).filter(f => f && validatedFlags.has(f));

  const unique = new Set(entered).size;
  const status = document.getElementById('flagStatus');
  if (!status) return;

  if (unique === 10) {
    status.style.color = 'var(--green)';
    status.textContent = '✓ ALL FLAGS CAPTURED — certificate unlocked';
    // certificate trigger goes here later
  } else {
    status.style.color = 'var(--text2)';
    status.textContent = unique > 0 ? `${unique} / 10 valid flags` : '';
  }
}

function checkFlags() {
  Array.from({length:10}, (_,i) => {
    const val = document.getElementById(`flagInput${i}`)?.value.trim();
    if (val) validateFlag(i, val);
  });
}

// ─── INIT ─────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  // Update nav username display
  const token = getToken();
  const el = document.getElementById('userDisplay');
  if (el && token) {
    const p = decodeToken(token);
    if (p) el.textContent = (p.name || 'USER').split(' ')[0].toUpperCase();
  }

  renderFeed();
  buildFlagInputs();
});