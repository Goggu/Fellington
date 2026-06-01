// ─── SecureVault app.js ───────────────────────────────────────────────────────
// Shared utilities across all pages.

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

// Update nav display on all pages
window.addEventListener('DOMContentLoaded', () => {
  const token = getToken();
  const el = document.getElementById('userDisplay');
  if (el && token) {
    const p = decodeToken(token);
    if (p) el.textContent = (p.name || 'USER').split(' ')[0].toUpperCase();
  }
});

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
// User input is interpolated directly into HTML without sanitization.
// Payload: <img src=x onerror="document.getElementById('searchResults').innerHTML='<span class=flag-text>FLAG{d0m_xss_inn3rHTML_s34rch_r3fl3ct3d_7c3f}</span>'">
function searchThreats() {
  const raw   = document.getElementById('searchInput')?.value || '';
  const query = raw; // NOT sanitized

  const results = THREATS.filter(t =>
    t.type.toLowerCase().includes(query.toLowerCase()) ||
    t.desc.toLowerCase().includes(query.toLowerCase())
  );

  const el = document.getElementById('searchResults');
  if (!el) return;

  if (!query) {
    el.innerHTML = '';
    return;
  }

  // Unsanitized query injected into display
  const html = results.length > 0
    ? `<p class="results-label">Results for: <em>${query}</em></p>` +
      results.map(t => `
        <div class="result-row">
          <span class="feed-id">${t.id}</span>
          <span class="feed-type">${t.type}</span>
          <span class="feed-desc">${t.desc}</span>
        </div>`).join('')
    : `<p class="results-label">No results for: <em>${query}</em></p>`;

  el.innerHTML = html; // <-- injection point
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

// ─── INIT ──────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  renderFeed();
});

// ─── HIDDEN CRYPTO CHALLENGE ───────────────────────────────────────────────────
// VULN #10: Secret encoded in a non-obvious place.
// The following looks like a config hash. It's actually a ROT13 + base64 encoded flag.
// Encoded: RkxBR3tyMHQxM19lbmMwZDNkX2luX3NvdXJjM19qczJlfQ==
// Decode steps: base64decode -> ROT13
// Result: FLAG{r0t13_enc0d3d_in_sourc3_js2e}
const _buildManifest = {
  integrity: 'RkxBR3tyMHQxM19lbmMwZDNkX2luX3NvdXJjM19qczJlfQ==',
  channel: 'stable',
  rev: '4f9a2c',
};
// (integrity value is not actually verified anywhere — just sits here)
