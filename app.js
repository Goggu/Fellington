const WORKER_URL = 'https://vulnerioc.qzz.io/api/validate';

// cache of flags validated this session so we don't re-hit the worker on every keystroke
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

// debounce so we only call the worker when the user stops typing
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

  // already confirmed valid this session
  if (validatedFlags.has(flag)) {
    row.className = 'flag-row correct';
    ind.textContent = '✓';
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
  // collect unique valid flags across all inputs
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
  // manual recheck — re-validate all filled inputs
  Array.from({length:10}, (_,i) => {
    const val = document.getElementById(`flagInput${i}`)?.value.trim();
    if (val) validateFlag(i, val);
  });
}