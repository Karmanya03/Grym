const state = {
  connected: false,
  findings: [],
  scanning: false,
  tab: null
};

const el = (id) => document.getElementById(id);
const toast = (msg) => {
  const t = el('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2200);
};

function setStatus(connected) {
  state.connected = connected;
  const pill = el('statusPill');
  const text = el('statusText');
  if (connected) {
    pill.classList.add('connected');
    text.textContent = 'Connected';
  } else {
    pill.classList.remove('connected');
    text.textContent = 'Offline';
  }
}

function renderFindings() {
  const list = el('scanList');
  const count = el('findingsCount');
  count.textContent = state.findings.length;

  if (state.findings.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          <polyline points="14 2 14 8 20 8"/>
          <line x1="12" y1="18" x2="12" y2="12"/>
          <line x1="9" y1="15" x2="15" y2="15"/>
        </svg>
        <p>No findings yet. Run a quick scan to start.</p>
      </div>`;
    return;
  }

  const severityClass = (s) => {
    const sev = String(s).toLowerCase();
    if (sev.includes('critical') || sev.includes('high')) return 'high';
    if (sev.includes('medium')) return 'medium';
    if (sev.includes('low')) return 'low';
    return 'info';
  };

  const items = state.findings.slice(0, 5).map(f => {
    const sev = severityClass(f.severity || f.type || 'info');
    return `
      <div class="scan-item" title="${escapeHtml(f.title || 'Finding')}">
        <span class="scan-dot ${sev}"></span>
        <span class="scan-title">${escapeHtml(truncate(f.title || f.type || 'Finding', 34))}</span>
        <span class="scan-severity ${sev}">${sev}</span>
      </div>
    `;
  }).join('');

  list.innerHTML = items;
}

function truncate(str, n) {
  return str.length > n ? str.slice(0, n - 1) + '…' : str;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

async function init() {
  try {
    const s = await chrome.runtime.sendMessage({ type: 'getState' });
    if (s) {
      setStatus(s.serverConnected || false);
      state.findings = s.findings || [];
      renderFindings();
    }
  } catch (e) {
    setStatus(false);
  }

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    state.tab = tab;
  } catch {}
}

async function checkConnection() {
  try {
    const ok = await chrome.runtime.sendMessage({ type: 'connect' });
    setStatus(ok);
  } catch {
    setStatus(false);
  }
}

async function runQuickScan() {
  if (state.scanning) return;
  state.scanning = true;
  const btn = el('quickScanBtn');
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span><span>Scanning…</span>`;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error('No active tab');

    const result = await chrome.tabs.sendMessage(tab.id, { type: 'full' });
    if (result?.findings?.length) {
      state.findings.unshift(...result.findings);
      chrome.runtime.sendMessage({ type: 'addFindings', findings: result.findings }).catch(() => {});
      renderFindings();
      toast(`${result.findings.length} findings found`);
    } else {
      toast('No findings on this page');
    }
  } catch (e) {
    toast('Scan failed: ' + e.message);
  } finally {
    state.scanning = false;
    btn.disabled = false;
    btn.innerHTML = original;
  }
}

function openDashboard() {
  chrome.runtime.sendMessage({ type: 'openDashboard' }).catch(() => {
    window.open(chrome.runtime.getURL('dashboard/dashboard.html'), '_blank');
  });
  window.close();
}

function showFindings() {
  openDashboard();
}

function clearFindings() {
  state.findings = [];
  renderFindings();
  chrome.runtime.sendMessage({ type: 'clearFindings' }).catch(() => {});
  toast('Findings cleared');
}

el('quickScanBtn').addEventListener('click', runQuickScan);
el('dashboardBtn').addEventListener('click', openDashboard);
el('findingsBtn').addEventListener('click', showFindings);
el('clearBtn').addEventListener('click', clearFindings);
el('retryBtn').addEventListener('click', checkConnection);
el('settingsBtn').addEventListener('click', openDashboard);

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'connection') {
    setStatus(msg.connected);
  } else if (msg.type === 'quickAnalysis') {
    if (msg.data?.findings) {
      state.findings.unshift(...msg.data.findings);
      renderFindings();
    }
  } else if (msg.type === 'scanComplete') {
    state.findings.unshift(...(msg.findings || []));
    renderFindings();
  }
});

init();
checkConnection();
