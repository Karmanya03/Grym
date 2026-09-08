const STORAGE_KEY = 'grym_state';
const CONNECTION_KEY = 'grym_connection';
const NATIVE_HOST = 'grym.scanner';

let grymState = {
  serverConnected: false,
  serverUrl: 'http://localhost:9378',
  activeScan: null,
  findings: [],
  scanHistory: [],
  preferences: {
    theme: 'dark',
    autoAnalyze: true,
    notifications: true
  }
};

async function loadState() {
  try {
    const stored = await chrome.storage.local.get([STORAGE_KEY]);
    if (stored[STORAGE_KEY]) {
      grymState = { ...grymState, ...stored[STORAGE_KEY] };
    }
  } catch (e) {
    console.warn('[Grym] Failed to load state:', e);
  }
}

async function saveState() {
  try {
    await chrome.storage.local.set({ [STORAGE_KEY]: grymState });
  } catch (e) {
    console.warn('[Grym] Failed to save state:', e);
  }
}

async function tryConnectNative() {
  try {
    const port = chrome.runtime.connectNative(NATIVE_HOST);
    port.onMessage.addListener((msg) => {
      grymState.serverConnected = true;
      saveState();
      broadcast({ type: 'connection', connected: true, transport: 'native' });
    });
    port.onDisconnect.addListener(() => {
      grymState.serverConnected = false;
      saveState();
      broadcast({ type: 'connection', connected: false, transport: 'native' });
    });
    port.postMessage({ type: 'ping' });
    return true;
  } catch {
    return false;
  }
}

async function tryConnectHttp(url) {
  try {
    const resp = await fetch(`${url}/health`, {
      method: 'GET',
      signal: AbortSignal.timeout(3000)
    });
    if (resp.ok) {
      grymState.serverConnected = true;
      grymState.serverUrl = url;
      saveState();
      broadcast({ type: 'connection', connected: true, transport: 'http' });
      return true;
    }
  } catch {}
  grymState.serverConnected = false;
  broadcast({ type: 'connection', connected: false, transport: 'http' });
  return false;
}

async function detectServer() {
  const nativeOk = await tryConnectNative();
  if (nativeOk) return true;
  for (const port of [9378, 9379, 8080]) {
    if (await tryConnectHttp(`http://localhost:${port}`)) return true;
  }
  grymState.serverConnected = false;
  broadcast({ type: 'connection', connected: false });
  return false;
}

function broadcast(msg) {
  try {
    chrome.runtime.sendMessage(msg).catch(() => {});
  } catch {}
}

function addFindings(newFindings) {
  const fresh = (Array.isArray(newFindings) ? newFindings : [])
    .filter((f) => f && typeof f === 'object' && (f.title || f.type));
  if (fresh.length === 0) return;
  const seen = new Set(grymState.findings.map((f) => `${f.target}|${f.title}|${f.type}`));
  for (const f of fresh) {
    const key = `${f.target || ''}|${f.title || ''}|${f.type || ''}`;
    if (!seen.has(key)) {
      seen.add(key);
      grymState.findings.unshift({ ...f, timestamp: f.timestamp || new Date().toISOString() });
    }
  }
  if (grymState.findings.length > 500) grymState.findings.length = 500;
  saveState();
}

async function handleScanRequest(request, sender, sendResponse) {
  const { target, scanType, options } = request;

  const scanId = crypto.randomUUID();
  grymState.activeScan = { id: scanId, target, scanType, status: 'running', progress: 0, startedAt: Date.now() };
  saveState();
  broadcast({ type: 'scanStart', scan: grymState.activeScan });

  try {
    if (grymState.serverConnected && grymState.serverUrl) {
      const resp = await fetch(`${grymState.serverUrl}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scan_types: options.modules || ['all'], options })
      });
      if (resp.ok) {
        const result = await resp.json();
        addFindings(result.findings || []);
        grymState.activeScan = { ...grymState.activeScan, status: 'completed', progress: 100, completedAt: Date.now() };
        grymState.scanHistory.push(grymState.activeScan);
        saveState();
        broadcast({ type: 'scanComplete', scan: grymState.activeScan, findings: result.findings || [] });
        return;
      }
    }

    const findings = await runLocalScan(target, scanType, options);
    addFindings(findings);
    grymState.activeScan = { ...grymState.activeScan, status: 'completed', progress: 100, completedAt: Date.now() };
    grymState.scanHistory.push(grymState.activeScan);
    saveState();
    broadcast({ type: 'scanComplete', scan: grymState.activeScan, findings });

  } catch (err) {
    grymState.activeScan = { ...grymState.activeScan, status: 'failed', error: err.message };
    saveState();
    broadcast({ type: 'scanError', scan: grymState.activeScan, error: err.message });
  }
}

async function runLocalScan(target, scanType, options) {
  const findings = [];
  const tabId = options?.tabId;

  if (tabId) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        func: (type, opts) => {
          return window.__grymScan ? window.__grymScan(type, opts) : { error: 'scan not available' };
        },
        args: [scanType, options]
      });
      if (results?.[0]?.result?.findings) {
        findings.push(...results[0].result.findings);
      }
    } catch {}
  }

  return findings;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case 'getState':
      sendResponse(grymState);
      break;
    case 'connect':
      detectServer().then(sendResponse);
      return true;
    case 'startScan':
      handleScanRequest(message, sender, sendResponse);
      return true;
    case 'getFindings':
      sendResponse(grymState.findings);
      break;
    case 'clearFindings':
      grymState.findings = [];
      saveState();
      sendResponse({ ok: true });
      break;
    case 'pageData':
      grymState.lastPageData = message.data || null;
      saveState();
      broadcast({ type: 'stateUpdate', lastPageData: grymState.lastPageData });
      break;
    case 'getPageData':
      sendResponse(grymState.lastPageData || null);
      break;
    case 'quickAnalysis':
      if (message.data?.findings) {
        addFindings(message.data.findings);
        broadcast({ type: 'quickAnalysis', data: message.data });
      }
      sendResponse({ ok: true });
      break;
    case 'addFindings':
      addFindings(message.findings || []);
      broadcast({ type: 'stateUpdate', findings: grymState.findings });
      sendResponse({ ok: true, total: grymState.findings.length });
      break;
    case 'openDashboard':
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
      sendResponse({ ok: true });
      break;
    case 'analyzeTab':
      chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
        if (tab?.id) {
          chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => window.__grymQuickAnalyze ? window.__grymQuickAnalyze() : null
          });
        }
      });
      sendResponse({ ok: true });
      break;
  }
});

chrome.runtime.onInstalled.addListener(async () => {
  await loadState();
  detectServer().catch(() => {});
  broadcast({ type: 'ready' });
});

loadState();
