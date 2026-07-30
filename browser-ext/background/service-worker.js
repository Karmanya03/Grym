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
  chrome.runtime.sendMessage(msg).catch(() => {});
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
        grymState.findings.push(...(result.findings || []));
        grymState.activeScan = { ...grymState.activeScan, status: 'completed', progress: 100, completedAt: Date.now() };
        grymState.scanHistory.push(grymState.activeScan);
        saveState();
        broadcast({ type: 'scanComplete', scan: grymState.activeScan, findings: result.findings || [] });
        return;
      }
    }

    const findings = await runLocalScan(target, scanType, options);
    grymState.findings.push(...findings);
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
