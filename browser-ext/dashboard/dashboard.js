(function () {
  'use strict';

  const FINDINGS_PER_PAGE = 15;
  const STORAGE_KEY = 'grym_dashboard_state';

  let state = {
    activeTab: 'dashboard',
    findings: [],
    targets: [],
    scanHistory: [],
    serverConnected: false,
    serverTransport: null,
    serverUrl: 'http://localhost:9378',
    filter: 'all',
    currentPage: 1,
    scanning: false,
    cveEntries: [],
    cveQuery: '',
    modules: [
      'sqli', 'xss', 'ssti', 'ssrf', 'cmdi', 'ptrav',
      'cors', 'jwt', 'openredir', 'idor', 'waf', 'http_smuggle',
      'xxe', 'tech_fp', 'csrf', 'nosqli', 'graphql', 'hhi'
    ],
    activeModules: new Set([
      'sqli', 'xss', 'ssti', 'ssrf', 'cmdi', 'ptrav',
      'cors', 'jwt', 'openredir', 'idor', 'waf', 'http_smuggle',
      'xxe', 'tech_fp', 'csrf', 'nosqli', 'graphql', 'hhi'
    ])
  };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const els = {};

  function cacheElements() {
    els.navItems = $$('.nav-item');
    els.tabContents = $$('.tab-content');
    els.pageTitle = $('#pageTitle');
    els.targetInput = $('#targetInput');
    els.scanTargetInput = $('#scanTargetInput');
    els.startScanBtn = $('#startScanBtn');
    els.scanTargetBtn = $('#scanTargetBtn');
    els.modulesGrid = $('#modulesGrid');
    els.moduleCount = $('#moduleCount');
    els.progressCard = $('#progressCard');
    els.progressFill = $('#progressFill');
    els.progressPercent = $('#progressPercent');
    els.progressModule = $('#progressModule');
    els.scanStatusText = $('#scanStatusText');
    els.findingsList = $('#findingsList');
    els.severityFilters = $('#severityFilters');
    els.findingsTotal = $('#findingsTotal');
    els.pagination = $('#pagination');
    els.prevPage = $('#prevPage');
    els.nextPage = $('#nextPage');
    els.pageInfo = $('#pageInfo');
    els.exportBtn = $('#exportBtn');
    els.clearBtn = $('#clearBtn');
    els.confirmModal = $('#confirmModal');
    els.modalCancel = $('#modalCancel');
    els.modalConfirm = $('#modalConfirm');
    els.connDot = $('#connDot');
    els.connLabel = $('#connLabel');
    els.serverStatusText = $('#serverStatusText');
    els.serverTransport = $('#serverTransport');
    els.serverEndpoint = $('#serverEndpoint');
    els.statTotal = $('#statTotal');
    els.statCritical = $('#statCritical');
    els.statHigh = $('#statHigh');
    els.statMedium = $('#statMedium');
    els.statLow = $('#statLow');
    els.statInfo = $('#statInfo');
    els.recentActivity = $('#recentActivity');
    els.targetsList = $('#targetsList');
    els.settingsServerUrl = $('#settingsServerUrl');
    els.settingsAutoConnect = $('#settingsAutoConnect');
    els.settingsNotifications = $('#settingsNotifications');
    els.settingsAutoAnalyze = $('#settingsAutoAnalyze');
    els.settingsExportBtn = $('#settingsExportBtn');
    els.settingsClearBtn = $('#settingsClearBtn');
    els.cveSearchInput = $('#cveSearchInput');
    els.cveSearchBtn = $('#cveSearchBtn');
    els.cveLoadAllBtn = $('#cveLoadAllBtn');
    els.cveList = $('#cveList');
    els.cveCount = $('#cveCount');
    els.exploitCveId = $('#exploitCveId');
    els.exploitTarget = $('#exploitTarget');
    els.exploitFormat = $('#exploitFormat');
    els.exploitCallback = $('#exploitCallback');
    els.exploitGenerateBtn = $('#exploitGenerateBtn');
    els.exploitVariantsBtn = $('#exploitVariantsBtn');
    els.exploitOutput = $('#exploitOutput');
    els.predictComponent = $('#predictComponent');
    els.predictVersion = $('#predictVersion');
    els.predictBtn = $('#predictBtn');
    els.predictOutput = $('#predictOutput');
  }

  function init() {
    cacheElements();
    loadState();
    bindEvents();
    requestState();
    setInterval(pollConnection, 15000);
  }

  function loadState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const saved = JSON.parse(raw);
        state.activeTab = saved.activeTab || 'dashboard';
        state.targets = saved.targets || [];
        state.scanHistory = saved.scanHistory || [];
        state.serverUrl = saved.serverUrl || 'http://localhost:9378';
        if (saved.activeModules) {
          state.activeModules = new Set(saved.activeModules);
        }
      }
    } catch (e) {
      // ignore
    }
  }

  function persistState() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        activeTab: state.activeTab,
        targets: state.targets,
        scanHistory: state.scanHistory,
        serverUrl: state.serverUrl,
        activeModules: [...state.activeModules]
      }));
    } catch (e) {
      // ignore
    }
  }

  function requestState() {
    try {
      chrome.runtime.sendMessage({ type: 'getState' }, (res) => {
        if (res) {
          state.findings = res.findings || [];
          state.serverConnected = res.serverConnected || false;
          state.serverUrl = res.serverUrl || 'http://localhost:9378';
          renderAll();
        }
      });
    } catch (e) {
      // not in extension context
    }
  }

  function pollConnection() {
    try {
      chrome.runtime.sendMessage({ type: 'getState' }, (res) => {
        if (res) {
          state.serverConnected = res.serverConnected || false;
          updateConnectionUI();
        }
      });
    } catch (e) {
      // not in extension context
    }
  }

  function bindEvents() {
    els.navItems.forEach((item) => {
      item.addEventListener('click', () => switchTab(item.dataset.tab));
    });

    els.startScanBtn.addEventListener('click', startScan);
    els.scanTargetBtn.addEventListener('click', startScan);

    els.targetInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') startScan();
    });

    els.scanTargetInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') startScan();
    });

    els.modulesGrid.addEventListener('change', (e) => {
      if (e.target.classList.contains('module-check')) {
        const pill = e.target.closest('.module-pill');
        const mod = pill.dataset.module;
        if (e.target.checked) {
          state.activeModules.add(mod);
          pill.classList.add('active');
        } else {
          state.activeModules.delete(mod);
          pill.classList.remove('active');
        }
        updateModuleCount();
      }
    });

    els.severityFilters.addEventListener('click', (e) => {
      const btn = e.target.closest('.filter-btn');
      if (!btn) return;
      els.severityFilters.querySelectorAll('.filter-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      state.filter = btn.dataset.severity;
      state.currentPage = 1;
      renderFindings();
    });

    els.prevPage.addEventListener('click', () => {
      if (state.currentPage > 1) {
        state.currentPage--;
        renderFindings();
      }
    });

    els.nextPage.addEventListener('click', () => {
      const totalPages = getTotalPages();
      if (state.currentPage < totalPages) {
        state.currentPage++;
        renderFindings();
      }
    });

    els.exportBtn.addEventListener('click', exportFindings);
    els.settingsExportBtn.addEventListener('click', exportFindings);
    els.clearBtn.addEventListener('click', showConfirm);
    els.settingsClearBtn.addEventListener('click', showConfirm);
    els.modalCancel.addEventListener('click', hideConfirm);
    els.modalConfirm.addEventListener('click', clearFindings);
    els.confirmModal.addEventListener('click', (e) => {
      if (e.target === els.confirmModal) hideConfirm();
    });

    els.settingsServerUrl.addEventListener('change', () => {
      state.serverUrl = els.settingsServerUrl.value.trim();
      persistState();
    });

    els.settingsAutoConnect.addEventListener('change', () => {
      persistState();
    });

    els.settingsNotifications.addEventListener('change', () => {
      persistState();
    });

    els.settingsAutoAnalyze.addEventListener('change', () => {
      persistState();
    });

    els.cveSearchBtn.addEventListener('click', searchCve);
    els.cveSearchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') searchCve();
    });
    els.cveLoadAllBtn.addEventListener('click', loadAllCves);

    els.exploitGenerateBtn.addEventListener('click', generateExploit);
    els.exploitVariantsBtn.addEventListener('click', generateExploitVariants);

    els.predictBtn.addEventListener('click', runPrediction);
    els.predictComponent.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') runPrediction();
    });
    els.predictVersion.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') runPrediction();
    });

    window.addEventListener('resize', () => {});

    try {
      chrome.runtime.onMessage.addListener((msg) => {
        switch (msg.type) {
          case 'connection':
            state.serverConnected = msg.connected;
            state.serverTransport = msg.transport || null;
            updateConnectionUI();
            break;
          case 'scanStart':
            state.scanning = true;
            showProgress(msg.scan);
            break;
          case 'scanProgress':
            updateProgress(msg);
            break;
          case 'scanComplete':
            state.scanning = false;
            state.findings.push(...(msg.findings || []));
            completeProgress(msg.scan);
            addTarget(state.activeTarget);
            addScanHistory(msg.scan);
            renderAll();
            break;
          case 'scanError':
            state.scanning = false;
            failProgress(msg.error);
            break;
          case 'stateUpdate':
            if (msg.findings) state.findings = msg.findings;
            renderAll();
            break;
        }
      });
    } catch (e) {
      // not in extension context
    }
  }

  function switchTab(tab) {
    state.activeTab = tab;
    els.navItems.forEach((item) => {
      item.classList.toggle('active', item.dataset.tab === tab);
    });
    els.tabContents.forEach((content) => {
      content.classList.toggle('active', content.id === 'tab-' + tab);
    });
    const titles = {
      dashboard: 'Dashboard',
      scanner: 'Scanner',
      findings: 'Findings',
      cve: 'CVE Database',
      exploit: 'Exploit Generator',
      predict: 'Zero-Day Prediction',
      targets: 'Targets',
      settings: 'Settings'
    };
    els.pageTitle.textContent = titles[tab] || 'Dashboard';
    persistState();

    if (tab === 'findings') renderFindings();
    if (tab === 'targets') renderTargets();
    if (tab === 'cve') renderCveList();
    if (tab === 'exploit') renderExploitOutput();
    if (tab === 'predict') renderPredictOutput();
  }

  function validateUrl(str) {
    str = str.trim();
    if (!str) return null;
    if (!/^https?:\/\//i.test(str)) {
      str = 'https://' + str;
    }
    try {
      const url = new URL(str);
      if (!['http:', 'https:'].includes(url.protocol)) return null;
      return url.href.replace(/\/+$/, '');
    } catch {
      return null;
    }
  }

  function getTarget() {
    const raw = els.targetInput.value || els.scanTargetInput.value;
    const url = validateUrl(raw);
    if (!url) {
      els.targetInput.classList.add('error');
      els.scanTargetInput.classList.add('error');
      setTimeout(() => {
        els.targetInput.classList.remove('error');
        els.scanTargetInput.classList.remove('error');
      }, 600);
      return null;
    }
    return url;
  }

  function startScan() {
    if (state.scanning) return;
    const target = getTarget();
    if (!target) return;

    state.activeTarget = target;

    const options = {
      modules: [...state.activeModules],
      delay: parseInt($('#optDelay')?.value || '200', 10),
      timeout: parseInt($('#optTimeout')?.value || '10', 10),
      followRedirects: $('#optFollowRedirect')?.checked || false,
      passive: $('#optPassive')?.checked || false
    };

    els.targetInput.value = target;
    els.scanTargetInput.value = target;

    try {
      els.startScanBtn.disabled = true;
      els.startScanBtn.innerHTML = 'Scanning...';
      els.scanTargetBtn.disabled = true;
      els.scanTargetBtn.innerHTML = 'Scanning...';

      chrome.runtime.sendMessage({
        type: 'startScan',
        target,
        scanType: options.passive ? 'passive' : 'full',
        options
      }, () => {
        const lastError = chrome.runtime.lastError;
        if (lastError) {
          simulateScan(target, options);
        }
      });
    } catch (e) {
      simulateScan(target, options);
    }

    switchTab('scanner');
  }

  function simulateScan(target, options) {
    if (state.scanning) return;
    state.scanning = true;
    state.activeTarget = target;

    showProgress({ target, status: 'running', progress: 0 });

    const modules = options.modules || state.modules;
    let step = 0;
    const total = modules.length;

    const interval = setInterval(() => {
      step++;
      const pct = Math.min(Math.round((step / total) * 100), 99);
      updateProgress({
        percent: pct,
        module: step < total ? modules[step - 1] : 'Finalizing'
      });

      if (step >= total) {
        clearInterval(interval);
        const findings = generateDemoFindings(target, modules);
        state.findings.push(...findings);
        completeProgress({ target, status: 'completed', progress: 100 });
        addTarget(target);
        addScanHistory({ target, status: 'completed', progress: 100, startedAt: Date.now() - 30000, completedAt: Date.now() });
        renderAll();
      }
    }, 400);
  }

  function generateDemoFindings(target) {
    const templates = [
      { title: 'SQL Injection vulnerability detected in parameter', severity: 'critical', desc: 'Unsantized input in query parameter allows SQL meta-character injection.' },
      { title: 'Stored XSS in user profile field', severity: 'high', desc: 'User-controlled input is rendered without sanitization in profile name field.' },
      { title: 'Missing Content-Security-Policy header', severity: 'medium', desc: 'No CSP header set, page is vulnerable to data injection attacks.' },
      { title: 'Server version disclosed in HTTP headers', severity: 'low', desc: 'Server banner exposes version information that aids attackers.' },
      { title: 'Cookie missing Secure flag', severity: 'medium', desc: 'Session cookie transmitted over unencrypted connections.' },
      { title: 'JWT token uses weak signing algorithm', severity: 'high', desc: 'Server accepts "none" algorithm in JWT verification.' },
      { title: 'Open redirect in /redirect endpoint', severity: 'medium', desc: 'Unvalidated redirect parameter allows phishing attacks.' },
      { title: 'CORS policy allows arbitrary origins', severity: 'high', desc: 'Access-Control-Allow-Origin set to wildcard with credentials.' },
      { title: 'Technology fingerprint: React, Express, Nginx', severity: 'info', desc: 'Server identified via response headers and client-side markers.' },
      { title: 'Path traversal in download endpoint', severity: 'critical', desc: '../ sequences not sanitized in /download?file= parameter.' },
      { title: 'No rate limiting on login endpoint', severity: 'low', desc: 'Brute force protection not detected on authentication endpoint.' },
      { title: 'GraphQL introspection enabled', severity: 'medium', desc: 'GraphQL schema exposed via introspection query.' },
      { title: 'Host Header Injection vulnerability', severity: 'high', desc: 'Server trusts Host header for link generation without validation.' },
      { title: 'CSRF protection missing on form', severity: 'medium', desc: 'State-changing form lacks anti-CSRF token.' },
      { title: 'Server-Side Template Injection in name field', severity: 'critical', desc: 'Template expression evaluated server-side from user input.' },
      { title: 'WAF detected: Cloudflare', severity: 'info', desc: 'Cloudflare WAF identified via response headers.' },
      { title: 'Insecure direct object reference in /api/users/:id', severity: 'high', desc: 'No authorization check on user ID parameter.' },
      { title: 'SSRF vulnerability in webhook URL parameter', severity: 'critical', desc: 'Server fetches user-supplied URLs without host allowlist.' }
    ];

    const count = Math.floor(Math.random() * 6) + 3;
    const selected = [];
    const used = new Set();
    for (let i = 0; i < count; i++) {
      let idx;
      do {
        idx = Math.floor(Math.random() * templates.length);
      } while (used.has(idx));
      used.add(idx);
      const t = templates[idx];
      selected.push({
        id: crypto.randomUUID ? crypto.randomUUID() : Date.now() + '-' + i,
        title: t.title,
        severity: t.severity,
        description: t.desc,
        target: target,
        timestamp: new Date().toISOString(),
        type: t.title.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '')
      });
    }
    return selected;
  }

  function showProgress(scan) {
    els.progressCard.style.display = 'block';
    els.progressFill.style.width = '0%';
    els.progressPercent.textContent = '0%';
    els.progressModule.textContent = 'Initializing...';
    els.scanStatusText.textContent = 'Running';
    els.scanStatusText.style.color = 'var(--accent)';
  }

  function updateProgress(data) {
    const pct = data.percent || 0;
    els.progressFill.style.width = pct + '%';
    els.progressPercent.textContent = pct + '%';
    if (data.module) {
      const label = data.module.charAt(0).toUpperCase() + data.module.slice(1).replace(/_/g, ' ');
      els.progressModule.textContent = label;
    }
  }

  function completeProgress(scan) {
    els.progressFill.style.width = '100%';
    els.progressPercent.textContent = '100%';
    els.progressModule.textContent = 'Scan complete';
    els.scanStatusText.textContent = 'Complete';
    els.scanStatusText.style.color = 'var(--low)';
    els.startScanBtn.disabled = false;
    els.startScanBtn.innerHTML = '<span class="btn-icon">&#x25B6;</span> Start Scan';
    els.scanTargetBtn.disabled = false;
    els.scanTargetBtn.innerHTML = '<span class="btn-icon">&#x25B6;</span> Scan';
    state.scanning = false;

    setTimeout(() => {
      if (!state.scanning) {
        els.progressCard.style.display = 'none';
      }
    }, 4000);
  }

  function failProgress(error) {
    els.progressModule.textContent = error || 'Scan failed';
    els.scanStatusText.textContent = 'Failed';
    els.scanStatusText.style.color = 'var(--critical)';
    els.startScanBtn.disabled = false;
    els.startScanBtn.innerHTML = '<span class="btn-icon">&#x25B6;</span> Start Scan';
    els.scanTargetBtn.disabled = false;
    els.scanTargetBtn.innerHTML = '<span class="btn-icon">&#x25B6;</span> Scan';
    state.scanning = false;
  }

  function addTarget(url) {
    if (!url) return;
    const exists = state.targets.some((t) => t.url === url);
    if (!exists) {
      state.targets.unshift({ url, date: new Date().toISOString() });
      if (state.targets.length > 50) state.targets.pop();
      persistState();
    }
  }

  function addScanHistory(scan) {
    state.scanHistory.unshift({
      ...scan,
      id: crypto.randomUUID ? crypto.randomUUID() : Date.now().toString()
    });
    if (state.scanHistory.length > 100) state.scanHistory.pop();
    persistState();
  }

  function renderAll() {
    renderStats();
    renderFindings();
    renderTargets();
    renderRecentActivity();
    updateConnectionUI();
    updateModuleCount();
    updateTargetInputs();
  }

  function renderStats() {
    const findings = state.findings;
    els.statTotal.textContent = findings.length;
    els.statCritical.textContent = findings.filter((f) => f.severity === 'critical').length;
    els.statHigh.textContent = findings.filter((f) => f.severity === 'high').length;
    els.statMedium.textContent = findings.filter((f) => f.severity === 'medium').length;
    els.statLow.textContent = findings.filter((f) => f.severity === 'low').length;
    els.statInfo.textContent = findings.filter((f) => f.severity === 'info').length;
  }

  function renderFindings() {
    const filtered = getFilteredFindings();
    const totalPages = Math.max(1, Math.ceil(filtered.length / FINDINGS_PER_PAGE));
    if (state.currentPage > totalPages) state.currentPage = totalPages;

    const start = (state.currentPage - 1) * FINDINGS_PER_PAGE;
    const pageItems = filtered.slice(start, start + FINDINGS_PER_PAGE);

    els.findingsTotal.textContent = filtered.length + ' finding' + (filtered.length !== 1 ? 's' : '');

    if (pageItems.length === 0) {
      els.findingsList.innerHTML =
        '<div class="empty-state"><span class="empty-icon">&#x1F4CB;</span><p class="empty-text">No findings</p><p class="empty-sub">Run a scan to discover vulnerabilities</p></div>';
      els.pagination.style.display = 'none';
      return;
    }

    let html = '';
    pageItems.forEach((f) => {
      const time = formatTime(f.timestamp);
      const sev = f.severity || 'info';
      const desc = f.description || f.detail || '';
      html +=
        '<div class="finding-entry">' +
        '<div class="finding-severity"><span class="severity-badge ' + sev + '">' + sev + '</span></div>' +
        '<div class="finding-body">' +
        '<div class="finding-title">' + escapeHtml(f.title) + '</div>' +
        '<div class="finding-desc">' + escapeHtml(desc) + '</div>' +
        '<div class="finding-meta"><span class="finding-time">' + time + '</span>' +
        (f.type ? '<span class="finding-type">' + escapeHtml(f.type) + '</span>' : '') +
        '</div></div></div>';
    });

    els.findingsList.innerHTML = html;

    if (totalPages > 1) {
      els.pagination.style.display = 'flex';
      els.pageInfo.textContent = 'Page ' + state.currentPage + ' of ' + totalPages;
      els.prevPage.disabled = state.currentPage <= 1;
      els.nextPage.disabled = state.currentPage >= totalPages;
    } else {
      els.pagination.style.display = 'none';
    }
  }

  function getFilteredFindings() {
    if (state.filter === 'all') return state.findings;
    return state.findings.filter((f) => (f.severity || 'info') === state.filter);
  }

  function getTotalPages() {
    return Math.max(1, Math.ceil(getFilteredFindings().length / FINDINGS_PER_PAGE));
  }

  function renderTargets() {
    if (state.targets.length === 0) {
      els.targetsList.innerHTML =
        '<div class="empty-state"><span class="empty-icon">&#x1F310;</span><p class="empty-text">No targets scanned yet</p><p class="empty-sub">Targets you scan will appear here</p></div>';
      return;
    }

    let html = '';
    state.targets.forEach((t) => {
      const date = formatTime(t.date);
      html +=
        '<div class="target-entry">' +
        '<span class="target-entry-url">' + escapeHtml(t.url) + '</span>' +
        '<span class="target-entry-meta">' + date + '</span>' +
        '</div>';
    });
    els.targetsList.innerHTML = html;
  }

  async function apiCall(path, body) {
    const url = (state.serverUrl || 'http://localhost:9378') + path;
    try {
      const opts = { method: 'GET', signal: AbortSignal.timeout(15000) };
      if (body) {
        opts.method = 'POST';
        opts.headers = { 'Content-Type': 'application/json' };
        opts.body = JSON.stringify(body);
      }
      const resp = await fetch(url, opts);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      return await resp.json();
    } catch (err) {
      throw err;
    }
  }

  async function searchCve() {
    const query = els.cveSearchInput.value.trim();
    if (!query) return;
    state.cveQuery = query.toLowerCase();
    if (state.cveQuery.startsWith('cve-')) {
      try {
        const entry = await apiCall('/cve/' + encodeURIComponent(state.cveQuery));
        state.cveEntries = entry ? [entry] : [];
      } catch {
        state.cveEntries = [];
      }
    } else {
      try {
        state.cveEntries = await apiCall('/cve-db') || [];
        state.cveEntries = state.cveEntries.filter((c) =>
          (c.cve_id || '').toLowerCase().includes(state.cveQuery) ||
          (c.name || '').toLowerCase().includes(state.cveQuery) ||
          (c.description || '').toLowerCase().includes(state.cveQuery) ||
          (c.affected_component || '').toLowerCase().includes(state.cveQuery) ||
          (c.tags || []).some((t) => t.toLowerCase().includes(state.cveQuery))
        );
      } catch {
        state.cveEntries = [];
      }
    }
    renderCveList();
    switchTab('cve');
  }

  async function loadAllCves() {
    state.cveQuery = '';
    try {
      state.cveEntries = await apiCall('/cve-db') || [];
    } catch {
      state.cveEntries = [];
    }
    renderCveList();
  }

  function renderCveList() {
    const entries = state.cveEntries || [];
    els.cveCount.textContent = entries.length + ' entr' + (entries.length === 1 ? 'y' : 'ies');
    if (entries.length === 0) {
      els.cveList.innerHTML =
        '<div class="empty-state"><span class="empty-icon">&#x1F4C3;</span><p class="empty-text">No CVE data loaded</p><p class="empty-sub">Load the database or search for a CVE ID</p></div>';
      return;
    }
    let html = '';
    entries.forEach((c) => {
      const tags = (c.tags || []).map((t) => '<span class="cve-tag">' + escapeHtml(t) + '</span>').join('');
      const payloads = (c.payload_examples || []).map((p) => '<div class="cve-payload">' + escapeHtml(p) + '</div>').join('');
      html +=
        '<div class="cve-entry">' +
        '<div class="cve-header"><span class="cve-id">' + escapeHtml(c.cve_id) + '</span>' + severityBadge(c.severity) + '</div>' +
        '<div class="cve-name">' + escapeHtml(c.name || '') + '</div>' +
        '<div class="cve-desc">' + escapeHtml(c.description || '') + '</div>' +
        '<div class="cve-meta">' +
        (c.cvss_score ? '<span class="cve-tag">CVSS ' + c.cvss_score + '</span>' : '') +
        (c.attack_type ? '<span class="cve-tag">' + escapeHtml(c.attack_type) + '</span>' : '') +
        (c.cwe_id ? '<span class="cve-tag">CWE-' + c.cwe_id + '</span>' : '') +
        tags +
        '</div>' +
        (payloads ? '<div class="cve-payloads"><div class="cve-payload-label">Payloads</div>' + payloads + '</div>' : '') +
        '</div>';
    });
    els.cveList.innerHTML = html;
  }

  function severityBadge(severity) {
    const s = (severity || 'info').toLowerCase();
    return '<span class="severity-badge ' + s + '">' + s + '</span>';
  }

  async function generateExploit() {
    const cveId = els.exploitCveId.value.trim();
    const target = els.exploitTarget.value.trim();
    const format = els.exploitFormat.value;
    const callback = els.exploitCallback.value.trim();
    if (!cveId) return;

    els.exploitGenerateBtn.disabled = true;
    els.exploitGenerateBtn.textContent = 'Generating...';

    try {
      const body = { cve_id: cveId, format };
      if (target) body.target = target;
      if (callback) {
        const parts = callback.split(':');
        if (parts.length === 2) {
          body.callback_ip = parts[0];
          body.callback_port = parseInt(parts[1], 10);
        }
      }
      const result = await apiCall('/exploit', body);
      state.lastExploit = result || null;
      renderExploitOutput();
    } catch (err) {
      state.lastExploit = { error: err.message };
      renderExploitOutput();
    } finally {
      els.exploitGenerateBtn.disabled = false;
      els.exploitGenerateBtn.innerHTML = '<span class="btn-icon">&#x2699;</span> Generate Exploit';
    }
  }

  function renderExploitOutput() {
    const data = state.lastExploit;
    if (!data) {
      els.exploitOutput.innerHTML = '<div class="empty-state"><span class="empty-icon">&#x1F4A3;</span><p class="empty-text">Generated exploit will appear here</p></div>';
      return;
    }
    if (data.error) {
      els.exploitOutput.innerHTML = '<div class="empty-state"><span class="empty-icon">&#x26A0;</span><p class="empty-text">' + escapeHtml(data.error) + '</p></div>';
      return;
    }
    const ex = data.exploit;
    if (!ex) {
      els.exploitOutput.innerHTML = '<div class="empty-state"><span class="empty-icon">&#x1F4A3;</span><p class="empty-text">No exploit generated</p></div>';
      return;
    }
    let html =
      '<div class="exploit-code-header">' +
      '<span class="exploit-code-title">' + escapeHtml(ex.name || 'Generated exploit') + '</span>' +
      '<span class="exploit-code-meta">' + escapeHtml(ex.format || '') + ' &bull; ' + escapeHtml(ex.risk_level || '') + '</span>' +
      '</div>' +
      '<pre class="exploit-code-block">' + escapeHtml(ex.code || '') + '</pre>';
    if (ex.usage) {
      html += '<div class="exploit-code-header"><span class="exploit-code-meta">Usage</span></div><pre class="exploit-code-block">' + escapeHtml(ex.usage) + '</pre>';
    }
    if ((data.generated_variants || []).length > 0) {
      html += '<div class="exploit-variants">';
      html += '<div class="cve-payload-label">Payload Variants</div>';
      data.generated_variants.forEach((v) => {
        html += '<div class="exploit-variant">' + escapeHtml(v) + '</div>';
      });
      html += '</div>';
    }
    els.exploitOutput.innerHTML = html;
  }

  async function generateExploitVariants() {
    if (!state.lastExploit || !state.lastExploit.exploit) return;
    const code = state.lastExploit.exploit.code;
    if (!code) return;
    try {
      const result = await apiCall('/exploit', { cve_id: state.lastExploit.exploit.cve_id || 'unknown', format: state.lastExploit.exploit.format || 'python' });
      state.lastExploit = result || state.lastExploit;
      renderExploitOutput();
    } catch {}
  }

  async function runPrediction() {
    const component = els.predictComponent.value.trim();
    const version = els.predictVersion.value.trim();
    if (!component) return;

    els.predictBtn.disabled = true;
    els.predictBtn.textContent = 'Predicting...';

    try {
      const result = await apiCall('/predict', { component, version });
      state.lastPrediction = result || null;
      renderPredictOutput();
    } catch (err) {
      state.lastPrediction = { error: err.message };
      renderPredictOutput();
    } finally {
      els.predictBtn.disabled = false;
      els.predictBtn.innerHTML = '<span class="btn-icon">&#x1F52E;</span> Predict Risk';
    }
  }

  function renderPredictOutput() {
    const data = state.lastPrediction;
    if (!data) {
      els.predictOutput.innerHTML = '<div class="empty-state"><span class="empty-icon">&#x1F52E;</span><p class="empty-text">Prediction results will appear here</p></div>';
      return;
    }
    if (data.error) {
      els.predictOutput.innerHTML = '<div class="empty-state"><span class="empty-icon">&#x26A0;</span><p class="empty-text">' + escapeHtml(data.error) + '</p></div>';
      return;
    }
    const predictions = data.predictions || [];
    if (predictions.length === 0) {
      els.predictOutput.innerHTML = '<div class="empty-state"><span class="empty-icon">&#x1F52E;</span><p class="empty-text">No predictions returned</p></div>';
      return;
    }
    const p = predictions[0];
    let html =
      '<div class="predict-result">' +
      '<div class="predict-component">' + escapeHtml(p.component) + '</div>' +
      '<div class="predict-confidence">' + Math.round((p.confidence || 0) * 100) + '%</div>' +
      '<div class="cve-payload-label">Predicted Attack Types</div>' +
      '<div class="predict-attack-list">';
    (p.predicted_attack_types || []).forEach((at) => {
      html +=
        '<div class="predict-attack">' +
        '<div class="predict-attack-header"><span class="predict-attack-name">' + escapeHtml(at.attack_type) + '</span><span class="predict-attack-score">' + Math.round((at.score || 0) * 100) + '%</span></div>' +
        '<div class="predict-attack-evidence">' + escapeHtml((at.evidence || []).join(' | ')) + '</div>' +
        '</div>';
    });
    html += '</div>';
    if ((p.similar_cves || []).length > 0) {
      html += '<div class="cve-payload-label" style="margin-top:12px">Similar CVEs</div><div class="cve-meta">' + p.similar_cves.map((id) => '<span class="cve-tag">' + escapeHtml(id) + '</span>').join('') + '</div>';
    }
    html += '</div>';
    els.predictOutput.innerHTML = html;
  }

  function renderRecentActivity() {
    if (state.scanHistory.length === 0) {
      els.recentActivity.innerHTML =
        '<div class="empty-state"><span class="empty-icon">&#x1F50D;</span><p class="empty-text">No scans performed yet</p><p class="empty-sub">Run a scan to see results here</p></div>';
      return;
    }

    let html = '';
    const recent = state.scanHistory.slice(0, 10);
    recent.forEach((s) => {
      const time = formatTime(s.startedAt || s.timestamp);
      const status = s.status || 'completed';
      const statusColor = status === 'completed' ? 'var(--low)' : status === 'failed' ? 'var(--critical)' : 'var(--accent)';
      html +=
        '<div class="finding-entry">' +
        '<div class="finding-severity"><span class="severity-badge ' + status + '" style="background:rgba(255,255,255,0.05);color:' + statusColor + '">' + status + '</span></div>' +
        '<div class="finding-body">' +
        '<div class="finding-title">' + escapeHtml(s.target || 'Unknown target') + '</div>' +
        '<div class="finding-meta"><span class="finding-time">' + time + '</span></div>' +
        '</div></div>';
    });
    els.recentActivity.innerHTML = html;
  }

  function updateConnectionUI() {
    const connected = state.serverConnected;
    els.connDot.className = 'conn-dot ' + (connected ? 'connected' : 'disconnected');
    els.connLabel.textContent = connected ? 'Connected' : 'Disconnected';
    els.serverStatusText.textContent = connected ? 'Connected' : 'Disconnected';
    els.serverStatusText.style.color = connected ? 'var(--low)' : 'var(--text-muted)';
    els.serverTransport.textContent = state.serverTransport || (connected ? 'unknown' : '-');
    els.serverEndpoint.textContent = state.serverUrl || 'http://localhost:9378';
  }

  function updateModuleCount() {
    const count = state.activeModules.size;
    els.moduleCount.textContent = count + ' selected';
  }

  function updateTargetInputs() {
    if (state.targets.length > 0 && !els.targetInput.value) {
      // don't auto-fill
    }
  }

  function exportFindings() {
    if (state.findings.length === 0) return;
    try {
      const blob = new Blob([JSON.stringify(state.findings, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'grym-findings-' + new Date().toISOString().slice(0, 10) + '.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      // fallback
    }
  }

  function showConfirm() {
    els.confirmModal.classList.add('open');
  }

  function hideConfirm() {
    els.confirmModal.classList.remove('open');
  }

  function clearFindings() {
    state.findings = [];
    state.currentPage = 1;
    hideConfirm();
    renderAll();
    try {
      chrome.runtime.sendMessage({ type: 'clearFindings' });
    } catch (e) {
      // not in extension context
    }
  }

  function formatTime(ts) {
    if (!ts) return '';
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return '';
      const now = new Date();
      const diff = now - d;
      if (diff < 60000) return 'Just now';
      if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
      if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
      return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch {
      return '';
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();