(function() {
  'use strict';

  const TECH_PATTERNS = [
    { name: 'React', regex: /react(?:\.development)?\.js|_reactRootContainer|__REACT_DEVTOOLS_GLOBAL_HOOK__|data-reactroot/i },
    { name: 'Vue.js', regex: /vue(?:\.development)?\.js|__VUE_DEVTOOLS_GLOBAL_HOOK__|data-v-[a-f0-9]+|v-[a-z-]+=["']/i },
    { name: 'Angular', regex: /angular(?:\.core)?\.js|ng-app|ng-version|ng-binding|[_]ng[Ee][vV][Ee][nN][tT]/i },
    { name: 'Svelte', regex: /svelte(?:\.development)?\.js|__svelte|svelte-hmr/i },
    { name: 'Next.js', regex: /next\.js|__NEXT_DATA__|__next|_next\/static/i },
    { name: 'Nuxt.js', regex: /nuxt\.js|__NUXT__|_nuxt/i },
    { name: 'jQuery', regex: /jquery(?:\.min)?\.js|jQuery|jQuery\.fn/i },
    { name: 'Bootstrap', regex: /bootstrap(?:\.min)?\.(?:js|css)|data-bs-|bs\.|bootstrap\./i },
    { name: 'Tailwind CSS', regex: /tailwindcss|\.tw-|bg-gray-|text-white|class=".* (?:sm|md|lg|xl):/i },
    { name: 'Django', regex: /django|csrfmiddlewaretoken|__admin_header|__admin/i },
    { name: 'Laravel', regex: /laravel|LARAVEL|livewire|csrf-token.*=.*[a-zA-Z0-9]{40}/i },
    { name: 'Ruby on Rails', regex: /rails|csrf-token.*=.*[a-zA-Z0-9]{32}|authenticity_token|data-remote="?true"?/i },
    { name: 'ASP.NET', regex: /__VIEWSTATE|__EVENTVALIDATION|ASP\.NET_SessionId|\.aspx|\.ashx/i },
    { name: 'Spring Boot', regex: /spring|actuator|X-Application-Context/i },
    { name: 'WordPress', regex: /wp-content|wp-admin|wp-includes|wordpress\.js|wp-json/i },
    { name: 'Drupal', regex: /drupal\.js|Drupal\.|sites\/default\/files|drupalSettings/i },
    { name: 'Joomla', regex: /joomla|com_content|com_users|\/media\/jui/i },
    { name: 'GraphQL', regex: /graphql|__typename|__schema|"data"|"query"|"mutation"/i },
    { name: 'REST API', regex: /application\/json|api\/v[0-9]|\/api\/|swagger|openapi/i },
    { name: 'WebSocket', regex: /new WebSocket|ws:\/\/|wss:\/\//i },
    { name: 'Google Analytics', regex: /googletagmanager\.com|ga\s*\(|gtag\s*\(|analytics\.js|ga\.js/i },
    { name: 'Cloudflare', regex: /__cfduid|cf-ray|cf-request-id|cloudflare-nginx/i },
    { name: 'Nginx', regex: /nginx|server: nginx/i },
    { name: 'Apache', regex: /apache|server: apache/i },
    { name: 'Express', regex: /express|x-powered-by: express/i },
    { name: 'Socket.IO', regex: /socket\.io|io\.connect|io\(/i },
    { name: 'Alpine.js', regex: /alpine\.js|x-data|x-bind|x-on|x-show|x-text|x-init|x-ref/i },
    { name: 'HTMX', regex: /htmx\.js|hx-get|hx-post|hx-put|hx-delete|hx-trigger|hx-target|hx-swap/i },
    { name: 'Remix', regex: /remix|_remix|@remix-run/i },
    { name: 'Astro', regex: /astro(?:\.island)?\.|__ASTRO|_astro\//i },
    { name: 'Gatsby', regex: /gatsby|___gatsby|gatsby-\w+/i },
    { name: 'Vite', regex: /vite|__vite|\\\/@vite/i },
    { name: 'Webpack', regex: /webpack|__webpack_require__|webpackJsonp/i },
    { name: 'Shopify', regex: /shopify|cdn\.shopify\.com|Shopify\.theme/i },
    { name: 'Magento', regex: /magento|mage-|mage\.cookies|MAGE_VERSION/i },
    { name: 'ColdFusion', regex: /_cf_|cfml|coldfusion|CFIDE/i },
    { name: 'Salesforce', regex: /salesforce|salesforce\.com|lightning|aura/i },
    { name: 'SharePoint', regex: /sharepoint|_layouts|spfx|Microsoft.SharePoint/i },
    { name: 'Axios', regex: /axios(?:\.min)?\.js|axios\.defaults|from 'axios'/i },
    { name: 'Lodash', regex: /lodash(?:\.min)?\.js|_.\w{2,}.*_\.VERSION|lodash\.js/i },
    { name: 'Moment.js', regex: /moment(?:\.min)?\.js|moment\.fn/i },
    { name: 'GSAP', regex: /gsap(?:\.min)?\.js|gsap\.to\(|TweenMax|TimelineMax/i },
    { name: 'Chart.js', regex: /chart(?:\.min)?\.js|Chart\.defaults|new Chart/i },
    { name: 'ApexCharts', regex: /apexcharts|ApexCharts/i },
    { name: 'Leaflet', regex: /leaflet(?:\.min)?\.js|L\.map\(/i },
    { name: 'Google Tag Manager', regex: /googletagmanager\.com\/gtm\.js|dataLayer/i },
    { name: 'Meta Pixel', regex: /connect\.facebook\.net\/en_US\/fbevents|fbq\(/i },
    { name: 'Hotjar', regex: /static\.hotjar\.com|hj\(|_hjSettings/i },
    { name: 'Segment', regex: /cdn\.segment\.com|analytics\.load\(/i },
    { name: 'Stripe', regex: /js\.stripe\.com|Stripe\.js|stripe\.com\/v3/i },
    { name: 'reCAPTCHA', regex: /recaptcha\/api\.js|grecaptcha|recaptcha\.net/i },
    { name: 'hCaptcha', regex: /hcaptcha\.com|hcaptcha\.js/i }
  ];

  const SECRET_PATTERNS = [
    { type: 'AWS Key', regex: /(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}/g },
    { type: 'AWS Secret', regex: /aws[_\-\.]?(?:secret|access)[_\-\.]?key['"]?\s*[:=]\s*['"][A-Za-z0-9\/+=]{40}['"]/gi },
    { type: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9]{36,252}|github[_\-\.]?token['"]?\s*[:=]\s*['"][A-Za-z0-9]+['"]/g },
    { type: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g },
    { type: 'JWT Token', regex: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g },
    { type: 'Slack Token', regex: /xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]{10,14}/g },
    { type: 'Generic Secret', regex: /(?:secret|token|password|api[_-]?key)['"]?\s*[:=]\s*['"][A-Za-z0-9_\-\.]{16,64}['"]/gi }
  ];

  const FORM_ANALYSIS_PATTERNS = [
    { type: 'login', fields: ['username', 'password', 'email', 'login', 'signin'] },
    { type: 'registration', fields: ['password', 'password_confirm', 'email', 'signup', 'register'] },
    { type: 'password_reset', fields: ['email', 'reset', 'forgot'] },
    { type: 'search', fields: ['q', 'query', 'search', 's'] },
    { type: 'contact', fields: ['message', 'name', 'email', 'subject'] },
    { type: 'payment', fields: ['card', 'cvv', 'expiry', 'cc_number', 'billing'] }
  ];

  let analysisCache = null;

  function detectTechnologies() {
    const html = document.documentElement.innerHTML;
    const headers = getHeaderInfo();
    const techs = [];

    for (const pattern of TECH_PATTERNS) {
      if (pattern.regex.test(html)) {
        techs.push(pattern.name);
      }
    }

    if (headers.server) techs.push(`Server: ${headers.server}`);
    if (headers.xPoweredBy) techs.push(`Powered by: ${headers.xPoweredBy}`);

    return [...new Set(techs)];
  }

  function getHeaderInfo() {
    const meta = document.querySelectorAll('meta');
    const headers = {};
    meta.forEach(m => {
      const name = m.getAttribute('name') || m.getAttribute('http-equiv');
      const content = m.getAttribute('content');
      if (name && content) headers[name.toLowerCase()] = content;
    });
    return headers;
  }

  function findSecrets() {
    const html = document.documentElement.innerHTML;
    const scripts = document.querySelectorAll('script:not([src])');
    let allJs = '';
    scripts.forEach(s => { allJs += s.textContent + '\n'; });
    const combined = html + '\n' + allJs;

    const found = [];
    for (const pattern of SECRET_PATTERNS) {
      const matches = combined.matchAll(pattern.regex);
      for (const match of matches) {
        found.push({
          type: pattern.type,
          value: match[0].substring(0, 40) + (match[0].length > 40 ? '...' : ''),
          location: getContextAround(match.index, combined, 60)
        });
      }
    }

    const unique = [];
    const seen = new Set();
    for (const f of found) {
      if (!seen.has(f.type + f.value)) {
        seen.add(f.type + f.value);
        unique.push(f);
      }
    }
    return unique.slice(0, 50);
  }

  function getContextAround(index, text, radius) {
    const start = Math.max(0, index - radius);
    const end = Math.min(text.length, index + radius);
    return text.substring(start, end).replace(/\s+/g, ' ').trim();
  }

  function analyzeForms() {
    const forms = document.querySelectorAll('form');
    const results = [];

    forms.forEach((form, idx) => {
      const action = form.getAttribute('action') || '(self)';
      const method = (form.getAttribute('method') || 'get').toUpperCase();
      const inputs = form.querySelectorAll('input, select, textarea');
      const formFields = [];

      inputs.forEach(input => {
        const type = input.getAttribute('type') || 'text';
        const name = input.getAttribute('name');
        const value = input.getAttribute('value') || '';
        if (name) formFields.push({ type, name, hasValue: !!value });
      });

      const csrfInputs = formFields.filter(f =>
        f.name.toLowerCase().includes('csrf') ||
        f.name.toLowerCase().includes('token') ||
        f.name.toLowerCase().includes('nonce') ||
        f.name.toLowerCase().includes('authenticity')
      );

      const formType = FORM_ANALYSIS_PATTERNS.find(pt =>
        formFields.some(f => pt.fields.includes(f.name.toLowerCase()))
      );

      const isOverHttp = window.location.protocol === 'http:';
      const isOverExternal = action && !action.startsWith('#') && !action.startsWith('/') && !action.includes(window.location.host);

      results.push({
        index: idx,
        action,
        method,
        fieldCount: formFields.length,
        hasCsrfProtection: csrfInputs.length > 0,
        csrfInputs: csrfInputs.map(c => c.name),
        type: formType?.type || 'generic',
        insecureAction: isOverHttp ? 'http' : null,
        externalAction: isOverExternal ? action : null,
        fields: formFields.slice(0, 20)
      });
    });

    return results;
  }

  function analyzeEndpoints() {
    const html = document.documentElement.innerHTML;
    const endpoints = new Set();

    const apiPatterns = [
      /["'](?:https?:\/\/[^"']*\/api\/[^"']*)["']/g,
      /["'](?:\/[a-zA-Z0-9_-]+\/api\/[^"']*)["']/g,
      /["']\/v[0-9]+\/[a-zA-Z0-9_\/-]+["']/g,
      /["']\/graphql["']/g,
      /["']\/rest\/[^"']+["']/g,
    ];

    for (const pattern of apiPatterns) {
      const matches = html.matchAll(pattern);
      for (const m of matches) {
        endpoints.add(m[0].replace(/["']/g, ''));
      }
    }

    const linkEndpoints = new Set();
    document.querySelectorAll('a[href]').forEach(a => {
      const href = a.getAttribute('href');
      if (href && !href.startsWith('#') && !href.startsWith('javascript:') && !href.startsWith('mailto:')) {
        try {
          const url = new URL(href, window.location.origin);
          if (url.pathname.length > 3) linkEndpoints.add(url.pathname);
        } catch {}
      }
    });

    return {
      apiEndpoints: [...endpoints].slice(0, 50),
      paths: [...linkEndpoints].slice(0, 100),
      pageLinks: document.querySelectorAll('a').length
    };
  }

  function checkSecurityHeaders() {
    const meta = document.querySelectorAll('meta[http-equiv]');
    const findings = [];

    meta.forEach(m => {
      const equiv = m.getAttribute('http-equiv').toLowerCase();
      const content = m.getAttribute('content');
      if (equiv === 'content-security-policy') findings.push({ header: 'CSP', value: content });
      if (equiv === 'x-frame-options') findings.push({ header: 'X-Frame-Options', value: content });
      if (equiv === 'strict-transport-security') findings.push({ header: 'HSTS', value: content });
    });

    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    const xfoMeta = document.querySelector('meta[http-equiv="X-Frame-Options"]');

    return {
      hasCSP: !!cspMeta,
      hasXFO: !!xfoMeta,
      cspValue: cspMeta?.getAttribute('content') || null,
      xfoValue: xfoMeta?.getAttribute('content') || null,
      findings
    };
  }

  function findUnsafeLinks() {
    const unsafe = [];
    document.querySelectorAll('a[target="_blank"]').forEach(a => {
      const rel = (a.getAttribute('rel') || '').toLowerCase();
      const href = a.getAttribute('href');
      if (!rel.split(/\s+/).includes('noopener') && href && !href.startsWith('#')) {
        unsafe.push({
          href: href.length > 120 ? href.slice(0, 120) + '…' : href,
          missingRel: rel.trim() === '' ? 'no rel attribute' : `rel="${rel}"`
        });
      }
    });
    return unsafe.slice(0, 20);
  }

  window.__grymScan = function(scanType, options) {
    const findings = [];
    const pageAnalysis = fullAnalyze();

    switch (scanType) {
      case 'passive':
        findings.push({
          type: 'tech_detection',
          severity: 'info',
          title: `${pageAnalysis.technologies.length} technologies detected`,
          detail: pageAnalysis.technologies.join(', ')
        });
        findings.push({
          type: 'security_headers',
          severity: pageAnalysis.security.hasCSP ? 'info' : 'medium',
          title: pageAnalysis.security.hasCSP ? 'CSP header present' : 'No CSP header detected',
          detail: pageAnalysis.security.cspValue || 'Missing Content-Security-Policy'
        });
        break;

      case 'secret_scan':
        pageAnalysis.secrets.forEach(s => {
          findings.push({
            type: 'secret',
            severity: 'high',
            title: `Potential ${s.type} exposed`,
            detail: s.value,
            location: s.location
          });
        });
        break;

      case 'form_analysis':
        pageAnalysis.forms.forEach(f => {
          if (!f.hasCsrfProtection) {
            findings.push({
              type: 'missing_csrf',
              severity: 'medium',
              title: `Form #${f.index} (${f.type}) lacks CSRF protection`,
              detail: `Action: ${f.action}, Method: ${f.method}, ${f.fieldCount} fields`
            });
          }
          if (f.insecureAction) {
            findings.push({
              type: 'insecure_form',
              severity: 'high',
              title: `Form #${f.index} submits over HTTP`,
              detail: f.action
            });
          }
        });
        break;

      case 'endpoint_discovery':
        findings.push({
          type: 'endpoints',
          severity: 'info',
          title: `${pageAnalysis.endpoints.apiEndpoints.length} API endpoints found`,
          detail: pageAnalysis.endpoints.apiEndpoints.join('\n')
        });
        break;

      case 'full':
        pageAnalysis.secrets.forEach(s => {
          findings.push({ type: 'secret', severity: 'high', title: `Potential ${s.type} exposed`, detail: s.value });
        });
        pageAnalysis.forms.forEach(f => {
          if (!f.hasCsrfProtection) {
            findings.push({ type: 'missing_csrf', severity: 'medium', title: `Form lacks CSRF`, detail: f.action });
          }
        });
        pageAnalysis.unsafeLinks.forEach(l => {
          findings.push({
            type: 'unsafe_link',
            severity: 'low',
            title: 'target=_blank without rel=noopener',
            detail: `${l.href} (${l.missingRel})`
          });
        });
        findings.push({
          type: 'summary',
          severity: 'info',
          title: `Page analysis complete`,
          detail: `Technologies: ${pageAnalysis.technologies.length} | Secrets: ${pageAnalysis.secrets.length} | Forms: ${pageAnalysis.forms.length}`
        });
        break;
    }

    return { findings };
  };

  window.__grymQuickAnalyze = function() {
    const result = fullAnalyze();
    chrome.runtime.sendMessage({
      type: 'quickAnalysis',
      data: result
    }).catch(() => {});
    return result;
  };

  function fullAnalyze() {
    if (analysisCache) return analysisCache;

    const result = {
      url: window.location.href,
      hostname: window.location.hostname,
      title: document.title,
      technologies: detectTechnologies(),
      secrets: findSecrets(),
      forms: analyzeForms(),
      endpoints: analyzeEndpoints(),
      security: checkSecurityHeaders(),
      unsafeLinks: findUnsafeLinks(),
      cookies: document.cookie.split(';').map(c => c.trim()).filter(Boolean),
      scripts: document.scripts.length,
      links: document.querySelectorAll('a').length,
      images: document.images.length,
      pageSize: document.documentElement.innerHTML.length,
      analyzedAt: Date.now()
    };

    analysisCache = result;
    return result;
  }

  const originalPushState = history.pushState;
  history.pushState = function() {
    analysisCache = null;
    return originalPushState.apply(this, arguments);
  };
  window.addEventListener('popstate', () => { analysisCache = null; });
  window.addEventListener('hashchange', () => { analysisCache = null; });

  setTimeout(() => {
    try {
      chrome.runtime.sendMessage({
        type: 'pageData',
        data: fullAnalyze()
      }).catch(() => {});
    } catch {}
  }, 1500);

  try {
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (typeof message !== 'object' || message === null) return;
      const scanType = message.type || message.scanType;
      if (typeof scanType === 'string' && scanType.length > 0 && scanType.length < 40) {
        const result = window.__grymScan(scanType, message.options || {});
        sendResponse(result);
        return true;
      }
      if (message.type === 'quickAnalyze') {
        const result = window.__grymQuickAnalyze();
        sendResponse(result);
        return true;
      }
    });
  } catch {}
})();
