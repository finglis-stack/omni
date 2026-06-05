/**
 * OmniScan — Real-Time Cybersecurity Dashboard
 * Vanilla JS Single-Page Application
 * Connects to ws://localhost:8888/ws for live scan data.
 */

/* ═══════════════════════════════════════════════════════════════════
   0.  LIGHTWEIGHT MARKDOWN PARSER
   ═══════════════════════════════════════════════════════════════════ */

function parseMarkdown(text) {
    if (!text) return '';

    // Normalize line endings
    let src = text.replace(/\r\n/g, '\n');

    // ── Tables ──────────────────────────────────────────────────
    src = src.replace(
        /(?:^|\n)((?:\|.+\|\n)+)/g,
        (_, block) => {
            const rows = block.trim().split('\n');
            if (rows.length < 2) return block;

            // Check if second row is a separator row
            const sepTest = rows[1].replace(/\s/g, '');
            const isSep = /^\|?[-:|]+(\|[-:|]+)+\|?$/.test(sepTest);
            const dataRows = isSep ? [rows[0], ...rows.slice(2)] : rows;

            let html = '<table>';
            dataRows.forEach((row, i) => {
                const cells = row.split('|').filter((c, idx, arr) => idx !== 0 && idx !== arr.length - 0 ? true : c.trim() !== '');
                // Cleaner: split by | and trim empties at edges
                const cleaned = row.replace(/^\||\|$/g, '').split('|').map(c => c.trim());
                const tag = (i === 0 && isSep) ? 'th' : 'td';
                html += '<tr>' + cleaned.map(c => `<${tag}>${c}</${tag}>`).join('') + '</tr>';
            });
            html += '</table>';
            return '\n' + html + '\n';
        }
    );

    // ── Code blocks (fenced) ────────────────────────────────────
    src = src.replace(/```[\s\S]*?```/g, match => {
        const inner = match.replace(/^```\w*\n?/, '').replace(/\n?```$/, '');
        return `<pre><code>${inner.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></pre>`;
    });

    // ── Headings ────────────────────────────────────────────────
    src = src.replace(/^######\s+(.+)$/gm, '<h6>$1</h6>');
    src = src.replace(/^#####\s+(.+)$/gm, '<h5>$1</h5>');
    src = src.replace(/^####\s+(.+)$/gm,  '<h4>$1</h4>');
    src = src.replace(/^###\s+(.+)$/gm,   '<h3>$1</h3>');
    src = src.replace(/^##\s+(.+)$/gm,    '<h2>$1</h2>');
    src = src.replace(/^#\s+(.+)$/gm,     '<h1>$1</h1>');

    // ── Horizontal rules ────────────────────────────────────────
    src = src.replace(/^---$/gm, '<hr>');

    // ── Unordered lists ─────────────────────────────────────────
    src = src.replace(
        /(?:^|\n)((?:[-*+]\s+.+\n?)+)/g,
        (_, block) => {
            const items = block.trim().split('\n')
                .map(l => l.replace(/^[-*+]\s+/, '').trim())
                .filter(Boolean)
                .map(l => `<li>${l}</li>`)
                .join('');
            return `\n<ul>${items}</ul>\n`;
        }
    );

    // ── Ordered lists ───────────────────────────────────────────
    src = src.replace(
        /(?:^|\n)((?:\d+\.\s+.+\n?)+)/g,
        (_, block) => {
            const items = block.trim().split('\n')
                .map(l => l.replace(/^\d+\.\s+/, '').trim())
                .filter(Boolean)
                .map(l => `<li>${l}</li>`)
                .join('');
            return `\n<ol>${items}</ol>\n`;
        }
    );

    // ── Inline: bold, italic, inline code ───────────────────────
    src = src.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    src = src.replace(/\*(.+?)\*/g,     '<em>$1</em>');
    src = src.replace(/`([^`]+)`/g,     '<code>$1</code>');

    // ── Links ───────────────────────────────────────────────────
    src = src.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');

    // ── Paragraphs (double newline) ─────────────────────────────
    src = src.replace(/\n{2,}/g, '</p><p>');
    src = '<p>' + src + '</p>';

    // Clean up empty paragraphs and paragraphs wrapping block elements
    src = src.replace(/<p>\s*<\/p>/g, '');
    src = src.replace(/<p>\s*(<(?:h[1-6]|ul|ol|table|pre|hr|blockquote))/g, '$1');
    src = src.replace(/(<\/(?:h[1-6]|ul|ol|table|pre|hr|blockquote)>)\s*<\/p>/g, '$1');

    return src;
}


/* ═══════════════════════════════════════════════════════════════════
   1.  GLOBAL STATE
   ═══════════════════════════════════════════════════════════════════ */

const STATE = {
    ws: null,
    reconnectAttempt: 0,
    maxReconnect: 20,
    reconnectDelay: 1000,
    status: 'idle',         // idle | running | complete | error
    target: '',
    findings: [],           // array of finding objects
    results: {},
    severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    phaseCount: 7,
    currentPhase: 0,
    aiData: null,
    d3Loaded: false,
    attackGraphSim: null,
};

// Severity ordering & color map
const SEVERITY = {
    critical: { order: 0, color: '#ff1744', bg: 'rgba(255,23,68,.15)',  label: 'CRITICAL' },
    high:     { order: 1, color: '#ff6d00', bg: 'rgba(255,109,0,.15)', label: 'HIGH'     },
    medium:   { order: 2, color: '#ffc400', bg: 'rgba(255,196,0,.15)', label: 'MEDIUM'   },
    low:      { order: 3, color: '#00e676', bg: 'rgba(0,230,118,.15)', label: 'LOW'      },
    info:     { order: 4, color: '#40c4ff', bg: 'rgba(64,196,255,.15)', label: 'INFO'    },
};

const PHASE_NAMES = [
    'Recon',
    'Enumeration',
    'Vulnerability Scan',
    'Exploitation',
    'Auto-Exploit',
    'Proof Generation',
    'Report',
];


/* ═══════════════════════════════════════════════════════════════════
   2.  WEBSOCKET MANAGER
   ═══════════════════════════════════════════════════════════════════ */

function wsConnect() {
    if (STATE.ws && (STATE.ws.readyState === WebSocket.OPEN || STATE.ws.readyState === WebSocket.CONNECTING)) return;

    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${location.host}/ws`;
    STATE.ws = new WebSocket(url);

    STATE.ws.onopen = () => {
        STATE.reconnectAttempt = 0;
        updateConnectionBadge(true);
        showToast('Connected to OmniScan server', 'success');
    };

    STATE.ws.onclose = () => {
        updateConnectionBadge(false);
        scheduleReconnect();
    };

    STATE.ws.onerror = () => {
        STATE.ws.close();
    };

    STATE.ws.onmessage = (evt) => {
        let msg;
        try { msg = JSON.parse(evt.data); } catch { return; }
        routeMessage(msg);
    };
}

function scheduleReconnect() {
    if (STATE.reconnectAttempt >= STATE.maxReconnect) {
        showToast('Unable to reconnect – please refresh', 'error');
        return;
    }
    const delay = Math.min(STATE.reconnectDelay * Math.pow(1.5, STATE.reconnectAttempt), 30000);
    STATE.reconnectAttempt++;
    setTimeout(wsConnect, delay);
}

function wsSend(obj) {
    if (STATE.ws && STATE.ws.readyState === WebSocket.OPEN) {
        STATE.ws.send(JSON.stringify(obj));
    } else {
        showToast('Not connected to server', 'error');
    }
}

function updateConnectionBadge(connected) {
    const dot = document.getElementById('connection-dot');
    const label = document.getElementById('connection-label');
    if (dot) {
        dot.className = 'connection-dot ' + (connected ? 'connected' : 'disconnected');
    }
    if (label) {
        label.textContent = connected ? 'Connected' : 'Disconnected';
    }
}


/* ═══════════════════════════════════════════════════════════════════
   3.  MESSAGE ROUTER
   ═══════════════════════════════════════════════════════════════════ */

function routeMessage(msg) {
    switch (msg.type) {
        case 'state':
            handleState(msg);
            break;
        case 'scan_started':
            handleScanStarted(msg.data);
            break;
        case 'scan_complete':
            handleScanComplete(msg.data);
            break;
        case 'finding':
            handleFinding(msg.data);
            break;
        case 'phase':
            handlePhase(msg.data);
            break;
        case 'ai_started':
            handleAIStarted();
            break;
        case 'ai_complete':
            handleAIComplete(msg.data);
            break;
        case 'error':
        case 'scan_error':
        case 'ai_error':
            handleError(msg.data);
            break;
        default:
            break;
    }
}


/* ═══════════════════════════════════════════════════════════════════
   4.  STATE HANDLER
   ═══════════════════════════════════════════════════════════════════ */

function handleState(msg) {
    STATE.status = msg.status || 'idle';
    STATE.target = msg.target || '';
    STATE.results = msg.results || {};

    updateStatus(STATE.status);

    // Replay past events
    if (Array.isArray(msg.events)) {
        msg.events.forEach(evt => {
            if (evt.type === 'finding') handleFinding(evt.data);
            if (evt.type === 'phase')   handlePhase(evt.data);
            if (evt.type === 'ai_complete') handleAIComplete(evt.data);
        });
    }

    // If scan is complete and we have results, build attack graph
    if (STATE.status === 'complete' && Object.keys(STATE.results).length) {
        loadD3().then(() => buildAttackGraph(STATE.results));
    }
}


/* ═══════════════════════════════════════════════════════════════════
   5.  SCAN CONTROL
   ═══════════════════════════════════════════════════════════════════ */

function startScan() {
    const url       = (document.getElementById('scan-url')       || {}).value || '';
    const threads   = (document.getElementById('scan-threads')   || {}).value || '5';
    const stealth   = (document.getElementById('scan-stealth')   || {}).value || 'light';
    const proxy     = (document.getElementById('scan-proxy')     || {}).value || '';
    const impersonate = (document.getElementById('scan-impersonate') || {}).value || '';

    if (!url) {
        showToast('Please enter a target URL', 'error');
        return;
    }

    wsSend({
        action: 'start_scan',
        url,
        threads: parseInt(threads, 10),
        stealth,
        proxy: proxy || undefined,
        impersonate: impersonate || undefined,
    });

    updateStatus('running');
    showToast('Scan initiated — waiting for server...', 'info');
}

function handleScanStarted(data) {
    STATE.status = 'running';
    STATE.target = data.target;
    STATE.findings = [];
    STATE.severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    STATE.currentPhase = 0;
    STATE.aiData = null;

    updateStatus('running');
    updateCounters();
    clearFeed();
    resetPhaseBar();
    resetGauge();
    clearAIPanel();
    showToast(`Scanning ${data.target}`, 'info');
}

function handleScanComplete(data) {
    STATE.status = 'complete';
    updateStatus('complete');
    showToast(
        `Scan complete — ${data.total_findings} findings, ${data.endpoints} endpoints, ${data.forms} forms`,
        'success'
    );

    // Enable AI analysis button
    const aiBtn = document.getElementById('btn-ai-analyze');
    if (aiBtn) aiBtn.classList.remove('disabled');

    // Build the attack graph
    loadD3().then(() => buildAttackGraph(STATE.results));
}

function updateStatus(status) {
    STATE.status = status;
    const dot  = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    const btn  = document.getElementById('btn-start-scan');

    if (dot) {
        dot.className = 'status-dot';
        dot.classList.add('status-' + status);
    }
    if (text) {
        const labels = { idle: 'Idle', running: 'Scanning…', complete: 'Complete', error: 'Error' };
        text.textContent = labels[status] || status;
    }
    if (btn) {
        btn.disabled = (status === 'running');
        btn.textContent = status === 'running' ? 'Scanning…' : 'Start Scan';
    }
}


/* ═══════════════════════════════════════════════════════════════════
   6.  LIVE FEED
   ═══════════════════════════════════════════════════════════════════ */

function handleFinding(data) {
    STATE.findings.push(data);

    const sev = (data.severity || 'info').toLowerCase();
    if (STATE.severityCounts.hasOwnProperty(sev)) {
        STATE.severityCounts[sev]++;
    }
    updateCounters();
    addFinding(data);

    // Also accumulate into results for the attack graph
    const mod = data.module || 'unknown';
    if (!STATE.results[mod]) STATE.results[mod] = [];
    STATE.results[mod].push(data);
}

function addFinding(finding) {
    const feed = document.getElementById('feed-list');
    if (!feed) return;

    const sev = (finding.severity || 'info').toLowerCase();
    const sevMeta = SEVERITY[sev] || SEVERITY.info;

    const item = document.createElement('div');
    item.className = 'feed-item feed-item-enter';
    item.innerHTML = `
        <span class="severity-badge severity-${sev}" style="--sev-color:${sevMeta.color};--sev-bg:${sevMeta.bg}">
            ${sevMeta.label}
        </span>
        <span class="feed-module">${escHtml(finding.module || '')}</span>
        <span class="feed-type">${escHtml(finding.type || '')}</span>
        <span class="feed-desc">${escHtml(finding.desc || finding.description || '')}</span>
    `;

    feed.prepend(item);

    // Trigger reflow then animate in
    requestAnimationFrame(() => {
        requestAnimationFrame(() => item.classList.remove('feed-item-enter'));
    });

    // Limit visible items to 200
    while (feed.children.length > 200) {
        feed.removeChild(feed.lastChild);
    }
}

function clearFeed() {
    const feed = document.getElementById('feed-list');
    if (feed) feed.innerHTML = '';
}


/* ═══════════════════════════════════════════════════════════════════
   7.  SEVERITY COUNTERS (animated)
   ═══════════════════════════════════════════════════════════════════ */

function updateCounters() {
    const ids = ['critical', 'high', 'medium', 'low', 'info'];
    let total = 0;
    ids.forEach(sev => {
        const el = document.getElementById('count-' + sev);
        if (el) animateCount(el, STATE.severityCounts[sev] || 0);
        total += STATE.severityCounts[sev] || 0;
    });
    const totalEl = document.getElementById('count-total');
    if (totalEl) animateCount(totalEl, total);
}

function animateCount(element, target) {
    const current = parseInt(element.textContent, 10) || 0;
    if (current === target) return;

    const start = performance.now();
    const duration = 500; // ms

    function step(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        const value = Math.round(current + (target - current) * eased);
        element.textContent = value;

        if (progress < 1) {
            requestAnimationFrame(step);
        } else {
            element.textContent = target;
            // Pulse effect
            element.classList.add('counter-pulse');
            setTimeout(() => element.classList.remove('counter-pulse'), 400);
        }
    }
    requestAnimationFrame(step);
}


/* ═══════════════════════════════════════════════════════════════════
   8.  RISK SCORE GAUGE (SVG)
   ═══════════════════════════════════════════════════════════════════ */

function updateGauge(score, grade) {
    const container = document.getElementById('gauge-container');
    if (!container) return;

    score = Math.max(0, Math.min(100, score || 0));
    grade = grade || gradeFromScore(score);

    // Gauge dimensions
    const cx = 120, cy = 120, r = 100;
    const startAngle = Math.PI * 0.75;  // 135°
    const endAngle   = Math.PI * 2.25;  // 405° (270° arc)
    const totalArc   = endAngle - startAngle;

    // Score arc endpoint
    const scoreAngle = startAngle + (totalArc * score / 100);

    // Color based on inverted score (high score = more risk = red)
    const gaugeColor = riskColor(score);

    // Build arc path
    function arcPath(startA, endA) {
        const x1 = cx + r * Math.cos(startA);
        const y1 = cy + r * Math.sin(startA);
        const x2 = cx + r * Math.cos(endA);
        const y2 = cy + r * Math.sin(endA);
        const sweep = (endA - startA) > Math.PI ? 1 : 0;
        return `M ${x1} ${y1} A ${r} ${r} 0 ${sweep} 1 ${x2} ${y2}`;
    }

    const bgArc    = arcPath(startAngle, endAngle);
    const scoreArc = arcPath(startAngle, scoreAngle);

    container.innerHTML = `
        <svg viewBox="0 0 240 240" class="gauge-svg">
            <!-- Background arc -->
            <path d="${bgArc}" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="18" stroke-linecap="round"/>
            <!-- Score arc (animated) -->
            <path d="${scoreArc}" fill="none" stroke="${gaugeColor}" stroke-width="18" stroke-linecap="round"
                  class="gauge-arc" style="--gauge-color:${gaugeColor}"/>
            <!-- Glow filter -->
            <defs>
                <filter id="gauge-glow">
                    <feGaussianBlur stdDeviation="4" result="blur"/>
                    <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                </filter>
            </defs>
            <path d="${scoreArc}" fill="none" stroke="${gaugeColor}" stroke-width="6" stroke-linecap="round"
                  filter="url(#gauge-glow)" opacity="0.6"/>
            <!-- Score text -->
            <text x="${cx}" y="${cy - 5}" text-anchor="middle" class="gauge-score" fill="${gaugeColor}">${score}</text>
            <text x="${cx}" y="${cy + 28}" text-anchor="middle" class="gauge-grade" fill="${gaugeColor}">${grade}</text>
            <text x="${cx}" y="${cy + 50}" text-anchor="middle" class="gauge-label" fill="rgba(255,255,255,.4)">Risk Score</text>
        </svg>
    `;

    // Animate the arc in
    const arcEl = container.querySelector('.gauge-arc');
    if (arcEl) {
        const len = arcEl.getTotalLength();
        arcEl.style.strokeDasharray  = len;
        arcEl.style.strokeDashoffset = len;
        requestAnimationFrame(() => {
            arcEl.style.transition = 'stroke-dashoffset 1.5s cubic-bezier(.4,0,.2,1)';
            arcEl.style.strokeDashoffset = '0';
        });
    }
}

function resetGauge() {
    const container = document.getElementById('gauge-container');
    if (container) {
        container.innerHTML = `
            <svg viewBox="0 0 240 240" class="gauge-svg">
                <text x="120" y="120" text-anchor="middle" class="gauge-label" fill="rgba(255,255,255,.25)">Awaiting Analysis</text>
            </svg>
        `;
    }
}

function riskColor(score) {
    // 0 = green (safe), 100 = red (dangerous)
    if (score <= 30)  return '#00e676';
    if (score <= 60)  return '#ffc400';
    if (score <= 80)  return '#ff6d00';
    return '#ff1744';
}

function gradeFromScore(score) {
    if (score <= 20)  return 'A';
    if (score <= 40)  return 'B';
    if (score <= 60)  return 'C';
    if (score <= 80)  return 'D';
    return 'F';
}


/* ═══════════════════════════════════════════════════════════════════
   9.  ATTACK GRAPH (D3.js v7 force-directed)
   ═══════════════════════════════════════════════════════════════════ */

function loadD3() {
    if (STATE.d3Loaded) return Promise.resolve();
    return new Promise((resolve, reject) => {
        if (window.d3) { STATE.d3Loaded = true; return resolve(); }
        const s = document.createElement('script');
        s.src = 'https://d3js.org/d3.v7.min.js';
        s.onload = () => { STATE.d3Loaded = true; resolve(); };
        s.onerror = () => reject(new Error('Failed to load D3.js'));
        document.head.appendChild(s);
    });
}

function buildAttackGraph(results) {
    const container = document.getElementById('attack-graph');
    if (!container || !window.d3) return;

    // Teardown previous simulation
    if (STATE.attackGraphSim) { STATE.attackGraphSim.stop(); STATE.attackGraphSim = null; }
    container.innerHTML = '';

    const width  = container.clientWidth  || 700;
    const height = container.clientHeight || 500;

    // ── Build node & link data ──────────────────────────────────
    const nodes = [];
    const links = [];
    const nodeMap = {};

    // Center target node
    const targetNode = { id: 'Target', label: STATE.target || 'Target', group: 'target', r: 28, color: '#40c4ff', findings: 0 };
    nodes.push(targetNode);
    nodeMap['Target'] = targetNode;

    // Impact nodes
    const rceNode      = { id: 'RCE',         label: 'Remote Code Exec', group: 'impact', r: 22, color: '#ff1744', findings: 0 };
    const dataNode     = { id: 'Data Breach',  label: 'Data Breach',      group: 'impact', r: 22, color: '#ff6d00', findings: 0 };
    nodes.push(rceNode, dataNode);
    nodeMap['RCE'] = rceNode;
    nodeMap['Data Breach'] = dataNode;

    // Exploit modules that map to RCE / Data Breach
    const rceMods  = ['sqli', 'lfi', 'xmlrpc_exploit', 'wp_cve_exploit', 'iis_exploit', 'elementor_exploit', 'auto_exploit'];
    const dataMods = ['sqli', 'info_disclosure', 'cors_misconfig', 'xss', 'open_redirect'];

    // Module nodes
    const moduleEndpoints = {};

    Object.keys(results).forEach(mod => {
        if (mod === 'endpoints' || mod === 'forms') return;
        const items = results[mod];
        if (!Array.isArray(items) || items.length === 0) return;

        // Determine max severity of findings in this module
        let maxOrder = 4;
        const endpoints = new Set();
        items.forEach(f => {
            const sev = (f.severity || 'info').toLowerCase();
            if (SEVERITY[sev] && SEVERITY[sev].order < maxOrder) maxOrder = SEVERITY[sev].order;
            // Collect endpoints/urls referenced
            if (f.url)  endpoints.add(f.url);
            if (f.path) endpoints.add(f.path);
        });

        const sevKey   = Object.keys(SEVERITY).find(k => SEVERITY[k].order === maxOrder) || 'info';
        const nodeColor = SEVERITY[sevKey].color;
        const r = Math.min(8 + items.length * 2, 30);

        const node = { id: mod, label: mod.replace(/_/g, ' '), group: 'module', r, color: nodeColor, findings: items.length };
        nodes.push(node);
        nodeMap[mod] = node;
        moduleEndpoints[mod] = endpoints;

        // Link module → target
        links.push({ source: 'Target', target: mod, value: 1 });

        // Link to impact nodes
        if (rceMods.includes(mod))  links.push({ source: mod, target: 'RCE',        value: 2 });
        if (dataMods.includes(mod)) links.push({ source: mod, target: 'Data Breach', value: 2 });
    });

    // Link modules sharing endpoints
    const modNames = Object.keys(moduleEndpoints);
    for (let i = 0; i < modNames.length; i++) {
        for (let j = i + 1; j < modNames.length; j++) {
            const a = moduleEndpoints[modNames[i]];
            const b = moduleEndpoints[modNames[j]];
            let shared = 0;
            a.forEach(ep => { if (b.has(ep)) shared++; });
            if (shared > 0) {
                links.push({ source: modNames[i], target: modNames[j], value: shared });
            }
        }
    }

    if (nodes.length <= 3) {
        container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:rgba(255,255,255,.3);font-size:14px;">No module data to visualize</div>';
        return;
    }

    // ── D3 SVG ──────────────────────────────────────────────────
    const svg = d3.select(container)
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .attr('viewBox', `0 0 ${width} ${height}`);

    // Arrow marker
    svg.append('defs').append('marker')
        .attr('id', 'arrowhead')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', 'rgba(255,255,255,.2)');

    // Glow filter for nodes
    const glowFilter = svg.select('defs').append('filter').attr('id', 'node-glow');
    glowFilter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'blur');
    glowFilter.append('feMerge').selectAll('feMergeNode')
        .data(['blur', 'SourceGraphic']).enter()
        .append('feMergeNode').attr('in', d => d);

    const linkGroup = svg.append('g').attr('class', 'graph-links');
    const nodeGroup = svg.append('g').attr('class', 'graph-nodes');

    // ── Force simulation ────────────────────────────────────────
    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(100).strength(0.3))
        .force('charge', d3.forceManyBody().strength(-250))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => d.r + 10));

    STATE.attackGraphSim = simulation;

    // Links
    const link = linkGroup.selectAll('line')
        .data(links)
        .enter().append('line')
        .attr('stroke', 'rgba(255,255,255,.1)')
        .attr('stroke-width', d => Math.min(d.value, 3))
        .attr('marker-end', 'url(#arrowhead)');

    // Node groups
    const node = nodeGroup.selectAll('g')
        .data(nodes)
        .enter().append('g')
        .attr('class', 'graph-node')
        .call(d3.drag()
            .on('start', dragStart)
            .on('drag',  dragging)
            .on('end',   dragEnd));

    // Glow circle behind
    node.append('circle')
        .attr('r', d => d.r + 4)
        .attr('fill', d => d.color)
        .attr('opacity', 0.15)
        .attr('filter', 'url(#node-glow)');

    // Main circle
    node.append('circle')
        .attr('r', d => d.r)
        .attr('fill', d => d.color)
        .attr('stroke', d => d.color)
        .attr('stroke-width', 2)
        .attr('fill-opacity', 0.2)
        .attr('class', 'node-circle');

    // Label
    node.append('text')
        .text(d => d.label)
        .attr('dy', d => d.r + 16)
        .attr('text-anchor', 'middle')
        .attr('fill', 'rgba(255,255,255,.6)')
        .attr('font-size', '10px')
        .attr('pointer-events', 'none');

    // Count inside node
    node.filter(d => d.findings > 0)
        .append('text')
        .text(d => d.findings)
        .attr('text-anchor', 'middle')
        .attr('dy', '4px')
        .attr('fill', '#fff')
        .attr('font-size', '11px')
        .attr('font-weight', '700')
        .attr('pointer-events', 'none');

    // Icon for special nodes
    node.filter(d => d.group === 'target')
        .append('text')
        .text('⦿')
        .attr('text-anchor', 'middle')
        .attr('dy', '5px')
        .attr('fill', '#fff')
        .attr('font-size', '20px')
        .attr('pointer-events', 'none');

    node.filter(d => d.group === 'impact')
        .append('text')
        .text(d => d.id === 'RCE' ? '💀' : '🔓')
        .attr('text-anchor', 'middle')
        .attr('dy', '6px')
        .attr('font-size', '16px')
        .attr('pointer-events', 'none');

    // Tooltip
    const tooltip = d3.select('body').append('div')
        .attr('class', 'graph-tooltip')
        .style('opacity', 0);

    node.on('mouseover', (event, d) => {
        tooltip.transition().duration(200).style('opacity', 1);
        let html = `<strong>${escHtml(d.label)}</strong>`;
        if (d.findings) html += `<br>${d.findings} finding${d.findings !== 1 ? 's' : ''}`;
        if (d.group === 'impact') html += `<br><em>Impact Category</em>`;
        tooltip.html(html)
            .style('left', (event.pageX + 14) + 'px')
            .style('top',  (event.pageY - 14) + 'px');
    })
    .on('mousemove', (event) => {
        tooltip.style('left', (event.pageX + 14) + 'px')
               .style('top',  (event.pageY - 14) + 'px');
    })
    .on('mouseout', () => {
        tooltip.transition().duration(300).style('opacity', 0);
    })
    .on('click', (event, d) => {
        showNodeDetails(d);
    });

    // Tick
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Drag handlers
    function dragStart(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
    }
    function dragging(event, d) {
        d.fx = event.x; d.fy = event.y;
    }
    function dragEnd(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null; d.fy = null;
    }
}

function showNodeDetails(node) {
    if (node.group === 'target' || node.group === 'impact') return;

    const findings = STATE.results[node.id];
    if (!Array.isArray(findings) || findings.length === 0) return;

    const content = findings.map(f => {
        const sev = (f.severity || 'info').toLowerCase();
        const meta = SEVERITY[sev] || SEVERITY.info;
        return `<div class="detail-finding">
            <span class="severity-badge severity-${sev}" style="--sev-color:${meta.color};--sev-bg:${meta.bg}">${meta.label}</span>
            <span>${escHtml(f.type || f.desc || '')}</span>
            <div class="detail-desc">${escHtml(f.desc || f.description || '')}</div>
        </div>`;
    }).join('');

    showModal(`${escHtml(node.label)} — ${findings.length} Findings`, content);
}


/* ═══════════════════════════════════════════════════════════════════
   10. AI ANALYSIS PANEL (tabbed)
   ═══════════════════════════════════════════════════════════════════ */

function triggerAIAnalysis() {
    wsSend({ action: 'ai_analyze' });
    showToast('AI analysis requested…', 'info');
    const panel = document.getElementById('ai-panel');
    if (panel) panel.innerHTML = '<div class="ai-loading"><div class="spinner"></div><span>Analyzing with AI…</span></div>';
}

function handleAIStarted() {
    showToast('AI analysis in progress…', 'info');
    const panel = document.getElementById('ai-panel');
    if (panel) panel.innerHTML = '<div class="ai-loading"><div class="spinner"></div><span>AI is thinking…</span></div>';
}

function handleAIComplete(data) {
    STATE.aiData = data;
    showToast('AI analysis complete', 'success');
    showAIResults(data);

    // Update gauge if risk_score present
    if (data.risk_score) {
        updateGauge(data.risk_score.score, data.risk_score.grade);
    }
}

function showAIResults(data) {
    const panel = document.getElementById('ai-panel');
    if (!panel) return;

    const tabs = [
        { id: 'tab-summary',    label: 'Executive Summary', content: parseMarkdown(data.executive_summary || '_No data_') },
        { id: 'tab-narrative',  label: 'Attack Narrative',  content: parseMarkdown(data.attack_narrative  || '_No data_') },
        { id: 'tab-remediation',label: 'Remediation',       content: parseMarkdown(data.remediation_plan  || '_No data_') },
        { id: 'tab-risk',       label: 'Risk Breakdown',    content: buildRiskBreakdown(data.risk_score)                    },
    ];

    let tabBarHtml = '<div class="ai-tab-bar">';
    let contentHtml = '';

    tabs.forEach((t, i) => {
        const active = i === 0 ? 'active' : '';
        tabBarHtml += `<button class="ai-tab-btn ${active}" data-tab="${t.id}">${t.label}</button>`;
        contentHtml += `<div class="ai-tab-content ${active}" id="${t.id}">${t.content}</div>`;
    });
    tabBarHtml += '</div>';

    panel.innerHTML = tabBarHtml + contentHtml;

    // Tab switching
    panel.querySelectorAll('.ai-tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            panel.querySelectorAll('.ai-tab-btn').forEach(b => b.classList.remove('active'));
            panel.querySelectorAll('.ai-tab-content').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(btn.dataset.tab).classList.add('active');
        });
    });
}

function buildRiskBreakdown(riskScore) {
    if (!riskScore || !riskScore.breakdown) return '<p>No risk breakdown available.</p>';

    const categories = [
        { key: 'infrastructure', label: 'Infrastructure',  icon: '🏗️' },
        { key: 'application',    label: 'Application',     icon: '🌐' },
        { key: 'data_exposure',  label: 'Data Exposure',   icon: '📊' },
        { key: 'authentication', label: 'Authentication',  icon: '🔑' },
    ];

    let html = `
        <div class="risk-overview">
            <div class="risk-big-score" style="color:${riskColor(riskScore.score)}">${riskScore.score}<span class="risk-grade">${riskScore.grade}</span></div>
            <p class="risk-summary">${escHtml(riskScore.summary || '')}</p>
        </div>
        <div class="risk-bars">
    `;

    categories.forEach(cat => {
        const val = riskScore.breakdown[cat.key] || 0;
        const color = riskColor(val);
        html += `
            <div class="risk-bar-row">
                <span class="risk-bar-label">${cat.icon} ${cat.label}</span>
                <div class="risk-bar-track">
                    <div class="risk-bar-fill" style="width:${val}%;background:${color}" data-value="${val}"></div>
                </div>
                <span class="risk-bar-value" style="color:${color}">${val}</span>
            </div>
        `;
    });

    html += '</div>';

    // Animate bars after render
    setTimeout(() => {
        document.querySelectorAll('.risk-bar-fill').forEach(bar => {
            const target = bar.getAttribute('data-value');
            bar.style.width = '0%';
            requestAnimationFrame(() => {
                bar.style.transition = 'width 1s cubic-bezier(.4,0,.2,1)';
                bar.style.width = target + '%';
            });
        });
    }, 50);

    return html;
}

function clearAIPanel() {
    const panel = document.getElementById('ai-panel');
    if (panel) {
        panel.innerHTML = '<div class="ai-placeholder">Run a scan and click <strong>AI Analyze</strong> to get insights.</div>';
    }
}


/* ═══════════════════════════════════════════════════════════════════
   11. PHASE INDICATOR
   ═══════════════════════════════════════════════════════════════════ */

function handlePhase(data) {
    const number = data.number || 0;
    const name   = data.name   || '';
    updatePhase(name, number);
}

function updatePhase(name, number) {
    STATE.currentPhase = number;
    const bar = document.getElementById('phase-bar');
    if (!bar) return;

    // Update dots
    for (let i = 0; i < STATE.phaseCount; i++) {
        const dot   = document.getElementById(`phase-dot-${i}`);
        const label = document.getElementById(`phase-label-${i}`);
        if (dot) {
            dot.classList.remove('phase-active', 'phase-done');
            if (i < number)      dot.classList.add('phase-done');
            else if (i === number) dot.classList.add('phase-active');
        }
        if (label) {
            label.classList.remove('phase-active', 'phase-done');
            if (i < number)      label.classList.add('phase-done');
            else if (i === number) label.classList.add('phase-active');
        }
    }

    // Update current phase name display
    const phaseName = document.getElementById('phase-current-name');
    if (phaseName) phaseName.textContent = name || PHASE_NAMES[number] || '';
}

function resetPhaseBar() {
    STATE.currentPhase = 0;
    for (let i = 0; i < STATE.phaseCount; i++) {
        const dot   = document.getElementById(`phase-dot-${i}`);
        const label = document.getElementById(`phase-label-${i}`);
        if (dot)   { dot.classList.remove('phase-active', 'phase-done'); }
        if (label) { label.classList.remove('phase-active', 'phase-done'); }
    }
    const phaseName = document.getElementById('phase-current-name');
    if (phaseName) phaseName.textContent = '';
}

function initPhaseBar() {
    const bar = document.getElementById('phase-bar');
    if (!bar || bar.children.length > 0) return;

    let html = '<div class="phase-track">';
    PHASE_NAMES.forEach((name, i) => {
        html += `
            <div class="phase-step">
                <div class="phase-dot" id="phase-dot-${i}"></div>
                <span class="phase-step-label" id="phase-label-${i}">${name}</span>
            </div>
            ${i < PHASE_NAMES.length - 1 ? '<div class="phase-connector"></div>' : ''}
        `;
    });
    html += '</div>';
    html += '<div class="phase-current"><span id="phase-current-name"></span></div>';
    bar.innerHTML = html;
}


/* ═══════════════════════════════════════════════════════════════════
   12. TOAST NOTIFICATIONS
   ═══════════════════════════════════════════════════════════════════ */

let toastContainer = null;

function getToastContainer() {
    if (toastContainer) return toastContainer;
    toastContainer = document.createElement('div');
    toastContainer.id = 'toast-container';
    toastContainer.className = 'toast-container';
    document.body.appendChild(toastContainer);
    return toastContainer;
}

function showToast(message, type = 'info') {
    const container = getToastContainer();

    const icons = { success: '✓', error: '✕', info: 'ℹ', warning: '⚠' };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type} toast-enter`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-msg">${escHtml(message)}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">×</button>
    `;

    container.appendChild(toast);

    // Animate in
    requestAnimationFrame(() => {
        requestAnimationFrame(() => toast.classList.remove('toast-enter'));
    });

    // Auto-dismiss
    setTimeout(() => {
        toast.classList.add('toast-exit');
        setTimeout(() => toast.remove(), 400);
    }, 4000);
}


/* ═══════════════════════════════════════════════════════════════════
   13. ERROR HANDLER
   ═══════════════════════════════════════════════════════════════════ */

function handleError(data) {
    const message = data && data.message ? data.message : 'Unknown error';
    showToast(message, 'error');
    if (STATE.status === 'running') {
        updateStatus('error');
    }
}


/* ═══════════════════════════════════════════════════════════════════
   14. MODAL
   ═══════════════════════════════════════════════════════════════════ */

function showModal(title, content) {
    // Remove existing
    const old = document.getElementById('app-modal');
    if (old) old.remove();

    const overlay = document.createElement('div');
    overlay.id = 'app-modal';
    overlay.className = 'modal-overlay modal-enter';
    overlay.innerHTML = `
        <div class="modal-box">
            <div class="modal-header">
                <h3>${title}</h3>
                <button class="modal-close" onclick="closeModal()">×</button>
            </div>
            <div class="modal-body">${content}</div>
        </div>
    `;
    document.body.appendChild(overlay);

    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) closeModal();
    });

    requestAnimationFrame(() => {
        requestAnimationFrame(() => overlay.classList.remove('modal-enter'));
    });
}

function closeModal() {
    const overlay = document.getElementById('app-modal');
    if (overlay) {
        overlay.classList.add('modal-exit');
        setTimeout(() => overlay.remove(), 300);
    }
}


/* ═══════════════════════════════════════════════════════════════════
   15. UTILITY
   ═══════════════════════════════════════════════════════════════════ */

function escHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}


/* ═══════════════════════════════════════════════════════════════════
   16. INITIALIZATION
   ═══════════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
    // Init phase bar
    initPhaseBar();

    // Init gauge placeholder
    resetGauge();

    // Init AI panel placeholder
    clearAIPanel();

    // Wire up scan button
    const startBtn = document.getElementById('btn-start-scan');
    if (startBtn) startBtn.addEventListener('click', startScan);

    // Wire up AI button
    const aiBtn = document.getElementById('btn-ai-analyze');
    if (aiBtn) {
        aiBtn.addEventListener('click', () => {
            if (!aiBtn.classList.contains('disabled')) {
                triggerAIAnalysis();
            }
        });
    }

    // Enter key on URL input
    const urlInput = document.getElementById('scan-url');
    if (urlInput) {
        urlInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') startScan();
        });
    }

    // Set initial status
    updateStatus('idle');

    // Connect WebSocket
    wsConnect();

    // Add ambient pulse to status dot
    setInterval(() => {
        const dot = document.getElementById('status-dot');
        if (dot && STATE.status === 'running') {
            dot.classList.toggle('pulse');
        }
    }, 1500);
});
