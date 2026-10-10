class SOCSimulator {
    constructor() {
        this.incidents = [];
        this.threats = [];
        this.stats = {
            activeIncidents: 0,
            threatsDetected: 0,
            assetsProtected: 0,
            mttr: null
        };
        this.chart = null;
        this.init();
    }

    init() {
        console.log('SOC Simulator initializing...');
        this.showLoading();
       // Dashboard metrics are derived from the active simulated shift; no fabricated telemetry.
        this.setupEventListeners();
        this.updateDateTime();
        this.startDataSimulation();
        
        // Hide loading screen after simulation
        setTimeout(() => {
            this.hideLoading();
            console.log('SOC Simulator ready! Try clicking navigation items.');
        }, 3000);
    }

    showLoading() {
        const progress = document.getElementById('loadingProgress');
        const status = document.getElementById('loadingStatus');
        const stages = [
            { progress: 20, text: 'Loading scenario library...' },
            { progress: 40, text: 'Preparing simulated shift...' },
            { progress: 60, text: 'Initializing investigation tools...' },
            { progress: 80, text: 'Preparing analyst workspace...' },
            { progress: 100, text: 'Training environment ready!' }
        ];

        let currentStage = 0;
        const updateProgress = () => {
            if (currentStage < stages.length) {
                const stage = stages[currentStage];
                progress.style.width = stage.progress + '%';
                status.textContent = stage.text;
                currentStage++;
                setTimeout(updateProgress, 600);
            }
        };

        updateProgress();
    }

    hideLoading() {
        const loadingScreen = document.getElementById('loadingScreen');
        loadingScreen.classList.add('hidden');
        setTimeout(() => {
            loadingScreen.style.display = 'none';
        }, 500);
    }

    // Legacy sample-data generation was removed. Dashboard content comes from the active shift.

    renderIncidentsTable() {
        const tbody = document.getElementById('incidentsTableBody');
        if (!tbody) return;
        tbody.innerHTML = '';

        this.incidents.slice(0, 5).forEach(incident => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><span class="incident-id">${incident.id}</span></td>
                <td>${incident.title}</td>
                <td><span class="severity-badge severity-${incident.severity.toLowerCase()}">${incident.severity}</span></td>
                <td><span class="status-badge status-${incident.status.toLowerCase().replace(' ', '-')}">${incident.status}</span></td>
                <td>${this.formatTime(incident.timestamp)}</td>
            `;
            tbody.appendChild(row);
        });
    }
    renderFullIncidentsTable() {
        const tbody = document.getElementById('fullIncidentsTableBody');
        if (!tbody) return;
        tbody.innerHTML = '';

        this.incidents.forEach(incident => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><span class="incident-id">${incident.id}</span></td>
                <td>${incident.title}</td>
                <td><span class="severity-badge severity-${incident.severity.toLowerCase()}">${incident.severity}</span></td>
                <td><span class="status-badge status-${incident.status.toLowerCase().replace(' ', '-')}">${incident.status}</span></td>
                <td>SOC Analyst</td>
                <td>${this.formatTime(incident.timestamp)}</td>
                <td><button class="btn btn-secondary btn-sm" data-id="${incident.id}">View</button></td>
            `;
            tbody.appendChild(row);
        });

        tbody.onclick = (e) => {
            const btn = e.target.closest('button[data-id]');
            if (btn) this.viewIncident(btn.dataset.id);
        };
    }

        addIncidentFromAlert(alert) {
        this.incidents.unshift({
            id: alert.id,
            title: alert.rule,
            severity: alert.severity,
            status: 'New',
            timestamp: alert.releasedAt
        });
        this.refreshIncidentViews();
    }

    closeIncident(id) {
        const inc = this.incidents.find(i => i.id === id);
        if (inc) inc.status = 'Closed';
        this.refreshIncidentViews();
    }

    refreshIncidentViews() {
        this.stats.activeIncidents = this.incidents.filter(i => i.status !== 'Closed').length;
        this.stats.threatsDetected = this.incidents.length;
        const hosts = new Set((window.toolkit?.scenario?.assets?.hosts || []));
        this.stats.assetsProtected = hosts.size;
        const decisions = Object.values(window.shiftState?.decisions || {}).filter(d => Number.isFinite(d.responseMin));
        this.stats.mttr = decisions.length ? decisions.reduce((sum, d) => sum + d.responseMin, 0) / decisions.length : null;
        this.updateStatsDisplay();
        this.renderIncidentsTable();
        this.renderFullIncidentsTable();
        this.renderThreatFeed();
        this.renderFullThreatFeed();
        this.initChart();
    }

    viewIncident(id) {
        document.getElementById('aq-panel').classList.add('open');
        queue.openDetail(id);
    }

    renderThreatFeed() {
        const container = document.getElementById('threatFeedContent');
        if (!container) return;
        const latest = [...this.incidents].slice(0, 8);
        if (!latest.length) {
            container.innerHTML = '<div class="empty-state" style="padding:1.5rem;color:var(--text-muted);">No alerts released yet. Start the simulated shift to populate this feed.</div>';
            return;
        }
        container.innerHTML = latest.map(item => `
            <div class="threat-item">
                <div class="threat-icon" style="background:var(--primary);"><i class="fas fa-bell"></i></div>
                <div class="threat-content">
                    <div class="threat-title">${this.escapeHtml(item.title)}</div>
                    <div class="threat-description">${this.escapeHtml(item.severity)} severity · ${this.escapeHtml(item.status)}</div>
                    <div class="threat-time">${this.escapeHtml(this.formatTime(item.timestamp))} · ${this.escapeHtml(item.id)}</div>
                </div>
            </div>`).join('');
    }

    renderFullThreatFeed() {
        const container = document.getElementById('fullThreatFeedContent');
        if (!container) return;
        const latest = [...this.incidents];
        container.innerHTML = latest.length ? latest.map(item => `
            <div class="threat-item">
                <div class="threat-icon" style="background:var(--primary);"><i class="fas fa-bell"></i></div>
                <div class="threat-content">
                    <div class="threat-title">${this.escapeHtml(item.title)}</div>
                    <div class="threat-description">${this.escapeHtml(item.severity)} severity · ${this.escapeHtml(item.status)}</div>
                    <div class="threat-time">${this.escapeHtml(this.formatTime(item.timestamp))} · ${this.escapeHtml(item.id)}</div>
                </div>
            </div>`).join('') : '<div class="empty-state" style="padding:1.5rem;color:var(--text-muted);">No alerts have been released during this shift yet.</div>';
    }

    escapeHtml(value) {
        return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    initChart() {
        const canvas = document.getElementById('threatTrendsChart');
        if (!canvas || typeof Chart === 'undefined') return;
        const labels = this.incidents.map(item => item.timestamp);
        const counts = this.incidents.map((_, index) => index + 1);
        if (this.chart) { this.chart.destroy(); this.chart = null; }
        this.chart = new Chart(canvas.getContext('2d'), {
            type: 'line',
            data: {
                labels: labels.length ? labels : ['No alerts yet'],
                datasets: [{
                    label: 'Alerts released this shift',
                    data: counts.length ? counts : [0],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.25
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, ticks: { precision: 0, color: '#94a3b8' }, grid: { color: '#475569' } },
                    x: { ticks: { color: '#94a3b8', maxRotation: 45, minRotation: 0 }, grid: { color: '#475569' } }
                }
            }
        });
    }

    setupEventListeners() {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const currentActive = document.querySelector('.nav-item.active');
                if (currentActive) currentActive.classList.remove('active');
                item.classList.add('active');
                
                const view = item.getAttribute('data-view');
                this.switchView(view);
            });
        });

        document.addEventListener('click', (e) => {
            if (e.target.textContent && e.target.textContent.includes('View All')) {
                e.preventDefault();
                const currentActive = document.querySelector('.nav-item.active');
                if (currentActive) currentActive.classList.remove('active');
                
                const incidentsNav = document.querySelector('[data-view="incidents"]');
                if (incidentsNav) incidentsNav.classList.add('active');
                
                this.switchView('incidents');
            }
        });
    }

    updateDateTime() {
        const dateElem = document.getElementById('currentDateTime');
        if (dateElem) {
            dateElem.textContent = new Date().toLocaleString('en-US', {
                weekday: 'short',
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        }
    }

    startDataSimulation() {
        // Only keep the clock. Incidents and stats now come from the scenario engine.
        setInterval(() => this.updateDateTime(), 1000);
    }

    simulateNewIncident() {
        const notification = document.getElementById('notificationTemplate');
        if (notification) {
            notification.classList.add('show');
            setTimeout(() => notification.classList.remove('show'), 5000);
        }

        this.refreshIncidentViews();
    }

    updateStats() {
        this.refreshIncidentViews();
    }

    updateStatsDisplay() {
        const safeSetText = (id, text) => {
            const el = document.getElementById(id);
            if (el) el.textContent = text;
        };

        const safeSetHtml = (id, html) => {
            const el = document.getElementById(id);
            if (el) el.innerHTML = html;
        };

        safeSetText('activeIncidentsValue', this.stats.activeIncidents);
        safeSetText('threatsValue', this.stats.threatsDetected.toLocaleString());
        safeSetText('assetsValue', this.stats.assetsProtected.toLocaleString());
        safeSetHtml('mttrValue', this.stats.mttr === null ? '—' : `${this.stats.mttr.toFixed(1)}<span style="font-size: 1rem; color: var(--text-muted);">min</span>`);
        safeSetText('activeIncidentsBadge', this.stats.activeIncidents);
        safeSetText('activeIncidentsCount', `${this.stats.activeIncidents} Active Incidents`);
    }

        formatTime(timestamp) {
        if (typeof timestamp === 'string') return timestamp;
        return new Date(timestamp).toLocaleTimeString();
    }

    switchView(view) {
        const mainContent = document.getElementById('mainContent');
        if (!mainContent) return;
        
        switch(view) {
            case 'overview':
                mainContent.innerHTML = this.getOverviewContent();
                setTimeout(() => {
                    this.renderIncidentsTable();
                    this.renderThreatFeed();
                    this.initChart();
                }, 50);
                break;
            case 'incidents':
                mainContent.innerHTML = this.getIncidentsContent();
                setTimeout(() => this.renderFullIncidentsTable(), 50);
                break;
            case 'threat-feed':
                mainContent.innerHTML = this.getThreatFeedContent();
                setTimeout(() => this.renderFullThreatFeed(), 50);
                break;
            case 'forensics':
                mainContent.innerHTML = this.getForensicsContent();
                break;
            case 'threat-hunting':
                mainContent.innerHTML = this.getThreatHuntingContent();
                break;
            case 'intel':
                mainContent.innerHTML = this.getThreatIntelContent();
                break;
            case 'playbooks':
                mainContent.innerHTML = this.getPlaybooksContent();
                break;
            case 'containment':
                mainContent.innerHTML = this.getContainmentContent();
                break;
            case 'recovery':
                mainContent.innerHTML = this.getRecoveryContent();
                break;
            case 'analytics':
                mainContent.innerHTML = this.getAnalyticsContent();
                setTimeout(() => this.initChart(), 50);
                break;
            case 'reports':
                mainContent.innerHTML = this.getReportsContent();
                break;
            default:
                mainContent.innerHTML = this.getOverviewContent();
                setTimeout(() => {
                    this.renderIncidentsTable();
                    this.renderThreatFeed();
                    this.initChart();
                }, 50);
        }
    }

    getOverviewContent() {
        return `
            <h1 class="page-title">Security Operations Center</h1>
            <p class="page-subtitle">Training shift overview · metrics from the active simulation</p>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-title">Active Incidents</div>
                        <div class="stat-icon" style="background: var(--danger);"><i class="fas fa-exclamation-triangle"></i></div>
                    </div>
                    <div class="stat-value" id="activeIncidentsValue">${this.stats.activeIncidents}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-title">Alerts Released</div>
                        <div class="stat-icon" style="background: var(--warning);"><i class="fas fa-shield-alt"></i></div>
                    </div>
                    <div class="stat-value" id="threatsValue">${this.stats.threatsDetected.toLocaleString()}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-title">Assets in Scenario</div>
                        <div class="stat-icon" style="background: var(--success);"><i class="fas fa-server"></i></div>
                    </div>
                    <div class="stat-value" id="assetsValue">${this.stats.assetsProtected.toLocaleString()}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-title">Mean Triage Time</div>
                        <div class="stat-icon" style="background: var(--primary);"><i class="fas fa-clock"></i></div>
                    </div>
                    <div class="stat-value" id="mttrValue">${this.stats.mttr.toFixed(1)}<span style="font-size: 1rem; color: var(--text-muted);">min</span></div>
                </div>
            </div>
            <div class="content-grid">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">Recent Incidents</h3>
                        <button class="btn btn-secondary btn-sm"><i class="fas fa-external-link-alt"></i> View All</button>
                    </div>
                    <div class="card-body" style="padding: 0;">
                        <table class="incidents-table">
                            <thead>
                                <tr><th>Incident ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Time</th></tr>
                            </thead>
                            <tbody id="incidentsTableBody"></tbody>
                        </table>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">Live Threat Feed</h3>
                        <div class="status-indicator"></div>
                    </div>
                    <div class="card-body" style="padding: 0;" id="threatFeedContent"></div>
                </div>
            </div>
            <div class="card" style="margin-top: 2rem;">
                <div class="card-header"><h3 class="card-title">Alerts Released During This Shift</h3></div>
                <div class="card-body"><div class="chart-container"><canvas id="threatTrendsChart"></canvas></div></div>
            </div>
        `;
    }

    getIncidentsContent() {
        return `
            <h1 class="page-title">Active Incidents</h1>
            <p class="page-subtitle">Manage and investigate security incidents</p>
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">All Incidents</h3>
                </div>
                <div class="card-body" style="padding: 0;">
                    <table class="incidents-table">
                        <thead>
                            <tr><th>Incident ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Assigned To</th><th>Created</th><th>Actions</th></tr>
                        </thead>
                        <tbody id="fullIncidentsTableBody"></tbody>
                    </table>
                </div>
            </div>
        `;
    }

    getThreatFeedContent() {
        return `
            <h1 class="page-title">Threat Intelligence Feed</h1>
            <p class="page-subtitle">Real-time threat intelligence and IOCs</p>
            <div class="card">
                <div class="card-header"><h3 class="card-title">Live Threat Feed</h3></div>
                <div class="card-body" style="padding: 0;" id="fullThreatFeedContent"></div>
            </div>
        `;
    }

    getForensicsContent() { return this.getComingSoonContent('Digital Forensics', 'Evidence acquisition and forensic artefact analysis'); }
    getThreatHuntingContent() { return this.getComingSoonContent('Threat Hunting', 'Hypothesis-driven proactive investigation'); }
    getThreatIntelContent() { return this.getComingSoonContent('Threat Intelligence', 'IOC enrichment and threat context'); }
    getPlaybooksContent() { return this.getComingSoonContent('Incident Response Playbooks', 'Browseable playbook library; per-alert guidance is available inside the Shift Console'); }
    getContainmentContent() { return this.getComingSoonContent('Threat Containment', 'Dedicated containment console; current response actions are simulated in Toolkit'); }
    getRecoveryContent() { return this.getComingSoonContent('System Recovery', 'Recovery planning and validation workflows'); }
    getAnalyticsContent() { return this.getComingSoonContent('Security Analytics', 'Longitudinal metrics across completed practice shifts'); }
    getReportsContent() { return this.getComingSoonContent('Security Reports', 'Exportable shift reports are planned; the current report is available in Toolkit'); }

    getComingSoonContent(title, description) { return `<h1 class="page-title">${this.escapeHtml(title)}</h1><p class="page-subtitle">${this.escapeHtml(description)}</p><div class="card"><div class="card-body"><span class="status-badge">Coming soon</span><p>This workspace is not implemented yet. Use the Shift Console and Toolkit for the currently supported training workflow.</p></div></div>`; }
}

document.addEventListener('DOMContentLoaded', () => {
    window.soc = new SOCSimulator();
});

  const engine = new ScenarioEngine({ msPerMinute: 6000 });
  const queue = new AlertQueueUI(engine);

  const scenarioId = new URLSearchParams(location.search).get('scenario') || 'sc-001';

  const CHECKPOINT_KEY = 'cybersim.activeShift.v1';
  let lastCheckpointAt = 0;
  window.saveShiftCheckpoint = (force = false) => {
    try {
      if (!engine || !engine.scenario || engine.ended) return false;
      const now = Date.now();
      if (!force && now - lastCheckpointAt < 3000) return false;
      const snapshot = engine.createSnapshot(window.shiftState);
      if (!snapshot) return false;
      localStorage.setItem(CHECKPOINT_KEY, JSON.stringify(snapshot));
      lastCheckpointAt = now;
      return true;
    } catch (err) {
      console.warn('[CyberSim] Could not save shift checkpoint:', err);
      return false;
    }
  };

  engine.load(`data/scenarios/${scenarioId}.json`).then(() => {
    let checkpoint = null;
    try { checkpoint = JSON.parse(localStorage.getItem(CHECKPOINT_KEY) || 'null'); } catch {}
    const canResume = checkpoint && checkpoint.version === 1 && checkpoint.scenario && !checkpoint.scenario.id?.startsWith('__invalid__');
    let resumed = false;
    if (canResume && confirm(`A saved SOC shift was found: ${checkpoint.scenario.title || checkpoint.scenario.id}.\n\nResume this shift? Choose Cancel to discard it and start a new shift.`)) {
      try {
        engine.restoreSnapshot(checkpoint);
        resumed = true;
      } catch (err) {
        console.warn('[CyberSim] Saved shift could not be restored:', err);
        alert('The saved shift could not be restored. A new shift will start.');
      }
    }
    if (!resumed && checkpoint) {
      try { localStorage.removeItem(CHECKPOINT_KEY); } catch {}
    }

    queue.mount();
    window.toolkit = new Toolkit(engine);
    toolkit.mount();

    if (resumed) {
      queue.$('aq-scenario').textContent = `${engine.scenario.title} · ${engine.scenario.difficulty || ''} · Resumed`;
      queue.renderList();
      queue.onTick({ clock: engine.clock, minutes: engine.minutes });
      if (window.soc) {
        window.soc.incidents = [];
        window.shiftState.alerts.forEach(alert => window.soc.addIncidentFromAlert(alert));
        Object.keys(window.shiftState.decisions).forEach(id => window.soc.closeIncident(id));
      }
      const speed = queue.$('aq-speed');
      if ([12000, 6000, 2000, 500].includes(engine.msPerMinute)) speed.value = String(engine.msPerMinute);
      console.info(`[CyberSim] Resumed shift ${engine.scenario.id} at ${engine.minutes.toFixed(1)} simulated minutes.`);
    }

    engine.onTick = info => {
      queue.onTick(info);
      window.saveShiftCheckpoint?.(false);
    };
    window.addEventListener('beforeunload', () => window.saveShiftCheckpoint?.(true));
    engine.start();
    window.soc?.refreshIncidentViews();
  }).catch(err => {
    console.error('[CyberSim] Could not start the shift:', err);
    alert(`Could not load the training scenario.\n\n${err.message}`);
  });