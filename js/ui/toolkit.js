// js/ui/toolkit.js — Investigation Toolkit: Scenarios, Log Search, IOC Lookup, Context

class Toolkit {
  static esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // IPv4 | hash (16-64 hex) | domain (supports defanged [.])
  static PIVOT_SRC = String.raw`\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-f0-9]{16,64}\b|\b(?:[a-z0-9-]+(?:\[\.\]|\.))+(?:com|net|co|info|org)\b`;
  static pivotRe(flags = 'gi') { return new RegExp(Toolkit.PIVOT_SRC, flags); }
  static linkify(escaped) {
    return escaped.replace(Toolkit.pivotRe(), m => `<a href="#" class="tk-pivot" data-v="${m}">${m}</a>`);
  }

  // Response catalog. `target` = what the analyst must type; `kind` = validated against the environment.
  static ACTIONS = [
    { id: 'block_ip', label: 'Block IP address', group: 'Network', target: 'IP address' },
    { id: 'block_domain', label: 'Block domain', group: 'Network', target: 'Domain' },
    { id: 'block_hash', label: 'Block file hash', group: 'Endpoint', target: 'SHA-256 hash' },
    { id: 'isolate_host', label: 'Isolate host', group: 'Endpoint', target: 'Hostname', kind: 'host', confirm: true },
    { id: 'scan_host', label: 'Run full AV scan', group: 'Endpoint' },
    { id: 'kill_process', label: 'Kill malicious process', group: 'Endpoint' },
    { id: 'uninstall_pup', label: 'Uninstall unwanted software', group: 'Endpoint' },
    { id: 'retrieve_usb_device', label: 'Retrieve USB device', group: 'Endpoint' },
    { id: 'confirm_quarantine', label: 'Confirm quarantine', group: 'Endpoint' },
    { id: 'disable_account', label: 'Disable account', group: 'Identity', target: 'Username', kind: 'user', confirm: true },
    { id: 'reset_password', label: 'Force password reset', group: 'Identity', target: 'Username', kind: 'user' },
    { id: 'revoke_sessions', label: 'Revoke active sessions', group: 'Identity', target: 'Username', kind: 'user' },
    { id: 'enforce_mfa', label: 'Enforce MFA', group: 'Identity' },
    { id: 'reset_krbtgt_twice', label: 'Reset krbtgt account (twice)', group: 'Identity', confirm: true },
    { id: 'delete_email', label: 'Delete email from all mailboxes', group: 'Email' },
    { id: 'release_email', label: 'Release quarantined email', group: 'Email' },
    { id: 'remove_inbox_rule', label: 'Remove malicious inbox rule', group: 'Email' },
    { id: 'notify_manager', label: "Notify the user's manager", group: 'Notify' },
    { id: 'notify_finance', label: 'Notify Finance team', group: 'Notify' },
    { id: 'notify_hr_legal', label: 'Notify HR and Legal', group: 'Notify' },
    { id: 'document_policy_violation', label: 'Document policy violation', group: 'Case' },
    { id: 'preserve_evidence', label: 'Preserve forensic evidence', group: 'Case' },
    { id: 'initiate_incident_response', label: 'Declare incident / start IR', group: 'Case', confirm: true },
  ];

  /** Does this hostname / username appear anywhere in the scenario (alerts, logs, assets)? */
  static entityExists(scenario, name) {
    const n = String(name || '').trim().toLowerCase();
    if (n.length < 3) return false;
    if (!scenario._corpus) {
      scenario._corpus = (JSON.stringify([scenario.alerts, scenario.logs, scenario.assets])).toLowerCase();
    }
    const esc = n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`(^|[^a-z0-9_.-])${esc}($|[^a-z0-9_.-])`).test(scenario._corpus);
  }

  constructor(engine, { indexUrl = 'data/scenarios/index.json' } = {}) {
    this.ended = false;
    this.report = null;
    this.engine = engine;
    this.indexUrl = indexUrl;
    this.index = null;
    this.tab = 'logs';
  }

  // ---------------------------------------------------------------- mount
  mount() {
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <button id="tk-toggle" type="button">🔎 Toolkit</button>
      <div id="tk-modal" hidden>
        <div class="tk-box" role="dialog" aria-label="Investigation Toolkit">
          <header class="tk-head">
            <nav class="tk-tabs">
              <button type="button" data-tab="logs">Log Search</button>
              <button type="button" data-tab="ioc">IOC Lookup</button>
              <button type="button" data-tab="context">Context</button>
              <button type="button" data-tab="response">Response</button>
              <button type="button" data-tab="report">Report</button>
              <button type="button" data-tab="scenarios">Scenarios</button>
            </nav>
            <button id="tk-close" type="button" aria-label="Close">×</button>
          </header>

          <section class="tk-pane" data-pane="logs">
            <div class="tk-row">
              <input id="tk-log-q" type="search" placeholder="Search logs: IP, host, user, domain, event ID… (all words must match)">
              <select id="tk-log-src"><option value="">All sources</option></select>
              <button id="tk-log-go" class="tk-btn" type="button">Search</button>
            </div>
            <div id="tk-log-meta" class="tk-meta"></div>
            <div class="tk-scroll">
              <table class="tk-table">
                <thead><tr><th>Time</th><th>Source</th><th>Host</th><th>User</th><th>Message</th></tr></thead>
                <tbody id="tk-log-body"></tbody>
              </table>
            </div>
          </section>

          <section class="tk-pane" data-pane="ioc">
            <div class="tk-row">
              <input id="tk-ioc-q" type="search" placeholder="IP, domain, URL or file hash (defanged input is fine)">
              <button id="tk-ioc-go" class="tk-btn" type="button">Lookup</button>
            </div>
            <div id="tk-ioc-out" class="tk-scroll"></div>
          </section>

          <section class="tk-pane" data-pane="context"><div id="tk-ctx" class="tk-scroll"></div></section>

          <section class="tk-pane" data-pane="response">
            <div class="tk-row">
              <select id="tk-act"></select>
              <input id="tk-act-target" type="search" placeholder="Target">
              <button id="tk-act-go" class="tk-btn" type="button">Execute</button>
            </div>
            <div id="tk-act-msg" class="tk-meta"></div>
            <div class="tk-scroll">
              <table class="tk-table">
                <thead><tr><th>Time</th><th>Action</th><th>Target</th></tr></thead>
                <tbody id="tk-act-body"></tbody>
              </table>
            </div>
          </section>

          <section class="tk-pane" data-pane="report"><div id="tk-report" class="tk-scroll"></div></section>

          <section class="tk-pane" data-pane="scenarios">
            <div class="tk-row">
              <select id="tk-sc-tier">
                <option value="">All tiers</option><option>Tier 1</option><option>Tier 2</option><option>Tier 3</option>
              </select>
              <input id="tk-sc-q" type="search" placeholder="Filter by shift number, e.g. 017">
              <label class="tk-check"><input type="checkbox" id="tk-sc-hints"> Show hints</label>
              <button id="tk-sc-random" class="tk-btn" type="button">Random shift</button>
            </div>
            <div id="tk-sc-list" class="tk-scroll"></div>
          </section>
        </div>
      </div>`;
    document.body.append(...wrap.children);
    this.$ = id => document.getElementById(id);

    try { window.cybersimLearningMode = localStorage.getItem('cybersim.learningMode') !== 'false'; }
    catch { window.cybersimLearningMode = true; }
    this.$('tk-sc-hints').checked = window.cybersimLearningMode;
    this.$('tk-toggle').onclick = () => this.open();
    this.$('tk-close').onclick = () => this.close();
    this.$('tk-modal').addEventListener('mousedown', e => { if (e.target.id === 'tk-modal') this.close(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') this.close(); });

    this.$('tk-modal').querySelector('.tk-tabs').onclick = e => {
      const b = e.target.closest('button[data-tab]');
      if (b) this.setTab(b.dataset.tab);
    };

    // logs
    this.$('tk-log-go').onclick = () => this.searchLogs();
    this.$('tk-log-q').addEventListener('keydown', e => { if (e.key === 'Enter') this.searchLogs(); });
    this.$('tk-log-src').onchange = () => this.searchLogs();
    this.$('tk-log-body').onclick = e => {
      const td = e.target.closest('td[data-q]');
      if (td && !e.target.closest('.tk-pivot')) { this.$('tk-log-q').value = td.dataset.q; this.searchLogs(); }
    };

    // ioc
    this.$('tk-ioc-go').onclick = () => this.lookupIoc(this.$('tk-ioc-q').value);
    this.$('tk-ioc-q').addEventListener('keydown', e => { if (e.key === 'Enter') this.lookupIoc(e.target.value); });
    this.$('tk-ioc-out').onclick = e => {
      const b = e.target.closest('[data-logs]');
      if (b) this.open('logs', b.dataset.logs);
    };

    // scenarios
    this.$('tk-sc-tier').onchange = () => this.renderScenarios();
    this.$('tk-sc-hints').onchange = () => {
      window.cybersimLearningMode = this.$('tk-sc-hints').checked;
      try { localStorage.setItem('cybersim.learningMode', String(window.cybersimLearningMode)); } catch {}
      this.renderScenarios();
    };
    this.$('tk-sc-q').oninput = () => this.renderScenarios();
    this.$('tk-sc-random').onclick = () => this.startRandom();
    this.$('tk-sc-list').onclick = e => {
      const row = e.target.closest('.tk-sc');
      if (row) this.startScenario(row.dataset.id, row.dataset.title);
    };

    // response + report
    this.$('tk-act-go').onclick = () => this.executeAction();
    this.$('tk-act-target').addEventListener('keydown', e => { if (e.key === 'Enter') this.executeAction(); });
    this.$('tk-report').onclick = e => {
      const b = e.target.closest('[data-act]');
      if (!b) return;
      if (b.dataset.act === 'finish' && confirm('End the shift now? Alerts still open will count as untriaged.')) this.finishShift();
      if (b.dataset.act === 'retry') location.reload();
      if (b.dataset.act === 'random') this.startRandom(true);
      if (b.dataset.act === 'export') this.exportReport();
    };
    const prevEnd = this.engine.onEnd;
    this.engine.onEnd = info => {
      try { if (typeof prevEnd === 'function') prevEnd.call(this.engine, info); }
      finally { this.finishShift(); }
    };

    // any IP / domain / hash anywhere on the page becomes clickable
    document.addEventListener('click', e => {
      const a = e.target.closest('.tk-pivot');
      if (!a) return;
      e.preventDefault();
      this.open('ioc', a.dataset.v);
    });
    this.observeDetail();
  }

  // ---------------------------------------------------------------- open / tabs
  open(tab = this.tab, value) {
    this.$('tk-modal').hidden = false;
    this.setTab(tab);
    if (value != null) {
      if (tab === 'ioc') { this.$('tk-ioc-q').value = value; this.lookupIoc(value); }
      if (tab === 'logs') { this.$('tk-log-q').value = value; this.searchLogs(); }
    }
  }

  close() { this.$('tk-modal').hidden = true; }

  setTab(t) {
    this.tab = t;
    this.$('tk-modal').querySelectorAll('.tk-tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === t));
    this.$('tk-modal').querySelectorAll('.tk-pane').forEach(p => { p.hidden = p.dataset.pane !== t; });
    if (t === 'logs') { this.fillSources(); this.searchLogs(); }
    if (t === 'context') this.renderContext();
    if (t === 'scenarios') this.renderScenarios();
    if (t === 'response') this.renderResponse();
    if (t === 'report') this.renderReport();
    if (t === 'ioc') this.$('tk-ioc-q').focus();
  }

  // ---------------------------------------------------------------- helpers
  get scenario() { return this.engine.scenario; }

  track(type, query) {
    const s = window.shiftState;
    if (!s) return;
    (s.activity = s.activity || []).push({ type, query, alertId: window.activeAlertId || null, at: this.engine.clock, min: this.engine.minutes });
  }

  toSec(t) { const [h, m, s = 0] = t.split(':').map(Number); return h * 3600 + m * 60 + s; }

  /** seconds relative to shift start (negative = before shift began) */
  rel(t) {
    let d = this.toSec(t) - (this.engine.startClock || 0);
    if (d < -43200) d += 86400;
    if (d > 43200) d -= 86400;
    return d;
  }

  visibleLogs() {
    if (!this.scenario) return [];
    const limit = this.engine.minutes * 60;
    return this.scenario.logs.map(l => ({ ...l, rel: this.rel(l.t) })).filter(l => l.rel <= limit);
  }

  norm(v) {
    return String(v || '').trim().toLowerCase()
      .replace(/\[\.\]/g, '.').replace(/^hxxps?:\/\//, '').replace(/^https?:\/\//, '')
      .split(/[\/?#]/)[0].replace(/:\d+$/, '');
  }

  // ---------------------------------------------------------------- log search
  fillSources() {
    const sel = this.$('tk-log-src'), cur = sel.value;
    const srcs = [...new Set(this.scenario?.logs.map(l => l.src) || [])].sort();
    sel.innerHTML = '<option value="">All sources</option>' +
      srcs.map(s => `<option ${s === cur ? 'selected' : ''}>${Toolkit.esc(s)}</option>`).join('');
  }

  searchLogs() {
    const meta = this.$('tk-log-meta'), body = this.$('tk-log-body');
    if (!this.scenario) { meta.textContent = 'No active shift.'; body.innerHTML = ''; return; }

    const q = this.$('tk-log-q').value.trim().toLowerCase().replace(/\[\.\]/g, '.');
    const terms = q ? q.split(/\s+/) : [];
    const src = this.$('tk-log-src').value;
    const visible = this.visibleLogs();

    let rows = visible.filter(l =>
      (!src || l.src === src) &&
      terms.every(t => `${l.t} ${l.src} ${l.host} ${l.user} ${l.msg}`.toLowerCase().includes(t)));
    rows.sort((a, b) => a.rel - b.rel);
    if (q || src) this.track('log_search', `${q}${src ? ` [src=${src}]` : ''}`);

    const shown = rows.slice(0, 300);
    meta.textContent = `${rows.length} match(es) of ${visible.length} entries ingested so far` +
      (rows.length > 300 ? ' (showing first 300)' : '') + '. New log entries keep arriving as the shift runs.';
    body.innerHTML = shown.map(l => {
      const consequences = window.getSimulatedLogConsequences?.(l) || [];
      const assessment = window.ResponseModel?.assessLog(l, Object.values(window.shiftState?.effects || {}));
      const impactText = assessment?.status === 'observed-after-control'
        ? 'Matching activity observed after simulated control time; prevention is not inferred.'
        : assessment?.status === 'occurred-before-control'
          ? 'Event occurred before the matching simulated control.'
          : '';
      const impactNote = consequences.length || impactText
        ? `<small class="tk-impact-note">${Toolkit.esc(impactText || [...new Set(consequences.map(e => e.effect))].join(' '))}</small>`
        : '';
      return `
      <tr>
        <td class="mono">${Toolkit.esc(l.t)}</td>
        <td><span class="tk-src">${Toolkit.esc(l.src)}</span></td>
        <td data-q="${Toolkit.esc(l.host)}" class="tk-click">${Toolkit.esc(l.host)}</td>
        <td data-q="${Toolkit.esc(l.user)}" class="tk-click">${Toolkit.esc(l.user)}</td>
        <td>${Toolkit.linkify(Toolkit.esc(l.msg))}${impactNote}</td>
      </tr>`;
    }).join('') ||
      '<tr><td colspan="5" class="tk-empty">No log entries match. Absence of evidence is also a finding.</td></tr>';
  }

  // ---------------------------------------------------------------- IOC lookup
  ipHostMap() {
    const m = {};
    for (const a of this.scenario?.alerts || []) {
      const d = a.details || {};
      if (d.host_ip && a.host) m[d.host_ip] = a.host;
      if (d.src_ip && /^10\./.test(d.src_ip) && /-PC-/.test(a.host || '')) m[d.src_ip] ||= a.host;
    }
    return m;
  }

  findIoc(q) {
    const iocs = this.scenario?.iocs || {};
    for (const [k, v] of Object.entries(iocs)) {
      const key = k.toLowerCase();
      if (key === q) return { key: k, ...v };
      if (/^[a-f0-9]{12,}$/.test(q) && key.startsWith(q)) return { key: k, ...v };
    }
    return null;
  }

  lookupIoc(raw) {
    const out = this.$('tk-ioc-out');
    if (!this.scenario) { out.innerHTML = '<div class="tk-empty">No active shift.</div>'; return; }
    const q = this.norm(raw);
    if (!q) return;
    this.track('ioc_lookup', q);

    const hit = this.findIoc(q);
    const needle = /^[a-f0-9]{16,}$/.test(q) ? q.slice(0, 16) : q;
    const seen = this.visibleLogs().filter(l => `${l.host} ${l.user} ${l.msg}`.toLowerCase().includes(needle)).length;
    const internal = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(q);
    const host = internal ? this.ipHostMap()[q] : null;

    let rep = 'unknown', type = 'indicator', note = 'No intelligence available for this indicator. ' +
      'No reports does not mean it is safe — correlate with logs and alert context.';
    if (hit) { rep = hit.reputation; type = hit.type; note = hit.note; }
    else if (internal) { rep = 'internal'; type = 'ip'; note = `Internal address${host ? `, seen in alerts as ${host}` : ''}. Not an external threat indicator.`; }

    out.innerHTML = `
      <div class="tk-card">
        <div class="tk-card-top">
          <span class="mono tk-ind">${Toolkit.esc(hit ? hit.key : q)}</span>
          <span class="tk-rep rep-${Toolkit.esc(rep)}">${Toolkit.esc(rep)}</span>
        </div>
        <dl class="tk-dl">
          <dt>Type</dt><dd>${Toolkit.esc(type)}</dd>
          <dt>Assessment</dt><dd>${Toolkit.esc(note)}</dd>
          <dt>Seen in logs</dt><dd>${seen} entr${seen === 1 ? 'y' : 'ies'} so far</dd>
        </dl>
        <button type="button" class="tk-btn" data-logs="${Toolkit.esc(needle)}">Search logs for this</button>
      </div>`;
  }

  // ---------------------------------------------------------------- context
  renderContext() {
    const el = this.$('tk-ctx');
    const s = this.scenario;
    if (!s) { el.innerHTML = '<div class="tk-empty">No active shift.</div>'; return; }
    this.track('context_view', 'context');
    const ctx = s.context || {};
    const changes = ctx.change_calendar || [], notices = ctx.notices || [];
    const users = Object.entries(s.assets?.users || {});

    el.innerHTML = `
      <h4>Change calendar</h4>
      ${changes.length ? `<table class="tk-table"><thead><tr><th>ID</th><th>Description</th><th>Owner</th><th>Window</th></tr></thead><tbody>
        ${changes.map(c => `<tr><td class="mono">${Toolkit.esc(c.id)}</td><td>${Toolkit.esc(c.desc)}</td><td>${Toolkit.esc(c.owner)}</td><td>${Toolkit.esc(c.window)}</td></tr>`).join('')}
        </tbody></table>` : '<div class="tk-empty">No approved changes are scheduled for this window.</div>'}
      <h4>HR / IT notices</h4>
      ${notices.length ? `<ul class="tk-list">${notices.map(n => `<li>${Toolkit.linkify(Toolkit.esc(n))}</li>`).join('')}</ul>`
        : '<div class="tk-empty">No relevant notices on file.</div>'}
      <h4>Asset directory</h4>
      ${users.length ? `<table class="tk-table"><thead><tr><th>User</th><th>Workstation</th></tr></thead><tbody>
        ${users.map(([u, h]) => `<tr><td>${Toolkit.esc(u)}</td><td>${Toolkit.esc(h)}</td></tr>`).join('')}</tbody></table>`
        : '<div class="tk-empty">No user assets listed.</div>'}
      <h4>Simulated environment state</h4>
      ${Object.keys(window.shiftState?.effects || {}).length ? `<table class="tk-table"><thead><tr><th>Action</th><th>Target</th><th>Status</th><th>Recorded at</th></tr></thead><tbody>${Object.values(window.shiftState.effects).map(e => `<tr><td>${Toolkit.esc(e.type.replace(/_/g, ' '))}</td><td>${Toolkit.esc(e.target || '—')}</td><td><span class="tk-badge">${Toolkit.esc(e.status)}</span></td><td class="mono">${Toolkit.esc(e.at)}</td></tr>`).join('')}</tbody></table>` : '<div class="tk-empty">No simulated environment changes yet.</div>'}
      <h4>Simulated response ledger</h4>
      ${(window.shiftState?.actions || []).length ? `<ul class="tk-list">${[...window.shiftState.actions].reverse().map(a => `<li><b>${Toolkit.esc(a.type.replace(/_/g, ' '))}</b>${a.target ? ` · ${Toolkit.esc(a.target)}` : ''} — ${Toolkit.esc(a.effect || 'Action recorded in simulator.')}</li>`).join('')}</ul>` : '<div class="tk-empty">No response actions have been recorded in this shift.</div>'}
      <p class="tk-sub">These are stateful records inside the simulator only; they do not modify real infrastructure or suppress alerts unless a scenario explicitly implements that consequence.</p>`;
  }

  // ---------------------------------------------------------------- scenarios
  async loadIndex() {
    if (this.index) return this.index;
    const res = await fetch(this.indexUrl);
    if (!res.ok) throw new Error(`Cannot load ${this.indexUrl} (${res.status})`);
    this.index = await res.json();
    return this.index;
  }

  async renderScenarios() {
    const list = this.$('tk-sc-list');
    try { await this.loadIndex(); }
    catch (e) { list.innerHTML = `<div class="tk-empty">${Toolkit.esc(e.message)}</div>`; return; }

    const tier = this.$('tk-sc-tier').value, q = this.$('tk-sc-q').value.trim();
    const hints = this.$('tk-sc-hints').checked, current = this.scenario?.id;
    window.cybersimLearningMode = hints;
    const outcome = { false_positive: 'False positive', true_positive: 'True positive', escalation: 'Escalation', mixed: 'Mixed' };

    list.innerHTML = this.index
      .filter(s => (!tier || s.difficulty === tier) && (!q || s.id.includes(q) || s.title.includes(q)))
      .map(s => `
        <div class="tk-sc ${s.id === current ? 'current' : ''}" data-id="${Toolkit.esc(s.id)}" data-title="${Toolkit.esc(s.title)}">
          <div><b>${Toolkit.esc(s.title)}</b>
            <span class="tk-sub">${Toolkit.esc(s.difficulty)} · starts ${Toolkit.esc(s.startTime)}</span></div>
          <div>${hints ? `<span class="tk-badge">${Toolkit.esc(s.category)}</span><span class="tk-badge out-${Toolkit.esc(s.outcome)}">${outcome[s.outcome] || ''} · ${s.alerts} alert(s)</span>` : ''}
            ${s.id === current ? '<span class="tk-badge cur">Current</span>' : '<span class="tk-go">Start ▸</span>'}</div>
        </div>`).join('') || '<div class="tk-empty">No shifts match.</div>';
  }

  startScenario(id, title, force = false) {
    if (id === this.scenario?.id) return;
    if (!force && !confirm(`Start ${title}? Progress in the current shift will be lost.`)) return;
    try { localStorage.removeItem('cybersim.activeShift.v1'); } catch {}
    const u = new URL(location.href);
    u.searchParams.set('scenario', id);
    location.href = u.toString();
  }

  async startRandom(force = false) {
    await this.loadIndex();
    const pool = this.index.filter(s => s.id !== this.scenario?.id);
    const s = pool[Math.floor(Math.random() * pool.length)];
    this.startScenario(s.id, s.title, force);
  }

  // ---------------------------------------------------------------- response actions
  syncActionTarget() {
    const def = Toolkit.ACTIONS.find(a => a.id === this.$('tk-act').value);
    const input = this.$('tk-act-target');
    input.hidden = !def?.target;
    input.placeholder = def?.target || '';
  }

  renderResponse() {
    const sel = this.$('tk-act');
    if (!sel.options.length) {
      const groups = {};
      Toolkit.ACTIONS.forEach(a => (groups[a.group] = groups[a.group] || []).push(a));
      sel.innerHTML = Object.entries(groups).map(([g, items]) =>
        `<optgroup label="${g}">${items.map(a => `<option value="${a.id}">${Toolkit.esc(a.label)}</option>`).join('')}</optgroup>`).join('');
      sel.onchange = () => this.syncActionTarget();
    }
    this.syncActionTarget();
    const list = window.shiftState?.actions || [];
    const label = id => Toolkit.ACTIONS.find(a => a.id === id)?.label || id;
    this.$('tk-act-body').innerHTML = list.length
      ? [...list].reverse().map(a => `<tr><td class="mono">${Toolkit.esc(a.clock)}</td><td>${Toolkit.esc(label(a.type))}</td><td class="mono">${Toolkit.esc(a.target || '-')}<br><small>${Toolkit.esc(a.effect || 'Recorded in simulator.')}</small></td></tr>`).join('')
      : '<tr><td colspan="3" class="tk-empty">No response actions taken yet.</td></tr>';
    this.$('tk-act-go').disabled = this.ended;
  }

  executeAction() {
    const msg = this.$('tk-act-msg');
    const say = (text, ok = false) => { msg.textContent = text; msg.className = `tk-meta ${ok ? 'ok' : 'err'}`; };
    if (!this.scenario) return say('No active shift.');
    if (this.ended) return say('The shift has ended; no further actions can be taken.');

    const def = Toolkit.ACTIONS.find(a => a.id === this.$('tk-act').value);
    let target = this.$('tk-act-target').value.trim();
    if (def.target && !target) return say(`Enter a target (${def.target.toLowerCase()}).`);
    if (['block_ip', 'block_domain', 'block_hash'].includes(def.id)) target = this.norm(target);
    if (def.kind && !Toolkit.entityExists(this.scenario, target)) {
      return say(def.kind === 'host' ? `Host "${target}" was not found in the asset inventory.`
                                     : `Account "${target}" was not found in the directory.`);
    }

    const st = (window.shiftState = window.shiftState || {});
    const list = (st.actions = st.actions || []);
    const k = `${def.id}:${(target || '').toLowerCase()}`;
    if (list.some(a => `${a.type}:${(a.target || '').toLowerCase()}` === k)) return say('That action has already been executed.');
    if (def.confirm && !confirm(`${def.label}${target ? ` - ${target}` : ''}\n\nThis is a disruptive action. Continue?`)) return;

    const effectText = {
      block_ip: 'Simulated network-control action recorded for this indicator.',
      block_domain: 'Simulated domain-control action recorded for this indicator.',
      block_hash: 'Simulated file-control action recorded for this hash.',
      isolate_host: 'Simulated host-isolation decision recorded; no real host is affected.',
      disable_account: 'Simulated account-disable decision recorded; no real account is affected.',
      reset_password: 'Simulated password-reset decision recorded; no real account is changed.',
      revoke_sessions: 'Simulated session-revocation decision recorded; no real sessions are affected.',
      enforce_mfa: 'Simulated MFA-enforcement decision recorded; no real account is changed.',
      delete_email: 'Simulated email-removal decision recorded; no real mailbox is changed.',
      release_email: 'Simulated email-release decision recorded; no real mailbox is changed.',
      remove_inbox_rule: 'Simulated inbox-rule-removal decision recorded; no real mailbox is changed.',
      preserve_evidence: 'Evidence preservation recorded in the case timeline.',
      initiate_incident_response: 'Incident response declared in the simulated case timeline.'
    }[def.id] || `${def.label} recorded in the simulated case log.`;
    const action = { type: def.id, target: target || null, min: this.engine.minutes, clock: this.engine.clock, effect: effectText };
    list.push(action);
    window.applySimulatedAction?.(action);
    // Link Toolkit response actions to the currently selected incident when available.
    const activeAlertId = window.activeIncidentAlertId;
    if (activeAlertId && window.IncidentLifecycle) {
      try {
        window.IncidentLifecycle.recordAction(st, activeAlertId, action);
        window.dispatchEvent(new CustomEvent('soc:incident-updated', { detail: { alertId: activeAlertId } }));
      } catch (err) { console.warn('Incident action linkage:', err.message); }
    }
    window.saveShiftCheckpoint?.(true);
    this.$('tk-act-target').value = '';
    say(`Done: ${def.label}${target ? ` (${target})` : ''}.`, true);
    this.renderResponse();
  }

  // ---------------------------------------------------------------- shift end + report
  finishShift() {
    if (this.ended || !this.scenario) return;
    this.ended = true;
    this.engine.ended = true;
    if (this.engine.running) this.engine.pause();
    const st = window.shiftState || {};
    this.report = ShiftScoring.evaluate({
      scenario: this.scenario,
      released: (window.shiftState?.alerts || []).map(a => a.id),
      decisions: st.decisions || {},
      actions: st.actions || [],
      activity: st.activity || [],
      incidents: st.incidents || {},
    });
    this.saveHistory();
    try { localStorage.removeItem('cybersim.activeShift.v1'); } catch {}
    this.open('report');
  }

  exportReport() {
    if (!this.report || !this.scenario) return;
    const payload = {
      product: 'CyberSim SOC Simulator Pro',
      exportedAt: new Date().toISOString(),
      scenario: { id: this.scenario.id, title: this.scenario.title, difficulty: this.scenario.difficulty },
      score: this.report.total,
      grade: this.report.grade,
      categories: this.report.categories,
      weights: this.report.weights,
      lifecycleScore: this.report.lifecycle,
      findings: this.report.findings,
      alertReviews: this.report.rows.map(row => ({
        id: row.id, rule: row.rule, decision: row.decision,
        modelAnswer: row.truth, triageScore: row.triage,
        responseMinutes: row.responseMin, slaMinutes: row.sla,
        evidenceReviewed: row.investigated
      })),
      expectedActions: this.report.expected,
      responseTiming: {
        late: this.report.lateActions,
        premature: this.report.prematureActions
      },
      harmfulActions: this.report.harmful,
      unnecessaryActions: this.report.unnecessary,
      incidentLifecycle: { summary: window.IncidentLifecycle?.summary(window.shiftState || {}) || null, cases: window.shiftState?.incidents || {} },
      simulatedEffects: Object.values(window.shiftState?.effects || {}),
      responseActivity: (window.shiftState?.activity || []).filter(x => x.type === 'response_action'),
      responseImpact: window.ResponseModel?.assessLogs(
        (this.scenario.logs || []).map(log => ({ ...log, rel: this.rel(log.t) })),
        Object.values(window.shiftState?.effects || {})
      ) || null,
      disclaimer: 'Educational simulation result; response impact is rule-based interpretation of supplied logs, not proof of prevention or a full causal simulation.'
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybersim-report-${this.scenario.id}-${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  saveHistory() {
    try {
      const h = JSON.parse(localStorage.getItem('cybersim.history') || '[]');
      h.push({ id: this.scenario.id, score: this.report.total, grade: this.report.grade, at: Date.now() });
      localStorage.setItem('cybersim.history', JSON.stringify(h.slice(-200)));
    } catch (e) { /* storage unavailable */ }
  }

  historySummary() {
    try {
      const h = JSON.parse(localStorage.getItem('cybersim.history') || '[]');
      if (!h.length) return '';
      const avg = Math.round(h.reduce((a, x) => a + x.score, 0) / h.length);
      const scores = h.filter(x => x.id === this.scenario.id).map(x => x.score);
      const best = scores.length ? Math.max(...scores) : '—';
      return `Shifts completed: ${h.length} · Average score: ${avg} · Best on this shift: ${best}`;
    } catch (e) { return ''; }
  }

  renderReport() {
    const el = this.$('tk-report');
    const esc = Toolkit.esc;
    if (!this.scenario) { el.innerHTML = '<div class="tk-empty">No active shift.</div>'; return; }
    if (!this.report) {
      el.innerHTML = `<div class="tk-card"><p>The shift is still in progress. Triage your alerts, take response actions,
        then end the shift to receive your score and the model answer.</p>
        <button type="button" class="tk-btn" data-act="finish">End shift and view report</button></div>`;
      return;
    }

    const r = this.report, sc = this.scenario;
    const kind = { false_positive: 'False positive shift', true_positive: 'True positive shift', escalation: 'Escalation shift', mixed: 'Mixed shift' };
    const truthText = t => `${t.verdict}${t.verdict === 'TP' ? ` · ${t.severity}` : ''}${t.escalate ? ' · Escalate' : ''}`;
    const callText = d => (d ? `${d.verdict}${d.verdict === 'TP' ? ` · ${d.severity}` : ''}${d.escalate ? ' · Escalate' : ''}` : 'Not closed');
    const bar = (label, v, w) => `<div class="tk-bar"><div class="tk-bar-top"><span>${label} <small>(${Math.round(w * 100)}%)</small></span><b>${v}</b></div>
      <div class="tk-bar-track"><i style="width:${v}%"></i></div></div>`;

    el.innerHTML = `
      <div class="tk-score">
        <div class="tk-score-num grade-${r.grade}">${r.total}<small>/100</small><span>${r.grade}</span></div>
        <div class="tk-score-meta">
          <h3>${esc(sc.title)}</h3>
          <div class="tk-sub">${esc(kind[sc.outcome] || '')} · ${esc(sc.category)} · ${esc(sc.difficulty)}</div>
          <div class="tk-bars">
            ${bar('Triage accuracy', r.categories.triage, r.weights.triage)}
            ${bar('Response actions', r.categories.response, r.weights.response)}
            ${bar('Investigation', r.categories.investigation, r.weights.investigation)}
            ${bar('Speed (SLA)', r.categories.speed, r.weights.speed)}
            ${bar('Incident lifecycle', r.categories.lifecycle ?? 0, r.weights.lifecycle ?? 0)}
          </div>
        </div>
      </div>

      <h4>Key findings</h4>
      <ul class="tk-find">${r.findings.map(f => `<li class="f-${f.level}">${esc(f.text)}</li>`).join('') || '<li class="f-good">Nothing to report.</li>'}</ul>

      <h4>Incident lifecycle review</h4>
      <div class="tk-card">
        <p><b>Lifecycle quality:</b> ${r.lifecycle?.quality ?? 0}/100 · <b>Evidence items:</b> ${r.lifecycle?.evidenceCount ?? 0} · <b>Verified actions:</b> ${r.lifecycle?.verifiedCount ?? 0}</p>
        <p class="tk-sub">Only actions with explicit verification evidence count as verified. Incident status transitions are gated by evidence, verification, and residual-risk checks.</p>
        ${(Object.values(window.shiftState?.incidents || {}).filter(c => (window.shiftState?.alerts || []).some(a => a.id === c.alertId)).length)
          ? `<table class="tk-table"><thead><tr><th>Incident</th><th>Status</th><th>Evidence</th><th>Verified actions</th><th>Latest history</th></tr></thead><tbody>${Object.values(window.shiftState?.incidents || {}).filter(c => (window.shiftState?.alerts || []).some(a => a.id === c.alertId)).map(c => `<tr><td><span class="mono">${esc(c.alertId)}</span><br><small>${esc(c.title || '')}</small></td><td>${esc(c.status)}</td><td>${(c.evidence || []).length}</td><td>${(c.actions || []).filter(a => a.verified && String(a.verification || '').trim()).length}/${(c.actions || []).length}</td><td>${esc(c.history?.[c.history.length-1]?.reason || '—')}</td></tr>`).join('')}</tbody></table>`
          : '<p>No incident lifecycle cases were created during this shift.</p>'}
      </div>

      <h4>Recommended next practice</h4>
      <ul class="tk-list">${[
        ...(r.categories.triage < 80 ? ['Repeat a guided triage scenario and practise verdict, severity, and escalation decisions.'] : []),
        ...(r.categories.investigation < 80 ? ['Practise evidence-first investigations: review logs, IOC reputation, and host/user context before closing alerts.'] : []),
        ...(r.categories.response < 80 ? ['Review the response playbook and justify each disruptive action against the evidence.'] : []),
        ...(r.categories.speed < 80 ? ['Practise prioritising by severity and SLA while preserving investigation quality.'] : []),
        ...((r.categories.lifecycle ?? 0) < 80 ? ['Improve incident lifecycle quality: attach evidence to each alert, link response actions, verify outcomes, and document residual risk before closure.'] : []),
        ...(r.findings.some(f => f.level === 'critical') ? ['Replay a similar scenario in Learning Mode before attempting an independent assessment.'] : []),
        ...(!r.findings.some(f => f.level === 'critical') && r.total >= 80 ? ['Try a harder scenario tier and complete it without hints to check consistency.'] : [])
      ].map(x => `<li>${esc(x)}</li>`).join('') || '<li>Complete another shift to confirm this performance is consistent across different scenarios.</li>'}</ul>

      <h4>Alert review: your call vs. the model answer</h4>
      <table class="tk-table">
        <thead><tr><th>Alert</th><th>Your call</th><th>Model answer</th><th>Points</th><th>Time / SLA</th><th>Evidence</th></tr></thead>
        <tbody>${r.rows.map(x => `
          <tr>
            <td><span class="mono">${esc(x.id)}</span><br><small>${esc(x.rule)}</small></td>
            <td>${esc(callText(x.decision))}</td>
            <td>${esc(truthText(x.truth))}${x.mitre ? `<br><small class="mono">${esc(x.mitre)}</small>` : ''}</td>
            <td><b>${x.triage}</b>/100</td>
            <td>${x.responseMin === null ? '-' : `${x.responseMin.toFixed(1)} min`} / ${x.sla} min</td>
            <td>${x.investigated ? '<span class="tk-yes">Checked</span>' : '<span class="tk-no">None</span>'}</td>
          </tr>`).join('')}</tbody>
      </table>

      <h4>Recommended next practice</h4>
      <ul class="tk-find">
        ${r.categories.triage < 80 ? '<li class="f-warn">Practise verdict and severity selection: explain which evidence supports True Positive vs False Positive.</li>' : ''}
        ${r.categories.investigation < 80 ? '<li class="f-warn">Practise evidence-first triage: search logs, review IOC reputation, and check asset/user context before closing alerts.</li>' : ''}
        ${r.categories.response < 80 ? '<li class="f-warn">Review response playbooks and avoid disruptive actions until the target and evidence are verified.</li>' : ''}
        ${r.categories.speed < 80 ? '<li class="f-warn">Practise prioritising high-severity alerts and managing the SLA without skipping investigation.</li>' : ''}
        ${r.categories.triage >= 80 && r.categories.investigation >= 80 && r.categories.response >= 80 && r.categories.speed >= 80 ? '<li class="f-good">Good shift. Try a different scenario or a higher difficulty tier to test whether the skills transfer.</li>' : ''}
      </ul>

      <h4>Log-to-response assessment</h4>
      <p class="tk-sub">Rule-based correlation of supplied logs with simulated controls. Events remain in the log; this section does not claim that actions prevented activity.</p>
      ${(() => {
        const impact = window.ResponseModel?.assessLogs((sc.logs || []).map(log => ({ ...log, rel: this.rel(log.t) })), Object.values(window.shiftState?.effects || {}));
        if (!impact) return '<p class="tk-sub">Assessment engine unavailable.</p>';
        const m = impact.summary;
        return `<p class="tk-sub">${m.totalLogs} log events · ${m.observedAfterControl} matching events after control time · ${m.occurredBeforeControl} before control time · ${m.noMatchingControl} without a matching control</p>`;
      })()}

      <h4>Simulated response impact</h4>
      <p class="tk-sub">These are educational state changes only; no real endpoint, account, mailbox, or network control is contacted.</p>
      <ul class="tk-find">
        ${Object.values(window.shiftState?.effects || {}).map(e => `<li class="f-good"><b>${esc(e.status.replace(/_/g, ' '))}</b>${e.target ? ` · ${esc(e.target)}` : ''}: ${esc(e.effect)}</li>`).join('') || '<li class="f-warn">No response effects were recorded during this shift.</li>'}
      </ul>

      <h4>Response checklist & timing</h4>
      <p class="tk-sub">Timing is measured from the related alert's simulated release time. Items without a matched alert are scored for coverage only.</p>
      <ul class="tk-find">
        ${r.expected.map(e => {
          const timingLabel = e.timing === 'within-sla' ? ` · ${e.delayMin.toFixed(1)} min (within ${e.sla} min SLA)`
            : e.timing === 'late' ? ` · LATE: ${e.delayMin.toFixed(1)} min / ${e.sla} min SLA`
            : e.timing === 'premature' ? ` · before related alert by ${Math.abs(e.delayMin).toFixed(1)} min`
            : '';
          const cls = !e.met ? 'f-warn' : e.timing === 'late' || e.timing === 'premature' ? 'f-warn' : 'f-good';
          return `<li class="${cls}">${e.met ? 'Done' : 'Missing'}: ${esc(e.type.replace(/_/g, ' '))}${e.target ? ` ${esc(e.target)}` : ''}${esc(timingLabel)}${e.relatedAlertId ? ` · linked to ${esc(e.relatedAlertId)}` : ''}</li>`;
        }).join('')}
        ${r.harmful.map(a => `<li class="f-critical">Harmful: ${esc(a.type.replace(/_/g, ' '))}${a.target ? ` ${esc(a.target)}` : ''}</li>`).join('')}
        ${r.unnecessary.map(a => `<li class="f-warn">Unnecessary: ${esc(a.type.replace(/_/g, ' '))}${a.target ? ` ${esc(a.target)}` : ''}</li>`).join('')}
      </ul>
        ${r.harmful.map(a => `<li class="f-critical">Harmful: ${esc(a.type.replace(/_/g, ' '))}${a.target ? ` ${esc(a.target)}` : ''}</li>`).join('')}
        ${r.unnecessary.map(a => `<li class="f-warn">Unnecessary: ${esc(a.type.replace(/_/g, ' '))}${a.target ? ` ${esc(a.target)}` : ''}</li>`).join('')}
      </ul>

      <div class="tk-foot">
        <span class="tk-sub">${esc(this.historySummary())}</span>
        <span><button type="button" class="tk-btn alt" data-act="export">Export report JSON</button>
        <button type="button" class="tk-btn" data-act="retry">Retry this shift</button>
        <button type="button" class="tk-btn alt" data-act="random">Random shift</button></span>
      </div>`;
  }

  // ---------------------------------------------------------------- auto-pivot links in alert details
  observeDetail() {
    let pending = false;
    const run = () => {
      pending = false;
      const el = document.getElementById('aq-detail');
      if (!el || el.hidden) return;
      obs.disconnect();
      try { this.linkifyNode(el); } finally { obs.observe(document.body, { childList: true, subtree: true }); }
    };
    const obs = new MutationObserver(() => { if (!pending) { pending = true; setTimeout(run, 60); } });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  linkifyNode(root) {
    const probe = Toolkit.pivotRe('i');
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: n => {
        const p = n.parentElement;
        if (!p || p.closest('a.tk-pivot, textarea, select, option, script, style, button')) return NodeFilter.FILTER_REJECT;
        return probe.test(n.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      },
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    for (const n of nodes) {
      const text = n.nodeValue, frag = document.createDocumentFragment();
      let last = 0;
      text.replace(Toolkit.pivotRe(), (m, off) => {
        frag.append(text.slice(last, off));
        const a = document.createElement('a');
        a.href = '#'; a.className = 'tk-pivot'; a.dataset.v = m; a.textContent = m;
        frag.append(a);
        last = off + m.length;
        return m;
      });
      frag.append(text.slice(last));
      n.replaceWith(frag);
    }
  }
}

window.Toolkit = Toolkit;
