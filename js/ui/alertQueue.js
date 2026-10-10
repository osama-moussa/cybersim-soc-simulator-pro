// js/ui/alertQueue.js — لوحة الـ Alert Queue + نموذج الـ triage

const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

class AlertQueueUI {
  constructor(engine, state = window.shiftState) {
    this.engine = engine;
    this.state = state;
    this.openId = null; // التنبيه المفتوح في التفاصيل

    engine.onAlert = a => this.onAlert(a);
    engine.onTick = t => this.onTick(t);
    engine.onEnd = () => this.onEnd();
  }

  // ---------- بناء الواجهة ----------
  mount() {
    const root = document.createElement('div');
    root.innerHTML = `
      <button id="aq-toggle" type="button">🛡 Alerts <span id="aq-badge">0</span></button>
      <aside id="aq-panel">
        <header class="aq-head">
          <div>
            <div class="aq-title">SHIFT CONSOLE</div>
            <div class="aq-sub" id="aq-scenario"></div>
          </div>
          <div class="aq-clock" id="aq-clock">--:--:--</div>
          <button id="aq-close" type="button" aria-label="Close">×</button>
        </header>
        <div class="aq-controls">
          <button id="aq-pause" type="button">⏸ Pause</button>
          <button id="aq-save" type="button" title="Save this shift and continue later">💾 Save shift</button>
          <label>Speed
            <select id="aq-speed">
              <option value="12000">Slow</option>
              <option value="6000" selected>Normal</option>
              <option value="2000">Fast</option>
              <option value="500">Turbo</option>
            </select>
          </label>
        </div>
        <div id="aq-list"></div>
        <div id="aq-detail" hidden></div>
      </aside>`;
    document.body.append(...root.children);

    this.$ = id => document.getElementById(id);
    this.$('aq-scenario').textContent = `${this.engine.scenario.title} · ${this.engine.scenario.difficulty || ''}`;

    this.$('aq-toggle').onclick = () => this.$('aq-panel').classList.toggle('open');
    this.$('aq-close').onclick = () => this.$('aq-panel').classList.remove('open');
    this.$('aq-pause').onclick = () => this.togglePause();
    this.$('aq-save').onclick = () => {
      const saved = window.saveShiftCheckpoint?.(true);
      if (saved) { this.$('aq-save').textContent = '✓ Saved'; setTimeout(() => { if (this.$('aq-save')) this.$('aq-save').textContent = '💾 Save shift'; }, 1600); }
    };
    this.$('aq-speed').onchange = e => this.engine.setSpeed(Number(e.target.value));
    this.$('aq-list').onclick = e => {
      const item = e.target.closest('.aq-item');
      if (item) this.openDetail(item.dataset.id);
    };

    this.$('aq-panel').classList.add('open');
    this.renderList();
  }

  // ---------- أحداث الـ engine ----------
  onAlert(alert) {
    this.state.addAlert(alert);
     window.soc?.addIncidentFromAlert(alert);
    this.renderList();
    this.updateBadge();
    this.$('aq-toggle').classList.add('flash');
    setTimeout(() => this.$('aq-toggle').classList.remove('flash'), 1500);
  }

  onTick({ clock }) {
    this.$('aq-clock').textContent = clock;
  }

  onEnd() {
    this.$('aq-clock').textContent += ' (ended)';
    this.$('aq-pause').disabled = true;
    console.log('Shift ended. Decisions:');
    console.table(this.state.decisions);
  }

  togglePause() {
    const btn = this.$('aq-pause');
    if (this.engine.running) { this.engine.pause(); btn.textContent = '▶ Resume'; }
    else { this.engine.resume(); btn.textContent = '⏸ Pause'; }
  }

  updateBadge() {
    this.$('aq-badge').textContent = this.state.openCount;
  }

  // ---------- القايمة ----------
  renderList() {
    const alerts = [...this.state.alerts].reverse(); // الأحدث فوق
    const briefing = `<div class="aq-brief"><b>Briefing</b><br>${esc(this.engine.scenario.briefing)}</div>`;

    const items = alerts.map(a => {
      const d = this.state.decisions[a.id];
      return `
        <div class="aq-item sev-${esc(a.severity.toLowerCase())} ${d ? 'closed' : ''}" data-id="${esc(a.id)}">
          <div class="aq-top">
            <span class="aq-id">${esc(a.id)}</span>
            <span class="aq-sev">${esc(a.severity)}</span>
            <span class="aq-time">${esc(a.releasedAt)}</span>
          </div>
          <div class="aq-rule">${esc(a.rule)}</div>
          <div class="aq-meta">${esc(a.source)} · ${esc(a.host)} · ${esc(a.user)}${a.details?.['Source IP'] ? ` · ${esc(a.details['Source IP'])}` : ''}</div>
          ${d ? `<span class="aq-done">Closed: ${esc(d.verdict)} / ${esc(d.severity)}${d.escalate ? ' / Escalated' : ''}</span>` : ''}
        </div>`;
    }).join('');

    this.$('aq-list').innerHTML = briefing +
      (items || '<div class="aq-empty">No alerts yet. Waiting for the shift to start…</div>');
    this.updateBadge();
  }

  // ---------- التفاصيل + القرار ----------
  openDetail(id) {
    const a = this.state.alerts.find(x => x.id === id);
    if (!a) return;
    this.openId = id;
    window.activeAlertId = id;
    const d = this.state.decisions[id];
    const sevs = ['Low', 'Medium', 'High', 'Critical'];

    this.$('aq-detail').innerHTML = `
      <button type="button" class="aq-back">← Back to queue</button>
      <h3>${esc(a.id)} — ${esc(a.rule)}</h3>
      <dl class="aq-dl">
        <dt>Rule</dt><dd>${esc(a.rule)}${a.ruleId ? ` (${esc(a.ruleId)})` : ''}</dd>
        <dt>Released</dt><dd>${esc(a.releasedAt)}</dd>
        <dt>Source</dt><dd>${esc(a.source)}</dd>
        <dt>Host</dt><dd>${esc(a.host)}</dd>
        <dt>User</dt><dd>${esc(a.user)}</dd>
        <dt>Initial severity</dt><dd>${esc(a.severity)}</dd>
      </dl>
      <div class="aq-summary">${esc(a.summary)}</div>
      ${window.cybersimLearningMode ? `<section class="aq-learning-tip" aria-label="Beginner investigation guide">
        <strong>Beginner investigation guide</strong>
        <ol>
          <li>Confirm what triggered the rule and check the severity/SLA.</li>
          <li>Review the host, user, and approved change notices.</li>
          <li>Search relevant logs and look up indicators before deciding.</li>
          <li>Correlate related alerts; document your evidence and rationale.</li>
          <li>Choose a verdict and escalate if the evidence or impact warrants it.</li>
        </ol>
        <small>Guidance only — it does not reveal the model answer.</small>
      </section>` : ''}
      <h4 class="aq-sub-h">Alert details</h4>
      <dl class="aq-dl">
        ${Object.entries(a.details || {}).map(([k, v]) =>
          `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}
      </dl>

      <fieldset ${d ? 'disabled' : ''}>
        <legend>Your decision</legend>
        <div class="aq-row">
          <label><input type="radio" name="verdict" value="TP" ${d?.verdict === 'TP' ? 'checked' : ''}> True Positive</label>
          <label><input type="radio" name="verdict" value="FP" ${d?.verdict === 'FP' ? 'checked' : ''}> False Positive</label>
        </div>
        <div class="aq-row">
          <label>Severity
            <select name="severity">
              ${sevs.map(s => `<option ${s === (d?.severity || a.severity) ? 'selected' : ''}>${s}</option>`).join('')}
            </select>
          </label>
          <label><input type="checkbox" name="escalate" ${d?.escalate ? 'checked' : ''}> Escalate to Tier 2</label>
        </div>
        <textarea name="note" rows="3" placeholder="Analyst notes (what evidence did you use?)">${esc(d?.note || '')}</textarea>
        <button type="button" class="aq-submit">Close alert</button>
        <div class="aq-error" hidden></div>
      </fieldset>`;

    const detail = this.$('aq-detail');
    detail.querySelector('.aq-back').onclick = () => this.closeDetail();
    detail.querySelector('.aq-submit').onclick = () => this.submitDecision(a);
    detail.hidden = false;
    window.ActionsPanel?.mount(detail, a);
    window.AlertBrief?.mount(detail, a);
    window.AlertMeta?.mount(detail, a);
    window.AlertRelated?.mount(detail, a);
    window.AlertTimeline?.mount(detail, a);
    this.$('aq-list').hidden = true;
  }

  closeDetail() {
    this.openId = null;
    window.activeAlertId = null;
    this.$('aq-detail').hidden = true;
    this.$('aq-list').hidden = false;
    this.renderList();
  }

  submitDecision(alert) {
    const detail = this.$('aq-detail');
    const verdict = detail.querySelector('input[name="verdict"]:checked')?.value;
    const err = detail.querySelector('.aq-error');

    if (!verdict) {
      err.textContent = 'Choose True Positive or False Positive first.';
      err.hidden = false;
      return;
    }

    this.state.decide(alert.id, {
      verdict,
      severity: detail.querySelector('select[name="severity"]').value,
      escalate: detail.querySelector('input[name="escalate"]').checked,
      note: detail.querySelector('textarea[name="note"]').value.trim(),
      decidedAt: this.engine.clock,
      responseMin: Math.max(0, +(this.engine.minutes - alert.at).toFixed(1)),
    });
        window.soc?.closeIncident(alert.id);
    window.saveShiftCheckpoint?.(true);
    this.closeDetail();
  }
}

window.AlertQueueUI = AlertQueueUI;
