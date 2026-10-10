// js/ui/alertMeta.js — Status / Assignee / SLA strip inside the alert detail view.
// Read-only: uses window.shiftState.decisions, window.toolkit.engine (clock) and ShiftScoring.SLA.
// SLA is based on the alert's INITIAL severity only (never reads alert.truth).
// Public API: AlertMeta.mount(detailEl, alert)

(() => {
  if (!document.getElementById('am-style')) {
    const style = document.createElement('style');
    style.id = 'am-style';
    style.textContent = `
      .am-strip { display: flex; gap: 1.2rem; flex-wrap: wrap; align-items: center; margin: .2rem 0 1rem;
                  padding: .6rem .9rem; border: 1px solid var(--border, #475569); border-radius: 8px;
                  background: rgba(15, 23, 42, .5); font-size: .85rem; }
      .am-item small { display: block; font-size: .68rem; text-transform: uppercase; letter-spacing: .05em;
                       color: var(--text-muted, #94a3b8); }
      .am-pill { display: inline-block; padding: 2px 10px; border-radius: 999px; font-weight: 700; font-size: .75rem;
                 background: #334155; }
      .am-pill.prog { background: rgba(59, 130, 246, .25); color: #93c5fd; }
      .am-pill.done { background: rgba(16, 185, 129, .25); color: #6ee7b7; }
      .am-sla { font-family: Monaco, ui-monospace, monospace; font-weight: 700; }
      .am-sla.ok { color: var(--success, #10b981); }
      .am-sla.warn { color: var(--warning, #f59e0b); }
      .am-sla.bad { color: var(--danger, #ef4444); }
    `;
    document.head.appendChild(style);
  }

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const FALLBACK_SLA = { Critical: 15, High: 30, Medium: 60, Low: 120 };
  const slaTable = () => (typeof ShiftScoring !== 'undefined' && ShiftScoring.SLA) ? ShiftScoring.SLA : FALLBACK_SLA;
  const engine = () => window.toolkit?.engine || null;

  let timer = null;

  function fmt(min) {
    const total = Math.round(Math.abs(min) * 60);
    const m = Math.floor(total / 60), s = total % 60;
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  }

  function mount(detailEl, alert) {
    if (!detailEl || !alert) return;
    clearInterval(timer);
    detailEl.querySelectorAll('[data-am]').forEach(n => n.remove());

    const sla = slaTable()[alert.severity] ?? 120;
    const root = document.createElement('div');
    root.className = 'am-strip';
    root.setAttribute('data-am', '');
    root.innerHTML = `
      <div class="am-item"><small>Status</small><span class="am-pill" data-f="status"></span></div>
      <div class="am-item"><small>Assignee</small>You (Tier 1)</div>
      <div class="am-item"><small>SLA target</small>${esc(sla)} min</div>
      <div class="am-item"><small>SLA</small><span class="am-sla" data-f="sla">--:--</span></div>`;

    const title = detailEl.querySelector('h3');
    if (title) title.after(root); else detailEl.prepend(root);

    const statusEl = root.querySelector('[data-f="status"]');
    const slaEl = root.querySelector('[data-f="sla"]');

    function refresh() {
      if (!root.isConnected) { clearInterval(timer); return; }
      const d = window.shiftState?.decisions?.[alert.id];
      statusEl.textContent = d ? 'Closed' : 'In Progress';
      statusEl.className = `am-pill ${d ? 'done' : 'prog'}`;

      const e = engine();
      if (d) {                                  // closed: freeze the timer, show the response time
        const rm = Number.isFinite(d.responseMin) ? d.responseMin : null;
        slaEl.textContent = rm === null ? 'closed' : `closed in ${rm.toFixed(1)} min`;
        slaEl.className = `am-sla ${rm !== null && rm > sla ? 'bad' : 'ok'}`;
        clearInterval(timer);
        return;
      }
      if (!e || typeof alert.at !== 'number') { slaEl.textContent = 'n/a'; slaEl.className = 'am-sla'; return; }
      const left = sla - (e.minutes - alert.at);
      slaEl.textContent = left >= 0 ? `${fmt(left)} left` : `BREACHED +${fmt(left)}`;
      slaEl.className = `am-sla ${left < 0 ? 'bad' : left < sla * 0.25 ? 'warn' : 'ok'}`;
    }

    refresh();
    timer = setInterval(refresh, 1000);
  }

  window.AlertMeta = { mount };
})();
