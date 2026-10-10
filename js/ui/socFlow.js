// js/ui/socFlow.js — three workflow realism features, built only on data that already exists.
//  1) Shift handover: a briefing modal when the shift starts (engine is paused until "Start shift").
//  2) Alert updates: notifies when NEW log entries (Toolkit.visibleLogs) match an open alert's entities.
//  3) Approvals: disruptive response actions need a written justification (min 15 chars) = "Tier 2 approval request".
//     Implemented by wrapping window.confirm ONLY for messages that contain "disruptive action".
// Never reads alert.truth. Approvals are stored in window.shiftState.approvals (not used by scoring).

(() => {
  if (!document.getElementById('sf-style')) {
    const style = document.createElement('style');
    style.id = 'sf-style';
    style.textContent = `
      #sf-modal { position: fixed; inset: 0; z-index: 10002; background: rgba(2, 6, 23, .8); display: flex; align-items: center; justify-content: center; }
      .sf-box { width: min(640px, 92vw); background: #0f172a; color: #e2e8f0; border: 1px solid #334155; border-radius: 12px; padding: 22px 24px; box-shadow: 0 20px 60px rgba(0,0,0,.6); }
      .sf-box h2 { margin: 0 0 4px; font-size: 20px; }
      .sf-box h4 { margin: 16px 0 6px; font-size: 12px; letter-spacing: .06em; text-transform: uppercase; color: #22d3ee; }
      .sf-box p, .sf-box li { font-size: 14px; line-height: 1.6; }
      .sf-box ul { margin: 0; padding-left: 20px; }
      .sf-go { margin-top: 18px; background: #0ea5e9; color: #fff; border: 0; border-radius: 6px; padding: 10px 20px; font-weight: 700; cursor: pointer; }
      #sf-stack { position: fixed; left: 300px; bottom: 90px; z-index: 9997; display: flex; flex-direction: column; gap: 8px; max-width: 360px; }
      .sf-toast { background: #1e293b; color: #e2e8f0; border: 1px solid #475569; border-left: 4px solid #0ea5e9; border-radius: 8px; padding: 10px 12px; font-size: 13px; line-height: 1.45; box-shadow: 0 6px 20px rgba(0,0,0,.45); }
      .sf-toast.ok { border-left-color: #10b981; }
      .sf-from { font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #94a3b8; margin-bottom: 3px; }
      .sf-row { display: flex; gap: 8px; margin-top: 8px; }
      .sf-row button { background: #334155; color: #e2e8f0; border: 0; border-radius: 6px; padding: 4px 10px; cursor: pointer; font-size: 12px; }
      .sf-row button.go { background: #0ea5e9; color: #fff; font-weight: 600; }
    `;
    document.head.appendChild(style);
  }

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const engine = () => window.toolkit?.engine || null;

  // ------------------------------------------------------------------ toast helper
  let stack = null;
  function toast({ from, text, id, kind }) {
    if (!stack || !stack.isConnected) { stack = document.createElement('div'); stack.id = 'sf-stack'; document.body.appendChild(stack); }
    const el = document.createElement('div');
    el.className = `sf-toast ${kind || ''}`;
    el.innerHTML = `<div class="sf-from">${esc(from)} &middot; ${esc(engine()?.clock || '')}</div><div>${esc(text)}</div>
      <div class="sf-row">${id ? '<button type="button" class="go">Open alert</button>' : ''}<button type="button" class="x">Dismiss</button></div>`;
    el.querySelector('.x').onclick = () => el.remove();
    const go = el.querySelector('.go');
    if (go) go.onclick = () => {
      document.getElementById('aq-panel')?.classList.add('open');
      document.querySelector('#aq-detail:not([hidden]) .aq-back')?.click();
      document.querySelector(`#aq-list .aq-item[data-id="${CSS.escape(id)}"]`)?.click();
      el.remove();
    };
    stack.appendChild(el);
    setTimeout(() => el.remove(), 30000);
  }

  // ------------------------------------------------------------------ 1) shift handover
  function showHandover() {
    const e = engine();
    const sc = window.toolkit?.scenario;
    if (!e || !sc) return;
    e.pause();
    const modal = document.createElement('div');
    modal.id = 'sf-modal';
    modal.innerHTML = `
      <div class="sf-box">
        <h2>Shift handover</h2>
        <div style="color:#94a3b8;font-size:13px">${esc(sc.title || '')} &middot; shift starts at ${esc(sc.startTime || '')}</div>
        <h4>From the outgoing analyst</h4>
        <p>${esc(sc.briefing || 'No special notes. Queue is clear at handover.')}</p>
        <h4>Ground rules for this shift</h4>
        <ul>
          <li>Work the queue by severity and remaining SLA (Critical 15 min, High 30, Medium 60, Low 120).</li>
          <li>Check evidence (logs, IOC lookup, context) before you close an alert.</li>
          <li>Escalate to Tier 2 with a written handover note; disruptive actions need a written justification.</li>
          <li>The shift runs 2 hours of shift time. Use Pause if you need a break.</li>
        </ul>
        <button type="button" class="sf-go">Start shift</button>
      </div>`;
    document.body.appendChild(modal);
    modal.querySelector('.sf-go').onclick = () => { modal.remove(); e.resume(); };
  }

  const boot = setInterval(() => {
    const e = engine();
    if (e && window.toolkit?.scenario) { clearInterval(boot); showHandover(); }
  }, 250);

  // ------------------------------------------------------------------ 2) alert updates (new related logs)
  const seen = {};        // alertId -> number of matching logs already counted
  const lastToast = {};   // alertId -> shift minute of last notification

  function entitiesOf(a) {
    const d = a.details || {};
    const vals = ['src_ip', 'dst_ip', 'host_ip', 'domain', 'file_hash'].map(k => String(d[k] ?? '').toLowerCase()).filter(v => v.length > 3 && v !== 'n/a');
    return { host: String(a.host || '').toLowerCase(), user: String(a.user || '').toLowerCase(), vals };
  }

  function checkUpdates() {
    const e = engine(), t = window.toolkit, st = window.shiftState;
    if (!e || !t || !st || !e.running || typeof t.visibleLogs !== 'function') return;
    let logs;
    try { logs = t.visibleLogs() || []; } catch { return; }
    for (const a of st.alerts || []) {
      if (st.decisions?.[a.id] || typeof a.at !== 'number') continue;
      const ent = entitiesOf(a);
      const hits = logs.filter(l => typeof l.rel === 'number' && l.rel > a.at + 0.01 && (
        (ent.host && String(l.host || '').toLowerCase() === ent.host) ||
        (ent.user && ent.user !== 'n/a' && String(l.user || '').toLowerCase() === ent.user) ||
        ent.vals.some(v => String(l.msg || '').toLowerCase().includes(v))));
      const prev = seen[a.id] ?? 0;
      seen[a.id] = hits.length;
      if (hits.length > prev && (lastToast[a.id] === undefined || e.minutes - lastToast[a.id] >= 10)) {
        lastToast[a.id] = e.minutes;
        toast({ from: 'SIEM update', id: a.id, text: `${a.id}: ${hits.length - prev} new log entr${hits.length - prev === 1 ? 'y' : 'ies'} now match this alert's host, user or indicators. Search the logs to review.` });
      }
    }
  }
  setInterval(checkUpdates, 5000);

  // ------------------------------------------------------------------ 3) approvals for disruptive actions
  const origConfirm = window.confirm.bind(window);
  window.confirm = msg => {
    if (!/disruptive action/i.test(String(msg))) return origConfirm(msg);
    const action = String(msg).split('\n')[0];
    const j = window.prompt(`Tier 2 approval request\n\nAction: ${action}\n\nWrite your justification (min 15 characters):`);
    if (j === null) return false;
    if (j.trim().length < 15) { window.alert('Approval denied: the justification is too short. Explain the evidence that requires this action.'); return false; }
    const st = (window.shiftState = window.shiftState || {});
    (st.approvals = st.approvals || []).push({ action, text: j.trim(), clock: engine()?.clock || '', min: engine()?.minutes ?? null });
    toast({ from: 'Tier 2 lead', kind: 'ok', text: `Approved: ${action}. Justification logged.` });
    return true;
  };

  window.SocFlow = { showHandover, checkUpdates };
})();
