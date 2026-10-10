// js/ui/socMessages.js — SOC lead notifications built from the shift's own data (no scripted fake events).
//  - "SLA warning" when an open alert has used 60% of its SLA.
//  - "SLA breached" when the SLA runs out.
// Toasts appear bottom-left, auto-dismiss, and "Open alert" jumps to it. Never reads alert.truth.
// Uses window.toolkit.engine (minutes/running), window.shiftState, ShiftScoring.SLA.

(() => {
  if (!document.getElementById('sm-style')) {
    const style = document.createElement('style');
    style.id = 'sm-style';
    style.textContent = `
      #sm-stack { position: fixed; left: 300px; bottom: 20px; z-index: 9997; display: flex; flex-direction: column; gap: 8px; max-width: 360px; }
      .sm-toast { background: #1e293b; color: #e2e8f0; border: 1px solid #475569; border-left: 4px solid #f59e0b;
                  border-radius: 8px; padding: 10px 12px; font-size: 13px; line-height: 1.45; box-shadow: 0 6px 20px rgba(0,0,0,.45); }
      .sm-toast.bad { border-left-color: #ef4444; }
      .sm-from { font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #94a3b8; margin-bottom: 3px; }
      .sm-row { display: flex; gap: 8px; margin-top: 8px; }
      .sm-row button { background: #334155; color: #e2e8f0; border: 0; border-radius: 6px; padding: 4px 10px; cursor: pointer; font-size: 12px; }
      .sm-row button.go { background: #0ea5e9; color: #fff; font-weight: 600; }
    `;
    document.head.appendChild(style);
  }

  const FALLBACK_SLA = { Critical: 15, High: 30, Medium: 60, Low: 120 };
  const slaOf = a => ((typeof ShiftScoring !== 'undefined' && ShiftScoring.SLA) ? ShiftScoring.SLA : FALLBACK_SLA)[a.severity] ?? 120;
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  let stack = null;
  const fired = new Set();

  function ensureStack() {
    if (!stack || !stack.isConnected) {
      stack = document.createElement('div');
      stack.id = 'sm-stack';
      document.body.appendChild(stack);
    }
    return stack;
  }

  function openAlert(id) {
    document.getElementById('aq-panel')?.classList.add('open');
    document.querySelector('#aq-detail:not([hidden]) .aq-back')?.click();
    document.querySelector(`#aq-list .aq-item[data-id="${CSS.escape(id)}"]`)?.click();
  }

  function toast({ kind, id, text }) {
    const el = document.createElement('div');
    el.className = `sm-toast ${kind === 'bad' ? 'bad' : ''}`;
    el.innerHTML = `
      <div class="sm-from">SOC Lead &middot; ${esc(window.toolkit?.engine?.clock || '')}</div>
      <div>${esc(text)}</div>
      <div class="sm-row"><button type="button" class="go">Open alert</button><button type="button" class="x">Dismiss</button></div>`;
    el.querySelector('.go').onclick = () => { openAlert(id); el.remove(); };
    el.querySelector('.x').onclick = () => el.remove();
    ensureStack().appendChild(el);
    setTimeout(() => el.remove(), 30000);
  }

  function check() {
    const e = window.toolkit?.engine;
    const st = window.shiftState;
    if (!e || !st || !e.running || e.ended) return;
    for (const a of st.alerts || []) {
      if (st.decisions?.[a.id] || typeof a.at !== 'number') continue;
      const sla = slaOf(a);
      const used = e.minutes - a.at;
      if (used >= sla && !fired.has(`b:${a.id}`)) {
        fired.add(`b:${a.id}`);
        toast({ kind: 'bad', id: a.id, text: `${a.id} (${a.rule}) breached its ${sla}-minute SLA. What is the status?` });
      } else if (used >= sla * 0.6 && !fired.has(`w:${a.id}`)) {
        fired.add(`w:${a.id}`);
        toast({ kind: 'warn', id: a.id, text: `${a.id} (${a.rule}) is still open and has used 60% of its ${sla}-minute SLA.` });
      }
    }
  }

  setInterval(check, 4000);
  window.SocMessages = { check };
})();
