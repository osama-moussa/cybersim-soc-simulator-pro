// js/ui/askPeople.js — "Ask the people" box in alert detail + Tier 2 reply after escalation.
// New file only. Never shows alert.truth before the answer; replies are derived from it after you ask.
//  1) AskPeople.mount(detail, alert): buttons Ask user / Ask IT / Ask asset owner -> simulated reply (1.5s delay).
//  2) Wraps AlertQueueUI.prototype.submitDecision: after you escalate, Tier 2 answers (accepts, returns, or asks for missing info).
// Load AFTER socFlow.js in index.html.
(() => {
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const hash = s => { let h = 0; for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) >>> 0; return h; };

  if (!document.getElementById('ask-style')) {
    const st = document.createElement('style');
    st.id = 'ask-style';
    st.textContent = `
      .ask-box { margin: .8rem 0; padding: .7rem .9rem; border: 1px solid #334155; border-radius: 8px; background: #0f172a; }
      .ask-box h5 { margin: 0 0 .5rem; font-size: .85rem; color: #e2e8f0; }
      .ask-btns { display: flex; gap: .5rem; flex-wrap: wrap; }
      .ask-btns button { background: #1e293b; color: #e2e8f0; border: 1px solid #475569; border-radius: 6px; padding: .3rem .7rem; cursor: pointer; font-size: .8rem; }
      .ask-btns button:disabled { opacity: .5; cursor: default; }
      .ask-log { margin-top: .6rem; font-size: .8rem; color: #cbd5e1; display: grid; gap: .3rem; }
      .ask-log .q { color: #94a3b8; } .ask-log .a { padding-left: .8rem; border-left: 2px solid #475569; }
      .ask-t2 { position: fixed; right: 1rem; bottom: 1rem; z-index: 9999; max-width: 360px; background: #1e293b; color: #e2e8f0;
               border: 1px solid #475569; border-left: 4px solid #38bdf8; border-radius: 8px; padding: .7rem .9rem; font-size: .82rem; }
      .ask-t2.warn { border-left-color: #f59e0b; }`;
    document.head.appendChild(st);
  }

  const sh = () => window.shiftState || (window.shiftState = {});
  const asked = {}; // alertId -> [{who, q, a}]

  const WHO = {
    user: { label: 'Ask the user', q: a => `Hi ${a.user && a.user !== '-' ? a.user : ''}, did you perform this activity on ${a.host}? (${a.rule})` },
    it: { label: 'Ask IT / change mgmt', q: a => `Is there an approved change or maintenance task for ${a.host} matching "${a.rule}"?` },
    owner: { label: 'Ask asset owner', q: a => `Is ${a.host} expected to do this (service, scan, backup, job)?` },
  };

  function reply(who, a) {
    const tp = a.truth?.verdict === 'TP';
    const h = hash(a.id + who) % 6;
    if (h === 0) return who === 'it' ? 'No change ticket found, but I will double-check with the team and get back to you.' : 'Not sure, I will check and reply later.';
    if (who === 'it') return tp ? 'No approved change or maintenance for that host in this window.' : `Yes, this is covered by approved change CHG-${1000 + hash(a.id) % 9000}.`;
    if (who === 'user') return tp ? 'No, that was not me. I did not do this.' : 'Yes, that was me. It is part of my normal work.';
    return tp ? 'No, that host should not behave like this.' : 'Yes, that is expected for this host (scheduled job / known service).';
  }

  function mount(detail, a) {
    if (!detail || !a || detail.querySelector('.ask-box')) return;
    const box = document.createElement('div');
    box.className = 'ask-box';
    box.innerHTML = `<h5>Ask the people</h5><div class="ask-btns">${Object.entries(WHO).map(([k, v]) => `<button data-who="${k}">${esc(v.label)}</button>`).join('')}</div><div class="ask-log"></div>`;
    const log = box.querySelector('.ask-log');
    const draw = () => { log.innerHTML = (asked[a.id] || []).map(e => `<div class="q">You (${esc(e.who)}): ${esc(e.q)}</div><div class="a">${e.a ? esc(e.a) : '...typing'}</div>`).join(''); };
    box.querySelectorAll('button').forEach(b => b.addEventListener('click', () => {
      const who = b.dataset.who;
      if ((asked[a.id] || []).some(e => e.who === who)) return;
      const entry = { who, q: WHO[who].q(a), a: '' };
      (asked[a.id] = asked[a.id] || []).push(entry);
      b.disabled = true; draw();
      const s = sh(); (s.activity = s.activity || []).push({ type: 'contact', action: 'ask_' + who, query: entry.q, alertId: a.id, at: window.toolkit?.engine?.clock, min: window.toolkit?.engine?.minutes });
      setTimeout(() => { entry.a = reply(who, a); draw(); }, 1500);
    }));
    (asked[a.id] || []).forEach(e => { const b = box.querySelector(`[data-who="${e.who}"]`); if (b) b.disabled = true; });
    draw();
    const anchor = detail.querySelector('[data-am]') || detail.querySelector('h3');
    anchor ? anchor.after(box) : detail.prepend(box);
  }
  window.AskPeople = { mount };

  function t2(text, warn) {
    const el = document.createElement('div');
    el.className = 'ask-t2' + (warn ? ' warn' : '');
    el.innerHTML = `<b>Tier 2:</b> ${esc(text)}`;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 12000);
  }

  const Q = window.AlertQueueUI;
  if (Q?.prototype?.submitDecision) {
    const orig = Q.prototype.submitDecision;
    Q.prototype.submitDecision = function (alert, ...rest) {
      const d = document.getElementById('aq-detail');
      const wants = d?.querySelector('input[name="escalate"]')?.checked;
      const note = (d?.querySelector('textarea[name="note"]')?.value || '').toLowerCase();
      const r = orig.call(this, alert, ...rest);
      const dec = sh().decisions;
      const saved = Array.isArray(dec) ? dec.some(x => x.alertId === alert.id || x.id === alert.id) : !!dec?.[alert.id];
      if (wants && saved) {
        const ioc = alert.details?.src_ip || alert.details?.domain || alert.details?.hash || '';
        const missing = [];
        if (alert.host && !note.includes(String(alert.host).toLowerCase())) missing.push('affected host');
        if (ioc && !note.includes(String(ioc).toLowerCase())) missing.push('the IOC (' + ioc + ')');
        setTimeout(() => {
          if (missing.length) t2(`${alert.id}: your handover is missing ${missing.join(' and ')}. I need it to take this over.`, true);
          else if (alert.truth?.escalate) t2(`${alert.id}: accepted, I am taking ownership. Thanks for the clear handover.`);
          else t2(`${alert.id}: returned. This did not need Tier 2; please close it per the runbook.`, true);
        }, 3000);
      }
      return r;
    };
  } else console.warn('[askPeople] submitDecision not found; Tier 2 reply skipped.');
})();
