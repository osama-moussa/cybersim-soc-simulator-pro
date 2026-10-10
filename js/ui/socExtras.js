// js/ui/socExtras.js — realism extras, installed by wrapping AlertQueueUI methods (no edits to alertQueue.js).
//  1) Queue: filter (All/Open/Closed), sort (Newest/Severity/SLA left), SLA badge, "xN" duplicate badge.
//  2) Alert detail: small "Asset & user" card (from scenario.assets only; never reads alert.truth).
//  3) Escalation: escalating to Tier 2 requires a handover note (min 20 chars).
// If AlertQueueUI or a method is missing/renamed, the matching feature is skipped (see console warnings).

(() => {
  const Q = window.AlertQueueUI;
  if (!Q || !Q.prototype) { console.warn('[socExtras] AlertQueueUI not found; nothing installed.'); return; }
  const P = Q.prototype;

  if (!document.getElementById('sx-style')) {
    const style = document.createElement('style');
    style.id = 'sx-style';
    style.textContent = `
      .sx-bar { display: flex; gap: .6rem; align-items: center; margin: 0 0 .7rem; font-size: .78rem; color: #94a3b8; flex-wrap: wrap; }
      .sx-sla, .sx-grp { font-size: .68rem; font-weight: 700; padding: 1px 7px; border-radius: 999px; background: #334155; font-family: ui-monospace, Consolas, monospace; }
      .sx-sla.warn { background: #b45309; color: #fff; }
      .sx-sla.bad { background: #b91c1c; color: #fff; }
      .sx-grp { background: #6d28d9; color: #fff; margin-left: .4rem; }
      .sx-card { margin: 1rem 0; padding: .7rem 1rem; border: 1px solid var(--border, #475569); border-radius: 8px;
                 background: rgba(15, 23, 42, .5); font-size: .85rem; line-height: 1.7; }
      .sx-card h4 { margin: 0 0 .3rem; font-size: .85rem; letter-spacing: .04em; text-transform: uppercase; color: var(--accent, #06b6d4); }
      .sx-card .k { color: var(--text-muted, #94a3b8); display: inline-block; min-width: 11rem; }
      .sx-card .w { color: #fbbf24; }
    `;
    document.head.appendChild(style);
  }

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const SEV = { Critical: 3, High: 2, Medium: 1, Low: 0 };
  const FALLBACK_SLA = { Critical: 15, High: 30, Medium: 60, Low: 120 };
  const slaOf = a => ((typeof ShiftScoring !== 'undefined' && ShiftScoring.SLA) ? ShiftScoring.SLA : FALLBACK_SLA)[a.severity] ?? 120;
  const engine = () => window.toolkit?.engine || null;
  const alertById = id => (window.shiftState?.alerts || []).find(a => a.id === id);
  const leftMin = a => {
    const e = engine();
    return (e && typeof a?.at === 'number') ? slaOf(a) - (e.minutes - a.at) : null;
  };

  // ------------------------------------------------------------------ 1) queue
  let fFilter = 'all', fSort = 'new';

  function paintBadge(el) {
    const a = alertById(el.dataset.id);
    const left = a ? leftMin(a) : null;
    if (left === null) { el.textContent = ''; return; }
    el.textContent = left >= 0 ? `${Math.ceil(left)}m` : 'BREACH';
    el.className = `sx-sla ${left < 0 ? 'bad' : left < slaOf(a) * 0.25 ? 'warn' : ''}`;
  }

  function applyView(list) {
    const items = [...list.querySelectorAll('.aq-item')];
    const info = item => {
      const a = alertById(item.dataset.id);
      return { item, a, closed: item.classList.contains('closed'), idx: Number(item.dataset.sxIdx) };
    };
    const rows = items.map(info);
    rows.forEach(r => { r.item.style.display = (fFilter === 'open' && r.closed) || (fFilter === 'closed' && !r.closed) ? 'none' : ''; });
    const cmp = {
      new: (x, y) => x.idx - y.idx,
      sev: (x, y) => (x.closed - y.closed) || ((SEV[y.a?.severity] ?? 0) - (SEV[x.a?.severity] ?? 0)) || (x.idx - y.idx),
      sla: (x, y) => (x.closed - y.closed) || ((leftMin(x.a) ?? 1e9) - (leftMin(y.a) ?? 1e9)),
    }[fSort];
    rows.sort(cmp).forEach(r => list.appendChild(r.item));
  }

  function enhanceList(ui) {
    const list = document.getElementById('aq-list');
    if (!list) return;
    const items = [...list.querySelectorAll('.aq-item')];
    if (!items.length) return;

    const counts = {};
    const open = items.filter(i => !i.classList.contains('closed'));
    open.forEach(i => { const a = alertById(i.dataset.id); if (a) { const k = `${a.rule}|${a.host}`; counts[k] = (counts[k] || 0) + 1; } });

    items.forEach((item, idx) => {
      item.dataset.sxIdx = idx;
      if (item.classList.contains('closed')) return;
      const a = alertById(item.dataset.id);
      const top = item.querySelector('.aq-top');
      if (top) { const b = document.createElement('span'); b.className = 'sx-sla'; b.dataset.id = item.dataset.id; paintBadge(b); top.appendChild(b); }
      const n = a ? counts[`${a.rule}|${a.host}`] : 0;
      if (n > 1) { const g = document.createElement('span'); g.className = 'sx-grp'; g.textContent = `x${n}`; g.title = 'Open alerts with the same rule on the same host'; item.querySelector('.aq-rule')?.appendChild(g); }
    });

    const bar = document.createElement('div');
    bar.className = 'sx-bar';
    bar.innerHTML = `
      <label>Show <select data-k="f"><option value="all">All</option><option value="open">Open</option><option value="closed">Closed</option></select></label>
      <label>Sort <select data-k="s"><option value="new">Newest</option><option value="sev">Severity</option><option value="sla">SLA left</option></select></label>`;
    bar.querySelector('[data-k="f"]').value = fFilter;
    bar.querySelector('[data-k="s"]').value = fSort;
    bar.onchange = e => {
      if (e.target.dataset.k === 'f') fFilter = e.target.value;
      if (e.target.dataset.k === 's') fSort = e.target.value;
      applyView(list);
    };
    const brief = list.querySelector('.aq-brief');
    if (brief) brief.after(bar); else list.prepend(bar);
    applyView(list);
  }

  if (typeof P.renderList === 'function') {
    const orig = P.renderList;
    P.renderList = function (...args) {
      const r = orig.apply(this, args);
      try { enhanceList(this); } catch (e) { console.warn('[socExtras] queue enhance failed:', e); }
      return r;
    };
    setInterval(() => {
      const list = document.getElementById('aq-list');
      if (!list || list.hidden) return;
      list.querySelectorAll('.sx-sla').forEach(paintBadge);
      if (fSort === 'sla') applyView(list);
    }, 3000);
  } else console.warn('[socExtras] renderList not found; queue extras skipped.');

  // ------------------------------------------------------------------ 2) asset & user card
  function assetCard(alert) {
    const sc = window.toolkit?.scenario;
    const assets = sc?.assets || {};
    const hosts = (assets.hosts || []).map(h => String(h).toLowerCase());
    const users = assets.users || {};
    const uKey = Object.keys(users).find(u => u.toLowerCase() === String(alert.user || '').toLowerCase());
    const ws = uKey ? users[uKey] : null;
    const host = String(alert.host || '');
    const same = (window.shiftState?.alerts || []).filter(a => a.id !== alert.id && (
      (host && a.host === host) || (alert.user && alert.user !== 'n/a' && a.user === alert.user)));
    const openN = same.filter(a => !window.shiftState.decisions[a.id]).length;

    const rows = [];
    rows.push(['Host in asset inventory', hosts.length ? (hosts.includes(host.toLowerCase()) ? 'Yes' : '<span class="w">Not found</span>') : 'No inventory loaded']);
    if (uKey) {
      const match = String(ws).toLowerCase() === host.toLowerCase();
      rows.push(['User registered workstation', `${esc(ws)}${match ? '' : ' <span class="w">(different from alert host)</span>'}`]);
    } else if (alert.user && alert.user !== 'n/a') {
      rows.push(['User registered workstation', '<span class="w">User not found in directory</span>']);
    }
    rows.push(['Other alerts, same host/user', `${same.length} (${openN} still open)`]);

    const el = document.createElement('section');
    el.className = 'sx-card';
    el.setAttribute('data-sx', '');
    el.innerHTML = `<h4>Asset &amp; user</h4>${rows.map(([k, v]) => `<div><span class="k">${esc(k)}</span>${v}</div>`).join('')}`;
    return el;
  }

  if (typeof P.openDetail === 'function') {
    const orig = P.openDetail;
    P.openDetail = function (id, ...rest) {
      const r = orig.call(this, id, ...rest);
      try {
        const detail = document.getElementById('aq-detail');
        const a = alertById(id);
        if (detail && a) {
          detail.querySelectorAll('[data-sx]').forEach(n => n.remove());
          const card = assetCard(a);
          const anchor = detail.querySelector('[data-am]') || detail.querySelector('h3');
          if (anchor) anchor.after(card);
        }
      } catch (e) { console.warn('[socExtras] asset card failed:', e); }
      return r;
    };
  } else console.warn('[socExtras] openDetail not found; asset card skipped.');

  // ------------------------------------------------------------------ 3) escalation needs a handover note
  if (typeof P.submitDecision === 'function') {
    const orig = P.submitDecision;
    P.submitDecision = function (alert, ...rest) {
      const detail = document.getElementById('aq-detail');
      const esc2 = detail?.querySelector('input[name="escalate"]')?.checked;
      const note = detail?.querySelector('textarea[name="note"]')?.value.trim() || '';
      if (esc2 && note.length < 20) {
        const err = detail.querySelector('.aq-error');
        if (err) {
          err.textContent = 'Escalating to Tier 2 needs a handover note (what happened, what you checked, why you escalate) - at least 20 characters.';
          err.hidden = false;
        }
        return;
      }
      return orig.call(this, alert, ...rest);
    };
  } else console.warn('[socExtras] submitDecision not found; escalation rule skipped.');
})();
