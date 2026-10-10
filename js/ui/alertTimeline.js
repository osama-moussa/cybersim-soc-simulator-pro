// js/ui/alertTimeline.js — "Timeline & notes" box inside the alert detail view.
// Builds a read-only timeline from data that already exists:
//   alert release time, investigation activity (shiftState.activity) and response actions
//   (shiftState.actions) that touch this alert's entities, and the closing decision.
// Plus quick analyst notes kept in memory (per shift + alert id). Never reads alert.truth.
// Public API: AlertTimeline.mount(detailEl, alert)

(() => {
  if (!document.getElementById('at-style')) {
    const style = document.createElement('style');
    style.id = 'at-style';
    style.textContent = `
      .at-box { margin: 1rem 0; padding: .9rem 1rem; border: 1px solid var(--border, #475569);
                border-radius: 8px; background: rgba(15, 23, 42, .5); }
      .at-h { margin: 0 0 .6rem; font-size: .85rem; letter-spacing: .04em; text-transform: uppercase;
              color: var(--accent, #06b6d4); }
      .at-list { font-size: .85rem; }
      .at-ev { display: flex; gap: .75rem; padding: .25rem 0; border-top: 1px solid rgba(71, 85, 105, .5); }
      .at-ev:first-child { border-top: 0; }
      .at-t { font-family: Monaco, ui-monospace, monospace; color: var(--text-muted, #94a3b8); min-width: 4.5rem; }
      .at-k { font-size: .7rem; text-transform: uppercase; letter-spacing: .04em; min-width: 5.5rem; color: var(--accent, #06b6d4); }
      .at-x { font-family: Monaco, ui-monospace, monospace; word-break: break-all; }
      .at-add { display: flex; gap: .5rem; margin-top: .7rem; }
      .at-add input { flex: 1; background: var(--bg-primary, #0f172a); color: var(--text, #f8fafc);
              border: 1px solid var(--border, #475569); border-radius: 6px; padding: .45rem .6rem; font: inherit; }
      .at-add button { background: var(--bg-card, #334155); color: var(--text, #f8fafc); border: 0; border-radius: 6px;
              padding: .45rem .9rem; font-weight: 600; cursor: pointer; }
    `;
    document.head.appendChild(style);
  }

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const notesStore = {};   // "<scenarioId>:<alertId>" -> [{min, clock, text}]
  const KEYS = ['src_ip', 'dst_ip', 'host_ip', 'first_ip', 'domain', 'file_hash',
                'email_from', 'email_to', 'target_account', 'performed_by', 'destination'];

  const engine = () => window.toolkit?.engine || null;
  const storeKey = alert => `${window.toolkit?.scenario?.id ?? 'shift'}:${alert.id}`;
  const LABEL = { log_search: 'Log search', ioc_lookup: 'IOC lookup', context_view: 'Context view' };
  const ACTION_LABEL = id => (typeof Toolkit !== 'undefined' && Toolkit.ACTIONS?.find(a => a.id === id)?.label) || id;

  function entities(a) {
    const set = new Set();
    const add = v => {
      const s = String(v ?? '').trim().toLowerCase();
      if (s && s !== 'n/a' && s.length < 120) set.add(s);
    };
    add(a.host); add(a.user);
    const d = a.details || {};
    KEYS.forEach(k => add(d[k]));
    return set;
  }

  function events(alert) {
    const st = window.shiftState || {};
    const ents = entities(alert);
    const touches = v => {
      const s = String(v ?? '').trim().toLowerCase();
      if (!s) return false;
      if (ents.has(s)) return true;
      for (const e of ents) if (e.length > 3 && s.includes(e)) return true;
      return false;
    };
    const out = [];
    out.push({ min: alert.at ?? 0, clock: alert.releasedAt || '', kind: 'Released', text: alert.rule });

    for (const x of (st.activity || [])) {
      if (typeof x.min === 'number' && typeof alert.at === 'number' && x.min < alert.at - 0.01) continue;
      if (touches(x.query)) out.push({ min: x.min ?? 0, clock: x.at || '', kind: LABEL[x.type] || x.type, text: x.query });
    }
    for (const x of (st.actions || [])) {
      if (x.target && touches(x.target)) out.push({ min: x.min ?? 0, clock: x.clock || '', kind: 'Action', text: `${ACTION_LABEL(x.type)} - ${x.target}` });
    }
    for (const n of (notesStore[storeKey(alert)] || [])) out.push({ min: n.min, clock: n.clock, kind: 'Note', text: n.text });

    const d = st.decisions?.[alert.id];
    if (d) {
      out.push({
        min: (alert.at ?? 0) + (Number.isFinite(d.responseMin) ? d.responseMin : 0) + 0.001,
        clock: d.decidedAt || '', kind: 'Closed',
        text: `${d.verdict} / ${d.severity}${d.escalate ? ' / Escalated to Tier 2' : ''}`,
      });
    }
    return out.sort((a, b) => a.min - b.min);
  }

  const renderList = evs => evs.map(e =>
    `<div class="at-ev"><span class="at-t">${esc(e.clock)}</span><span class="at-k">${esc(e.kind)}</span><span class="at-x">${esc(e.text)}</span></div>`).join('');

  function mount(detailEl, alert) {
    if (!detailEl || !alert) return;
    detailEl.querySelectorAll('[data-at]').forEach(n => n.remove());

    const root = document.createElement('section');
    root.className = 'at-box';
    root.setAttribute('data-at', '');
    root.innerHTML = `
      <h4 class="at-h">Timeline &amp; notes</h4>
      <div class="at-list"></div>
      <div class="at-add"><input class="at-in" type="text" placeholder="Add a quick note (e.g. SPF passes, sender is a known newsletter)"><button type="button" class="at-btn">Add note</button></div>`;

    const fieldset = detailEl.querySelector('fieldset');
    if (fieldset) fieldset.before(root); else detailEl.append(root);

    const list = root.querySelector('.at-list');
    let last = '';
    const refresh = () => {
      if (!root.isConnected) { clearInterval(timer); return; }
      const html = renderList(events(alert));
      if (html !== last) { list.innerHTML = html; last = html; }
    };

    const input = root.querySelector('.at-in');
    const add = () => {
      const text = input.value.trim();
      const e = engine();
      if (!text || !e) return;
      (notesStore[storeKey(alert)] = notesStore[storeKey(alert)] || []).push({ min: e.minutes, clock: e.clock, text });
      input.value = '';
      refresh();
    };
    root.querySelector('.at-btn').onclick = add;
    input.addEventListener('keydown', ev => { if (ev.key === 'Enter') add(); });

    refresh();
    const timer = setInterval(refresh, 1500);
  }

  window.AlertTimeline = { mount };
})();
