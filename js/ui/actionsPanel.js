// js/ui/actionsPanel.js — Response actions inside the alert detail view.
// Read-only dependency on Toolkit (Toolkit.ACTIONS, Toolkit.entityExists, toolkit.norm).
// Stores actions in window.shiftState.actions, exactly like the Toolkit "Response" tab,
// so scoring.js and the Report keep working unchanged.

(() => {
  // ---------------------------------------------------------------- styles (self-contained)
  if (!document.getElementById('ap-style')) {
    const style = document.createElement('style');
    style.id = 'ap-style';
    style.textContent = `
      .ap-box { margin: 1rem 0; padding: .9rem 1rem; border: 1px solid var(--border, #475569);
                border-radius: 8px; background: rgba(15, 23, 42, .5); }
      .ap-h { margin: 0 0 .6rem; font-size: .85rem; letter-spacing: .04em; text-transform: uppercase;
              color: var(--accent, #06b6d4); }
      .ap-row { display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }
      .ap-row select, .ap-row input { background: var(--bg-primary, #0f172a); color: var(--text, #f8fafc);
              border: 1px solid var(--border, #475569); border-radius: 6px; padding: .45rem .6rem; font: inherit; }
      .ap-row select { min-width: 230px; }
      .ap-row input { flex: 1; min-width: 180px; font-family: Monaco, monospace; font-size: .85rem; }
      .ap-go { background: var(--primary, #3b82f6); color: #fff; border: 0; border-radius: 6px;
               padding: .5rem 1rem; font-weight: 600; cursor: pointer; }
      .ap-go:disabled { opacity: .45; cursor: not-allowed; }
      .ap-msg { min-height: 1.2em; margin-top: .5rem; font-size: .85rem; }
      .ap-msg.ok { color: var(--success, #10b981); }
      .ap-msg.err { color: var(--danger, #ef4444); }
      .ap-hint { margin-top: .4rem; font-size: .75rem; color: var(--text-muted, #94a3b8); }
      .ap-log { margin-top: .6rem; font-size: .8rem; }
      .ap-log div { display: flex; gap: .75rem; padding: .2rem 0; border-top: 1px solid rgba(71, 85, 105, .5); }
      .ap-log .t { font-family: Monaco, monospace; color: var(--text-muted, #94a3b8); }
      .ap-log .x { font-family: Monaco, monospace; color: var(--accent, #06b6d4); }
    `;
    document.head.appendChild(style);
  }

  // ---------------------------------------------------------------- helpers
  const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
  let seq = 0;

  const tk = () => window.toolkit;
  const esc = s => Toolkit.esc(s);
  const norm = v => (tk() && typeof tk().norm === 'function')
    ? tk().norm(v)
    : String(v || '').trim().toLowerCase();
  const key = (type, target) => `${type}:${String(target || '').toLowerCase()}`;

  /** Entities that appear on the alert; used only as autocomplete suggestions (nothing is pre-selected). */
  function entities(alert) {
    const out = new Set();
    const add = v => {
      const s = String(v ?? '').trim();
      if (s && s.toLowerCase() !== 'n/a' && s.length < 90) out.add(s);
    };
    const hostOfUrl = u => {
      try { return new URL(String(u).replace(/^hxxp/i, 'http')).hostname; } catch { return null; }
    };
    const afterAt = e => (String(e).includes('@') ? String(e).split('@').pop() : null);

    add(alert.host);
    add(alert.user);
    const d = alert.details || {};
    for (const k of ['src_ip', 'dst_ip', 'host_ip', 'first_ip']) {
      if (IPV4.test(String(d[k] ?? ''))) add(d[k]);
    }
    if (d.domain) add(d.domain);
    if (d.file_hash) add(d.file_hash);
    if (d.target_account) add(d.target_account);
    if (d.performed_by) add(d.performed_by);
    if (d.destination) add(d.destination);
    if (d.url) add(hostOfUrl(d.url));
    if (d.sender) add(afterAt(d.sender));
    if (d.forward_to) add(afterAt(d.forward_to));
    return [...out];
  }

  // ---------------------------------------------------------------- render
  function actionOptions() {
    const groups = {};
    Toolkit.ACTIONS.forEach(a => (groups[a.group] = groups[a.group] || []).push(a));
    return Object.entries(groups).map(([g, items]) =>
      `<optgroup label="${esc(g)}">${items.map(a => `<option value="${a.id}">${esc(a.label)}</option>`).join('')}</optgroup>`
    ).join('');
  }

  function renderLog(root, ents) {
    const mine = new Set(ents.map(e => e.toLowerCase()));
    const list = (window.shiftState?.actions || []).filter(a => a.target && mine.has(String(a.target).toLowerCase()));
    const label = id => Toolkit.ACTIONS.find(a => a.id === id)?.label || id;
    root.querySelector('.ap-log').innerHTML = list.length
      ? [...list].reverse().map(a =>
          `<div><span class="t">${esc(a.clock)}</span><span>${esc(label(a.type))}</span><span class="x">${esc(a.target)}</span></div>`).join('')
      : '';
  }

  function syncTarget(root) {
    const def = Toolkit.ACTIONS.find(a => a.id === root.querySelector('.ap-act').value);
    const input = root.querySelector('.ap-target');
    input.hidden = !def?.target;
    input.placeholder = def?.target || '';
  }

  // ---------------------------------------------------------------- execute (same rules as Toolkit.executeAction)
  function execute(root, ents, alert) {
    const t = tk();
    const msg = root.querySelector('.ap-msg');
    const say = (text, ok = false) => { msg.textContent = text; msg.className = `ap-msg ${ok ? 'ok' : 'err'}`; };

    if (!t || !t.scenario) return say('No active shift.');
    if (t.ended) return say('The shift has ended; no further actions can be taken.');

    const def = Toolkit.ACTIONS.find(a => a.id === root.querySelector('.ap-act').value);
    let target = root.querySelector('.ap-target').value.trim();
    if (def.target && !target) return say(`Enter a target (${def.target.toLowerCase()}).`);
    if (['block_ip', 'block_domain', 'block_hash'].includes(def.id)) target = norm(target);
    if (def.kind && !Toolkit.entityExists(t.scenario, target)) {
      return say(def.kind === 'host'
        ? `Host "${target}" was not found in the asset inventory.`
        : `Account "${target}" was not found in the directory.`);
    }

    const st = (window.shiftState = window.shiftState || {});
    const list = (st.actions = st.actions || []);
    if (list.some(a => key(a.type, a.target) === key(def.id, target))) return say('That action has already been executed.');
    if (def.confirm && !confirm(`${def.label}${target ? ` - ${target}` : ''}\n\nThis is a disruptive action. Continue?`)) return;

    const action = { type: def.id, target: target || null, min: t.engine.minutes, clock: t.engine.clock };
    list.push(action);
    window.applySimulatedAction?.(action);
    // Keep the per-alert case ledger in sync with the global response-action ledger.
    if (alert?.id && window.IncidentLifecycle) {
      try {
        window.IncidentLifecycle.recordAction(st, alert.id, action);
        window.dispatchEvent(new CustomEvent('soc:incident-updated', { detail: { alertId: alert.id } }));
      } catch (err) { console.warn('Incident action linkage:', err.message); }
    }
    window.saveShiftCheckpoint?.(true);
    root.querySelector('.ap-target').value = '';
    say(`Done: ${def.label}${target ? ` (${target})` : ''}.`, true);
    renderLog(root, ents);
    try { t.renderResponse(); } catch { /* Toolkit tab not mounted yet: ignore */ }
  }

  // ---------------------------------------------------------------- public API
  function mount(detailEl, alert) {
    if (!detailEl || !alert) return;
    detailEl.querySelectorAll('[data-ap]').forEach(n => n.remove());

    const ents = entities(alert);
    const listId = `ap-ents-${++seq}`;
    const root = document.createElement('section');
    root.className = 'ap-box';
    root.setAttribute('data-ap', '');
    root.innerHTML = `
      <h4 class="ap-h">Response actions</h4>
      <div class="ap-row">
        <select class="ap-act">${actionOptions()}</select>
        <input class="ap-target" type="text" list="${listId}" autocomplete="off" placeholder="Target">
        <button type="button" class="ap-go">Execute</button>
      </div>
      <datalist id="${listId}">${ents.map(e => `<option value="${esc(e)}"></option>`).join('')}</datalist>
      <div class="ap-msg"></div>
      <div class="ap-hint">Type the target yourself; suggestions only list entities seen on this alert. Actions are shared with the Toolkit &rarr; Response tab.</div>
      <div class="ap-log"></div>`;

    const fieldset = detailEl.querySelector('fieldset');
    if (fieldset) fieldset.before(root); else detailEl.append(root);

    root.querySelector('.ap-act').onchange = () => syncTarget(root);
    root.querySelector('.ap-go').onclick = () => execute(root, ents, alert);
    root.querySelector('.ap-target').addEventListener('keydown', e => { if (e.key === 'Enter') execute(root, ents, alert); });
    syncTarget(root);
    renderLog(root, ents);
  }

  window.ActionsPanel = { mount };
})();
