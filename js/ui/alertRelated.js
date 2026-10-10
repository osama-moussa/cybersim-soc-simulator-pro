// js/ui/alertRelated.js — "Related alerts" box inside the alert detail view.
// Lists OTHER alerts already released in this shift that share an entity with the open alert
// (host, user, IP, domain, hash, email address). Never reads alert.truth.
// Clicking a row goes back to the queue and opens that alert (uses the existing .aq-item click handler).
// Public API: AlertRelated.mount(detailEl, alert)

(() => {
  if (!document.getElementById('ar-style')) {
    const style = document.createElement('style');
    style.id = 'ar-style';
    style.textContent = `
      .ar-box { margin: 1rem 0; padding: .9rem 1rem; border: 1px solid var(--border, #475569);
                border-radius: 8px; background: rgba(15, 23, 42, .5); }
      .ar-h { margin: 0 0 .6rem; font-size: .85rem; letter-spacing: .04em; text-transform: uppercase;
              color: var(--accent, #06b6d4); }
      .ar-row { display: flex; gap: .75rem; align-items: baseline; flex-wrap: wrap; padding: .4rem .2rem;
                border-top: 1px solid rgba(71, 85, 105, .5); cursor: pointer; font-size: .85rem; }
      .ar-row:first-of-type { border-top: 0; }
      .ar-row:hover { background: rgba(59, 130, 246, .08); }
      .ar-row.closed { opacity: .6; }
      .ar-id { font-family: Monaco, ui-monospace, monospace; color: var(--accent, #06b6d4); }
      .ar-sev { font-weight: 600; }
      .ar-why { margin-left: auto; font-size: .75rem; color: var(--text-muted, #94a3b8); font-family: Monaco, ui-monospace, monospace; }
      .ar-none { font-size: .85rem; color: var(--text-muted, #94a3b8); }
    `;
    document.head.appendChild(style);
  }

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const KEYS = ['src_ip', 'dst_ip', 'host_ip', 'first_ip', 'domain', 'file_hash',
                'email_from', 'email_to', 'target_account', 'performed_by'];

  /** Map of normalized value -> label ("host", "user", "src_ip"...) */
  function entityMap(a) {
    const m = new Map();
    const add = (label, v) => {
      const s = String(v ?? '').trim().toLowerCase();
      if (s && s !== 'n/a' && s.length < 120 && !m.has(s)) m.set(s, label);
    };
    add('host', a.host);
    add('user', a.user);
    const d = a.details || {};
    KEYS.forEach(k => add(k, d[k]));
    return m;
  }

  function findRelated(alert) {
    const mine = entityMap(alert);
    const out = [];
    for (const other of (window.shiftState?.alerts || [])) {
      if (other.id === alert.id) continue;
      const theirs = entityMap(other);
      const shared = [];
      for (const [val, label] of theirs) if (mine.has(val)) shared.push(`${label}: ${val}`);
      if (shared.length) out.push({ alert: other, shared });
    }
    return out.slice(0, 8);
  }

  function mount(detailEl, alert) {
    if (!detailEl || !alert) return;
    detailEl.querySelectorAll('[data-ar]').forEach(n => n.remove());

    const rel = findRelated(alert);
    const decisions = window.shiftState?.decisions || {};
    const root = document.createElement('section');
    root.className = 'ar-box';
    root.setAttribute('data-ar', '');
    root.innerHTML = `
      <h4 class="ar-h">Related alerts (${rel.length})</h4>
      ${rel.length ? rel.map(r => `
        <div class="ar-row ${decisions[r.alert.id] ? 'closed' : ''}" data-id="${esc(r.alert.id)}">
          <span class="ar-id">${esc(r.alert.id)}</span>
          <span class="ar-sev">${esc(r.alert.severity)}</span>
          <span>${esc(r.alert.rule)}</span>
          <span class="ar-why">${esc(r.shared[0])}${r.shared.length > 1 ? ` +${r.shared.length - 1}` : ''}</span>
        </div>`).join('')
        : '<div class="ar-none">No other released alert shares a host, user, IP, domain or hash with this one (yet).</div>'}`;

    const anchor = detailEl.querySelector('.ab-box') || detailEl.querySelector('.aq-summary');
    if (anchor) anchor.after(root); else detailEl.append(root);

    root.addEventListener('click', e => {
      const row = e.target.closest('.ar-row');
      if (!row) return;
      const id = row.dataset.id;
      detailEl.querySelector('.aq-back')?.click();                       // back to the queue list
      document.querySelector(`#aq-list .aq-item[data-id="${CSS.escape(id)}"]`)?.click(); // open the other alert
    });
  }

  window.AlertRelated = { mount, findRelated };
})();
