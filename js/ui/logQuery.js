// js/ui/logQuery.js — SIEM-style query language for the Log Search tab (new file, wraps Toolkit.prototype.searchLogs).
// Plain keyword search still works. A query is used when it has field=value, field~word or a pipe:
//   src=dns host=FS-01 user=adm.* after=08:10 before=08:40 psexec | count by user | head 5
// Fields: src host user msg (= exact, ~ contains, * wildcard) and after/before (HH:MM). Bare words match anywhere.
// Stages: count | count by <src|host|user> | head N.   Load AFTER toolkit.js and BEFORE app.js.
(() => {
  const FIELDS = ['src', 'host', 'user', 'msg'];
  const norm = s => String(s ?? '').toLowerCase();
  const isQuery = q => /(^|\s)(src|host|user|msg|after|before)\s*[=~]/i.test(q) || q.includes('|');
  const tm = s => (/^\d{1,2}:\d{2}$/.test(s) ? s.padStart(5, '0') + ':00' : s);
  const rx = p => new RegExp('^' + p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');

  function parse(raw) {
    const parts = raw.replace(/\[\.\]/g, '.').split('|').map(s => s.trim());
    const conds = [], words = [];
    let rest = parts[0];
    rest = rest.replace(/(\w+)\s*([=~])\s*("[^"]*"|\S+)/g, (m, f, op, v) => {
      f = f.toLowerCase(); v = v.replace(/^"|"$/g, '');
      if (![...FIELDS, 'after', 'before'].includes(f)) throw new Error(`Unknown field "${f}". Use: src, host, user, msg, after, before.`);
      conds.push({ f, op, v: norm(v) }); return ' ';
    });
    rest.split(/\s+/).filter(Boolean).forEach(w => words.push(norm(w)));
    const stages = parts.slice(1).filter(Boolean).map(s => {
      let m;
      if ((m = /^count(?:\s+by\s+(\w+))?$/i.exec(s))) {
        const by = m[1] && m[1].toLowerCase();
        if (by && !FIELDS.includes(by)) throw new Error(`count by: unknown field "${by}". Use: ${FIELDS.join(', ')}.`);
        return { type: 'count', by };
      }
      if ((m = /^head\s+(\d+)$/i.exec(s))) return { type: 'head', n: +m[1] };
      throw new Error(`Unknown stage "${s}". Use: count, count by <field>, head N.`);
    });
    const match = l => {
      const t = String(l.t || '').slice(0, 8);
      for (const c of conds) {
        if (c.f === 'after') { if (!(t >= tm(c.v))) return false; continue; }
        if (c.f === 'before') { if (!(t <= tm(c.v))) return false; continue; }
        const val = norm(l[c.f]);
        if (c.op === '~') { if (!val.includes(c.v)) return false; }
        else if (c.f === 'msg') { if (!(c.v.includes('*') ? rx(c.v).test(val) || new RegExp(c.v.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*'), 'i').test(val) : val.includes(c.v))) return false; }
        else if (c.v.includes('*') ? !rx(c.v).test(val) : val !== c.v) return false;
      }
      const all = `${l.t} ${l.src} ${l.host} ${l.user} ${l.msg}`.toLowerCase();
      return words.every(w => all.includes(w));
    };
    return { match, stages };
  }
  window.LogQuery = { parse, isQuery };

  const T = window.Toolkit;
  if (!T?.prototype?.searchLogs) { console.warn('[logQuery] Toolkit.searchLogs not found; query language skipped.'); return; }
  const orig = T.prototype.searchLogs;

  T.prototype.searchLogs = function () {
    const inp = this.$('tk-log-q');
    if (inp && !inp.dataset.hq) { inp.dataset.hq = '1'; inp.placeholder += '  |  or query: src=dns host=FS-01 | count by user'; }
    const raw = (inp?.value || '').trim();
    if (!this.scenario || !isQuery(raw)) return orig.call(this);

    const meta = this.$('tk-log-meta'), body = this.$('tk-log-body');
    let p;
    try { p = parse(raw); } catch (e) {
      meta.textContent = 'Query error: ' + e.message;
      body.innerHTML = '<tr><td colspan="5" class="tk-empty">Fix the query and search again.</td></tr>';
      return;
    }
    const src = this.$('tk-log-src').value;
    const all = this.visibleLogs();
    let rows = all.filter(l => (!src || l.src === src) && p.match(l));
    this.track('log_search', raw + (src ? ` [src=${src}]` : ''));

    const agg = p.stages.find(s => s.type === 'count');
    if (agg) {
      if (!agg.by) {
        meta.textContent = `Query: ${rows.length} event(s) of ${all.length} ingested so far.`;
        body.innerHTML = `<tr><td colspan="3" class="mono">count</td><td colspan="2"><b>${rows.length}</b></td></tr>`;
        return;
      }
      const g = new Map();
      rows.forEach(l => g.set(l[agg.by], (g.get(l[agg.by]) || 0) + 1));
      let list = [...g.entries()].sort((a, b) => b[1] - a[1]);
      const h = p.stages.find(s => s.type === 'head'); if (h) list = list.slice(0, h.n);
      meta.textContent = `Query: ${rows.length} event(s), ${g.size} distinct ${agg.by}.`;
      body.innerHTML = list.map(([k, n]) => `<tr><td colspan="3" class="mono">${agg.by}=${T.esc(k)}</td><td colspan="2"><b>${n}</b></td></tr>`).join('') ||
        '<tr><td colspan="5" class="tk-empty">No log entries match.</td></tr>';
      return;
    }
    const h = p.stages.find(s => s.type === 'head'); if (h) rows = rows.slice(0, h.n);
    this.visibleLogs = () => rows;
    inp.value = '';
    try { orig.call(this); } finally { delete this.visibleLogs; inp.value = raw; }
    meta.textContent = `Query: ${rows.length} event(s) shown of ${all.length} ingested so far.`;
  };
})();
