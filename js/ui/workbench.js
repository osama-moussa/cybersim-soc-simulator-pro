// js/ui/workbench.js — يربط الـ Alert panel بالـ Toolkit (Context / Logs / IOC / Response)
// ملف مستقل: مابيعدّلش أي ملف تاني، ومابيستبدلش أي function موجودة.
// بيعتمد على: #aq-panel, #aq-detail, #tk-modal, window.toolkit, window.shiftState, window.activeAlertId
// ماعدا ده بيشتغل بـ MutationObserver بس.
(function () {
  const SPLIT_MIN_WIDTH = 1100; // تحت العرض ده الـ Toolkit بيفضل modal زي ما هو

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ---------- CSS ----------
  if (!document.getElementById('wb-style')) {
    const style = document.createElement('style');
    style.id = 'wb-style';
    style.textContent = `
      /* شريط الـ alert جوه الـ detail (sticky فوق) */
      .wb-bar { position: sticky; top: -14px; z-index: 5; margin: -14px -16px 12px; padding: 10px 16px;
        background: #0b1220; border-bottom: 1px solid #334155; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
      .wb-chip { font-size: 12px; color: #94a3b8; flex: 1 1 100%; }
      .wb-chip b { color: #22d3ee; font-family: monospace; font-size: 13px; }
      .wb-btn { background: #1e293b; color: #e2e8f0; border: 1px solid #475569; border-radius: 6px;
        padding: 5px 10px; font-size: 12px; cursor: pointer; }
      .wb-btn:hover { background: #273449; border-color: #22d3ee; }
      .wb-btn.primary { background: #0ea5e9; border-color: #0ea5e9; color: #fff; font-weight: 600; }

      /* شريط الـ alert جوه الـ Toolkit */
      #wb-tk-bar { display: flex; align-items: center; gap: 10px; padding: 8px 14px; font-size: 12px;
        background: #0b1220; border-bottom: 1px solid #334155; color: #94a3b8; }
      #wb-tk-bar b { color: #22d3ee; font-family: monospace; }
      #wb-tk-bar .wb-grow { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

      /* Split view: الـ Toolkit جنب الـ alert بدل ما يغطيه */
      body.wb-split #aq-panel { width: max(520px, 46vw) !important; }
      body.wb-split #tk-modal { inset: 0 auto 0 0; width: calc(100vw - max(520px, 46vw));
        background: transparent; pointer-events: none; justify-content: flex-start; align-items: stretch; }
      body.wb-split .tk-box { pointer-events: auto; width: 100%; height: 100%; border-radius: 0; box-shadow: none; border-right: 2px solid #22d3ee; }
      body.wb-split .tk-head { border-radius: 0; }

      /* زرار 🔎 Toolkit الأصلي: يقعد جنب الـ panel العريض بدل ما يختفي تحته */
      body:has(#aq-detail:not([hidden])) #tk-toggle { right: calc(min(960px, 100vw) + 20px); }
      @media (max-width: 1100px) { body:has(#aq-detail:not([hidden])) #tk-toggle { display: none; } }

      /* Context: تظليل اللي يخص الـ alert المفتوح */
      #tk-ctx .wb-hit td, #tk-ctx li.wb-hit { background: rgba(34,211,238,.13) !important; }
      #tk-ctx li.wb-hit { border-left: 3px solid #22d3ee; padding-left: 6px; list-style-position: inside; }
      #tk-ctx tr.wb-generic td:first-child { box-shadow: inset 3px 0 0 #f59e0b; }
      #tk-ctx li.wb-generic { border-left: 3px solid #f59e0b; padding-left: 6px; list-style-position: inside; }
      .wb-ctx-note { margin: 0 0 12px; padding: 8px 12px; border-left: 3px solid #22d3ee; background: #0b1220; font-size: 13px; color: #94a3b8; }
    `;
    document.head.appendChild(style);
  }

  const usable = v => !!v && !/^(n\/a|na|none|unknown|-|—)$/i.test(String(v).trim());

  const activeAlert = () => (window.shiftState?.alerts || []).find(a => a.id === window.activeAlertId) || null;

  // ---------- جوه الـ alert detail ----------
  function mountBar() {
    const detail = document.getElementById('aq-detail');
    if (!detail || detail.hidden || !window.activeAlertId) return;
    if (detail.querySelector('[data-wb-bar]')) return;
    const a = activeAlert();
    if (!a) return;
    const ip = a.details?.['Source IP'];

    const bar = document.createElement('div');
    bar.className = 'wb-bar';
    bar.dataset.wbBar = '1';
    bar.innerHTML = `
      <div class="wb-chip"><b>${esc(a.id)}</b> · ${esc(a.severity)} · ${esc(a.host)} · ${esc(a.user)}</div>
      <button type="button" class="wb-btn primary" data-wb="context">Context</button>
      ${usable(a.host) ? `<button type="button" class="wb-btn" data-wb="logs" data-v="${esc(a.host)}">Logs: ${esc(a.host)}</button>` : ''}
      ${usable(a.user) ? `<button type="button" class="wb-btn" data-wb="logs" data-v="${esc(a.user)}">Logs: ${esc(a.user)}</button>` : ''}
      ${usable(ip) ? `<button type="button" class="wb-btn" data-wb="ioc" data-v="${esc(ip)}">IOC: ${esc(ip)}</button>` : ''}
      <button type="button" class="wb-btn" data-wb="response">Response</button>`;
    bar.onclick = e => {
      const b = e.target.closest('[data-wb]');
      if (!b) return;
      window.toolkit?.open(b.dataset.wb, b.dataset.v);
    };
    detail.prepend(bar);
  }

  // ---------- جوه الـ Toolkit ----------
  function mountToolkitBar() {
    const box = document.querySelector('#tk-modal .tk-box');
    if (!box) return;
    let bar = document.getElementById('wb-tk-bar');
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'wb-tk-bar';
      const head = box.querySelector('.tk-head');
      if (head) head.after(bar); else box.prepend(bar);
    }
    const a = activeAlert();
    bar.innerHTML = a
      ? `<span class="wb-grow">Working on <b>${esc(a.id)}</b> — ${esc(a.rule)} · ${esc(a.host)} · ${esc(a.user)}</span>
         <button type="button" class="wb-btn" data-wb-close>${document.body.classList.contains('wb-split') ? 'Close toolkit' : '← Back to alert'}</button>`
      : `<span class="wb-grow">No alert open — pick one from the queue to keep its context here.</span>
         <button type="button" class="wb-btn" data-wb-close>Close toolkit</button>`;
    bar.querySelector('[data-wb-close]').onclick = () => window.toolkit?.close();
  }

  // ---------- Context: تظليل الصفوف اللي فيها host أو user بتاع الـ alert ----------
  const GENERIC = /\ball\s+(workstations|servers|hosts|endpoints|users|systems|devices)/i;
  function highlightContext() {
    const ctx = document.getElementById('tk-ctx');
    if (!ctx) return;
    ctx.querySelectorAll('.wb-hit, .wb-generic').forEach(e => e.classList.remove('wb-hit', 'wb-generic'));
    ctx.querySelector('.wb-ctx-note')?.remove();
    const a = activeAlert();
    if (!a || !ctx.querySelector('table, ul')) return;
    const terms = [a.host, a.user].filter(usable).map(t => String(t).toLowerCase());
    if (!terms.length) return;
    const hits = [...ctx.querySelectorAll('tbody tr, li')].filter(r => {
      const txt = r.textContent.toLowerCase();
      return terms.some(t => txt.includes(t));
    });
    hits.forEach(r => r.classList.add('wb-hit'));
    const generic = [...ctx.querySelectorAll('tbody tr, li')].filter(r => !hits.includes(r) && GENERIC.test(r.textContent));
    generic.forEach(r => { r.classList.add('wb-generic'); r.title = 'Applies to a whole group — may still cover this host'; });
    const note = document.createElement('div');
    note.className = 'wb-ctx-note';
    const who = [a.host, a.user].filter(usable).join(' / ');
    note.textContent = (hits.length ? `${hits.length} item(s) mention ${who} (cyan).` : `Nothing here mentions ${who} directly.`)
      + (generic.length ? ` ${generic.length} item(s) apply to a whole group such as "all workstations" (amber) and may still cover this host.` : '');
    ctx.prepend(note);
    hits[0]?.scrollIntoView({ block: 'nearest' });
  }

  // ---------- split mode ----------
  function syncSplit() {
    const modal = document.getElementById('tk-modal');
    const panel = document.getElementById('aq-panel');
    if (!modal || !panel) return;
    const on = !modal.hidden && panel.classList.contains('open') && window.innerWidth >= SPLIT_MIN_WIDTH;
    document.body.classList.toggle('wb-split', on);
    mountToolkitBar();
  }

  function init() {
    const detail = document.getElementById('aq-detail');
    const modal = document.getElementById('tk-modal');
    const panel = document.getElementById('aq-panel');
    if (!detail || !modal || !panel || !window.toolkit) return false;

    new MutationObserver(() => { mountBar(); mountToolkitBar(); highlightContext(); })
      .observe(detail, { childList: true, attributes: true, attributeFilter: ['hidden'] });
    const ctxEl = document.getElementById('tk-ctx');
    if (ctxEl) {
      const ctxObs = new MutationObserver(() => { ctxObs.disconnect(); try { highlightContext(); } finally { ctxObs.observe(ctxEl, { childList: true }); } });
      ctxObs.observe(ctxEl, { childList: true });
    }
    new MutationObserver(syncSplit).observe(modal, { attributes: true, attributeFilter: ['hidden'] });
    new MutationObserver(syncSplit).observe(panel, { attributes: true, attributeFilter: ['class'] });
    window.addEventListener('resize', syncSplit);
    mountToolkitBar();
    return true;
  }

  // app.js بيبني الـ panel والـ toolkit بعد التحميل، فنستنى لحد ما يبقوا موجودين
  let tries = 0;
  const t = setInterval(() => { if (init() || ++tries > 100) clearInterval(t); }, 100);
})();
