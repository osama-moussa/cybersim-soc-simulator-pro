// js/ui/analystTools.js — ملف مستقل (مابيعدّلش أي ملف تاني)
// 1) شريط قرار ثابت تحت في الـ alert detail (TP/FP + Escalate + Close) بدل النزول لآخر الصفحة
// 2) تاب Email في الـ Toolkit: headers + SPF/DKIM/DMARC + links/attachments + email logs
// 3) تاب EDR في الـ Toolkit: process tree + command line + EDR logs للـ host
// بيقرا من alert.details و toolkit.visibleLogs() بس — ومابيقراش حقل truth أبداً.
(function () {
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = id => document.getElementById(id);
  const usable = v => v != null && v !== '' && !/^(n\/a|na|none|unknown|-|—)$/i.test(String(v).trim());
  const val = (d, ...ks) => { for (const k of ks) if (usable(d?.[k])) return d[k]; return null; };
  const activeAlert = () => (window.shiftState?.alerts || []).find(a => a.id === window.activeAlertId) || null;

  if (!$('xt-style')) {
    const st = document.createElement('style');
    st.id = 'xt-style';
    st.textContent = `
      .xt-bar { position: sticky; bottom: -14px; z-index: 6; margin: 14px -16px -14px; padding: 10px 16px;
        background: #0b1220; border-top: 1px solid #334155; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
      .xt-bar .xt-lbl { font-size: 12px; color: #94a3b8; }
      .xt-b { background: #1e293b; color: #e2e8f0; border: 1px solid #475569; border-radius: 6px; padding: 6px 12px; font-size: 13px; cursor: pointer; }
      .xt-b:disabled { opacity: .5; cursor: default; }
      .xt-b.on-tp { background: #b91c1c; border-color: #b91c1c; color: #fff; }
      .xt-b.on-fp { background: #047857; border-color: #047857; color: #fff; }
      .xt-b.go { background: #0ea5e9; border-color: #0ea5e9; color: #fff; font-weight: 600; margin-left: auto; }
      .xt-chk { font-size: 12px; color: #cbd5e1; display: flex; gap: 4px; align-items: center; }
      .xt-msg { flex-basis: 100%; font-size: 12px; color: #f87171; }
      .xt-pre { background: #0b1220; border: 1px solid #334155; border-radius: 6px; padding: 8px 10px; font: 12px ui-monospace, Consolas, monospace; white-space: pre-wrap; word-break: break-all; }
      .xt-tree { font: 13px ui-monospace, Consolas, monospace; line-height: 1.8; margin: 0 0 14px; }
      .xt-tree .xt-ch { margin-left: 22px; border-left: 2px solid #334155; padding-left: 10px; }
      .xt-tree .xt-cmd { color: #fbbf24; word-break: break-all; }
      .xt-h { margin: 16px 0 8px; color: #22d3ee; font-size: 13px; letter-spacing: .06em; text-transform: uppercase; }
      .xt-auth { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 6px; }
      .xt-auth span { font-size: 12px; color: #94a3b8; }
      .xt-link { background: none; border: 0; color: #22d3ee; cursor: pointer; text-decoration: underline dotted; padding: 0; font: inherit; }
    `;
    document.head.appendChild(st);
  }

  // =========================================================== 1) شريط القرار الثابت
  const decisionFs = d => d.querySelector('input[name="verdict"]')?.closest('fieldset') || d.querySelector('fieldset');
  function syncBar(detail, bar) {
    const fs = decisionFs(detail);
    if (!fs) return;
    const verdict = fs.querySelector('input[name="verdict"]:checked')?.value;
    bar.querySelectorAll('[data-v]').forEach(b => {
      b.classList.toggle('on-tp', b.dataset.v === 'TP' && verdict === 'TP');
      b.classList.toggle('on-fp', b.dataset.v === 'FP' && verdict === 'FP');
    });
    bar.querySelector('input[type=checkbox]').checked = !!fs.querySelector('input[name="escalate"]')?.checked;
    bar.querySelectorAll('button, input').forEach(e => { e.disabled = fs.disabled; });
    bar.querySelector('[data-xt-close]').textContent = fs.disabled ? 'Closed' : 'Close alert';
  }

  function mountDecisionBar() {
    const detail = $('aq-detail');
    if (!detail || detail.hidden || !window.activeAlertId || !decisionFs(detail)) return;
    let bar = detail.querySelector('[data-xt-bar]');
    if (!bar) {
      bar = document.createElement('div');
      bar.className = 'xt-bar';
      bar.dataset.xtBar = '1';
      bar.innerHTML = `
        <span class="xt-lbl">Decision</span>
        <button type="button" class="xt-b" data-v="TP">True Positive</button>
        <button type="button" class="xt-b" data-v="FP">False Positive</button>
        <label class="xt-chk"><input type="checkbox"> Escalate</label>
        <button type="button" class="xt-b" data-xt-notes>Notes ↓</button>
        <button type="button" class="xt-b go" data-xt-close>Close alert</button>
        <div class="xt-msg" hidden></div>`;
      bar.onclick = e => {
        if (e.target.closest('.xt-chk')) return; // الـ checkbox ليه onchange خاص بيه
        const fs = decisionFs(detail);
        const msg = bar.querySelector('.xt-msg');
        if (!fs) return;
        const v = e.target.closest('[data-v]');
        if (v) {
          const r = fs.querySelector(`input[name="verdict"][value="${v.dataset.v}"]`);
          if (r) { r.checked = true; r.dispatchEvent(new Event('change', { bubbles: true })); }
          msg.hidden = true;
        }
        if (e.target.closest('[data-xt-notes]')) { fs.scrollIntoView({ block: 'center' }); fs.querySelector('textarea')?.focus(); }
        if (e.target.closest('[data-xt-close]')) {
          if (!fs.querySelector('input[name="verdict"]:checked')) { msg.textContent = 'Choose True Positive or False Positive first.'; msg.hidden = false; return; }
          detail.querySelector('.aq-submit')?.click();
          // قواعد تانية (زي ملاحظة الـ handover للـ escalate) بتكتب الخطأ في أسفل الفورم — نعكسه هنا عشان يبان
          const err = detail.querySelector('.aq-error');
          if (err && !err.hidden && err.textContent.trim()) { msg.textContent = err.textContent.trim(); msg.hidden = false; fs.querySelector('textarea')?.focus(); }
        }
        syncBar(detail, bar);
      };
      bar.querySelector('input[type=checkbox]').onchange = e => {
        const c = detail.querySelector('fieldset input[name="escalate"]');
        if (c) { c.checked = e.target.checked; c.dispatchEvent(new Event('change', { bubbles: true })); }
      };
    }
    if (detail.lastElementChild !== bar) detail.append(bar); // يفضل آخر عنصر حتى لو module تاني اتضاف بعده
    if (!detail.__xtSync) { detail.__xtSync = true; detail.addEventListener('change', () => { const b = detail.querySelector('[data-xt-bar]'); if (b) syncBar(detail, b); }); }
    syncBar(detail, bar);
  }

  // =========================================================== 2) + 3) تابات Email و EDR
  const empty = t => `<div class="tk-empty">${esc(t)}</div>`;
  const piv = v => usable(v) ? `<a href="#" class="tk-pivot" data-v="${esc(v)}">${esc(v)}</a>` : '—';
  const logBtn = v => usable(v) ? ` <button type="button" class="xt-link" data-xt-logs="${esc(v)}">logs</button>` : '';
  const authBadge = v => {
    if (!usable(v)) return '<span class="tk-rep">not provided</span>';
    const cls = /^pass/i.test(v) ? 'rep-clean' : /fail/i.test(v) ? 'rep-malicious' : 'rep-suspicious';
    return `<span class="tk-rep ${cls}">${esc(v)}</span>`;
  };
  const logsTable = rows => rows.length
    ? `<table class="tk-table"><thead><tr><th>Time</th><th>Host</th><th>User</th><th>Message</th></tr></thead><tbody>${rows.map(l =>
        `<tr><td class="mono">${esc(l.t)}</td><td>${esc(l.host)}</td><td>${esc(l.user)}</td><td>${esc(l.msg)}</td></tr>`).join('')}</tbody></table>`
    : empty('No matching log entries so far.');
  const visibleLogs = () => { try { return window.toolkit?.visibleLogs() || []; } catch { return []; } };

  function emailView(a) {
    if (!a) return empty('Open an alert from the queue to see its email details here.');
    const d = a.details || {};
    const from = val(d, 'email_from', 'sender'), to = val(d, 'email_to', 'recipients');
    const att = val(d, 'file_name', 'attachment'), hash = d.file_hash, url = d.url;
    if (!from && !to && !d.subject && !url && !att && !d.spf) return empty(`${a.id} has no email fields (source: ${a.source}).`);
    const dom = from && String(from).includes('@') ? String(from).split('@').pop() : null;
    const mail = visibleLogs().filter(l => l.src === 'email' && (l.user === a.user || l.host === a.host || (dom && String(l.msg).includes(dom)))).slice(-15);
    return `
      <h4 class="xt-h" style="margin-top:0">Message</h4>
      <dl class="tk-dl">
        <dt>From</dt><dd>${piv(from)}${dom ? ` · domain ${piv(dom)}${logBtn(dom)}` : ''}</dd>
        <dt>To</dt><dd>${esc(to ?? '—')}</dd>
        <dt>Subject</dt><dd>${esc(d.subject ?? '—')}${logBtn(d.subject)}</dd>
        <dt>URL</dt><dd>${piv(url)}</dd>
        <dt>Attachment</dt><dd>${esc(att ?? '—')}</dd>
        <dt>File hash</dt><dd class="mono">${piv(hash)}</dd>
      </dl>
      <h4 class="xt-h">Authentication</h4>
      <div class="xt-auth"><span>SPF ${authBadge(d.spf)}</span><span>DKIM ${authBadge(d.dkim)}</span><span>DMARC ${authBadge(d.dmarc)}</span></div>
      <h4 class="xt-h">Related email log entries</h4>
      ${logsTable(mail)}`;
  }

  function edrView(a) {
    if (!a) return empty('Open an alert from the queue to see its EDR details here.');
    const d = a.details || {};
    const proc = val(d, 'process'), par = val(d, 'parent_process'), cmd = val(d, 'command_line');
    const logs = visibleLogs().filter(l => l.src === 'edr' && l.host === a.host).slice(-25);
    if (!proc && !par && !cmd && !logs.length) return empty(`${a.id} has no process or EDR data (source: ${a.source}).`);
    return `
      <h4 class="xt-h" style="margin-top:0">Process tree</h4>
      ${proc || par || cmd ? `<div class="xt-tree">
        ${par ? `<div>${esc(par)}</div>` : '<div>(parent not recorded)</div>'}
        <div class="xt-ch">${esc(proc ?? '(process not recorded)')}
          ${cmd ? `<div class="xt-ch xt-cmd">${esc(cmd)}</div>` : ''}</div></div>` : empty('No process fields on this alert.')}
      <dl class="tk-dl">
        <dt>Host</dt><dd>${esc(a.host)}${logBtn(a.host)}</dd>
        <dt>Host IP</dt><dd>${piv(d.host_ip)}</dd>
        <dt>User</dt><dd>${esc(a.user)}${logBtn(a.user)}</dd>
        <dt>File hash</dt><dd class="mono">${piv(d.file_hash)}</dd>
      </dl>
      ${d.raw_log ? `<h4 class="xt-h">Raw EDR event</h4><div class="xt-pre">${esc(d.raw_log)}</div>` : ''}
      <h4 class="xt-h">EDR log entries on ${esc(a.host)}</h4>
      ${logsTable(logs)}`;
  }

  const VIEWS = { email: emailView, edr: edrView };
  function renderVisible() {
    for (const t of Object.keys(VIEWS)) {
      const pane = document.querySelector(`#tk-modal [data-pane="${t}"]`);
      const body = pane?.querySelector('[data-xt]');
      if (pane && body && !pane.hidden) body.innerHTML = VIEWS[t](activeAlert());
    }
  }

  function addBarButtons() {
    const bar = document.querySelector('#aq-detail .wb-bar'), a = activeAlert();
    if (!bar || !a || bar.querySelector('[data-xt-btn]')) return;
    const d = a.details || {};
    const add = (tab, label) => {
      const b = document.createElement('button');
      b.type = 'button'; b.className = 'wb-btn'; b.dataset.xtBtn = tab; b.textContent = label;
      b.onclick = () => window.toolkit?.open(tab);
      bar.append(b);
    };
    if (val(d, 'email_from', 'sender', 'email_to', 'recipients') || d.subject || d.spf) add('email', 'Email');
    if (val(d, 'process', 'parent_process', 'command_line')) add('edr', 'EDR');
  }

  function init() {
    const modal = $('tk-modal'), detail = $('aq-detail');
    const nav = modal?.querySelector('.tk-tabs'), ctxPane = modal?.querySelector('[data-pane="context"]');
    if (!modal || !detail || !nav || !ctxPane || !window.toolkit) return false;

    const mkBtn = (t, label) => { const b = document.createElement('button'); b.type = 'button'; b.dataset.tab = t; b.textContent = label; return b; };
    const eb = mkBtn('email', 'Email'), db = mkBtn('edr', 'EDR');
    nav.querySelector('[data-tab="context"]').after(eb); eb.after(db);
    let prev = ctxPane;
    for (const t of ['email', 'edr']) {
      const s = document.createElement('section');
      s.className = 'tk-pane'; s.dataset.pane = t; s.hidden = true;
      s.innerHTML = `<div class="tk-scroll" data-xt="${t}"></div>`;
      s.querySelector('[data-xt]').onclick = e => {
        const b = e.target.closest('[data-xt-logs]');
        if (b) window.toolkit.open('logs', b.dataset.xtLogs);
      };
      prev.after(s); prev = s;
      new MutationObserver(renderVisible).observe(s, { attributes: true, attributeFilter: ['hidden'] });
    }
    new MutationObserver(renderVisible).observe(modal, { attributes: true, attributeFilter: ['hidden'] });
    new MutationObserver(() => { mountDecisionBar(); addBarButtons(); renderVisible(); })
      .observe(detail, { childList: true, attributes: true, attributeFilter: ['hidden'] });
    return true;
  }

  let tries = 0;
  const t = setInterval(() => { if (init() || ++tries > 100) clearInterval(t); }, 100);
})();
