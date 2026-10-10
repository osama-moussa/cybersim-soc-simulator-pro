// Connect the incident lifecycle to each alert detail and the shift report.
(() => {
  if (!window.ActionsPanel || !window.IncidentLifecycle) return;
  const originalMount = window.ActionsPanel.mount.bind(window.ActionsPanel);
  const esc = s => Toolkit.esc(String(s ?? ''));
  function mountLifecycle(detail, alert) {
    if (!detail || !alert?.id) return;
    window.activeIncidentAlertId = alert.id;
    detail.querySelector('[data-incident-panel]')?.remove();
    const panel = document.createElement('section');
    panel.dataset.incidentPanel = '';
    panel.className = 'ap-box';
    panel.innerHTML = `<h4 class="ap-h">Incident lifecycle · <span data-status>New</span></h4>
      <label>Evidence / finding<textarea data-evidence placeholder="Observable evidence and why it matters"></textarea></label>
      <div class="ap-row"><select data-type><option value="log">Log / telemetry</option><option value="ioc">IOC enrichment</option><option value="asset">Host / user context</option><option value="analyst-note">Analyst note</option><option value="verification">Control verification</option></select>
      <select data-confidence><option value="high">High confidence</option><option value="medium" selected>Medium confidence</option><option value="low">Low confidence</option></select>
      <button type="button" data-add>Add evidence</button></div>
      <div class="ap-row"><button type="button" data-investigate>Start investigation</button><button type="button" data-contain>Mark contained</button><button type="button" data-resolve>Resolve incident</button></div>
      <p data-message class="ap-msg" aria-live="polite"></p><b>Evidence ledger</b><ul data-evidence-list></ul><b>Response actions & verification</b><ul data-actions></ul><b>Audit history</b><ul data-history></ul>`;
    detail.append(panel);
    const st = () => window.shiftState;
    const caseFile = () => IncidentLifecycle.get(st(), alert.id, alert);
    const message = txt => { panel.querySelector('[data-message]').textContent = txt; };
    const refresh = () => {
      const c = caseFile();
      panel.querySelector('[data-status]').textContent = c.status;
      panel.querySelector('[data-evidence-list]').innerHTML = c.evidence.map(e => `<li>${esc(e.description)} <small>(${esc(e.type)} · ${esc(e.confidence)})</small></li>`).join('') || '<li>No evidence recorded.</li>';
      panel.querySelector('[data-actions]').innerHTML = c.actions.map((a,i) => `<li>${esc(a.type.replace(/_/g,' '))}${a.target ? ' · '+esc(a.target):''} — ${a.verified ? 'Verified: '+esc(a.verification) : `<button type="button" data-verify="${i}">Verify outcome</button>`}</li>`).join('') || '<li>No actions linked yet.</li>';
      panel.querySelector('[data-history]').innerHTML = c.history.map(h => `<li>${esc(h.from || '—')} → <b>${esc(h.to)}</b>${h.reason ? ' · '+esc(h.reason):''}</li>`).join('');
      panel.querySelectorAll('[data-verify]').forEach(b => b.onclick = () => {
        const evidence = prompt('Describe the verification evidence from simulated telemetry/control state:');
        if (!evidence?.trim()) return;
        try { IncidentLifecycle.verifyAction(st(), alert.id, Number(b.dataset.verify), {verified:true,evidence:evidence.trim(),at:window.toolkit?.engine?.clock || null}); message('Action outcome verified with evidence.'); refresh(); window.saveShiftCheckpoint?.(true); }
        catch (e) { message(e.message); }
      });
    };
    const run = fn => { try { fn(); message('Incident updated.'); refresh(); window.saveShiftCheckpoint?.(true); } catch(e) { message(e.message); } };
    panel.querySelector('[data-add]').onclick = () => run(() => { const input=panel.querySelector('[data-evidence]'); IncidentLifecycle.addEvidence(st(),alert.id,{description:input.value,type:panel.querySelector('[data-type]').value,confidence:panel.querySelector('[data-confidence]').value,source:'Alert investigation'}); input.value=''; });
    panel.querySelector('[data-investigate]').onclick = () => run(() => IncidentLifecycle.transition(st(),alert.id,'Investigating',{reason:'Evidence-led investigation started',at:window.toolkit?.engine?.clock || null}));
    panel.querySelector('[data-contain]').onclick = () => run(() => IncidentLifecycle.transition(st(),alert.id,'Contained',{reason:'Analyst confirmed containment',residualRisk:confirm('Is residual risk still present?')}));
    panel.querySelector('[data-resolve]').onclick = () => run(() => IncidentLifecycle.transition(st(),alert.id,'Resolved',{reason:prompt('Resolution summary / closure rationale:') || '',residualRisk:confirm('Is residual risk still present?'),resolutionConfirmed:confirm('Confirm the recovery/cleanup outcome was verified?')}));
    refresh();
    const onIncidentUpdate = event => {
      if (!event.detail?.alertId || event.detail.alertId === alert.id) refresh();
    };
    window.addEventListener('soc:incident-updated', onIncidentUpdate);
  }
  window.ActionsPanel.mount = function(detail, alert) { originalMount(detail, alert); mountLifecycle(detail, alert); };
})();
