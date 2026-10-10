// Incident lifecycle model for the educational simulator. No real systems are touched.
(function (root) {
  const VALID = ['New', 'Investigating', 'Contained', 'Resolved'];
  const TERMINAL = 'Resolved';

  function ensureState(state) {
    if (!state || typeof state !== 'object') throw new Error('A shift state is required.');
    state.incidents = state.incidents && typeof state.incidents === 'object' ? state.incidents : {};
    return state.incidents;
  }
  function get(state, alertId, alert = {}) {
    if (!alertId) throw new Error('alertId is required.');
    const all = ensureState(state);
    if (!all[alertId]) all[alertId] = {
      alertId, title: alert.rule || alert.summary || alertId,
      status: 'New', createdAt: alert.releasedAt || null, updatedAt: alert.releasedAt || null,
      evidence: [], actions: [], notes: [], history: [{ from: null, to: 'New', reason: 'Incident created', at: alert.releasedAt || null }]
    };
    return all[alertId];
  }
  function addEvidence(state, alertId, evidence) {
    if (!evidence || !String(evidence.description || '').trim()) throw new Error('Evidence description is required.');
    const incident = get(state, alertId);
    const item = { id: evidence.id || `EV-${incident.evidence.length + 1}`, type: evidence.type || 'analyst-note',
      description: String(evidence.description).trim(), source: evidence.source || 'Analyst supplied',
      at: evidence.at || null, confidence: ['low','medium','high'].includes(evidence.confidence) ? evidence.confidence : 'medium' };
    if (incident.evidence.some(e => e.id === item.id)) throw new Error(`Duplicate evidence id: ${item.id}`);
    incident.evidence.push(item);
    return item;
  }
  function recordAction(state, alertId, action) {
    if (!action || !String(action.type || '').trim()) throw new Error('Action type is required.');
    const incident = get(state, alertId);
    const item = { type: String(action.type), target: action.target || null, min: Number.isFinite(Number(action.min)) ? Number(action.min) : null,
      at: action.clock || null, verified: false, verification: 'Action recorded; outcome not yet verified.' };
    incident.actions.push(item);
    return item;
  }
  function transition(state, alertId, next, opts = {}) {
    const incident = get(state, alertId);
    if (!VALID.includes(next)) throw new Error(`Invalid incident status: ${next}`);
    const current = incident.status;
    const allowed = { New: ['Investigating'], Investigating: ['Contained'], Contained: ['Investigating','Resolved'], Resolved: [] };
    if (!allowed[current].includes(next)) throw new Error(`Transition not allowed: ${current} -> ${next}`);
    if (next === 'Investigating' && incident.evidence.length === 0 && !opts.allowWithoutEvidence)
      throw new Error('Add at least one evidence item before investigation can be marked active.');
    if (next === 'Contained') {
      const verified = incident.actions.some(a => a.verified);
      if (!verified) throw new Error('Containment requires a verified response action.');
      if (opts.residualRisk === true) throw new Error('Containment blocked: residual risk is still present.');
    }
    if (next === TERMINAL) {
      if (incident.evidence.length === 0) throw new Error('Resolution requires documented evidence.');
      if (opts.residualRisk === true) throw new Error('Resolution blocked: residual risk remains.');
      if (opts.resolutionConfirmed !== true) throw new Error('Resolution requires explicit outcome confirmation.');
    }
    incident.status = next;
    incident.updatedAt = opts.at || null;
    incident.history.push({ from: current, to: next, reason: opts.reason || '', at: opts.at || null });
    return incident;
  }
  function verifyAction(state, alertId, index, result) {
    const incident = get(state, alertId);
    const action = incident.actions[index];
    if (!action) throw new Error('Response action not found.');
    if (result?.verified !== true || !String(result?.evidence || '').trim())
      throw new Error('Verification needs a positive result and supporting evidence.');
    action.verified = true;
    action.verification = String(result.evidence).trim();
    action.verifiedAt = result.at || null;
    return action;
  }
  function addNote(state, alertId, note, at = null) {
    const value = String(note || '').trim();
    if (!value) throw new Error('Case note cannot be empty.');
    const incident = get(state, alertId);
    const item = { text: value, at };
    incident.notes.push(item);
    return item;
  }
  function summary(state) {
    const all = Object.values(ensureState(state));
    return { total: all.length, new: all.filter(i=>i.status==='New').length,
      investigating: all.filter(i=>i.status==='Investigating').length,
      contained: all.filter(i=>i.status==='Contained').length,
      resolved: all.filter(i=>i.status==='Resolved').length };
  }
  const api = { statuses: VALID.slice(), get, addEvidence, recordAction, verifyAction, transition, addNote, summary };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.IncidentLifecycle = api;
})(typeof window !== 'undefined' ? window : globalThis);
