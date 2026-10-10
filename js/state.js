// js/state.js — حالة الشيفت (التنبيهات النازلة + قرارات المحلل)

window.shiftState = {
  alerts: [],      // التنبيهات اللي نزلت (من غير truth)
  decisions: {},   // alertId -> { verdict, severity, escalate, note, decidedAt, responseMin }
  actions: [],      // simulated response actions
  activity: [],     // investigation events, associated with an alert when possible
  effects: {},      // simulated environment state changes (never real infrastructure)
  incidents: {},    // per-alert incident lifecycle, evidence, verification, notes

  reset() {
    this.alerts = [];
    this.decisions = {};
    this.actions = [];
    this.activity = [];
    this.effects = {};
    this.incidents = {};
  },

  addAlert(alert) {
    this.alerts.push(alert);
  },

  decide(alertId, decision) {
    this.decisions[alertId] = decision;
  },

  isClosed(alertId) {
    return alertId in this.decisions;
  },

  get openCount() {
    return this.alerts.filter(a => !this.isClosed(a.id)).length;
  },
};

// Apply a response action to the simulated environment. This never calls external systems.
window.applySimulatedAction = function applySimulatedAction(action) {
  const st = window.shiftState;
  if (!st || !action || !action.type) throw new Error('A shift and action type are required.');
  st.effects = st.effects || {};
  st.activity = st.activity || [];
  const target = String(action.target || '').trim();
  const normalized = target.toLowerCase();
  const key = `${action.type}:${normalized}`;
  const impact = {
    block_ip: ['network_blocked', 'Future simulated connections to this IP are marked as blocked.'],
    block_domain: ['domain_blocked', 'Future simulated lookups to this domain are marked as blocked.'],
    block_hash: ['hash_blocked', 'Future simulated detections for this hash are marked as blocked.'],
    isolate_host: ['host_isolated', 'The host is isolated in the simulation; later host activity is flagged as constrained.'],
    disable_account: ['account_disabled', 'The account is disabled in the simulation; later account activity is flagged.'],
    reset_password: ['password_reset_required', 'The account requires a password reset in the simulation.'],
    revoke_sessions: ['sessions_revoked', 'Existing sessions are treated as revoked in the simulation.'],
    enforce_mfa: ['mfa_enforced', 'MFA enforcement is recorded in the simulation.'],
    remove_inbox_rule: ['inbox_rule_removed', 'The malicious inbox rule is marked removed in the simulation.'],
    delete_email: ['email_removed', 'The email is marked removed in the simulation.'],
    release_email: ['email_released', 'The email is marked released from quarantine in the simulation.'],
    preserve_evidence: ['evidence_preserved', 'Evidence preservation is recorded in the case timeline.'],
    initiate_incident_response: ['incident_declared', 'Incident response is declared in the simulated case.']
  }[action.type] || ['recorded', 'Action recorded in the simulated environment.'];
  const entry = { type: action.type, target: target || null, status: impact[0], effect: impact[1], at: action.clock || '', min: Number(action.min) || 0 };
  st.effects[key] = entry;
  const alertId = window.activeAlertId || null;
  st.activity.push({ type: 'response_action', action: action.type, query: target || '', alertId, at: entry.at, min: entry.min, effect: entry.effect });
  // Every response action is attached to the currently investigated incident for verification.
  if (alertId && window.IncidentLifecycle) {
    try {
      const alert = (st.alerts || []).find(a => a.id === alertId) || {};
      const incident = window.IncidentLifecycle.get(st, alertId, alert);
      if (!incident.actions.some(a => a.type === action.type && String(a.target || '').toLowerCase() === normalized)) {
        window.IncidentLifecycle.recordAction(st, alertId, action);
      }
    } catch (err) { console.warn('Could not link response action to incident:', err.message); }
  }
  return entry;
};

// Return explanatory consequences for a log row based on response actions already taken.
window.getSimulatedLogConsequences = function getSimulatedLogConsequences(log) {
  const effects = Object.values(window.shiftState?.effects || {});
  const haystack = `${log?.host || ''} ${log?.user || ''} ${log?.msg || ''}`.toLowerCase();
  return effects.filter(e => e.target && haystack.includes(String(e.target).toLowerCase()) && (Number(log?.rel ?? Infinity) / 60) >= Number(e.min || 0));
};
