// js/responseModel.js — explain, but do not fabricate, simulated response impact.
// Pure logic: no DOM, storage, network calls, or real security controls.
(function (root) {
  const normalize = value => String(value ?? '').trim().toLowerCase()
    .replace(/\[\.\]/g, '.').replace(/^hxxps?:\/\//, '').replace(/^https?:\/\//, '')
    .replace(/[<>"']/g, '').replace(/\/$/, '');

  function targetMatches(effect, log) {
    const target = normalize(effect?.target);
    if (!target) return false;
    const type = String(effect.type || '');
    const host = normalize(log.host), user = normalize(log.user);
    const msg = normalize(log.msg);
    const all = normalize([log.srcIp, log.dstIp, log.ip, log.hash, log.domain, log.url, log.msg].filter(Boolean).join(' '));
    if (type === 'isolate_host') return host === target;
    if (['disable_account', 'reset_password', 'revoke_sessions', 'enforce_mfa'].includes(type)) {
      return user === target || user.endsWith('\\' + target) || msg.includes(target);
    }
    if (['block_ip'].includes(type)) return normalize(log.srcIp) === target || normalize(log.dstIp) === target || all.includes(target);
    if (['block_domain', 'remove_inbox_rule', 'delete_email'].includes(type)) return msg.includes(target) || normalize(log.domain) === target || normalize(log.url).includes(target);
    if (type === 'block_hash') return normalize(log.hash) === target || msg.includes(target);
    return false;
  }

  function assessLog(log, effects = []) {
    const matching = effects.filter(effect => targetMatches(effect, log));
    const relMin = Number.isFinite(Number(log.rel)) ? Number(log.rel) / 60 : null;
    const relevant = matching.filter(effect => relMin !== null && Number.isFinite(Number(effect.min)));
    const before = relevant.filter(effect => Number(effect.min) <= relMin);
    const after = relevant.filter(effect => Number(effect.min) > relMin);
    let status = 'no-matching-control';
    if (before.length) status = 'observed-after-control';
    else if (after.length) status = 'occurred-before-control';
    return {
      logTime: log.t || null,
      source: log.src || null,
      host: log.host || null,
      user: log.user || null,
      message: log.msg || '',
      status,
      matchingActions: (before.length ? before : after).map(e => ({ type: e.type, target: e.target, at: e.at || '', min: Number(e.min) || 0, effect: e.effect || '' })),
      explanation: status === 'observed-after-control'
        ? 'Matching activity is still present in the supplied log after the simulated control time; this is not proof that the control failed or prevented later activity.'
        : status === 'occurred-before-control'
          ? 'This event predates the matching simulated control, so the action could not have prevented this recorded event.'
          : 'No supported action-to-log match was found; no impact is inferred.'
    };
  }

  function assessLogs(logs = [], effects = []) {
    const rows = logs.map(log => assessLog(log, effects));
    return {
      rows,
      summary: {
        totalLogs: rows.length,
        observedAfterControl: rows.filter(r => r.status === 'observed-after-control').length,
        occurredBeforeControl: rows.filter(r => r.status === 'occurred-before-control').length,
        noMatchingControl: rows.filter(r => r.status === 'no-matching-control').length
      }
    };
  }

  const api = { assessLog, assessLogs, targetMatches };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.ResponseModel = api;
})(typeof window !== 'undefined' ? window : globalThis);
