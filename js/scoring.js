// js/scoring.js — shift scoring (pure logic, no DOM)
// Compares the analyst's decisions, response actions and investigation
// activity against the scenario's hidden "truth".

const ShiftScoring = (() => {
  const SEV = ['Low', 'Medium', 'High', 'Critical'];
  const SLA = { Critical: 15, High: 30, Medium: 60, Low: 120 };          // minutes
  const WEIGHTS = { triage: 0.35, response: 0.25, investigation: 0.15, speed: 0.15, lifecycle: 0.10 };
  const INVESTIGATION_TYPES = ['log_search', 'ioc_lookup', 'context_view'];
  // Harmless extras are never penalised when not expected
  const LOW_RISK = new Set(['notify_manager', 'notify_finance', 'notify_hr_legal',
    'document_policy_violation', 'preserve_evidence', 'scan_host', 'confirm_quarantine']);

  const MITRE = {
    'T1566.001': 'Phishing: Spearphishing Attachment', 'T1566.002': 'Phishing: Spearphishing Link',
    'T1078': 'Valid Accounts', 'T1056.003': 'Input Capture: Web Portal Capture',
    'T1110': 'Brute Force', 'T1110.003': 'Brute Force: Password Spraying',
    'T1595': 'Active Scanning', 'T1204.002': 'User Execution: Malicious File',
    'T1059': 'Command and Scripting Interpreter', 'T1059.001': 'PowerShell',
    'T1496': 'Resource Hijacking', 'T1091': 'Replication Through Removable Media',
    'T1190': 'Exploit Public-Facing Application', 'T1090.003': 'Proxy: Multi-hop Proxy',
    'T1490': 'Inhibit System Recovery', 'T1486': 'Data Encrypted for Impact',
    'T1071.004': 'Application Layer Protocol: DNS', 'T1021.002': 'Remote Services: SMB/Windows Admin Shares',
    'T1003.001': 'OS Credential Dumping: LSASS Memory', 'T1003.006': 'OS Credential Dumping: DCSync',
    'T1560.001': 'Archive Collected Data: Archive via Utility', 'T1567.002': 'Exfiltration to Cloud Storage',
    'T1558.003': 'Steal or Forge Kerberos Tickets: Kerberoasting', 'T1505.003': 'Server Software Component: Web Shell',
    'T1530': 'Data from Cloud Storage', 'T1052.001': 'Exfiltration over USB',
    'T1114.003': 'Email Collection: Email Forwarding Rule', 'T1534': 'Internal Spearphishing',
    'T1136.001': 'Create Account: Local Account',
  };

  const clean = t => String(t).trim().toLowerCase().replace(/\[\.\]/g, '.');
  const key = (type, target) => (target ? `${type}:${clean(target)}` : type);
  const parse = s => { const i = s.indexOf(':'); return i < 0 ? { type: s, target: null } : { type: s.slice(0, i), target: s.slice(i + 1) }; };
  const mean = a => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0);
  const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));
  const isInternal = ip => /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip);
  const describe = (type, target) => `${type.replace(/_/g, ' ')}${target ? ` ${target}` : ''}`;

  function grade(score) {
    return score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
  }

  function evaluate({ scenario, released = [], decisions = {}, actions = [], activity = [], incidents = {} }) {
    const relSet = new Set(released);
    const alerts = scenario.alerts.filter(a => relSet.has(a.id));
    const findings = [];
    const rows = [];

    // ---------------------------------------------------------- per-alert triage
    for (const a of alerts) {
      const t = a.truth, d = decisions[a.id] || null;
      const sla = t.verdict === 'TP'
        ? Math.min(SLA[a.severity] ?? 120, SLA[t.severity] ?? 120)
        : (SLA[a.severity] ?? 120);
      const row = {
        id: a.id, rule: a.rule, truth: t, decision: d, sla,
        mitre: t.mitre ? `${t.mitre} ${MITRE[t.mitre] || ''}`.trim() : null,
        points: { verdict: 0, severity: 0, escalation: 0 }, triage: 0, speed: 0,
        responseMin: null, investigated: false,
      };

      const rm = d && Number.isFinite(d.responseMin) ? d.responseMin : null;
      row.responseMin = rm;
      const decidedAtMin = rm === null ? Infinity : a.at + rm;
      const alertTokens = [a.id, a.rule, a.host, a.user, ...Object.values(a.details || {})]
        .filter(v => typeof v === 'string' || typeof v === 'number')
        .map(v => clean(v));
      row.investigated = activity.some(x => {
        if (!INVESTIGATION_TYPES.includes(x.type) || !Number.isFinite(x.min)) return false;
        if (x.min < a.at - 0.01 || x.min > decidedAtMin + 0.01) return false;
        if (x.alertId) return x.alertId === a.id;
        // Searches made before opening an alert count only when the query matches its identifiers.
        const q = clean(x.query || '');
        return x.type === 'context_view' ? false : Boolean(q && alertTokens.some(token => token.length >= 4 && q.includes(token)));
      });

      if (!d) {
        findings.push(t.verdict === 'TP'
          ? { level: 'critical', text: `${a.id} (${a.rule}) was never triaged, and it was a real threat.` }
          : { level: 'warn', text: `${a.id} (${a.rule}) was left open.` });
        rows.push(row);
        continue;
      }

      const verdictOk = d.verdict === t.verdict;
      row.points.verdict = verdictOk ? 50 : 0;
      if (verdictOk) {
        if (t.verdict === 'FP') row.points.severity = 25;                 // severity is moot for benign events
        else {
          const diff = Math.abs(SEV.indexOf(d.severity) - SEV.indexOf(t.severity));
          row.points.severity = diff === 0 ? 25 : diff === 1 ? 12 : 0;
        }
        row.points.escalation = Boolean(d.escalate) === Boolean(t.escalate) ? 25 : 0;
      }
      row.triage = row.points.verdict + row.points.severity + row.points.escalation;

      row.speed = rm === null ? 50 : rm <= sla ? 100 : rm <= sla * 2 ? 50 : 0;

      if (t.verdict === 'TP' && d.verdict === 'FP')
        findings.push({ level: 'critical', text: `${a.id} (${a.rule}) was a real threat but you closed it as a False Positive.` });
      else if (t.verdict === 'FP' && d.verdict === 'TP')
        findings.push({ level: 'warn', text: `${a.id} (${a.rule}) was benign, but you closed it as a True Positive.` });
      else if (verdictOk && t.escalate && !d.escalate)
        findings.push({ level: 'critical', text: `${a.id} (${a.rule}) required escalation to Tier 2 and you did not escalate.` });
      else if (verdictOk && !t.escalate && d.escalate)
        findings.push({ level: 'warn', text: `${a.id} (${a.rule}) did not need escalation.` });
      if (rm !== null && rm > sla)
        findings.push({ level: 'warn', text: `${a.id} was closed after ${rm.toFixed(1)} min; the SLA is ${sla} min.` });
      rows.push(row);
    }

    const blind = rows.filter(r => r.decision && !r.investigated).length;
    if (blind) findings.push({ level: 'warn', text: `${blind} alert(s) were closed without checking any evidence (logs, IOC lookup or context).` });

    // ---------------------------------------------------------- response actions
    const executed = new Map();
    for (const a of actions) executed.set(key(a.type, a.target), a);

    const relatedAlertForTarget = (target, actionMin) => {
      if (!target) return null;
      const needle = clean(target);
      const matches = alerts.filter(a => [a.id, a.host, a.user, ...Object.values(a.details || {})]
        .filter(v => typeof v === 'string' || typeof v === 'number')
        .some(v => clean(v) === needle || clean(v).includes(needle)));
      if (!matches.length) return null;
      // If the same account/host appears in multiple alerts, associate the action with
      // the most recent matching alert already released at action time.
      const prior = matches.filter(a => !Number.isFinite(actionMin) || a.at <= actionMin)
        .sort((a, b) => b.at - a.at);
      return prior[0] || matches.sort((a, b) => a.at - b.at)[0];
    };
    const expected = [...new Set(scenario.expected_actions || [])].map(raw => {
      const { type, target } = parse(raw);
      let met;
      if (type === 'escalate_tier2') met = alerts.some(a => a.truth.escalate && decisions[a.id]?.escalate);
      else if (type === 'close_false_positive') {
        const fp = alerts.filter(a => a.truth.verdict === 'FP');
        met = fp.length > 0 && fp.every(a => decisions[a.id]?.verdict === 'FP');
      } else met = executed.has(key(type, target));
      const action = type === 'escalate_tier2' || type === 'close_false_positive' ? null : executed.get(key(type, target)) || null;
      const relatedAlert = relatedAlertForTarget(target, action?.min);
      let timing = 'not-applicable', delayMin = null, sla = null;
      if (action && relatedAlert && Number.isFinite(action.min)) {
        sla = Math.min(SLA[relatedAlert.severity] ?? 120, SLA[relatedAlert.truth?.severity] ?? 120);
        delayMin = +(action.min - relatedAlert.at).toFixed(1);
        timing = delayMin < 0 ? 'premature' : delayMin > sla ? 'late' : 'within-sla';
      }
      return { raw, type, target, met, action, relatedAlertId: relatedAlert?.id || null, timing, delayMin, sla,
        derived: type === 'escalate_tier2' || type === 'close_false_positive' };
    });

    const expectedKeys = new Set(expected.map(e => key(e.type, e.target)));
    const hasTP = alerts.some(a => a.truth.verdict === 'TP');
    const benign = new Set();
    alerts.filter(a => a.truth.verdict === 'FP').forEach(a => {
      [a.host, a.user].forEach(v => v && benign.add(clean(v)));
      Object.values(a.details || {}).forEach(v => { if (typeof v === 'string' && v.length < 80) benign.add(clean(v)); });
    });
    Object.entries(scenario.iocs || {}).forEach(([k, v]) => {
      if (['clean', 'benign'].includes(v.reputation)) benign.add(clean(k));
    });

    const harmful = [], unnecessary = [];
    for (const [k, a] of executed) {
      if (expectedKeys.has(k)) continue;
      if (LOW_RISK.has(a.type)) continue;
      const tgt = a.target ? clean(a.target) : null;
      const bad = !hasTP || (tgt && (benign.has(tgt) || (a.type === 'block_ip' && isInternal(tgt))));
      (bad ? harmful : unnecessary).push(a);
    }

    const metCount = expected.filter(e => e.met).length;
    const coverage = expected.length ? metCount / expected.length : 1;
    const lateActions = expected.filter(e => e.met && e.timing === 'late');
    const prematureActions = expected.filter(e => e.met && e.timing === 'premature');
    const response = clamp(Math.round(coverage * 100 - 20 * harmful.length - 5 * unnecessary.length - 8 * lateActions.length - 5 * prematureActions.length), 0, 100);

    lateActions.forEach(e => findings.push({ level: 'warn', text: `${describe(e.type, e.target)} was taken ${e.delayMin.toFixed(1)} min after ${e.relatedAlertId}; the response target was ${e.sla} min.` }));
    prematureActions.forEach(e => findings.push({ level: 'warn', text: `${describe(e.type, e.target)} was recorded ${Math.abs(e.delayMin).toFixed(1)} min before related alert ${e.relatedAlertId}; confirm that the evidence justified acting that early.` }));
    harmful.forEach(a => findings.push({ level: 'critical', text: `Disruptive action on a benign event or asset: ${describe(a.type, a.target)}.` }));
    const missing = expected.filter(e => !e.met && !e.derived);
    if (missing.length) findings.push({ level: 'warn', text: `Missing response: ${missing.slice(0, 4).map(e => describe(e.type, e.target)).join('; ')}${missing.length > 4 ? '…' : ''}.` });

    // ---------------------------------------------------------- totals
    const categories = {
      triage: Math.round(mean(rows.map(r => r.triage))),
      response,
      investigation: Math.round(mean(rows.map(r => (r.investigated ? 100 : 0)))),
      speed: Math.round(mean(rows.map(r => r.speed))),
    };
    // Lifecycle quality is evidence-based: an action log alone is not verification.
    const incidentCases = alerts.map(a => incidents[a.id] || { alertId: a.id, status: 'New', evidence: [], actions: [], history: [] });
    const evidenceCount = incidentCases.reduce((n, c) => n + (c.evidence || []).length, 0);
    const verifiedCount = incidentCases.reduce((n, c) => n + (c.actions || []).filter(a => a.verified === true && String(a.verification || '').trim()).length, 0);
    const lifecycleQuality = incidentCases.length ? Math.round(100 * (
      incidentCases.filter(c => (c.evidence || []).length > 0).length / incidentCases.length * 0.5 +
      incidentCases.filter(c => ['Contained','Resolved'].includes(c.status) && (c.actions || []).some(a => a.verified && String(a.verification || '').trim())).length / incidentCases.length * 0.5
    )) : 0;
    categories.lifecycle = lifecycleQuality;
    if (incidentCases.length) {
      findings.push({ level: lifecycleQuality >= 75 ? 'good' : lifecycleQuality >= 40 ? 'warn' : 'critical',
        text: `Incident lifecycle quality: ${lifecycleQuality}/100; ${evidenceCount} evidence item(s), ${verifiedCount} verified response action(s). Recorded actions without verification do not count as verified containment.` });
    }
    const total = rows.length ? Math.round(
      WEIGHTS.triage * categories.triage + WEIGHTS.response * categories.response +
      WEIGHTS.investigation * categories.investigation + WEIGHTS.speed * categories.speed + WEIGHTS.lifecycle * lifecycleQuality) : 0;

    const order = { critical: 0, warn: 1, good: 2 };
    if (!findings.some(f => f.level === 'critical') && total >= 80)
      findings.push({ level: 'good', text: 'No critical mistakes: threats were handled and benign events were not disrupted.' });
    findings.sort((x, y) => order[x.level] - order[y.level]);

    return { total, grade: grade(total), categories, weights: WEIGHTS, rows, expected, harmful, unnecessary, lateActions, prematureActions, findings, mitre: MITRE, lifecycle: { cases: incidentCases.length, evidenceCount, verifiedCount, quality: lifecycleQuality } };
  }

  return { evaluate, grade, MITRE, SLA, WEIGHTS };
})();

if (typeof module !== 'undefined') module.exports = ShiftScoring;
