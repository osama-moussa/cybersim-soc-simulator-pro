const test = require('node:test');
const assert = require('node:assert/strict');
const ShiftScoring = require('../js/scoring.js');

const scenario = {
  id: 'test-shift',
  alerts: [
    { id: 'A-1', at: 5, severity: 'High', rule: 'Suspicious PowerShell', host: 'WS-01', user: 'analyst1', details: { src_ip: '203.0.113.10' }, truth: { verdict: 'TP', severity: 'High', escalate: true, mitre: 'T1059.001' } },
    { id: 'A-2', at: 10, severity: 'Low', rule: 'Approved scanner', host: 'SCAN-01', user: 'svc-scan', details: { src_ip: '10.0.0.5' }, truth: { verdict: 'FP', severity: 'Low', escalate: false, mitre: null } }
  ],
  expected_actions: ['block_ip:203.0.113.10', 'escalate_tier2', 'close_false_positive'],
  iocs: {}
};

test('investigation evidence is attributed to the relevant alert, not every alert', () => {
  const result = ShiftScoring.evaluate({
    scenario,
    released: ['A-1', 'A-2'],
    decisions: {
      'A-1': { verdict: 'TP', severity: 'High', escalate: true, responseMin: 5 },
      'A-2': { verdict: 'FP', severity: 'Low', escalate: false, responseMin: 5 }
    },
    actions: [{ type: 'block_ip', target: '203.0.113.10' }],
    activity: [{ type: 'log_search', query: '203.0.113.10', alertId: 'A-1', min: 6 }]
  });
  assert.equal(result.rows.find(r => r.id === 'A-1').investigated, true);
  assert.equal(result.rows.find(r => r.id === 'A-2').investigated, false);
});

test('pre-detail search only counts when its query matches alert evidence', () => {
  const result = ShiftScoring.evaluate({
    scenario,
    released: ['A-1'],
    decisions: { 'A-1': { verdict: 'TP', severity: 'High', escalate: true, responseMin: 5 } },
    activity: [{ type: 'ioc_lookup', query: '203.0.113.10', min: 6 }]
  });
  assert.equal(result.rows[0].investigated, true);
});

test('unrelated search does not count as investigation evidence', () => {
  const result = ShiftScoring.evaluate({
    scenario,
    released: ['A-1'],
    decisions: { 'A-1': { verdict: 'TP', severity: 'High', escalate: true, responseMin: 5 } },
    activity: [{ type: 'log_search', query: 'random-user', min: 6 }]
  });
  assert.equal(result.rows[0].investigated, false);
});

test('a missed true-positive alert is reported as critical and receives no triage points', () => {
  const result = ShiftScoring.evaluate({ scenario, released: ['A-1'], decisions: {}, actions: [], activity: [] });
  assert.equal(result.rows[0].triage, 0);
  assert.ok(result.findings.some(f => f.level === 'critical' && f.text.includes('never triaged')));
});


test('investigation work is retained for alerts that remain open at shift end', () => {
  const result = ShiftScoring.evaluate({
    scenario,
    released: ['A-1'],
    decisions: {},
    activity: [{ type: 'log_search', query: '203.0.113.10', alertId: 'A-1', min: 6 }]
  });
  assert.equal(result.rows[0].investigated, true);
  assert.equal(result.rows[0].triage, 0);
});


test('expected response actions are assessed against the related alert SLA', () => {
  const result = ShiftScoring.evaluate({
    scenario,
    released: ['A-1'],
    decisions: { 'A-1': { verdict: 'TP', severity: 'High', escalate: true, responseMin: 10 } },
    actions: [{ type: 'block_ip', target: '203.0.113.10', min: 40 }],
    activity: [{ type: 'log_search', query: '203.0.113.10', alertId: 'A-1', min: 7 }]
  });
  const action = result.expected.find(e => e.raw === 'block_ip:203.0.113.10');
  assert.equal(action.met, true);
  assert.equal(action.relatedAlertId, 'A-1');
  assert.equal(action.timing, 'late');
  assert.equal(action.delayMin, 35);
  assert.equal(result.lateActions.length, 1);
  assert.ok(result.findings.some(f => f.text.includes('response target was 30 min')));
});

test('response actions recorded before the related alert are flagged as premature', () => {
  const result = ShiftScoring.evaluate({
    scenario,
    released: ['A-1'],
    decisions: {},
    actions: [{ type: 'block_ip', target: '203.0.113.10', min: 2 }],
    activity: []
  });
  const action = result.expected.find(e => e.raw === 'block_ip:203.0.113.10');
  assert.equal(action.timing, 'premature');
  assert.equal(action.delayMin, -3);
  assert.equal(result.prematureActions.length, 1);
});

test('incident lifecycle quality is reported from evidence and verified actions, not action count alone', () => {
  const result = ShiftScoring.evaluate({
    scenario, released: ['A-1'], decisions: {}, actions: [], activity: [],
    incidents: { 'A-1': { alertId: 'A-1', status: 'Investigating', evidence: [{ description: 'Matching event in endpoint log' }], actions: [{ type: 'isolate_host', verified: false }], history: [] } }
  });
  assert.equal(result.lifecycle.cases, 1);
  assert.equal(result.lifecycle.evidenceCount, 1);
  assert.equal(result.lifecycle.verifiedCount, 0);
  assert.equal(result.lifecycle.quality, 50);
  assert.ok(result.findings.some(f => f.text.includes('Incident lifecycle quality')));
});


test('verified incident lifecycle quality contributes to the final shift score', () => {
  const common = {
    scenario, released: ['A-1'],
    decisions: { 'A-1': { verdict: 'TP', severity: 'High', escalate: true, responseMin: 5 } },
    actions: [{ type: 'block_ip', target: '203.0.113.10', min: 6 }],
    activity: [{ type: 'log_search', query: '203.0.113.10', alertId: 'A-1', min: 6 }]
  };
  const incomplete = ShiftScoring.evaluate({ ...common, incidents: { 'A-1': { alertId: 'A-1', status: 'Investigating', evidence: [{ description: 'Matching event in endpoint log' }], actions: [{ type: 'block_ip', verified: false }], history: [] } } });
  const verified = ShiftScoring.evaluate({ ...common, incidents: { 'A-1': { alertId: 'A-1', status: 'Contained', evidence: [{ description: 'Matching event in endpoint log' }], actions: [{ type: 'block_ip', verified: true, verification: 'Follow-up simulated telemetry confirms the control state.' }], history: [] } } });
  assert.equal(incomplete.categories.lifecycle, 50);
  assert.equal(verified.categories.lifecycle, 100);
  assert.equal(verified.total - incomplete.total, 5);
});
