const test = require('node:test');
const assert = require('node:assert/strict');
const Incident = require('../js/incidentLifecycle.js');

function state() { return { incidents: {} }; }

test('new incident begins New and transitions require evidence', () => {
  const s = state();
  assert.equal(Incident.get(s, 'A-1', { rule: 'Suspicious login' }).status, 'New');
  assert.throws(() => Incident.transition(s, 'A-1', 'Investigating'), /evidence/i);
  Incident.addEvidence(s, 'A-1', { description: 'Six failures then successful login', source: 'Windows Security' });
  assert.equal(Incident.transition(s, 'A-1', 'Investigating').status, 'Investigating');
});

test('containment requires an action that has been verified with evidence', () => {
  const s = state();
  Incident.get(s, 'A-2');
  Incident.addEvidence(s, 'A-2', { description: 'Suspicious outbound connection' });
  Incident.transition(s, 'A-2', 'Investigating');
  Incident.recordAction(s, 'A-2', { type: 'block_ip', target: '203.0.113.9', min: 4 });
  assert.throws(() => Incident.transition(s, 'A-2', 'Contained'), /verified/i);
  Incident.verifyAction(s, 'A-2', 0, { verified: true, evidence: 'Follow-up simulated telemetry shows the target flow marked blocked.' });
  assert.throws(() => Incident.transition(s, 'A-2', 'Contained', { residualRisk: true }), /residual risk/i);
  assert.equal(Incident.transition(s, 'A-2', 'Contained', { residualRisk: false }).status, 'Contained');
});

test('resolution requires evidence, explicit confirmation and no residual risk', () => {
  const s = state();
  Incident.get(s, 'A-3');
  Incident.addEvidence(s, 'A-3', { description: 'Malicious email identified' });
  Incident.transition(s, 'A-3', 'Investigating');
  Incident.recordAction(s, 'A-3', { type: 'delete_email', target: 'MSG-7' });
  Incident.verifyAction(s, 'A-3', 0, { verified: true, evidence: 'Message no longer appears in simulated mailbox results.' });
  Incident.transition(s, 'A-3', 'Contained');
  assert.throws(() => Incident.transition(s, 'A-3', 'Resolved'), /confirmation/i);
  assert.throws(() => Incident.transition(s, 'A-3', 'Resolved', { resolutionConfirmed: true, residualRisk: true }), /residual risk/i);
  assert.equal(Incident.transition(s, 'A-3', 'Resolved', { resolutionConfirmed: true, residualRisk: false, reason: 'Verified cleanup' }).status, 'Resolved');
  assert.throws(() => Incident.transition(s, 'A-3', 'Investigating'), /not allowed/i);
});

test('notes and evidence reject empty content and duplicate evidence ids', () => {
  const s = state();
  Incident.get(s, 'A-4');
  assert.throws(() => Incident.addNote(s, 'A-4', '  '), /empty/i);
  Incident.addEvidence(s, 'A-4', { id: 'EV-1', description: 'Log evidence' });
  assert.throws(() => Incident.addEvidence(s, 'A-4', { id: 'EV-1', description: 'Duplicate' }), /Duplicate/i);
});

test('summary reports incident lifecycle counts', () => {
  const s = state();
  Incident.get(s, 'a'); Incident.get(s, 'b'); Incident.get(s, 'c');
  Incident.addEvidence(s, 'b', { description: 'evidence' });
  Incident.transition(s, 'b', 'Investigating');
  Incident.addEvidence(s, 'c', { description: 'evidence' });
  Incident.transition(s, 'c', 'Investigating');
  Incident.recordAction(s, 'c', { type: 'isolate_host', target: 'WS-1' });
  Incident.verifyAction(s, 'c', 0, { verified: true, evidence: 'Simulated verification' });
  Incident.transition(s, 'c', 'Contained');
  assert.deepEqual(Incident.summary(s), { total: 3, new: 1, investigating: 1, contained: 1, resolved: 0 });
});
