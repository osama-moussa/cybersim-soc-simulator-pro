const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

global.window = global.window || {};
require('../js/engine.js');
const ScenarioEngine = global.window.ScenarioEngine;

const root = path.join(__dirname, '..', 'data', 'scenarios');
const index = JSON.parse(fs.readFileSync(path.join(root, 'index.json'), 'utf8'));

test('scenario index points to existing unique scenario files', () => {
  const ids = new Set();
  for (const item of index) {
    assert.ok(item.id && !ids.has(item.id), `duplicate/missing index id: ${item.id}`);
    ids.add(item.id);
    const file = path.join(root, item.file);
    assert.ok(fs.existsSync(file), `missing scenario file: ${item.file}`);
    const scenario = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.equal(scenario.id, item.id);
  }
});

test('all indexed scenarios pass engine validation', () => {
  const engine = new ScenarioEngine();
  for (const item of index) {
    const scenario = JSON.parse(fs.readFileSync(path.join(root, item.file), 'utf8'));
    assert.doesNotThrow(() => engine._validate(scenario), item.id);
  }
});

test('engine rejects duplicate alert IDs and invalid severities', () => {
  const engine = new ScenarioEngine();
  const base = { id: 'test', alerts: [{ id: 'A-1', at: 1, severity: 'Low', truth: { verdict: 'FP', severity: 'Low', escalate: false } }] };
  assert.doesNotThrow(() => engine._validate(base));
  assert.throws(() => engine._validate({ ...base, alerts: [...base.alerts, { ...base.alerts[0] }] }), /Duplicate alert id/);
  assert.throws(() => engine._validate({ ...base, alerts: [{ ...base.alerts[0], severity: 'Urgent' }] }), /invalid severity/);
});


test('shift checkpoint restores elapsed time, released alerts, and analyst state', () => {
  const engine = new ScenarioEngine();
  const scenario = {
    id: 'checkpoint-test', title: 'Checkpoint test', startTime: '09:00:00',
    alerts: [{ id: 'A-1', at: 1, severity: 'Low', truth: { verdict: 'FP', severity: 'Low', escalate: false } }]
  };
  engine.scenario = scenario;
  engine.startClock = 9 * 3600;
  engine.shiftMinutes = 20;
  engine.elapsedMs = 18000;
  engine.released.add('A-1');
  global.window.shiftState = {
    alerts: [{ id: 'A-1', at: 1, severity: 'Low', releasedAt: '09:01:00' }],
    decisions: { 'A-1': { verdict: 'FP', severity: 'Low', escalate: false, responseMin: 2 } },
    actions: [{ type: 'notify_manager', target: null, min: 3, clock: '09:03:00' }],
    activity: [{ type: 'log_search', query: 'A-1', alertId: 'A-1', min: 2 }],
    effects: { 'isolate_host:WS-01': { type: 'isolate_host', target: 'WS-01', status: 'recorded', at: '09:03:00' } }
  };
  const snapshot = engine.createSnapshot(global.window.shiftState);
  engine.elapsedMs = 0;
  engine.released.clear();
  global.window.shiftState.decisions = {};
  engine.restoreSnapshot(snapshot);
  assert.equal(engine.scenario.id, 'checkpoint-test');
  assert.equal(engine.minutes, 3);
  assert.deepEqual([...engine.released], ['A-1']);
  assert.equal(global.window.shiftState.decisions['A-1'].verdict, 'FP');
  assert.equal(global.window.shiftState.actions.length, 1);
  assert.equal(global.window.shiftState.activity.length, 1);
  assert.equal(global.window.shiftState.effects['isolate_host:WS-01'].status, 'recorded');
});

test('shift checkpoint rejects unsupported or malformed snapshots', () => {
  const engine = new ScenarioEngine();
  assert.throws(() => engine.restoreSnapshot({ version: 999, scenario: { id: 'bad', alerts: [] } }), /invalid or unsupported/);
});
