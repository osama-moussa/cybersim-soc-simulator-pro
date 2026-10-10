const test = require('node:test');
const assert = require('node:assert/strict');

global.window = { activeAlertId: 'A-1' };
require('../js/state.js');

test('response actions create explicit simulated environment effects and audit activity', () => {
  window.shiftState.reset();
  const effect = window.applySimulatedAction({ type: 'isolate_host', target: 'WS-01', clock: '09:10:00', min: 10 });
  assert.equal(effect.status, 'host_isolated');
  assert.equal(effect.target, 'WS-01');
  assert.equal(window.shiftState.activity[0].alertId, 'A-1');
  assert.match(effect.effect, /simulation/i);
});

test('later matching log rows are annotated with relevant simulated response consequences', () => {
  window.shiftState.reset();
  window.applySimulatedAction({ type: 'block_ip', target: '203.0.113.10', clock: '09:10:00', min: 10 });
  assert.equal(window.getSimulatedLogConsequences({ host: 'WS-01', user: 'u', msg: 'connection to 203.0.113.10', rel: 11 * 60 }).length, 1);
  assert.equal(window.getSimulatedLogConsequences({ host: 'WS-01', user: 'u', msg: 'connection to 203.0.113.10', rel: 9 * 60 }).length, 0);
  assert.equal(window.getSimulatedLogConsequences({ host: 'WS-01', user: 'u', msg: 'normal activity', rel: 11 * 60 }).length, 0);
});

test('unrelated log rows are not changed by a response action', () => {
  window.shiftState.reset();
  window.applySimulatedAction({ type: 'disable_account', target: 'user-a', clock: '09:10:00', min: 10 });
  assert.deepEqual(window.getSimulatedLogConsequences({ host: 'WS-01', user: 'user-b', msg: 'login succeeded', rel: 12 * 60 }), []);
});
