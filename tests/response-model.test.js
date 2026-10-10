const test = require('node:test');
const assert = require('node:assert/strict');
const ResponseModel = require('../js/responseModel.js');

const effects = [
  { type: 'block_ip', target: '203.0.113.9', min: 5, at: '09:05:00', effect: 'Simulated block' },
  { type: 'isolate_host', target: 'WS-01', min: 8, at: '09:08:00', effect: 'Simulated isolation' },
  { type: 'disable_account', target: 'alice', min: 9, at: '09:09:00', effect: 'Simulated disable' }
];

test('classifies matching IP activity after a simulated block without claiming prevention', () => {
  const row = ResponseModel.assessLog({ t: '09:06:00', rel: 6 * 60, srcIp: '203.0.113.9', host: 'GW-01', msg: 'connection' }, effects);
  assert.equal(row.status, 'observed-after-control');
  assert.match(row.explanation, /not proof/i);
  assert.equal(row.matchingActions[0].type, 'block_ip');
});

test('classifies a host event before isolation as occurring before control', () => {
  const row = ResponseModel.assessLog({ t: '09:07:00', rel: 7 * 60, host: 'WS-01', msg: 'process started' }, effects);
  assert.equal(row.status, 'occurred-before-control');
  assert.equal(row.matchingActions[0].type, 'isolate_host');
});

test('account actions match the user but unrelated users do not', () => {
  assert.equal(ResponseModel.assessLog({ rel: 10 * 60, user: 'alice', msg: 'login' }, effects).status, 'observed-after-control');
  assert.equal(ResponseModel.assessLog({ rel: 10 * 60, user: 'bob', msg: 'login' }, effects).status, 'no-matching-control');
});

test('summary counts each supplied log row exactly once', () => {
  const result = ResponseModel.assessLogs([
    { rel: 6 * 60, srcIp: '203.0.113.9' },
    { rel: 2 * 60, host: 'WS-01' },
    { rel: 4 * 60, user: 'bob' }
  ], effects);
  assert.deepEqual(result.summary, { totalLogs: 3, observedAfterControl: 1, occurredBeforeControl: 1, noMatchingControl: 1 });
});

test('normalizes defanged domains and does not infer impact for unsupported action types', () => {
  const domain = [{ type: 'block_domain', target: 'evil[.]example', min: 1, effect: 'blocked' }];
  assert.equal(ResponseModel.assessLog({ rel: 2 * 60, msg: 'GET evil.example/login' }, domain).status, 'observed-after-control');
  assert.equal(ResponseModel.assessLog({ rel: 2 * 60, host: 'WS-01', msg: 'event' }, [{ type: 'notify_manager', target: 'WS-01', min: 1 }]).status, 'no-matching-control');
});
