const test = require('node:test');
const assert = require('node:assert/strict');
const { check } = require('../alerts.js');

test('alert without coordinates is flagged', () => {
  const { findings } = check('medium | verified feed | none | Something happened');
  assert.ok(findings.some((f) => f.code === 'MISSING_GEOLOCATION'));
});

test('unverified source on high severity is an error', () => {
  const { findings } = check('high | anonymous tip | 13.75,100.50 | Convoy moving, verified by staff');
  const f = findings.find((x) => x.code === 'SOURCE_UNVERIFIED');
  assert.ok(f && f.level === 'error');
});

test('high severity without a review hint is flagged', () => {
  const { findings } = check('critical | verified feed | 13.75,100.50 | Explosion reported downtown');
  assert.ok(findings.some((f) => f.code === 'HIGH_SEVERITY_NO_REVIEW_HINT'));
});

test('duplicate alert text is flagged with the earlier line', () => {
  const { findings } = check('low | verified feed | 1.0,2.0 | Same event\nmedium | verified feed | 3.0,4.0 | same event');
  const f = findings.find((x) => x.code === 'DUPLICATE_ALERT');
  assert.ok(f && /line 1/.test(f.text));
});

test('long alert text is flagged as payload heavy', () => {
  const { findings } = check('low | verified feed | 1.0,2.0 | ' + 'x'.repeat(300));
  assert.ok(findings.some((f) => f.code === 'PAYLOAD_HEAVY'));
});

test('clean alerts yield the well-formed note', () => {
  const { findings } = check('high | verified NGO feed | 13.75,100.50 | Checkpoint reported, confirmed by field staff');
  assert.ok(findings.some((f) => f.code === 'ALERTS_WELL_FORMED'));
});

test('malformed lines are reported as unparsed', () => {
  const { findings } = check('not valid');
  assert.ok(findings.some((f) => f.code === 'UNPARSED'));
});
