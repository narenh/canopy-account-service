const test = require('node:test');
const assert = require('node:assert/strict');
const { isCanopyUrl, isCanopyOrigin, safeReturn, cookieDomainFor, passkeyRpId } = require('../lib/domain');

test('what counts as a Canopy page', () => {
  assert.ok(isCanopyUrl('https://canopysf.com/'));
  assert.ok(isCanopyUrl('https://tickets.canopysf.com/mine?x=1'));
  assert.ok(isCanopyUrl('https://a.b.canopysf.com/'));
  assert.ok(!isCanopyUrl('http://tickets.canopysf.com/'), 'https only');
  assert.ok(!isCanopyUrl('https://canopysf.com.evil.example/'));
  assert.ok(!isCanopyUrl('https://evilcanopysf.com/'));
  assert.ok(!isCanopyUrl('https://canopysf.com@evil.example/'));
  assert.ok(!isCanopyUrl('https://x:y@tickets.canopysf.com/'));
  assert.ok(!isCanopyUrl('javascript:alert(1)'));
  assert.ok(!isCanopyUrl('//tickets.canopysf.com/'));
  assert.ok(!isCanopyOrigin('null'));
  assert.ok(!isCanopyOrigin(undefined));
  assert.equal(safeReturn('https://evil.example/'), null);
  assert.equal(safeReturn('https://tickets.canopysf.com/a b'), 'https://tickets.canopysf.com/a%20b');
});

test('cookie domain and passkey RP', () => {
  assert.equal(cookieDomainFor('account.canopysf.com'), 'canopysf.com');
  assert.equal(cookieDomainFor('localhost'), null);
  assert.equal(passkeyRpId('account.canopysf.com'), 'canopysf.com');
  assert.equal(passkeyRpId('localhost'), 'localhost');
});
