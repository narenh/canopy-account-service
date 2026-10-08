const test = require('node:test');
const assert = require('node:assert/strict');
const { codeEmail, sendCode, addressInUseEmail } = require('../lib/mailer');

test('the code email', async () => {
  const { subject, text, html } = codeEmail('482913', 'https://account.canopysf.com/canopy-logo.png');
  assert.equal(subject, '482913 is your Canopy code');
  assert.match(text, /^Your Canopy code is 482913/);
  assert.match(html, /<img src="https:\/\/account\.canopysf\.com\/canopy-logo\.png"/);
  // The code whole, not split, in the box and the hidden preview line.
  assert.equal((html.match(/482913/g) || []).length, 2);
  assert.doesNotMatch(html, /482 913/);
  // Only ever a 6-digit code goes into the page.
  await assert.rejects(sendCode('a@b.co', '<b>hi</b>', 'x'), /6 digits/);
});

// Sent in place of a code when an email change asks for an address that
// already has an account: no code, and nothing about who asked.
test('the address-in-use notice', () => {
  const { subject, text, html } = addressInUseEmail('https://account.canopysf.com/canopy-logo.png');
  assert.equal(subject, 'Someone tried to use this email on Canopy');
  assert.match(text, /already has a Canopy account, so nothing was changed/);
  assert.doesNotMatch(text + html, /\d{6}/);
  assert.match(html, /<img src="https:\/\/account\.canopysf\.com\/canopy-logo\.png"/);
});
