const test = require('node:test');
const assert = require('node:assert/strict');
const { codeEmail, sendCode } = require('../lib/mailer');

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
