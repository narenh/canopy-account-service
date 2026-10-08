// Where you're signed in: the profile's list of browsers (and apps), with
// signing one out, and signing out everywhere.

const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, browser } = require('./harness');

const IPHONE_SAFARI = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';
const MAC_CHROME = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

test('where you are signed in', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');

  const phone = browser(server);
  const anaId = (await phone.signUp('ana@example.com', 'Ana', 'Lima', { headers: { 'User-Agent': IPHONE_SAFARI } })).data.person.id;
  const laptop = browser(server);
  laptop.authenticator.creds.push(...phone.authenticator.creds);
  assert.equal((await laptop.signInWithPasskey(undefined, { headers: { 'User-Agent': MAC_CHROME } })).data.person.id, anaId);

  await t.test('each browser, named from its User-Agent, this one marked', async () => {
    const r = await phone.get('/api/profile/sessions');
    assert.equal(r.status, 200, r.text);
    const names = r.data.sessions.map((s) => s.name).sort();
    assert.deepEqual(names, ['Chrome on Mac', 'Safari on iPhone']);
    const mine = r.data.sessions.find((s) => s.current);
    assert.equal(mine.name, 'Safari on iPhone');
    assert.equal(mine.kind, 'web');
    assert.ok(mine.signedInAt && mine.lastSeenAt);
    assert.match(mine.id, /^[0-9a-f]{24}$/);
    assert.equal(r.data.sessions.filter((s) => s.current).length, 1);
    // Only ever your own.
    assert.equal((await admin.get('/api/profile/sessions')).data.sessions.length, 1);
    assert.equal((await browser(server).get('/api/profile/sessions')).status, 401);
  });

  await t.test("signing out another browser; someone else's is not found", async () => {
    const theirs = (await admin.get('/api/profile/sessions')).data.sessions[0].id;
    assert.equal((await phone.del('/api/profile/sessions/' + theirs)).status, 404);
    assert.ok((await admin.get('/api/me')).data.person, 'the admin is still signed in');
    const laptopId = (await phone.get('/api/profile/sessions')).data.sessions.find((s) => !s.current).id;
    const r = await phone.del('/api/profile/sessions/' + laptopId);
    assert.equal(r.status, 200, r.text);
    assert.equal(r.data.current, false);
    assert.equal((await laptop.get('/api/me')).data.person, null);
    assert.ok((await phone.get('/api/me')).data.person, 'this one is still in');
  });

  await t.test('signing out everywhere ends every session, this one included', async () => {
    const other = browser(server);
    other.authenticator.creds.push(...phone.authenticator.creds);
    await other.signInWithPasskey();
    const r = await phone.post('/api/signout/everywhere');
    assert.equal(r.status, 200, r.text);
    assert.equal(phone.cookie, null, 'the cookie was cleared');
    assert.equal((await other.get('/api/me')).data.person, null);
    assert.ok((await admin.get('/api/me')).data.person, "nobody else's");
  });

  await t.test('the profile page has the list', async () => {
    await phone.signInWithPasskey();
    assert.match((await phone.get('/profile')).text, /id="sessionList"/);
  });
});
