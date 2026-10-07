// Changing your own email: a passkey check, a code to the new address,
// and a notice to the old one.

const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, browser } = require('./harness');

test('changing your own email', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const ana = browser(server);
  const anaId = (await ana.signUp('ana@example.com', 'Ana', 'Lima')).data.person.id;

  const reauth = async (b, credId) => {
    const start = await b.post('/api/auth/reauth/options');
    assert.equal(start.status, 200, start.text);
    assert.equal(start.data.options.userVerification, 'required');
    const response = b.authenticator.authenticate(start.data.options, server.base, credId);
    return b.post('/api/auth/reauth/verify', { response });
  };

  await t.test('no passkey check, no change', async () => {
    const r = await ana.post('/api/profile/email/start', { email: 'ana.new@example.com' });
    assert.equal(r.status, 403);
    assert.equal(r.data.reason, 'reauth_required');
  });

  await t.test("someone else's passkey doesn't count", async () => {
    const start = await ana.post('/api/auth/reauth/options');
    const response = admin.authenticator.authenticate(start.data.options, server.base);
    const r = await ana.post('/api/auth/reauth/verify', { response });
    assert.equal(r.status, 400);
    assert.equal((await ana.post('/api/profile/email/start', { email: 'ana.new@example.com' })).data.reason, 'reauth_required');
  });

  await t.test('passkey, then a code to the new address, then the old one hears about it', async () => {
    assert.equal((await reauth(ana)).status, 200);
    assert.equal((await ana.post('/api/profile/email/start', { email: 'host@example.com' })).data.reason, 'email_unavailable');
    assert.equal((await ana.post('/api/profile/email/start', { email: 'ana@example.com' })).data.reason, 'same_email');
    const start = await ana.post('/api/profile/email/start', { email: 'Ana.New@Example.com' });
    assert.equal(start.status, 200, start.text);
    const code = server.lastCode('ana.new@example.com');
    assert.match(code, /^\d{6}$/);
    assert.equal((await ana.post('/api/profile/email/verify', { code: code === '000000' ? '111111' : '000000' })).data.reason, 'wrong_code');
    const done = await ana.post('/api/profile/email/verify', { code });
    assert.equal(done.status, 200, done.text);
    assert.equal(done.data.person.email, 'ana.new@example.com');
    assert.match(server.output(), /email-changed notice for ana@example\.com: now a•••@example\.com/);
    // Proven, so it counts as verified.
    const listed = (await admin.get('/api/admin/people')).data.people.find((p) => p.id === anaId);
    assert.ok(listed.emailVerifiedAt);
  });

  await t.test('one change per passkey check', async () => {
    const r = await ana.post('/api/profile/email/start', { email: 'ana.third@example.com' });
    assert.equal(r.data.reason, 'reauth_required');
  });

  await t.test('signed out, nothing', async () => {
    const nobody = browser(server);
    assert.equal((await nobody.post('/api/auth/reauth/options')).status, 401);
    assert.equal((await nobody.post('/api/profile/email/start', { email: 'x@example.com' })).status, 401);
  });

  await t.test('the new email signs in with a code; the old one is just a new email', async () => {
    const phone = browser(server);
    const proven = await phone.proveEmail('ana.new@example.com');
    assert.equal(proven.data.state, 'existing');
    const other = browser(server);
    assert.equal((await other.proveEmail('ana@example.com')).data.state, 'new');
  });
});
