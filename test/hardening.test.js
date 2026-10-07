// Things found in review, each one pinned so it stays fixed: a passkey
// response reusing a credential id that's already saved, email addresses
// the mailer would read as somebody else's, and the favicon.

const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, browser } = require('./harness');

test('hardening', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());

  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  assert.equal((await admin.signUp('host@example.com', 'Hana', 'Host')).status, 201);
  const ana = browser(server);
  const made = await ana.signUp('ana@example.com', 'Ana', 'Lima');
  assert.equal(made.status, 201);
  const anaId = made.data.person.id;
  const anaCred = (await ana.get('/api/profile/passkeys')).data.passkeys[0].id;

  const alive = async () => (await fetch(server.base + '/healthz')).status === 200;

  await t.test('a passkey whose id is already saved is refused, and the server stays up', async () => {
    // Signed in, adding "another" passkey that reuses her own id.
    const opts = await ana.post('/api/auth/register/add');
    const response = ana.authenticator.register(opts.data.options, server.base, { credId: anaCred });
    const r = await ana.post('/api/auth/register/verify', { response });
    assert.equal(r.status, 409, r.text);
    assert.equal(r.data.reason, 'passkey_exists');
    assert.ok(await alive(), 'the server is still running');
    assert.equal((await ana.get('/api/profile/passkeys')).data.passkeys.length, 1);
  });

  await t.test("a sign-up reusing someone else's passkey id makes no account", async () => {
    const mallory = browser(server);
    await mallory.proveEmail('mallory@example.com');
    const opts = await mallory.post('/api/auth/register/new', { firstName: 'Mal', lastName: 'Lory' });
    const response = mallory.authenticator.register(opts.data.options, server.base, { credId: anaCred });
    const r = await mallory.post('/api/auth/register/verify', { response });
    assert.equal(r.status, 409, r.text);
    assert.equal(r.data.reason, 'passkey_exists');
    assert.ok(await alive(), 'the server is still running');
    const people = (await admin.get('/api/admin/people')).data.people;
    assert.ok(!people.some((p) => p.email === 'mallory@example.com'));
    // And the id still signs Ana in, not anyone else.
    const phone = browser(server);
    phone.authenticator.creds.push(...ana.authenticator.creds);
    assert.equal((await phone.signInWithPasskey()).data.person.id, anaId);
  });

  await t.test('a refused passkey on a setup link leaves the link usable', async () => {
    const code = (await admin.post(`/api/admin/people/${anaId}/setup-link`)).data.setupUrl.split('/setup/')[1];
    const b = browser(server);
    const opts = await b.post('/api/auth/register/link', { code });
    const response = b.authenticator.register(opts.data.options, server.base, { credId: anaCred });
    const r = await b.post('/api/auth/register/verify', { response });
    assert.equal(r.status, 409, r.text);
    assert.ok(await alive(), 'the server is still running');
    assert.equal((await b.get('/api/setup/' + code)).status, 200, 'the link was not spent');
  });

  await t.test('an email the mailer would send somewhere else is refused', async () => {
    const b = browser(server);
    // nodemailer reads each of these as a different (or a second) recipient.
    for (const email of ['x<attacker@evil.example>', 'ana@example.com,attacker', 'a,b@evil.example', 'a;b@evil.example', 'grp:b@evil.example']) {
      const r = await b.post('/api/auth/email/start', { email });
      assert.equal(r.status, 400, `${email} -> ${r.status}`);
      assert.equal(r.data.reason, 'bad_email');
    }
    for (const email of ["o'brien@example.com", 'a+tag@example.co.uk']) {
      assert.equal((await b.post('/api/auth/email/start', { email })).status, 200, email);
    }
  });

  await t.test('/favicon.ico answers 204, not a 404', async () => {
    const r = await fetch(server.base + '/favicon.ico');
    assert.equal(r.status, 204);
  });
});
