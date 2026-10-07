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

test('passkey sign-in from another Canopy page (CORS)', async (t) => {
  const { startServer, browser } = require('./harness');
  const server = await startServer();
  t.after(() => server.stop());
  const tix = 'https://tix.canopysf.com';

  const pre = await fetch(server.base + '/api/auth/login/options', {
    method: 'OPTIONS', headers: { Origin: tix, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' }
  });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('access-control-allow-origin'), tix);
  assert.equal(pre.headers.get('access-control-allow-credentials'), 'true');

  const evil = await fetch(server.base + '/api/auth/login/options', {
    method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' }
  });
  assert.equal(evil.status, 403);
  assert.equal(evil.headers.get('access-control-allow-origin'), null);

  // Only sign-in gets CORS: nothing else answers a Canopy page's preflight.
  const other = await fetch(server.base + '/api/auth/email/start', {
    method: 'OPTIONS', headers: { Origin: tix, 'Access-Control-Request-Method': 'POST' }
  });
  assert.equal(other.headers.get('access-control-allow-origin'), null);

  // A passkey made on the account page signs in from tickets' page.
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  const made = await admin.signUp('host@example.com', 'Hana', 'Host');
  const fromTix = browser(server, { origin: 'http://localhost:9999' });
  fromTix.authenticator.creds.push(...admin.authenticator.creds);
  const r = await fromTix.signInWithPasskey();
  assert.equal(r.status, 200, r.text);
  assert.equal(r.data.person.id, made.data.person.id);
  assert.ok(fromTix.cookie, 'the session cookie came back');
});

test('admin images: upload, then remove back to none', async (t) => {
  const { startServer, browser } = require('./harness');
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const form = new FormData();
  form.append('image', new Blob([Buffer.from('89504e47', 'hex')], { type: 'image/png' }), 'bg.png');
  assert.equal((await admin.upload('/api/admin/backdrop-image', form)).status, 200);
  assert.equal((await browser(server).get('/backdrop-image')).status, 200);
  assert.match((await browser(server).get('/')).text, /data-backdrop="\/backdrop-image\?v=/);
  assert.equal((await browser(server).del('/api/admin/backdrop-image', { headers: { Origin: server.base } })).status, 401, 'admin only');
  assert.equal((await admin.del('/api/admin/backdrop-image')).status, 200);
  assert.equal((await browser(server).get('/backdrop-image')).status, 404);
  assert.match((await browser(server).get('/')).text, /data-backdrop=""/);
});

test("the admin's Edit profile: every field, email included", async (t) => {
  const { startServer, browser } = require('./harness');
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const ana = browser(server);
  const anaId = (await ana.signUp('ana@example.com', 'Ana', 'Lima')).data.person.id;

  const edit = (body) => admin.patch(`/api/admin/people/${anaId}`, { firstName: 'Ana', lastName: 'Lima', ...body });
  const r = await edit({ firstName: 'Anna', email: 'Anna@Example.com', phone: '415 555 1234', instagram: '@anna', venmoHandle: 'anna-v', cashapp: '$AnnaL' });
  assert.equal(r.status, 200, r.text);
  const p = r.data.person;
  assert.deepEqual([p.firstName, p.email, p.phone, p.instagram, p.venmo, p.cashapp],
    ['Anna', 'anna@example.com', '+14155551234', 'anna', 'anna-v', 'AnnaL']);
  assert.equal(p.emailVerifiedAt, null, 'a changed email is unverified');
  assert.equal(p.passkeyCount, 1);
  // She sees it, and signs in as before.
  assert.equal((await ana.get('/api/me')).data.person.email, 'anna@example.com');

  assert.equal((await edit({ email: 'host@example.com' })).status, 409, "someone else's email");
  assert.equal((await edit({ email: 'nope' })).data.reason, 'bad_email');
  assert.equal((await edit({ phone: '123' })).data.reason, 'bad_phone');
  assert.equal((await edit({ firstName: '' })).status, 400);
  assert.equal((await admin.patch('/api/admin/people/00000000-0000-0000-0000-000000000000', { firstName: 'A', lastName: 'B' })).status, 404);
  assert.equal((await ana.patch(`/api/admin/people/${anaId}`, { firstName: 'X', lastName: 'Y' })).status, 401, 'admin only');
  // People can't change their own email on the profile page.
  const own = await ana.patch('/api/profile', { firstName: 'Anna', lastName: 'Lima', email: 'other@example.com' });
  assert.equal(own.data.person.email, 'anna@example.com');
});
