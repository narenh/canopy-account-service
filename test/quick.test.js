// Quick sign-ups (name, email, passkey; no code), what sites see of them,
// proving the email afterwards, and the limits on them.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, browser } = require('./harness');

const EVENT = 'https://events.canopysf.com/e/abc123';

test('quick sign-up and verification', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());

  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  const adminId = (await admin.signUp('host@example.com', 'Hana', 'Host')).data.person.id;
  // tickets doesn't allow unverified accounts; events does.
  const tickets = (await admin.post('/api/admin/apps', { name: 'tickets' })).data;
  const events = (await admin.post('/api/admin/apps', { name: 'events' })).data;
  const switched = await admin.patch(`/api/admin/apps/${events.app.id}`, { allowsUnverified: true });
  assert.equal(switched.status, 200, switched.text);
  assert.equal(switched.data.app.allowsUnverified, true);
  assert.equal((await admin.get('/api/admin/apps')).data.apps.find((a) => a.name === 'tickets').allowsUnverified, false);

  const sessionFor = (site, token) => browser(server).get('/api/session', {
    headers: { Authorization: `Bearer ${site.key}`, 'X-Canopy-Session': token }
  });

  const ana = browser(server);
  let anaId;

  await t.test('?quick=1 is the quick form, with the way back to sign in', async () => {
    const page = await browser(server).get('/?quick=1&return=' + encodeURIComponent(EVENT));
    assert.equal(page.status, 200);
    assert.match(page.text, /id="quickForm"/);
    assert.match(page.text, /data-copy="welcome\.quickSignIn"/);
    assert.match(page.text, /data-return="https:\/\/events\.canopysf\.com\/e\/abc123"/);
  });

  await t.test('name, email and a passkey make an unverified account, with no code sent', async () => {
    const made = await ana.quickSignUp('Ana@Example.com', 'Ana', 'Lima');
    assert.equal(made.status, 201, made.text);
    assert.equal(made.data.person.email, 'ana@example.com');
    assert.equal(made.data.person.emailVerified, false);
    assert.equal(made.data.person.isAdmin, false);
    anaId = made.data.person.id;
    assert.equal(server.lastCode('ana@example.com'), undefined, 'no email was sent');
    assert.equal((await ana.get('/api/me')).data.person.emailVerified, false);
    const listed = (await admin.get('/api/admin/people')).data.people.find((p) => p.id === anaId);
    assert.equal(listed.emailVerified, false);
    assert.equal(listed.emailVerifiedAt, null);
    // Signing in with that passkey works like any other.
    const phone = browser(server);
    phone.authenticator.creds.push(...ana.authenticator.creds);
    assert.equal((await phone.signInWithPasskey()).data.person.id, anaId);
  });

  await t.test('a site that does not allow them sees null and unverified; one that does sees emailVerified: false', async () => {
    assert.deepEqual((await sessionFor(tickets, ana.cookie)).data, { person: null, unverified: true });
    const onEvents = (await sessionFor(events, ana.cookie)).data;
    assert.equal(onEvents.person.id, anaId);
    assert.equal(onEvents.person.emailVerified, false);
    assert.equal(onEvents.unverified, undefined);
    // A verified person reads the same on both, with emailVerified: true.
    assert.equal((await sessionFor(tickets, admin.cookie)).data.person.emailVerified, true);
    assert.equal((await sessionFor(events, admin.cookie)).data.person.emailVerified, true);
  });

  await t.test('an email with an account, verified or not, is told so', async () => {
    const b = browser(server);
    for (const email of ['host@example.com', 'ANA@example.com']) {
      const r = await b.post('/api/auth/quick/start', { email, firstName: 'X', lastName: 'Y' });
      assert.equal(r.status, 409, email);
      assert.equal(r.data.reason, 'email_has_account');
    }
    assert.equal((await b.post('/api/auth/quick/start', { email: 'nope', firstName: 'X', lastName: 'Y' })).data.reason, 'bad_email');
    assert.equal((await b.post('/api/auth/quick/start', { email: 'x@example.com', firstName: '', lastName: 'Y' })).data.reason, 'names_required');
  });

  await t.test('unverified people have their own profile, but never /admin', async () => {
    assert.equal((await ana.patch('/api/profile', { firstName: 'Ana', lastName: 'Lima', phone: '415 555 1234' })).status, 200);
    assert.equal((await ana.get('/admin')).headers.get('location'), '/profile');
    assert.equal((await ana.get('/api/admin/people')).status, 401);
    assert.equal((await ana.patch(`/api/admin/apps/${tickets.app.id}`, { allowsUnverified: true })).status, 401);
  });

  await t.test('/profile?verify=1: signed out goes to sign in and comes back', async () => {
    const r = await browser(server).get('/profile?verify=1&return=' + encodeURIComponent(EVENT));
    assert.equal(r.status, 302);
    const back = new URL(r.headers.get('location'), server.base).searchParams.get('return');
    assert.equal(back, `${server.base}/profile?verify=1&return=${encodeURIComponent(EVENT)}`);
    const page = await ana.get('/profile?verify=1&return=' + encodeURIComponent(EVENT));
    assert.equal(page.status, 200);
    assert.match(page.text, /data-return="https:\/\/events\.canopysf\.com\/e\/abc123"/);
    assert.match(page.text, /id="verifyBanner"/);
    // Somewhere that isn't Canopy is dropped.
    assert.match((await ana.get('/profile?verify=1&return=' + encodeURIComponent('https://evil.example/'))).text, /data-return=""/);
  });

  await t.test('proving the email from the profile: then every site sees them', async () => {
    assert.equal((await ana.post('/api/profile/verify/check', { code: '123456' })).data.reason, 'expired', 'no code sent yet');
    const start = await ana.post('/api/profile/verify/start');
    assert.equal(start.status, 200, start.text);
    assert.equal(start.data.verified, false);
    const code = server.lastCode('ana@example.com');
    assert.match(code, /^\d{6}$/);
    assert.equal((await ana.post('/api/profile/verify/check', { code: code === '000000' ? '111111' : '000000' })).data.reason, 'wrong_code');
    const done = await ana.post('/api/profile/verify/check', { code });
    assert.equal(done.status, 200, done.text);
    assert.equal(done.data.person.emailVerified, true);
    const onTickets = (await sessionFor(tickets, ana.cookie)).data;
    assert.equal(onTickets.person.id, anaId);
    assert.equal(onTickets.person.emailVerified, true);
    // Nothing more to send, and ?verify=1 goes straight back.
    assert.equal((await ana.post('/api/profile/verify/start')).data.verified, true);
    assert.equal((await ana.get('/profile?verify=1&return=' + encodeURIComponent(EVENT))).headers.get('location'), EVENT);
    // Her passkey is still hers.
    assert.equal((await ana.get('/api/profile/passkeys')).data.passkeys.length, 1);
  });

  await t.test('signing in by code to an unverified account proves it, and takes it from whoever made it', async () => {
    // Someone quick-signs-up with an email that isn't theirs...
    const mallory = browser(server);
    const squat = await mallory.quickSignUp('bob@example.com', 'Bob', 'Bobson');
    assert.equal(squat.status, 201, squat.text);
    const bobId = squat.data.person.id;
    // ...and the inbox's owner signs in with a code.
    const bob = browser(server);
    const proven = await bob.proveEmail('bob@example.com');
    assert.equal(proven.data.state, 'existing');
    assert.equal(proven.data.unverified, true);
    const made = await bob.makePasskey(await bob.post('/api/auth/register/existing'));
    assert.equal(made.status, 201, made.text);
    assert.equal(made.data.person.id, bobId);
    assert.equal(made.data.person.emailVerified, true);
    assert.equal((await bob.get('/api/profile/passkeys')).data.passkeys.length, 1, 'only his passkey is left');
    assert.equal((await mallory.get('/api/me')).data.person, null, "the maker's session is gone");
    assert.equal((await mallory.signInWithPasskey()).data.reason, 'unknown_passkey');
    assert.equal((await sessionFor(tickets, bob.cookie)).data.person.id, bobId);
  });

  await t.test('changing the email of an unverified account proves the new one', async () => {
    const cat = browser(server);
    assert.equal((await cat.quickSignUp('cat@example.com', 'Cat', 'Cole')).status, 201);
    const start = await cat.post('/api/auth/reauth/options');
    const response = cat.authenticator.authenticate(start.data.options, server.base);
    assert.equal((await cat.post('/api/auth/reauth/verify', { response })).status, 200);
    assert.equal((await cat.post('/api/profile/email/start', { email: 'cat.cole@example.com' })).status, 200);
    const done = await cat.post('/api/profile/email/verify', { code: server.lastCode('cat.cole@example.com') });
    assert.equal(done.status, 200, done.text);
    assert.equal(done.data.person.email, 'cat.cole@example.com');
    assert.equal(done.data.person.emailVerified, true);
    assert.equal((await sessionFor(tickets, cat.cookie)).data.person.email, 'cat.cole@example.com');
  });

  await t.test("an email the admin changes is unverified until a code proves it", async () => {
    const edited = await admin.patch(`/api/admin/people/${anaId}`, { firstName: 'Ana', lastName: 'Lima', email: 'ana.lima@example.com' });
    assert.equal(edited.status, 200, edited.text);
    assert.equal(edited.data.person.emailVerified, false);
    assert.deepEqual((await sessionFor(tickets, ana.cookie)).data, { person: null, unverified: true });
    // Saving without changing it changes nothing.
    assert.equal((await admin.patch(`/api/admin/people/${anaId}`, { firstName: 'Ana', lastName: 'Lima', email: 'ana.lima@example.com' })).data.person.emailVerified, false);
    await ana.post('/api/profile/verify/start');
    const done = await ana.post('/api/profile/verify/check', { code: server.lastCode('ana.lima@example.com') });
    assert.equal(done.data.person.emailVerified, true);
    assert.equal((await sessionFor(tickets, ana.cookie)).data.person.id, anaId);
  });

  await t.test("the admin's own email isn't changed from Edit profile, and an unverified admin isn't one", async () => {
    const own = await admin.patch(`/api/admin/people/${adminId}`, { firstName: 'Hana', lastName: 'Host', email: 'hana@example.com' });
    assert.equal(own.status, 409);
    assert.equal(own.data.reason, 'own_email');
    assert.equal((await admin.patch(`/api/admin/people/${adminId}`, { firstName: 'Hana', lastName: 'Host', email: 'host@example.com' })).status, 200);
    const db = new Database(path.join(server.dataDir, 'account.db'));
    db.prepare('UPDATE people SET email_verified_at = NULL WHERE id = ?').run(adminId);
    try {
      assert.equal((await admin.get('/api/admin/people')).status, 401);
      assert.equal((await admin.get('/admin')).headers.get('location'), '/profile');
    } finally {
      db.prepare('UPDATE people SET email_verified_at = 1 WHERE id = ?').run(adminId);
      db.close();
    }
    assert.equal((await admin.get('/api/admin/people')).status, 200);
  });
});

test('no quick sign-up before there is an admin', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const r = await browser(server).post('/api/auth/quick/start', { email: 'a@example.com', firstName: 'A', lastName: 'B' });
  assert.equal(r.status, 403);
  assert.equal(r.data.reason, 'setup_required');
});

test('quick sign-up limits', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  // Each step from its own address (Cloudflare's header), so the
  // per-address counts don't mix.
  const from = (ip) => ({ headers: { 'CF-Connecting-IP': ip } });
  let n = 0;
  const fresh = () => `person${++n}@example.com`;

  await t.test('10 tries per browser per 15 minutes', async () => {
    const b = browser(server);
    for (let i = 0; i < 10; i++) {
      assert.equal((await b.post('/api/auth/quick/start', { email: fresh(), firstName: 'A', lastName: 'B' }, from('10.0.0.1'))).status, 200);
    }
    assert.equal((await b.post('/api/auth/quick/start', { email: fresh(), firstName: 'A', lastName: 'B' }, from('10.0.0.1'))).status, 429);
  });

  await t.test('20 tries per address an hour, the ones that hit an account included', async () => {
    for (let i = 0; i < 20; i++) {
      const email = i % 4 === 0 ? 'host@example.com' : fresh();
      const r = await browser(server).post('/api/auth/quick/start', { email, firstName: 'A', lastName: 'B' }, from('10.0.0.2'));
      assert.equal(r.status, email === 'host@example.com' ? 409 : 200);
    }
    assert.equal((await browser(server).post('/api/auth/quick/start', { email: 'host@example.com', firstName: 'A', lastName: 'B' }, from('10.0.0.2'))).status, 429);
    assert.equal((await browser(server).post('/api/auth/quick/start', { email: fresh(), firstName: 'A', lastName: 'B' }, from('10.0.0.3'))).status, 200, 'other addresses are fine');
  });

  await t.test('10 accounts per address an hour', async () => {
    for (let i = 0; i < 10; i++) assert.equal((await browser(server).quickSignUp(fresh(), 'A', 'B', from('10.0.0.4'))).status, 201);
    assert.equal((await browser(server).quickSignUp(fresh(), 'A', 'B', from('10.0.0.4'))).status, 429);
  });

  await t.test('50 accounts an hour across everyone', async () => {
    for (let ip = 1; ip <= 4; ip++) {
      for (let i = 0; i < 10; i++) assert.equal((await browser(server).quickSignUp(fresh(), 'A', 'B', from(`10.0.1.${ip}`))).status, 201);
    }
    assert.equal((await browser(server).quickSignUp(fresh(), 'A', 'B', from('10.0.1.9'))).status, 429);
    // The usual sign-up, with a code, isn't held up by it.
    assert.equal((await browser(server).signUp(fresh(), 'A', 'B')).status, 201);
  });
});
