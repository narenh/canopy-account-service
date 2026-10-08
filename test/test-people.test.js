// Test people: made up by the admin to fill events with guests. Ordinary
// people to every site; never found by a lookup, never sent a code, never
// given a passkey or setup link; signed in only by the admin's tokens,
// which are only ever made for them. See "Admin: test people" in the
// README.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { startServer, browser, nativeApp } = require('./harness');

const TINY_JPEG = Buffer.from('ffd8ffdb0004aaaaffda0004bbbb0102ffd9', 'hex');

test('test people', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  const adminId = (await admin.signUp('host@example.com', 'Hana', 'Host')).data.person.id;
  const site = (await admin.post('/api/admin/apps', { name: 'events' })).data;
  await admin.patch(`/api/admin/apps/${site.app.id}`, { allowsLookup: true, contactFields: ['email'] });
  const bob = browser(server);
  const bobId = (await bob.signUp('bob@example.com', 'Bob', 'Bell')).data.person.id;
  const asSite = (token) => ({ headers: { Authorization: `Bearer ${site.key}`, ...(token ? { 'X-Canopy-Session': token } : {}) } });
  const lookup = (body, token) => browser(server).post('/api/people/lookup', body, {
    headers: { Authorization: `Bearer ${site.key}`, Origin: null, 'X-Canopy-Session': token }
  });

  let made;
  let tokens;
  let photoId;

  await t.test('the admin creates them: verified, not findable, no passkeys or contact details, an undeliverable email', async () => {
    for (const count of [0, 51, 2.5, '3', undefined]) {
      const bad = await admin.post('/api/admin/test-people', { count });
      assert.equal(bad.status, 400, `count ${count}`);
      assert.equal(bad.data.reason, 'bad_count');
    }
    const r = await admin.post('/api/admin/test-people', { count: 12 });
    assert.equal(r.status, 201, r.text);
    made = r.data.people;
    assert.equal(made.length, 12);
    assert.equal(r.data.count, 12);
    for (const p of made) {
      assert.equal(p.isTest, true);
      assert.match(p.email, /^test-[0-9a-f]{12}@canopy\.invalid$/);
      assert.equal(p.emailVerified, true);
      assert.equal(p.findable, false);
      assert.equal(p.passkeyCount, 0);
      assert.equal(p.photoUrl, null);
      for (const f of ['phone', 'instagram', 'venmo', 'cashapp']) assert.equal(p[f], null, f);
      assert.ok(p.firstName && p.lastName);
    }
    assert.equal(new Set(made.map((p) => `${p.firstName} ${p.lastName}`)).size, 12, 'no two the same');
    // More than once: they add up.
    const more = await admin.post('/api/admin/test-people', { count: 3 });
    assert.equal(more.data.count, 15);
    made = made.concat(more.data.people);
    const listed = (await admin.get('/api/admin/people')).data.people;
    assert.equal(listed.filter((p) => p.isTest).length, 15);
    assert.equal(listed.find((p) => p.id === bobId).isTest, false);
    assert.equal(listed.find((p) => p.id === adminId).isTest, false);
  });

  await t.test('only the admin, and only from a Canopy page', async () => {
    const send = (who, method, url, opts) => (method === 'del' ? who.del(url, opts) : who.post(url, { count: 1 }, opts));
    for (const [method, url] of [['post', '/api/admin/test-people'], ['post', '/api/admin/test-people/tokens'], ['del', '/api/admin/test-people']]) {
      const asBob = await send(bob, method, url);
      assert.equal(asBob.status, 401, `${method} ${url} as Bob`);
      const asNobody = await send(browser(server), method, url);
      assert.equal(asNobody.status, 401, `${method} ${url} signed out`);
      const elsewhere = await send(admin, method, url, { headers: { Origin: 'https://evil.example' } });
      assert.equal(elsewhere.status, 403, `${method} ${url} from another site`);
      assert.equal(elsewhere.data.reason, 'bad_origin');
    }
    // A bearer token (Bob's app) gets nowhere near the admin routes.
    const bobApp = nativeApp(server);
    bobApp.authenticator.creds.push(...bob.authenticator.creds);
    await bobApp.signInWithPasskey();
    const res = await fetch(`${server.base}/api/admin/test-people/tokens`, { method: 'POST', headers: { Authorization: `Bearer ${bobApp.token}`, Origin: server.base } });
    assert.equal(res.status, 401);
    assert.equal((await admin.get('/api/admin/people')).data.people.filter((p) => p.isTest).length, 15, 'nothing was made');
  });

  await t.test('tokens: one per test person, signed in, and they work as a bearer token', async () => {
    const r = await admin.post('/api/admin/test-people/tokens');
    assert.equal(r.status, 200, r.text);
    assert.equal(r.headers.get('cache-control'), 'no-store');
    tokens = r.data.people;
    assert.deepEqual(tokens.map((x) => x.id).sort(), made.map((p) => p.id).sort());
    assert.deepEqual(Object.keys(tokens[0]).sort(), ['firstName', 'id', 'lastName', 'token']);
    const first = tokens[0];
    // A site sees an ordinary person, never that they're a test one.
    const s = await browser(server).get('/api/session', asSite(first.token));
    assert.equal(s.status, 200);
    assert.equal(s.data.person.id, first.id);
    assert.equal(s.data.person.firstName, first.firstName);
    assert.equal(s.data.person.emailVerified, true);
    assert.ok(!('isTest' in s.data.person));
    const ppl = await browser(server).get(`/api/people?ids=${first.id}`, asSite());
    assert.deepEqual(Object.keys(ppl.data.people[0]).sort(), ['firstName', 'id', 'lastName', 'photoUrl', 'shortName']);
    // And the account service's own app API.
    const app = nativeApp(server);
    app.token = first.token;
    const me = await app.get('/me');
    assert.equal(me.status, 200);
    assert.equal(me.data.person.id, first.id);
    assert.ok(!('isTest' in me.data.person));
    // A photo, the way the seeding script gives them one.
    const form = new FormData();
    form.append('photo', new Blob([TINY_JPEG], { type: 'image/jpeg' }), 'photo.jpg');
    const up = await app.upload('/me/photo', form);
    assert.equal(up.status, 200, up.text);
    assert.ok(fs.existsSync(path.join(server.dataDir, 'photos', `${first.id}.jpg`)));
    photoId = first.id;
    const sessions = (await app.get('/me/sessions')).data.sessions;
    assert.equal(sessions.length, 1);
    assert.equal(sessions[0].kind, 'test');
  });

  await t.test('getting tokens again signs the old ones out', async () => {
    const again = (await admin.post('/api/admin/test-people/tokens')).data.people;
    assert.equal(again.length, 15);
    for (const old of tokens) {
      assert.equal((await browser(server).get('/api/session', asSite(old.token))).data.person, null, 'old token is signed out');
    }
    const fresh = again[0];
    assert.equal((await browser(server).get('/api/session', asSite(fresh.token))).data.person.id, fresh.id);
    assert.ok(!again.some((x) => tokens.some((o) => o.token === x.token)));
    tokens = again;
  });

  await t.test('never a token for a real person, however the request is made', async () => {
    const crafted = [
      { ids: [bobId, adminId] }, { id: bobId }, { personId: adminId }, { people: [{ id: bobId }] }, { all: true, isTest: false }
    ];
    for (const body of crafted) {
      const r = await admin.post('/api/admin/test-people/tokens', body);
      assert.equal(r.status, 200);
      assert.ok(!r.data.people.some((x) => x.id === bobId || x.id === adminId), JSON.stringify(body));
      tokens = r.data.people;
    }
    // Bob's and the admin's own sessions are untouched by any of it.
    assert.equal((await bob.get('/api/me')).data.person.id, bobId);
    assert.equal((await admin.get('/api/me')).data.person.id, adminId);
    const bobSessions = (await bob.get('/api/profile/sessions')).data.sessions;
    assert.ok(bobSessions.every((s) => s.kind !== 'test'));
  });

  await t.test('never found by a lookup, even with a phone and the switch on', async () => {
    const tp = nativeApp(server);
    tp.token = tokens[0].token;
    const saved = await tp.patch('/me', { firstName: tokens[0].firstName, lastName: tokens[0].lastName, phone: '415 555 0199', instagram: 'tess.tester', findable: true });
    assert.equal(saved.status, 200, saved.text);
    assert.equal(saved.data.person.findable, true);
    assert.equal((await lookup({ phone: '4155550199' }, bob.cookie)).data.person, null);
    assert.equal((await lookup({ instagram: 'tess.tester' }, bob.cookie)).data.person, null);
    // A real person with the same details still is.
    await bob.patch('/api/profile', { firstName: 'Bob', lastName: 'Bell', instagram: 'bob.bell' });
    assert.equal((await lookup({ instagram: 'bob.bell' }, tokens[1].token)).data.person.id, bobId, 'and a test person can look others up');
  });

  await t.test('no emailed code, no setup link, no new passkey', async () => {
    const email = made[0].email;
    for (const r of [
      await browser(server).post('/api/auth/email/start', { email }),
      await browser(server).post('/api/auth/email/start', { email: 'anyone@somewhere.invalid' })
    ]) {
      assert.equal(r.status, 400, r.text);
      assert.equal(r.data.reason, 'bad_email');
    }
    // A quick sign-up with their address finds it taken, like anyone's.
    assert.equal((await browser(server).post('/api/auth/quick/start', { email, firstName: 'A', lastName: 'B' })).data.reason, 'email_has_account');
    assert.ok(!server.output().includes(`code for ${email}`), 'no code was sent');
    const app = nativeApp(server);
    await app.begin();
    assert.equal((await app.post('/auth/email/start', { email })).data.reason, 'bad_email');
    for (const url of [`/api/admin/people/${made[0].id}/setup-link`, `/api/admin/people/${made[0].id}/reset-passkeys`]) {
      const r = await admin.post(url);
      assert.equal(r.status, 409, url);
      assert.equal(r.data.reason, 'test_person');
    }
    // Changing their email needs a passkey check, which they can't do.
    const tp = nativeApp(server);
    tp.token = tokens[0].token;
    assert.equal((await tp.post('/me/email/start', { email: 'real@example.com' })).data.reason, 'reauth_required');
  });

  await t.test('delete all: every test person and everything of theirs goes, and nobody else', async () => {
    const photo = path.join(server.dataDir, 'photos', `${photoId}.jpg`);
    assert.ok(fs.existsSync(photo));
    const tp = nativeApp(server);
    tp.token = tokens[0].token;
    assert.equal((await tp.get('/me/calendar')).status, 200, 'a calendar feed to delete');
    const r = await admin.del('/api/admin/test-people');
    assert.equal(r.status, 200);
    assert.deepEqual(r.data, { ok: true, deleted: 15 });
    const listed = (await admin.get('/api/admin/people')).data.people;
    assert.deepEqual(listed.map((p) => p.id).sort(), [adminId, bobId].sort());
    assert.ok(!fs.existsSync(photo), 'photos go');
    for (const x of tokens) assert.equal((await browser(server).get('/api/session', asSite(x.token))).data.person, null);
    const ppl = await browser(server).get(`/api/people?ids=${tokens.map((x) => x.id).join(',')}`, asSite());
    assert.deepEqual(ppl.data.people, [], 'former members to every site');
    assert.equal((await admin.post('/api/admin/test-people/tokens')).data.people.length, 0);
    assert.equal((await bob.get('/api/me')).data.person.id, bobId);
    // Again: nothing to delete.
    assert.deepEqual((await admin.del('/api/admin/test-people')).data, { ok: true, deleted: 0 });
  });

  await t.test('at most 200 at once', async () => {
    for (let i = 0; i < 4; i++) assert.equal((await admin.post('/api/admin/test-people', { count: 50 })).status, 201);
    const over = await admin.post('/api/admin/test-people', { count: 1 });
    assert.equal(over.status, 409);
    assert.equal(over.data.reason, 'too_many_test_people');
    assert.equal((await admin.del('/api/admin/test-people')).data.deleted, 200);
  });

  await t.test('the Account Manager has the section and the badge', async () => {
    const page = await admin.get('/admin');
    for (const id of ['testCreateForm', 'testCountInput', 'testTokensBtn', 'testDeleteBtn', 'tokensSheet', 'tokensText', 'tokensDownloadBtn']) {
      assert.match(page.text, new RegExp(`id="${id}"`), id);
    }
    assert.match(page.text, /canopy-test-tokens\.json/);
    assert.match(page.text, /tag test/);
  });
});
