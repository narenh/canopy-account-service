// Test people: made up by the admin to fill events with guests. Ordinary
// people to every site; never found by a lookup, never sent a code, never
// given a passkey or setup link; signed in only by the admin's tokens,
// which are only ever made for them. See "Admin: test people" in the
// README.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { startServer, browser, nativeApp } = require('./harness');
const createCanopyAccount = require('../client/canopy-account');

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
    for (const [method, url] of [['post', '/api/admin/test-people'], ['post', '/api/admin/test-people/tokens'], ['del', '/api/admin/test-people'],
      ['post', '/api/admin/test-people/photos'], ['post', '/api/admin/test-people/befriend'], ['post', '/api/admin/test-people/events']]) {
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
    // No site with a calendar here, so there's nobody else to ask.
    assert.deepEqual(r.data, { ok: true, deleted: 15, sites: [] });
    const listed = (await admin.get('/api/admin/people')).data.people;
    assert.deepEqual(listed.map((p) => p.id).sort(), [adminId, bobId].sort());
    assert.ok(!fs.existsSync(photo), 'photos go');
    for (const x of tokens) assert.equal((await browser(server).get('/api/session', asSite(x.token))).data.person, null);
    const ppl = await browser(server).get(`/api/people?ids=${tokens.map((x) => x.id).join(',')}`, asSite());
    assert.deepEqual(ppl.data.people, [], 'former members to every site');
    assert.equal((await admin.post('/api/admin/test-people/tokens')).data.people.length, 0);
    assert.equal((await bob.get('/api/me')).data.person.id, bobId);
    // Again: nothing to delete.
    assert.deepEqual((await admin.del('/api/admin/test-people')).data, { ok: true, deleted: 0, sites: [] });
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
    for (const id of ['testCreateForm', 'testCountInput', 'testTokensBtn', 'testDeleteBtn', 'tokensSheet', 'tokensText', 'tokensDownloadBtn',
      'testFriendsBtn', 'testEventsBtn', 'testPhotosBtn', 'testResult']) {
      assert.match(page.text, new RegExp(`id="${id}"`), id);
    }
    assert.match(page.text, /canopy-test-tokens\.json/);
    assert.match(page.text, /tag test/);
  });
});

// ---- Photos, from a stand-in for pravatar ----

// A JPEG with an EXIF segment (APP1) that the photo cleaning takes out.
const EXIF_JPEG = Buffer.concat([
  Buffer.from('ffd8', 'hex'),
  Buffer.from('ffe1000c457869660000aabbccdd', 'hex'),
  Buffer.from('ffdb0004aaaaffda0004bbbb0102ffd9', 'hex')
]);

// GET /512?img=<n>, answered by `mode`: 'ok' (that JPEG), 'fail' (a 500),
// 'hang' (never), 'png' (not a JPEG).
async function fakePravatar(t) {
  const stub = { mode: 'ok', asked: [] };
  const app = express();
  app.get('/512', (req, res) => {
    stub.asked.push(req.query.img);
    if (stub.mode === 'fail') return res.status(500).end();
    if (stub.mode === 'hang') return;
    if (stub.mode === 'png') return res.type('image/png').send(Buffer.from('89504e470d0a1a0a0000', 'hex'));
    res.type('image/jpeg').send(EXIF_JPEG);
  });
  const listener = await new Promise((resolve) => { const l = app.listen(0, () => resolve(l)); });
  t.after(() => { listener.closeAllConnections(); listener.close(); });
  stub.url = `http://127.0.0.1:${listener.address().port}`;
  return stub;
}

test('test people get photos, kept as an upload is; no photo is no failure', async (t) => {
  const stub = await fakePravatar(t);
  const server = await startServer({ TEST_PHOTOS_URL: stub.url, TEST_PHOTOS_TIMEOUT_MS: '300' });
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const photoFile = (id) => path.join(server.dataDir, 'photos', `${id}.jpg`);

  const r = await admin.post('/api/admin/test-people', { count: 5 });
  assert.equal(r.status, 201, r.text);
  assert.equal(r.data.photos, 5);
  for (const p of r.data.people) {
    assert.match(p.photoUrl, new RegExp(`/photo/${p.id}\\?v=\\d+$`));
    const saved = fs.readFileSync(photoFile(p.id));
    assert.ok(!saved.includes(Buffer.from('Exif')), 'its metadata is taken out');
    assert.equal(saved[0], 0xff);
  }
  // Five different faces, from pravatar's 70.
  assert.equal(new Set(stub.asked).size, 5);
  assert.ok(stub.asked.every((n) => Number(n) >= 1 && Number(n) <= 70));

  // pravatar failing, hanging, or sending something that isn't a JPEG:
  // the people are made all the same, without a photo.
  for (const mode of ['fail', 'hang', 'png']) {
    stub.mode = mode;
    const started = Date.now();
    const more = await admin.post('/api/admin/test-people', { count: 2 });
    assert.equal(more.status, 201, `${mode}: ${more.text}`);
    assert.equal(more.data.photos, 0, mode);
    assert.ok(more.data.people.every((p) => p.photoUrl === null && !fs.existsSync(photoFile(p.id))), mode);
    assert.ok(Date.now() - started < 5000, `${mode} doesn't hold it up`);
  }

  // Add photos: only those without one.
  stub.mode = 'ok';
  stub.asked.length = 0;
  const added = await admin.post('/api/admin/test-people/photos');
  assert.equal(added.status, 200, added.text);
  assert.deepEqual(added.data, { photos: 6, without: 0 });
  assert.equal(stub.asked.length, 6);
  assert.deepEqual((await admin.post('/api/admin/test-people/photos')).data, { photos: 0, without: 0 });
  const listed = (await admin.get('/api/admin/people')).data.people.filter((p) => p.isTest);
  assert.equal(listed.length, 11);
  assert.ok(listed.every((p) => p.photoUrl));

  // Deleting them deletes their photos.
  assert.equal((await admin.del('/api/admin/test-people')).data.deleted, 11);
  assert.ok(listed.every((p) => !fs.existsSync(photoFile(p.id))));
});

// ---- The sites: friends, past events, and clearing both ----

// A Canopy site with the test people endpoints, checking the account
// service's signature with the client file, as events does. `mode` is
// 'ok', 'fail' (a 500) or 'missing' (no such endpoints: a 404).
async function fakeSite(t) {
  const site = { mode: 'ok', calls: [], refused: 0, secret: null, canopy: null };
  const app = express();
  app.use(express.json());
  const signed = (purpose, answer) => (req, res) => {
    if (site.mode === 'missing') return res.status(404).json({ error: 'not found', reason: 'not_found' });
    if (!site.canopy) site.canopy = createCanopyAccount({ url: 'http://unused', key: 'unused', calendarSecret: site.secret });
    if (!site.canopy.verifyInternalRequest(req, purpose)) { site.refused++; return res.status(401).json({ reason: 'unauthorized' }); }
    site.calls.push({ method: req.method, path: req.path, body: req.body, auth: req.get('authorization'), origin: req.get('origin') || null });
    if (site.mode === 'fail') return res.status(500).json({ error: 'down for a deploy' });
    res.json(answer(req.body));
  };
  app.post('/api/internal/test-friends', signed('test-friends', (b) => ({ added: b.friendIds.length, alreadyFriends: 0 })));
  app.post('/api/internal/test-friends/remove', signed('test-friends', (b) => ({ removed: b.personIds.length * 2 })));
  app.post('/api/internal/test-events', signed('test-events', (b) => ({ created: b.count })));
  app.delete('/api/internal/test-events', signed('test-events', () => ({ deleted: 7 })));
  app.use((req, res) => res.status(404).json({ error: 'not found' }));
  const listener = await new Promise((resolve) => { const l = app.listen(0, () => resolve(l)); });
  t.after(() => { listener.closeAllConnections(); listener.close(); });
  site.url = `http://127.0.0.1:${listener.address().port}`;
  return site;
}

async function addSite(admin, name, site) {
  const made = (await admin.post('/api/admin/apps', { name })).data;
  const r = await admin.patch(`/api/admin/apps/${made.app.id}`, { calendarUrl: site.url });
  assert.equal(r.status, 200, r.text);
  site.secret = r.data.calendarSecret;
  return made.app.id;
}

test('befriend, past events and delete ask the sites, signed, with only test people', async (t) => {
  const server = await startServer({ SITE_CALL_TIMEOUT_MS: '1000' });
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  const adminId = (await admin.signUp('host@example.com', 'Hana', 'Host')).data.person.id;
  const bob = browser(server);
  const bobId = (await bob.signUp('bob@example.com', 'Bob', 'Bell')).data.person.id;

  // Nobody to befriend yet, then nowhere to do it.
  for (const url of ['/api/admin/test-people/befriend', '/api/admin/test-people/events']) {
    const r = await admin.post(url);
    assert.equal(r.status, 409, url);
    assert.equal(r.data.reason, 'no_test_people');
  }
  const ids = (await admin.post('/api/admin/test-people', { count: 5 })).data.people.map((p) => p.id).sort();
  const none = await admin.post('/api/admin/test-people/befriend');
  assert.equal(none.status, 409);
  assert.equal(none.data.reason, 'no_sites');

  const events = await fakeSite(t);
  await addSite(admin, 'events', events);
  // A site with a calendar but none of this (tickets, say) is left out.
  const tickets = await fakeSite(t);
  tickets.mode = 'missing';
  await addSite(admin, 'tickets', tickets);

  // Befriend: the admin's id and the test people's, whatever the request
  // says, signed, with no Origin.
  const r = await admin.post('/api/admin/test-people/befriend', { personId: bobId, friendIds: [bobId, adminId] });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.data, { sites: [{ site: 'events', ok: true, added: 5, alreadyFriends: 0 }] });
  assert.equal(events.calls.length, 1);
  const call = events.calls[0];
  assert.equal(call.path, '/api/internal/test-friends');
  assert.equal(call.body.personId, adminId);
  assert.deepEqual(call.body.friendIds.slice().sort(), ids);
  assert.ok(!call.body.friendIds.includes(bobId) && !call.body.friendIds.includes(adminId));
  assert.match(call.auth, /^Canopy-Internal t=\d+, n=[0-9a-f]{32}, sig=[0-9a-f]{64}$/);
  assert.equal(call.origin, null);
  assert.equal(events.refused, 0);

  // The same signature again is refused by the site (once only), and so
  // is one for the calendar.
  const replay = await fetch(`${events.url}/api/internal/test-friends`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: call.auth }, body: JSON.stringify(call.body)
  });
  assert.equal(replay.status, 401);
  const t0 = Math.floor(Date.now() / 1000);
  const calSig = crypto.createHmac('sha256', events.secret).update(`canopy-calendar-v1\n${adminId}\n${t0}`).digest('hex');
  const asCalendar = await fetch(`${events.url}/api/internal/test-friends`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Canopy-Calendar t=${t0}, sig=${calSig}` }, body: JSON.stringify(call.body)
  });
  assert.equal(asCalendar.status, 401);

  // Past events: the count, 6 unless given, 1 to 20.
  for (const count of [0, 21, 2.5, '6']) {
    const bad = await admin.post('/api/admin/test-people/events', { count });
    assert.equal(bad.status, 400, String(count));
    assert.equal(bad.data.reason, 'bad_count');
  }
  const made = await admin.post('/api/admin/test-people/events', {});
  assert.equal(made.status, 200, made.text);
  assert.deepEqual(made.data, { sites: [{ site: 'events', ok: true, created: 6 }] });
  const evCall = events.calls[events.calls.length - 1];
  assert.equal(evCall.path, '/api/internal/test-events');
  assert.deepEqual({ ...evCall.body, testPeopleIds: evCall.body.testPeopleIds.slice().sort() }, { personId: adminId, testPeopleIds: ids, count: 6 });
  assert.equal((await admin.post('/api/admin/test-people/events', { count: 3 })).data.sites[0].created, 3);

  // Not for anyone but the admin, and only from a Canopy page.
  for (const url of ['/api/admin/test-people/befriend', '/api/admin/test-people/events']) {
    assert.equal((await bob.post(url)).status, 401, url);
    assert.equal((await browser(server).post(url)).status, 401, url);
    assert.equal((await admin.post(url, {}, { headers: { Origin: 'https://evil.example' } })).status, 403, url);
  }
  const before = events.calls.length;

  // A site that's failing, or can't be reached: a 502 that says so.
  events.mode = 'fail';
  const failed = await admin.post('/api/admin/test-people/befriend');
  assert.equal(failed.status, 502);
  assert.equal(failed.data.reason, 'sites_failed');
  assert.match(failed.data.error, /events answered 500/);
  events.mode = 'ok';
  const apps = (await admin.get('/api/admin/apps')).data.apps;
  const eventsApp = apps.find((a) => a.name === 'events');
  await admin.patch(`/api/admin/apps/${eventsApp.id}`, { calendarUrl: 'http://127.0.0.1:9' });
  const down = await admin.post('/api/admin/test-people/befriend');
  assert.equal(down.status, 502);
  assert.match(down.data.error, /events couldn't be reached/);
  await admin.patch(`/api/admin/apps/${eventsApp.id}`, { calendarUrl: events.url });
  assert.equal(events.calls.length, before + 1, 'only the failing one got there');

  // Delete all: the site clears its test events and every friendship with
  // these ids first, then the people go.
  const del = await admin.del('/api/admin/test-people');
  assert.equal(del.status, 200, del.text);
  assert.deepEqual(del.data, { ok: true, deleted: 5, sites: [{ site: 'events', ok: true, events: 7, friendships: 10 }] });
  const last = events.calls.slice(-2).sort((a, b) => a.path.localeCompare(b.path));
  assert.deepEqual(last.map((c) => `${c.method} ${c.path}`), ['DELETE /api/internal/test-events', 'POST /api/internal/test-friends/remove']);
  assert.deepEqual(last[0].body, {});
  assert.deepEqual(last[1].body.personIds.slice().sort(), ids);

  // A site that fails doesn't stop the delete; it's reported.
  await admin.post('/api/admin/test-people', { count: 2 });
  events.mode = 'fail';
  const del2 = await admin.del('/api/admin/test-people');
  assert.equal(del2.status, 200);
  assert.deepEqual(del2.data, { ok: true, deleted: 2, sites: [{ site: 'events', ok: false, error: 'answered 500; answered 500' }] });
  assert.equal((await admin.get('/api/admin/people')).data.people.filter((p) => p.isTest).length, 0);
});
