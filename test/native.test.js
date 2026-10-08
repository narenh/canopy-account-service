// The apps: every sign-in flow from /api/native/v1 end to end with a
// software passkey signing as the iOS or Android app, the token that comes
// out of it working as a bearer token everywhere a cookie does, every way
// it gets taken away, the Origin check (only a bearer header skips it),
// photos, and the limits the apps share with the web.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const Database = require('better-sqlite3');
const { startServer, browser, nativeApp } = require('./harness');
const { fakeSigningCert } = require('./softAuthenticator');

const ANDROID = fakeSigningCert('canopy-events-release');
const UNLISTED_ANDROID = fakeSigningCert('someone-elses-app');

// A JPEG's structure with metadata in every place a camera or an editor
// puts it: EXIF in APP1, IPTC in APP13, a comment, and a trailer after
// the end (a "motion photo"). The server never decodes the pixels, so the
// scan data can be anything without an FF in it.
function jpegWithMetadata() {
  const seg = (marker, text) => {
    const payload = Buffer.from(text, 'latin1');
    const len = Buffer.alloc(2);
    len.writeUInt16BE(payload.length + 2);
    return Buffer.concat([Buffer.from([0xff, marker]), len, payload]);
  };
  return Buffer.concat([
    Buffer.from([0xff, 0xd8]),
    seg(0xe0, 'JFIF\u0000\u0001\u0001'),
    seg(0xe1, 'Exif\u0000\u0000GPS 37.7749N 122.4194W secret-location'),
    seg(0xe2, 'ICC_PROFILE\u0000colour'),
    seg(0xed, 'Photoshop 3.0\u0000secret-iptc'),
    seg(0xfe, 'secret-comment'),
    seg(0xdb, 'quant-tables'),
    seg(0xda, 'scan-header'),
    Buffer.from('the-pixels', 'latin1'),
    Buffer.from([0xff, 0xd9]),
    Buffer.from('secret-motion-photo', 'latin1')
  ]);
}

function photoForm(buf, type = 'image/jpeg') {
  const form = new FormData();
  form.append('photo', new Blob([buf], { type }), 'photo.jpg');
  return form;
}

async function withDb(server, fn) {
  const db = new Database(path.join(server.dataDir, 'account.db'));
  try { return fn(db); } finally { db.close(); }
}

test('apps, end to end', async (t) => {
  const server = await startServer({ ANDROID_APK_KEY_HASHES: ` ${ANDROID.fingerprint} , not-a-hash` });
  t.after(() => server.stop());

  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const tickets = (await admin.post('/api/admin/apps', { name: 'tickets' })).data;
  const events = (await admin.post('/api/admin/apps', { name: 'events' })).data;
  await admin.patch(`/api/admin/apps/${events.app.id}`, { allowsUnverified: true });

  const sessionFor = (site, token, headers = {}) => browser(server).get('/api/session', {
    headers: { Authorization: `Bearer ${site.key}`, 'X-Canopy-Session': token, ...headers }
  });

  assert.match(server.output(), /ANDROID_APK_KEY_HASHES: ignoring "not-a-hash"/);

  await t.test('begin: a platform, and a 43-character ceremony', async () => {
    const app = nativeApp(server);
    assert.equal((await app.post('/auth/begin', { platform: 'windows' })).data.reason, 'bad_platform');
    const r = await app.begin();
    assert.equal(r.status, 201, r.text);
    assert.match(r.data.ceremony, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(r.headers.get('cache-control'), 'no-store');
    // A ceremony isn't anyone.
    assert.equal((await app.get('/me')).status, 401);
    assert.deepEqual((await sessionFor(events, app.token)).data, { person: null });
  });

  await t.test('a step without a ceremony, or with a made-up one, starts again', async () => {
    const app = nativeApp(server);
    assert.equal((await app.post('/auth/passkey/options')).data.reason, 'bad_origin', 'no bearer: an ordinary POST with no Origin');
    const r = await app.post('/auth/passkey/options', {}, { bearer: 'x'.repeat(43) });
    assert.equal(r.status, 400);
    assert.equal(r.data.reason, 'expired');
    assert.equal((await app.post('/auth/email/start', { email: 'a@example.com' }, { bearer: 'not a token' })).data.reason, 'expired');
  });

  let ana; let anaId;

  await t.test('sign-up by email code on iOS: the token comes back, and the ceremony is spent', async () => {
    ana = nativeApp(server);
    const proven = await ana.proveEmail('ana@example.com');
    assert.equal(proven.status, 200, proven.text);
    assert.equal(proven.data.state, 'new');
    const ceremony = ana.token;
    const opts = await ana.post('/auth/register/new', { firstName: 'Ana', lastName: 'Lima', venmoHandle: '@ana-l' });
    assert.equal(opts.status, 200, opts.text);
    assert.equal(opts.data.options.rp.id, 'localhost');
    const made = await ana.makePasskey(opts);
    assert.equal(made.status, 201, made.text);
    assert.match(made.data.token, /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(made.data.token, ceremony, 'signed in under a new token');
    assert.equal(made.data.person.email, 'ana@example.com');
    assert.equal(made.data.person.emailVerified, true);
    assert.equal(made.data.person.venmo, 'ana-l');
    anaId = made.data.person.id;
    assert.equal((await ana.get('/me', { bearer: ceremony })).status, 401, 'the ceremony token is worthless now');
    const me = await ana.get('/me');
    assert.equal(me.status, 200, me.text);
    assert.equal(me.data.person.id, anaId);
    assert.equal(made.headers.get('set-cookie'), null, 'no cookie, ever');
  });

  await t.test('the token is a bearer token for sites, kept alive without a renewCookie', async () => {
    const r = await sessionFor(tickets, ana.token);
    assert.equal(r.data.person.id, anaId);
    assert.equal(r.data.renewCookie, undefined);
    // Long unseen and long unrenewed: asking marks it seen, and still
    // hands back no cookie.
    await withDb(server, (db) => db.prepare('UPDATE sessions SET last_seen_at = ?, cookie_set_at = 0 WHERE person_id = ?').run(Date.now() - 30 * 24 * 3600 * 1000, anaId));
    const again = await sessionFor(tickets, ana.token);
    assert.equal(again.data.person.id, anaId);
    assert.equal(again.data.renewCookie, undefined);
    const seen = await withDb(server, (db) => db.prepare('SELECT last_seen_at FROM sessions WHERE person_id = ?').get(anaId).last_seen_at);
    assert.ok(Date.now() - seen < 60 * 1000, 'last seen just now');
    // And the app's own calls keep it alive the same way.
    await withDb(server, (db) => db.prepare('UPDATE sessions SET last_seen_at = ? WHERE person_id = ?').run(Date.now() - 1000 * 1000, anaId));
    await ana.get('/me');
    const seen2 = await withDb(server, (db) => db.prepare('SELECT last_seen_at FROM sessions WHERE person_id = ?').get(anaId).last_seen_at);
    assert.ok(Date.now() - seen2 < 60 * 1000);
  });

  await t.test('a token past a year unseen is over', async () => {
    const app = nativeApp(server);
    app.authenticator.creds.push(...ana.authenticator.creds);
    assert.equal((await app.signInWithPasskey()).status, 200);
    const idHash = require('crypto').createHash('sha256').update(app.token).digest('hex');
    await withDb(server, (db) => db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?').run(Date.now() - 366 * 24 * 3600 * 1000, idHash));
    // Only that one was aged; Ana's own app is still in.
    assert.equal((await app.get('/me')).status, 401);
    assert.equal((await ana.get('/me')).status, 200);
  });

  await t.test('the profile: get, edit, and a photo with its metadata taken out', async () => {
    const saved = await ana.patch('/me', { firstName: 'Ana', lastName: 'Lima', phone: '415 555 1234', instagram: '@Ana.L', cashapp: '$AnaL', findable: false });
    assert.equal(saved.status, 200, saved.text);
    assert.deepEqual([saved.data.person.phone, saved.data.person.instagram, saved.data.person.cashapp, saved.data.person.findable],
      ['+14155551234', 'ana.l', 'AnaL', false]);
    assert.equal((await ana.patch('/me', { firstName: 'Ana', lastName: 'Lima', phone: '12' })).data.reason, 'bad_phone');
    assert.equal((await ana.patch('/me', { firstName: '', lastName: 'Lima' })).status, 400);

    assert.equal((await ana.upload('/me/photo', photoForm(Buffer.from('89504e470d0a1a0a', 'hex'), 'image/png'))).data.reason, 'bad_photo');
    assert.equal((await ana.upload('/me/photo', new FormData())).data.reason, 'no_photo');
    const up = await ana.upload('/me/photo', photoForm(jpegWithMetadata()));
    assert.equal(up.status, 200, up.text);
    const photoUrl = new URL(up.data.person.photoUrl);
    const stored = Buffer.from(await (await fetch(server.base + photoUrl.pathname, { headers: { Authorization: `Bearer ${ana.token}` } })).arrayBuffer());
    const text = stored.toString('latin1');
    for (const secret of ['secret-location', 'secret-iptc', 'secret-comment', 'secret-motion-photo', 'Exif']) {
      assert.ok(!text.includes(secret), `${secret} was taken out`);
    }
    for (const kept of ['JFIF', 'ICC_PROFILE', 'quant-tables', 'scan-header', 'the-pixels']) assert.ok(text.includes(kept), `${kept} was kept`);
    assert.deepEqual([...stored.subarray(-2)], [0xff, 0xd9]);
  });

  await t.test('photos: a bearer token, or a cookie; a bearer header decides alone', async () => {
    const url = `/photo/${anaId}`;
    const get = (headers) => fetch(server.base + url, { headers }).then((r) => r.status);
    assert.equal(await get({ Authorization: `Bearer ${ana.token}` }), 200, 'an app');
    assert.equal(await get({ Cookie: `canopy_session=${admin.cookie}` }), 200, 'a browser, as before');
    assert.equal(await get({}), 404, 'nobody');
    assert.equal(await get({ Authorization: 'Bearer nonsense', Cookie: `canopy_session=${admin.cookie}` }), 404, 'a malformed bearer is nobody, cookie or not');
    assert.equal(await get({ Authorization: `Bearer ${'x'.repeat(43)}`, Cookie: `canopy_session=${admin.cookie}` }), 404, 'an unknown bearer too');
    assert.equal(await get({ Authorization: `Bearer ${events.key}` }), 404, "a site's key isn't a session");
    assert.equal(await get({ Authorization: 'Basic abc', Cookie: `canopy_session=${admin.cookie}` }), 200, 'other schemes are left alone');
  });

  await t.test('passkeys: list, add one, remove one, never the last', async () => {
    assert.equal((await ana.get('/me/passkeys')).data.passkeys.length, 1);
    const opts = await ana.post('/me/passkeys/options');
    assert.equal(opts.status, 200, opts.text);
    assert.equal(opts.data.options.excludeCredentials.length, 1);
    const added = await ana.makePasskey(opts, '/me/passkeys/verify');
    assert.equal(added.status, 201, added.text);
    assert.deepEqual(added.data, { ok: true });
    const keys = (await ana.get('/me/passkeys')).data.passkeys;
    assert.equal(keys.length, 2);
    assert.equal((await ana.del('/me/passkeys/' + encodeURIComponent(keys[0].id))).status, 200);
    const last = (await ana.get('/me/passkeys')).data.passkeys[0].id;
    assert.equal((await ana.del('/me/passkeys/' + encodeURIComponent(last))).data.reason, 'last_passkey');
    ana.authenticator.creds.splice(0, 1);
  });

  await t.test('passkey sign-in from the Android app, by its signing certificate', async () => {
    const android = nativeApp(server, { origin: ANDROID.origin, platform: 'android', device: 'Pixel 9' });
    android.authenticator.creds.push(...ana.authenticator.creds);
    const r = await android.signInWithPasskey();
    assert.equal(r.status, 200, r.text);
    assert.equal(r.data.person.id, anaId);
    assert.equal((await sessionFor(tickets, android.token)).data.person.id, anaId);
    // An app signed with some other certificate isn't Canopy.
    const other = nativeApp(server, { origin: UNLISTED_ANDROID.origin, platform: 'android' });
    other.authenticator.creds.push(...ana.authenticator.creds);
    assert.equal((await other.signInWithPasskey()).data.reason, 'not_verified');
  });

  await t.test("the web's sign-in doesn't take an app's origin", async () => {
    for (const origin of [ANDROID.origin, 'https://localhost']) {
      const b = browser(server);
      const start = await b.post('/api/auth/login/options');
      const response = ana.authenticator.authenticate(start.data.options, origin);
      const r = await b.post('/api/auth/login/verify', { response });
      assert.equal(r.status, 400, origin);
      assert.equal(r.data.reason, 'not_verified');
      assert.equal(b.cookie === null || (await b.get('/api/me')).data.person === null, true);
    }
  });

  await t.test('a signed-in token is no ceremony', async () => {
    const r = await ana.post('/auth/passkey/options');
    assert.equal(r.status, 409);
    assert.equal(r.data.reason, 'signed_in');
  });

  await t.test('a new phone: code, then a passkey added to the account', async () => {
    const phone = nativeApp(server);
    const proven = await phone.proveEmail('ana@example.com');
    assert.equal(proven.data.state, 'existing');
    assert.equal(proven.data.unverified, false);
    const made = await phone.makePasskey(await phone.post('/auth/register/existing'));
    assert.equal(made.status, 201, made.text);
    assert.equal(made.data.person.id, anaId);
    assert.equal((await ana.get('/me')).status, 200, "a verified account's other sessions stay");
    assert.equal((await phone.post('/signout')).status, 200);
  });

  await t.test('changing the email: a passkey check, then a code to the new address', async () => {
    assert.equal((await ana.post('/me/email/start', { email: 'ana.new@example.com' })).data.reason, 'reauth_required');
    const start = await ana.post('/me/reauth/options');
    assert.equal(start.data.options.userVerification, 'required');
    const response = ana.authenticator.authenticate(start.data.options, ana.origin);
    assert.equal((await ana.post('/me/reauth/verify', { response })).status, 200);
    assert.equal((await ana.post('/me/email/start', { email: 'host@example.com' })).data.reason, 'email_unavailable');
    assert.equal((await ana.post('/me/email/start', { email: 'Ana.New@example.com' })).status, 200);
    const done = await ana.post('/me/email/verify', { code: server.lastCode('ana.new@example.com') });
    assert.equal(done.status, 200, done.text);
    assert.equal(done.data.person.email, 'ana.new@example.com');
    assert.match(server.output(), /email-changed notice for ana@example\.com/);
  });

  await t.test('quick sign-up from the app: unverified, the email-has-account answer, then proven by code', async () => {
    const quinn = nativeApp(server);
    const taken = await quinn.quickSignUp('ANA.NEW@example.com', 'X', 'Y');
    assert.equal(taken.status, 409);
    assert.equal(taken.data.reason, 'email_has_account');
    const made = await quinn.quickSignUp('quinn@example.com', 'Quinn', 'Quick');
    assert.equal(made.status, 201, made.text);
    assert.equal(made.data.person.emailVerified, false);
    assert.equal(server.lastCode('quinn@example.com'), undefined, 'no email was sent');
    assert.deepEqual((await sessionFor(tickets, quinn.token)).data, { person: null, unverified: true });
    assert.equal((await sessionFor(events, quinn.token)).data.person.emailVerified, false);
    // The banner's button.
    const start = await quinn.post('/me/verify/start');
    assert.equal(start.data.verified, false);
    const code = server.lastCode('quinn@example.com');
    assert.equal((await quinn.post('/me/verify/check', { code: code === '000000' ? '111111' : '000000' })).data.reason, 'wrong_code');
    const done = await quinn.post('/me/verify/check', { code });
    assert.equal(done.data.person.emailVerified, true);
    assert.equal((await sessionFor(tickets, quinn.token)).data.person.emailVerified, true);
  });

  await t.test('signing in by code from the app takes an unverified account over', async () => {
    // A quick sign-up with someone else's email, on the web and in an app...
    const mallory = browser(server);
    const bobId = (await mallory.quickSignUp('bob@example.com', 'Bob', 'Bobson')).data.person.id;
    const malloryApp = nativeApp(server);
    malloryApp.authenticator.creds.push(...mallory.authenticator.creds);
    // (her passkey was made on the web page, so the app signs as that page)
    const start = await malloryApp.begin().then(() => malloryApp.post('/auth/passkey/options'));
    const response = malloryApp.authenticator.authenticate(start.data.options, server.base);
    assert.equal((await malloryApp.post('/auth/passkey/verify', { response })).data.person.id, bobId);
    // ...and the inbox's owner signs in by code from his app.
    const bob = nativeApp(server);
    const proven = await bob.proveEmail('bob@example.com');
    assert.equal(proven.data.unverified, true);
    const made = await bob.makePasskey(await bob.post('/auth/register/existing'));
    assert.equal(made.status, 201, made.text);
    assert.equal(made.data.person.id, bobId);
    assert.equal(made.data.person.emailVerified, true);
    assert.equal((await bob.get('/me/passkeys')).data.passkeys.length, 1, 'only his passkey is left');
    assert.equal((await mallory.get('/api/me')).data.person, null, "the maker's browser is signed out");
    assert.equal((await malloryApp.get('/me')).status, 401, "and the maker's app");
    assert.equal((await bob.get('/me')).status, 200);
  });

  await t.test('where you are signed in: the app by name, from the app and from the web', async () => {
    const web = browser(server);
    web.authenticator.creds.push(...ana.authenticator.creds);
    // Ana's passkey signs as the iOS app; the web page takes that origin
    // too, being https://canopysf.com.
    const start = await web.post('/api/auth/login/options');
    const response = ana.authenticator.authenticate(start.data.options, ana.origin);
    assert.equal((await web.post('/api/auth/login/verify', { response })).status, 200);
    const fromApp = (await ana.get('/me/sessions')).data.sessions;
    const mine = fromApp.find((s) => s.current);
    assert.equal(mine.kind, 'ios');
    assert.equal(mine.name, 'Canopy Events on iPhone');
    assert.ok(fromApp.some((s) => s.kind === 'android' && s.name === 'Canopy Events on Pixel 9'));
    const fromWeb = (await web.get('/api/profile/sessions')).data.sessions;
    const appRow = fromWeb.find((s) => s.id === mine.id);
    assert.equal(appRow.current, false);
    // Signing the Android app out from the web.
    const androidId = fromWeb.find((s) => s.kind === 'android').id;
    assert.equal((await web.del('/api/profile/sessions/' + androidId)).status, 200);
    assert.ok(!(await ana.get('/me/sessions')).data.sessions.some((s) => s.kind === 'android'));
    // And the web browser from the app.
    const webId = (await ana.get('/me/sessions')).data.sessions.find((s) => s.kind === 'web').id;
    assert.equal((await ana.del('/me/sessions/' + webId)).status, 200);
    assert.equal((await web.get('/api/me')).data.person, null);
  });

  await t.test('signing out ends the token: here, and on every site', async () => {
    const app = nativeApp(server);
    app.authenticator.creds.push(...ana.authenticator.creds);
    await app.signInWithPasskey();
    const token = app.token;
    assert.equal((await sessionFor(tickets, token)).data.person.id, anaId);
    const r = await app.post('/signout');
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('set-cookie'), null);
    assert.deepEqual((await sessionFor(tickets, token)).data, { person: null });
    assert.equal((await app.get('/me')).status, 401);
    assert.equal((await app.post('/signout')).status, 200, 'twice is fine');
  });

  await t.test('signing out everywhere ends every token and cookie', async () => {
    const app = nativeApp(server);
    app.authenticator.creds.push(...ana.authenticator.creds);
    await app.signInWithPasskey();
    const web = browser(server);
    web.authenticator.creds.push(...ana.authenticator.creds);
    const start = await web.post('/api/auth/login/options');
    await web.post('/api/auth/login/verify', { response: ana.authenticator.authenticate(start.data.options, ana.origin) });
    assert.ok((await web.get('/api/me')).data.person);
    assert.equal((await app.post('/signout/everywhere')).status, 200);
    assert.equal((await app.get('/me')).status, 401);
    assert.equal((await ana.get('/me')).status, 401);
    assert.equal((await web.get('/api/me')).data.person, null);
  });

  await t.test("the admin's reset and delete end an app's token", async () => {
    const cat = nativeApp(server);
    const catId = (await cat.signUp('cat@example.com', 'Cat', 'Cole')).data.person.id;
    assert.equal((await sessionFor(tickets, cat.token)).data.person.id, catId);
    assert.equal((await admin.post(`/api/admin/people/${catId}/reset-passkeys`)).status, 200);
    assert.equal((await cat.get('/me')).status, 401);
    assert.deepEqual((await sessionFor(tickets, cat.token)).data, { person: null });

    const dan = nativeApp(server);
    const danId = (await dan.signUp('dan@example.com', 'Dan', 'Dunn')).data.person.id;
    assert.equal((await admin.del(`/api/admin/people/${danId}`)).status, 200);
    assert.equal((await dan.get('/me')).status, 401);
    assert.deepEqual((await sessionFor(tickets, dan.token)).data, { person: null });
  });

  await t.test('no admin-only answers from the app', async () => {
    const r = await nativeApp(server).signUp('eve@example.com', 'Eve', 'Ewe');
    assert.equal(r.data.person.isAdmin, false);
  });
});

test('apps: nothing until there is an admin', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const app = nativeApp(server);
  await app.begin();
  assert.equal((await app.post('/auth/email/start', { email: 'a@example.com' })).data.reason, 'setup_required');
  assert.equal((await app.post('/auth/passkey/options')).data.reason, 'setup_required');
  assert.equal((await app.post('/auth/quick/start', { email: 'a@example.com', firstName: 'A', lastName: 'B' })).data.reason, 'setup_required');
});

test('the Origin check: only a bearer header skips it', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const app = nativeApp(server);
  app.authenticator.creds.push(...admin.authenticator.creds);
  const start = await app.begin().then(() => app.post('/auth/passkey/options'));
  assert.equal((await app.post('/auth/passkey/verify', { response: app.authenticator.authenticate(start.data.options, server.base) })).status, 200);

  const raw = (url, { method = 'POST', headers = {}, body } = {}) => fetch(server.base + url, { method, headers, body }).then(async (r) => ({ status: r.status, data: await r.json().catch(() => null), headers: r.headers }));
  const cookie = `canopy_session=${admin.cookie}`;

  await t.test('a forged cross-site POST with the cookie and no bearer is refused, on the web and app routes', async () => {
    for (const url of ['/api/signout', '/api/native/v1/signout', '/api/native/v1/signout/everywhere', '/api/signout/everywhere']) {
      for (const origin of ['https://evil.example', undefined]) {
        const r = await raw(url, { headers: { Cookie: cookie, 'Content-Type': 'application/json', ...(origin ? { Origin: origin } : {}) }, body: '{}' });
        assert.equal(r.status, 403, `${url} from ${origin}`);
        assert.equal(r.data.reason, 'bad_origin');
      }
    }
    assert.ok((await admin.get('/api/me')).data.person, 'still signed in');
  });

  await t.test('a bearer POST with no Origin goes through', async () => {
    const r = await raw('/api/native/v1/me/verify/start', { headers: { Authorization: `Bearer ${app.token}` } });
    assert.equal(r.status, 200);
    assert.equal(r.data.verified, true);
  });

  await t.test('a bearer header on a web route skips nothing', async () => {
    const r = await raw('/api/signout', { headers: { Cookie: cookie, Authorization: `Bearer ${admin.cookie}` } });
    assert.equal(r.status, 403);
    assert.ok((await admin.get('/api/me')).data.person);
  });

  await t.test("the app routes never read the cookie, even from a Canopy page", async () => {
    const me = await raw('/api/native/v1/me', { method: 'GET', headers: { Cookie: cookie } });
    assert.equal(me.status, 401);
    const out = await raw('/api/native/v1/signout', { headers: { Cookie: cookie, Origin: server.base } });
    assert.equal(out.status, 200);
    assert.ok((await admin.get('/api/me')).data.person, 'the cookie\'s session was not signed out');
    // With both, the bearer is who it is.
    const both = await raw('/api/native/v1/me', { method: 'GET', headers: { Cookie: cookie, Authorization: `Bearer ${app.token}` } });
    assert.equal(both.data.person.id, (await admin.get('/api/me')).data.person.id);
    const bad = await raw('/api/native/v1/me', { method: 'GET', headers: { Cookie: cookie, Authorization: 'Bearer nonsense' } });
    assert.equal(bad.status, 401, 'a malformed bearer is nobody, cookie or not');
  });

  await t.test('begin: JSON from anywhere, but a form from a page elsewhere is refused', async () => {
    assert.equal((await raw('/api/native/v1/auth/begin', { headers: { 'Content-Type': 'application/json' }, body: '{"platform":"ios"}' })).status, 201);
    const form = await raw('/api/native/v1/auth/begin', { headers: { 'Content-Type': 'text/plain', Origin: 'https://evil.example' }, body: '{"platform":"ios"}' });
    assert.equal(form.status, 403);
    assert.equal(form.data.reason, 'bad_origin');
  });

  await t.test('no CORS for the app routes: a page elsewhere is never told yes', async () => {
    const pre = await fetch(server.base + '/api/native/v1/me', {
      method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization' }
    });
    assert.equal(pre.headers.get('access-control-allow-origin'), null);
    assert.equal(pre.headers.get('access-control-allow-headers'), null);
  });
});

test('apps share the web limits', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const from = (ip) => ({ headers: { 'CF-Connecting-IP': ip } });

  await t.test('5 codes per email an hour, wherever they were asked for', async () => {
    const web = browser(server);
    for (let i = 0; i < 3; i++) assert.equal((await web.post('/api/auth/email/start', { email: 'ana@example.com' })).status, 200);
    const app = nativeApp(server);
    await app.begin();
    for (let i = 0; i < 2; i++) assert.equal((await app.post('/auth/email/start', { email: 'ana@example.com' })).status, 200);
    assert.equal((await app.post('/auth/email/start', { email: 'ana@example.com' })).status, 429);
    assert.equal((await web.post('/api/auth/email/start', { email: 'ana@example.com' })).status, 429);
  });

  await t.test('wrong codes per email, counted together', async () => {
    const web = browser(server);
    await web.post('/api/auth/email/start', { email: 'bea@example.com' });
    const wrong = server.lastCode('bea@example.com') === '000000' ? '111111' : '000000';
    for (let i = 0; i < 5; i++) assert.equal((await web.post('/api/auth/email/verify', { code: wrong })).status, 403);
    const app = nativeApp(server);
    await app.begin();
    await app.post('/auth/email/start', { email: 'bea@example.com' });
    for (let i = 0; i < 5; i++) assert.equal((await app.post('/auth/email/verify', { code: wrong })).status, 403);
    assert.equal((await app.post('/auth/email/verify', { code: server.lastCode('bea@example.com') })).status, 429, '10 wrong per email per 15 minutes');
  });

  await t.test('quick sign-up tries per address, counted together', async () => {
    let n = 0;
    const fresh = () => `q${++n}@example.com`;
    const web = browser(server);
    for (let i = 0; i < 10; i++) assert.equal((await web.post('/api/auth/quick/start', { email: fresh(), firstName: 'A', lastName: 'B' }, from('10.7.0.1'))).status, 200);
    for (let i = 0; i < 10; i++) {
      const app = nativeApp(server);
      await app.begin();
      assert.equal((await app.post('/auth/quick/start', { email: fresh(), firstName: 'A', lastName: 'B' }, from('10.7.0.1'))).status, 200);
    }
    const app = nativeApp(server);
    await app.begin();
    assert.equal((await app.post('/auth/quick/start', { email: fresh(), firstName: 'A', lastName: 'B' }, from('10.7.0.1'))).status, 429);
  });
});

test('photo metadata: what withoutMetadata keeps and refuses', () => {
  const { withoutMetadata } = require('../lib/photoStore');
  assert.equal(withoutMetadata(Buffer.from('not a jpeg')), null);
  assert.equal(withoutMetadata(Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0xff, 0xff])), null, 'a segment longer than the file');
  const noEnd = jpegWithMetadata();
  assert.equal(withoutMetadata(noEnd.subarray(0, noEnd.indexOf('the-pixels') + 4)), null, 'no end marker');
  const clean = withoutMetadata(jpegWithMetadata());
  assert.deepEqual(withoutMetadata(clean), clean, 'cleaning a clean one changes nothing');
});
