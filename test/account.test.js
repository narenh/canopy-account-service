// End to end against the real server: sign-up with an emailed code, the
// first admin, passkey sign-in, self-serve recovery, setup links, site
// keys, /api/session and /api/people, and the checks around them.

const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, browser } = require('./harness');

test('accounts, end to end', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());

  const admin = browser(server);
  const ana = browser(server);
  let adminId, anaId, siteKey;

  await t.test('a brand-new install takes the setup password before anything else', async () => {
    const refused = await ana.post('/api/auth/email/start', { email: 'ana@example.com' });
    assert.equal(refused.status, 403);
    assert.equal(refused.data.reason, 'setup_required');
    assert.equal((await admin.post('/api/auth/admin-setup', { password: 'nope' })).status, 403);
    assert.equal((await admin.post('/api/auth/admin-setup', { password: 'setup-pw' })).status, 200);
  });

  await t.test('after the setup password, the first account is the admin (no code needed)', async () => {
    const before = admin.cookie;
    const start = await admin.post('/api/auth/email/start', { email: 'Host@Example.com' });
    assert.equal(start.data.verified, true);
    assert.equal(start.data.state, 'new');
    const opts = await admin.post('/api/auth/register/new', { firstName: 'Hana', lastName: 'Host' });
    assert.equal(opts.status, 200);
    assert.equal(opts.data.options.rp.name, 'Canopy');
    const made = await admin.makePasskey(opts);
    assert.equal(made.status, 201, made.text);
    assert.equal(made.data.person.isAdmin, true);
    assert.equal(made.data.person.email, 'host@example.com');
    assert.notEqual(admin.cookie, before, 'signing in rotates the session token');
    adminId = made.data.person.id;
    assert.equal((await admin.get('/admin')).status, 200);
  });

  await t.test('a change from a page that is not Canopy is refused', async () => {
    const evil = browser(server, { origin: 'https://evil.example' });
    evil.cookie = admin.cookie;
    const r = await evil.patch('/api/profile', { firstName: 'X', lastName: 'Y' });
    assert.equal(r.status, 403);
    assert.equal(r.data.reason, 'bad_origin');
    const none = await admin.post('/api/signout', {}, { headers: { Origin: '' } });
    assert.equal(none.status, 403);
  });

  await t.test('a new email gets a code; a wrong one is refused; the right one leads to sign-up', async () => {
    const start = await ana.post('/api/auth/email/start', { email: 'ana@example.com' });
    assert.equal(start.status, 200);
    assert.equal(start.data.verified, false);
    assert.equal(start.data.state, undefined, 'nothing about the account is said before the code');
    const code = server.lastCode('ana@example.com');
    assert.match(code, /^\d{6}$/);
    const wrong = await ana.post('/api/auth/email/verify', { code: code === '000000' ? '111111' : '000000' });
    assert.equal(wrong.status, 403);
    // Can't skip the code.
    assert.equal((await ana.post('/api/auth/register/new', { firstName: 'Ana', lastName: 'Lima' })).data.reason, 'verify_first');
    const right = await ana.post('/api/auth/email/verify', { code });
    assert.equal(right.status, 200);
    assert.equal(right.data.state, 'new');
    const opts = await ana.post('/api/auth/register/new', { firstName: 'Ana', lastName: 'Lima', venmoHandle: '@ana-l' });
    const made = await ana.makePasskey(opts);
    assert.equal(made.status, 201, made.text);
    assert.equal(made.data.person.isAdmin, false);
    assert.equal(made.data.person.venmo, 'ana-l');
    assert.equal(made.data.person.shortName, 'Ana L');
    anaId = made.data.person.id;
  });

  await t.test('a code dies after five wrong tries', async () => {
    const b = browser(server);
    await b.post('/api/auth/email/start', { email: 'tries@example.com' });
    const code = server.lastCode('tries@example.com');
    const wrongCode = code === '000000' ? '111111' : '000000';
    for (let i = 0; i < 5; i++) assert.equal((await b.post('/api/auth/email/verify', { code: wrongCode })).status, 403);
    const after = await b.post('/api/auth/email/verify', { code });
    assert.equal(after.status, 400);
    assert.equal(after.data.reason, 'expired');
  });

  await t.test('signing in with a passkey on a fresh browser', async () => {
    const phone = browser(server);
    phone.authenticator.creds.push(...ana.authenticator.creds);
    const r = await phone.signInWithPasskey();
    assert.equal(r.status, 200, r.text);
    assert.equal(r.data.person.id, anaId);
  });

  await t.test('an existing email on a new phone: code, then a new passkey (self-serve recovery)', async () => {
    const newPhone = browser(server);
    const proven = await newPhone.proveEmail('ana@example.com');
    assert.equal(proven.data.state, 'existing');
    assert.equal(proven.data.firstName, 'Ana');
    assert.equal(proven.data.hasPasskey, true);
    const opts = await newPhone.post('/api/auth/register/existing');
    assert.equal(opts.status, 200);
    assert.equal(opts.data.options.excludeCredentials.length, 1);
    const made = await newPhone.makePasskey(opts);
    assert.equal(made.status, 201, made.text);
    assert.equal(made.data.person.id, anaId);
    const keys = await newPhone.get('/api/profile/passkeys');
    assert.equal(keys.data.passkeys.length, 2);
    // Removing the old phone's passkey is fine; the last one isn't.
    const old = keys.data.passkeys[0].id;
    assert.equal((await newPhone.del('/api/profile/passkeys/' + encodeURIComponent(old))).status, 200);
    const last = (await newPhone.get('/api/profile/passkeys')).data.passkeys[0].id;
    const refused = await newPhone.del('/api/profile/passkeys/' + encodeURIComponent(last));
    assert.equal(refused.status, 409);
    assert.equal(refused.data.reason, 'last_passkey');
    // The old phone's passkey no longer gets in.
    const oldPhone = browser(server);
    oldPhone.authenticator.creds.push(...ana.authenticator.creds);
    assert.equal((await oldPhone.signInWithPasskey()).data.reason, 'unknown_passkey');
    ana.authenticator.creds.splice(0, ana.authenticator.creds.length, ...newPhone.authenticator.creds);
    assert.equal((await ana.signInWithPasskey()).status, 200);
  });

  await t.test('profile: rename, Venmo, photo; photos only for signed-in browsers', async () => {
    const r = await ana.patch('/api/profile', { firstName: ' Ana  Maria ', lastName: 'Lima', venmoHandle: '' });
    assert.equal(r.data.person.firstName, 'Ana Maria');
    assert.equal(r.data.person.venmo, null);
    assert.equal((await ana.patch('/api/profile', { firstName: 'A', lastName: 'L', venmoHandle: 'bad handle!' })).data.reason, 'bad_venmo');
    // Phone: US/Canada without +1, anywhere else with +; stored as E.164.
    const phone = async (value) => (await ana.patch('/api/profile', { firstName: 'Ana Maria', lastName: 'Lima', phone: value })).data;
    assert.equal((await phone('(415) 555-1234')).person.phone, '+14155551234');
    assert.equal((await phone('1 415.555.1234')).person.phone, '+14155551234');
    assert.equal((await phone('+44 20 7946 0958')).person.phone, '+442079460958');
    for (const bad of ['555-1234', '(015) 555-1234', '415-155-1234', '+1 415 555 123', 'call me', '+0 123 456 789']) {
      assert.equal((await phone(bad)).reason, 'bad_phone', bad);
    }
    assert.equal((await phone('')).person.phone, null);
    assert.equal((await phone('4155551234')).person.phone, '+14155551234');
    const form = new FormData();
    form.append('photo', new Blob([Buffer.from('ffd8ffe0', 'hex')], { type: 'image/jpeg' }), 'photo.jpg');
    const up = await ana.upload('/api/profile/photo', form);
    assert.equal(up.status, 200, up.text);
    const photoPath = new URL(up.data.person.photoUrl).pathname + new URL(up.data.person.photoUrl).search;
    assert.equal((await ana.get(photoPath)).status, 200);
    assert.equal((await browser(server).get(photoPath)).status, 404);
  });

  await t.test('?return= only goes to Canopy pages', async () => {
    const out = browser(server);
    const page = await out.get('/?return=' + encodeURIComponent('https://evil.example/x'));
    assert.match(page.text, /data-return=""/);
    const ok = await out.get('/?return=' + encodeURIComponent('https://tickets.canopysf.com/mine'));
    assert.match(ok.text, /data-return="https:\/\/tickets\.canopysf\.com\/mine"/);
    assert.equal((await ana.get('/?return=' + encodeURIComponent('https://tickets.canopysf.com/mine'))).headers.get('location'), 'https://tickets.canopysf.com/mine');
    assert.equal((await ana.get('/?return=' + encodeURIComponent('https://canopysf.com.evil.example/'))).headers.get('location'), '/profile');
    assert.equal((await ana.get('/?return=' + encodeURIComponent('https://canopysf.com@evil.example/'))).headers.get('location'), '/profile');
  });

  await t.test('sites: a key, /api/session and /api/people', async () => {
    assert.equal((await ana.get('/api/admin/apps')).status, 401, 'admin only');
    const made = await admin.post('/api/admin/apps', { name: 'Tickets' });
    assert.equal(made.status, 201);
    assert.equal(made.data.app.name, 'tickets');
    siteKey = made.data.key;
    const auth = { Authorization: `Bearer ${siteKey}` };

    assert.equal((await browser(server).get('/api/session')).status, 401, 'no key');
    const anon = await browser(server).get('/api/session', { headers: { ...auth, 'X-Canopy-Session': 'x'.repeat(43) } });
    assert.deepEqual(anon.data, { person: null });
    const me = await browser(server).get('/api/session', { headers: { ...auth, 'X-Canopy-Session': ana.cookie } });
    assert.equal(me.data.person.id, anaId);
    assert.equal(me.data.person.email, 'ana@example.com');
    assert.equal(me.data.person.phone, '+14155551234');
    assert.match(me.data.person.photoUrl, /\/photo\//);

    const ppl = await browser(server).get(`/api/people?ids=${anaId},${adminId},00000000-0000-0000-0000-000000000000`, { headers: auth });
    assert.deepEqual(ppl.data.people.map((p) => p.id).sort(), [anaId, adminId].sort());
    assert.equal(ppl.data.people[0].email, undefined, 'other people come without their email');
  });

  await t.test('reset passkeys: signed out everywhere, and a one-time setup link', async () => {
    assert.equal((await admin.post(`/api/admin/people/${adminId}/reset-passkeys`)).status, 409, 'not your own');
    const r = await admin.post(`/api/admin/people/${anaId}/reset-passkeys`);
    assert.equal(r.status, 200);
    const code = r.data.setupUrl.split('/setup/')[1];
    assert.equal((await ana.get('/api/me')).data.person, null, 'her session is gone');
    assert.equal((await ana.signInWithPasskey()).data.reason, 'unknown_passkey');

    const info = await ana.get('/api/setup/' + code);
    assert.equal(info.data.firstName, 'Ana Maria');
    const opts = await ana.post('/api/auth/register/link', { code });
    ana.authenticator.creds.length = 0;
    const made = await ana.makePasskey(opts);
    assert.equal(made.status, 201, made.text);
    assert.equal(made.data.person.id, anaId);
    assert.equal((await ana.get('/api/setup/' + code)).status, 404, 'one use');
    assert.equal((await browser(server).post('/api/auth/register/link', { code })).status, 404);

    // Only the newest link works.
    const first = (await admin.post(`/api/admin/people/${anaId}/setup-link`)).data.setupUrl.split('/setup/')[1];
    const second = (await admin.post(`/api/admin/people/${anaId}/setup-link`)).data.setupUrl.split('/setup/')[1];
    assert.equal((await ana.get('/api/setup/' + first)).status, 404);
    assert.equal((await ana.get('/api/setup/' + second)).status, 200);
  });

  await t.test('signing out ends the session for every site', async () => {
    const token = ana.cookie;
    assert.equal((await ana.post('/api/signout')).status, 200);
    const s = await browser(server).get('/api/session', { headers: { Authorization: `Bearer ${siteKey}`, 'X-Canopy-Session': token } });
    assert.equal(s.data.person, null);
  });

  await t.test('a GET /signout from another website does nothing', async () => {
    assert.equal((await ana.signInWithPasskey()).status, 200);
    const r = await ana.get('/signout?return=' + encodeURIComponent('https://evil.example/'), { headers: { 'Sec-Fetch-Site': 'cross-site' } });
    assert.equal(r.headers.get('location'), '/profile');
    assert.ok((await ana.get('/api/me')).data.person);
    const ok = await ana.get('/signout?return=' + encodeURIComponent('https://tickets.canopysf.com/'), { headers: { 'Sec-Fetch-Site': 'same-site' } });
    assert.equal(ok.headers.get('location'), 'https://tickets.canopysf.com/');
    assert.equal((await ana.get('/api/me')).data.person, null);
  });

  await t.test('deleting someone: gone from /api/people (a former member to every site)', async () => {
    assert.equal((await admin.del(`/api/admin/people/${adminId}`)).status, 409, 'not yourself');
    assert.equal((await admin.del(`/api/admin/people/${anaId}`)).status, 200);
    const ppl = await browser(server).get(`/api/people?ids=${anaId}`, { headers: { Authorization: `Bearer ${siteKey}` } });
    assert.deepEqual(ppl.data.people, []);
  });

  await t.test('a cut-off site key stops working', async () => {
    const apps = (await admin.get('/api/admin/apps')).data.apps;
    assert.equal((await admin.post(`/api/admin/apps/${apps[0].id}/revoke`)).status, 200);
    assert.equal((await browser(server).get('/api/people?ids=', { headers: { Authorization: `Bearer ${siteKey}` } })).status, 401);
    const rekeyed = await admin.post(`/api/admin/apps/${apps[0].id}/rekey`);
    assert.equal((await browser(server).get('/api/people?ids=', { headers: { Authorization: `Bearer ${rekeyed.data.key}` } })).status, 200);
  });

  await t.test('sending codes is limited per email', async () => {
    const b = browser(server);
    for (let i = 0; i < 5; i++) assert.equal((await b.post('/api/auth/email/start', { email: 'spam@example.com' })).status, 200);
    assert.equal((await b.post('/api/auth/email/start', { email: 'spam@example.com' })).status, 429);
  });
});
