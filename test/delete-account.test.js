// Deleting your own account, from the web profile and from an app: a
// passkey check first, then exactly what the admin's delete does, and
// signed out. Never the admin.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { startServer, browser, nativeApp } = require('./harness');

// The smallest JPEG the photo upload keeps (as in account.test.js).
const TINY_JPEG = Buffer.from('ffd8ffdb0004aaaaffda0004bbbb0102ffd9', 'hex');

test('deleting your own account', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  const adminId = (await admin.signUp('host@example.com', 'Hana', 'Host')).data.person.id;
  const site = (await admin.post('/api/admin/apps', { name: 'events' })).data;
  // A passkey check, with Face ID or the like, as the page does it.
  const reauth = async (b) => {
    const start = await b.post('/api/auth/reauth/options');
    const response = b.authenticator.authenticate(start.data.options, server.base);
    return b.post('/api/auth/reauth/verify', { response });
  };

  await t.test('from the web: a passkey first, then everything goes, and this browser is signed out', async () => {
    const ana = browser(server);
    const anaId = (await ana.signUp('ana@example.com', 'Ana', 'Lima')).data.person.id;
    await ana.patch('/api/profile', { firstName: 'Ana', lastName: 'Lima', phone: '415 555 1234', instagram: 'ana.lima' });
    const form = new FormData();
    form.append('photo', new Blob([TINY_JPEG], { type: 'image/jpeg' }), 'photo.jpg');
    assert.equal((await ana.upload('/api/profile/photo', form)).status, 200);
    const photoFile = path.join(server.dataDir, 'photos', `${anaId}.jpg`);
    assert.ok(fs.existsSync(photoFile));
    // Signed in somewhere else too, in a browser and an app, and a setup
    // link out for her.
    const laptop = browser(server);
    laptop.authenticator.creds.push(...ana.authenticator.creds);
    await laptop.signInWithPasskey();
    const app = nativeApp(server);
    await app.proveEmail('ana@example.com');
    await app.makePasskey(await app.post('/auth/register/existing'));
    assert.ok((await app.get('/me')).data.person);
    const link = (await admin.post(`/api/admin/people/${anaId}/setup-link`)).data.setupUrl.split('/setup/')[1];

    // Not without a passkey check.
    const early = await ana.del('/api/profile');
    assert.equal(early.status, 403);
    assert.equal(early.data.reason, 'reauth_required');
    // Not from another website's page, whatever else.
    assert.equal((await ana.del('/api/profile', { headers: { Origin: 'https://evil.example' } })).data.reason, 'bad_origin');
    assert.equal((await reauth(ana)).status, 200);
    const gone = await ana.del('/api/profile');
    assert.equal(gone.status, 200, gone.text);
    assert.deepEqual(gone.data, { ok: true });
    assert.ok(gone.headers.getSetCookie().some((c) => /^canopy_session=;.*Max-Age=0/.test(c)), 'the cookie is cleared');

    // Gone, everywhere.
    assert.equal((await ana.get('/api/me')).data.person, null);
    assert.equal((await laptop.get('/api/me')).data.person, null, 'signed out on the other browser');
    assert.equal((await app.get('/me')).status, 401, 'and in the app');
    assert.equal((await laptop.signInWithPasskey()).data.reason, 'unknown_passkey', 'her passkeys are gone');
    assert.equal((await browser(server).get('/api/setup/' + link)).status, 404, 'and her setup link');
    assert.ok(!fs.existsSync(photoFile), 'and her photo');
    assert.ok(!(await admin.get('/api/admin/people')).data.people.some((p) => p.id === anaId));
    // A site sees a former member: the id is left out.
    const ppl = await browser(server).get(`/api/people?ids=${anaId},${adminId}`, { headers: { Authorization: `Bearer ${site.key}` } });
    assert.deepEqual(ppl.data.people.map((p) => p.id), [adminId]);
    // Her email is free again: signing up with it makes a new account.
    assert.equal((await browser(server).proveEmail('ana@example.com')).data.state, 'new');
  });

  await t.test('from an app: DELETE /me, with the same passkey check', async () => {
    const app = nativeApp(server);
    const bobId = (await app.signUp('bob@example.com', 'Bob', 'Bell')).data.person.id;
    const early = await app.del('/me');
    assert.equal(early.status, 403);
    assert.equal(early.data.reason, 'reauth_required');
    const start = await app.post('/me/reauth/options');
    const response = app.authenticator.authenticate(start.data.options, app.origin);
    assert.equal((await app.post('/me/reauth/verify', { response })).status, 200);
    const gone = await app.del('/me');
    assert.equal(gone.status, 200, gone.text);
    assert.deepEqual(gone.data, { ok: true });
    assert.equal(gone.headers.getSetCookie().length, 0, 'no cookie for an app');
    assert.equal((await app.get('/me')).status, 401);
    assert.ok(!(await admin.get('/api/admin/people')).data.people.some((p) => p.id === bobId));
  });

  await t.test("never the admin: it would leave nobody to run the place", async () => {
    assert.equal((await reauth(admin)).status, 200);
    const refused = await admin.del('/api/profile');
    assert.equal(refused.status, 409);
    assert.equal(refused.data.reason, 'is_admin');
    assert.match(refused.data.error, /nobody to run/);
    assert.equal((await admin.get('/api/me')).data.person.id, adminId, 'still here, still signed in');
    assert.equal((await admin.get('/api/admin/people')).status, 200);
  });

  await t.test('the profile page has it at the bottom', async () => {
    const page = await admin.get('/profile');
    assert.match(page.text, /id="deleteOpenBtn"/);
    assert.match(page.text, /id="deleteWord"/);
    assert.ok(page.text.indexOf('id="deleteOpenBtn"') > page.text.indexOf('id="signOutBtn"'), 'after sign out');
  });
});
