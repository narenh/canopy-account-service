// client/canopy-account.js, the file sites copy in, against the real
// server: req.person, requireSignIn's redirect, people(), the minute's
// cache, and the cookie renewal it passes on.

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { startServer, browser } = require('./harness');
const createCanopyAccount = require('../client/canopy-account');

test('the site middleware', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());

  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  const made = await admin.signUp('host@example.com', 'Hana', 'Host');
  assert.equal(made.status, 201);
  const key = (await admin.post('/api/admin/apps', { name: 'tickets' })).data.key;

  const canopy = createCanopyAccount({ url: server.base, key, cacheMs: 200 });
  const site = express();
  site.use(canopy.attach);
  site.get('/who', (req, res) => res.json({ person: req.person }));
  site.get('/mine', canopy.requireSignIn, (req, res) => res.send(`hi ${req.person.firstName}`));
  site.get('/api/mine', canopy.requireSignIn, (req, res) => res.json({ ok: true }));
  site.get('/people', async (req, res) => res.json(Object.fromEntries(await canopy.people(String(req.query.ids).split(',')))));
  const listener = await new Promise((resolve) => { const l = site.listen(0, () => resolve(l)); });
  t.after(() => listener.close());
  const siteBase = `http://localhost:${listener.address().port}`;
  const cookie = `canopy_session=${admin.cookie}`;

  await t.test('req.person is the visitor, or null', async () => {
    const me = await (await fetch(siteBase + '/who', { headers: { Cookie: cookie } })).json();
    assert.equal(me.person.firstName, 'Hana');
    const nobody = await (await fetch(siteBase + '/who')).json();
    assert.equal(nobody.person, null);
  });

  await t.test('requireSignIn: pages go to sign in and back, APIs get a 401', async () => {
    const page = await fetch(siteBase + '/mine', { headers: { Accept: 'text/html' }, redirect: 'manual' });
    assert.equal(page.status, 302);
    const loc = new URL(page.headers.get('location'));
    assert.equal(loc.origin, server.base);
    assert.equal(loc.searchParams.get('return'), siteBase + '/mine');
    assert.equal((await fetch(siteBase + '/api/mine')).status, 401);
    assert.equal(await (await fetch(siteBase + '/mine', { headers: { Cookie: cookie } })).text(), 'hi Hana');
  });

  await t.test('people(): names and photos by id, the missing left out', async () => {
    const id = made.data.person.id;
    const ppl = await (await fetch(`${siteBase}/people?ids=${id},00000000-0000-0000-0000-000000000000`)).json();
    assert.deepEqual(Object.keys(ppl), [id]);
    assert.equal(ppl[id].shortName, 'Hana H');
  });

  await t.test('a cookie due for renewal is renewed by the site', async () => {
    const Database = require('better-sqlite3');
    const db = new Database(require('path').join(server.dataDir, 'account.db'));
    db.prepare('UPDATE sessions SET cookie_set_at = 0').run();
    db.close();
    await new Promise((r) => setTimeout(r, 250));
    const res = await fetch(siteBase + '/who', { headers: { Cookie: cookie } });
    const set = res.headers.getSetCookie().find((c) => c.startsWith('canopy_session='));
    assert.ok(set, 'a Set-Cookie came back');
    assert.ok(set.startsWith(`canopy_session=${admin.cookie};`));
    assert.match(set, /Max-Age=31536000/);
    assert.match(set, /HttpOnly/);
    // Once is enough: the next answer doesn't renew it again.
    await new Promise((r) => setTimeout(r, 250));
    const again = await fetch(siteBase + '/who', { headers: { Cookie: cookie } });
    assert.equal(again.headers.getSetCookie().length, 0);
  });

  await t.test('a sign-out shows once the cache has run out', async () => {
    assert.ok((await (await fetch(siteBase + '/who', { headers: { Cookie: cookie } })).json()).person);
    await admin.post('/api/signout');
    await new Promise((r) => setTimeout(r, 250));
    assert.equal((await (await fetch(siteBase + '/who', { headers: { Cookie: cookie } })).json()).person, null);
  });
});
