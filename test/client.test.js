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

test('the site middleware: bearer tokens and unverified people', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());

  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const ticketsKey = (await admin.post('/api/admin/apps', { name: 'tickets' })).data.key;
  const events = (await admin.post('/api/admin/apps', { name: 'events' })).data;
  await admin.patch(`/api/admin/apps/${events.app.id}`, { allowsUnverified: true });
  const ana = browser(server);
  const anaId = (await ana.quickSignUp('ana@example.com', 'Ana', 'Lima')).data.person.id;

  // A site on each key: tickets doesn't allow unverified accounts, events
  // does. No cache, so each request asks.
  async function site(key) {
    const canopy = createCanopyAccount({ url: server.base, key, cacheMs: 0 });
    const app = express();
    app.use(canopy.attach);
    app.get('/who', (req, res) => res.json({ person: req.person, unverified: req.canopyUnverified }));
    app.get('/mine', canopy.requireSignIn, (req, res) => res.send(`hi ${req.person.firstName}`));
    app.get('/api/mine', canopy.requireSignIn, (req, res) => res.json({ ok: true }));
    const listener = await new Promise((resolve) => { const l = app.listen(0, () => resolve(l)); });
    t.after(() => listener.close());
    return { canopy, base: `http://localhost:${listener.address().port}` };
  }
  const tickets = await site(ticketsKey);
  const eventsSite = await site(events.key);
  const who = async (s, headers) => (await fetch(s.base + '/who', { headers })).json();
  const asCookie = (b) => ({ Cookie: `canopy_session=${b.cookie}` });
  const asBearer = (b) => ({ Authorization: `Bearer ${b.cookie}` });

  await t.test('quickSignUpUrl and verifyUrl', () => {
    const req = {};
    assert.equal(tickets.canopy.quickSignUpUrl(req, 'https://events.canopysf.com/e/x'), `${server.base}/?quick=1&return=https%3A%2F%2Fevents.canopysf.com%2Fe%2Fx`);
    assert.equal(tickets.canopy.verifyUrl(req, 'https://events.canopysf.com/e/x'), `${server.base}/profile?verify=1&return=https%3A%2F%2Fevents.canopysf.com%2Fe%2Fx`);
  });

  await t.test('an unverified visitor: nobody on tickets (and told why), themself on events', async () => {
    assert.deepEqual(await who(tickets, asCookie(ana)), { person: null, unverified: true });
    const there = await who(eventsSite, asCookie(ana));
    assert.equal(there.person.id, anaId);
    assert.equal(there.person.emailVerified, false);
    assert.equal(there.unverified, false);
    assert.deepEqual(await who(tickets), { person: null, unverified: false });
  });

  await t.test('requireSignIn sends them to prove their email: pages by redirect, APIs by a 403', async () => {
    const page = await fetch(tickets.base + '/mine', { headers: { ...asCookie(ana), Accept: 'text/html' }, redirect: 'manual' });
    assert.equal(page.status, 302);
    const loc = new URL(page.headers.get('location'));
    assert.equal(loc.origin + loc.pathname, server.base + '/profile');
    assert.equal(loc.searchParams.get('verify'), '1');
    assert.equal(loc.searchParams.get('return'), tickets.base + '/mine');
    const api = await fetch(tickets.base + '/api/mine', { headers: asBearer(ana) });
    assert.equal(api.status, 403);
    const body = await api.json();
    assert.equal(body.reason, 'email_unverified');
    assert.match(body.verify, /\/profile\?verify=1&return=/);
    assert.equal(await (await fetch(eventsSite.base + '/mine', { headers: asCookie(ana) })).text(), 'hi Ana');
  });

  await t.test('a bearer token works like the cookie, and wins over it', async () => {
    assert.equal((await who(tickets, asBearer(admin))).person.firstName, 'Hana');
    assert.equal((await who(tickets, { ...asBearer(admin), ...asCookie(ana) })).person.firstName, 'Hana');
    // One that isn't a session token is nobody, not a fall back to the cookie.
    assert.equal((await who(tickets, { Authorization: 'Bearer nope', ...asCookie(admin) })).person, null);
    // Other schemes are left alone.
    assert.equal((await who(tickets, { Authorization: 'Basic eDp5', ...asCookie(admin) })).person.firstName, 'Hana');
    assert.equal((await fetch(tickets.base + '/api/mine', { headers: asBearer(admin) })).status, 200);
  });

  await t.test('nothing is sent back as Set-Cookie for a bearer request', async () => {
    const db = new (require('better-sqlite3'))(require('path').join(server.dataDir, 'account.db'));
    db.prepare('UPDATE sessions SET cookie_set_at = 0').run();
    db.close();
    const viaBearer = await fetch(tickets.base + '/who', { headers: asBearer(admin) });
    assert.equal(viaBearer.headers.getSetCookie().length, 0);
    // Still due, so the cookie itself is renewed on its next visit.
    const viaCookie = await fetch(tickets.base + '/who', { headers: asCookie(admin) });
    assert.ok(viaCookie.headers.getSetCookie().some((c) => c.startsWith(`canopy_session=${admin.cookie};`)));
  });

  await t.test('once the email is proven, tickets sees them', async () => {
    await ana.post('/api/profile/verify/start');
    assert.equal((await ana.post('/api/profile/verify/check', { code: server.lastCode('ana@example.com') })).status, 200);
    const now = await who(tickets, asCookie(ana));
    assert.equal(now.person.id, anaId);
    assert.equal(now.person.emailVerified, true);
    assert.equal(now.unverified, false);
  });
});
