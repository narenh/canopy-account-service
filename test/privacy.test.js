// Contact details never leak: everything another person or a site can get
// about someone, walked for any of their email, phone, Instagram, Venmo or
// Cash App, from a browser and from an app. Only the person themself
// (/api/me, /api/native/v1/me, /api/session as them) and the admin ever
// see those.

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { startServer, browser, nativeApp } = require('./harness');
const createCanopyAccount = require('../client/canopy-account');

// Every string anywhere in a JSON value.
function strings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => strings(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => strings(v, out));
  return out;
}

test("one person's contact details never reach another person or a site", async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const site = (await admin.post('/api/admin/apps', { name: 'events' })).data;
  await admin.patch(`/api/admin/apps/${site.app.id}`, { allowsLookup: true, allowsUnverified: true });

  const ana = browser(server);
  const anaId = (await ana.signUp('ana.secret@example.com', 'Ana', 'Lima')).data.person.id;
  await ana.patch('/api/profile', {
    firstName: 'Ana', lastName: 'Lima', phone: '415 555 1234', instagram: 'ana.secret', venmoHandle: 'ana-venmo-secret', cashapp: 'AnaCashSecret'
  });
  const secrets = ['ana.secret@example.com', '+14155551234', '4155551234', 'ana.secret', 'ana-venmo-secret', 'anacashsecret'];

  const bob = browser(server);
  await bob.signUp('bob@example.com', 'Bob', 'Bell');
  const quinn = browser(server);
  await quinn.quickSignUp('quinn@example.com', 'Quinn', 'Quick');
  // Bob in the app too, and a quick sign-up made in an app.
  const bobApp = nativeApp(server);
  bobApp.authenticator.creds.push(...bob.authenticator.creds);
  await bobApp.signInWithPasskey();
  const quinnApp = nativeApp(server, { platform: 'android' });
  await quinnApp.quickSignUp('quinn.app@example.com', 'Quinn', 'App');
  // Ana is in an app as well, so there's an app session of hers to leak.
  const anaApp = nativeApp(server);
  anaApp.authenticator.creds.push(...ana.authenticator.creds);
  await anaApp.signInWithPasskey();
  const strangerApp = nativeApp(server);
  await strangerApp.begin();
  const asSite = (asker) => ({ headers: { Authorization: `Bearer ${site.key}`, ...(asker ? { 'X-Canopy-Session': asker.cookie } : {}) } });

  // Everything Bob, Quinn, a stranger or the site can ask that could
  // mention Ana.
  const answers = {
    'bob /api/me': await bob.get('/api/me'),
    'bob /api/session': await browser(server).get('/api/session', asSite(bob)),
    'quinn /api/session': await browser(server).get('/api/session', asSite(quinn)),
    '/api/people': await browser(server).get(`/api/people?ids=${anaId}`, asSite()),
    'lookup by phone': await browser(server).get('/api/people/lookup?phone=4155551234', asSite(bob)),
    'lookup by instagram': await browser(server).get('/api/people/lookup?instagram=ana.secret', asSite(bob)),
    'quinn lookup': await browser(server).get('/api/people/lookup?phone=4155551234', asSite(quinn)),
    'bob profile save': await bob.patch('/api/profile', { firstName: 'Bob', lastName: 'Bell' }),
    'bob passkeys': await bob.get('/api/profile/passkeys'),
    'stranger auth state': await browser(server).get('/api/auth/state'),
    'stranger code start': await browser(server).post('/api/auth/email/start', { email: 'someone@example.com' }),
    'bob /api/admin/people': await bob.get('/api/admin/people'),
    'setup link': await browser(server).get('/api/setup/' + (await admin.post(`/api/admin/people/${anaId}/setup-link`)).data.setupUrl.split('/setup/')[1]),
    // The apps.
    'bob app /me': await bobApp.get('/me'),
    'bob app profile save': await bobApp.patch('/me', { firstName: 'Bob', lastName: 'Bell' }),
    'bob app passkeys': await bobApp.get('/me/passkeys'),
    'bob app sessions': await bobApp.get('/me/sessions'),
    'bob app /api/session': await browser(server).get('/api/session', { headers: { Authorization: `Bearer ${site.key}`, 'X-Canopy-Session': bobApp.token } }),
    'bob app lookup': await browser(server).get('/api/people/lookup?phone=4155551234', { headers: { Authorization: `Bearer ${site.key}`, 'X-Canopy-Session': bobApp.token } }),
    'bob app verify start': await bobApp.post('/me/verify/start'),
    'quinn app /me': await quinnApp.get('/me'),
    'quinn app sessions': await quinnApp.get('/me/sessions'),
    'stranger app passkey options': await strangerApp.post('/auth/passkey/options'),
    'stranger app code start': await strangerApp.post('/auth/email/start', { email: 'someone@example.com' }),
    'stranger app /me': await strangerApp.get('/me'),
    'stranger app begin': await nativeApp(server).post('/auth/begin', { platform: 'ios' }),
    'openapi.yaml': { data: (await nativeApp(server).get('/openapi.yaml')).text }
  };
  assert.equal(answers['lookup by phone'].data.person.id, anaId, 'the lookup did find her');
  assert.equal(answers['bob /api/admin/people'].status, 401);
  assert.equal(answers['bob app lookup'].data.person.id, anaId, 'the lookup found her from the app too');
  assert.equal(answers['stranger app /me'].status, 401);
  // Bob's list of where he's signed in is his alone: none of Ana's.
  const anaSessions = (await anaApp.get('/me/sessions')).data.sessions.map((x) => x.id);
  assert.equal(anaSessions.length, 2);
  assert.ok(!answers['bob app sessions'].data.sessions.some((x) => anaSessions.includes(x.id)));
  for (const [what, r] of Object.entries(answers)) {
    const found = strings(r.data).map((v) => v.toLowerCase()).filter((v) => secrets.some((x) => v.includes(x)));
    assert.deepEqual(found, [], `${what} carries Ana's contact details`);
  }
  // The public shape, exactly.
  const shape = ['firstName', 'id', 'lastName', 'photoUrl', 'shortName'];
  assert.deepEqual(Object.keys(answers['/api/people'].data.people[0]).sort(), shape);
  assert.deepEqual(Object.keys(answers['lookup by phone'].data.person).sort(), shape);
  assert.deepEqual(Object.keys(answers['bob app lookup'].data.person).sort(), shape);

  // And through the client file, as a site uses it.
  const canopy = createCanopyAccount({ url: server.base, key: site.key, cacheMs: 0 });
  const app = express();
  app.get('/p', async (req, res) => res.json({
    people: Object.fromEntries(await canopy.people([anaId])),
    byPhone: await canopy.lookup(req, { phone: '(415) 555-1234' }),
    byInstagram: await canopy.lookup(req, { instagram: '@Ana.Secret' })
  }));
  app.get('/q', async (req, res) => {
    try { await canopy.lookup(req, { phone: '4155551234' }); res.json({}); } catch (err) { res.status(err.status).json({ reason: err.reason }); }
  });
  const listener = await new Promise((resolve) => { const l = app.listen(0, () => resolve(l)); });
  t.after(() => listener.close());
  const base = `http://localhost:${listener.address().port}`;
  const viaClient = await (await fetch(base + '/p', { headers: { Cookie: `canopy_session=${bob.cookie}` } })).json();
  assert.equal(viaClient.byPhone.id, anaId);
  assert.equal(viaClient.byInstagram.id, anaId);
  assert.deepEqual(strings(viaClient).filter((v) => secrets.some((x) => v.toLowerCase().includes(x))), []);
  // The client's errors carry the reason.
  assert.deepEqual(await (await fetch(base + '/q', { headers: { Authorization: `Bearer ${quinn.cookie}` } })).json(), { reason: 'email_unverified' });
  assert.deepEqual(await (await fetch(base + '/q')).json(), { reason: 'signed_out' });
});
