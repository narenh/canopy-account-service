// /api/people and everyone's Venmo and Cash App: only for a site the admin
// has switched on, only the ones it's granted, and never anything else.

const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, browser } = require('./harness');

test("a site switched on sees everyone's granted payment handles, and nothing more", async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const site = (await admin.post('/api/admin/apps', { name: 'tickets' })).data;
  const other = (await admin.post('/api/admin/apps', { name: 'events' })).data;

  const ana = browser(server);
  const anaId = (await ana.signUp('ana@example.com', 'Ana', 'Lima')).data.person.id;
  await ana.patch('/api/profile', {
    firstName: 'Ana', lastName: 'Lima', phone: '415 555 1234', instagram: 'ana.l', venmoHandle: 'ana-old', cashapp: 'AnaCash'
  });
  const bob = browser(server);
  const bobId = (await bob.signUp('bob@example.com', 'Bob', 'Bell')).data.person.id;

  const people = async (s) => (await browser(server).get(`/api/people?ids=${anaId},${bobId}`, {
    headers: { Authorization: `Bearer ${s.key}` }
  })).data.people;
  const byId = (list, id) => list.find((p) => p.id === id);

  // Off by default, even with Venmo granted for the visitor.
  await admin.patch(`/api/admin/apps/${site.app.id}`, { contactFields: ['venmo'] });
  assert.equal('venmo' in byId(await people(site), anaId), false);

  // On: Venmo, because it's granted; not Cash App, which isn't.
  const on = await admin.patch(`/api/admin/apps/${site.app.id}`, { allowsPaymentHandles: true });
  assert.equal(on.data.app.allowsPaymentHandles, true);
  let list = await people(site);
  assert.equal(byId(list, anaId).venmo, 'ana-old');
  assert.equal('cashapp' in byId(list, anaId), false);
  // Granted but not filled in is null, as in /api/session.
  assert.equal(byId(list, bobId).venmo, null);

  // A change shows up on the next ask.
  await ana.patch('/api/profile', { firstName: 'Ana', lastName: 'Lima', venmoHandle: 'ana-new' });
  assert.equal(byId(await people(site), anaId).venmo, 'ana-new');

  // Even with every field granted, only the two payment handles go.
  await admin.patch(`/api/admin/apps/${site.app.id}`, { contactFields: ['email', 'phone', 'instagram', 'venmo', 'cashapp'] });
  const ana2 = byId(await people(site), anaId);
  assert.deepEqual(Object.keys(ana2).sort(), ['cashapp', 'firstName', 'id', 'lastName', 'photoUrl', 'shortName', 'venmo']);
  assert.equal(ana2.cashapp, 'AnaCash');

  // Another site, not switched on, still gets names and photos only.
  await admin.patch(`/api/admin/apps/${other.app.id}`, { contactFields: ['venmo', 'cashapp'] });
  assert.deepEqual(Object.keys(byId(await people(other), anaId)).sort(), ['firstName', 'id', 'lastName', 'photoUrl', 'shortName']);

  // Switched back off, they're gone again.
  await admin.patch(`/api/admin/apps/${site.app.id}`, { allowsPaymentHandles: false });
  assert.equal('venmo' in byId(await people(site), anaId), false);
});
