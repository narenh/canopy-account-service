// Finding someone by their exact phone number or Instagram: who may ask,
// what's matched, what comes back, and the limits.

const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, browser } = require('./harness');

const PUBLIC_KEYS = ['firstName', 'id', 'lastName', 'photoUrl', 'shortName'];

// The usual setup: an admin, events (may look people up) and tickets (may
// not), and Bob, a verified person to ask as.
async function setUp(t) {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const events = (await admin.post('/api/admin/apps', { name: 'events' })).data;
  const switched = await admin.patch(`/api/admin/apps/${events.app.id}`, { allowsLookup: true, allowsUnverified: true });
  assert.equal(switched.data.app.allowsLookup, true);
  const tickets = (await admin.post('/api/admin/apps', { name: 'tickets' })).data;
  const bob = browser(server);
  await bob.signUp('bob@example.com', 'Bob', 'Bell');
  const lookup = (site, asker, query, headers = {}) => browser(server).get(`/api/people/lookup?${query}`, {
    headers: { Authorization: `Bearer ${site.key}`, ...(asker ? { 'X-Canopy-Session': asker.cookie } : {}), ...headers }
  });
  return { server, admin, events, tickets, bob, lookup };
}

test('finding someone by phone or Instagram', async (t) => {
  const { server, events, tickets, bob, lookup } = await setUp(t);
  const ana = browser(server);
  const anaId = (await ana.signUp('ana@example.com', 'Ana', 'Lima')).data.person.id;
  const r = await ana.patch('/api/profile', { firstName: 'Ana', lastName: 'Lima', phone: '415 555 1234', instagram: '@Ana.Lima', venmoHandle: 'ana-v', cashapp: '$AnaL' });
  assert.equal(r.data.person.findable, true, 'findable unless they turn it off');

  await t.test('only a site allowed to, for a signed-in visitor with a proven email', async () => {
    const off = await lookup(tickets, bob, 'phone=4155551234');
    assert.equal(off.status, 403);
    assert.equal(off.data.reason, 'lookup_not_allowed');
    assert.equal((await browser(server).get('/api/people/lookup?phone=4155551234')).status, 401, 'no site key');
    const nobody = await lookup(events, null, 'phone=4155551234');
    assert.equal(nobody.status, 401);
    assert.equal(nobody.data.reason, 'signed_out');
    // A quick sign-up can't ask, even on a site that lets them in.
    const quinn = browser(server);
    await quinn.quickSignUp('quinn@example.com', 'Quinn', 'Quick');
    const unverified = await lookup(events, quinn, 'phone=4155551234');
    assert.equal(unverified.status, 403);
    assert.equal(unverified.data.reason, 'email_unverified');
  });

  await t.test('a phone number, however it is typed, the way the profile reads it', async () => {
    for (const phone of ['(415) 555-1234', '1 415.555.1234', '+14155551234', '415 555 1234']) {
      const found = await lookup(events, bob, 'phone=' + encodeURIComponent(phone));
      assert.equal(found.status, 200, phone);
      assert.equal(found.data.person.id, anaId, phone);
      assert.deepEqual(Object.keys(found.data.person).sort(), PUBLIC_KEYS, 'the public shape and nothing else');
    }
    assert.deepEqual((await lookup(events, bob, 'phone=4155551235')).data, { person: null });
    // Never a prefix: part of a number isn't a number.
    assert.equal((await lookup(events, bob, 'phone=415555123')).data.reason, 'bad_phone');
    assert.equal((await lookup(events, bob, 'phone=')).data.reason, 'bad_phone');
  });

  await t.test('an Instagram username, with or without the @ or the link, exactly', async () => {
    for (const handle of ['ana.lima', '@Ana.Lima', 'https://www.instagram.com/ana.lima/']) {
      assert.equal((await lookup(events, bob, 'instagram=' + encodeURIComponent(handle))).data.person.id, anaId, handle);
    }
    for (const handle of ['ana', 'ana.lim', 'ana.lima_']) {
      assert.deepEqual((await lookup(events, bob, 'instagram=' + encodeURIComponent(handle))).data, { person: null }, handle);
    }
    assert.equal((await lookup(events, bob, 'instagram=' + encodeURIComponent('ana lima'))).data.reason, 'bad_instagram');
  });

  await t.test('one of phone or instagram, not both or neither', async () => {
    assert.equal((await lookup(events, bob, '')).data.reason, 'one_of');
    assert.equal((await lookup(events, bob, 'phone=4155551234&instagram=ana.lima')).data.reason, 'one_of');
    assert.equal((await lookup(events, bob, 'phone=4155551234&phone=4155551234')).data.reason, 'one_of');
  });

  await t.test('unverified accounts are found by Instagram, by phone only once their email is proven', async () => {
    const q = browser(server);
    const made = await q.quickSignUp('quincy@example.com', 'Quincy', 'Quick');
    await q.patch('/api/profile', { firstName: 'Quincy', lastName: 'Quick', instagram: 'quincy.q', phone: '415 555 9876' });
    assert.equal((await lookup(events, bob, 'instagram=quincy.q')).data.person.id, made.data.person.id);
    assert.deepEqual((await lookup(events, bob, 'phone=4155559876')).data, { person: null });
    // Proving the email (here, from the profile) makes the phone findable too.
    await q.post('/api/profile/verify/start');
    assert.equal((await q.post('/api/profile/verify/check', { code: server.lastCode('quincy@example.com') })).status, 200);
    assert.equal((await lookup(events, bob, 'phone=4155559876')).data.person.id, made.data.person.id);
  });

  // The reviewer's case: someone makes a quick account (nothing proven)
  // with a friend's name and their phone or Instagram, so that a host
  // looking the friend up finds the impostor and invites them. By phone
  // they never are. By Instagram they are, until the real owner claims
  // the handle too (an accepted cost, see the README).
  await t.test("an impostor's quick account: never by phone, by Instagram only while uncontested", async () => {
    const zed = browser(server);
    await zed.signUp('zed@example.com', 'Zed', 'Zane');
    // Zed hasn't put his phone in yet: the impostor's would be the only
    // claim, and is still not found.
    const imp = browser(server);
    await imp.quickSignUp('zed.zane@nowhere.invalid', 'Zed', 'Zane');
    await imp.patch('/api/profile', { firstName: 'Zed', lastName: 'Zane', phone: '415 555 4444', instagram: 'zed.zane' });
    assert.deepEqual((await lookup(events, bob, 'phone=4155554444')).data, { person: null });
    assert.equal((await lookup(events, bob, 'instagram=zed.zane')).data.person.lastName, 'Zane');
    // Once Zed has them too, the claim is contested and nobody is found:
    // the impostor can hide him, but never stand in for him.
    await zed.patch('/api/profile', { firstName: 'Zed', lastName: 'Zane', phone: '415 555 4444', instagram: 'zed.zane' });
    assert.deepEqual((await lookup(events, bob, 'phone=4155554444')).data, { person: null });
    assert.deepEqual((await lookup(events, bob, 'instagram=zed.zane')).data, { person: null });
  });

  await t.test('nobody who turned it off', async () => {
    const off = await ana.patch('/api/profile', { firstName: 'Ana', lastName: 'Lima', findable: false });
    assert.equal(off.data.person.findable, false);
    assert.deepEqual((await lookup(events, bob, 'phone=4155551234')).data, { person: null });
    assert.deepEqual((await lookup(events, bob, 'instagram=ana.lima')).data, { person: null });
    // Saving the profile without it leaves it as it was.
    assert.equal((await ana.patch('/api/profile', { firstName: 'Ana', lastName: 'Lima' })).data.person.findable, false);
    await ana.patch('/api/profile', { firstName: 'Ana', lastName: 'Lima', findable: true });
    assert.equal((await lookup(events, bob, 'phone=4155551234')).data.person.id, anaId);
  });

  await t.test('nobody when two accounts claim the same one', async () => {
    const copycat = browser(server);
    await copycat.signUp('copy@example.com', 'Copy', 'Cat');
    await copycat.patch('/api/profile', { firstName: 'Copy', lastName: 'Cat', instagram: 'ana.lima' });
    assert.deepEqual((await lookup(events, bob, 'instagram=ana.lima')).data, { person: null });
    // Her phone is still hers alone.
    assert.equal((await lookup(events, bob, 'phone=4155551234')).data.person.id, anaId);
  });
});

test('lookup limits', async (t) => {
  const { server, events, lookup } = await setUp(t);
  let n = 0;
  const asker = async () => {
    const b = browser(server);
    await b.signUp(`asker${++n}@example.com`, 'Ask', 'Er');
    return b;
  };
  const from = (ip) => ({ 'X-Canopy-Visitor-Ip': ip });

  await t.test('30 an hour per asker, found or not', async () => {
    const a = await asker();
    for (let i = 0; i < 30; i++) assert.equal((await lookup(events, a, `phone=41555500${String(i).padStart(2, '0')}`, from('10.0.0.1'))).status, 200);
    const r = await lookup(events, a, 'phone=4155559999', from('10.0.0.1'));
    assert.equal(r.status, 429);
    assert.equal(r.data.reason, 'rate_limited');
    assert.equal((await lookup(events, await asker(), 'phone=4155559999', from('10.0.0.2'))).status, 200, 'someone else is fine');
  });

  await t.test('60 an hour per address', async () => {
    for (const a of [await asker(), await asker()]) {
      for (let i = 0; i < 30; i++) assert.equal((await lookup(events, a, 'instagram=nobody.here', from('10.0.1.1'))).status, 200);
    }
    const c = await asker();
    assert.equal((await lookup(events, c, 'instagram=nobody.here', from('10.0.1.1'))).status, 429);
    assert.equal((await lookup(events, c, 'instagram=nobody.here', from('10.0.1.2'))).status, 200);
  });

  await t.test('300 an hour across everyone', async () => {
    // 30 + 1 + 60 + 1 so far; fill the rest from fresh askers and addresses.
    let used = 92;
    while (used < 300) {
      const a = await asker();
      const ip = `10.0.2.${n}`;
      for (let i = 0; i < 30 && used < 300; i++, used++) assert.equal((await lookup(events, a, 'instagram=nobody.here', from(ip))).status, 200);
    }
    assert.equal((await lookup(events, await asker(), 'instagram=nobody.here', from('10.0.3.1'))).status, 429);
  });
});
