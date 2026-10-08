// The lookup log: every lookup written down, found or not and refused or
// not, with what was looked for only as a keyed hash; old entries pruned;
// a warning (and the admin's Lookups tab) when an asker or an address
// misses too much.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Database = require('better-sqlite3');
const { init, LOOKUP_LOG_TTL_MS } = require('../lib/db');
const { createContactCrypto } = require('../lib/contactCrypto');
const { startServer, browser } = require('./harness');

async function setUp(t) {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const events = (await admin.post('/api/admin/apps', { name: 'events' })).data;
  await admin.patch(`/api/admin/apps/${events.app.id}`, { allowsLookup: true, allowsUnverified: true });
  const tickets = (await admin.post('/api/admin/apps', { name: 'tickets' })).data;
  const lookup = (site, asker, body, ip = '198.51.100.7') => browser(server).post('/api/people/lookup', body, {
    headers: { Authorization: `Bearer ${site.key}`, Origin: null, 'X-Canopy-Visitor-Ip': ip, ...(asker ? { 'X-Canopy-Session': asker.cookie } : {}) }
  });
  // The server's own database, read as it is on disk.
  const log = () => {
    const db = new Database(path.join(server.dataDir, 'account.db'), { readonly: true });
    try { return db.prepare('SELECT * FROM lookup_log ORDER BY id').all(); } finally { db.close(); }
  };
  return { server, admin, events, tickets, lookup, log };
}

test('every lookup is written down, and nothing it looked for is', async (t) => {
  const { server, events, tickets, lookup, log } = await setUp(t);
  const ana = browser(server);
  const anaId = (await ana.signUp('ana@example.com', 'Ana', 'Lima')).data.person.id;
  await ana.patch('/api/profile', { firstName: 'Ana', lastName: 'Lima', phone: '415 555 2468', instagram: 'ana.lookup.target' });
  const bob = browser(server);
  const bobId = (await bob.signUp('bob@example.com', 'Bob', 'Bell')).data.person.id;
  const quinn = browser(server);
  const quinnId = (await quinn.quickSignUp('quinn@example.com', 'Quinn', 'Quick')).data.person.id;

  // Every path: found, missed, and each refusal.
  assert.equal((await lookup(events, bob, { phone: '(415) 555-2468' })).data.person.id, anaId);
  assert.deepEqual((await lookup(events, bob, { instagram: 'nobody.there' })).data, { person: null });
  assert.equal((await lookup(tickets, bob, { phone: '4155552468' })).data.reason, 'lookup_not_allowed');
  assert.equal((await lookup(events, null, { phone: '4155552468' })).data.reason, 'signed_out');
  assert.equal((await lookup(events, quinn, { phone: '4155552468' })).data.reason, 'email_unverified');
  assert.equal((await lookup(events, bob, { phone: '4155552468', instagram: 'ana.lookup.target' })).data.reason, 'one_of');
  assert.equal((await lookup(events, bob, { phone: '555' })).data.reason, 'bad_phone');
  assert.equal((await lookup(events, bob, { instagram: 'not valid!' })).data.reason, 'bad_instagram');

  const rows = log();
  const shape = (r) => ({ asker: r.asker_id, kind: r.kind, matched: r.matched, refused: r.refused, target: !!r.target_hash });
  assert.deepEqual(rows.map(shape), [
    { asker: bobId, kind: 'phone', matched: 1, refused: null, target: true },
    { asker: bobId, kind: 'instagram', matched: 0, refused: null, target: true },
    { asker: bobId, kind: null, matched: 0, refused: 'lookup_not_allowed', target: false },
    { asker: null, kind: null, matched: 0, refused: 'signed_out', target: false },
    { asker: quinnId, kind: null, matched: 0, refused: 'email_unverified', target: false },
    { asker: bobId, kind: null, matched: 0, refused: 'one_of', target: false },
    { asker: bobId, kind: 'phone', matched: 0, refused: 'bad_phone', target: false },
    { asker: bobId, kind: 'instagram', matched: 0, refused: 'bad_instagram', target: false }
  ]);
  assert.deepEqual(rows.map((r) => r.site_id), [events.app.id, events.app.id, tickets.app.id, ...Array(5).fill(events.app.id)]);
  assert.ok(rows.every((r) => r.at > Date.now() - 60 * 1000));
  // The target is the same keyed hash the lookup column has, so equal
  // targets are equal entries, and that's all that can be told.
  const db = new Database(path.join(server.dataDir, 'account.db'), { readonly: true });
  const anaRow = db.prepare('SELECT phone_hash FROM people WHERE id = ?').get(anaId);
  db.close();
  assert.equal(rows[0].target_hash, anaRow.phone_hash);
  // The address is a keyed hash too, the same for the same address.
  assert.ok(rows.every((r) => r.address_hash && r.address_hash === rows[0].address_hash));
  await lookup(events, bob, { instagram: 'nobody.there' }, '203.0.113.99');
  assert.notEqual(log().at(-1).address_hash, rows[0].address_hash);

  // No plain-text target, or address, anywhere in the file or the server's output.
  const raw = ['', '-wal'].map((x) => {
    const f = path.join(server.dataDir, 'account.db' + x);
    return fs.existsSync(f) ? fs.readFileSync(f).toString('latin1') : '';
  }).join('');
  for (const plain of ['4155552468', '415) 555-2468', 'ana.lookup.target', 'nobody.there', '198.51.100.7', '203.0.113.99']) {
    assert.ok(!raw.includes(plain), `${plain} is in account.db`);
    assert.ok(!server.output().includes(plain), `${plain} is in the log output`);
  }
});

test("refusals before the limits can't fill the disk", async (t) => {
  const { server, tickets, lookup, log } = await setUp(t);
  const bob = browser(server);
  await bob.signUp('bob@example.com', 'Bob', 'Bell');
  for (let i = 0; i < 35; i++) assert.equal((await lookup(tickets, bob, { phone: '4155550000' })).status, 403);
  assert.equal(log().length, 30, '30 an hour per asker are written down');
});

test('a warning, once, when someone misses too much; and the admin sees them', async (t) => {
  const { server, admin, events, lookup } = await setUp(t);
  const ana = browser(server);
  await ana.signUp('ana@example.com', 'Ana', 'Lima');
  await ana.patch('/api/profile', { firstName: 'Ana', lastName: 'Lima', phone: '415 555 2468' });
  const eve = browser(server);
  const eveId = (await eve.signUp('eve@example.com', 'Eve', 'Enum')).data.person.id;
  const host = browser(server);
  const hostId = (await host.signUp('kim@example.com', 'Kim', 'Host')).data.person.id;
  const alerts = () => server.output().split('\n').filter((l) => l.includes('lookup alert'));

  // A host who finds a friend, misses a few, finds another: fine.
  await lookup(events, host, { phone: '4155552468' }, '192.0.2.1');
  for (let i = 0; i < 5; i++) await lookup(events, host, { phone: `41555530${String(i).padStart(2, '0')}` }, '192.0.2.1');
  await lookup(events, host, { phone: '4155552468' }, '192.0.2.1');

  // Someone working down a list: 9 misses in a row is still nothing...
  for (let i = 0; i < 9; i++) await lookup(events, eve, { phone: `41555540${String(i).padStart(2, '0')}` }, '192.0.2.2');
  await new Promise((r) => setTimeout(r, 100));
  assert.deepEqual(alerts(), []);
  // ...the 10th says so, for her and for her address.
  await lookup(events, eve, { phone: '4155554009' }, '192.0.2.2');
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(alerts().length, 2, alerts().join('\n'));
  assert.ok(alerts().some((l) => l.includes(`asker ${eveId}`) && l.includes('10 misses in a row') && l.includes('site events')));
  assert.ok(alerts().some((l) => /address #[A-Za-z0-9_-]{12} /.test(l)));
  // Once a day: more misses don't say it again.
  for (let i = 10; i < 15; i++) await lookup(events, eve, { phone: `41555540${i}` }, '192.0.2.2');
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(alerts().length, 2);
  assert.ok(!alerts().some((l) => /4155554/.test(l)), 'never the numbers');

  // The admin's Lookups: Eve first, marked, with counts and no targets.
  assert.equal((await eve.get('/api/admin/lookups')).status, 401, 'admin only');
  const page = (await admin.get('/api/admin/lookups')).data;
  assert.equal(page.askers[0].personId, eveId);
  assert.equal(page.askers[0].name, 'Eve Enum');
  assert.deepEqual(page.askers[0].sites, ['events']);
  assert.equal(page.askers[0].lookups, 15);
  assert.equal(page.askers[0].missed, 15);
  assert.ok(page.askers[0].concerns.some((c) => /misses in a row/.test(c)));
  const kim = page.askers.find((a) => a.personId === hostId);
  assert.deepEqual([kim.lookups, kim.found, kim.missed, kim.concerns], [7, 2, 5, []]);
  assert.equal(page.addresses.length, 1, 'only the address that looks wrong');
  assert.match(page.addresses[0].address, /^[A-Za-z0-9_-]{12}$/);
  assert.ok(!JSON.stringify(page).includes('4155554'), 'no targets');
  assert.ok(!JSON.stringify(page).includes('192.0.2'), 'no addresses');
  assert.match((await admin.get('/admin')).text, /id="lookupList"/);
});

test('entries older than 90 days are pruned, daily and at startup', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-lookup-log-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'account.db');
  const contactCrypto = createContactCrypto({ keys: [{ id: 'k1', key: Buffer.alloc(32, 1) }], hmacKey: Buffer.alloc(32, 2) });
  const store = init({ file, snapshots: false, contactCrypto });
  store.logLookup({ askerId: 'a', siteId: 's', kind: 'phone', targetHash: 'h', matched: false });
  const insert = store.db.prepare("INSERT INTO lookup_log (at, asker_id, site_id) VALUES (?, 'old', 's')");
  insert.run(Date.now() - LOOKUP_LOG_TTL_MS - 1000);
  insert.run(Date.now() - LOOKUP_LOG_TTL_MS + 60 * 1000);
  assert.equal(store.pruneLookupLog(), 1, 'just the one past 90 days');
  assert.equal(store.db.prepare('SELECT COUNT(*) AS n FROM lookup_log').get().n, 2);
  insert.run(Date.now() - LOOKUP_LOG_TTL_MS - 1000);
  store.db.close();
  // Opening it again prunes (the daily run starts at startup).
  const again = init({ file, snapshots: false, contactCrypto });
  assert.equal(again.db.prepare('SELECT COUNT(*) AS n FROM lookup_log').get().n, 2);
  again.db.close();
});
