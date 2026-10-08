// A database from an earlier schema is brought up to date on open, and
// keeps what it had.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Database = require('better-sqlite3');
const { init, SCHEMA_VERSION, FINDABLE_BY_DEFAULT } = require('../lib/db');

test('a version 1 database is brought up to date', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-schema-test-'));
  const file = path.join(dir, 'account.db');
  try {
    // Make a version 1 database: today's, without what versions 2 and up added.
    init({ file, snapshots: false }).db.close();
    const old = new Database(file);
    old.exec('DROP INDEX people_phone');
    old.exec('DROP INDEX people_instagram');
    ['phone', 'instagram', 'cashapp'].forEach((c) => old.exec(`ALTER TABLE people DROP COLUMN ${c}`));
    old.exec('ALTER TABLE sessions DROP COLUMN reauth_at');
    old.exec('ALTER TABLE apps DROP COLUMN allows_unverified');
    old.exec('ALTER TABLE apps DROP COLUMN allows_lookup');
    old.exec('ALTER TABLE people DROP COLUMN findable');
    ['client_kind', 'client_name', 'signed_in_at'].forEach((c) => old.exec(`ALTER TABLE sessions DROP COLUMN ${c}`));
    old.exec('ALTER TABLE apps DROP COLUMN contact_fields');
    // p1's email was proven; p2's was changed by the admin (null), which
    // before version 5 changed nothing.
    old.prepare("INSERT INTO people (id, email, first_name, last_name, email_verified_at, created_at, updated_at) VALUES ('p1', 'a@b.co', 'A', 'B', 5, 1, 1)").run();
    old.prepare("INSERT INTO people (id, email, first_name, last_name, created_at, updated_at) VALUES ('p2', 'c@d.co', 'C', 'D', 1, 7)").run();
    old.prepare("INSERT INTO apps (id, name, key_hash, created_at) VALUES ('a1', 'tickets', 'h', 1)").run();
    // A browser signed in as p1, and one that never signed in.
    const now = Date.now();
    old.prepare("INSERT INTO sessions (id_hash, person_id, created_at, last_seen_at, cookie_set_at) VALUES ('s1', 'p1', ?, ?, ?)").run(now - 1000, now, now);
    old.prepare("INSERT INTO sessions (id_hash, created_at, last_seen_at, cookie_set_at) VALUES ('s2', ?, ?, ?)").run(now, now, now);
    old.pragma('user_version = 1');
    old.close();

    const store = init({ file, snapshots: false });
    assert.equal(store.db.pragma('user_version', { simple: true }), SCHEMA_VERSION);
    assert.equal(store.getPerson('p1').phone, null);
    assert.equal(store.setPersonPhone('p1', '+14155551234').phone, '+14155551234');
    assert.equal(store.setPersonInstagram('p1', 'ana.l').instagram, 'ana.l');
    assert.equal(store.setPersonCashapp('p1', 'AnaL').cashapp, 'AnaL');
    assert.ok(store.db.prepare("SELECT 1 FROM pragma_table_info('sessions') WHERE name = 'reauth_at'").get());
    // Everyone already here counts as verified; sites start closed to
    // unverified accounts.
    assert.equal(store.getPerson('p1').emailVerifiedAt, 5);
    assert.equal(store.getPerson('p2').emailVerifiedAt, 7);
    assert.equal(store.listApps()[0].allowsUnverified, false);
    assert.equal(store.setAppSettings('a1', { allowsUnverified: true }).allowsUnverified, true);
    // Version 6: everyone gets the findable default; no site may look up.
    assert.equal(store.getPerson('p1').findable, FINDABLE_BY_DEFAULT);
    assert.equal(store.listApps()[0].allowsLookup, false);
    assert.ok(store.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'people_phone'").get());
    store.setPersonPhone('p1', '+14155551234');
    assert.equal(store.findPerson({ phone: '+14155551234' }).id, 'p1');
    // Version 7: every signed-in session already here is a browser's,
    // signed in when it started.
    const [s1] = store.sessionsOf('p1');
    assert.equal(s1.clientKind, 'web');
    assert.equal(s1.signedInAt, s1.createdAt);
    assert.equal(store.db.prepare("SELECT client_kind FROM sessions WHERE id_hash = 's2'").get().client_kind, null);
    // Version 8: a site already here keeps every contact detail it was
    // getting; one made after gets none until the admin grants them.
    assert.deepEqual(store.listApps()[0].contactFields, ['email', 'phone', 'instagram', 'venmo', 'cashapp']);
    assert.deepEqual(store.createApp('events').app.contactFields, []);
    store.db.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
