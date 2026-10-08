// A database from an earlier schema is brought up to date on open, and
// keeps what it had.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Database = require('better-sqlite3');
const { init, SCHEMA_VERSION, FINDABLE_BY_DEFAULT } = require('../lib/db');
const { createContactCrypto } = require('../lib/contactCrypto');

const contactCrypto = createContactCrypto({ keys: [{ id: 'k1', key: Buffer.alloc(32, 7) }], hmacKey: Buffer.alloc(32, 8) });

test('a version 1 database is brought up to date', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-schema-test-'));
  const file = path.join(dir, 'account.db');
  try {
    // Make a version 1 database: today's, without what versions 2 and up added.
    init({ file, snapshots: false, contactCrypto }).db.close();
    const old = new Database(file);
    ['email', 'phone', 'instagram'].forEach((c) => {
      old.exec(`DROP INDEX people_${c}_hash`);
      old.exec(`ALTER TABLE people DROP COLUMN ${c}_hash`);
    });
    ['phone', 'instagram', 'cashapp'].forEach((c) => old.exec(`ALTER TABLE people DROP COLUMN ${c}`));
    old.exec('ALTER TABLE sessions DROP COLUMN reauth_at');
    old.exec('ALTER TABLE apps DROP COLUMN allows_unverified');
    old.exec('ALTER TABLE apps DROP COLUMN allows_lookup');
    old.exec('ALTER TABLE people DROP COLUMN findable');
    ['client_kind', 'client_name', 'signed_in_at'].forEach((c) => old.exec(`ALTER TABLE sessions DROP COLUMN ${c}`));
    old.exec('ALTER TABLE apps DROP COLUMN contact_fields');
    old.exec('DROP TABLE lookup_log');
    ['calendar_url', 'calendar_secret', 'calendar_secret_at'].forEach((c) => old.exec(`ALTER TABLE apps DROP COLUMN ${c}`));
    old.exec('DROP TABLE calendar_feeds');
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

    const store = init({ file, snapshots: false, contactCrypto });
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
    assert.ok(store.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'people_phone_hash'").get());
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
    // Version 10: the lookup log, empty.
    assert.equal(store.db.prepare('SELECT COUNT(*) AS n FROM lookup_log').get().n, 0);
    // Version 11: the calendar feed. No site has a calendar until the
    // admin says where it is; feeds are made as people ask for them.
    assert.equal(store.listApps()[0].calendarUrl, null);
    assert.equal(store.listApps()[0].calendarSecretAt, null);
    assert.deepEqual(store.calendarSites(), []);
    const made = store.setAppCalendarUrl('a1', 'https://tickets.canopysf.com');
    assert.match(made.secret, /^cnc_/);
    assert.equal(store.calendarSites()[0].secret, made.secret);
    const feed = store.calendarFeed('p1');
    assert.equal(store.personByCalendarSecret(feed.secret).id, 'p1');
    assert.equal(store.calendarFeed('nobody'), null);
    store.db.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a version 10 database (contact details sealed) opens at 11, and calendar secrets follow a key rotation', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-schema-test-'));
  const file = path.join(dir, 'account.db');
  try {
    const first = init({ file, snapshots: false, contactCrypto });
    first.db.prepare("INSERT INTO people (id, email, email_hash, first_name, last_name, created_at, updated_at) VALUES ('p1', ?, ?, 'A', 'B', 1, 1)")
      .run(contactCrypto.seal('email', 'a@b.co'), contactCrypto.hash('email', 'a@b.co'));
    first.db.close();
    // Back to version 10: what this branch's upgrade starts from.
    const old = new Database(file);
    ['calendar_url', 'calendar_secret', 'calendar_secret_at'].forEach((c) => old.exec(`ALTER TABLE apps DROP COLUMN ${c}`));
    old.exec('DROP TABLE calendar_feeds');
    old.prepare("INSERT INTO apps (id, name, key_hash, created_at) VALUES ('a1', 'events', 'h', 1)").run();
    old.pragma('user_version = 10');
    old.close();

    // The keys are checked before the upgrade, against columns that
    // aren't there yet: that has to work.
    const store = init({ file, snapshots: false, contactCrypto, production: true });
    assert.equal(store.db.pragma('user_version', { simple: true }), SCHEMA_VERSION);
    assert.equal(SCHEMA_VERSION, 11);
    const site = store.setAppCalendarUrl('a1', 'http://events:3000');
    const feed = store.calendarFeed('p1');
    store.db.close();

    // A new key first in the list: both secrets are re-sealed under it at
    // the next start, and still open.
    const rotated = createContactCrypto({ keys: [{ id: 'k2', key: Buffer.alloc(32, 9) }, { id: 'k1', key: Buffer.alloc(32, 7) }], hmacKey: Buffer.alloc(32, 8) });
    const after = init({ file, snapshots: false, contactCrypto: rotated });
    assert.match(after.db.prepare('SELECT secret FROM calendar_feeds').get().secret, /^v1:k2:/);
    assert.match(after.db.prepare('SELECT calendar_secret FROM apps').get().calendar_secret, /^v1:k2:/);
    assert.equal(after.calendarFeed('p1').secret, feed.secret);
    assert.equal(after.calendarSites()[0].secret, site.secret);
    after.db.close();

    // A lost key: the site's secret can't be opened, so the site is left
    // out until the admin makes a new one; the person's link is replaced.
    const lost = createContactCrypto({ keys: [{ id: 'k3', key: Buffer.alloc(32, 5) }], hmacKey: Buffer.alloc(32, 8) });
    const afterLoss = init({ file, snapshots: false, contactCrypto: lost });
    assert.deepEqual(afterLoss.calendarSites(), []);
    assert.notEqual(afterLoss.calendarFeed('p1').secret, feed.secret);
    assert.equal(afterLoss.personByCalendarSecret(feed.secret), null);
    afterLoss.db.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
