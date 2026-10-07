// A database from an earlier schema is brought up to date on open, and
// keeps what it had.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Database = require('better-sqlite3');
const { init, SCHEMA_VERSION } = require('../lib/db');

test('a version 1 database gains the phone column', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-schema-test-'));
  const file = path.join(dir, 'account.db');
  try {
    // Make a version 1 database: today's, without what version 2 added.
    init({ file, snapshots: false }).db.close();
    const old = new Database(file);
    old.exec('ALTER TABLE people DROP COLUMN phone');
    old.prepare("INSERT INTO people (id, email, first_name, last_name, created_at, updated_at) VALUES ('p1', 'a@b.co', 'A', 'B', 1, 1)").run();
    old.pragma('user_version = 1');
    old.close();

    const store = init({ file, snapshots: false });
    assert.equal(store.db.pragma('user_version', { simple: true }), SCHEMA_VERSION);
    assert.equal(store.getPerson('p1').phone, null);
    assert.equal(store.setPersonPhone('p1', '+14155551234').phone, '+14155551234');
    store.db.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
