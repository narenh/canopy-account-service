// Contact details at rest: sealed with AES-256-GCM under a key that can be
// rotated, found by keyed hash, sealed by the upgrade to version 9 in one
// go, refused at startup without the keys, and nowhere in plain text in a
// copy of the database.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Database = require('better-sqlite3');
const { init, SEALED_COLUMNS, SCHEMA_VERSION } = require('../lib/db');
const { createContactCrypto, parseEncryptionKeys, parseHmacKey, fromEnv } = require('../lib/contactCrypto');
const { startServer, browser, TEST_KEYS } = require('./harness');

const K1 = { id: 'k1', key: Buffer.alloc(32, 1) };
const K2 = { id: 'k2', key: Buffer.alloc(32, 2) };
const HMAC = Buffer.alloc(32, 3);
const keysOf = (keys, hmacKey = HMAC) => createContactCrypto({ keys, hmacKey });

function scratch(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-crypto-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return path.join(dir, 'account.db');
}

let credN = 0;
const cred = () => ({ id: `cred-${++credN}`, publicKey: new Uint8Array([1, 2, 3]), counter: 0 });

// Someone with every contact detail filled in.
function addPerson(store, n, extra = {}) {
  const id = `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
  const made = store.createPersonWithPasskey({ id, email: `p${n}@example.com`, firstName: `P${n}`, lastName: 'Test', venmo: `venmo-${n}` }, cred());
  assert.ok(made.ok);
  store.setPersonPhone(id, extra.phone || `+1415555${String(1000 + n)}`);
  store.setPersonInstagram(id, extra.instagram || `handle.${n}`);
  store.setPersonCashapp(id, `Cash${n}`);
  return id;
}

// Every byte of the database's files, as one string, to search for plain text.
function rawBytes(file) {
  return ['', '-wal', '-shm'].map((x) => (fs.existsSync(file + x) ? fs.readFileSync(file + x).toString('latin1') : '')).join('\n');
}

test('sealing: a round trip, a fresh nonce every time, and nothing opens what it shouldn\'t', () => {
  const c = keysOf([K1]);
  const sealed = c.seal('phone', '+14155551234');
  assert.match(sealed, /^v1:k1:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]+$/);
  assert.equal(c.open('phone', sealed), '+14155551234');
  assert.notEqual(c.seal('phone', '+14155551234'), sealed, 'a new nonce each time');
  assert.equal(c.seal('phone', null), null);
  assert.equal(c.seal('phone', ''), null);
  assert.equal(c.open('phone', null), null);
  // Its kind is part of it: a phone moved into the Instagram column won't open.
  assert.equal(c.open('instagram', sealed), null);
  // Nor will one that's been tampered with, or one under a key that isn't here.
  const [v, id, nonce, body] = sealed.split(':');
  const flipped = body.slice(0, -2) + (body.slice(-2) === 'AA' ? 'AB' : 'AA');
  assert.equal(c.open('phone', [v, id, nonce, flipped].join(':')), null);
  assert.equal(keysOf([K2]).open('phone', sealed), null);
  assert.ok(c.unreadableCount() >= 2);
  // Plain text where a sealed value should be is a bug, and says so.
  assert.throws(() => c.open('phone', '+14155551234'), /isn't sealed/);
});

test('lookup hashes: keyed, per kind, equal for equal values', () => {
  const c = keysOf([K1]);
  assert.equal(c.hash('phone', '+14155551234'), c.hash('phone', '+14155551234'));
  assert.notEqual(c.hash('phone', '+14155551234'), c.hash('phone', '+14155551235'));
  assert.notEqual(c.hash('phone', 'x'), c.hash('instagram', 'x'), 'a kind of its own');
  assert.notEqual(c.hash('phone', '+14155551234'), keysOf([K1], Buffer.alloc(32, 9)).hash('phone', '+14155551234'), 'keyed');
  // The encryption key has nothing to do with it.
  assert.equal(c.hash('email', 'a@b.co'), keysOf([K2]).hash('email', 'a@b.co'));
  assert.equal(c.hash('phone', null), null);
});

test('the keys from the environment', () => {
  const k = Buffer.alloc(32, 5).toString('base64');
  assert.deepEqual(parseEncryptionKeys(`new:${k}, old:${k}`).map((x) => x.id), ['new', 'old']);
  assert.throws(() => parseEncryptionKeys(`a:${Buffer.alloc(16).toString('base64')}`), /32 bytes/);
  assert.throws(() => parseEncryptionKeys(k), /<id>:<base64 key>/);
  assert.throws(() => parseEncryptionKeys(`a:${k},a:${k}`), /its own id/);
  assert.throws(() => parseHmacKey('c2hvcnQ='), /at least 32 bytes/);
  // Both or neither: one without the other is a mistake, not a fresh install.
  assert.throws(() => fromEnv({ CONTACT_ENCRYPTION_KEYS: `a:${k}` }), /LOOKUP_HMAC_KEY/);
  assert.throws(() => fromEnv({ LOOKUP_HMAC_KEY: k }), /CONTACT_ENCRYPTION_KEYS/);
  assert.equal(fromEnv({ CONTACT_ENCRYPTION_KEYS: `a:${k}`, LOOKUP_HMAC_KEY: k }).currentKeyId, 'a');
  // Neither: throwaway keys for this run, said loudly.
  const warn = console.warn;
  const said = [];
  console.warn = (line) => said.push(line);
  try {
    const c = fromEnv({ NODE_ENV: 'production' });
    assert.equal(c.generated, true);
    assert.equal(c.open('email', c.seal('email', 'a@b.co')), 'a@b.co');
  } finally {
    console.warn = warn;
  }
  assert.ok(said.some((l) => /!!! CONTACT_ENCRYPTION_KEYS and LOOKUP_HMAC_KEY are not set/.test(l)));
});

test('stored sealed, found and kept unique by keyed hash', (t) => {
  const file = scratch(t);
  const store = init({ file, snapshots: false, contactCrypto: keysOf([K1]) });
  const a = addPerson(store, 1);
  const b = addPerson(store, 2, { phone: '+14155550000', instagram: 'shared.handle' });
  // What's on disk is sealed, with hashes beside it; what comes out is plain.
  const row = store.db.prepare('SELECT * FROM people WHERE id = ?').get(a);
  for (const [col] of SEALED_COLUMNS.people) assert.match(row[col], /^v1:k1:/, col);
  assert.ok(row.email_hash && row.phone_hash && row.instagram_hash);
  const p = store.getPerson(a);
  assert.deepEqual([p.email, p.phone, p.instagram, p.venmo, p.cashapp], ['p1@example.com', '+14155551001', 'handle.1', 'venmo-1', 'Cash1']);
  // Found by email, phone and Instagram through the hashes.
  assert.equal(store.getPersonByEmail('p1@example.com').id, a);
  assert.equal(store.getPersonByEmail('nobody@example.com'), null);
  assert.equal(store.findPerson({ phone: '+14155551001' }).id, a);
  assert.equal(store.findPerson({ instagram: 'handle.1' }).id, a);
  // One account per email, by its hash.
  assert.equal(store.createPersonWithPasskey({ id: 'x', email: 'p1@example.com', firstName: 'X', lastName: 'Y' }, cred()).reason, 'conflict');
  assert.equal(store.setPersonEmail(b, 'p1@example.com').reason, 'conflict');
  assert.ok(store.setPersonEmail(b, 'p2@example.com').ok, 'its own is fine');
  // Duplicates are counted by hash: a second claim hides both.
  store.setPersonPhone(a, '+14155550000');
  assert.equal(store.findPerson({ phone: '+14155550000' }), null);
  store.setPersonInstagram(a, 'shared.handle');
  assert.equal(store.findPerson({ instagram: 'shared.handle' }), null);
  // Cleared means cleared, hash and all.
  store.setPersonPhone(a, null);
  assert.equal(store.db.prepare('SELECT phone_hash FROM people WHERE id = ?').get(a).phone_hash, null);
  assert.equal(store.findPerson({ phone: '+14155550000' }).id, b);
  // An address waiting for its code, and a sign-up waiting for its passkey,
  // are sealed on the session too.
  const { session } = store.createSession();
  store.issueEmailCode(session.idHash, 'waiting@example.com');
  store.setPending(session.idHash, { challenge: 'c', kind: 'register', profile: { mode: 'new', email: 'waiting@example.com', venmo: 'v-waiting' } });
  const s = store.db.prepare('SELECT code_email, pending_profile FROM sessions WHERE id_hash = ?').get(session.idHash);
  assert.match(s.code_email, /^v1:k1:/);
  assert.match(s.pending_profile, /^v1:k1:/);
  assert.equal(store.codeEmail(session.idHash), 'waiting@example.com');
  assert.equal(store.takePending(session.idHash).profile.venmo, 'v-waiting');
  store.db.close();
});

test('key rotation: a new key first, the old one after, and everything is re-sealed at startup', (t) => {
  const file = scratch(t);
  const first = init({ file, snapshots: false, contactCrypto: keysOf([K1]) });
  const a = addPerson(first, 1);
  first.db.close();

  // Taking the old key out before re-sealing: refused in production...
  assert.throws(() => init({ file, snapshots: false, contactCrypto: keysOf([K2]), production: true }), (err) => {
    assert.equal(err.code, 'CANOPY_STARTUP');
    assert.match(err.message, /isn't in CONTACT_ENCRYPTION_KEYS/);
    assert.match(err.message, /CONTACT_KEYS_LOST=1/);
    return true;
  });
  // The rotation itself: k2 first, k1 still there.
  const log = console.log;
  const said = [];
  console.log = (line) => said.push(line);
  let rotated;
  try {
    rotated = init({ file, snapshots: false, contactCrypto: keysOf([K2, K1]), production: true });
  } finally {
    console.log = log;
  }
  assert.ok(said.some((l) => /re-encrypted 5 contact detail\(s\) under the current key, "k2"/.test(l)), said.join('\n'));
  const row = rotated.db.prepare('SELECT * FROM people WHERE id = ?').get(a);
  for (const [col] of SEALED_COLUMNS.people) assert.match(row[col], /^v1:k2:/, col);
  assert.equal(rotated.getPerson(a).phone, '+14155551001');
  assert.equal(rotated.reseal(), 0, 'nothing left to do');
  rotated.db.close();
  // Now k1 can go.
  const after = init({ file, snapshots: false, contactCrypto: keysOf([K2]), production: true });
  assert.equal(after.getPerson(a).email, 'p1@example.com');
  assert.equal(after.findPerson({ instagram: 'handle.1' }).id, a);
  after.db.close();
});

test('a lost key: refused until CONTACT_KEYS_LOST=1, then empty, and an email comes back by its code', (t) => {
  const file = scratch(t);
  const first = init({ file, snapshots: false, contactCrypto: keysOf([K1]) });
  const a = addPerson(first, 1);
  first.db.close();
  const warn = console.warn;
  const err = console.error;
  console.warn = () => {};
  console.error = () => {};
  let store;
  try {
    store = init({ file, snapshots: false, contactCrypto: keysOf([K2]), production: true, keysLost: true });
    const p = store.getPerson(a);
    assert.deepEqual([p.email, p.phone, p.instagram, p.venmo, p.cashapp], [null, null, null, null, null]);
    assert.equal(p.firstName, 'P1', 'names stay');
    // The keyed hashes still work (LOOKUP_HMAC_KEY wasn't lost): signing in
    // by email still finds the account, and so does the lookup.
    assert.equal(store.getPersonByEmail('p1@example.com').id, a);
    assert.equal(store.findPerson({ phone: '+14155551001' }).id, a);
    // A code proves the address, and it's sealed again under the new key.
    const { session } = store.createSession();
    assert.ok(store.addPasskeyProvingEmail(a, cred(), session.idHash, 'p1@example.com').ok);
    assert.equal(store.getPerson(a).email, 'p1@example.com');
    // Someone else's address doesn't overwrite it.
    store.addPasskeyProvingEmail(a, cred(), session.idHash, 'other@example.com');
    assert.equal(store.getPerson(a).email, 'p1@example.com');
  } finally {
    console.warn = warn;
    console.error = err;
  }
  store.db.close();
});

test('a new LOOKUP_HMAC_KEY: every hash is worked out again at startup', (t) => {
  const file = scratch(t);
  const first = init({ file, snapshots: false, contactCrypto: keysOf([K1]) });
  const a = addPerson(first, 1);
  const before = first.db.prepare('SELECT phone_hash FROM people WHERE id = ?').get(a).phone_hash;
  first.db.close();
  const log = console.log;
  console.log = () => {};
  let store;
  try {
    store = init({ file, snapshots: false, contactCrypto: keysOf([K1], Buffer.alloc(32, 4)) });
  } finally {
    console.log = log;
  }
  assert.notEqual(store.db.prepare('SELECT phone_hash FROM people WHERE id = ?').get(a).phone_hash, before);
  assert.equal(store.findPerson({ phone: '+14155551001' }).id, a);
  assert.equal(store.getPersonByEmail('p1@example.com').id, a);
  store.db.close();
});

test('the upgrade to version 9 seals a populated database in one go, and leaves no plain text in the file', (t) => {
  const file = scratch(t);
  const c = keysOf([K1]);
  // A version 8 database: today's, without what version 9 added, with
  // plain-text contact details in it.
  init({ file, snapshots: false, contactCrypto: c }).db.close();
  const old = new Database(file);
  ['email', 'phone', 'instagram'].forEach((col) => {
    old.exec(`DROP INDEX people_${col}_hash`);
    old.exec(`ALTER TABLE people DROP COLUMN ${col}_hash`);
  });
  old.exec('CREATE INDEX people_phone ON people(phone)');
  old.exec('CREATE INDEX people_instagram ON people(instagram)');
  const insert = old.prepare(`INSERT INTO people (id, email, first_name, last_name, venmo, phone, instagram, cashapp, email_verified_at, findable, created_at, updated_at)
    VALUES (?, ?, ?, 'Test', ?, ?, ?, ?, 1, 1, 1, 1)`);
  const plain = [];
  for (let n = 1; n <= 40; n++) {
    const values = [`old${n}@example.com`, `old-venmo-${n}`, `+1415777${String(1000 + n)}`, `old.handle.${n}`, `OldCash${n}`];
    plain.push(...values);
    insert.run(`p${n}`, values[0], `Old${n}`, values[1], values[2], values[3], values[4]);
  }
  // One with nothing but an email.
  insert.run('bare', 'bare@example.com', 'Bare', null, null, null, null);
  old.prepare("INSERT INTO sessions (id_hash, created_at, last_seen_at, cookie_set_at, code_email, code_hash, code_at, pending_profile) VALUES ('s', 1, ?, 1, 'waiting@example.com', 'h', 1, ?)")
    .run(Date.now(), JSON.stringify({ mode: 'new', email: 'pending@example.com', venmo: 'pending-venmo' }));
  plain.push('waiting@example.com', 'pending@example.com', 'pending-venmo');
  old.pragma('user_version = 8');
  old.close();
  assert.ok(rawBytes(file).includes('old.handle.7'), 'the test database does have plain text in it');

  const warn = console.warn;
  const said = [];
  console.warn = (line) => said.push(line);
  let store;
  try {
    store = init({ file, snapshots: false, contactCrypto: c });
  } finally {
    console.warn = warn;
  }
  assert.ok(said.some((l) => /Snapshots in backups\/sqlite made before this upgrade/.test(l)));
  assert.equal(store.db.pragma('user_version', { simple: true }), SCHEMA_VERSION);
  const rows = store.db.prepare('SELECT * FROM people').all();
  for (const r of rows) {
    for (const [col] of SEALED_COLUMNS.people) if (r[col] !== null) assert.match(r[col], /^v1:k1:/, `${r.id}.${col}`);
    assert.ok(r.email_hash);
  }
  assert.equal(store.db.prepare("SELECT phone, phone_hash, venmo FROM people WHERE id = 'bare'").get().phone_hash, null);
  assert.ok(!store.db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'people_phone'").get(), 'the plain-text index is gone');
  // Everything still reads and is found.
  assert.equal(store.getPerson('p7').instagram, 'old.handle.7');
  assert.equal(store.getPersonByEmail('old7@example.com').id, 'p7');
  assert.equal(store.findPerson({ phone: '+14157771007' }).id, 'p7');
  assert.equal(store.findPerson({ instagram: 'old.handle.7' }).id, 'p7');
  assert.equal(store.codeEmail('s'), 'waiting@example.com');
  // And none of it is left anywhere in the file.
  const raw = rawBytes(file);
  assert.deepEqual(plain.filter((v) => raw.includes(v)), []);
  store.db.close();
});

test('the server: refuses to start in production without keys once there are people; warns loudly on a fresh install', async (t) => {
  // A fresh production install with no keys starts, loudly.
  const fresh = await startServer({ NODE_ENV: 'production', CONTACT_ENCRYPTION_KEYS: '', LOOKUP_HMAC_KEY: '', DATA_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-crypto-srv-')) });
  t.after(() => fs.rmSync(fresh.dataDir, { recursive: true, force: true }));
  fresh.stop();
  assert.match(fresh.output(), /!!! CONTACT_ENCRYPTION_KEYS and LOOKUP_HMAC_KEY are not set/);

  // Someone signs up (on keys), and then the keys go missing.
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-crypto-srv-'));
  t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
  const server = await startServer({ DATA_DIR: dataDir });
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  server.stop();
  await new Promise((r) => setTimeout(r, 200));
  await assert.rejects(
    startServer({ DATA_DIR: dataDir, NODE_ENV: 'production', CONTACT_ENCRYPTION_KEYS: '', LOOKUP_HMAC_KEY: '' }),
    (err) => /server exited 1/.test(err.message) && /not starting: CONTACT_ENCRYPTION_KEYS and LOOKUP_HMAC_KEY are not set/.test(err.message)
  );
  // The wrong keys are refused too, and the right ones still work.
  const wrong = `other:${Buffer.alloc(32, 9).toString('base64')}`;
  await assert.rejects(
    startServer({ DATA_DIR: dataDir, NODE_ENV: 'production', CONTACT_ENCRYPTION_KEYS: wrong }),
    (err) => /isn't in CONTACT_ENCRYPTION_KEYS/.test(err.message)
  );
  const again = await startServer({ DATA_DIR: dataDir, ...TEST_KEYS });
  again.stop();
});

test('a snapshot of a live database holds no phone number, handle, email, Venmo or Cash App', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-crypto-snap-'));
  t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
  const server = await startServer({ DATA_DIR: dataDir });
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host.secret@example.com', 'Hana', 'Host');
  const ana = browser(server);
  await ana.signUp('ana.secret@example.com', 'Ana', 'Lima');
  await ana.patch('/api/profile', { firstName: 'Ana', lastName: 'Lima', phone: '(415) 555-0199', instagram: 'ana.secret.handle', venmoHandle: 'ana-secret-venmo', cashapp: 'AnaSecretCash' });
  // Changed once, so an old value has been overwritten in the file too.
  await ana.patch('/api/profile', { firstName: 'Ana', lastName: 'Lima', phone: '(415) 555-0198' });
  // Someone part way through signing up, with their email on the session.
  await browser(server).post('/api/auth/email/start', { email: 'halfway.secret@example.com' });
  server.stop();
  await new Promise((r) => setTimeout(r, 200));
  // A restart takes the day's snapshot.
  const again = await startServer({ DATA_DIR: dataDir });
  t.after(() => again.stop());
  const dir = path.join(dataDir, 'backups', 'sqlite');
  let snap = null;
  for (let i = 0; i < 50 && !snap; i++) {
    const files = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.db')) : [];
    if (files.length) snap = path.join(dir, files[0]);
    else await new Promise((r) => setTimeout(r, 50));
  }
  assert.ok(snap, 'a snapshot was taken');
  await new Promise((r) => setTimeout(r, 200));
  const secrets = ['4155550199', '4155550198', '555-0199', 'ana.secret.handle', 'ana-secret-venmo', 'AnaSecretCash', 'ana.secret@example.com',
    'host.secret@example.com', 'halfway.secret@example.com'];
  for (const [what, bytes] of [['the snapshot', fs.readFileSync(snap).toString('latin1')], ['account.db', rawBytes(path.join(dataDir, 'account.db'))]]) {
    assert.deepEqual(secrets.filter((x) => bytes.includes(x)), [], `${what} has plain text in it`);
  }
  // It's all still there, sealed: the snapshot opens with the keys.
  const copy = init({ file: snap, snapshots: false, contactCrypto: fromEnv(TEST_KEYS) });
  const found = copy.listPeople().find((p) => p.firstName === 'Ana');
  assert.equal(found.phone, '+14155550198');
  assert.equal(found.cashapp, 'AnaSecretCash');
  copy.db.close();
});
