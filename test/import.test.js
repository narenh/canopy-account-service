// scripts/import-from-tickets.js against a tickets-shaped data folder: a
// dry run leaves nothing behind, a real run brings everyone across, and
// the passkeys tickets made sign in here.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const Database = require('better-sqlite3');
const webauthn = require('@simplewebauthn/server');
const { createAuthenticator } = require('./softAuthenticator');
const { startServer, browser } = require('./harness');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'import-from-tickets.js');

// The tables the import reads, as tickets (schema 17) has them.
function ticketsSchema(db) {
  db.exec(`
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE people (
      id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, first_name TEXT NOT NULL, last_name TEXT NOT NULL,
      photo_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, venmo TEXT,
      calendar_token TEXT, calendar_prompt_done INTEGER, favorites TEXT NOT NULL DEFAULT '[]',
      usual TEXT NOT NULL DEFAULT '[]', usual_gone INTEGER NOT NULL DEFAULT 0, favorites_prompt_done INTEGER,
      peanut_allergy INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE passkeys (
      id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES people(id) ON DELETE CASCADE,
      public_key BLOB NOT NULL, counter INTEGER NOT NULL DEFAULT 0, transports TEXT, device_type TEXT,
      backed_up INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, last_used_at INTEGER
    );
  `);
  db.pragma('user_version = 17');
}

async function makePasskey(personId, email) {
  const auth = createAuthenticator();
  const origin = 'http://localhost:1';
  const options = await webauthn.generateRegistrationOptions({
    rpName: 'Canopy Tickets', rpID: 'localhost', userID: new TextEncoder().encode(personId), userName: email, attestationType: 'none'
  });
  const v = await webauthn.verifyRegistrationResponse({
    response: auth.register(options, origin), expectedChallenge: options.challenge, expectedOrigin: origin,
    expectedRPID: 'localhost', requireUserVerification: false
  });
  return { auth, cred: v.registrationInfo.credential };
}

function run(args, env) {
  try {
    return { code: 0, out: execFileSync(process.execPath, [SCRIPT, ...args], { env: { ...process.env, ...env }, encoding: 'utf8' }) };
  } catch (e) {
    return { code: e.status, out: String(e.stdout) + String(e.stderr) };
  }
}

test('importing from tickets', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-import-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const from = path.join(root, 'tickets');
  const to = path.join(root, 'account');
  fs.mkdirSync(path.join(from, 'photos'), { recursive: true });

  const src = new Database(path.join(from, 'canopy.db'));
  ticketsSchema(src);
  const insertPerson = src.prepare(`INSERT INTO people (id, email, first_name, last_name, photo_at, created_at, updated_at, venmo, peanut_allergy)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`);
  const insertKey = src.prepare(`INSERT INTO passkeys (id, person_id, public_key, counter, transports, device_type, backed_up, created_at, last_used_at)
    VALUES (?, ?, ?, ?, ?, 'multiDevice', 1, ?, ?)`);
  const hana = { id: crypto.randomUUID(), email: 'host@example.com' };
  const ana = { id: crypto.randomUUID(), email: 'ana@example.com' };
  insertPerson.run(hana.id, hana.email, 'Hana', 'Host', 111, 100, 200, null);
  insertPerson.run(ana.id, ana.email, 'Ana', 'Lima', null, 101, 201, 'ana-l');
  fs.writeFileSync(path.join(from, 'photos', `${hana.id}.jpg`), 'jpegbytes');
  const devices = {};
  for (const p of [hana, ana]) {
    const { auth, cred } = await makePasskey(p.id, p.email);
    insertKey.run(cred.id, p.id, Buffer.from(cred.publicKey), 3, JSON.stringify(['internal', 'hybrid']), 300, 400);
    // The device has signed in 3 times already (the counter tickets kept),
    // so its next sign-in counts 4 -- a counter that went backwards would
    // rightly be refused.
    auth.creds[0].counter = 3;
    devices[p.email] = auth;
  }
  src.prepare("INSERT INTO meta (key, value) VALUES ('admin_person_id', ?)").run(hana.id);
  src.close();
  fs.writeFileSync(path.join(from, 'logo-image'), 'png');
  fs.writeFileSync(path.join(from, 'logo-image.json'), JSON.stringify({ mimeType: 'image/png', uploadedAt: 5 }));
  // Tickets' link-preview image, a movie still: not for the sign-in page.
  fs.writeFileSync(path.join(from, 'og-image'), 'jpg');
  fs.writeFileSync(path.join(from, 'og-image.json'), JSON.stringify({ mimeType: 'image/jpeg', uploadedAt: 6 }));

  await t.test('a dry run checks it and writes nothing', () => {
    const r = run(['--from', from, '--dry-run'], { DATA_DIR: to });
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /2 people, 2 passkeys, 1 photos copied/);
    assert.match(r.out, /intact/);
    assert.ok(!fs.existsSync(to));
  });

  await t.test('a real run copies everyone, and refuses to run twice', () => {
    const r = run(['--from', from], { DATA_DIR: to });
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /admin: Hana Host <host@example\.com>/);
    assert.equal(fs.readFileSync(path.join(to, 'photos', `${hana.id}.jpg`), 'utf8'), 'jpegbytes');
    assert.ok(fs.existsSync(path.join(to, 'logo-image')));
    assert.ok(!fs.existsSync(path.join(to, 'backdrop-image')), "tickets' og-image is not the backdrop");
    const again = run(['--from', from], { DATA_DIR: to });
    assert.equal(again.code, 1);
    assert.match(again.out, /already has people/);
  });

  await t.test("tickets' passkeys sign in here, the admin is the admin", async () => {
    const server = await startServer({ DATA_DIR: to });
    t.after(() => server.stop());
    for (const p of [hana, ana]) {
      const b = browser(server);
      b.authenticator.creds.push(...devices[p.email].creds);
      const r = await b.signInWithPasskey();
      assert.equal(r.status, 200, r.text);
      assert.equal(r.data.person.id, p.id);
      assert.equal(r.data.person.isAdmin, p === hana);
    }
  });
});
