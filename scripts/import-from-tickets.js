#!/usr/bin/env node
// One-time copy of everyone out of tickets into the account service:
// people (same ids), their passkeys (every column, unchanged), who the
// admin is, profile photos, and the sign-in page's logo and backdrop
// (tickets' link-preview image).
//
//   node scripts/import-from-tickets.js --from <tickets DATA_DIR copy> [--dry-run]
//
// --from is a copy of tickets' data directory (canopy.db, photos/,
// logo-image, og-image...). --db points at a different database file in
// it, e.g. one of the consistent daily snapshots in backups/sqlite/.
//
// --dry-run imports into a scratch database and folder instead of
// DATA_DIR, checks it, and throws it away: nothing here is touched.
//
// Either way, afterwards every person and passkey is read back from both
// sides and compared field by field (photos by their bytes); any
// difference is listed and the script exits 1.
//
// It only imports into an EMPTY account database: no people yet. Stop the
// account service while it runs.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

function arg(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? null : process.argv[i + 1];
}

function fail(message) {
  console.error(`import: ${message}`);
  process.exit(1);
}

const from = arg('--from');
const dryRun = process.argv.includes('--dry-run');
if (!from) fail('usage: node scripts/import-from-tickets.js --from <tickets data dir> [--db <file>] [--dry-run]');
const sourceFile = arg('--db') || path.join(from, 'canopy.db');
if (!fs.existsSync(sourceFile)) fail(`no database at ${sourceFile}`);

// Where it goes: DATA_DIR, or a scratch folder for a dry run.
const targetDir = dryRun
  ? fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-account-dry-run-'))
  : process.env.DATA_DIR || path.join(__dirname, '..', 'data');
process.env.DATA_DIR = targetDir; // read by lib/photoStore.js and lib/uploadedImage.js
const { init } = require('../lib/db');
const photoStore = require('../lib/photoStore');
const { createImageStore } = require('../lib/uploadedImage');

const source = new Database(sourceFile, { readonly: true, fileMustExist: true });
const sourceVersion = source.pragma('user_version', { simple: true });
for (const table of ['people', 'passkeys', 'meta']) {
  if (!source.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table)) {
    fail(`${sourceFile} has no ${table} table -- is it tickets' canopy.db (schema 16 or later)?`);
  }
}

const store = init({ file: path.join(targetDir, 'account.db'), snapshots: false });
const target = store.db;
if (target.prepare('SELECT COUNT(*) AS n FROM people').get().n > 0) {
  fail(`${path.join(targetDir, 'account.db')} already has people in it; this only imports into an empty one`);
}

const people = source.prepare('SELECT * FROM people ORDER BY created_at').all();
const passkeys = source.prepare('SELECT * FROM passkeys ORDER BY created_at').all();
const adminRow = source.prepare("SELECT value FROM meta WHERE key = 'admin_person_id'").get();
const adminId = adminRow ? adminRow.value : null;

console.log(`import: ${dryRun ? 'DRY RUN into ' + targetDir : 'into ' + targetDir}`);
console.log(`import: from ${sourceFile} (tickets schema ${sourceVersion}): ${people.length} people, ${passkeys.length} passkeys`);

// ---- Copy ----

const insertPerson = target.prepare(`
  INSERT INTO people (id, email, first_name, last_name, venmo, photo_at, email_verified_at, created_at, updated_at)
  VALUES (@id, @email, @first_name, @last_name, @venmo, @photo_at, NULL, @created_at, @updated_at)`);
const insertPasskey = target.prepare(`
  INSERT INTO passkeys (id, person_id, public_key, counter, transports, device_type, backed_up, created_at, last_used_at)
  VALUES (@id, @person_id, @public_key, @counter, @transports, @device_type, @backed_up, @created_at, @last_used_at)`);

const photoProblems = [];
target.transaction(() => {
  people.forEach((p) => {
    // A photo date with no file behind it would be a broken image on
    // every site; it comes across as no photo, and is listed.
    let photoAt = p.photo_at || null;
    if (photoAt && !fs.existsSync(path.join(from, 'photos', `${p.id}.jpg`))) {
      photoProblems.push(`${p.first_name} ${p.last_name} (${p.id}): photo date set, but no photos/${p.id}.jpg -- imported without a photo`);
      photoAt = null;
    }
    insertPerson.run({
      id: p.id,
      email: String(p.email).trim().toLowerCase(),
      first_name: p.first_name,
      last_name: p.last_name,
      venmo: p.venmo || null,
      photo_at: photoAt,
      created_at: p.created_at,
      updated_at: p.updated_at
    });
  });
  passkeys.forEach((k) => insertPasskey.run(k));
  if (adminId) {
    if (!people.some((p) => p.id === adminId)) throw new Error(`the admin (${adminId}) isn't among tickets' people`);
    store.setAdminPersonId(adminId);
  }
})();

let photosCopied = 0;
people.forEach((p) => {
  const file = path.join(from, 'photos', `${p.id}.jpg`);
  if (p.photo_at && fs.existsSync(file)) {
    photoStore.save(p.id, fs.readFileSync(file));
    photosCopied++;
  }
});

// The sign-in page's look: tickets' logo, and its link-preview image as
// the backdrop (that's what tickets' sign-in page shows behind the card).
const images = [['logo', 'logo'], ['og', 'backdrop']];
const imagesCopied = [];
images.forEach(([fromName, toName]) => {
  const img = path.join(from, `${fromName}-image`);
  const meta = path.join(from, `${fromName}-image.json`);
  if (!fs.existsSync(img) || !fs.existsSync(meta)) return;
  const { mimeType } = JSON.parse(fs.readFileSync(meta, 'utf8'));
  createImageStore(toName).save(fs.readFileSync(img), mimeType);
  imagesCopied.push(`${fromName}-image -> ${toName}-image`);
});

// ---- Check every row came across intact ----

const problems = [];
const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const imported = new Map(target.prepare('SELECT * FROM people').all().map((p) => [p.id, p]));
const missingPhoto = new Set(photoProblems.map((m) => m.match(/\(([0-9a-f-]{36})\)/)[1]));

people.forEach((p) => {
  const q = imported.get(p.id);
  if (!q) return problems.push(`person ${p.id} (${p.email}) is missing`);
  const expect = {
    email: String(p.email).trim().toLowerCase(), first_name: p.first_name, last_name: p.last_name,
    venmo: p.venmo || null, photo_at: missingPhoto.has(p.id) ? null : p.photo_at || null,
    created_at: p.created_at, updated_at: p.updated_at
  };
  Object.keys(expect).forEach((k) => {
    if (expect[k] !== q[k]) problems.push(`person ${p.id}: ${k} is ${JSON.stringify(q[k])}, expected ${JSON.stringify(expect[k])}`);
  });
  if (expect.photo_at) {
    const a = path.join(from, 'photos', `${p.id}.jpg`);
    const b = photoStore.pathFor(p.id);
    if (!b) problems.push(`person ${p.id}: photo not copied`);
    else if (sha(fs.readFileSync(a)) !== sha(fs.readFileSync(b))) problems.push(`person ${p.id}: photo differs`);
  }
});
if (imported.size !== people.length) problems.push(`${imported.size} people imported, ${people.length} in tickets`);

const importedKeys = new Map(target.prepare('SELECT * FROM passkeys').all().map((k) => [k.id, k]));
passkeys.forEach((k) => {
  const q = importedKeys.get(k.id);
  if (!q) return problems.push(`passkey ${k.id} is missing`);
  Object.keys(k).forEach((col) => {
    const same = Buffer.isBuffer(k[col]) ? Buffer.isBuffer(q[col]) && k[col].equals(q[col]) : k[col] === q[col];
    if (!same) problems.push(`passkey ${k.id}: ${col} differs`);
  });
});
if (importedKeys.size !== passkeys.length) problems.push(`${importedKeys.size} passkeys imported, ${passkeys.length} in tickets`);
if (store.getAdminPersonId() !== adminId) problems.push(`admin is ${store.getAdminPersonId()}, expected ${adminId}`);

// ---- Report ----

const withoutPasskey = people.filter((p) => !passkeys.some((k) => k.person_id === p.id));
console.log(`import: ${imported.size} people, ${importedKeys.size} passkeys, ${photosCopied} photos copied`);
console.log(`import: admin: ${adminId ? (() => { const a = people.find((p) => p.id === adminId); return `${a.first_name} ${a.last_name} <${a.email}>`; })() : 'none in tickets'}`);
if (imagesCopied.length) console.log(`import: images: ${imagesCopied.join(', ')}`);
if (withoutPasskey.length) {
  console.log(`import: ${withoutPasskey.length} people have no passkey yet (they'll sign in with an emailed code):`);
  withoutPasskey.forEach((p) => console.log(`   ${p.first_name} ${p.last_name} <${p.email}>`));
}
photoProblems.forEach((m) => console.log(`import: note: ${m}`));

source.close();
target.close();
if (dryRun) fs.rmSync(targetDir, { recursive: true, force: true });

if (problems.length) {
  console.error(`import: ${problems.length} problem(s):`);
  problems.forEach((m) => console.error(`   ${m}`));
  process.exit(1);
}
console.log(`import: every person and passkey checked: intact.${dryRun ? ' (dry run: nothing was written)' : ''}`);
