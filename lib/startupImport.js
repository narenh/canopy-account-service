// The import from tickets, run at startup instead of from a terminal --
// for when there's no shell into the container (Coolify's terminal).
//
// Set IMPORT_FROM_TICKETS to where tickets' data folder is mounted in this
// container (e.g. /tickets-data: tickets' own volume, added to this
// service's Storages too). On boot, before anything else opens the
// database, this runs scripts/import-from-tickets.js twice: a dry run,
// and only if that checks out, the real one. Both print everything to the
// log. Once the account database has people, the script refuses and
// nothing changes, so a redeploy with the setting still on is harmless --
// but remove it (and the mount) once it's done.
//
// The service starts either way; a failed import leaves the database as
// it was (empty), to fix and redeploy.

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { DB_FILE } = require('./db');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'import-from-tickets.js');

function run(args) {
  const r = spawnSync(process.execPath, [SCRIPT, ...args], { env: process.env, encoding: 'utf8' });
  String(r.stdout || '').split('\n').filter(Boolean).forEach((l) => console.log(`[canopy-account] ${l}`));
  String(r.stderr || '').split('\n').filter(Boolean).forEach((l) => console.error(`[canopy-account] ${l}`));
  return r.status === 0;
}

// Whether account.db already has people (and so has been imported into,
// or set up by hand).
function hasPeople() {
  if (!fs.existsSync(DB_FILE)) return false;
  const db = new Database(DB_FILE, { readonly: true });
  try {
    return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'people'").get() &&
      db.prepare('SELECT COUNT(*) AS n FROM people').get().n > 0;
  } finally {
    db.close();
  }
}

function importFromTicketsAtStartup(from) {
  if (hasPeople()) {
    console.log('[canopy-account] IMPORT_FROM_TICKETS is set, but the account database already has people: nothing to do. Remove the setting.');
    return;
  }
  console.log(`[canopy-account] IMPORT_FROM_TICKETS=${from}: dry run first`);
  if (!run(['--from', from, '--dry-run'])) {
    console.error('[canopy-account] import: the dry run did not check out (above), so nothing was imported.');
    return;
  }
  console.log('[canopy-account] import: dry run checked out; importing for real');
  if (run(['--from', from])) {
    console.log('[canopy-account] import: done. Remove IMPORT_FROM_TICKETS and the tickets volume mount, then redeploy.');
  } else {
    console.error('[canopy-account] import: the real run reported problems (above).');
  }
}

module.exports = { importFromTicketsAtStartup };
