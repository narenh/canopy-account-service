// SQLite persistence for Canopy accounts: people, their passkeys, signed-in
// sessions, one-time setup links, the sites allowed to ask about people,
// and who the admin is.
//
// One file, DATA_DIR/account.db, on the service's own volume (photos sit
// next to it, see lib/photoStore.js). better-sqlite3 is synchronous and
// this is one process, so a transaction is the whole locking story.
//
// ---- What's stored as a hash, and why ----
//
// sessions.id_hash     the cookie holds a random token; only its SHA-256
//                      is here, so a leaked copy of this file (a backup, a
//                      snapshot) can't be turned back into a cookie.
// setup_links.code_hash the same for the code in a /setup/<code> link.
// apps.key_hash        the same for each site's secret key.
// sessions.code_hash   the emailed sign-in code, salted with the session.
//
// Passkeys are public keys: nothing in this file lets anyone sign in.
//
// A NULL column means "no value".

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const DB_FILE = path.join(DATA_DIR, 'account.db');

// Bumped whenever the schema changes; see prepareSchema.
const SCHEMA_VERSION = 7;

// Whether someone new can be found by their phone number or Instagram
// (the profile's "Let people who know your phone number or Instagram find
// you"). On: a host typing a number they already have is how they invite a
// friend, and the lookup never gives anything away but the public name and
// photo (see "Finding people" in the README). Flip it here; it applies to
// accounts made from then on, and to everyone when version 6 is first
// opened.
const FINDABLE_BY_DEFAULT = true;

// A session nobody's used in a year is over (the cookie it belonged to
// has expired too). One that never signed in only lasts a day: it was a
// sign-in started and abandoned.
const SESSION_TTL_MS = 365 * 24 * 60 * 60 * 1000;
const UNSIGNED_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

// An emailed code is good for 10 minutes and 5 tries; after it checks
// out, the address counts as proven on this browser for 15 minutes, which
// is the time to fill in a profile and make a passkey.
const CODE_TTL_MS = 10 * 60 * 1000;
const CODE_MAX_TRIES = 5;
const VERIFIED_EMAIL_TTL_MS = 15 * 60 * 1000;

const SETUP_LINK_TTL_MS = 24 * 60 * 60 * 1000;

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function createSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    -- A person. Every site keys its own records by this id. Friends see
    -- "First L".
    CREATE TABLE IF NOT EXISTS people (
      id          TEXT PRIMARY KEY,
      email       TEXT NOT NULL UNIQUE,
      first_name  TEXT NOT NULL,
      last_name   TEXT NOT NULL,
      -- Their own Venmo username (without the @).
      venmo       TEXT,
      -- Their phone number, optional, as +<country><number> (E.164):
      -- server.js cleans what they type, +1 when no country is given.
      phone       TEXT,
      -- Their Instagram username (without the @) and Cash App $cashtag
      -- (without the $), both optional.
      instagram   TEXT,
      cashapp     TEXT,
      -- When their photo was last changed: the ?v= on its URL.
      photo_at    INTEGER,
      -- When their email was last proven (a code typed back, or the setup
      -- password for the first admin). Null means unverified: a quick
      -- sign-up that hasn't typed a code yet, or an email the admin
      -- changed, until its owner gets a code there. Sites that don't
      -- allow unverified accounts see them as signed out (server.js).
      email_verified_at INTEGER,
      -- 1 if a site's lookup may find them by their exact phone number or
      -- Instagram (their profile's setting; FINDABLE_BY_DEFAULT when made).
      findable    INTEGER NOT NULL DEFAULT 1,
      created_at  INTEGER NOT NULL,
      updated_at  INTEGER NOT NULL
    );
    -- A person's passkeys (WebAuthn credentials). id is the credential id, base64url.
    CREATE TABLE IF NOT EXISTS passkeys (
      id            TEXT PRIMARY KEY,
      person_id     TEXT NOT NULL REFERENCES people(id) ON DELETE CASCADE,
      public_key    BLOB NOT NULL,
      counter       INTEGER NOT NULL DEFAULT 0,
      transports    TEXT,
      device_type   TEXT,
      backed_up     INTEGER NOT NULL DEFAULT 0,
      created_at    INTEGER NOT NULL,
      last_used_at  INTEGER
    );
    CREATE INDEX IF NOT EXISTS passkeys_person ON passkeys(person_id);
    -- One browser's session: the canopy_session cookie, shared by every
    -- Canopy site. Signed in once person_id is set. Replaces tickets'
    -- devices table. An app's session is the same thing, with the token
    -- in the app's keychain instead of a cookie (server.js, "Apps").
    CREATE TABLE IF NOT EXISTS sessions (
      id_hash         TEXT PRIMARY KEY,
      person_id       TEXT REFERENCES people(id) ON DELETE CASCADE,
      created_at      INTEGER NOT NULL,
      last_seen_at    INTEGER NOT NULL,
      -- When the cookie was last (re)sent with a fresh year on it.
      cookie_set_at   INTEGER NOT NULL,
      -- A passkey ceremony in progress: the challenge the server issued,
      -- and what it's for (see server.js).
      pending_challenge TEXT,
      pending_kind      TEXT,
      pending_person_id TEXT,
      pending_profile   TEXT,
      pending_at        INTEGER,
      -- When this browser entered the setup password (first run, or
      -- ADMIN_RECOVERY): good for one sign-in soon after.
      admin_setup_at  INTEGER,
      -- When the person signed in here last confirmed it's them with a
      -- passkey (Face ID etc.), for changes that need it: their email.
      reauth_at       INTEGER,
      -- An emailed sign-in code waiting to be typed in.
      code_hash       TEXT,
      code_email      TEXT,
      code_at         INTEGER,
      code_tries      INTEGER NOT NULL DEFAULT 0,
      -- The address that code proved, until a passkey is made with it.
      verified_email  TEXT,
      verified_at     INTEGER,
      -- What it is, for the person's own list of where they're signed in:
      -- 'web', 'ios' or 'android', and a name ("Safari on iPhone", "Canopy
      -- Events on iPhone"). Null for one that never said.
      client_kind     TEXT,
      client_name     TEXT,
      -- When it was signed in (created_at is when the browser first got a
      -- cookie, which can be long before).
      signed_in_at    INTEGER
    );
    CREATE INDEX IF NOT EXISTS sessions_person ON sessions(person_id);
    -- "Set up a passkey for this person": the admin's answer to a lost
    -- phone. One use, a day to use it.
    CREATE TABLE IF NOT EXISTS setup_links (
      code_hash   TEXT PRIMARY KEY,
      person_id   TEXT NOT NULL REFERENCES people(id) ON DELETE CASCADE,
      created_at  INTEGER NOT NULL,
      expires_at  INTEGER NOT NULL,
      used_at     INTEGER
    );
    -- A site that may ask who's signed in (tickets, the next one...), with
    -- its own key so one can be cut off without the others.
    CREATE TABLE IF NOT EXISTS apps (
      id           TEXT PRIMARY KEY,
      name         TEXT NOT NULL UNIQUE,
      key_hash     TEXT NOT NULL UNIQUE,
      created_at   INTEGER NOT NULL,
      last_used_at INTEGER,
      revoked_at   INTEGER,
      -- 1 if people whose email isn't proven yet (quick sign-ups) count
      -- as signed in on this site. Off unless the admin turns it on.
      allows_unverified INTEGER NOT NULL DEFAULT 0,
      -- 1 if it may find people by phone number or Instagram
      -- (/api/people/lookup). Off unless the admin turns it on.
      allows_lookup INTEGER NOT NULL DEFAULT 0
    );
  `);
}

// Each step brings an existing database from the version it's keyed by
// to the next.
const UPGRADES = {
  // 1 -> 2: people get an optional phone number.
  1(db) {
    db.exec('ALTER TABLE people ADD COLUMN phone TEXT');
  },
  // 2 -> 3: and an Instagram username and a Cash App $cashtag.
  2(db) {
    db.exec('ALTER TABLE people ADD COLUMN instagram TEXT');
    db.exec('ALTER TABLE people ADD COLUMN cashapp TEXT');
  },
  // 3 -> 4: sessions remember a passkey check, for changing an email.
  3(db) {
    db.exec('ALTER TABLE sessions ADD COLUMN reauth_at INTEGER');
  },
  // 4 -> 5: quick sign-ups, whose email isn't proven, and the sites that
  // let them in. A null email_verified_at used to mean only "the admin
  // changed it" and changed nothing; now it shuts the person out of most
  // sites. So everyone already here counts as verified, rather than
  // being shut out by an upgrade they didn't ask for.
  4(db) {
    db.exec('UPDATE people SET email_verified_at = updated_at WHERE email_verified_at IS NULL');
    db.exec('ALTER TABLE apps ADD COLUMN allows_unverified INTEGER NOT NULL DEFAULT 0');
  },
  // 5 -> 6: finding people by phone or Instagram. Everyone already here
  // gets the default, like someone signing up today. The indexes are
  // made in prepareSchema, after every upgrade.
  5(db) {
    db.exec('ALTER TABLE people ADD COLUMN findable INTEGER NOT NULL DEFAULT 1');
    db.prepare('UPDATE people SET findable = ?').run(FINDABLE_BY_DEFAULT ? 1 : 0);
    db.exec('ALTER TABLE apps ADD COLUMN allows_lookup INTEGER NOT NULL DEFAULT 0');
  },
  // 6 -> 7: apps sign in too, so sessions say what they are. Every session
  // already here is a browser's; when it signed in isn't known, so it's
  // when it started.
  6(db) {
    db.exec('ALTER TABLE sessions ADD COLUMN client_kind TEXT');
    db.exec('ALTER TABLE sessions ADD COLUMN client_name TEXT');
    db.exec('ALTER TABLE sessions ADD COLUMN signed_in_at INTEGER');
    db.exec("UPDATE sessions SET client_kind = 'web', signed_in_at = created_at WHERE person_id IS NOT NULL");
  }
};

// Opens a new database at SCHEMA_VERSION, or brings an existing one up to
// it. One from newer code is refused rather than opened with columns this
// code doesn't know about.
function prepareSchema(db) {
  let version = db.pragma('user_version', { simple: true });
  const isNew = version === 0 && !db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'people'").get();
  if (!isNew && (version < 1 || version > SCHEMA_VERSION)) {
    throw new Error(`${DB_FILE} is at schema version ${version}, and this code only opens versions 1 to ${SCHEMA_VERSION}.`);
  }
  db.transaction(() => {
    createSchema(db);
    if (!isNew) for (; version < SCHEMA_VERSION; version++) UPGRADES[version](db);
    // Indexes on columns an upgrade may have only just added, so after
    // them. For the lookup: exact matches only, so a plain index will do.
    db.exec('CREATE INDEX IF NOT EXISTS people_phone ON people(phone)');
    db.exec('CREATE INDEX IF NOT EXISTS people_instagram ON people(instagram)');
    db.pragma(`user_version = ${SCHEMA_VERSION}`);
  })();
}

function open(file) {
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  return db;
}

// A consistent copy of the database, made with SQLite's own online
// backup, at startup and then daily -- Coolify's volume backups archive
// files as they sit on disk, and a live database file can come out of
// that inconsistent. backups/sqlite/account-YYYY-MM-DD.db, newest 14 kept.
const SNAPSHOT_DIR = path.join(DATA_DIR, 'backups', 'sqlite');
const SNAPSHOTS_KEPT = 14;

function snapshot(db) {
  fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
  const day = new Date().toISOString().slice(0, 10);
  return db
    .backup(path.join(SNAPSHOT_DIR, `account-${day}.db`))
    .then(() => {
      fs.readdirSync(SNAPSHOT_DIR)
        .filter((f) => /^account-\d{4}-\d{2}-\d{2}\.db$/.test(f))
        .sort()
        .slice(0, -SNAPSHOTS_KEPT)
        .forEach((f) => fs.unlinkSync(path.join(SNAPSHOT_DIR, f)));
    })
    .catch((err) => console.error(`[canopy-account] database snapshot failed: ${err.message}`));
}

// ---------------- Rows -> records ----------------

function shortName(p) {
  return `${p.first_name} ${(p.last_name || '').charAt(0).toUpperCase()}`.trim();
}

function personRow(p) {
  if (!p) return null;
  return {
    id: p.id,
    email: p.email,
    firstName: p.first_name,
    lastName: p.last_name,
    shortName: shortName(p),
    venmo: p.venmo || null,
    phone: p.phone || null,
    instagram: p.instagram || null,
    cashapp: p.cashapp || null,
    photoAt: p.photo_at || null,
    emailVerifiedAt: p.email_verified_at || null,
    findable: !!p.findable,
    createdAt: p.created_at,
    updatedAt: p.updated_at,
    passkeyCount: p.passkey_count
  };
}

function passkeyRow(r) {
  return {
    id: r.id,
    personId: r.person_id,
    publicKey: new Uint8Array(r.public_key),
    counter: r.counter,
    transports: r.transports ? JSON.parse(r.transports) : undefined,
    deviceType: r.device_type || null,
    backedUp: !!r.backed_up,
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at || null
  };
}

// `cred` is registrationInfo.credential from @simplewebauthn/server, plus
// deviceType/backedUp from the same result.
function passkeyParams(personId, cred) {
  return {
    id: cred.id,
    person_id: personId,
    public_key: Buffer.from(cred.publicKey),
    counter: cred.counter || 0,
    transports: cred.transports ? JSON.stringify(cred.transports) : null,
    device_type: cred.deviceType || null,
    backed_up: cred.backedUp ? 1 : 0,
    now: Date.now()
  };
}

// What a person's list of their sessions calls one: never the hash
// itself, which is the key to the row (and salts its emailed codes). It
// changes when the token does, which is only ever at sign-in.
function sessionPublicId(idHash) {
  return sha256(`session:${idHash}`).slice(0, 24);
}

function sessionRow(s) {
  if (!s) return null;
  return {
    idHash: s.id_hash,
    publicId: sessionPublicId(s.id_hash),
    personId: s.person_id || null,
    createdAt: s.created_at,
    lastSeenAt: s.last_seen_at,
    cookieSetAt: s.cookie_set_at,
    adminSetupAt: s.admin_setup_at || null,
    reauthAt: s.reauth_at || null,
    clientKind: s.client_kind || null,
    clientName: s.client_name || null,
    signedInAt: s.signed_in_at || null
  };
}

function appRow(a) {
  if (!a) return null;
  return {
    id: a.id,
    name: a.name,
    createdAt: a.created_at,
    lastUsedAt: a.last_used_at || null,
    revokedAt: a.revoked_at || null,
    allowsUnverified: !!a.allows_unverified,
    allowsLookup: !!a.allows_lookup
  };
}

// ---------------- The store ----------------

// Opens (and if need be, creates) the database. `file` is for tests; the
// server uses DATA_DIR/account.db. Throws if it's at
// a schema version this code doesn't open.
function init({ file = DB_FILE, snapshots = true } = {}) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = open(file);
  prepareSchema(db);

  if (snapshots) {
    snapshot(db);
    setInterval(() => snapshot(db), 24 * 60 * 60 * 1000).unref();
  }

  const q = {
    adminPerson: db.prepare("SELECT value FROM meta WHERE key = 'admin_person_id'"),
    setAdminPerson: db.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES ('admin_person_id', ?)"),
    clearAdminPerson: db.prepare("DELETE FROM meta WHERE key = 'admin_person_id'"),

    person: db.prepare('SELECT * FROM people WHERE id = ?'),
    personByEmail: db.prepare('SELECT * FROM people WHERE email = ?'),
    people: db.prepare(`
      SELECT p.*, (SELECT COUNT(*) FROM passkeys k WHERE k.person_id = p.id) AS passkey_count
      FROM people p ORDER BY p.first_name COLLATE NOCASE, p.last_name COLLATE NOCASE`),
    insertPerson: db.prepare(`
      INSERT INTO people (id, email, first_name, last_name, venmo, email_verified_at, findable, created_at, updated_at)
      VALUES (@id, @email, @first_name, @last_name, @venmo, @email_verified_at, @findable, @now, @now)`),
    renamePerson: db.prepare('UPDATE people SET first_name = ?, last_name = ?, updated_at = ? WHERE id = ?'),
    setVenmo: db.prepare('UPDATE people SET venmo = ?, updated_at = ? WHERE id = ?'),
    setPhone: db.prepare('UPDATE people SET phone = ?, updated_at = ? WHERE id = ?'),
    setInstagram: db.prepare('UPDATE people SET instagram = ?, updated_at = ? WHERE id = ?'),
    setCashapp: db.prepare('UPDATE people SET cashapp = ?, updated_at = ? WHERE id = ?'),
    setFindable: db.prepare('UPDATE people SET findable = ?, updated_at = ? WHERE id = ?'),
    // At most 2: whether there's exactly one is all the lookup needs.
    findableByPhone: db.prepare('SELECT * FROM people WHERE phone = ? AND findable = 1 LIMIT 2'),
    findableByInstagram: db.prepare('SELECT * FROM people WHERE instagram = ? AND findable = 1 LIMIT 2'),
    setPhoto: db.prepare('UPDATE people SET photo_at = ?, updated_at = ? WHERE id = ?'),
    setEmailVerified: db.prepare('UPDATE people SET email_verified_at = ? WHERE id = ?'),
    // What a takeover clears: everything whoever made the account typed in
    // about themselves, except the name.
    clearSquatted: db.prepare(`UPDATE people SET phone = NULL, instagram = NULL, venmo = NULL, cashapp = NULL,
      photo_at = NULL, findable = ?, updated_at = ? WHERE id = ?`),
    setEmail: db.prepare('UPDATE people SET email = ?, email_verified_at = NULL, updated_at = ? WHERE id = ?'),
    deletePerson: db.prepare('DELETE FROM people WHERE id = ?'),

    passkey: db.prepare('SELECT * FROM passkeys WHERE id = ?'),
    passkeysOf: db.prepare('SELECT * FROM passkeys WHERE person_id = ? ORDER BY created_at'),
    insertPasskey: db.prepare(`
      INSERT INTO passkeys (id, person_id, public_key, counter, transports, device_type, backed_up, created_at)
      VALUES (@id, @person_id, @public_key, @counter, @transports, @device_type, @backed_up, @now)`),
    usePasskey: db.prepare('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?'),
    deletePasskey: db.prepare('DELETE FROM passkeys WHERE id = ? AND person_id = ?'),
    deletePasskeysOf: db.prepare('DELETE FROM passkeys WHERE person_id = ?'),

    session: db.prepare('SELECT * FROM sessions WHERE id_hash = ?'),
    insertSession: db.prepare(`INSERT INTO sessions (id_hash, created_at, last_seen_at, cookie_set_at, client_kind, client_name)
      VALUES (?, ?, ?, ?, ?, ?)`),
    sessionsOf: db.prepare('SELECT * FROM sessions WHERE person_id = ? ORDER BY last_seen_at DESC'),
    markSignedIn: db.prepare('UPDATE sessions SET client_kind = ?, client_name = ?, signed_in_at = ? WHERE id_hash = ?'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE id_hash = ?'),
    deleteSessionsOf: db.prepare('DELETE FROM sessions WHERE person_id = ?'),
    deleteOtherSessionsOf: db.prepare('DELETE FROM sessions WHERE person_id = ? AND id_hash != ?'),
    touchSession: db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?'),
    cookieSet: db.prepare('UPDATE sessions SET cookie_set_at = ? WHERE id_hash = ?'),
    rekeySession: db.prepare('UPDATE sessions SET id_hash = ?, cookie_set_at = ? WHERE id_hash = ?'),
    setSessionPerson: db.prepare(`UPDATE sessions SET person_id = ?, verified_email = NULL, verified_at = NULL,
      code_hash = NULL, code_email = NULL, code_at = NULL, code_tries = 0 WHERE id_hash = ?`),
    setPending: db.prepare(`UPDATE sessions SET pending_challenge = @challenge, pending_kind = @kind,
      pending_person_id = @person_id, pending_profile = @profile, pending_at = @at WHERE id_hash = @id_hash`),
    clearPending: db.prepare(`UPDATE sessions SET pending_challenge = NULL, pending_kind = NULL,
      pending_person_id = NULL, pending_profile = NULL, pending_at = NULL WHERE id_hash = ?`),
    setAdminSetup: db.prepare('UPDATE sessions SET admin_setup_at = ? WHERE id_hash = ?'),
    setReauth: db.prepare('UPDATE sessions SET reauth_at = ? WHERE id_hash = ?'),
    setCode: db.prepare(`UPDATE sessions SET code_hash = ?, code_email = ?, code_at = ?, code_tries = 0,
      verified_email = NULL, verified_at = NULL WHERE id_hash = ?`),
    failCode: db.prepare('UPDATE sessions SET code_tries = code_tries + 1 WHERE id_hash = ?'),
    passCode: db.prepare(`UPDATE sessions SET code_hash = NULL, code_email = NULL, code_at = NULL, code_tries = 0,
      verified_email = ?, verified_at = ? WHERE id_hash = ?`),
    pruneSessions: db.prepare(`DELETE FROM sessions WHERE last_seen_at < @signed
      OR (person_id IS NULL AND last_seen_at < @unsigned)`),

    setupLink: db.prepare('SELECT * FROM setup_links WHERE code_hash = ?'),
    insertSetupLink: db.prepare('INSERT INTO setup_links (code_hash, person_id, created_at, expires_at) VALUES (?, ?, ?, ?)'),
    useSetupLink: db.prepare('UPDATE setup_links SET used_at = ? WHERE code_hash = ? AND used_at IS NULL'),
    // A new link replaces any the person still had: only the latest one
    // the admin sent works.
    retireSetupLinksOf: db.prepare('UPDATE setup_links SET used_at = ? WHERE person_id = ? AND used_at IS NULL'),
    pruneSetupLinks: db.prepare('DELETE FROM setup_links WHERE expires_at < ?'),

    apps: db.prepare('SELECT * FROM apps ORDER BY created_at'),
    app: db.prepare('SELECT * FROM apps WHERE id = ?'),
    appByName: db.prepare('SELECT * FROM apps WHERE name = ?'),
    appByKey: db.prepare('SELECT * FROM apps WHERE key_hash = ? AND revoked_at IS NULL'),
    insertApp: db.prepare('INSERT INTO apps (id, name, key_hash, created_at) VALUES (?, ?, ?, ?)'),
    rekeyApp: db.prepare('UPDATE apps SET key_hash = ?, revoked_at = NULL WHERE id = ?'),
    revokeApp: db.prepare('UPDATE apps SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL'),
    touchApp: db.prepare('UPDATE apps SET last_used_at = ? WHERE id = ?'),
    setAppAllowsUnverified: db.prepare('UPDATE apps SET allows_unverified = ? WHERE id = ?'),
    setAppAllowsLookup: db.prepare('UPDATE apps SET allows_lookup = ? WHERE id = ?')
  };

  function prune() {
    const now = Date.now();
    q.pruneSessions.run({ signed: now - SESSION_TTL_MS, unsigned: now - UNSIGNED_SESSION_TTL_MS });
    q.pruneSetupLinks.run(now - 30 * 24 * 60 * 60 * 1000);
  }
  prune();
  setInterval(prune, 60 * 60 * 1000).unref();

  function adminPersonId() {
    const row = q.adminPerson.get();
    return row ? row.value : null;
  }

  // A session row by its cookie token, or null if there's none or it's
  // run out (see SESSION_TTL_MS).
  function liveSession(idHash) {
    const s = q.session.get(idHash);
    if (!s) return null;
    const ttl = s.person_id ? SESSION_TTL_MS : UNSIGNED_SESSION_TTL_MS;
    if (Date.now() - s.last_seen_at > ttl) {
      q.deleteSession.run(idHash);
      return null;
    }
    return s;
  }

  // A new one-time link code for `personId`. Any earlier link of theirs
  // stops working. Only the hash is kept.
  function createSetupLink(personId) {
    const code = randomToken();
    const now = Date.now();
    q.retireSetupLinksOf.run(now, personId);
    q.insertSetupLink.run(sha256(code), personId, now, now + SETUP_LINK_TTL_MS);
    return code;
  }

  return {
    db,
    sha256,

    // ---- The admin ----

    getAdminPersonId: adminPersonId,

    setAdminPersonId(id) {
      if (!q.person.get(id)) return false;
      q.setAdminPerson.run(id);
      return true;
    },

    // ---- People ----

    getPerson(id) {
      return personRow(q.person.get(String(id || '')));
    },

    getPersonByEmail(email) {
      return personRow(q.personByEmail.get(String(email || '')));
    },

    listPeople() {
      return q.people.all().map(personRow);
    },

    // The ones of `ids` that exist. Anyone missing has been deleted: the
    // site asking shows them as a former member.
    peopleByIds(ids) {
      return ids.map((id) => q.person.get(id)).filter(Boolean).map(personRow);
    },

    // A brand-new profile and its first passkey, together -- the profile
    // doesn't exist until there's a way to sign into it. Conflict if the
    // email was taken in the meantime. `id` is chosen up front: it's the
    // passkey's user handle. Made from a proven email it's verified from
    // the start; a quick sign-up (`unverified`) isn't, until a code.
    createPersonWithPasskey({ id, email, firstName, lastName, venmo, unverified }, cred) {
      return db.transaction(() => {
        if (q.personByEmail.get(email) || q.person.get(id)) return { ok: false, reason: 'conflict' };
        const now = Date.now();
        q.insertPerson.run({
          id, email, first_name: firstName, last_name: lastName, venmo: venmo || null,
          email_verified_at: unverified ? null : now, findable: FINDABLE_BY_DEFAULT ? 1 : 0, now
        });
        q.insertPasskey.run(passkeyParams(id, cred));
        return { ok: true, person: personRow(q.person.get(id)) };
      })();
    },

    renamePerson(id, firstName, lastName) {
      if (!q.renamePerson.run(firstName, lastName, Date.now(), id).changes) return null;
      return personRow(q.person.get(id));
    },

    // `venmo` is already cleaned (server.js); null clears it.
    setPersonVenmo(id, venmo) {
      q.setVenmo.run(venmo || null, Date.now(), id);
      return personRow(q.person.get(id));
    },

    // `phone` is already cleaned (server.js); null clears it.
    setPersonPhone(id, phone) {
      q.setPhone.run(phone || null, Date.now(), id);
      return personRow(q.person.get(id));
    },

    // Both already cleaned (server.js); null clears them.
    setPersonInstagram(id, instagram) {
      q.setInstagram.run(instagram || null, Date.now(), id);
      return personRow(q.person.get(id));
    },

    setPersonCashapp(id, cashapp) {
      q.setCashapp.run(cashapp || null, Date.now(), id);
      return personRow(q.person.get(id));
    },

    setPersonFindable(id, findable) {
      q.setFindable.run(findable ? 1 : 0, Date.now(), id);
      return personRow(q.person.get(id));
    },

    // The one person who can be found by exactly this phone number or
    // Instagram (already cleaned, server.js), or null: nobody, someone who
    // turned it off, more than one account claiming it, or an account whose
    // email isn't proven. Both are typed in by their owners and proven by
    // nothing, so when two accounts claim the same one, either answer could
    // be the wrong person; there isn't one. An unverified account is never
    // the answer (anyone can make one, with anyone's name and number, in a
    // minute), but its claim still counts as the second: it may be the real
    // owner's, and the verified one the impostor. See "Finding people" in
    // the README.
    findPerson({ phone, instagram }) {
      const rows = phone ? q.findableByPhone.all(phone) : instagram ? q.findableByInstagram.all(instagram) : [];
      return rows.length === 1 && rows[0].email_verified_at ? personRow(rows[0]) : null;
    },

    setPersonPhoto(id, at) {
      q.setPhoto.run(at, Date.now(), id);
      return personRow(q.person.get(id));
    },

    // A new email for someone. Unverified until they type a code at it
    // (the profile's own change marks it verified right after; the
    // admin's edit leaves it unverified). Conflict if it's someone else's.
    setPersonEmail(id, email) {
      return db.transaction(() => {
        const p = q.person.get(id);
        if (!p) return { ok: false, reason: 'not_found' };
        if (p.email === email) return { ok: true };
        if (q.personByEmail.get(email)) return { ok: false, reason: 'conflict' };
        q.setEmail.run(email, Date.now(), id);
        return { ok: true };
      })();
    },

    markEmailVerified(id) {
      q.setEmailVerified.run(Date.now(), id);
    },

    // A passkey for someone whose email a code just proved, from a browser
    // that wasn't signed in as them (signing in by code). If the email
    // wasn't proven before, whoever already had a way in never showed they
    // own the inbox -- a quick sign-up can be made with anyone's email --
    // so their passkeys go and every session is signed out, and the inbox
    // owner is left holding the only passkey. `idHash` is the browser doing
    // it, which stays. What they typed in goes too: the phone and Instagram
    // (which the lookup finds people by), Venmo and Cash App (where friends
    // would send money), the photo, and the findable switch, back to the
    // default. The name stays, for the owner to check on their profile
    // (server.js sends them there); the photo's file is server.js's to
    // delete. `tookOver` says whether all that happened.
    addPasskeyProvingEmail(personId, cred, idHash) {
      return db.transaction(() => {
        const p = q.person.get(personId);
        if (!p) return { ok: false };
        const tookOver = !p.email_verified_at;
        if (tookOver) {
          q.deletePasskeysOf.run(personId);
          q.deleteOtherSessionsOf.run(personId, idHash);
          q.clearSquatted.run(FINDABLE_BY_DEFAULT ? 1 : 0, Date.now(), personId);
        }
        q.insertPasskey.run(passkeyParams(personId, cred));
        q.setEmailVerified.run(Date.now(), personId);
        return { ok: true, tookOver };
      })();
    },

    // Their passkeys, sessions and setup links go with them (ON DELETE
    // CASCADE). Every site keeps its own records under their id and shows
    // them as a former member.
    deletePerson(id) {
      return db.transaction(() => {
        if (adminPersonId() === id) q.clearAdminPerson.run();
        return q.deletePerson.run(id).changes > 0;
      })();
    },

    // ---- Passkeys ----

    // { id, personId, publicKey (Uint8Array), counter, transports[], ... }, or null.
    getPasskey(id) {
      const r = q.passkey.get(String(id || ''));
      return r ? passkeyRow(r) : null;
    },

    passkeysOf(personId) {
      return q.passkeysOf.all(personId).map(passkeyRow);
    },

    addPasskey(personId, cred) {
      q.insertPasskey.run(passkeyParams(personId, cred));
    },

    usePasskey(id, counter) {
      q.usePasskey.run(counter, Date.now(), id);
    },

    // One of their own, from the profile page. Never the last one: that's
    // the only way into the account from this browser's next session
    // without an emailed code.
    removePasskey(personId, passkeyId) {
      return db.transaction(() => {
        const mine = q.passkeysOf.all(personId);
        if (!mine.some((k) => k.id === passkeyId)) return { ok: false, reason: 'not_found' };
        if (mine.length === 1) return { ok: false, reason: 'last_passkey' };
        q.deletePasskey.run(passkeyId, personId);
        return { ok: true };
      })();
    },

    // Lost phone: their passkeys go, they're signed out everywhere, and a
    // fresh setup link (the only one that works) comes back for the admin
    // to send them. They can also get back in with an emailed code.
    resetPasskeys(personId) {
      return db.transaction(() => {
        if (!q.person.get(personId)) return { ok: false, reason: 'not_found' };
        q.deletePasskeysOf.run(personId);
        q.deleteSessionsOf.run(personId);
        return { ok: true, code: createSetupLink(personId) };
      })();
    },

    // ---- Sessions ----

    // A new session: { token, session }. The token goes in the cookie (or
    // an app's keychain) and is never stored. An app says what it is up
    // front (`client`: { kind, name }); a browser is labelled when it
    // signs in.
    createSession(client) {
      const token = randomToken();
      const idHash = sha256(token);
      const now = Date.now();
      q.insertSession.run(idHash, now, now, now, (client && client.kind) || null, (client && client.name) || null);
      return { token, session: sessionRow(q.session.get(idHash)) };
    },

    getSessionByToken(token) {
      if (typeof token !== 'string' || !token) return null;
      return sessionRow(liveSession(sha256(token)));
    },

    // Seen now. Written at most once a minute per session.
    touchSession(idHash, lastSeenAt) {
      const now = Date.now();
      if (now - lastSeenAt > 60 * 1000) q.touchSession.run(now, idHash);
    },

    cookieRenewed(idHash) {
      q.cookieSet.run(Date.now(), idHash);
    },

    // The same session under a new token, so a token anyone saw before
    // sign-in is worthless after it. Returns the new token.
    rotateSession(idHash) {
      const token = randomToken();
      q.rekeySession.run(sha256(token), Date.now(), idHash);
      return { token, idHash: sha256(token) };
    },

    signIn(idHash, personId) {
      q.setSessionPerson.run(personId, idHash);
    },

    // Just signed in, as this browser or app (`client`: { kind, name }).
    markSignedIn(idHash, client) {
      q.markSignedIn.run((client && client.kind) || null, (client && client.name) || null, Date.now(), idHash);
    },

    // Everywhere someone is signed in, most recently seen first. Run-out
    // ones are left out (and go, the way liveSession drops them).
    sessionsOf(personId) {
      return q.sessionsOf.all(personId).map((s) => sessionRow(liveSession(s.id_hash))).filter(Boolean);
    },

    // Signing out ends the session itself, on every Canopy site at once.
    endSession(idHash) {
      q.deleteSession.run(idHash);
    },

    // One of their own, by the id their list shows. The session it was, or
    // null if it isn't theirs.
    endSessionOf(personId, publicId) {
      const s = q.sessionsOf.all(personId).find((r) => sessionPublicId(r.id_hash) === publicId);
      if (!s) return null;
      q.deleteSession.run(s.id_hash);
      return sessionRow(s);
    },

    // Signed out everywhere: every browser and every app.
    endSessionsOf(personId) {
      return q.deleteSessionsOf.run(personId).changes;
    },

    setPending(idHash, { challenge, kind, personId, profile }) {
      q.setPending.run({
        id_hash: idHash, challenge, kind, person_id: personId || null,
        profile: profile ? JSON.stringify(profile) : null, at: Date.now()
      });
    },

    // The ceremony on this browser, read and cleared in one go: a
    // challenge is good for one try.
    takePending(idHash) {
      return db.transaction(() => {
        const s = q.session.get(idHash);
        q.clearPending.run(idHash);
        if (!s || !s.pending_challenge) return null;
        return {
          challenge: s.pending_challenge,
          kind: s.pending_kind,
          personId: s.pending_person_id,
          profile: s.pending_profile ? JSON.parse(s.pending_profile) : null,
          at: s.pending_at
        };
      })();
    },

    // The person signed in on this session just confirmed it with a
    // passkey; null clears it (spent).
    setReauth(idHash, at) {
      q.setReauth.run(at, idHash);
    },

    grantAdminSetup(idHash) {
      q.setAdminSetup.run(Date.now(), idHash);
    },

    // When it was (ms), or null -- and cleared: one use.
    takeAdminSetup(idHash) {
      return db.transaction(() => {
        const s = q.session.get(idHash);
        q.setAdminSetup.run(null, idHash);
        return s && s.admin_setup_at ? s.admin_setup_at : null;
      })();
    },

    // ---- Emailed codes ----

    // A fresh 6-digit code for `email` on this session, replacing any
    // earlier one. Returns the code to send.
    issueEmailCode(idHash, email) {
      const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
      q.setCode.run(sha256(`${idHash}:${code}`), email, Date.now(), idHash);
      return code;
    },

    // 'ok' (with the email it proved), 'wrong', or 'expired' -- the last
    // also once it's had CODE_MAX_TRIES wrong guesses, after which only a
    // new code works.
    checkEmailCode(idHash, code) {
      return db.transaction(() => {
        const s = q.session.get(idHash);
        if (!s || !s.code_hash || Date.now() - s.code_at > CODE_TTL_MS || s.code_tries >= CODE_MAX_TRIES) {
          return { outcome: 'expired' };
        }
        const expected = Buffer.from(s.code_hash, 'hex');
        const given = Buffer.from(sha256(`${idHash}:${String(code || '').trim()}`), 'hex');
        if (!crypto.timingSafeEqual(expected, given)) {
          q.failCode.run(idHash);
          return { outcome: 'wrong' };
        }
        q.passCode.run(s.code_email, Date.now(), idHash);
        return { outcome: 'ok', email: s.code_email };
      })();
    },

    // The email this session's waiting code was sent to, or null.
    codeEmail(idHash) {
      const s = q.session.get(idHash);
      return s && s.code_hash ? s.code_email : null;
    },

    // Proving an email without a code: the setup password stands in for
    // it on first run and in recovery (server.js decides when).
    setVerifiedEmail(idHash, email) {
      q.passCode.run(email, Date.now(), idHash);
    },

    // The email this browser has proven in the last 15 minutes, or null.
    verifiedEmail(idHash) {
      const s = q.session.get(idHash);
      if (!s || !s.verified_email || Date.now() - s.verified_at > VERIFIED_EMAIL_TTL_MS) return null;
      return s.verified_email;
    },

    // ---- Setup links ----

    createSetupLink,

    // { person, codeHash, expiresAt } for a link that still works, or
    // null.
    getSetupLink(code) {
      if (typeof code !== 'string' || !code || code.length > 100) return null;
      const l = q.setupLink.get(sha256(code));
      if (!l || l.used_at || Date.now() > l.expires_at) return null;
      const person = personRow(q.person.get(l.person_id));
      return person ? { person, codeHash: l.code_hash, expiresAt: l.expires_at } : null;
    },

    // Spends it, by the hash getSetupLink gave (the code itself isn't
    // kept, even while a passkey is being made). False if it was spent or
    // ran out in the meantime, or isn't this person's.
    useSetupLink(codeHash, personId) {
      return db.transaction(() => {
        const l = q.setupLink.get(String(codeHash || ''));
        if (!l || l.used_at || Date.now() > l.expires_at || l.person_id !== personId) return false;
        return q.useSetupLink.run(Date.now(), l.code_hash).changes > 0;
      })();
    },

    // ---- Sites ----

    listApps() {
      return q.apps.all().map(appRow);
    },

    // A new site and its key, shown once: { app, key }. Conflict if the
    // name is taken.
    createApp(name) {
      return db.transaction(() => {
        if (q.appByName.get(name)) return { ok: false, reason: 'conflict' };
        const id = crypto.randomUUID();
        const key = `cnp_${randomToken()}`;
        q.insertApp.run(id, name, sha256(key), Date.now());
        return { ok: true, app: appRow(q.app.get(id)), key };
      })();
    },

    // A new key for an existing site; the old one stops working.
    rekeyApp(id) {
      const key = `cnp_${randomToken()}`;
      if (!q.rekeyApp.run(sha256(key), id).changes) return null;
      return { app: appRow(q.app.get(id)), key };
    },

    revokeApp(id) {
      return q.revokeApp.run(Date.now(), id).changes > 0;
    },

    // The admin's switches for a site; the site after, or null.
    setAppSettings(id, { allowsUnverified, allowsLookup }) {
      if (!q.app.get(id)) return null;
      if (allowsUnverified !== undefined) q.setAppAllowsUnverified.run(allowsUnverified ? 1 : 0, id);
      if (allowsLookup !== undefined) q.setAppAllowsLookup.run(allowsLookup ? 1 : 0, id);
      return appRow(q.app.get(id));
    },

    // The site whose key this is, if it hasn't been cut off.
    appByKey(key) {
      if (typeof key !== 'string' || !key) return null;
      const a = q.appByKey.get(sha256(key));
      if (!a) return null;
      if (!a.last_used_at || Date.now() - a.last_used_at > 60 * 1000) q.touchApp.run(Date.now(), a.id);
      return appRow(a);
    }
  };
}

module.exports = { init, DB_FILE, SCHEMA_VERSION, SESSION_TTL_MS, FINDABLE_BY_DEFAULT };
