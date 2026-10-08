// Contact details at rest: every email, phone number, Instagram, Venmo and
// Cash App in account.db is encrypted, and the ones looked up by exact
// value (email, phone, Instagram) also have a keyed hash beside them to
// look them up by. So a copy of the database -- a snapshot, a Coolify
// backup, a file pulled down to look at something -- has none of them in
// it. What this doesn't protect against is someone on the live server: the
// keys are in its environment. See "Contact details at rest" in the README.
//
// ---- Sealed values ----
//
//   v1:<keyId>:<nonce>:<ciphertext and tag>
//
// AES-256-GCM, a fresh random 12-byte nonce for every value, the nonce and
// the ciphertext (with GCM's 16-byte tag on the end) in base64url. The
// kind of value ('email', 'phone', ...) is the additional data, so a value
// can't be moved into a column for another kind and still open. `keyId`
// says which key sealed it, so keys can be rotated: CONTACT_ENCRYPTION_KEYS
// is a list, the first one seals and any of them opens (lib/db.js re-seals
// what's under an older one at startup).
//
// ---- Lookup hashes ----
//
// HMAC-SHA256 of '<kind>:<value>', with LOOKUP_HMAC_KEY (a separate key), in
// base64url, of the same cleaned value the profile stores ('+14155551234',
// 'ana.lima', 'ana@example.com'). Equal values give equal hashes, which is
// all a lookup, a uniqueness check or a count of duplicates needs. Without
// the key, a hash can't be checked against a guess; with it (on the live
// server) a phone number's can be, since there are few enough numbers to
// try them all. That's the same line as above.
//
// ---- The keys ----
//
//   CONTACT_ENCRYPTION_KEYS=<id>:<base64 of 32 bytes>[,<id>:<key>...]
//   LOOKUP_HMAC_KEY=<base64 of at least 32 bytes>
//
// Made with `openssl rand -base64 32`. An id is letters, digits, - and _.

const crypto = require('crypto');

const VERSION = 'v1';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const ID_RE = /^[A-Za-z0-9_-]{1,32}$/;
const SEALED_RE = /^v1:([A-Za-z0-9_-]{1,32}):([A-Za-z0-9_-]+):([A-Za-z0-9_-]+)$/;

function decodeKey(text) {
  const t = String(text || '').trim();
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(t)) return null;
  return Buffer.from(t.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

// CONTACT_ENCRYPTION_KEYS -> [{ id, key }], the first one current. Throws,
// saying what's wrong (never the key), on anything malformed.
function parseEncryptionKeys(text) {
  const keys = String(text || '').split(',').map((s) => s.trim()).filter(Boolean).map((entry, i) => {
    const colon = entry.indexOf(':');
    const id = colon > 0 ? entry.slice(0, colon) : '';
    const key = colon > 0 ? decodeKey(entry.slice(colon + 1)) : null;
    if (!ID_RE.test(id)) throw new Error(`CONTACT_ENCRYPTION_KEYS: entry ${i + 1} should be <id>:<base64 key>, the id letters, digits, - and _`);
    if (!key || key.length !== 32) throw new Error(`CONTACT_ENCRYPTION_KEYS: the key "${id}" should be 32 bytes, base64 (openssl rand -base64 32)`);
    return { id, key };
  });
  if (!keys.length) throw new Error('CONTACT_ENCRYPTION_KEYS is empty');
  const ids = keys.map((k) => k.id);
  if (new Set(ids).size !== ids.length) throw new Error('CONTACT_ENCRYPTION_KEYS: each key needs its own id');
  return keys;
}

function parseHmacKey(text) {
  const key = decodeKey(text);
  if (!key || key.length < 32) throw new Error('LOOKUP_HMAC_KEY should be at least 32 bytes, base64 (openssl rand -base64 32)');
  return key;
}

// The sealer and hasher for these keys. `keys` is [{ id, key }] (the first
// seals), `hmacKey` a Buffer.
function createContactCrypto({ keys, hmacKey, generated = false }) {
  const byId = new Map(keys.map((k) => [k.id, k.key]));
  const current = keys[0];
  // How many values couldn't be opened, and whether that's been said: a
  // value under a key that's gone reads as null (see the README's "If the
  // keys are lost") rather than failing every request that touches it.
  let unreadable = 0;
  let warned = false;

  function seal(kind, plaintext) {
    if (plaintext == null || plaintext === '') return null;
    const nonce = crypto.randomBytes(NONCE_BYTES);
    const cipher = crypto.createCipheriv('aes-256-gcm', current.key, nonce);
    cipher.setAAD(Buffer.from(kind));
    const body = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final(), cipher.getAuthTag()]);
    return `${VERSION}:${current.id}:${nonce.toString('base64url')}:${body.toString('base64url')}`;
  }

  function cantOpen(why) {
    unreadable++;
    if (!warned) {
      warned = true;
      console.error(`[canopy-account] a contact detail couldn't be decrypted (${why}); it reads as empty. See README.md > Contact details at rest.`);
    }
    return null;
  }

  // The plaintext, or null: for null, and for a value this can't open (a
  // key that isn't in the list, or one that fails its tag). Anything that
  // isn't a sealed value at all is a bug, and throws.
  function open(kind, sealed) {
    if (sealed == null) return null;
    const m = SEALED_RE.exec(String(sealed));
    if (!m) throw new Error(`a ${kind} in the database isn't sealed`);
    const key = byId.get(m[1]);
    if (!key) return cantOpen(`its key "${m[1]}" isn't in CONTACT_ENCRYPTION_KEYS`);
    try {
      const nonce = Buffer.from(m[2], 'base64url');
      const body = Buffer.from(m[3], 'base64url');
      if (nonce.length !== NONCE_BYTES || body.length < TAG_BYTES) return cantOpen('it is malformed');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
      decipher.setAAD(Buffer.from(kind));
      decipher.setAuthTag(body.subarray(body.length - TAG_BYTES));
      return Buffer.concat([decipher.update(body.subarray(0, body.length - TAG_BYTES)), decipher.final()]).toString('utf8');
    } catch (e) {
      return cantOpen('it failed its check');
    }
  }

  function hash(kind, value) {
    if (value == null || value === '') return null;
    return crypto.createHmac('sha256', hmacKey).update(`${kind}:${value}`).digest('base64url');
  }

  // The id of the key a sealed value is under, or null.
  function keyIdOf(sealed) {
    const m = SEALED_RE.exec(String(sealed || ''));
    return m ? m[1] : null;
  }

  return {
    seal,
    open,
    hash,
    keyIdOf,
    currentKeyId: current.id,
    keyIds: keys.map((k) => k.id),
    hasKey: (id) => byId.has(id),
    // Stored in meta, to notice LOOKUP_HMAC_KEY changing (lib/db.js then
    // works every hash out again).
    hmacCheck: () => hash('check', 'canopy-lookup-key'),
    // True when the keys were made up for this run (none were set).
    generated,
    unreadableCount: () => unreadable
  };
}

// The keys from the environment. Unset (both of them), it makes throwaway
// ones for this run and prints them, the way ADMIN_PASSWORD does: fine
// for development and a brand-new install, and lib/db.js refuses to start
// a production server on them once there's anyone in the database. Only
// one of the two set, or either malformed, throws: that's a mistake, not
// a fresh install.
function fromEnv(env = process.env) {
  const keysText = env.CONTACT_ENCRYPTION_KEYS;
  const hmacText = env.LOOKUP_HMAC_KEY;
  if (keysText || hmacText) {
    if (!keysText) throw new Error('LOOKUP_HMAC_KEY is set but CONTACT_ENCRYPTION_KEYS isn\'t: set both (README.md > Contact details at rest)');
    if (!hmacText) throw new Error('CONTACT_ENCRYPTION_KEYS is set but LOOKUP_HMAC_KEY isn\'t: set both (README.md > Contact details at rest)');
    return createContactCrypto({ keys: parseEncryptionKeys(keysText), hmacKey: parseHmacKey(hmacText) });
  }
  const key = crypto.randomBytes(32).toString('base64');
  const hmac = crypto.randomBytes(32).toString('base64');
  const production = env.NODE_ENV === 'production';
  const say = (line) => console.warn(`[canopy-account] ${line}`);
  console.warn('');
  say(production
    ? '!!! CONTACT_ENCRYPTION_KEYS and LOOKUP_HMAC_KEY are not set. Made throwaway keys for this run:'
    : 'CONTACT_ENCRYPTION_KEYS and LOOKUP_HMAC_KEY not set. Made throwaway keys for this run:');
  say(`  CONTACT_ENCRYPTION_KEYS=run:${key}`);
  say(`  LOOKUP_HMAC_KEY=${hmac}`);
  say(production
    ? '!!! Set these (or your own) in Coolify NOW. Contact details saved under throwaway keys are lost at the next restart, and once there is anyone in the database the server will refuse to start without keys.'
    : 'Set them in your environment to keep what is encrypted readable after a restart.');
  console.warn('');
  return createContactCrypto({ keys: [{ id: 'run', key: Buffer.from(key, 'base64') }], hmacKey: Buffer.from(hmac, 'base64'), generated: true });
}

module.exports = { createContactCrypto, parseEncryptionKeys, parseHmacKey, fromEnv };
