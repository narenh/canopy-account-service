const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const webauthn = require('@simplewebauthn/server');

// A one-time import from tickets, when asked for (lib/startupImport.js).
// Before the store opens, so it's the first thing to touch the database.
if (process.env.IMPORT_FROM_TICKETS) require('./lib/startupImport').importFromTicketsAtStartup(process.env.IMPORT_FROM_TICKETS);

const store = require('./lib/db').init();
const photoStore = require('./lib/photoStore');
const { createImageStore } = require('./lib/uploadedImage');
const session = require('./lib/session');
const mailer = require('./lib/mailer');
const { attemptLimiter, guessLimits, clientIp } = require('./lib/limits');
const { BASE, isCanopyOrigin, safeReturn, passkeyRpId } = require('./lib/domain');

const logoImageStore = createImageStore('logo');
const backdropImageStore = createImageStore('backdrop');

const app = express();
const PORT = process.env.PORT || 3000;
const PRODUCTION = process.env.NODE_ENV === 'production';

// Coolify (and Cloudflare) terminate TLS in front of this container, so
// the request Express sees is plain HTTP; trusting the proxy makes
// req.protocol and req.hostname read what the visitor actually used.
app.set('trust proxy', true);
app.disable('x-powered-by');
app.use(express.json({ limit: '200kb' }));

// Express 4 doesn't catch a rejected promise from an async route: it
// becomes an unhandled rejection, and Node ends the process on one -- so a
// single request that made a database call throw took the whole service
// down. Every async route goes through this, which hands the error to
// Express instead (a 500 for that request, like a synchronous throw).
function handle(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function requireEnvPassword(envVar) {
  let value = process.env[envVar];
  if (!value) {
    value = crypto.randomBytes(9).toString('base64url');
    console.warn(`\n[canopy-account] ${envVar} not set. Generated a temporary setup password for this run:`);
    console.warn(`[canopy-account]   ${value}`);
    console.warn(`[canopy-account] Set ${envVar} in your environment to keep a stable one.\n`);
  }
  return value;
}

// The setup password: entered once on a brand-new install to make the
// admin account, and again only with ADMIN_RECOVERY=1 (see "The admin").
const ADMIN_PASSWORD = requireEnvPassword('ADMIN_PASSWORD');
const ADMIN_RECOVERY = process.env.ADMIN_RECOVERY === '1';

// Where this service is, as other sites should link to it: photo URLs
// handed to sites, setup links. A site asks over Coolify's network, so
// the request's own host can't be trusted to be the public one.
function publicBase(req) {
  if (process.env.PUBLIC_URL) return process.env.PUBLIC_URL.replace(/\/+$/, '');
  if (PRODUCTION) return `https://account.${BASE}`;
  return `${req.protocol}://${req.get('host')}`;
}

{
  const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
  const count = store.listPeople().length;
  console.log(`[canopy-account] DATA_DIR=${dataDir} (${count} people found on disk at startup)`);
  if (count === 0) {
    console.log(
      '[canopy-account] If you expected people here, DATA_DIR is probably NOT on a persistent volume -- ' +
        'see README.md > Deploying on Coolify.'
    );
  }
}

// ---------------- Headers every response gets ----------------
//
// No framing (the sign-in page in someone else's frame is how a click
// gets stolen), no MIME sniffing, and no full URLs in Referer -- a
// /setup/<code> page's address is a key.
app.use((req, res, next) => {
  res.set('X-Frame-Options', 'DENY');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'same-origin');
  next();
});

// ---------------- Changes only from Canopy pages ----------------
//
// Every request that changes something has to come from a page on
// canopysf.com or one of its subdomains, by its Origin header. The
// browser already keeps other websites from sending the cookie
// (SameSite=Lax); this covers Canopy's own subdomains, which count as the
// same site to the browser. Browsers send Origin on every POST, PATCH,
// PUT and DELETE, so a missing one is refused too.
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  if (isCanopyOrigin(req.get('origin'))) return next();
  res.status(403).json({ error: 'requests that change something must come from a Canopy page', reason: 'bad_origin' });
});

// ---------------- Passkey sign-in from other Canopy pages ----------------
//
// A Canopy site can run "Sign in with passkey" on its own page (tickets
// does) rather than sending people here: its page calls these two
// endpoints directly, with credentials, and the session cookie that comes
// back is the same one this page would set. The browser only allows that
// with CORS, which is given to Canopy pages (lib/domain.js) and nobody
// else, and only for these two. The passkey itself is checked against the
// page it was used on (ceremonyOrigin), which may be any Canopy page.
// Everything else -- email codes, sign-up, the profile -- stays here.
const CROSS_SITE_SIGN_IN = ['/api/auth/login/options', '/api/auth/login/verify'];

app.use(CROSS_SITE_SIGN_IN, (req, res, next) => {
  const origin = req.get('origin');
  res.vary('Origin');
  if (origin && isCanopyOrigin(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  if (req.method !== 'OPTIONS') return next();
  if (!isCanopyOrigin(origin)) return res.status(403).end();
  res.set('Access-Control-Allow-Methods', 'POST');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
  res.set('Access-Control-Max-Age', '600');
  res.status(204).end();
});

// ---------------- Sessions ----------------

// Finds this browser's session (from its cookie), making one if `create`
// is set. Puts req.sess (or null) and req.person (or null) on the request,
// and renews the cookie when it's due.
function attachSession(create) {
  return (req, res, next) => {
    req.sess = null;
    req.person = null;
    const token = session.readToken(req.headers.cookie);
    let s = token ? store.getSessionByToken(token) : null;
    if (s) {
      store.touchSession(s.idHash, s.lastSeenAt);
      if (session.needsRenewal(s)) {
        res.append('Set-Cookie', session.cookieHeader(token, req.hostname));
        store.cookieRenewed(s.idHash);
      }
    } else if (create) {
      const made = store.createSession();
      s = made.session;
      res.append('Set-Cookie', session.cookieHeader(made.token, req.hostname));
    }
    req.sess = s;
    req.person = s && s.personId ? store.getPerson(s.personId) : null;
    next();
  };
}

function photoUrlFor(req, person) {
  return person && person.photoAt ? `${publicBase(req)}/photo/${person.id}?v=${person.photoAt}` : null;
}

// ---------------- The admin ----------------
//
// The admin is a person like anyone else -- same passkey, same sign-in --
// marked in meta as admin_person_id. Only they open /admin.
//
// There is never an account without an admin. On a brand-new install
// (nothing imported) the sign-in page is only the setup password
// (ADMIN_PASSWORD), and the server refuses every other sign-in and
// sign-up until it's been entered; whoever then signs up on that browser
// is the admin. ADMIN_RECOVERY=1 opens the setup password again for an
// admin who has lost every passkey AND can't get the emailed code -- it
// adds a passkey to the admin's own account and nothing else.

const ADMIN_SETUP_MS = 15 * 60 * 1000;

function adminSetupOpen() {
  return ADMIN_RECOVERY || !store.getAdminPersonId();
}

function isAdmin(req) {
  return !!req.person && req.person.id === store.getAdminPersonId();
}

function hasAdminSetupGrant(req) {
  const at = req.sess && req.sess.adminSetupAt;
  return adminSetupOpen() && !!at && Date.now() - at < ADMIN_SETUP_MS;
}

// No admin yet: nothing but the setup password until it's been entered
// on this browser. Sends the refusal itself and returns false.
function accountsOpen(req, res) {
  if (store.getAdminPersonId() || hasAdminSetupGrant(req)) return true;
  res.status(403).json({ error: 'set up the admin account first', reason: 'setup_required' });
  return false;
}

function requireAdmin(req, res, next) {
  attachSession(false)(req, res, () => {
    if (isAdmin(req)) return next();
    res.status(401).json({ error: 'unauthorized' });
  });
}

function requireSignedIn(req, res, next) {
  attachSession(false)(req, res, () => {
    if (req.person) return next();
    res.status(401).json({ error: 'unauthorized' });
  });
}

// ---------------- Cleaning what people type ----------------

// One @, a dot after it, and none of the characters that mean something
// in an address list: nodemailer reads "a,b@x.com" as two recipients and
// "x<me@evil.example>" as me@evil.example, so allowing them would send
// the code somewhere other than the address it then counts as proven.
const EMAIL_RE = /^[^\s@,;:<>()[\]\\"]+@[^\s@,;:<>()[\]\\"]+\.[^\s@,;:<>()[\]\\"]+$/;
function cleanEmail(raw) {
  const email = String(raw || '').trim().toLowerCase().slice(0, 200);
  return EMAIL_RE.test(email) ? email : null;
}

function cleanNames(body) {
  const firstName = String(body.firstName || '').trim().replace(/\s+/g, ' ').slice(0, 60);
  const lastName = String(body.lastName || '').trim().replace(/\s+/g, ' ').slice(0, 60);
  if (!firstName || !lastName) return { error: 'first and last name are both required' };
  return { firstName, lastName };
}

// A Venmo username: letters, digits, - or _, at most 30. A leading @ is
// dropped in case one gets pasted in. Empty clears it (null); anything
// else invalid is false.
function cleanVenmo(raw) {
  const v = String(raw == null ? '' : raw).trim().replace(/^@+/, '');
  if (!v) return null;
  return /^[A-Za-z0-9_-]{1,30}$/.test(v) ? v : false;
}

const BAD_VENMO = { error: 'a Venmo username is letters, numbers, - and _ only', reason: 'bad_venmo' };

// A phone number, as +<country code><number> (E.164). Spaces, dashes,
// dots and brackets are dropped. With no + it's a US/Canada number: 10
// digits, or 11 starting with 1, and the area code and exchange can't
// start with 0 or 1 (the North American plan). With a +, 8 to 15 digits
// (E.164's range), and a +1 number gets the same North American checks.
// Empty clears it (null); anything else invalid is false.
function cleanPhone(raw) {
  const v = String(raw == null ? '' : raw).trim();
  if (!v) return null;
  if (!/^\+?[\d\s().-]+$/.test(v)) return false;
  let digits = v.replace(/\D/g, '');
  if (!v.startsWith('+')) {
    if (digits.length === 10) digits = '1' + digits;
    else if (!(digits.length === 11 && digits[0] === '1')) return false;
  }
  if (digits.length < 8 || digits.length > 15 || digits[0] === '0') return false;
  if (digits[0] === '1' && !/^1[2-9]\d{2}[2-9]\d{6}$/.test(digits)) return false;
  return '+' + digits;
}

const BAD_PHONE = { error: 'that doesn\'t look like a phone number', reason: 'bad_phone' };

// An Instagram username: letters, digits, . and _, at most 30, not
// starting or ending with a dot or with two in a row (Instagram's own
// rules). A leading @, or a pasted instagram.com link, is trimmed to the
// name. Stored lowercase: Instagram names aren't case-sensitive. Empty
// clears it (null); anything else invalid is false.
function cleanInstagram(raw) {
  const v = String(raw == null ? '' : raw).trim()
    .replace(/^(https?:\/\/)?(www\.)?instagram\.com\//i, '')
    .replace(/[/?#].*$/, '')
    .replace(/^@+/, '')
    .toLowerCase();
  if (!v) return null;
  return /^(?!\.)(?!.*\.\.)[a-z0-9._]{1,30}(?<!\.)$/.test(v) ? v : false;
}

// A Cash App $cashtag: letters, digits, - and _, at most 20, with at
// least one letter. A leading $ is dropped. This is a little more lenient
// than Cash App may be; it only has to keep out what can't be one.
function cleanCashapp(raw) {
  const v = String(raw == null ? '' : raw).trim().replace(/^\$+/, '');
  if (!v) return null;
  return /^[A-Za-z0-9_-]{1,20}$/.test(v) && /[A-Za-z]/.test(v) ? v : false;
}

const BAD_INSTAGRAM = { error: 'an Instagram username is letters, numbers, . and _ only', reason: 'bad_instagram' };
const BAD_CASHAPP = { error: 'a $cashtag is letters, numbers, - and _ only, with at least one letter', reason: 'bad_cashapp' };

// Everything about a person a site gets: /api/session for the visitor,
// and the account service's own pages.
function personView(req, p) {
  return {
    id: p.id,
    email: p.email,
    firstName: p.firstName,
    lastName: p.lastName,
    shortName: p.shortName,
    photoUrl: photoUrlFor(req, p),
    venmo: p.venmo,
    phone: p.phone,
    instagram: p.instagram,
    cashapp: p.cashapp
  };
}

function meView(req) {
  return { person: req.person ? { ...personView(req, req.person), isAdmin: isAdmin(req) } : null };
}

app.get('/api/me', attachSession(false), (req, res) => res.json(meView(req)));

// ---------------- Guess limits ----------------
//
// Carried over from tickets' movie-password limits, pointed at what can
// be guessed or abused here:
//
// - Sending a code: 5 per email and 20 per address an hour, 100 an hour
//   across everyone (iCloud Mail allows about 1,000 a day).
// - Typing a code: each code dies after 5 wrong tries (lib/db.js), plus
//   10 wrong per email and 40 per address per 15 minutes, and 300 an hour
//   across everyone. With 5 codes an hour, that's at most 25 guesses an
//   hour at any one email, each a million-to-one.
// - The setup password: 8 per browser, 40 per address, 100 an hour overall.
// - Setup links: 40 wrong per address per 15 minutes. A link's code is
//   32 random bytes, so this is about noise, not guessing.
const codeSendLimits = guessLimits({ perWho: [5, 60 * 60 * 1000], perIp: [20, 60 * 60 * 1000], overall: [100, 60 * 60 * 1000] });
const codeGuessLimits = guessLimits({ perWho: [10, 15 * 60 * 1000], perIp: [40, 15 * 60 * 1000], overall: [300, 60 * 60 * 1000] });
const setupPasswordLimits = guessLimits({ perWho: [8, 15 * 60 * 1000], perIp: [40, 15 * 60 * 1000], overall: [100, 60 * 60 * 1000] });
const setupLinkIpLimiter = attemptLimiter(40, 15 * 60 * 1000);

function tooMany(res) {
  return res.status(429).json({ error: 'too many tries -- wait a few minutes', reason: 'rate_limited' });
}

function checkPassword(candidate, expected) {
  if (typeof candidate !== 'string' || candidate.length === 0) return false;
  const a = crypto.createHash('sha256').update(candidate).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

// ---------------- Passkeys ----------------
//
// Passkeys belong to canopysf.com (lib/domain.js), so the same passkey
// signs in from any Canopy page, and the ones tickets made keep working.
// The phone shows them as "Canopy"; changing that name doesn't affect a
// passkey already made.

const PASSKEY_RP_NAME = 'Canopy';
const PASSKEY_CEREMONY_MS = 5 * 60 * 1000;

function requirePasskeyRp(req, res) {
  const rpID = passkeyRpId(req.hostname);
  if (!rpID) res.status(400).json({ error: 'passkeys are not available on this address' });
  return rpID;
}

// The page the passkey was made or used on, from the browser's own
// signed record of it -- accepted if it's any Canopy page (lib/domain.js).
// The library then checks the response against exactly that.
function ceremonyOrigin(response) {
  try {
    const json = Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8');
    const origin = JSON.parse(json).origin;
    return isCanopyOrigin(origin) ? origin : null;
  } catch (e) {
    return null;
  }
}

async function registrationOptions(rpID, { userId, email, displayName, existing }) {
  return webauthn.generateRegistrationOptions({
    rpName: PASSKEY_RP_NAME,
    rpID,
    userID: new TextEncoder().encode(userId),
    userName: email,
    userDisplayName: displayName,
    attestationType: 'none',
    excludeCredentials: (existing || []).map((k) => ({ id: k.id, transports: k.transports })),
    // Discoverable, so signing in needs no email: the phone offers the
    // passkeys it has for Canopy.
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' }
  });
}

const NOT_VERIFIED = { error: 'that passkey could not be verified', reason: 'not_verified' };
const EXPIRED = { error: 'start again', reason: 'expired' };

// ---------------- Signing in ----------------
//
// Two ways in, and nothing else:
//
//   - a passkey ("Sign in with passkey": no email, the phone offers the
//     one it has);
//   - an email, which gets a 6-digit code. Typing it proves the address
//     on this browser for 15 minutes, and then:
//       new email      -> name and photo, then a passkey; the account is
//                         only made once the passkey exists;
//       existing email -> a new passkey on this phone. That's the lost
//                         phone (or new phone) path, and it's self-serve.
//     Every email gets a code, account or not, and what happens next is
//     only said after the code -- so the page doesn't tell anyone which
//     emails have accounts.
//
// Plus a /setup/<code> link from the admin, which makes a passkey for
// the person it was made for.
//
// After any of these, the session is signed in under a NEW token: a
// cookie anyone saw beforehand is worthless afterwards.

// What the sign-in page opens with.
app.get('/api/auth/state', attachSession(false), (req, res) => {
  res.json({
    adminExists: !!store.getAdminPersonId(),
    adminSetup: adminSetupOpen(),
    adminSetupGranted: hasAdminSetupGrant(req),
    signedIn: !!req.person
  });
});

app.post('/api/auth/admin-setup', attachSession(true), (req, res) => {
  if (!adminSetupOpen()) return res.status(409).json({ error: 'there is already an admin', reason: 'closed' });
  if (setupPasswordLimits.blocked(req, req.sess.idHash)) return tooMany(res);
  if (!checkPassword(String((req.body || {}).password || ''), ADMIN_PASSWORD)) {
    setupPasswordLimits.hit(req, req.sess.idHash);
    // 403, not 401: the page reads a 401 as "you've been signed out".
    return res.status(403).json({ error: 'wrong password', reason: 'wrong_password' });
  }
  store.grantAdminSetup(req.sess.idHash);
  res.json({ ok: true });
});

// What an email proven on this browser leads to.
function emailState(email) {
  const person = store.getPersonByEmail(email);
  if (!person) return { state: 'new', email };
  return { state: 'existing', email, firstName: person.firstName, hasPasskey: store.passkeysOf(person.id).length > 0 };
}

// Sends a code to the email. After the setup password, the admin's own
// email (or any, on first run) counts as proven without one -- that
// password is the stronger proof, and mail may not be set up yet.
app.post('/api/auth/email/start', attachSession(true), handle(async (req, res) => {
  if (!accountsOpen(req, res)) return;
  const email = cleanEmail((req.body || {}).email);
  if (!email) return res.status(400).json({ error: 'enter a valid email', reason: 'bad_email' });

  if (hasAdminSetupGrant(req)) {
    const adminId = store.getAdminPersonId();
    const person = store.getPersonByEmail(email);
    if (!adminId || (person && person.id === adminId)) {
      store.setVerifiedEmail(req.sess.idHash, email);
      return res.json({ verified: true, ...emailState(email) });
    }
  }

  if (codeSendLimits.blocked(req, email)) return tooMany(res);
  codeSendLimits.hit(req, email);
  const code = store.issueEmailCode(req.sess.idHash, email);
  try {
    await mailer.sendCode(email, code);
  } catch (err) {
    console.error(`[canopy-account] sending a code failed: ${err.message}`);
    return res.status(502).json({ error: "couldn't send the email", reason: 'mail_failed' });
  }
  res.json({ verified: false, email });
}));

app.post('/api/auth/email/verify', attachSession(false), (req, res) => {
  if (!req.sess) return res.status(400).json(EXPIRED);
  const email = store.codeEmail(req.sess.idHash);
  if (!email) return res.status(400).json({ error: 'that code has run out -- send a new one', reason: 'expired' });
  if (codeGuessLimits.blocked(req, email)) return tooMany(res);
  const code = String((req.body || {}).code || '').replace(/\s+/g, '');
  const result = store.checkEmailCode(req.sess.idHash, code);
  if (result.outcome === 'expired') return res.status(400).json({ error: 'that code has run out -- send a new one', reason: 'expired' });
  if (result.outcome === 'wrong') {
    codeGuessLimits.hit(req, email);
    return res.status(403).json({ error: "that isn't the code", reason: 'wrong_code' });
  }
  res.json({ verified: true, ...emailState(result.email) });
});

// The email this browser has proven, or a refusal (sent here).
function provenEmail(req, res) {
  const email = req.sess && store.verifiedEmail(req.sess.idHash);
  if (!email) res.status(400).json({ error: 'confirm your email first', reason: 'verify_first' });
  return email;
}

// A new account: its details wait on this session until the passkey
// exists (register/verify creates both). The photo is uploaded after.
app.post('/api/auth/register/new', attachSession(false), handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID || !accountsOpen(req, res)) return;
  const email = provenEmail(req, res);
  if (!email) return;
  const body = req.body || {};
  const names = cleanNames(body);
  if (names.error) return res.status(400).json({ error: names.error });
  if (store.getPersonByEmail(email)) return res.status(409).json({ error: 'that email already has an account', reason: 'conflict' });
  const venmo = cleanVenmo(body.venmoHandle);
  if (venmo === false) return res.status(400).json(BAD_VENMO);
  const id = crypto.randomUUID();
  const options = await registrationOptions(rpID, { userId: id, email, displayName: `${names.firstName} ${names.lastName}` });
  store.setPending(req.sess.idHash, {
    challenge: options.challenge, kind: 'register', profile: { mode: 'new', id, email, ...names, venmo }
  });
  res.json({ options });
}));

// A new passkey for the account an emailed code just proved: a new phone,
// or the old one lost.
app.post('/api/auth/register/existing', attachSession(false), handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID || !accountsOpen(req, res)) return;
  const email = provenEmail(req, res);
  if (!email) return;
  const person = store.getPersonByEmail(email);
  if (!person) return res.status(404).json({ error: 'not found' });
  const options = await registrationOptions(rpID, {
    userId: person.id, email: person.email, displayName: `${person.firstName} ${person.lastName}`,
    existing: store.passkeysOf(person.id)
  });
  store.setPending(req.sess.idHash, {
    challenge: options.challenge, kind: 'register', personId: person.id, profile: { mode: 'existing', email }
  });
  res.json({ options });
}));

// Who a setup link is for, so its page can say so. 404 for one that's
// spent, run out or never existed.
function setupLinkFor(req, res, code) {
  if (setupLinkIpLimiter.blocked(clientIp(req))) { tooMany(res); return null; }
  const link = store.getSetupLink(code);
  if (!link) {
    setupLinkIpLimiter.hit(clientIp(req));
    res.status(404).json({ error: 'that link has been used or has run out', reason: 'bad_link' });
  }
  return link;
}

app.get('/api/setup/:code', (req, res) => {
  const link = setupLinkFor(req, res, req.params.code);
  if (link) res.json({ firstName: link.person.firstName, expiresAt: link.expiresAt });
});

app.post('/api/auth/register/link', attachSession(true), handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID) return;
  const link = setupLinkFor(req, res, String((req.body || {}).code || ''));
  if (!link) return;
  const p = link.person;
  const options = await registrationOptions(rpID, {
    userId: p.id, email: p.email, displayName: `${p.firstName} ${p.lastName}`, existing: store.passkeysOf(p.id)
  });
  store.setPending(req.sess.idHash, {
    challenge: options.challenge, kind: 'register', personId: p.id, profile: { mode: 'link', codeHash: link.codeHash }
  });
  res.json({ options });
}));

// Another passkey for the signed-in person, from their profile page.
app.post('/api/auth/register/add', requireSignedIn, handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID) return;
  const p = req.person;
  const options = await registrationOptions(rpID, {
    userId: p.id, email: p.email, displayName: `${p.firstName} ${p.lastName}`, existing: store.passkeysOf(p.id)
  });
  store.setPending(req.sess.idHash, { challenge: options.challenge, kind: 'register', personId: p.id, profile: { mode: 'add' } });
  res.json({ options });
}));

// A passkey just checked out for personId: sign this browser in, under a
// new token. On first run (the setup password entered here, no admin yet)
// they're the admin now; in recovery the admin stays who it was.
function finishSignIn(req, res, personId) {
  const granted = hasAdminSetupGrant(req);
  const { token, idHash } = store.rotateSession(req.sess.idHash);
  res.append('Set-Cookie', session.cookieHeader(token, req.hostname));
  store.signIn(idHash, personId);
  if (granted) {
    store.takeAdminSetup(idHash);
    if (!store.getAdminPersonId()) store.setAdminPersonId(personId);
  }
  req.sess = { ...req.sess, idHash, personId, adminSetupAt: null };
  req.person = store.getPerson(personId);
}

app.post('/api/auth/register/verify', attachSession(false), handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID) return;
  if (!req.sess) return res.status(400).json(EXPIRED);
  const pending = store.takePending(req.sess.idHash);
  if (!pending || pending.kind !== 'register' || !pending.profile || Date.now() - pending.at > PASSKEY_CEREMONY_MS) {
    return res.status(400).json(EXPIRED);
  }
  const response = (req.body || {}).response;
  const origin = ceremonyOrigin(response);
  if (!origin) return res.status(400).json(NOT_VERIFIED);
  let result;
  try {
    result = await webauthn.verifyRegistrationResponse({
      response, expectedChallenge: pending.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: false
    });
  } catch (e) {
    return res.status(400).json(NOT_VERIFIED);
  }
  if (!result.verified) return res.status(400).json(NOT_VERIFIED);
  const cred = {
    ...result.registrationInfo.credential,
    deviceType: result.registrationInfo.credentialDeviceType,
    backedUp: result.registrationInfo.credentialBackedUp
  };
  // A credential id names one passkey, on one account. A real phone makes
  // a fresh one every time, but the id is whatever the response says, and
  // a made-up response can reuse one that's saved already (its own, or
  // someone else's). Refused here, before a setup link is spent on it.
  if (store.getPasskey(cred.id)) {
    return res.status(409).json({ error: 'that passkey is already saved', reason: 'passkey_exists' });
  }

  const { mode } = pending.profile;
  let personId = pending.personId;
  if (mode === 'new') {
    // Checked again: the setup password may have run out since.
    if (!accountsOpen(req, res)) return;
    const made = store.createPersonWithPasskey(pending.profile, cred);
    if (!made.ok) return res.status(409).json({ error: 'that email already has an account', reason: 'conflict' });
    personId = made.person.id;
  } else if (mode === 'existing') {
    const person = store.getPerson(personId);
    // The proven email still has to be this person's.
    if (!person || store.verifiedEmail(req.sess.idHash) !== person.email) return res.status(400).json(EXPIRED);
    store.addPasskey(personId, cred);
    store.markEmailVerified(personId);
  } else if (mode === 'link') {
    if (!store.useSetupLink(pending.profile.codeHash, personId)) {
      return res.status(404).json({ error: 'that link has been used or has run out', reason: 'bad_link' });
    }
    store.addPasskey(personId, cred);
  } else if (mode === 'add') {
    if (!req.person || req.person.id !== personId) return res.status(401).json({ error: 'unauthorized' });
    store.addPasskey(personId, cred);
    return res.status(201).json({ ok: true });
  } else {
    return res.status(400).json(EXPIRED);
  }
  finishSignIn(req, res, personId);
  res.status(201).json(meView(req));
}));

// Sign in: no email -- the phone offers whichever passkey it has here.
app.post('/api/auth/login/options', attachSession(true), handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID || !accountsOpen(req, res)) return;
  const options = await webauthn.generateAuthenticationOptions({ rpID, userVerification: 'preferred' });
  store.setPending(req.sess.idHash, { challenge: options.challenge, kind: 'login' });
  res.json({ options });
}));

app.post('/api/auth/login/verify', attachSession(false), handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID) return;
  if (!req.sess) return res.status(400).json(EXPIRED);
  if (!accountsOpen(req, res)) return;
  const pending = store.takePending(req.sess.idHash);
  if (!pending || pending.kind !== 'login' || Date.now() - pending.at > PASSKEY_CEREMONY_MS) {
    return res.status(400).json(EXPIRED);
  }
  const response = (req.body || {}).response;
  const passkey = store.getPasskey(response && response.id);
  // Deleted by a reset, or made for an account that's since gone.
  if (!passkey) return res.status(400).json({ error: 'that passkey is no longer linked to an account', reason: 'unknown_passkey' });
  const origin = ceremonyOrigin(response);
  if (!origin) return res.status(400).json(NOT_VERIFIED);
  let result;
  try {
    result = await webauthn.verifyAuthenticationResponse({
      response,
      expectedChallenge: pending.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: { id: passkey.id, publicKey: passkey.publicKey, counter: passkey.counter, transports: passkey.transports },
      requireUserVerification: false
    });
  } catch (e) {
    return res.status(400).json(NOT_VERIFIED);
  }
  if (!result.verified) return res.status(400).json(NOT_VERIFIED);
  store.usePasskey(passkey.id, result.authenticationInfo.newCounter);
  finishSignIn(req, res, passkey.personId);
  res.json(meView(req));
}));

// ---------------- Signing out ----------------
//
// Ends the session itself, so it's every Canopy site at once (a site may
// keep showing someone as signed in for up to the minute it caches the
// answer for).

function signOut(req, res) {
  if (req.sess) store.endSession(req.sess.idHash);
  res.append('Set-Cookie', session.clearHeader(req.hostname));
}

app.post('/api/signout', attachSession(false), (req, res) => {
  signOut(req, res);
  res.json({ ok: true });
});

// A link sites can put behind their "Sign out". A GET, so it's only
// honoured when the browser says it came from a Canopy page (or was typed
// in): another website linking here can't sign anyone out.
app.get('/signout', attachSession(false), (req, res) => {
  const back = safeReturn(req.query.return) || '/';
  if (req.get('sec-fetch-site') === 'cross-site') return res.redirect(req.person ? '/profile' : back);
  signOut(req, res);
  res.redirect(back);
});

// ---------------- Profile ----------------

// The cropped photo the page makes is a few dozen KB; this is only a
// ceiling.
const photoUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    cb(null, ['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype));
  }
});

app.patch('/api/profile', requireSignedIn, (req, res) => {
  const body = req.body || {};
  const names = cleanNames(body);
  if (names.error) return res.status(400).json({ error: names.error });
  let venmo;
  if (body.venmoHandle !== undefined) {
    venmo = cleanVenmo(body.venmoHandle);
    if (venmo === false) return res.status(400).json(BAD_VENMO);
  }
  let phone, instagram, cashapp;
  if (body.phone !== undefined) {
    phone = cleanPhone(body.phone);
    if (phone === false) return res.status(400).json(BAD_PHONE);
  }
  if (body.instagram !== undefined) {
    instagram = cleanInstagram(body.instagram);
    if (instagram === false) return res.status(400).json(BAD_INSTAGRAM);
  }
  if (body.cashapp !== undefined) {
    cashapp = cleanCashapp(body.cashapp);
    if (cashapp === false) return res.status(400).json(BAD_CASHAPP);
  }
  req.person = store.renamePerson(req.person.id, names.firstName, names.lastName);
  if (venmo !== undefined) req.person = store.setPersonVenmo(req.person.id, venmo);
  if (phone !== undefined) req.person = store.setPersonPhone(req.person.id, phone);
  if (instagram !== undefined) req.person = store.setPersonInstagram(req.person.id, instagram);
  if (cashapp !== undefined) req.person = store.setPersonCashapp(req.person.id, cashapp);
  res.json(meView(req));
});

app.post('/api/profile/photo', requireSignedIn, photoUpload.single('photo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'choose a photo' });
  photoStore.save(req.person.id, req.file.buffer);
  req.person = store.setPersonPhoto(req.person.id, Date.now());
  res.json(meView(req));
});

function passkeyView(k) {
  return {
    id: k.id,
    createdAt: k.createdAt,
    lastUsedAt: k.lastUsedAt,
    // Synced (iCloud Keychain, Google Password Manager...) or only on the
    // device that made it.
    synced: k.backedUp,
    // 'hybrid' is a phone used from another device's browser over QR.
    transports: k.transports || []
  };
}

app.get('/api/profile/passkeys', requireSignedIn, (req, res) => {
  res.json({ passkeys: store.passkeysOf(req.person.id).map(passkeyView) });
});

app.delete('/api/profile/passkeys/:id', requireSignedIn, (req, res) => {
  const result = store.removePasskey(req.person.id, req.params.id);
  if (result.ok) return res.json({ ok: true });
  if (result.reason === 'last_passkey') {
    return res.status(409).json({ error: "that's your only passkey -- add another first", reason: 'last_passkey' });
  }
  res.status(404).json({ error: 'not found' });
});

// Photos are for browsers signed in to a Canopy account, not the open
// web. Canopy sites show them straight from here: an <img> on any Canopy
// subdomain sends the cookie, since the browser counts it as the same
// site.
app.get('/photo/:personId', attachSession(false), (req, res) => {
  if (!req.person) return res.status(404).end();
  let file = null;
  try { file = photoStore.pathFor(req.params.personId); } catch (e) {}
  if (!file) return res.status(404).end();
  res.set('Content-Type', 'image/jpeg');
  res.set('Cache-Control', 'private, max-age=86400');
  res.sendFile(file);
});

// ---------------- Admin ----------------

function adminPersonView(req, p) {
  return {
    ...personView(req, p),
    passkeyCount: p.passkeyCount,
    emailVerifiedAt: p.emailVerifiedAt,
    createdAt: p.createdAt
  };
}

function setupLinkView(req, code) {
  return { setupUrl: `${publicBase(req)}/setup/${code}` };
}

app.use('/api/admin', requireAdmin);

app.get('/api/admin/people', (req, res) => {
  res.json({ people: store.listPeople().map((p) => adminPersonView(req, p)), adminPersonId: store.getAdminPersonId() });
});

app.patch('/api/admin/people/:id', (req, res) => {
  const names = cleanNames(req.body || {});
  if (names.error) return res.status(400).json({ error: names.error });
  const person = store.renamePerson(req.params.id, names.firstName, names.lastName);
  if (!person) return res.status(404).json({ error: 'not found' });
  res.json({ person: adminPersonView(req, person) });
});

// Your own would lock you out of here (that's what ADMIN_RECOVERY and
// your own email are for), and deleting yourself would leave no admin.
function notTheAdmin(req, res) {
  if (req.params.id !== store.getAdminPersonId()) return true;
  res.status(409).json({ error: 'not the admin', reason: 'is_admin' });
  return false;
}

// Lost phone: their passkeys go, they're signed out everywhere, and the
// answer is a setup link to send them.
app.post('/api/admin/people/:id/reset-passkeys', (req, res) => {
  if (!notTheAdmin(req, res)) return;
  const result = store.resetPasskeys(req.params.id);
  if (!result.ok) return res.status(404).json({ error: 'not found' });
  res.json(setupLinkView(req, result.code));
});

// A setup link without taking anything away: someone who has no passkey
// yet, or a link that ran out before they used it.
app.post('/api/admin/people/:id/setup-link', (req, res) => {
  if (!store.getPerson(req.params.id)) return res.status(404).json({ error: 'not found' });
  res.json(setupLinkView(req, store.createSetupLink(req.params.id)));
});

// Their records on every site stay, under their id; sites show them as a
// former member.
app.delete('/api/admin/people/:id', (req, res) => {
  if (!notTheAdmin(req, res)) return;
  if (!store.deletePerson(req.params.id)) return res.status(404).json({ error: 'not found' });
  try { photoStore.remove(req.params.id); } catch (e) {}
  res.json({ ok: true });
});

// Sites: each Canopy site that asks who's signed in has its own key,
// shown once when it's made (or replaced). Cutting one off stops only
// that site.
app.get('/api/admin/apps', (req, res) => res.json({ apps: store.listApps() }));

app.post('/api/admin/apps', (req, res) => {
  const name = String((req.body || {}).name || '').trim().toLowerCase().replace(/\s+/g, '-').slice(0, 40);
  if (!/^[a-z0-9][a-z0-9-]*$/.test(name)) return res.status(400).json({ error: 'a site name is letters, numbers and -' });
  const result = store.createApp(name);
  if (!result.ok) return res.status(409).json({ error: 'there is already a site with that name', reason: 'conflict' });
  res.status(201).json({ app: result.app, key: result.key });
});

app.post('/api/admin/apps/:id/rekey', (req, res) => {
  const result = store.rekeyApp(req.params.id);
  if (!result) return res.status(404).json({ error: 'not found' });
  res.json(result);
});

app.post('/api/admin/apps/:id/revoke', (req, res) => {
  if (!store.revokeApp(req.params.id)) return res.status(404).json({ error: 'not found' });
  res.json({ ok: true });
});

// ---------------- For Canopy sites (server to server) ----------------
//
// Each call carries the site's key: `Authorization: Bearer <key>`.
// client/canopy-account.js is the other end.

function requireSite(req, res, next) {
  const m = /^Bearer\s+(\S+)$/i.exec(req.get('authorization') || '');
  const site = m && store.appByKey(m[1]);
  if (!site) return res.status(401).json({ error: 'unknown or revoked site key' });
  req.site = site;
  next();
}

// Who the visitor is. The site passes their canopy_session cookie value
// in X-Canopy-Session, and its own host in X-Canopy-Site-Host so the
// renewed cookie (when one's due) is made for the right domain. The
// answer: { person } (null if not signed in), and `renewCookie`, a
// Set-Cookie value the site should send back to the visitor as is.
app.get('/api/session', requireSite, (req, res) => {
  res.set('Cache-Control', 'no-store');
  const token = session.readToken(`${session.COOKIE}=${req.get('x-canopy-session') || ''}`);
  const s = token && store.getSessionByToken(token);
  const person = s && s.personId ? store.getPerson(s.personId) : null;
  if (!person) return res.json({ person: null });
  store.touchSession(s.idHash, s.lastSeenAt);
  const body = { person: personView(req, person) };
  if (session.needsRenewal(s)) {
    body.renewCookie = session.cookieHeader(token, req.get('x-canopy-site-host') || '');
    store.cookieRenewed(s.idHash);
  }
  res.json(body);
});

// Names and photos for other people: ?ids=a,b,c (up to 200). Anyone not
// in the answer has been deleted -- a former member.
const ID_RE = /^[0-9a-f-]{36}$/;
app.get('/api/people', requireSite, (req, res) => {
  res.set('Cache-Control', 'no-store');
  const ids = Array.from(new Set(String(req.query.ids || '').split(',').map((s) => s.trim()).filter((s) => ID_RE.test(s))));
  if (ids.length > 200) return res.status(400).json({ error: 'at most 200 ids at a time' });
  res.json({
    people: store.peopleByIds(ids).map((p) => ({
      id: p.id, firstName: p.firstName, lastName: p.lastName, shortName: p.shortName, photoUrl: photoUrlFor(req, p)
    }))
  });
});

// ---------------- Pages ----------------

// The app's own scripts go inside each page rather than being fetched
// separately, so a page and its scripts always come from the same copy of
// the app. Tickets learned this the hard way: Cloudflare gives .js files a
// 4-hour browser cache whatever this server says, and during a deploy a
// phone can get the old file (or a 404) under the new URL and keep it.
const INLINE_SCRIPTS = [
  'copy.js', 'photo-crop.js', 'account.js', 'vendor/simplewebauthn-browser-14.0.0/index.umd.min.js'
].map((name) => {
  // `</script` inside the source would end the inline tag early.
  const source = fs.readFileSync(path.join(__dirname, 'public', name), 'utf8').replace(/<\/script/gi, '<\\/script');
  return { tag: `<script src="/${name}"></script>`, inline: `<script>/* ${name} */\n${source}\n</script>` };
});
// The shared stylesheet, the same way.
const INLINE_STYLES = ['account.css'].map((name) => {
  const source = fs.readFileSync(path.join(__dirname, 'public', name), 'utf8').replace(/<\/style/gi, '<\\/style');
  return { tag: `<link rel="stylesheet" href="/${name}">`, inline: `<style>/* ${name} */\n${source}\n</style>` };
});

function escapeAttr(value) {
  return String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// The uploaded logo, or the Canopy logo that ships in public/ until one is.
function logoImgTag() {
  const meta = logoImageStore.getMeta();
  const src = meta ? `/logo-image?v=${meta.uploadedAt}` : '/canopy-logo.png';
  return `<img src="${src}" alt="Canopy" class="site-logo">`;
}

function backdropUrl() {
  const meta = backdropImageStore.getMeta();
  return meta ? `/backdrop-image?v=${meta.uploadedAt}` : '';
}

// Sends a page from views/ with its placeholders filled: the logo
// (<!-- LOGO_IMG -->), the sign-in backdrop (__BACKDROP_URL__), where to
// go after signing in (__RETURN_URL__, already checked to be a Canopy
// page, or empty), and the scripts inlined.
function renderPage(res, name, { returnUrl = '' } = {}) {
  const logo = logoImgTag();
  let html = fs.readFileSync(path.join(__dirname, 'views', name), 'utf8')
    .replaceAll('<!-- LOGO_IMG -->', () => logo)
    .replaceAll('__BACKDROP_URL__', () => escapeAttr(backdropUrl()))
    .replaceAll('__RETURN_URL__', () => escapeAttr(returnUrl));
  INLINE_SCRIPTS.concat(INLINE_STYLES).forEach(({ tag, inline }) => {
    html = html.replace(tag, () => inline);
  });
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.set('Cache-Control', 'no-store');
  res.send(html);
}

// Sign in or sign up, then back to ?return= (a Canopy page) or the
// profile. Already signed in: straight there.
app.get('/', attachSession(false), (req, res) => {
  const back = safeReturn(req.query.return);
  if (req.person) return res.redirect(back || '/profile');
  renderPage(res, 'welcome.html', { returnUrl: back || '' });
});

app.get('/profile', attachSession(false), (req, res) => {
  if (!req.person) return res.redirect('/');
  renderPage(res, 'profile.html');
});

app.get('/setup/:code', (req, res) => renderPage(res, 'setup.html'));

app.get('/admin', attachSession(false), (req, res) => {
  if (isAdmin(req)) return renderPage(res, 'admin.html');
  res.redirect(req.person ? '/profile' : '/?return=' + encodeURIComponent(`${publicBase(req)}/admin`));
});

// ---------------- Site images (logo, sign-in backdrop) ----------------

const siteImageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    cb(null, ['image/png', 'image/jpeg', 'image/webp', 'image/gif'].includes(file.mimetype));
  }
});

// The admin's GET (metadata) and POST (upload), and the file itself for
// anyone: the sign-in page shows both before anyone's signed in.
function mountImageRoutes(urlName, imageStore) {
  app.get(`/api/admin/${urlName}`, (req, res) => {
    const meta = imageStore.getMeta();
    res.json(meta ? { uploadedAt: meta.uploadedAt, url: `/${urlName}?v=${meta.uploadedAt}` } : { uploadedAt: null, url: null });
  });
  app.post(`/api/admin/${urlName}`, siteImageUpload.single('image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'choose a PNG, JPEG, WebP, or GIF image' });
    const meta = imageStore.save(req.file.buffer, req.file.mimetype);
    res.json({ ok: true, uploadedAt: meta.uploadedAt, url: `/${urlName}?v=${meta.uploadedAt}` });
  });
  app.get(`/${urlName}`, (req, res) => {
    const meta = imageStore.getMeta();
    if (!meta) return res.status(404).end();
    res.set('Content-Type', meta.mimeType);
    res.set('Cache-Control', 'public, max-age=86400');
    res.sendFile(imageStore.getFilePath());
  });
}

mountImageRoutes('logo-image', logoImageStore);
mountImageRoutes('backdrop-image', backdropImageStore);

app.get('/healthz', (req, res) => res.json({ ok: true }));

// There's no icon; this keeps every page load from logging a 404 for one.
app.get('/favicon.ico', (req, res) => res.status(204).end());

// no-cache: a conditional GET every load, so a stale copy can't outlive a
// deploy in someone's browser.
app.use(
  express.static(path.join(__dirname, 'public'), {
    setHeaders(res) {
      res.set('Cache-Control', 'no-cache');
    }
  })
);

// Upload errors (bad type, too big) as JSON rather than Express's HTML.
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'image is too large' : err.message });
  }
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'bad JSON' });
  next(err);
});

app.listen(PORT, () => {
  console.log(`canopy-account listening on port ${PORT}`);
});
