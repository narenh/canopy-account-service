const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const webauthn = require('@simplewebauthn/server');

const store = require('./lib/db').init();
const photoStore = require('./lib/photoStore');
const { createImageStore } = require('./lib/uploadedImage');
const session = require('./lib/session');
const mailer = require('./lib/mailer');
const { attemptLimiter, guessLimits, clientIp } = require('./lib/limits');
const { BASE, isCanopyOrigin, safeReturn, passkeyRpId, isAppOrigin } = require('./lib/domain');

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
//
// The apps send no Origin, and don't need to: forging a request is about
// getting the browser to attach something it attaches by itself (the
// cookie), and the app endpoints never read the cookie. What they read is
// an Authorization: Bearer header, which no browser attaches by itself,
// and which another site's page can't set without asking first (a CORS
// preflight, which this service never says yes to for these). So a
// request to /api/native/ that carries a bearer header skips this check,
// and so does the one step that comes before there's a token to carry
// (auth/begin), if it's JSON: also something a page elsewhere can't send
// without that preflight. See "The Origin check" in the README.
const NATIVE = '/api/native/v1';

function exemptAsApp(req) {
  if (!req.path.startsWith(NATIVE + '/')) return false;
  if (session.readBearer(req.get('authorization')) !== undefined) return true;
  return req.path === `${NATIVE}/auth/begin` && !!req.is('application/json');
}

app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  if (isCanopyOrigin(req.get('origin'))) return next();
  if (exemptAsApp(req)) return next();
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

// The session an app's request names, by its Authorization: Bearer token
// and nothing else: never the cookie, even when one came along too. A
// bearer header that isn't shaped like a token is nobody. Puts req.sess
// and req.person on the request like attachSession, and keeps the session
// alive (last seen) the same way. There's no cookie to renew: the token
// lasts a year from when it was last used, like the cookie's session.
function bearerSession(req) {
  req.sess = null;
  req.person = null;
  const token = session.readBearer(req.get('authorization'));
  const s = token ? store.getSessionByToken(token) : null;
  if (!s) return;
  store.touchSession(s.idHash, s.lastSeenAt);
  req.sess = s;
  req.person = s.personId ? store.getPerson(s.personId) : null;
}

// For what both a browser and an app ask for (a photo): the bearer header
// when there is one, which then decides alone, otherwise the cookie.
function cookieOrBearer(req, res, next) {
  if (session.readBearer(req.get('authorization')) === undefined) return attachSession(false)(req, res, next);
  bearerSession(req);
  next();
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
// the sign-in page is only the setup password
// (ADMIN_PASSWORD), and the server refuses every other sign-in and
// sign-up until it's been entered; whoever then signs up on that browser
// is the admin. ADMIN_RECOVERY=1 opens the setup password again for an
// admin who has lost every passkey AND can't get the emailed code -- it
// adds a passkey to the admin's own account and nothing else.

const ADMIN_SETUP_MS = 15 * 60 * 1000;

function adminSetupOpen() {
  return ADMIN_RECOVERY || !store.getAdminPersonId();
}

// The admin's email is always proven (first run proves it with the setup
// password, and Edit profile won't change the admin's own), but the check
// is here too: an unverified account never opens /admin.
function isAdmin(req) {
  return !!req.person && !!req.person.emailVerifiedAt && req.person.id === store.getAdminPersonId();
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

// Everything about a person a site gets: /api/session for the visitor
// themself, and the account service's own pages. Contact details are in
// here, so it's only ever about the person asking (or for the admin).
function personView(req, p) {
  return {
    id: p.id,
    email: p.email,
    emailVerified: !!p.emailVerifiedAt,
    firstName: p.firstName,
    lastName: p.lastName,
    shortName: p.shortName,
    photoUrl: photoUrlFor(req, p),
    venmo: p.venmo,
    phone: p.phone,
    instagram: p.instagram,
    cashapp: p.cashapp,
    findable: p.findable
  };
}

// Everything anyone else -- another person, a site asking about someone
// who isn't the visitor -- ever gets about a person: /api/people and the
// lookup. Never their email, phone, Instagram, Venmo or Cash App. Knowing
// a number finds the account; the account never gives up its numbers.
function publicPersonView(req, p) {
  return { id: p.id, firstName: p.firstName, lastName: p.lastName, shortName: p.shortName, photoUrl: photoUrlFor(req, p) };
}

function meView(req) {
  return { person: req.person ? { ...personView(req, req.person), isAdmin: isAdmin(req) } : null };
}

const me = (req, res) => res.json(meView(req));
app.get('/api/me', attachSession(false), me);

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
// - Quick sign-ups send no email, so nothing like the code limits holds
//   them back. Each one tried says whether an email has an account, so
//   tries are counted: 10 per browser per 15 minutes, 20 per address and
//   200 across everyone an hour. Accounts actually made: 10 per address
//   and 50 across everyone an hour.
// - Changing your email: 5 new addresses per person an hour, on top of the
//   code-sending limits (each try sends an email). Someone changing their
//   email does it once, or twice after a typo.
const codeSendLimits = guessLimits({ perWho: [5, 60 * 60 * 1000], perIp: [20, 60 * 60 * 1000], overall: [100, 60 * 60 * 1000] });
const codeGuessLimits = guessLimits({ perWho: [10, 15 * 60 * 1000], perIp: [40, 15 * 60 * 1000], overall: [300, 60 * 60 * 1000] });
const setupPasswordLimits = guessLimits({ perWho: [8, 15 * 60 * 1000], perIp: [40, 15 * 60 * 1000], overall: [100, 60 * 60 * 1000] });
const setupLinkIpLimiter = attemptLimiter(40, 15 * 60 * 1000);
const quickTryLimits = guessLimits({ perWho: [10, 15 * 60 * 1000], perIp: [20, 60 * 60 * 1000], overall: [200, 60 * 60 * 1000] });
const quickMadeLimits = guessLimits({ perIp: [10, 60 * 60 * 1000], overall: [50, 60 * 60 * 1000] });
const emailChangeLimiter = attemptLimiter(5, 60 * 60 * 1000);

// An error that got as far as Express, as the JSON every API answer is:
// {error, reason}. An upload's own (too big, or malformed: uploadOne), a
// body that isn't JSON, anything else that says it's the request's fault
// (err.status or err.statusCode in the 4xx, like a path with a % that
// doesn't decode), and otherwise a 500 that says nothing more (the error
// itself goes to the log).
function errorAnswer(err) {
  if (err instanceof multer.MulterError) {
    return err.code === 'LIMIT_FILE_SIZE' ? [400, 'image is too large', 'too_large'] : [400, err.message, 'bad_upload'];
  }
  if (err && err.type === 'entity.parse.failed') return [400, 'bad JSON', 'bad_json'];
  if (err && err.type === 'entity.too.large') return [413, 'too large', 'too_large'];
  const status = err && (err.status || err.statusCode);
  if (Number.isInteger(status) && status >= 400 && status < 500) {
    return err.reason ? [status, err.message, err.reason] : [status, 'bad request', 'bad_request'];
  }
  return [500, 'something went wrong', 'server_error'];
}

function jsonErrors(err, req, res, next) {
  if (res.headersSent) return next(err);
  const [status, error, reason] = errorAnswer(err);
  if (status >= 500) console.error(`[canopy-account] ${req.method} ${req.originalUrl} failed: ${(err && err.stack) || err}`);
  res.status(status).json({ error, reason });
}

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
// signs in from any Canopy page.
// The phone shows them as "Canopy"; changing that name doesn't affect a
// passkey already made.

const PASSKEY_RP_NAME = 'Canopy';
const PASSKEY_CEREMONY_MS = 5 * 60 * 1000;

function requirePasskeyRp(req, res) {
  const rpID = passkeyRpId(req.hostname);
  if (!rpID) res.status(400).json({ error: 'passkeys are not available on this address', reason: 'no_passkeys' });
  return rpID;
}

// The page the passkey was made or used on, from the browser's own
// signed record of it -- accepted if it's any Canopy page (lib/domain.js).
// The library then checks the response against exactly that. From an app
// (req.native), the app's own origin is accepted too: https://<rpID> from
// iOS, or a listed Android signing certificate (lib/domain.js). The web's
// endpoints never accept those.
function ceremonyOrigin(req, response, rpID) {
  try {
    const json = Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8');
    const origin = JSON.parse(json).origin;
    if (typeof origin !== 'string') return null;
    if (isCanopyOrigin(origin)) return origin;
    return req.native && isAppOrigin(origin, rpID) ? origin : null;
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
  return {
    state: 'existing', email, firstName: person.firstName, hasPasskey: store.passkeysOf(person.id).length > 0,
    // A quick sign-up nobody has proven the email of yet: a new passkey
    // here takes the account over (see register/verify).
    unverified: !person.emailVerifiedAt
  };
}

// Sends a code to the email. After the setup password, the admin's own
// email (or any, on first run) counts as proven without one -- that
// password is the stronger proof, and mail may not be set up yet.
const emailStart = handle(async (req, res) => {
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
    await mailer.sendCode(email, code, emailLogoUrl(req));
  } catch (err) {
    console.error(`[canopy-account] sending a code failed: ${err.message}`);
    return res.status(502).json({ error: "couldn't send the email", reason: 'mail_failed' });
  }
  res.json({ verified: false, email });
});
app.post('/api/auth/email/start', attachSession(true), emailStart);

const emailVerify = (req, res) => {
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
};
app.post('/api/auth/email/verify', attachSession(false), emailVerify);

// The email this browser has proven, or a refusal (sent here).
function provenEmail(req, res) {
  const email = req.sess && store.verifiedEmail(req.sess.idHash);
  if (!email) res.status(400).json({ error: 'confirm your email first', reason: 'verify_first' });
  return email;
}

// A new account: its details wait on this session until the passkey
// exists (register/verify creates both). The photo is uploaded after.
const registerNew = handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID || !accountsOpen(req, res)) return;
  const email = provenEmail(req, res);
  if (!email) return;
  const body = req.body || {};
  const names = cleanNames(body);
  if (names.error) return res.status(400).json({ error: names.error, reason: 'names_required' });
  if (store.getPersonByEmail(email)) return res.status(409).json({ error: 'that email already has an account', reason: 'conflict' });
  const venmo = cleanVenmo(body.venmoHandle);
  if (venmo === false) return res.status(400).json(BAD_VENMO);
  const id = crypto.randomUUID();
  const options = await registrationOptions(rpID, { userId: id, email, displayName: `${names.firstName} ${names.lastName}` });
  store.setPending(req.sess.idHash, {
    challenge: options.challenge, kind: 'register', profile: { mode: 'new', id, email, ...names, venmo }
  });
  res.json({ options });
});
app.post('/api/auth/register/new', attachSession(false), registerNew);

// A new passkey for the account an emailed code just proved: a new phone,
// or the old one lost.
const registerExisting = handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID || !accountsOpen(req, res)) return;
  const email = provenEmail(req, res);
  if (!email) return;
  const person = store.getPersonByEmail(email);
  if (!person) return res.status(404).json({ error: 'not found', reason: 'not_found' });
  const options = await registrationOptions(rpID, {
    userId: person.id, email: person.email, displayName: `${person.firstName} ${person.lastName}`,
    existing: store.passkeysOf(person.id)
  });
  store.setPending(req.sess.idHash, {
    challenge: options.challenge, kind: 'register', personId: person.id, profile: { mode: 'existing', email }
  });
  res.json({ options });
});
app.post('/api/auth/register/existing', attachSession(false), registerExisting);

// ---------------- Quick sign-up ----------------
//
// For someone opening a link from a site that allows unverified accounts
// (events): first and last name, email, and a passkey, with no code and
// no photo. The account is only made once the passkey exists, like any
// other, but its email isn't proven: it's unverified until its owner
// types a code (their profile, or signing in by code), and sites that
// don't allow unverified accounts see them as signed out until then.
//
// An email that already has an account, verified or not, is told so.
// That says the account exists, which the code flow never does. It's the
// price of a sign-up with no code: the alternative is quietly making a
// second account or failing with no reason. The tries are limited (see
// "Guess limits"). Only once there's an admin.

const quickStart = handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID) return;
  if (!store.getAdminPersonId()) return res.status(403).json({ error: 'set up the admin account first', reason: 'setup_required' });
  const body = req.body || {};
  const names = cleanNames(body);
  if (names.error) return res.status(400).json({ error: names.error, reason: 'names_required' });
  const email = cleanEmail(body.email);
  if (!email) return res.status(400).json({ error: 'enter a valid email', reason: 'bad_email' });
  if (quickTryLimits.blocked(req, req.sess.idHash) || quickMadeLimits.blocked(req)) return tooMany(res);
  quickTryLimits.hit(req, req.sess.idHash);
  if (store.getPersonByEmail(email)) {
    return res.status(409).json({ error: 'that email has an account -- sign in instead', reason: 'email_has_account', email });
  }
  const id = crypto.randomUUID();
  const options = await registrationOptions(rpID, { userId: id, email, displayName: `${names.firstName} ${names.lastName}` });
  store.setPending(req.sess.idHash, {
    challenge: options.challenge, kind: 'register', profile: { mode: 'quick', id, email, ...names }
  });
  res.json({ options });
});
app.post('/api/auth/quick/start', attachSession(true), quickStart);

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
const registerAdd = handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID) return;
  const p = req.person;
  const options = await registrationOptions(rpID, {
    userId: p.id, email: p.email, displayName: `${p.firstName} ${p.lastName}`, existing: store.passkeysOf(p.id)
  });
  store.setPending(req.sess.idHash, { challenge: options.challenge, kind: 'register', personId: p.id, profile: { mode: 'add' } });
  res.json({ options });
});
app.post('/api/auth/register/add', requireSignedIn, registerAdd);

// A passkey just checked out for personId: sign this browser in, under a
// new token. On first run (the setup password entered here, no admin yet)
// they're the admin now; in recovery the admin stays who it was.
//
// An app's ceremony is signed in the same way, and its new token is its
// bearer token from then on: it goes back in the answer (signedInView)
// rather than in a cookie. The app said what it is when it began.
function finishSignIn(req, res, personId) {
  const granted = hasAdminSetupGrant(req);
  const { token, idHash } = store.rotateSession(req.sess.idHash);
  if (!req.native) res.append('Set-Cookie', session.cookieHeader(token, req.hostname));
  store.signIn(idHash, personId);
  store.markSignedIn(idHash, req.native
    ? { kind: req.sess.clientKind, name: req.sess.clientName }
    : { kind: 'web', name: session.browserName(req.get('user-agent')) });
  if (granted) {
    store.takeAdminSetup(idHash);
    if (!store.getAdminPersonId()) store.setAdminPersonId(personId);
  }
  req.sess = { ...req.sess, idHash, personId, adminSetupAt: null };
  req.person = store.getPerson(personId);
  req.signedInToken = token;
}

// The answer to a step that signed someone in: who they are, and for an
// app, the token to keep.
function signedInView(req) {
  return req.native ? { token: req.signedInToken, ...meView(req) } : meView(req);
}

const registerVerify = handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID) return;
  if (!req.sess) return res.status(400).json(EXPIRED);
  const pending = store.takePending(req.sess.idHash);
  if (!pending || pending.kind !== 'register' || !pending.profile || Date.now() - pending.at > PASSKEY_CEREMONY_MS) {
    return res.status(400).json(EXPIRED);
  }
  const response = (req.body || {}).response;
  const origin = ceremonyOrigin(req, response, rpID);
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
  let tookOver = false;
  if (mode === 'new') {
    // Checked again: the setup password may have run out since.
    if (!accountsOpen(req, res)) return;
    const made = store.createPersonWithPasskey(pending.profile, cred);
    if (!made.ok) return res.status(409).json({ error: 'that email already has an account', reason: 'conflict' });
    personId = made.person.id;
  } else if (mode === 'quick') {
    if (!store.getAdminPersonId()) return res.status(403).json({ error: 'set up the admin account first', reason: 'setup_required' });
    if (quickMadeLimits.blocked(req)) return tooMany(res);
    const { id, email, firstName, lastName } = pending.profile;
    const made = store.createPersonWithPasskey({ id, email, firstName, lastName, unverified: true }, cred);
    if (!made.ok) return res.status(409).json({ error: 'that email has an account -- sign in instead', reason: 'email_has_account', email });
    quickMadeLimits.hit(req);
    personId = made.person.id;
  } else if (mode === 'existing') {
    const person = store.getPerson(personId);
    // The proven email still has to be this person's.
    if (!person || store.verifiedEmail(req.sess.idHash) !== person.email) return res.status(400).json(EXPIRED);
    // The code proved the email, so the account is verified now -- and if
    // it wasn't before, it's this inbox's owner's alone, with what its maker
    // typed in cleared (lib/db.js). The answer says so (`tookOver`), and the
    // page goes on to the profile so the owner can check the name, which is
    // still the maker's.
    const proved = store.addPasskeyProvingEmail(personId, cred, req.sess.idHash);
    if (!proved.ok) return res.status(400).json(EXPIRED);
    if (proved.tookOver) {
      try { photoStore.remove(personId); } catch (e) {}
      tookOver = true;
    }
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
  res.status(201).json(tookOver ? { ...signedInView(req), tookOver } : signedInView(req));
});
app.post('/api/auth/register/verify', attachSession(false), registerVerify);

// Sign in: no email -- the phone offers whichever passkey it has here.
const loginOptions = handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID || !accountsOpen(req, res)) return;
  const options = await webauthn.generateAuthenticationOptions({ rpID, userVerification: 'preferred' });
  store.setPending(req.sess.idHash, { challenge: options.challenge, kind: 'login' });
  res.json({ options });
});
app.post('/api/auth/login/options', attachSession(true), loginOptions);

const loginVerify = handle(async (req, res) => {
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
  const origin = ceremonyOrigin(req, response, rpID);
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
  res.json(signedInView(req));
});
app.post('/api/auth/login/verify', attachSession(false), loginVerify);

// ---------------- Signing out ----------------
//
// Ends the session itself, so it's every Canopy site at once (a site may
// keep showing someone as signed in for up to the minute it caches the
// answer for).

function signOut(req, res) {
  if (req.sess) store.endSession(req.sess.idHash);
  if (!req.native) res.append('Set-Cookie', session.clearHeader(req.hostname));
}

const signOutHere = (req, res) => {
  signOut(req, res);
  res.json({ ok: true });
};
app.post('/api/signout', attachSession(false), signOutHere);

// ---------------- Where you're signed in ----------------
//
// The profile lists every browser and app signed in as you (each one a
// session), with a way to sign any of them out, and to sign out of all of
// them at once: someone who left a laptop signed in, or lost a phone with
// the app on it, shouldn't need the admin for that. Only ever your own.

function sessionView(req, s) {
  return {
    id: s.publicId,
    // 'web', 'ios' or 'android'.
    kind: s.clientKind || 'web',
    // "Safari on iPhone", "Canopy Events on iPhone", or null when it
    // didn't say.
    name: s.clientName,
    signedInAt: s.signedInAt || s.createdAt,
    lastSeenAt: s.lastSeenAt,
    current: s.idHash === req.sess.idHash
  };
}

const listSessions = (req, res) => {
  res.json({ sessions: store.sessionsOf(req.person.id).map((s) => sessionView(req, s)) });
};
app.get('/api/profile/sessions', requireSignedIn, listSessions);

// One of them, by the id the list gave. This one is the same as signing
// out.
const endOneSession = (req, res) => {
  const ended = store.endSessionOf(req.person.id, req.params.id);
  if (!ended) return res.status(404).json({ error: 'not found', reason: 'not_found' });
  const current = ended.idHash === req.sess.idHash;
  if (current) signOut(req, res);
  res.json({ ok: true, current });
};
app.delete('/api/profile/sessions/:id', requireSignedIn, endOneSession);

// Every browser and app, this one included.
const signOutEverywhere = (req, res) => {
  store.endSessionsOf(req.person.id);
  signOut(req, res);
  res.json({ ok: true });
};
app.post('/api/signout/everywhere', requireSignedIn, signOutEverywhere);

// A link sites can put behind their "Sign out". A GET, so it's only
// honoured when the browser says it came from a Canopy page (or was typed
// in): another website linking here can't sign anyone out.
app.get('/signout', attachSession(false), (req, res) => {
  const back = safeReturn(req.query.return) || '/';
  if (req.get('sec-fetch-site') === 'cross-site') return res.redirect(req.person ? '/profile' : back);
  signOut(req, res);
  res.redirect(back);
});

// ---------------- Changing your own email ----------------
//
// The email is the key to the account (lost-passkey codes go there), so
// changing it takes three things:
//   1. a passkey, with Face ID or the like, from someone already signed
//      in: someone holding an unlocked phone, or a stolen cookie, can't;
//   2. a code sent to the NEW address, typed back: no typos, and nobody
//      claims an address that isn't theirs;
//   3. a notice to the OLD address, the only warning its owner gets if it
//      wasn't them.
// The passkey check is good for 15 minutes and one change.

const REAUTH_MS = 15 * 60 * 1000;

const reauthOptions = handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID) return;
  const mine = store.passkeysOf(req.person.id);
  const options = await webauthn.generateAuthenticationOptions({
    rpID, userVerification: 'required', allowCredentials: mine.map((k) => ({ id: k.id, transports: k.transports }))
  });
  store.setPending(req.sess.idHash, { challenge: options.challenge, kind: 'reauth', personId: req.person.id });
  res.json({ options });
});
app.post('/api/auth/reauth/options', requireSignedIn, reauthOptions);

const reauthVerify = handle(async (req, res) => {
  const rpID = requirePasskeyRp(req, res);
  if (!rpID) return;
  const pending = store.takePending(req.sess.idHash);
  if (!pending || pending.kind !== 'reauth' || pending.personId !== req.person.id || Date.now() - pending.at > PASSKEY_CEREMONY_MS) {
    return res.status(400).json(EXPIRED);
  }
  const response = (req.body || {}).response;
  const passkey = store.getPasskey(response && response.id);
  // It has to be one of the signed-in person's own.
  if (!passkey || passkey.personId !== req.person.id) return res.status(400).json(NOT_VERIFIED);
  const origin = ceremonyOrigin(req, response, rpID);
  if (!origin) return res.status(400).json(NOT_VERIFIED);
  let result;
  try {
    result = await webauthn.verifyAuthenticationResponse({
      response, expectedChallenge: pending.challenge, expectedOrigin: origin, expectedRPID: rpID,
      credential: { id: passkey.id, publicKey: passkey.publicKey, counter: passkey.counter, transports: passkey.transports },
      requireUserVerification: true
    });
  } catch (e) {
    return res.status(400).json(NOT_VERIFIED);
  }
  if (!result.verified) return res.status(400).json(NOT_VERIFIED);
  store.usePasskey(passkey.id, result.authenticationInfo.newCounter);
  store.setReauth(req.sess.idHash, Date.now());
  res.json({ ok: true });
});
app.post('/api/auth/reauth/verify', requireSignedIn, reauthVerify);

function recentlyReauthed(req) {
  return !!req.sess.reauthAt && Date.now() - req.sess.reauthAt < REAUTH_MS;
}

const REAUTH_REQUIRED = { error: 'confirm with your passkey first', reason: 'reauth_required' };

// The new address gets a code -- or, if it's already someone's account,
// a short notice instead (someone tried to move an account there, and
// nothing changed). Either way the answer is the same, and so is the work
// behind it: one email sent, and a code waiting on this session. So this
// is no way to find out who has an account. Only the code step says the
// address is taken, and the code only ever went to that inbox, so whoever
// types it already knew. Every try is counted before anything is looked
// up: per person, and the code-sending limits (per email, per address,
// and the ceiling).
const emailChangeStart = handle(async (req, res) => {
  if (!recentlyReauthed(req)) return res.status(403).json(REAUTH_REQUIRED);
  const email = cleanEmail((req.body || {}).email);
  if (!email) return res.status(400).json({ error: 'enter a valid email', reason: 'bad_email' });
  if (email === req.person.email) return res.status(400).json({ error: "that's already your email", reason: 'same_email' });
  if (emailChangeLimiter.blocked(req.person.id) || codeSendLimits.blocked(req, email)) return tooMany(res);
  emailChangeLimiter.hit(req.person.id);
  codeSendLimits.hit(req, email);
  const code = store.issueEmailCode(req.sess.idHash, email);
  const taken = !!store.getPersonByEmail(email);
  try {
    if (taken) await mailer.sendAddressInUse(email, emailLogoUrl(req));
    else await mailer.sendCode(email, code, emailLogoUrl(req));
  } catch (err) {
    console.error(`[canopy-account] sending a code failed: ${err.message}`);
    return res.status(502).json({ error: "couldn't send the email", reason: 'mail_failed' });
  }
  res.json({ ok: true, email });
});
app.post('/api/profile/email/start', requireSignedIn, emailChangeStart);

const emailChangeVerify = handle(async (req, res) => {
  if (!recentlyReauthed(req)) return res.status(403).json(REAUTH_REQUIRED);
  const email = store.codeEmail(req.sess.idHash);
  if (!email) return res.status(400).json({ error: 'that code has run out -- send a new one', reason: 'expired' });
  if (codeGuessLimits.blocked(req, email)) return tooMany(res);
  const result = store.checkEmailCode(req.sess.idHash, String((req.body || {}).code || '').replace(/\s+/g, ''));
  if (result.outcome === 'expired') return res.status(400).json({ error: 'that code has run out -- send a new one', reason: 'expired' });
  if (result.outcome === 'wrong') {
    codeGuessLimits.hit(req, email);
    return res.status(403).json({ error: "that isn't the code", reason: 'wrong_code' });
  }
  const oldEmail = req.person.email;
  // Taken: by someone else's account all along (then no code was ever
  // sent there, and this was a lucky guess), or in the meantime. Saying so
  // tells the inbox's owner nothing they don't know.
  const changed = store.setPersonEmail(req.person.id, result.email);
  if (!changed.ok) return res.status(409).json({ error: 'that email already has an account', reason: 'email_unavailable' });
  store.markEmailVerified(req.person.id);
  // One change per passkey check, and the proven address isn't left
  // lying around on the session for a sign-up.
  store.setReauth(req.sess.idHash, null);
  store.signIn(req.sess.idHash, req.person.id);
  req.person = store.getPerson(req.person.id);
  try {
    await mailer.sendEmailChanged(oldEmail, req.person.email, emailLogoUrl(req));
  } catch (err) {
    console.error(`[canopy-account] the email-changed notice to the old address failed: ${err.message}`);
  }
  res.json(meView(req));
});
app.post('/api/profile/email/verify', requireSignedIn, emailChangeVerify);

// ---------------- Proving your own email ----------------
//
// A quick sign-up (or someone whose email the admin changed) proves the
// email they have from their profile: a code sent there, typed back. The
// same codes and limits as signing in. Nothing else changes: their
// passkeys are already the ones they signed in with.

const verifyStart = handle(async (req, res) => {
  const email = req.person.email;
  if (req.person.emailVerifiedAt) return res.json({ ok: true, verified: true, email });
  if (codeSendLimits.blocked(req, email)) return tooMany(res);
  codeSendLimits.hit(req, email);
  const code = store.issueEmailCode(req.sess.idHash, email);
  try {
    await mailer.sendCode(email, code, emailLogoUrl(req));
  } catch (err) {
    console.error(`[canopy-account] sending a code failed: ${err.message}`);
    return res.status(502).json({ error: "couldn't send the email", reason: 'mail_failed' });
  }
  res.json({ ok: true, verified: false, email });
});
app.post('/api/profile/verify/start', requireSignedIn, verifyStart);

const verifyCheck = (req, res) => {
  const email = store.codeEmail(req.sess.idHash);
  // The code waiting here has to be for their own email (not one meant for
  // changing it).
  if (!email || email !== req.person.email) return res.status(400).json({ error: 'that code has run out -- send a new one', reason: 'expired' });
  if (codeGuessLimits.blocked(req, email)) return tooMany(res);
  const result = store.checkEmailCode(req.sess.idHash, String((req.body || {}).code || '').replace(/\s+/g, ''));
  if (result.outcome === 'expired') return res.status(400).json({ error: 'that code has run out -- send a new one', reason: 'expired' });
  if (result.outcome === 'wrong') {
    codeGuessLimits.hit(req, email);
    return res.status(403).json({ error: "that isn't the code", reason: 'wrong_code' });
  }
  // Their email could have been changed while the code was out.
  const person = store.getPerson(req.person.id);
  if (!person || person.email !== result.email) return res.status(400).json({ error: 'that code has run out -- send a new one', reason: 'expired' });
  store.markEmailVerified(person.id);
  // The proven address isn't left lying around on the session.
  store.signIn(req.sess.idHash, person.id);
  req.person = store.getPerson(person.id);
  res.json(meView(req));
};
app.post('/api/profile/verify/check', requireSignedIn, verifyCheck);

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

// One file from a multipart body, with any error on the way marked as the
// upload's fault. Multer's own (too big, an unexpected part) already say
// so; the parser's (a body cut short, no boundary, the connection
// dropped) are plain errors, which would otherwise be a 500.
function uploadOne(upload, field) {
  const middleware = upload.single(field);
  return (req, res, next) => middleware(req, res, (err) => {
    if (err && !(err instanceof multer.MulterError)) {
      return next(Object.assign(new Error(`bad upload: ${err.message}`), { status: 400, reason: 'bad_upload' }));
    }
    next(err);
  });
}

// The fields of a profile, from a request body, cleaned: { changes } or
// { error } (a 400 to send). Names are required; every other field is
// only touched when sent, and empty clears it. The email is only for the
// admin's edit (`withEmail`): people change everything else themselves.
function profileChanges(body, { withEmail = false } = {}) {
  const names = cleanNames(body);
  if (names.error) return { error: { error: names.error, reason: 'names_required' } };
  const changes = { names };
  const fields = [
    ['venmoHandle', 'venmo', cleanVenmo, BAD_VENMO],
    ['phone', 'phone', cleanPhone, BAD_PHONE],
    ['instagram', 'instagram', cleanInstagram, BAD_INSTAGRAM],
    ['cashapp', 'cashapp', cleanCashapp, BAD_CASHAPP]
  ];
  for (const [key, name, clean, bad] of fields) {
    if (body[key] === undefined) continue;
    const value = clean(body[key]);
    if (value === false) return { error: bad };
    changes[name] = value;
  }
  // "Let people who know your phone number or Instagram find you."
  if (body.findable !== undefined) changes.findable = body.findable === true;
  if (withEmail && body.email !== undefined) {
    const email = cleanEmail(body.email);
    if (!email) return { error: { error: 'enter a valid email', reason: 'bad_email' } };
    changes.email = email;
  }
  return { changes };
}

// Writes them; the person after, or { conflict: true } if the email is
// someone else's.
function applyProfileChanges(id, changes) {
  if (changes.email !== undefined) {
    const result = store.setPersonEmail(id, changes.email);
    if (!result.ok) return result.reason === 'conflict' ? { conflict: true } : null;
  }
  let person = store.renamePerson(id, changes.names.firstName, changes.names.lastName);
  if (!person) return null;
  if (changes.venmo !== undefined) person = store.setPersonVenmo(id, changes.venmo);
  if (changes.phone !== undefined) person = store.setPersonPhone(id, changes.phone);
  if (changes.instagram !== undefined) person = store.setPersonInstagram(id, changes.instagram);
  if (changes.cashapp !== undefined) person = store.setPersonCashapp(id, changes.cashapp);
  if (changes.findable !== undefined) person = store.setPersonFindable(id, changes.findable);
  return person;
}

const saveProfile = (req, res) => {
  const { changes, error } = profileChanges(req.body || {});
  if (error) return res.status(400).json(error);
  req.person = applyProfileChanges(req.person.id, changes);
  res.json(meView(req));
};
app.patch('/api/profile', requireSignedIn, saveProfile);

// The browser's photo is already a fresh JPEG from its canvas; an app's is
// whatever the app sent, so it has to be a JPEG this can read, and its
// metadata (where it was taken, for one) is taken out either way.
const savePhoto = (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'choose a photo', reason: 'no_photo' });
  const clean = photoStore.withoutMetadata(req.file.buffer);
  if (!clean && req.native) return res.status(400).json({ error: 'a photo is a JPEG', reason: 'bad_photo' });
  photoStore.save(req.person.id, clean || req.file.buffer);
  req.person = store.setPersonPhoto(req.person.id, Date.now());
  res.json(meView(req));
};
app.post('/api/profile/photo', requireSignedIn, uploadOne(photoUpload, 'photo'), savePhoto);

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

const listPasskeys = (req, res) => {
  res.json({ passkeys: store.passkeysOf(req.person.id).map(passkeyView) });
};
app.get('/api/profile/passkeys', requireSignedIn, listPasskeys);

const removePasskey = (req, res) => {
  const result = store.removePasskey(req.person.id, req.params.id);
  if (result.ok) return res.json({ ok: true });
  if (result.reason === 'last_passkey') {
    return res.status(409).json({ error: "that's your only passkey -- add another first", reason: 'last_passkey' });
  }
  res.status(404).json({ error: 'not found', reason: 'not_found' });
};
app.delete('/api/profile/passkeys/:id', requireSignedIn, removePasskey);

// Photos are for browsers signed in to a Canopy account, not the open
// web. Canopy sites show them straight from here: an <img> on any Canopy
// subdomain sends the cookie, since the browser counts it as the same
// site. An app has no cookie: it sends its bearer token (cookieOrBearer).
app.get('/photo/:personId', cookieOrBearer, (req, res) => {
  if (!req.person) return res.status(404).end();
  let file = null;
  try { file = photoStore.pathFor(req.params.personId); } catch (e) {}
  if (!file) return res.status(404).end();
  res.set('Content-Type', 'image/jpeg');
  res.set('Cache-Control', 'private, max-age=86400');
  res.sendFile(file);
});

// ---------------- Apps ----------------
//
// The iOS and Android apps sign in here and then use a token, sent as
// `Authorization: Bearer <token>`, to Canopy sites (events) and to this
// service. The token is a canopy_session value like any browser's cookie,
// naming a row in `sessions`, so everything that works on sessions works
// on it: /api/session, signing out (here, on the profile, everywhere),
// the admin's reset and delete, and the takeover rule.
//
// A browser keeps a sign-in that's under way on its session row (the
// challenge, the emailed code, the proven email), found by its cookie. An
// app has no cookie, so it starts with auth/begin, which makes a fresh row
// that isn't signed in and hands back its token as `ceremony`. The app
// sends that as its bearer token at every step. When a step signs in, the
// row is signed in under a new token (as a browser's is), which comes
// back as `token`: the app keeps that one, in the Keychain or Keystore.
// A ceremony nobody finishes runs out after a day, like a browser's.
//
// Every step below is the web's own handler, mounted again: the same
// rules, the same limits (counted in the same counters, so the web and
// the apps share one budget), the same answers. What differs is decided
// by req.native: no cookies set or cleared, the token in the answer,
// passkeys accepted from the apps' origins, and a photo that has to be a
// JPEG. docs/native-api.md is the guide for app developers, and
// openapi.yaml the contract.
const native = express.Router();
app.use(NATIVE, (req, res, next) => {
  req.native = true;
  // Tokens travel in these answers.
  res.set('Cache-Control', 'no-store');
  next();
}, native);

// A step in a sign-in: the bearer has to be a ceremony from auth/begin,
// still running. An app that's signed in signs out before signing in
// again, so a signed-in token is never turned into someone else's.
function nativeCeremony(req, res, next) {
  bearerSession(req);
  if (!req.sess) return res.status(400).json(EXPIRED);
  if (req.person) return res.status(409).json({ error: 'already signed in -- sign out first', reason: 'signed_in' });
  next();
}

function nativeSignedIn(req, res, next) {
  bearerSession(req);
  if (req.person) return next();
  res.status(401).json({ error: 'unauthorized', reason: 'signed_out' });
}

function nativeAnyone(req, res, next) {
  bearerSession(req);
  next();
}

// What the app calls itself, for the person's list of where they're
// signed in: "Canopy Events on iPhone". Plain text, short, and only ever
// shown to the person themself.
function cleanLabel(raw) {
  return String(raw == null ? '' : raw).replace(/[\u0000-\u001f\u007f]/g, '').replace(/\s+/g, ' ').trim().slice(0, 40);
}

// Starts a sign-in (or sign-up) from an app: { platform: 'ios' |
// 'android', app?, device? } -> { ceremony }.
native.post('/auth/begin', (req, res) => {
  const body = req.body || {};
  if (body.platform !== 'ios' && body.platform !== 'android') {
    return res.status(400).json({ error: 'platform is ios or android', reason: 'bad_platform' });
  }
  const appName = cleanLabel(body.app);
  const device = cleanLabel(body.device);
  const name = appName && device ? `${appName} on ${device}` : appName || device || null;
  const { token } = store.createSession({ kind: body.platform, name });
  res.status(201).json({ ceremony: token });
});

// Signing in with a passkey.
native.post('/auth/passkey/options', nativeCeremony, loginOptions);
native.post('/auth/passkey/verify', nativeCeremony, loginVerify);
// An email and a code, then a new account or a new passkey.
native.post('/auth/email/start', nativeCeremony, emailStart);
native.post('/auth/email/verify', nativeCeremony, emailVerify);
native.post('/auth/register/new', nativeCeremony, registerNew);
native.post('/auth/register/existing', nativeCeremony, registerExisting);
// The quick sign-up.
native.post('/auth/quick/start', nativeCeremony, quickStart);
// The passkey that finishes any of the three above.
native.post('/auth/register/verify', nativeCeremony, registerVerify);

// Signing out: this token, or every browser and app.
native.post('/signout', nativeAnyone, signOutHere);
native.post('/signout/everywhere', nativeSignedIn, signOutEverywhere);

// The profile.
native.get('/me', nativeSignedIn, me);
native.patch('/me', nativeSignedIn, saveProfile);
native.post('/me/photo', nativeSignedIn, uploadOne(photoUpload, 'photo'), savePhoto);
native.get('/me/passkeys', nativeSignedIn, listPasskeys);
native.post('/me/passkeys/options', nativeSignedIn, registerAdd);
native.post('/me/passkeys/verify', nativeSignedIn, registerVerify);
native.delete('/me/passkeys/:id', nativeSignedIn, removePasskey);
// Changing the email: a passkey check, then a code to the new address.
native.post('/me/reauth/options', nativeSignedIn, reauthOptions);
native.post('/me/reauth/verify', nativeSignedIn, reauthVerify);
native.post('/me/email/start', nativeSignedIn, emailChangeStart);
native.post('/me/email/verify', nativeSignedIn, emailChangeVerify);
// Proving the email (an unverified account's banner).
native.post('/me/verify/start', nativeSignedIn, verifyStart);
native.post('/me/verify/check', nativeSignedIn, verifyCheck);
// Where they're signed in.
native.get('/me/sessions', nativeSignedIn, listSessions);
native.delete('/me/sessions/:id', nativeSignedIn, endOneSession);

// The contract, for app developers and their tools. test/docs.test.js
// keeps it and the routes above in step.
const OPENAPI = fs.readFileSync(path.join(__dirname, 'openapi.yaml'), 'utf8');
native.get('/openapi.yaml', (req, res) => {
  res.set('Content-Type', 'application/yaml; charset=utf-8');
  res.send(OPENAPI);
});

// Anything else under /api/native/v1 is an app asking for something that
// isn't there: JSON, like every other answer it gets, not a page. So is
// anything that goes wrong (jsonErrors).
native.use((req, res) => res.status(404).json({ error: 'not found', reason: 'not_found' }));
native.use((err, req, res, next) => jsonErrors(err, req, res, next));

// ---------------- Admin ----------------

function adminPersonView(req, p) {
  return {
    ...personView(req, p),
    passkeyCount: p.passkeyCount !== undefined ? p.passkeyCount : store.passkeysOf(p.id).length,
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

// The admin's "Edit profile": every field the person can set, and their
// email. A changed email is unverified until its owner types a code sent
// there, so sites that don't allow unverified accounts see them as signed
// out until then: the admin can't vouch for an address on someone's behalf.
//
// The admin's own email isn't changed here: it would leave the admin
// unverified, and an unverified account can't open this page. Their own
// profile changes it, with a passkey and a code, like anyone's.
app.patch('/api/admin/people/:id', (req, res) => {
  const current = store.getPerson(req.params.id);
  if (!current) return res.status(404).json({ error: 'not found' });
  const { changes, error } = profileChanges(req.body || {}, { withEmail: true });
  if (error) return res.status(400).json(error);
  if (req.params.id === store.getAdminPersonId() && changes.email !== undefined && changes.email !== current.email) {
    return res.status(409).json({ error: 'change your own email from your profile', reason: 'own_email' });
  }
  const person = applyProfileChanges(req.params.id, changes);
  if (person && person.conflict) return res.status(409).json({ error: 'that email already has an account', reason: 'conflict' });
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

// A site's switches: { allowsUnverified, allowsLookup }.
app.patch('/api/admin/apps/:id', (req, res) => {
  const body = req.body || {};
  const settings = {};
  if (body.allowsUnverified !== undefined) settings.allowsUnverified = !!body.allowsUnverified;
  if (body.allowsLookup !== undefined) settings.allowsLookup = !!body.allowsLookup;
  const site = store.setAppSettings(req.params.id, settings);
  if (!site) return res.status(404).json({ error: 'not found' });
  res.json({ app: site });
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

// Who the visitor is. The site passes their canopy_session value in
// X-Canopy-Session (from the cookie, or an app's bearer token), and its
// own host in X-Canopy-Site-Host so the renewed cookie (when one's due) is
// made for the right domain. The answer: { person } (null if not signed
// in), and `renewCookie`, a Set-Cookie value the site should send back to
// the visitor as is. No X-Canopy-Site-Host, no renewCookie: an app's
// token has no cookie to renew.
//
// Someone whose email isn't proven is only signed in on a site the admin
// lets unverified accounts into. Anywhere else the answer is { person:
// null, unverified: true }, so the site can send them to prove it rather
// than to sign in again. That's decided here, never by the site. The
// session is still theirs, so it's kept alive and renewed as usual.
app.get('/api/session', requireSite, (req, res) => {
  res.set('Cache-Control', 'no-store');
  const token = session.readToken(`${session.COOKIE}=${req.get('x-canopy-session') || ''}`);
  const s = token && store.getSessionByToken(token);
  const person = s && s.personId ? store.getPerson(s.personId) : null;
  if (!person) return res.json({ person: null });
  store.touchSession(s.idHash, s.lastSeenAt);
  const body = person.emailVerifiedAt || req.site.allowsUnverified
    ? { person: personView(req, person) }
    : { person: null, unverified: true };
  const siteHost = req.get('x-canopy-site-host');
  if (siteHost && session.needsRenewal(s)) {
    body.renewCookie = session.cookieHeader(token, siteHost);
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
  res.json({ people: store.peopleByIds(ids).map((p) => publicPersonView(req, p)) });
});

// ---------------- Finding someone by phone or Instagram ----------------
//
// GET /api/people/lookup?phone=… or ?instagram=… (one of them): the one
// person whose profile has exactly that, in the public shape, or { person:
// null }. For a host who already has someone's number or handle and wants
// to invite them. It's one-way: knowing the number finds the account, and
// the answer never carries a contact detail, not even the one asked about.
//
//   - The input is cleaned exactly as the profile cleans it (cleanPhone,
//     cleanInstagram), and matched exactly. Never by prefix or anything
//     fuzzy, so it can't be used to list people.
//   - Only sites the admin lets look people up, and only for a visitor
//     signed in there (X-Canopy-Session, as for /api/session) whose email
//     is proven: limits are per asker, so an asker has to be someone, and
//     an unverified account is too cheap to make.
//   - Nobody who turned "Let people ... find you" off, and nobody when two
//     accounts claim the same one (lib/db.js).
//   - A miss is { person: null } and says nothing about why.
//
// Phone numbers can be listed by brute force (an area code is ten million
// of them), so it's limited tightly: 30 an hour and 100 a day per asker,
// 60 an hour per address (the visitor's, which the site passes in
// X-Canopy-Visitor-Ip, or else the site's own), and 300 an hour across
// everyone. Every lookup counts, found or not.
const HOUR = 60 * 60 * 1000;
const lookupLimits = {
  askerHour: attemptLimiter(30, HOUR),
  askerDay: attemptLimiter(100, 24 * HOUR),
  address: attemptLimiter(60, HOUR),
  overall: attemptLimiter(300, HOUR),
  blocked(asker, address) {
    return this.askerHour.blocked(asker) || this.askerDay.blocked(asker) || this.address.blocked(address) || this.overall.blocked('all');
  },
  hit(asker, address) {
    this.askerHour.hit(asker);
    this.askerDay.hit(asker);
    this.address.hit(address);
    this.overall.hit('all');
  }
};

app.get('/api/people/lookup', requireSite, (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (!req.site.allowsLookup) return res.status(403).json({ error: 'this site may not look people up', reason: 'lookup_not_allowed' });
  const token = session.readToken(`${session.COOKIE}=${req.get('x-canopy-session') || ''}`);
  const s = token && store.getSessionByToken(token);
  const asker = s && s.personId ? store.getPerson(s.personId) : null;
  if (!asker) return res.status(401).json({ error: 'not signed in', reason: 'signed_out' });
  if (!asker.emailVerifiedAt) return res.status(403).json({ error: 'confirm your email first', reason: 'email_unverified' });

  const { phone, instagram } = req.query;
  if ((phone === undefined) === (instagram === undefined) || Array.isArray(phone) || Array.isArray(instagram)) {
    return res.status(400).json({ error: 'give one of phone or instagram', reason: 'one_of' });
  }
  const address = String(req.get('x-canopy-visitor-ip') || clientIp(req)).slice(0, 64);
  if (lookupLimits.blocked(asker.id, address)) return tooMany(res);
  lookupLimits.hit(asker.id, address);

  const wanted = phone !== undefined ? { phone: cleanPhone(phone) } : { instagram: cleanInstagram(instagram) };
  if (wanted.phone === false || wanted.phone === null) return res.status(400).json(BAD_PHONE);
  if (wanted.instagram === false || wanted.instagram === null) return res.status(400).json(BAD_INSTAGRAM);
  const found = store.findPerson(wanted);
  res.json({ person: found ? publicPersonView(req, found) : null });
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
// The logo as the code email shows it: absolute, since mail apps fetch it
// from the open web, and following an uploaded logo like the pages do.
function emailLogoUrl(req) {
  const meta = logoImageStore.getMeta();
  return `${publicBase(req)}${meta ? `/logo-image?v=${meta.uploadedAt}` : '/canopy-logo.png'}`;
}

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

// Where someone lands here with nowhere else to go: the admin's is the
// Account Manager, everyone else's their profile.
function homeFor(req) {
  return isAdmin(req) ? '/admin' : '/profile';
}

// Sign in or sign up, then back to ?return= (a Canopy page) or home.
// Already signed in: straight there.
app.get('/', attachSession(false), (req, res) => {
  const back = safeReturn(req.query.return);
  if (req.person) return res.redirect(back || homeFor(req));
  renderPage(res, 'welcome.html', { returnUrl: back || '' });
});

// ?verify=1 opens straight into proving the email, and ?return= (a
// Canopy page) is where to go once it's done: where a site sends someone
// it won't let in unverified. Already verified, they go straight back.
// Signed out, they sign in first and come back here.
app.get('/profile', attachSession(false), (req, res) => {
  const back = safeReturn(req.query.return);
  if (!req.person) {
    if (req.query.verify === undefined) return res.redirect('/');
    const here = `${publicBase(req)}/profile?verify=1${back ? `&return=${encodeURIComponent(back)}` : ''}`;
    return res.redirect('/?return=' + encodeURIComponent(here));
  }
  if (req.query.verify !== undefined && req.person.emailVerifiedAt && back) return res.redirect(back);
  renderPage(res, 'profile.html', { returnUrl: back || '' });
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
  app.post(`/api/admin/${urlName}`, uploadOne(siteImageUpload, 'image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'choose a PNG, JPEG, WebP, or GIF image' });
    const meta = imageStore.save(req.file.buffer, req.file.mimetype);
    res.json({ ok: true, uploadedAt: meta.uploadedAt, url: `/${urlName}?v=${meta.uploadedAt}` });
  });
  app.delete(`/api/admin/${urlName}`, (req, res) => {
    imageStore.remove();
    res.json({ ok: true });
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

// Errors under /api/ (and a bad upload or JSON body anywhere) as JSON
// rather than Express's HTML page. The apps' router has the same, for what
// goes wrong inside it.
app.use((err, req, res, next) => {
  const parsing = err instanceof multer.MulterError || (err && /^entity\./.test(err.type || ''));
  if (req.path.startsWith('/api/') || parsing) return jsonErrors(err, req, res, next);
  next(err);
});

// Started as the server (node server.js); a test can require this file
// for the routes without it listening.
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`canopy-account listening on port ${PORT}`);
  });
}

module.exports = { app, native };
