// Canopy Accounts, for a Canopy site (tickets, events, the next one...).
// Copy this one file into the site; it has no dependencies (Node 18+, for
// fetch).
//
//   const canopy = require('./lib/canopy-account')({
//     url: process.env.CANOPY_ACCOUNT_URL,   // https://account.canopysf.com
//     key: process.env.CANOPY_ACCOUNT_KEY    // from the account admin's Sites tab
//   });
//
//   app.set('trust proxy', true);          // so return URLs say https
//   app.use(canopy.attach);                // req.person: the visitor, or null
//   app.get('/mine', canopy.requireSignIn, ...);   // signed in, or off to sign in
//   const people = await canopy.people(ids);       // Map of id -> { firstName, ... }
//   const found = await canopy.lookup(req, { phone: '415 555 1234' });  // or { instagram }
//
// A site with a calendar (it shows up in each person's Canopy calendar
// feed) also passes `calendarSecret: process.env.CANOPY_CALENDAR_SECRET`
// (from the same Sites tab), and checks the account service's requests
// with it:
//
//   app.get('/api/calendar/:personId', (req, res) => {
//     const personId = canopy.verifyCalendarRequest(req);   // or null
//     if (!personId) return res.status(401).json({ error: 'not the account service' });
//     res.json({ entries: [...] });   // see the account service's README
//   });
//
// req.person is { id, emailVerified, firstName, lastName, shortName,
// photoUrl, findable }, plus whichever of the visitor's own email, phone,
// instagram, venmo and cashapp the account admin has granted this site in
// the Sites tab (none, for a new site). A field that wasn't granted isn't
// there at all; one that was granted is null when they haven't filled it
// in. They're the visitor's own details, never to be shown to anyone else,
// and a site that doesn't show them shouldn't be granted them: what it's
// never sent can't leak from it. photoUrl points at the account service
// and works straight in an <img> on any Canopy page (the browser sends the
// cookie along).
//
// Who the visitor is comes from their canopy_session cookie, or from an
// `Authorization: Bearer <token>` header carrying the same 43-character
// value (for the native apps, which get it by signing in through the
// account service's /api/native/v1; the bearer wins when both are there).
// Nothing is ever sent back as Set-Cookie for a bearer request.
//
// Someone whose email isn't proven yet (a quick sign-up) is only signed in
// on a site the account admin lets them into. Anywhere else req.person is
// null and req.canopyUnverified is true: send them to verifyUrl(), which
// requireSignIn does by itself. On a site that lets them in, req.person
// is there with emailVerified: false.
//
// The answer for each visitor is cached for a minute (`cacheMs`), so a
// sign-out, a name change or a newly confirmed email can take that long to
// show here. A person missing from people() has been deleted: show them
// as a former member, keeping whatever this site recorded for them.
//
// Other people -- people() and lookup() -- are only ever { id, firstName,
// lastName, shortName, photoUrl }. Never show one person another's email,
// phone, Instagram, Venmo or Cash App: this site never gets them anyway.

const crypto = require('crypto');

const COOKIE = 'canopy_session';
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

// How far the account service's clock and this one's may disagree, and so
// how long a signed calendar request can be replayed, in seconds.
const CALENDAR_SKEW_S = 5 * 60;
const CALENDAR_AUTH_RE = /^Canopy-Calendar\s+t=(\d{1,12}),\s*sig=([0-9a-fA-F]{64})$/;

module.exports = function createCanopyAccount({ url, key, cacheMs = 60 * 1000, calendarSecret } = {}) {
  if (!url || !key) throw new Error('canopy-account: url and key are both required');
  const base = String(url).replace(/\/+$/, '');
  const headers = { Authorization: `Bearer ${key}` };

  // token hash -> { answer: { person, unverified }, at }
  const cache = new Map();
  // How long a cached answer may stand in while the account service
  // can't be reached, before this gives up and says so (503).
  const STALE_OK_MS = 15 * 60 * 1000;

  // { token, bearer }: the visitor's session token, from a bearer header
  // or else the cookie. A bearer header that isn't a session token means
  // nobody (it doesn't fall back to the cookie: what the caller sent is
  // what counts). Other Authorization schemes are left alone.
  function readToken(req) {
    const auth = /^Bearer\s+(.*)$/i.exec(String(req.headers.authorization || '').trim());
    if (auth) return { token: TOKEN_RE.test(auth[1]) ? auth[1] : null, bearer: true };
    const pair = String(req.headers.cookie || '')
      .split(';')
      .map((p) => p.trim())
      .find((p) => p.startsWith(COOKIE + '='));
    const token = pair && pair.slice(COOKIE.length + 1);
    return { token: token && TOKEN_RE.test(token) ? token : null, bearer: false };
  }

  const NOBODY = { person: null, unverified: false };

  // { person, unverified } for this request.
  async function whoIs(req, res) {
    const { token, bearer } = readToken(req);
    if (!token) return NOBODY;
    const id = crypto.createHash('sha256').update(token).digest('hex');
    const hit = cache.get(id);
    if (hit && Date.now() - hit.at < cacheMs) return hit.answer;
    let body;
    try {
      const h = { ...headers, 'X-Canopy-Session': token };
      // Only a cookie gets renewed, so only a cookie says where it lives.
      if (!bearer) h['X-Canopy-Site-Host'] = req.hostname || '';
      const r = await fetch(`${base}/api/session`, { headers: h });
      if (!r.ok) throw new Error(`account service answered ${r.status}`);
      body = await r.json();
    } catch (err) {
      if (hit && Date.now() - hit.at < STALE_OK_MS) return hit.answer;
      err.canopyUnreachable = true;
      throw err;
    }
    // The cookie's year is renewed from here as well as from the account
    // service itself, so someone who only ever visits this site stays in.
    if (body.renewCookie && !bearer) res.append('Set-Cookie', body.renewCookie);
    const answer = { person: body.person || null, unverified: !body.person && !!body.unverified };
    if (cache.size > 5000) cache.clear();
    cache.set(id, { answer, at: Date.now() });
    return answer;
  }

  function hereUrl(req) {
    return `${req.protocol}://${req.get('host')}${req.originalUrl}`;
  }

  // Where to send someone to sign in, and come back to `returnTo` (this
  // page, by default).
  function signInUrl(req, returnTo) {
    return `${base}/?return=${encodeURIComponent(returnTo || hereUrl(req))}`;
  }

  // The quick sign-up (name, email, passkey; no code), and back to
  // `returnTo`. Only worth linking from a site that allows unverified
  // accounts: anywhere else the account it makes counts as signed out.
  function quickSignUpUrl(req, returnTo) {
    return `${base}/?quick=1&return=${encodeURIComponent(returnTo || hereUrl(req))}`;
  }

  // Where someone proves their email (a code), and back to `returnTo`.
  function verifyUrl(req, returnTo) {
    return `${base}/profile?verify=1&return=${encodeURIComponent(returnTo || hereUrl(req))}`;
  }

  // Signs out of every Canopy site, then back to `returnTo`.
  function signOutUrl(req, returnTo) {
    return `${base}/signout?return=${encodeURIComponent(returnTo || `${req.protocol}://${req.get('host')}/`)}`;
  }

  function unreachable(res, err) {
    console.error(`[canopy-account] ${err.message}`);
    res.status(503).send('Canopy Accounts could not be reached. Try again in a minute.');
  }

  async function settle(req, res) {
    const { person, unverified } = await whoIs(req, res);
    req.person = person;
    req.canopyUnverified = unverified;
  }

  // Puts req.person on every request (the signed-in visitor, or null), and
  // req.canopyUnverified (true for someone signed in whose email this site
  // needs proven first).
  async function attach(req, res, next) {
    try {
      await settle(req, res);
      next();
    } catch (err) {
      if (err.canopyUnreachable) return unreachable(res, err);
      next(err);
    }
  }

  // Signed in, or: a page is sent to sign in (or, for someone whose email
  // isn't proven, to prove it) and back; an API call gets a 401 (or a 403
  // with reason "email_unverified"). Works with or without attach before
  // it.
  async function requireSignIn(req, res, next) {
    try {
      if (req.person === undefined) await settle(req, res);
    } catch (err) {
      if (err.canopyUnreachable) return unreachable(res, err);
      return next(err);
    }
    if (req.person) return next();
    const wantsPage = req.method === 'GET' && String(req.get('accept') || '').includes('text/html');
    const backTo = req.get('referer') || undefined;
    if (req.canopyUnverified) {
      if (wantsPage) return res.redirect(verifyUrl(req));
      return res.status(403).json({ error: 'confirm your email first', reason: 'email_unverified', verify: verifyUrl(req, backTo) });
    }
    if (wantsPage) return res.redirect(signInUrl(req));
    res.status(401).json({ error: 'unauthorized', signIn: signInUrl(req, backTo) });
  }

  // Names and photos for other people, as a Map of id -> { id, firstName,
  // lastName, shortName, photoUrl }. Not cached: ask once per request and
  // reuse it.
  async function people(ids) {
    const unique = Array.from(new Set((ids || []).filter(Boolean)));
    const found = new Map();
    for (let i = 0; i < unique.length; i += 200) {
      const r = await fetch(`${base}/api/people?ids=${encodeURIComponent(unique.slice(i, i + 200).join(','))}`, { headers });
      if (!r.ok) throw new Error(`account service answered ${r.status}`);
      (await r.json()).people.forEach((p) => found.set(p.id, p));
    }
    return found;
  }

  function lookupError(status, reason, message) {
    const err = new Error(message);
    err.status = status;
    err.reason = reason;
    return err;
  }

  // The one person whose profile has exactly this phone number or
  // Instagram, as { id, firstName, lastName, shortName, photoUrl }, or
  // null. `query` is { phone } or { instagram }, as someone typed it (the
  // account service cleans it the way the profile does). Asked as the
  // visitor, who has to be signed in with a proven email, and only on a
  // site the account admin lets look people up. Anything else rejects
  // with an Error carrying `status` and `reason`: 401 signed_out, 403
  // email_unverified or lookup_not_allowed, 400 bad_phone, bad_instagram
  // or one_of, 429 rate_limited. Not cached. It's a POST with the number
  // or handle in the body, never in the URL: don't log `query` either.
  async function lookup(req, query) {
    const { token } = readToken(req);
    if (!token) throw lookupError(401, 'signed_out', 'not signed in');
    const q = query || {};
    let body;
    if (q.phone != null && q.instagram == null) body = { phone: String(q.phone) };
    else if (q.instagram != null && q.phone == null) body = { instagram: String(q.instagram) };
    else throw lookupError(400, 'one_of', 'give one of phone or instagram');
    // The visitor's address, for the per-address limit.
    const ip = (typeof req.get === 'function' && req.get('cf-connecting-ip')) || req.ip || '';
    // A POST, so the number or handle is in the body and never in a URL
    // (which ends up in logs along the way).
    const r = await fetch(`${base}/api/people/lookup`, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json', 'X-Canopy-Session': token, 'X-Canopy-Visitor-Ip': ip },
      body: JSON.stringify(body)
    });
    const answer = await r.json().catch(() => ({}));
    if (!r.ok) throw lookupError(r.status, answer.reason, answer.error || `account service answered ${r.status}`);
    return answer.person || null;
  }

  // The person whose calendar the account service is asking for, if this
  // request really is the account service's: GET .../api/calendar/<personId>
  // with `Authorization: Canopy-Calendar t=<unix seconds>, sig=<hex>`,
  // sig being HMAC-SHA256 with this site's calendar secret of
  // "canopy-calendar-v1\n<personId>\n<t>", and t within five minutes of
  // now. The secret never travels, only a signature good for that one
  // person for those few minutes. null for anything else, including a
  // site with no calendarSecret set. The person id comes from the path
  // (req.params.personId, or the URL's last part).
  function verifyCalendarRequest(req) {
    if (!calendarSecret) return null;
    const m = CALENDAR_AUTH_RE.exec(String(req.headers.authorization || '').trim());
    if (!m) return null;
    let personId = req.params && req.params.personId;
    if (!personId) {
      const path = String(req.originalUrl || req.url || '').split('?')[0];
      try { personId = decodeURIComponent(path.slice(path.lastIndexOf('/') + 1)); } catch (e) { return null; }
    }
    if (!personId || personId.length > 100) return null;
    if (Math.abs(Date.now() / 1000 - Number(m[1])) > CALENDAR_SKEW_S) return null;
    const want = crypto.createHmac('sha256', String(calendarSecret)).update(`canopy-calendar-v1\n${personId}\n${m[1]}`).digest();
    return crypto.timingSafeEqual(want, Buffer.from(m[2], 'hex')) ? personId : null;
  }

  return { attach, requireSignIn, people, lookup, signInUrl, signOutUrl, quickSignUpUrl, verifyUrl, verifyCalendarRequest };
};
