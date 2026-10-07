// Canopy accounts, for a Canopy site (tickets, the next one...). Copy this
// one file into the site; it has no dependencies (Node 18+, for fetch).
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
//
// req.person is { id, email, firstName, lastName, shortName, photoUrl,
// venmo }. photoUrl points at the account service and works straight in
// an <img> on any Canopy page (the browser sends the cookie along).
//
// The answer for each visitor is cached for a minute (`cacheMs`), so a
// sign-out or a name change can take that long to show here. A person
// missing from people() has been deleted: show them as a former member,
// keeping whatever this site recorded for them.

const crypto = require('crypto');

const COOKIE = 'canopy_session';
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

module.exports = function createCanopyAccount({ url, key, cacheMs = 60 * 1000 } = {}) {
  if (!url || !key) throw new Error('canopy-account: url and key are both required');
  const base = String(url).replace(/\/+$/, '');
  const headers = { Authorization: `Bearer ${key}` };

  // token hash -> { person, at }
  const cache = new Map();
  // How long a cached answer may stand in while the account service
  // can't be reached, before this gives up and says so (503).
  const STALE_OK_MS = 15 * 60 * 1000;

  function readToken(req) {
    const pair = String(req.headers.cookie || '')
      .split(';')
      .map((p) => p.trim())
      .find((p) => p.startsWith(COOKIE + '='));
    const token = pair && pair.slice(COOKIE.length + 1);
    return token && TOKEN_RE.test(token) ? token : null;
  }

  async function lookup(req, res) {
    const token = readToken(req);
    if (!token) return null;
    const id = crypto.createHash('sha256').update(token).digest('hex');
    const hit = cache.get(id);
    if (hit && Date.now() - hit.at < cacheMs) return hit.person;
    let body;
    try {
      const r = await fetch(`${base}/api/session`, {
        headers: { ...headers, 'X-Canopy-Session': token, 'X-Canopy-Site-Host': req.hostname || '' }
      });
      if (!r.ok) throw new Error(`account service answered ${r.status}`);
      body = await r.json();
    } catch (err) {
      if (hit && Date.now() - hit.at < STALE_OK_MS) return hit.person;
      err.canopyUnreachable = true;
      throw err;
    }
    // The cookie's year is renewed from here as well as from the account
    // service itself, so someone who only ever visits this site stays in.
    if (body.renewCookie) res.append('Set-Cookie', body.renewCookie);
    if (cache.size > 5000) cache.clear();
    cache.set(id, { person: body.person || null, at: Date.now() });
    return body.person || null;
  }

  function hereUrl(req) {
    return `${req.protocol}://${req.get('host')}${req.originalUrl}`;
  }

  // Where to send someone to sign in, and come back to `returnTo` (this
  // page, by default).
  function signInUrl(req, returnTo) {
    return `${base}/?return=${encodeURIComponent(returnTo || hereUrl(req))}`;
  }

  // Signs out of every Canopy site, then back to `returnTo`.
  function signOutUrl(req, returnTo) {
    return `${base}/signout?return=${encodeURIComponent(returnTo || `${req.protocol}://${req.get('host')}/`)}`;
  }

  function unreachable(res, err) {
    console.error(`[canopy-account] ${err.message}`);
    res.status(503).send('Canopy accounts could not be reached. Try again in a minute.');
  }

  // Puts req.person on every request: the signed-in visitor, or null.
  async function attach(req, res, next) {
    try {
      req.person = await lookup(req, res);
      next();
    } catch (err) {
      if (err.canopyUnreachable) return unreachable(res, err);
      next(err);
    }
  }

  // Signed in, or: a page is sent to sign in (and back), an API call gets
  // a 401. Works with or without attach before it.
  async function requireSignIn(req, res, next) {
    try {
      if (req.person === undefined) req.person = await lookup(req, res);
    } catch (err) {
      if (err.canopyUnreachable) return unreachable(res, err);
      return next(err);
    }
    if (req.person) return next();
    const wantsPage = req.method === 'GET' && String(req.get('accept') || '').includes('text/html');
    if (wantsPage) return res.redirect(signInUrl(req));
    res.status(401).json({ error: 'unauthorized', signIn: signInUrl(req, req.get('referer') || undefined) });
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

  return { attach, requireSignIn, people, signInUrl, signOutUrl };
};
