// The canopy_session cookie: a random token naming a row in `sessions`
// (lib/db.js stores only its hash). Sent to canopysf.com and every
// subdomain, so signing in on one Canopy site signs you in on all of them;
// HttpOnly, so page scripts can't read it; Secure, so it only travels over
// https.
//
// Good for a year from the last visit: a response more than a day after
// the cookie was last sent carries a fresh one. Sites renew it too -- they
// only see the visitor's session through /api/session, which hands them
// the Set-Cookie to pass on when it's due (see client/canopy-account.js).

const { cookieDomainFor } = require('./domain');

const COOKIE = 'canopy_session';
const TTL_MS = 365 * 24 * 60 * 60 * 1000;
const RENEW_AFTER_MS = 24 * 60 * 60 * 1000;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

function readToken(cookieHeader) {
  const pair = String(cookieHeader || '')
    .split(';')
    .map((p) => p.trim())
    .find((p) => p.startsWith(COOKIE + '='));
  if (!pair) return null;
  const token = pair.slice(COOKIE.length + 1);
  return TOKEN_RE.test(token) ? token : null;
}

// The Set-Cookie value for `token`. `host` decides the Domain: the base
// domain on any Canopy host, none locally.
function cookieHeader(token, host) {
  const domain = cookieDomainFor(host);
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${COOKIE}=${token}; Path=/${domain ? `; Domain=${domain}` : ''}; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(
    TTL_MS / 1000
  )}${secure}`;
}

function clearHeader(host) {
  const domain = cookieDomainFor(host);
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${COOKIE}=; Path=/${domain ? `; Domain=${domain}` : ''}; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}

function needsRenewal(session) {
  return Date.now() - session.cookieSetAt > RENEW_AFTER_MS;
}

// "Safari on iPhone", from a User-Agent, for the person's own list of
// where they're signed in. Only a hint (anything can send any
// User-Agent), so it's never used for anything but that label. An iPad's
// Safari says it's a Mac, and so it's called one.
function browserName(userAgent) {
  const ua = String(userAgent || '');
  const device = /iPhone/.test(ua) ? 'iPhone'
    : /iPad/.test(ua) ? 'iPad'
    : /Android/.test(ua) ? 'Android'
    : /CrOS/.test(ua) ? 'Chromebook'
    : /Macintosh/.test(ua) ? 'Mac'
    : /Windows/.test(ua) ? 'Windows'
    : /Linux/.test(ua) ? 'Linux'
    : null;
  const browser = /Edg(A|iOS)?\//.test(ua) ? 'Edge'
    : /Firefox\/|FxiOS\//.test(ua) ? 'Firefox'
    : /SamsungBrowser\//.test(ua) ? 'Samsung Internet'
    : /Chrome\/|CriOS\//.test(ua) ? 'Chrome'
    : /Safari\//.test(ua) ? 'Safari'
    : null;
  if (browser && device) return `${browser} on ${device}`;
  return browser || device;
}

module.exports = { COOKIE, TTL_MS, readToken, cookieHeader, clearHeader, needsRenewal, browserName };
