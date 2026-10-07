// Which addresses count as Canopy: canopysf.com and every subdomain of it,
// over https. One answer, used for everything that has to ask it --
//
//   - where ?return= may send someone after signing in or out (anything
//     else would make this service a way to bounce people to other sites);
//   - which pages may make a change here (the Origin check in server.js;
//     the browser already keeps other sites from sending the cookie, this
//     covers Canopy's own subdomains' pages);
//   - which pages a passkey may be used on.
//
// CANOPY_DOMAIN overrides the domain. Outside production, http on
// localhost / 127.0.0.1 counts too, so it can be run and tested locally.

const BASE = (process.env.CANOPY_DOMAIN || 'canopysf.com').toLowerCase();
const PRODUCTION = process.env.NODE_ENV === 'production';

function isLocalHost(host) {
  return host === 'localhost' || host === '127.0.0.1';
}

// A URL (string) is a Canopy page: https on the domain or a subdomain of
// it, with no username/password part (https://canopysf.com@evil.example
// reads as canopysf.com to a person and evil.example to a browser).
function isCanopyUrl(raw) {
  let url;
  try { url = new URL(String(raw)); } catch (e) { return false; }
  if (url.username || url.password) return false;
  const host = url.hostname.toLowerCase();
  if (!PRODUCTION && url.protocol === 'http:' && isLocalHost(host)) return true;
  return url.protocol === 'https:' && (host === BASE || host.endsWith('.' + BASE));
}

// An Origin header value ("https://tickets.canopysf.com") is a Canopy page.
function isCanopyOrigin(origin) {
  return !!origin && origin !== 'null' && isCanopyUrl(origin);
}

// ?return= cleaned: the URL if it's a Canopy page, otherwise null.
function safeReturn(raw) {
  if (typeof raw !== 'string' || !raw || raw.length > 2000) return null;
  return isCanopyUrl(raw) ? new URL(raw).toString() : null;
}

// The cookie's Domain: the base domain on it or a subdomain, so every
// Canopy site gets it. Locally, none (the browser keeps it to this host).
function cookieDomainFor(host) {
  host = String(host || '').toLowerCase();
  return host === BASE || host.endsWith('.' + BASE) ? BASE : null;
}

// Passkeys belong to the base domain, so one made here works on every
// subdomain. PASSKEY_RP_ID overrides; anywhere else (localhost) uses the
// page's own host. Null when this host can't use passkeys at all.
function passkeyRpId(host) {
  host = String(host || '').toLowerCase();
  const rpID = process.env.PASSKEY_RP_ID || (host === BASE || host.endsWith('.' + BASE) ? BASE : host);
  if (!host || (host !== rpID && !host.endsWith('.' + rpID))) return null;
  return rpID;
}

module.exports = { BASE, isCanopyUrl, isCanopyOrigin, safeReturn, cookieDomainFor, passkeyRpId, isLocalHost };
