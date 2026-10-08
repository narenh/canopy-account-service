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

// ---- Passkeys used from the apps ----
//
// A passkey's signed record says where it was used (clientDataJSON's
// origin), and the server only accepts the ones it expects:
//
//   - The iOS app (ASAuthorization, with the webcredentials association
//     in docs/well-known/) signs as "https://" + the passkey domain:
//     https://canopysf.com. That's a Canopy page's origin already, so
//     nothing here is needed for it beyond appOriginFor's rpID line.
//   - An Android app (Credential Manager) signs as
//     "android:apk-key-hash:" + the base64url SHA-256 of the certificate
//     that signed the app. ANDROID_APK_KEY_HASHES lists the ones accepted,
//     comma-separated: each either that base64url hash (with or without
//     the prefix) or the colon-separated hex fingerprint keytool and
//     assetlinks.json use. Empty by default: no Android app is trusted
//     until one is named.
//
// Only the app endpoints (server.js, "Apps") accept these. The web's
// passkeys still have to be used on a Canopy page.

const APK_PREFIX = 'android:apk-key-hash:';

function androidOrigin(entry) {
  const v = String(entry || '').trim();
  if (!v) return null;
  if (/^([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$/.test(v)) {
    return APK_PREFIX + Buffer.from(v.replace(/:/g, ''), 'hex').toString('base64url');
  }
  const hash = v.startsWith(APK_PREFIX) ? v.slice(APK_PREFIX.length) : v;
  return /^[A-Za-z0-9_-]{43}$/.test(hash) ? APK_PREFIX + hash : null;
}

const ANDROID_ORIGINS = String(process.env.ANDROID_APK_KEY_HASHES || '')
  .split(',')
  .filter((e) => e.trim())
  .map((e) => {
    const origin = androidOrigin(e);
    if (!origin) console.warn(`[canopy-account] ANDROID_APK_KEY_HASHES: ignoring "${e.trim()}", which isn't a SHA-256 hash or fingerprint`);
    return origin;
  })
  .filter(Boolean);

// An app's passkey origin, for passkeys belonging to rpID: the iOS app's
// https://<rpID>, or a listed Android signing certificate's.
function isAppOrigin(origin, rpID) {
  return (!!rpID && origin === `https://${rpID}`) || ANDROID_ORIGINS.includes(origin);
}

module.exports = {
  BASE, isCanopyUrl, isCanopyOrigin, safeReturn, cookieDomainFor, passkeyRpId, isLocalHost, isAppOrigin, androidOrigin
};
