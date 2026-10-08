// The calendar feed: one URL per person (/cal/<secret>.ics, server.js),
// made of entries from every Canopy site that has a calendar. This file
// asks the sites, keeps what they said, and merges it; lib/ics.js writes
// it out. See "Calendar feed" in the README.
//
// ---- Asking a site ----
//
//   GET <calendar_url>/api/calendar/<personId>
//   Authorization: Canopy-Calendar t=<unix seconds>, sig=<hex>
//
// sig is HMAC-SHA256, keyed with the site's calendar secret (made in the
// Sites tab, shown once, set on the site as CANOPY_CALENDAR_SECRET), of
//
//   canopy-calendar-v1\n<personId>\n<t>
//
// The site checks it with client/canopy-account.js's
// verifyCalendarRequest: the same string, a constant-time comparison, and
// t within five minutes of its own clock. Why a signature rather than a
// key sent as it is: the secret itself never travels, so a request that
// ends up in a log, or goes to a mistyped calendar URL, gives away one
// person's calendar on one site for five minutes rather than everyone's
// for good. The account service has to keep the secret (to sign with), so
// it's sealed in the database like a contact detail (lib/db.js).
//
// ---- What a site answers ----
//
//   { "entries": [{ uid, title, start, end, allDay, timeZone, location,
//                   url, status, description, updatedAt }] }
//
// cleanEntry says exactly what's accepted. An entry that doesn't pass is
// left out (and counted in the log), not the whole answer.
//
// ---- Keeping what they said ----
//
// Each person's answer from each site is kept in memory for FRESH_MS and
// used as it is. After that the site is asked again; if it can't answer
// (an error, a timeout, nonsense), the last good answer stands in, however
// old, so a calendar app doesn't delete someone's events because a site
// was down for a deploy. A site that has never answered for this person
// since the service started is left out. If every site is in that state,
// the feed answers 503 rather than an empty calendar (server.js): an empty
// calendar would make the app delete everything, and a 503 makes it keep
// what it had.
//
// In memory, not on disk, on purpose: what's kept is where people are going
// to be, with home addresses, and on disk it would be in every snapshot
// and backup. The cost is a restart during a site's outage, which is
// covered by the 503 above while there's one site.

const crypto = require('crypto');

const FRESH_MS = 5 * 60 * 1000;
const TIMEOUT_MS = 3000;
// The most entries taken from one site for one person, and the most bytes
// of answer read. A person's last 90 days and everything coming up is
// nowhere near either.
const MAX_ENTRIES = 1000;
const MAX_BYTES = 2 * 1024 * 1024;
// Last good answers kept, across everyone; the oldest-fetched go first.
const MAX_KEPT = 20000;
// A kept answer nobody has asked for in this long is dropped.
const KEEP_MS = 30 * 24 * 60 * 60 * 1000;

const STATUSES = ['confirmed', 'tentative', 'cancelled'];
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
// An instant: ISO 8601 with a Z or an offset.
const INSTANT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/;

function signature(secret, personId, t) {
  return crypto.createHmac('sha256', secret).update(`canopy-calendar-v1\n${personId}\n${t}`).digest('hex');
}

function authorization(secret, personId, now = Date.now()) {
  const t = Math.floor(now / 1000);
  return `Canopy-Calendar t=${t}, sig=${signature(secret, personId, t)}`;
}

function clip(value, max) {
  if (value == null) return null;
  const s = String(value).trim();
  return s ? s.slice(0, max) : null;
}

function instant(value) {
  if (typeof value !== 'string' || !INSTANT_RE.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function day(value) {
  if (typeof value !== 'string' || !DATE_RE.test(value)) return null;
  const ms = Date.parse(`${value}T00:00:00Z`);
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 10) === value ? value : null;
}

// One entry from a site, as lib/ics.js takes it, or null if it isn't one.
function cleanEntry(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const uid = typeof raw.uid === 'string' ? raw.uid.trim() : '';
  // Unique across every site: '<the site's own id>@<its host>'.
  if (!uid || uid.length > 255 || !uid.includes('@') || /[\u0000-\u001f\u007f\s]/.test(uid)) return null;
  const title = clip(raw.title, 500);
  if (!title) return null;
  if (!STATUSES.includes(raw.status)) return null;
  const updatedAt = instant(raw.updatedAt);
  if (updatedAt == null) return null;
  const allDay = raw.allDay === true;
  const start = allDay ? day(raw.start) : instant(raw.start);
  if (start == null) return null;
  let end = raw.end == null ? null : allDay ? day(raw.end) : instant(raw.end);
  if (end != null && end <= start) end = null;
  let url = null;
  if (typeof raw.url === 'string' && raw.url.length <= 2000) {
    try {
      const u = new URL(raw.url);
      if (u.protocol === 'https:' || u.protocol === 'http:') url = u.href;
    } catch (e) {}
  }
  return {
    uid,
    title,
    start,
    end,
    allDay,
    location: clip(raw.location, 1000),
    url,
    status: raw.status,
    description: clip(raw.description, 4000),
    updatedAt
  };
}

// Soonest first, then by UID, so the same entries always make the same
// text (and the same ETag).
function byStart(a, b) {
  const as = typeof a.start === 'number' ? new Date(a.start).toISOString() : a.start;
  const bs = typeof b.start === 'number' ? new Date(b.start).toISOString() : b.start;
  return as < bs ? -1 : as > bs ? 1 : a.uid < b.uid ? -1 : a.uid > b.uid ? 1 : 0;
}

// `sites()` is the sites with a calendar, each { id, name, calendarUrl,
// secret, allowsUnverified }, asked each time (the admin can change them).
function createCalendar({ sites, fetchImpl = (...args) => fetch(...args), freshMs = FRESH_MS, timeoutMs = TIMEOUT_MS, log = console } = {}) {
  // `${personId} ${siteId}` -> { entries, at, usedAt }, oldest-fetched first.
  const kept = new Map();
  const inFlight = new Map();

  function keep(key, entries) {
    kept.delete(key);
    kept.set(key, { entries, at: Date.now(), usedAt: Date.now() });
    while (kept.size > MAX_KEPT) kept.delete(kept.keys().next().value);
  }

  async function ask(site, personId) {
    const base = site.calendarUrl.replace(/\/+$/, '');
    const res = await fetchImpl(`${base}/api/calendar/${encodeURIComponent(personId)}`, {
      headers: { Accept: 'application/json', Authorization: authorization(site.secret, personId) },
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (!res.ok) throw new Error(`answered ${res.status}`);
    const text = await res.text();
    if (text.length > MAX_BYTES) throw new Error('answered too much');
    const body = JSON.parse(text);
    if (!body || !Array.isArray(body.entries)) throw new Error('answered without entries');
    const entries = [];
    let skipped = 0;
    for (const raw of body.entries.slice(0, MAX_ENTRIES)) {
      const e = cleanEntry(raw);
      if (e) entries.push(e);
      else skipped++;
    }
    if (skipped) log.warn(`[canopy-account] calendar: ${site.name} sent ${skipped} entr${skipped === 1 ? 'y' : 'ies'} that aren't valid; left out.`);
    return entries;
  }

  // This person's entries from this site: fresh, asked now, or the last
  // good ones. null when there have never been any.
  async function entriesFrom(site, personId) {
    const key = `${personId} ${site.id}`;
    const have = kept.get(key);
    if (have && Date.now() - have.at < freshMs) {
      have.usedAt = Date.now();
      return have.entries;
    }
    // Two fetches of the same feed at once (two devices) ask the site once.
    if (!inFlight.has(key)) {
      inFlight.set(key, ask(site, personId)
        .then((entries) => { keep(key, entries); return entries; })
        .catch((err) => {
          // Never the URL's person id with anything identifying: the site
          // and why is all an outage needs.
          log.warn(`[canopy-account] calendar: ${site.name} couldn't be asked (${err.name === 'TimeoutError' ? 'timed out' : err.message}); ${have ? 'using its last answer' : 'left out'}.`);
          if (have) have.usedAt = Date.now();
          return have ? have.entries : null;
        })
        .finally(() => inFlight.delete(key)));
    }
    return inFlight.get(key);
  }

  // Every entry for this person, merged: { entries } in order, or
  // { unavailable: true } when there are sites to ask and none of them
  // has ever answered. `person` is the store's person.
  async function entriesFor(person) {
    const asking = sites().filter((s) => person.emailVerifiedAt || s.allowsUnverified);
    const results = await Promise.all(asking.map((s) => entriesFrom(s, person.id)));
    if (asking.length && results.every((r) => r === null)) return { unavailable: true };
    const seen = new Set();
    const entries = [];
    for (const list of results) {
      for (const e of list || []) {
        // A UID is one event: if two sites (wrongly) send the same one,
        // the first site's stands.
        if (seen.has(e.uid)) continue;
        seen.add(e.uid);
        entries.push(e);
      }
    }
    return { entries: entries.sort(byStart) };
  }

  // A deleted person's kept answers.
  function forget(personId) {
    for (const key of kept.keys()) if (key.startsWith(`${personId} `)) kept.delete(key);
  }

  const sweep = setInterval(() => {
    const cutoff = Date.now() - KEEP_MS;
    for (const [key, v] of kept) if (v.usedAt < cutoff) kept.delete(key);
  }, 60 * 60 * 1000);
  sweep.unref();

  return { entriesFor, forget, keptCount: () => kept.size };
}

module.exports = { createCalendar, cleanEntry, signature, authorization, FRESH_MS, TIMEOUT_MS };
