// The calendar feed end to end: the link on the profile and in the apps,
// the admin setting a site's calendar up, and /cal/<secret>.ics merging
// two fake sites that check the account service's signature the way a
// real one does (client/canopy-account.js). Every feed is held to RFC 5545
// by test/icsCheck.js.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const Database = require('better-sqlite3');
const { startServer, browser, nativeApp } = require('./harness');
const createCanopyAccount = require('../client/canopy-account');
const { checkIcs } = require('./icsCheck');

const FRESH_MS = 300;
const TIMEOUT_MS = 400;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A Canopy site with a calendar: GET /api/calendar/:personId, answered
// from `entries(personId)`, refusing anything not signed with `secret`.
// `mode` is 'ok', 'fail' (a 500), 'hang' (never answers) or 'down'.
async function fakeSite(host) {
  const site = { secret: null, mode: 'ok', calls: [], refused: 0, entries: () => [] };
  const app = express();
  app.get('/api/calendar/:personId', (req, res) => {
    const canopy = createCanopyAccount({ url: 'http://unused', key: 'unused', calendarSecret: site.secret });
    const personId = canopy.verifyCalendarRequest(req);
    if (!personId) { site.refused++; return res.status(401).json({ error: 'not the account service' }); }
    site.calls.push(personId);
    if (site.mode === 'fail') return res.status(500).json({ error: 'down for a deploy' });
    if (site.mode === 'hang') return;
    res.json({ entries: site.entries(personId) });
  });
  const listener = await new Promise((resolve) => { const l = app.listen(0, () => resolve(l)); });
  site.url = `http://127.0.0.1:${listener.address().port}`;
  site.host = host;
  site.close = () => { listener.closeAllConnections(); listener.close(); };
  return site;
}

// Fixed for the whole file. A fake site that worked its times out from
// Date.now() on every request would send a new start whenever the feed
// asks it again (every FRESH_MS here), and the feed's text, and so its
// ETag, would change whenever that crossed a second: a real change, as far
// as the feed can tell, and a flaky 304 test.
const NOW = Date.now();

function entry(site, id, over = {}) {
  return {
    uid: `${id}@${site.host}`,
    title: `${site.host} ${id}`,
    start: new Date(NOW + 86400e3).toISOString(),
    end: new Date(NOW + 90000e3).toISOString(),
    allDay: false,
    timeZone: 'America/Los_Angeles',
    location: 'Somewhere, 1 Market St',
    url: `https://${site.host}/e/${id}`,
    status: 'confirmed',
    updatedAt: '2026-10-01T12:00:00.000Z',
    ...over
  };
}

async function setUp(t, env = {}) {
  const server = await startServer({ CALENDAR_FRESH_MS: String(FRESH_MS), CALENDAR_TIMEOUT_MS: String(TIMEOUT_MS), ...env });
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('admin@example.com', 'Ada', 'Admin');
  return { server, admin };
}

// A site with a calendar, set up the way the admin does it.
async function addSite(t, admin, name, host, settings = {}) {
  const site = await fakeSite(host);
  t.after(() => site.close());
  const made = (await admin.post('/api/admin/apps', { name })).data;
  site.id = made.app.id;
  const r = await admin.patch(`/api/admin/apps/${site.id}`, { calendarUrl: site.url + '/', ...settings });
  assert.equal(r.status, 200, r.text);
  assert.match(r.data.calendarSecret, /^cnc_[A-Za-z0-9_-]{43}$/);
  assert.equal(r.data.app.calendarUrl, site.url, 'the trailing / is taken off');
  site.secret = r.data.calendarSecret;
  return site;
}

const secretOf = (url) => /\/cal\/([A-Za-z0-9_-]{43})\.ics$/.exec(url)[1];
const feedPath = (cal) => new URL(cal.url).pathname;

test('the admin gives a site a calendar, and its secret is shown once', async (t) => {
  const { server, admin } = await setUp(t);
  const made = (await admin.post('/api/admin/apps', { name: 'events' })).data;
  const id = made.app.id;
  assert.equal(made.app.calendarUrl, null);
  for (const bad of ['events.canopysf.com', 'ftp://x.example', 'https://u:p@x.example', 'https://x.example/?a=1', 'https://x.example/#a', 5]) {
    assert.equal((await admin.patch(`/api/admin/apps/${id}`, { calendarUrl: bad })).data.reason, 'bad_calendar_url', String(bad));
  }
  const first = await admin.patch(`/api/admin/apps/${id}`, { calendarUrl: 'http://events:3000' });
  assert.match(first.data.calendarSecret, /^cnc_/);
  assert.ok(first.data.app.calendarSecretAt);
  // Changing the URL keeps the secret, and doesn't show it again.
  const again = await admin.patch(`/api/admin/apps/${id}`, { calendarUrl: 'https://events.canopysf.com' });
  assert.equal(again.data.calendarSecret, undefined);
  assert.equal(again.data.app.calendarUrl, 'https://events.canopysf.com');
  // A new one, on purpose.
  const rekeyed = await admin.post(`/api/admin/apps/${id}/calendar-secret`);
  assert.match(rekeyed.data.calendarSecret, /^cnc_/);
  assert.notEqual(rekeyed.data.calendarSecret, first.data.calendarSecret);
  // Nowhere else: not in the list of sites, and sealed in the database.
  const list = await admin.get('/api/admin/apps');
  assert.ok(!list.text.includes('cnc_'));
  const db = new Database(path.join(server.dataDir, 'account.db'), { readonly: true });
  const row = db.prepare('SELECT calendar_secret FROM apps WHERE id = ?').get(id);
  db.close();
  assert.match(row.calendar_secret, /^v1:test1:/);
  assert.ok(!row.calendar_secret.includes(rekeyed.data.calendarSecret.slice(4)));
  // '' takes the calendar away.
  assert.equal((await admin.patch(`/api/admin/apps/${id}`, { calendarUrl: '' })).data.app.calendarUrl, null);
  // Only the admin.
  const someone = browser(server);
  await someone.signUp('someone@example.com', 'Sam', 'One');
  assert.equal((await someone.patch(`/api/admin/apps/${id}`, { calendarUrl: 'https://evil.example' })).status, 401);
  assert.equal((await someone.post(`/api/admin/apps/${id}/calendar-secret`)).status, 401);
});

test('one link per person: made once, kept as a hash and sealed, shown again, reset', async (t) => {
  const { server } = await setUp(t);
  const ana = browser(server);
  const anaId = (await ana.signUp('ana@example.com', 'Ana', 'Lima')).data.person.id;
  const first = await ana.get('/api/profile/calendar');
  assert.equal(first.status, 200);
  assert.equal(first.headers.get('cache-control'), 'no-store');
  const cal = first.data.calendar;
  assert.match(cal.url, new RegExp(`^${server.base}/cal/[A-Za-z0-9_-]{43}\\.ics$`));
  assert.equal(cal.webcalUrl, cal.url.replace(/^http:/, 'webcal:'));
  assert.deepEqual((await ana.get('/api/profile/calendar')).data.calendar, cal, 'the same link every time');
  // The database has its SHA-256 and a sealed copy, never the secret.
  const secret = secretOf(cal.url);
  const db = new Database(path.join(server.dataDir, 'account.db'), { readonly: true });
  const row = db.prepare('SELECT * FROM calendar_feeds WHERE person_id = ?').get(anaId);
  db.close();
  assert.equal(row.secret_hash, crypto.createHash('sha256').update(secret).digest('hex'));
  assert.match(row.secret, /^v1:test1:/);
  assert.ok(!JSON.stringify(row).includes(secret));
  // It works; someone else's is someone else's.
  assert.equal((await browser(server).get(feedPath(cal))).status, 200);
  const bob = browser(server);
  await bob.signUp('bob@example.com', 'Bob', 'Bell');
  assert.notEqual((await bob.get('/api/profile/calendar')).data.calendar.url, cal.url);
  // Reset: a new link, and the old one is a 404 at once.
  const reset = await ana.post('/api/profile/calendar/reset');
  assert.equal(reset.status, 200);
  assert.notEqual(reset.data.calendar.url, cal.url);
  assert.equal((await browser(server).get(feedPath(cal))).status, 404);
  assert.equal((await browser(server).get(feedPath(reset.data.calendar))).status, 200);
  assert.deepEqual((await ana.get('/api/profile/calendar')).data.calendar.url, reset.data.calendar.url);
  // Reset needs a Canopy page (the Origin check), and someone signed in.
  assert.equal((await ana.post('/api/profile/calendar/reset', {}, { headers: { Origin: 'https://evil.example' } })).status, 403);
  assert.equal((await browser(server).get('/api/profile/calendar')).status, 401);
  // The same from an app.
  const app = nativeApp(server);
  app.authenticator.creds.push(...ana.authenticator.creds);
  await app.signInWithPasskey();
  assert.equal((await app.get('/me/calendar')).data.calendar.url, reset.data.calendar.url);
  const appReset = await app.post('/me/calendar/reset');
  assert.equal(appReset.status, 200);
  assert.notEqual(appReset.data.calendar.url, reset.data.calendar.url);
  assert.equal((await nativeApp(server).get('/me/calendar')).status, 401);
});

test('the feed merges every site, signed, and is valid iCalendar with an ETag', async (t) => {
  const { server, admin } = await setUp(t);
  const events = await addSite(t, admin, 'events', 'events.canopysf.com');
  const tickets = await addSite(t, admin, 'tickets', 'tickets.canopysf.com');
  const ana = browser(server);
  const anaId = (await ana.signUp('ana@example.com', 'Ana', 'Lima')).data.person.id;
  const later = (h) => new Date(NOW + h * 3600e3).toISOString();
  events.entries = (id) => (id === anaId ? [
    entry(events, 'e2', { start: later(48), end: later(50), title: 'Dinner, with friends; bring wine', status: 'tentative', description: 'On the waitlist' }),
    entry(events, 'e1', { start: later(24), end: null, status: 'cancelled' }),
    // Not valid: left out, the rest kept.
    { uid: 'broken' }
  ] : []);
  tickets.entries = () => [entry(tickets, 't1', { start: later(30), end: later(33), allDay: false })];
  const cal = (await ana.get('/api/profile/calendar')).data.calendar;

  const r = await browser(server).get(feedPath(cal));
  assert.equal(r.status, 200, r.text);
  assert.equal(r.headers.get('content-type'), 'text/calendar; charset=utf-8');
  assert.equal(r.headers.get('cache-control'), 'private, max-age=300');
  const etag = r.headers.get('etag');
  assert.match(etag, /^"[A-Za-z0-9_-]{32}"$/);
  const got = checkIcs(r.text);
  // Merged, soonest first.
  assert.deepEqual(got.map((e) => e.uid), ['e1@events.canopysf.com', 't1@tickets.canopysf.com', 'e2@events.canopysf.com']);
  assert.equal(got[0].status, 'CANCELLED');
  assert.equal(got[0].summary, 'Cancelled: events.canopysf.com e1');
  assert.equal(got[2].summary, 'Dinner, with friends; bring wine');
  assert.equal(got[2].status, 'TENTATIVE');
  assert.equal(got[2].description, 'On the waitlist');
  assert.equal(got[1].url, 'https://tickets.canopysf.com/e/t1');
  // Each site was asked about Ana, with a signature it checked.
  assert.deepEqual(events.calls, [anaId]);
  assert.deepEqual(tickets.calls, [anaId]);
  assert.equal(events.refused + tickets.refused, 0);

  // Unchanged: a 304 for an app that sends the ETag back, before and after
  // the sites are asked again.
  const again = await browser(server).get(feedPath(cal), { headers: { 'If-None-Match': etag } });
  assert.equal(again.status, 304);
  assert.equal(again.text, '');
  await sleep(FRESH_MS + 50);
  assert.equal((await browser(server).get(feedPath(cal), { headers: { 'If-None-Match': `W/${etag}` } })).status, 304);
  assert.equal(events.calls.length, 2, 'asked again once its answer was stale');
  // A change makes a new ETag.
  const before = tickets.entries;
  tickets.entries = () => before().map((e) => ({ ...e, title: 'Moved', updatedAt: '2026-10-02T12:00:00.000Z' }));
  await sleep(FRESH_MS + 50);
  const changed = await browser(server).get(feedPath(cal), { headers: { 'If-None-Match': etag } });
  assert.equal(changed.status, 200);
  assert.notEqual(changed.headers.get('etag'), etag);
  assert.ok(checkIcs(changed.text).some((e) => e.summary === 'Moved'));

  // HEAD is answered the same way, without the body.
  const head = await fetch(server.base + feedPath(cal), { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(head.headers.get('content-type'), 'text/calendar; charset=utf-8');
});

test('a site that fails is served from its last good copy; never a good copy, it is left out', async (t) => {
  const { server, admin } = await setUp(t);
  const events = await addSite(t, admin, 'events', 'events.canopysf.com');
  const tickets = await addSite(t, admin, 'tickets', 'tickets.canopysf.com');
  events.entries = (id) => [entry(events, `e-${id.slice(0, 4)}`)];
  tickets.entries = (id) => [entry(tickets, `t-${id.slice(0, 4)}`)];
  const ana = browser(server);
  await ana.signUp('ana@example.com', 'Ana', 'Lima');
  const cal = (await ana.get('/api/profile/calendar')).data.calendar;
  const uids = async (c) => {
    const r = await browser(server).get(feedPath(c));
    assert.equal(r.status, 200, r.text);
    return checkIcs(r.text).map((e) => e.uid.split('@')[1]).sort();
  };
  assert.deepEqual(await uids(cal), ['events.canopysf.com', 'tickets.canopysf.com']);

  // Events fails: its entries stay, from the last good answer.
  events.mode = 'fail';
  await sleep(FRESH_MS + 50);
  assert.deepEqual(await uids(cal), ['events.canopysf.com', 'tickets.canopysf.com']);
  assert.ok(events.calls.length >= 2, 'it was asked, and failed');
  // Hangs: given up on after the timeout, the same.
  events.mode = 'hang';
  await sleep(FRESH_MS + 50);
  const started = Date.now();
  assert.deepEqual(await uids(cal), ['events.canopysf.com', 'tickets.canopysf.com']);
  assert.ok(Date.now() - started < TIMEOUT_MS + 1500, 'the sites are asked in parallel, each with its timeout');
  // Its secret replaced and not yet on the site: refused, the same.
  events.mode = 'ok';
  await admin.post(`/api/admin/apps/${events.id}/calendar-secret`);
  await sleep(FRESH_MS + 50);
  assert.deepEqual(await uids(cal), ['events.canopysf.com', 'tickets.canopysf.com']);
  assert.ok(events.refused >= 1);

  // Someone the failing site has never answered about: left out.
  const bob = browser(server);
  await bob.signUp('bob@example.com', 'Bob', 'Bell');
  const bobCal = (await bob.get('/api/profile/calendar')).data.calendar;
  assert.deepEqual(await uids(bobCal), ['tickets.canopysf.com']);
  // Both down and nothing kept for this person: a 503, so the calendar app
  // keeps what it has rather than emptying it.
  tickets.mode = 'fail';
  const cy = browser(server);
  await cy.signUp('cy@example.com', 'Cy', 'Park');
  const cyFeed = await browser(server).get(feedPath((await cy.get('/api/profile/calendar')).data.calendar));
  assert.equal(cyFeed.status, 503);
  assert.equal(cyFeed.headers.get('retry-after'), '300');
  // Nothing in the log says who.
  assert.ok(!server.output().includes(secretOf(cal.url)));
});

test('which sites are asked: not cut off ones, and for an unverified person only those that let them in', async (t) => {
  const { server, admin } = await setUp(t);
  const events = await addSite(t, admin, 'events', 'events.canopysf.com', { allowsUnverified: true });
  const tickets = await addSite(t, admin, 'tickets', 'tickets.canopysf.com');
  events.entries = () => [entry(events, 'e1')];
  tickets.entries = () => [entry(tickets, 't1')];
  const quinn = browser(server);
  await quinn.quickSignUp('quinn@example.com', 'Quinn', 'Quick');
  const qCal = (await quinn.get('/api/profile/calendar')).data.calendar;
  assert.deepEqual(checkIcs((await browser(server).get(feedPath(qCal))).text).map((e) => e.uid), ['e1@events.canopysf.com']);
  assert.equal(tickets.calls.length, 0);
  // A site that's cut off isn't asked; one with no calendar URL isn't either.
  const ana = browser(server);
  await ana.signUp('ana@example.com', 'Ana', 'Lima');
  await admin.post(`/api/admin/apps/${tickets.id}/revoke`);
  await admin.patch(`/api/admin/apps/${events.id}`, { calendarUrl: '' });
  const r = await browser(server).get(feedPath((await ana.get('/api/profile/calendar')).data.calendar));
  assert.equal(r.status, 200);
  assert.deepEqual(checkIcs(r.text), [], 'no sites: an empty calendar, not a 503');
  assert.equal(tickets.calls.length, 0);
});

test('an unknown link is a bare 404, and a deleted person\'s feed is gone', async (t) => {
  const { server, admin } = await setUp(t);
  const ana = browser(server);
  const anaId = (await ana.signUp('ana@example.com', 'Ana', 'Lima')).data.person.id;
  const cal = (await ana.get('/api/profile/calendar')).data.calendar;
  for (const p of [`/cal/${'A'.repeat(43)}.ics`, '/cal/short.ics', `/cal/${secretOf(cal.url)}`, `/cal/${secretOf(cal.url)}.ics.ics`]) {
    const r = await browser(server).get(p);
    assert.equal(r.status, 404, p);
    assert.equal(r.text, 'Not found\n');
  }
  assert.equal((await browser(server).get(feedPath(cal))).status, 200);
  assert.equal((await admin.del(`/api/admin/people/${anaId}`)).status, 200);
  const gone = await browser(server).get(feedPath(cal));
  assert.equal(gone.status, 404);
  assert.equal(gone.text, 'Not found\n');
  const db = new Database(path.join(server.dataDir, 'account.db'), { readonly: true });
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM calendar_feeds').get().n, 0);
  db.close();
});

test('the feed is rate limited per feed and per address, lightly', async (t) => {
  const { server } = await setUp(t);
  const ana = browser(server);
  await ana.signUp('ana@example.com', 'Ana', 'Lima');
  const cal = (await ana.get('/api/profile/calendar')).data.calendar;
  // 120 an hour per feed (from different addresses, as a phone and a
  // laptop and Google would be).
  for (let i = 0; i < 120; i++) {
    const r = await browser(server).get(feedPath(cal), { headers: { 'CF-Connecting-IP': `198.51.100.${i % 200}` } });
    assert.equal(r.status, 200, `fetch ${i + 1}`);
  }
  const over = await browser(server).get(feedPath(cal), { headers: { 'CF-Connecting-IP': '203.0.113.9' } });
  assert.equal(over.status, 429);
  assert.equal(over.headers.get('retry-after'), '600');
  // Someone else's feed isn't held back by Ana's.
  const bob = browser(server);
  await bob.signUp('bob@example.com', 'Bob', 'Bell');
  const bobPath = feedPath((await bob.get('/api/profile/calendar')).data.calendar);
  assert.equal((await browser(server).get(bobPath, { headers: { 'CF-Connecting-IP': '203.0.113.9' } })).status, 200);
  // 60 unknown links an hour per address, and then that address waits.
  for (let i = 0; i < 60; i++) {
    assert.equal((await browser(server).get(`/cal/${String(i).padStart(43, 'x')}.ics`, { headers: { 'CF-Connecting-IP': '192.0.2.1' } })).status, 404);
  }
  assert.equal((await browser(server).get(bobPath, { headers: { 'CF-Connecting-IP': '192.0.2.1' } })).status, 429);
  assert.equal((await browser(server).get(bobPath, { headers: { 'CF-Connecting-IP': '192.0.2.2' } })).status, 200);
});

test('the per-address limit', async (t) => {
  const { server } = await setUp(t);
  const people = [];
  // 1,200 an hour per address, across feeds: eleven feeds at 110 each.
  for (let i = 0; i < 11; i++) {
    const p = browser(server);
    await p.signUp(`p${i}@example.com`, 'P', `N${i}`);
    people.push(feedPath((await p.get('/api/profile/calendar')).data.calendar));
  }
  const from = { headers: { 'CF-Connecting-IP': '203.0.113.50' } };
  let n = 0;
  for (const p of people) {
    for (let i = 0; i < 110 && n < 1200; i++, n++) assert.equal((await browser(server).get(p, from)).status, 200);
  }
  assert.equal(n, 1200);
  assert.equal((await browser(server).get(people[10], from)).status, 429);
  assert.equal((await browser(server).get(people[10], { headers: { 'CF-Connecting-IP': '203.0.113.51' } })).status, 200);
});
