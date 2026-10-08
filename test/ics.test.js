// The calendar feed's pieces on their own: the iCalendar text (lib/ics.js),
// what's accepted from a site and how answers are kept (lib/calendar.js),
// and the signature a site checks (client/canopy-account.js). The feed
// end to end, through the server, is test/calendar.test.js.

const test = require('node:test');
const assert = require('node:assert/strict');
const { buildCalendar, escapeText, fold, sequenceFor } = require('../lib/ics');
const { createCalendar, cleanEntry, authorization } = require('../lib/calendar');
const createCanopyAccount = require('../client/canopy-account');
const { checkIcs } = require('./icsCheck');

const quiet = { warn() {} };
const entry = (over = {}) => ({
  uid: 'e1@events.canopysf.com',
  title: 'Dinner',
  start: '2026-10-31T03:00:00.000Z',
  end: '2026-10-31T06:00:00.000Z',
  allDay: false,
  timeZone: 'America/Los_Angeles',
  location: "Ana's place, 1 Market St, San Francisco",
  url: 'https://events.canopysf.com/e/AbCdEfGhIjKl',
  status: 'confirmed',
  description: 'Bring a jacket.',
  updatedAt: '2026-10-01T12:00:00.000Z',
  ...over
});

test('text is escaped, and long lines are folded at 75 octets without splitting a character', () => {
  assert.equal(escapeText('a,b;c\\d\ne\r\nf\rg'), 'a\\,b\\;c\\\\d\\ne\\nf\\ng');
  assert.equal(escapeText('bell\u0007 tab\t'), 'bell tab\t');
  const long = 'SUMMARY:' + '🎉'.repeat(40);
  const folded = fold(long).split('\r\n');
  assert.ok(folded.length > 1);
  folded.forEach((l, i) => {
    assert.ok(Buffer.byteLength(l) <= 75);
    if (i) assert.equal(l[0], ' ');
  });
  assert.equal(folded.map((l, i) => (i ? l.slice(1) : l)).join(''), long);
  assert.equal(fold('SHORT:x'), 'SHORT:x');
  // SEQUENCE grows with updatedAt and fits in 32 bits for decades.
  assert.ok(sequenceFor(Date.UTC(2026, 0, 1)) < sequenceFor(Date.UTC(2026, 0, 2)));
  assert.ok(sequenceFor(Date.UTC(2080, 0, 1)) < 2 ** 31);
});

test('a calendar of awkward entries is valid, and reads back as it was written', () => {
  const awkward = [
    cleanEntry(entry({ title: 'Commas, semicolons; and a back\\slash', description: 'Line one\nLine two, with 🎉 and ünïcödé '.repeat(8) })),
    cleanEntry(entry({ uid: 'e2@events.canopysf.com', status: 'tentative', end: null, description: 'On the waitlist' })),
    cleanEntry(entry({ uid: 'e3@events.canopysf.com', status: 'cancelled', location: null, url: null, description: null })),
    cleanEntry(entry({ uid: 'e4@tickets.canopysf.com', allDay: true, start: '2026-11-02', end: '2026-11-04' })),
    cleanEntry(entry({ uid: 'e5@tickets.canopysf.com', allDay: true, start: '2026-11-05', end: null }))
  ];
  const text = buildCalendar(awkward);
  const events = checkIcs(text);
  assert.equal(events.length, 5);
  const [a, b, c, d, e] = events;
  assert.equal(a.summary, 'Commas, semicolons; and a back\\slash');
  assert.equal(a.description, awkward[0].description);
  assert.equal(a.location, "Ana's place, 1 Market St, San Francisco");
  assert.equal(a.url, 'https://events.canopysf.com/e/AbCdEfGhIjKl');
  assert.equal(a.start, Date.parse('2026-10-31T03:00:00Z'));
  assert.equal(a.end, Date.parse('2026-10-31T06:00:00Z'));
  assert.equal(a.status, 'CONFIRMED');
  assert.equal(a.sequence, sequenceFor(Date.parse('2026-10-01T12:00:00Z')));
  // No end: an hour.
  assert.equal(b.status, 'TENTATIVE');
  assert.equal(b.end - b.start, 60 * 60 * 1000);
  // Cancelled says so in the title too (Google ignores STATUS).
  assert.equal(c.status, 'CANCELLED');
  assert.equal(c.summary, 'Cancelled: Dinner');
  assert.equal(c.location, null);
  // All-day: dates, the end exclusive.
  assert.ok(d.allDay);
  assert.match(text, /DTSTART;VALUE=DATE:20261102\r\nDTEND;VALUE=DATE:20261104/);
  assert.match(text, /DTSTART;VALUE=DATE:20261105\r\nDTEND;VALUE=DATE:20261106/);
  assert.ok(e.allDay);
  // The same entries make the same text: nothing in it is "now".
  assert.equal(buildCalendar(awkward), text);
  assert.ok(text.includes('DTSTAMP:20261001T120000Z'));
  // An empty calendar is still a calendar.
  assert.deepEqual(checkIcs(buildCalendar([])), []);
});

test('what a site sends is checked entry by entry', () => {
  assert.ok(cleanEntry(entry()));
  const bad = [
    null, 'x', entry({ uid: '' }), entry({ uid: 'no-at-sign' }), entry({ uid: 'a b@x' }), entry({ uid: 'a\r\nX-EVIL:1@x' }),
    entry({ uid: 'x'.repeat(250) + '@x.com' }), entry({ title: '' }), entry({ title: '   ' }), entry({ status: 'going' }),
    entry({ start: 'tomorrow' }), entry({ start: '2026-10-31T03:00:00' }), entry({ start: 1761879600000 }),
    entry({ updatedAt: undefined }), entry({ allDay: true, start: '2026-02-30' }), entry({ allDay: true })
  ];
  bad.forEach((b) => assert.equal(cleanEntry(b), null, JSON.stringify(b)));
  // Fixable parts are fixed rather than the entry thrown away.
  assert.equal(cleanEntry(entry({ end: '2026-10-30T00:00:00Z' })).end, null);
  assert.equal(cleanEntry(entry({ url: 'javascript:alert(1)' })).url, null);
  assert.equal(cleanEntry(entry({ url: 'not a url' })).url, null);
  assert.equal(cleanEntry(entry({ title: 'x'.repeat(900) })).title.length, 500);
  assert.equal(cleanEntry(entry({ start: '2026-10-31T03:00:00-07:00' })).start, Date.parse('2026-10-31T10:00:00Z'));
});

test("a site's request is signed, and only the right signature, person and time pass", () => {
  const site = createCanopyAccount({ url: 'http://unused', key: 'unused', calendarSecret: 'cnc_secret' });
  const req = (auth, personId = 'p1', url) => ({ headers: { authorization: auth }, params: personId ? { personId } : {}, originalUrl: url });
  assert.equal(site.verifyCalendarRequest(req(authorization('cnc_secret', 'p1'))), 'p1');
  // From the URL when there's no :personId, with or without a query.
  assert.equal(site.verifyCalendarRequest(req(authorization('cnc_secret', 'p1'), null, '/api/calendar/p1?x=1')), 'p1');
  // Someone else's signature, another person, the wrong secret.
  assert.equal(site.verifyCalendarRequest(req(authorization('cnc_secret', 'p2'))), null);
  assert.equal(site.verifyCalendarRequest(req(authorization('cnc_other', 'p1'))), null);
  // Too old, or from too far in the future (a replay, or a clock gone wrong).
  assert.equal(site.verifyCalendarRequest(req(authorization('cnc_secret', 'p1', Date.now() - 6 * 60 * 1000))), null);
  assert.equal(site.verifyCalendarRequest(req(authorization('cnc_secret', 'p1', Date.now() + 6 * 60 * 1000))), null);
  assert.equal(site.verifyCalendarRequest(req(authorization('cnc_secret', 'p1', Date.now() - 4 * 60 * 1000))), 'p1');
  // Malformed, missing, the site's own key as a bearer.
  for (const auth of [undefined, '', 'Bearer cnp_x', 'Canopy-Calendar t=1', `Canopy-Calendar t=${Math.floor(Date.now() / 1000)}, sig=zz`]) {
    assert.equal(site.verifyCalendarRequest(req(auth)), null, String(auth));
  }
  // A site with no calendar secret set lets nobody in.
  const none = createCanopyAccount({ url: 'http://unused', key: 'unused' });
  assert.equal(none.verifyCalendarRequest(req(authorization('', 'p1'))), null);
});

test('answers are kept, asked once at a time, and the last good one stands in for a site that fails', async () => {
  let mode = 'ok';
  let calls = 0;
  let release;
  const fetchImpl = async (url, opts) => {
    calls++;
    assert.match(opts.headers.Authorization, /^Canopy-Calendar t=\d+, sig=[0-9a-f]{64}$/);
    if (mode === 'slow') await new Promise((r) => { release = r; });
    if (mode === 'fail') return new Response('nope', { status: 500 });
    if (mode === 'junk') return new Response('<html>', { status: 200 });
    return new Response(JSON.stringify({ entries: [entry(), { uid: 'bad' }] }), { status: 200 });
  };
  const sites = [{ id: 's1', name: 'events', calendarUrl: 'http://events.test/', secret: 'cnc_x', allowsUnverified: true }];
  const cal = createCalendar({ sites: () => sites, fetchImpl, freshMs: 1000, log: quiet });
  const ana = { id: 'p1', emailVerifiedAt: 1 };
  assert.equal((await cal.entriesFor(ana)).entries.length, 1);
  assert.equal((await cal.entriesFor(ana)).entries.length, 1);
  assert.equal(calls, 1, 'kept for freshMs');
  // Stale, and the site fails or talks nonsense: the last good answer.
  const cal2 = createCalendar({ sites: () => sites, fetchImpl, freshMs: 0, log: quiet });
  await cal2.entriesFor(ana);
  for (mode of ['fail', 'junk']) assert.equal((await cal2.entriesFor(ana)).entries.length, 1, mode);
  // Never a good answer: every site failed, so the feed is unavailable.
  assert.deepEqual(await cal2.entriesFor({ id: 'p2', emailVerifiedAt: 1 }), { unavailable: true });
  // Two at once ask once.
  mode = 'slow';
  calls = 0;
  const both = Promise.all([cal2.entriesFor(ana), cal2.entriesFor(ana)]);
  await new Promise((r) => setImmediate(r));
  release();
  await both;
  assert.equal(calls, 1);
  // Forgotten (a deleted person): back to never having had an answer.
  mode = 'fail';
  cal2.forget('p1');
  assert.deepEqual(await cal2.entriesFor(ana), { unavailable: true });
  // An unverified person is only asked about on sites that let them in.
  sites[0].allowsUnverified = false;
  assert.deepEqual(await cal2.entriesFor({ id: 'p3', emailVerifiedAt: null }), { entries: [] });
});

test('the same entries make the same feed, however the sites happen to answer', async () => {
  // Two sites, entries at the same start (so only the UID orders them),
  // answering after random delays: the merged text never changes.
  const sites = ['a', 'b'].map((id) => ({ id, name: id, calendarUrl: `http://${id}.test`, secret: 'cnc_x', allowsUnverified: true }));
  const fetchImpl = async (url) => {
    await new Promise((r) => setTimeout(r, Math.random() * 20));
    const host = new URL(url).hostname;
    const list = [entry({ uid: `2@${host}` }), entry({ uid: `1@${host}` })];
    return new Response(JSON.stringify({ entries: Math.random() < 0.5 ? list : list.reverse() }), { status: 200 });
  };
  const cal = createCalendar({ sites: () => sites, fetchImpl, freshMs: 0, log: quiet });
  const texts = new Set();
  for (let i = 0; i < 20; i++) texts.add(buildCalendar((await cal.entriesFor({ id: 'p1', emailVerifiedAt: 1 })).entries));
  assert.equal(texts.size, 1);
  assert.deepEqual(checkIcs([...texts][0]).map((e) => e.uid), ['1@a.test', '1@b.test', '2@a.test', '2@b.test']);
});
