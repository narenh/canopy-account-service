// The calendar feed's iCalendar text (RFC 5545), written by hand: it's a
// few dozen lines, and a library for it would be a dependency much bigger
// than what it does here. test/calendar.test.js reads every feed it gets
// back with a strict parser (ical.js) and checks the rules below line by
// line.
//
// What the RFC asks for, and where it's done:
//
// - Lines end in CRLF, every one of them, the last included (CRLF).
// - A line longer than 75 octets is folded: CRLF and a space, and the
//   space counts towards the next line's 75 (fold). Octets, not
//   characters: an emoji is four, and a fold never splits one.
// - Text values have backslashes, semicolons, commas and newlines escaped
//   (escapeText), and control characters other than a tab taken out (the
//   RFC doesn't allow them at all).
// - Every event has a UID (the site's, which it keeps the same for the
//   life of the entry) and a DTSTAMP. With no METHOD on the calendar,
//   DTSTAMP is when the event was last changed, so it's the entry's
//   updatedAt; that also keeps the text the same from one fetch to the
//   next when nothing changed, which is what lets the feed's ETag say so.
// - Times are UTC, with a Z. A calendar app shows them in its own zone,
//   which is what someone subscribing wants; the event's own zone isn't
//   needed to get the moment right. An all-day entry is a DATE, its end
//   the day after the last day (DTEND is exclusive).
//
// SEQUENCE has to grow whenever the event changes, and it has to be an
// integer a 32-bit client can hold: seconds since 2020 from updatedAt
// grows with every change and fits until about 2088.

const CRLF = '\r\n';
const SEQUENCE_EPOCH_MS = Date.UTC(2020, 0, 1);

// How long a calendar app should wait between fetches. Apple reads
// REFRESH-INTERVAL, Outlook X-PUBLISHED-TTL; Google ignores both and
// fetches every several hours whatever we say.
const REFRESH = 'PT1H';

// Text as an iCalendar TEXT value.
function escapeText(value) {
  return String(value)
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '')
    .replace(/\\/g, '\\\\')
    .replace(/;/g, '\\;')
    .replace(/,/g, '\\,')
    .replace(/\n/g, '\\n');
}

// One content line, folded at 75 octets without splitting a character.
function fold(line) {
  if (Buffer.byteLength(line, 'utf8') <= 75) return line;
  const parts = [];
  let current = '';
  let size = 0;
  let limit = 75;
  for (const ch of line) {
    const n = Buffer.byteLength(ch, 'utf8');
    if (size + n > limit) {
      parts.push(current);
      current = '';
      size = 0;
      // The space that starts a continuation line is one of its 75.
      limit = 74;
    }
    current += ch;
    size += n;
  }
  parts.push(current);
  return parts.join(CRLF + ' ');
}

const pad = (n, w = 2) => String(n).padStart(w, '0');

// 20261031T030000Z
function utcDateTime(ms) {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}T${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
}

// 20261031, from a 'YYYY-MM-DD' (already checked by lib/calendar.js).
function date(text) {
  return text.replace(/-/g, '');
}

// The day after a 'YYYY-MM-DD', as one.
function nextDay(text) {
  const d = new Date(`${text}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
}

function sequenceFor(updatedAtMs) {
  return Math.max(0, Math.floor((updatedAtMs - SEQUENCE_EPOCH_MS) / 1000));
}

// An entry with no end is shown as an hour long: the length every
// calendar app gives a new event. With no DTEND at all, the RFC makes a
// timed event a moment long, which most apps draw as a sliver that can't
// be read or tapped.
const DEFAULT_LENGTH_MS = 60 * 60 * 1000;

// One VEVENT's lines, from an entry lib/calendar.js has already cleaned:
// { uid, title, start, end, allDay, location, url, status, description,
// updatedAt } with start/end as ms (or 'YYYY-MM-DD' when allDay) and
// updatedAt as ms.
function eventLines(e) {
  const lines = ['BEGIN:VEVENT', `UID:${escapeText(e.uid)}`, `DTSTAMP:${utcDateTime(e.updatedAt)}`];
  if (e.allDay) {
    lines.push(`DTSTART;VALUE=DATE:${date(e.start)}`);
    lines.push(`DTEND;VALUE=DATE:${date(e.end && e.end > e.start ? e.end : nextDay(e.start))}`);
  } else {
    lines.push(`DTSTART:${utcDateTime(e.start)}`);
    lines.push(`DTEND:${utcDateTime(e.end != null && e.end > e.start ? e.end : e.start + DEFAULT_LENGTH_MS)}`);
  }
  // Google ignores STATUS:CANCELLED in a subscribed calendar and shows the
  // event as if it were on, so the title says it too.
  lines.push(`SUMMARY:${escapeText(e.status === 'cancelled' ? `Cancelled: ${e.title}` : e.title)}`);
  if (e.location) lines.push(`LOCATION:${escapeText(e.location)}`);
  if (e.description) lines.push(`DESCRIPTION:${escapeText(e.description)}`);
  // A URI, not TEXT: not escaped. lib/calendar.js only lets through an
  // http(s) URL, which has no spaces or line breaks in it.
  if (e.url) lines.push(`URL:${e.url}`);
  lines.push(`STATUS:${e.status.toUpperCase()}`);
  // Tentative events still block time; cancelled ones don't.
  lines.push(`TRANSP:${e.status === 'cancelled' ? 'TRANSPARENT' : 'OPAQUE'}`);
  lines.push(`SEQUENCE:${sequenceFor(e.updatedAt)}`);
  lines.push(`LAST-MODIFIED:${utcDateTime(e.updatedAt)}`);
  lines.push('END:VEVENT');
  return lines;
}

// The whole feed, from entries in the order they should appear.
function buildCalendar(entries, { name = 'Canopy' } = {}) {
  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//Canopy//Calendar feed//EN',
    'CALSCALE:GREGORIAN',
    `X-WR-CALNAME:${escapeText(name)}`,
    `X-WR-CALDESC:${escapeText('Your Canopy events')}`,
    `REFRESH-INTERVAL;VALUE=DURATION:${REFRESH}`,
    `X-PUBLISHED-TTL:${REFRESH}`
  ];
  entries.forEach((e) => lines.push(...eventLines(e)));
  lines.push('END:VCALENDAR');
  return lines.map(fold).join(CRLF) + CRLF;
}

module.exports = { buildCalendar, escapeText, fold, utcDateTime, sequenceFor, DEFAULT_LENGTH_MS };
