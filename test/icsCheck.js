// Holds a calendar feed to RFC 5545, strictly: ical.js parses it (and
// throws on anything it can't), and the rules a parser lets slide are
// checked here line by line: CRLF everywhere, no line over 75 octets,
// escaped text, the properties every event must have exactly once, and
// times in UTC. Returns the events as ical.js reads them back, so a test
// can check the text survived the trip.

const assert = require('node:assert/strict');
const ICAL = require('ical.js');

const TEXT_PROPS = ['SUMMARY', 'LOCATION', 'DESCRIPTION', 'X-WR-CALNAME', 'X-WR-CALDESC', 'UID'];
const ONCE = ['UID', 'DTSTAMP', 'DTSTART', 'DTEND', 'SUMMARY', 'STATUS', 'SEQUENCE', 'LAST-MODIFIED'];

function checkIcs(text) {
  assert.ok(text.endsWith('\r\n'), 'ends with CRLF');
  assert.ok(!/[^\r]\n/.test(text) && !/\r(?!\n)/.test(text), 'every line break is CRLF');
  const physical = text.slice(0, -2).split('\r\n');
  physical.forEach((l, i) => assert.ok(Buffer.byteLength(l, 'utf8') <= 75, `line ${i + 1} is ${Buffer.byteLength(l)} octets: ${l}`));
  // A fold never splits a character: each physical line is whole UTF-8.
  physical.forEach((l) => assert.ok(!l.includes('�')));
  const lines = text.replace(/\r\n[ \t]/g, '').split('\r\n');
  lines.pop();
  assert.equal(lines[0], 'BEGIN:VCALENDAR');
  assert.equal(lines[lines.length - 1], 'END:VCALENDAR');
  const stack = [];
  let event = null;
  const events = [];
  for (const line of lines) {
    assert.match(line, /^[A-Z][A-Z0-9-]*(;[A-Z0-9-]+=[^:;]+)*:/, `a content line: ${line}`);
    assert.ok(!/[\u0000-\u0008\u000a-\u001f\u007f]/.test(line), `no control characters: ${JSON.stringify(line)}`);
    const colon = line.indexOf(':');
    const head = line.slice(0, colon);
    const name = head.split(';')[0];
    const value = line.slice(colon + 1);
    if (name === 'BEGIN') { stack.push(value); if (value === 'VEVENT') event = {}; continue; }
    if (name === 'END') {
      assert.equal(stack.pop(), value, 'BEGIN and END match');
      if (value === 'VEVENT') { events.push(event); event = null; }
      continue;
    }
    if (TEXT_PROPS.includes(name)) assert.match(value, /^(?:[^\\;,]|\\[\\;,nN])*$/, `${name} is escaped: ${value}`);
    if (event) {
      event[name] = (event[name] || 0) + 1;
      if (['DTSTAMP', 'LAST-MODIFIED'].includes(name) || (['DTSTART', 'DTEND'].includes(name) && !head.includes('VALUE=DATE'))) {
        assert.match(value, /^\d{8}T\d{6}Z$/, `${name} is UTC`);
      }
      if (head.includes('VALUE=DATE')) assert.match(value, /^\d{8}$/);
      if (name === 'STATUS') assert.ok(['CONFIRMED', 'TENTATIVE', 'CANCELLED'].includes(value));
      if (name === 'SEQUENCE') assert.ok(/^\d+$/.test(value) && Number(value) < 2 ** 31);
    }
  }
  assert.equal(stack.length, 0);
  events.forEach((e) => ONCE.forEach((p) => assert.equal(e[p], 1, `${p} once in every event`)));
  for (const p of ['VERSION:2.0', 'PRODID:', 'X-WR-CALNAME:Canopy', 'REFRESH-INTERVAL;VALUE=DURATION:PT1H', 'X-PUBLISHED-TTL:PT1H']) {
    assert.ok(lines.some((l) => l.startsWith(p)), p);
  }
  const cal = new ICAL.Component(ICAL.parse(text));
  return cal.getAllSubcomponents('vevent').map((v) => {
    const e = new ICAL.Event(v);
    return {
      uid: e.uid,
      summary: e.summary,
      location: e.location,
      description: e.description,
      start: e.startDate.toJSDate().getTime(),
      end: e.endDate.toJSDate().getTime(),
      allDay: e.startDate.isDate,
      status: v.getFirstPropertyValue('status'),
      url: v.getFirstPropertyValue('url'),
      sequence: v.getFirstPropertyValue('sequence')
    };
  });
}

module.exports = { checkIcs };
