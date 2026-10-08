// The Account Manager's test people tools that happen on the sites (see
// "Admin: test people" in the README): making the admin friends with every
// test person, making past events with them, and clearing both away
// before the test people are deleted. Friendships and events are the
// sites' own, so this service asks each site to do it.
//
// Which sites: the ones the calendar feed asks (store.calendarSites(): a
// calendar URL and a calendar secret, not cut off), at the same URL. In
// practice that's events. A site that doesn't have the endpoint (a 404)
// is left out of the answer rather than counted as failing: tickets, say,
// if it ever has a calendar.
//
// Each request is signed with the site's calendar secret, the way
// client/canopy-account.js's internalAuthorization says: bound to its
// purpose, method, path and body, good for a minute and once. The secret
// itself never travels, and a calendar signature can't be passed off as
// one of these (or the other way round).

const { internalAuthorization } = require('../client/canopy-account');

const TIMEOUT_MS = 15000;
const MAX_BYTES = 64 * 1024;

// `sites()` is store.calendarSites(). The answer is a function that sends
// one request to every site: { purpose, method, path, body, fields }, and
// resolves to [{ site, ok: true, ...fields } | { site, ok: false, error }]
// (sites with no such endpoint left out). Only `fields`, each a whole
// number, are taken from a site's answer.
function createSiteCalls({ sites, fetchImpl = (...args) => fetch(...args), timeoutMs = TIMEOUT_MS, log = console } = {}) {
  async function callOne(site, { purpose, method, path, body, fields }) {
    const url = `${site.calendarUrl.replace(/\/+$/, '')}${path}`;
    const headers = { Accept: 'application/json', Authorization: internalAuthorization(site.secret, { purpose, method, url, body }) };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    try {
      const res = await fetchImpl(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs)
      });
      if (res.status === 404) return null;
      const text = await res.text();
      if (!res.ok) throw new Error(`answered ${res.status}`);
      if (text.length > MAX_BYTES) throw new Error('answered too much');
      const data = JSON.parse(text);
      const answer = { site: site.name, ok: true };
      for (const f of fields) {
        if (!Number.isInteger(data && data[f]) || data[f] < 0) throw new Error(`answered without ${f}`);
        answer[f] = data[f];
      }
      return answer;
    } catch (err) {
      const why = err.name === 'TimeoutError' ? 'timed out' : err instanceof SyntaxError ? 'answered nonsense' : /^answered/.test(err.message) ? err.message : "couldn't be reached";
      log.warn(`[canopy-account] test people: ${site.name} ${purpose} failed (${why}).`);
      return { site: site.name, ok: false, error: why };
    }
  }

  return async function callSites(request) {
    const results = await Promise.all(sites().map((s) => callOne(s, request)));
    return results.filter(Boolean);
  };
}

module.exports = { createSiteCalls, TIMEOUT_MS };
