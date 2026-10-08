// Photos for test people (see "Admin: test people" in the README): a
// made-up face from i.pravatar.cc for each, fetched here and kept exactly
// as an uploaded photo is (photoStore: its metadata taken out, one square
// JPEG per person), so nothing tells it apart from one a person chose.
//
// pravatar has 70 faces, numbered; each batch takes them in a shuffled
// order, so no two people in one batch share a face (past 70 they repeat).
// A few at a time, each with a short timeout, and the whole batch within
// a budget: if pravatar is slow or down, the people it didn't get to just
// have no photo (initials, everywhere), and nothing else fails.

const crypto = require('crypto');

const PRAVATAR = 'https://i.pravatar.cc';
const FACES = 70;
const SIZE = 512;
const TIMEOUT_MS = 5000;
const BUDGET_MS = 25000;
const AT_ONCE = 4;
// The same ceiling as an upload.
const MAX_BYTES = 3 * 1024 * 1024;

function shuffledFaces() {
  const faces = Array.from({ length: FACES }, (_, i) => i + 1);
  for (let i = faces.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [faces[i], faces[j]] = [faces[j], faces[i]];
  }
  return faces;
}

// Gives each of `ids` a photo, if it can: `save(id, jpeg)` keeps one (and
// returns false if it isn't a JPEG it can clean). Resolves to how many
// got one.
async function addTestPhotos(ids, { save, base = PRAVATAR, fetchImpl = (...args) => fetch(...args), timeoutMs = TIMEOUT_MS, budgetMs = BUDGET_MS, log = console } = {}) {
  const faces = shuffledFaces();
  const deadline = Date.now() + budgetMs;
  let next = 0;
  let saved = 0;
  let failed = 0;

  async function one(id, face) {
    try {
      const res = await fetchImpl(`${base.replace(/\/+$/, '')}/${SIZE}?img=${face}`, {
        headers: { Accept: 'image/jpeg' },
        signal: AbortSignal.timeout(Math.max(1, Math.min(timeoutMs, deadline - Date.now())))
      });
      if (!res.ok) throw new Error(`answered ${res.status}`);
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.length > MAX_BYTES) throw new Error('too big');
      if (save(id, buf)) saved++;
      else failed++;
    } catch (err) {
      failed++;
    }
  }

  async function worker() {
    while (next < ids.length && Date.now() < deadline) {
      const i = next++;
      await one(ids[i], faces[i % faces.length]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(AT_ONCE, ids.length) }, worker));
  const missed = ids.length - saved;
  if (missed) log.warn(`[canopy-account] test people: ${missed} of ${ids.length} got no photo (${failed} failed, ${missed - failed} out of time).`);
  return saved;
}

module.exports = { addTestPhotos, PRAVATAR };
