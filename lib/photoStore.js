// Profile photos, one per person, stored as the square JPEG the browser
// already cropped and shrank (see public/photo-crop.js) -- so what's on disk
// is small and carries none of the original photo's EXIF, location
// included.
//
// Not public: server.js only serves them to a browser signed in to a
// Canopy account.

const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const DIR = path.join(DATA_DIR, 'photos');
const ID_RE = /^[0-9a-f-]{36}$/;

function fileFor(personId) {
  if (!ID_RE.test(String(personId))) throw new Error('bad person id');
  return path.join(DIR, `${personId}.jpg`);
}

module.exports = {
  save(personId, buffer) {
    if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });
    fs.writeFileSync(fileFor(personId), buffer);
  },
  pathFor(personId) {
    const f = fileFor(personId);
    return fs.existsSync(f) ? f : null;
  },
  remove(personId) {
    const f = fileFor(personId);
    if (fs.existsSync(f)) fs.unlinkSync(f);
  }
};
