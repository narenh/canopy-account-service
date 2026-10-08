// Profile photos, one per person, stored as the square JPEG the browser
// already cropped and shrank (see public/photo-crop.js) -- so what's on disk
// is small and carries none of the original photo's EXIF, location
// included. An app crops and shrinks its own, and nothing makes it re-encode
// the way a browser's canvas does, so the metadata is taken out here as well
// (withoutMetadata).
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

// The JPEG with its metadata taken out, or null if it isn't a JPEG this
// can read. Cameras write the location, the time and the device into
// APP1 (EXIF and XMP), and editors into APP13 (IPTC) and comments; those
// go, along with every other APPn segment except the three that change
// how the picture looks: APP0 (JFIF), APP2 (the colour profile) and APP14
// (Adobe's colour transform). The picture itself is kept byte for byte,
// up to its end marker. Anything after that (a phone's "motion photo"
// video, say) goes too.
function withoutMetadata(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) return null;
  const parts = [buf.subarray(0, 2)];
  let i = 2;
  while (i + 4 <= buf.length) {
    if (buf[i] !== 0xff) return null;
    const marker = buf[i + 1];
    if (marker === 0xff) { i++; continue; }
    if (marker === 0xda) {
      // The start of the image data. Its end is the first FFD9: inside the
      // data a real FF is always followed by 00 or a restart marker, and
      // any embedded thumbnail was in the APP1 that's already gone.
      let end = i + 2;
      while (end + 1 < buf.length && !(buf[end] === 0xff && buf[end + 1] === 0xd9)) end++;
      if (end + 1 >= buf.length) return null;
      parts.push(buf.subarray(i, end + 2));
      return Buffer.concat(parts);
    }
    const len = buf.readUInt16BE(i + 2);
    if (len < 2 || i + 2 + len > buf.length) return null;
    const isApp = marker >= 0xe0 && marker <= 0xef;
    const keep = !(isApp && ![0xe0, 0xe2, 0xee].includes(marker)) && marker !== 0xfe;
    if (keep) parts.push(buf.subarray(i, i + 2 + len));
    i += 2 + len;
  }
  return null;
}

module.exports = {
  withoutMetadata,

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
