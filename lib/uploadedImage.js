// Persistence for admin-uploaded site images (the Open Graph link-preview
// image, the site logo, ...). Each named image gets its own file, all
// living in DATA_DIR, same as canopy.db -- not under public/ or
// views/, because those come from the git-tracked source and get wiped on
// every redeploy; DATA_DIR is the one path that's actually mounted as a
// persistent volume in production.

const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Returns an independent {getMeta, getFilePath, save} store for one named
// image, e.g. createImageStore('og') <-> data/og-image + data/og-image.json.
function createImageStore(name) {
  const imageFile = path.join(DATA_DIR, `${name}-image`);
  const metaFile = path.join(DATA_DIR, `${name}-image.json`);

  return {
    // Returns { mimeType, uploadedAt } for the current image, or null if
    // none has ever been uploaded.
    getMeta() {
      if (!fs.existsSync(metaFile) || !fs.existsSync(imageFile)) return null;
      try {
        return JSON.parse(fs.readFileSync(metaFile, 'utf8'));
      } catch (e) {
        return null;
      }
    },

    getFilePath() {
      return imageFile;
    },

    // uploadedAt becomes the cache-busting `?v=` on the public image URL --
    // every re-upload gets a brand new URL, so platforms/browsers that
    // cache by URL can't keep serving a stale image.
    save(buffer, mimeType) {
      ensureDir();
      fs.writeFileSync(imageFile, buffer);
      const meta = { mimeType, uploadedAt: Date.now() };
      fs.writeFileSync(metaFile, JSON.stringify(meta));
      return meta;
    }
  };
}

module.exports = { createImageStore };
