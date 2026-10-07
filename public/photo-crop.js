// Framing a profile photo: shows the picked file full screen with a fixed
// circle, pinch/drag to fit (Cropper.js 1.x, vendored in /vendor), and
// resolves with the framed part as a 512px square JPEG -- or null if the
// person cancels.
//
// What leaves the phone is that square, drawn fresh by the browser: not
// the original, and without its EXIF (location included).
//
// Used by the welcome page (setting up a profile) and the reservation
// page (changing the photo later). Brings its own markup and styles;
// needs cropper.min.js loaded first.
//
// The picked photo is shrunk BEFORE Cropper sees it (shrink() below). An
// iPhone hands over the full camera image -- 12 to 48 megapixels, often
// HEIC -- and Cropper keeps several full-size copies of it on screen;
// iOS Safari quietly stops drawing images past a memory budget, which
// left the framing screen black. A 1600px copy is plenty for a 512px
// result and cheap everywhere.
//
// And before that, the whole file is read into memory (readAll() below),
// with "Loading photo…" on screen and no time limit. A photo kept in
// iCloud and not on the phone can still be downloading when the picker
// hands it over; the 10-second limit used to start right then, so a slow
// download read as an unreadable photo. The limit now only covers drawing
// a photo that's already here.
(function(){
  const MAX_SIDE = 1600;
  const LOAD_TIMEOUT_MS = 10000;
  const CSS_HREF = '/vendor/cropperjs-1.6.3/cropper.min.css';

  function ensureStyles(){
    if (document.getElementById('photoCropStyles')) return;
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = CSS_HREF;
    document.head.appendChild(link);
    const style = document.createElement('style');
    style.id = 'photoCropStyles';
    style.textContent = [
      '.pc-overlay{position:fixed;inset:0;z-index:200;background:#000;display:flex;flex-direction:column;',
      'padding:calc(16px + env(safe-area-inset-top)) 16px calc(16px + env(safe-area-inset-bottom));',
      'font-family:-apple-system,BlinkMacSystemFont,"Helvetica Neue",Arial,sans-serif;}',
      '.pc-hint{color:var(--muted,#a6b8ab);font-size:13px;text-align:center;margin:6px 0 12px;}',
      // Clipped, and below the buttons: whatever the crop area does, Cancel
      // stays on top and tappable.
      '.pc-stage{flex:1;min-height:0;position:relative;overflow:hidden;}',
      '.pc-stage img{display:block;max-width:100%;}',
      '.pc-overlay .cropper-view-box,.pc-overlay .cropper-face{border-radius:50%;}',
      '.pc-overlay .cropper-view-box{outline:2px solid rgba(255,255,255,.85);outline-offset:-2px;}',
      '.pc-actions{display:flex;gap:10px;margin-top:14px;position:relative;z-index:2;}',
      '.pc-use:disabled{opacity:.45;}',
      '.pc-actions button{flex:1;border:none;border-radius:12px;padding:12px;font-size:15px;font-weight:700;cursor:pointer;}',
      '.pc-cancel{background:var(--secondary,#1a2b22);color:var(--text,#ecf2ec);border:1px solid var(--field-line,#527561) !important;}',
      '.pc-use{background:var(--accent,#2ec44f);color:var(--on-accent,#03190a);}'
    ].join('');
    document.head.appendChild(style);
  }

  // Every byte of the file, as an in-memory copy -- however long the phone
  // takes to fetch them. Rejects if it can't be read or comes back empty.
  function readAll(file){
    return file.arrayBuffer().then((buf) => {
      if (!buf.byteLength) throw new Error('empty file');
      return new Blob([buf], { type: file.type || 'image/jpeg' });
    });
  }

  // Decodes the file and redraws it at most MAX_SIDE on its long side, as a
  // JPEG blob. Drawing to a canvas also applies the photo's EXIF rotation
  // (browsers do that when drawing), so Cropper doesn't need to.
  function shrink(file){
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(file);
      const img = new Image();
      img.onload = () => {
        try{
          const scale = Math.min(1, MAX_SIDE / Math.max(img.naturalWidth, img.naturalHeight));
          const canvas = document.createElement('canvas');
          canvas.width = Math.max(1, Math.round(img.naturalWidth * scale));
          canvas.height = Math.max(1, Math.round(img.naturalHeight * scale));
          canvas.getContext('2d').drawImage(img, 0, 0, canvas.width, canvas.height);
          URL.revokeObjectURL(url);
          canvas.toBlob((blob) => blob ? resolve(blob) : reject(new Error('unreadable image')), 'image/jpeg', 0.9);
        }catch(err){
          URL.revokeObjectURL(url);
          reject(err);
        }
      };
      img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('unreadable image')); };
      img.src = url;
    });
  }

  // `hint` is the line above the photo, once it's showing; `loadingHint`
  // the line while it's still being read. Rejects if the file can't be
  // read as an image (some formats a browser can't open).
  window.cropProfilePhoto = function(file, hint, loadingHint){
    ensureStyles();
    return new Promise((resolve, reject) => {
      const overlay = document.createElement('div');
      overlay.className = 'pc-overlay';
      overlay.innerHTML =
        '<div class="pc-hint"></div>' +
        '<div class="pc-stage"><img alt=""></div>' +
        '<div class="pc-actions"><button type="button" class="pc-cancel">Cancel</button>' +
        '<button type="button" class="pc-use" disabled>Use photo</button></div>';
      const hintEl = overlay.querySelector('.pc-hint');
      hintEl.textContent = loadingHint || hint || '';
      document.body.appendChild(overlay);

      const img = overlay.querySelector('img');
      const useBtn = overlay.querySelector('.pc-use');
      let url = null;
      let cropper = null;
      let finished = false;
      const done = (value, error) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        if (cropper) cropper.destroy();
        if (url) URL.revokeObjectURL(url);
        overlay.remove();
        if (error) reject(error); else resolve(value);
      };
      // Never leave someone on a screen that isn't going to show anything --
      // counted from when the photo's bytes are here, not from the pick.
      let timer = null;

      img.onerror = () => done(null, new Error('unreadable image'));
      img.onload = () => {
        hintEl.textContent = hint || '';
        cropper = new Cropper(img, {
          checkOrientation: false,
          ready(){ useBtn.disabled = false; },
          aspectRatio: 1,
          viewMode: 1,
          dragMode: 'move',
          autoCropArea: 0.9,
          cropBoxMovable: false,
          cropBoxResizable: false,
          toggleDragModeOnDblclick: false,
          guides: false,
          center: false,
          highlight: false,
          background: false
        });
      };
      readAll(file).then((copy) => {
        if (finished) return null;
        timer = setTimeout(() => { if (!cropper || useBtn.disabled) done(null, new Error('timed out')); }, LOAD_TIMEOUT_MS);
        return shrink(copy).then((blob) => {
          if (finished) return;
          url = URL.createObjectURL(blob);
          img.src = url;
        });
      }).catch((err) => done(null, err));

      overlay.querySelector('.pc-cancel').addEventListener('click', () => done(null));
      useBtn.addEventListener('click', () => {
        if (!cropper || useBtn.disabled) return;
        const canvas = cropper.getCroppedCanvas({ width: 512, height: 512, fillColor: '#000', imageSmoothingQuality: 'high' });
        if (!canvas){ done(null, new Error('crop failed')); return; }
        canvas.toBlob((blob) => {
          if (!blob){ done(null, new Error('crop failed')); return; }
          done({ blob, dataUrl: canvas.toDataURL('image/jpeg', 0.8) });
        }, 'image/jpeg', 0.88);
      });
    });
  };
})();
