// Shared by every account page: talking to the server, the passkey
// prompts, the photo picker and the backdrop. Inlined into each page by
// server.js, after copy.js and the passkey library.

// The passkey library is inlined by the server. If it's somehow missing,
// say so rather than leaving dead buttons.
const { startRegistration, startAuthentication, browserSupportsWebAuthn } = window.SimpleWebAuthnBrowser || {
  startRegistration: () => Promise.reject(new Error('passkey library did not load -- reload the page')),
  startAuthentication: () => Promise.reject(new Error('passkey library did not load -- reload the page')),
  browserSupportsWebAuthn: () => true
};

async function sendJson(method, url, body){
  const res = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const data = await res.json().catch(() => ({}));
  return { res, data };
}

function postJson(url, body){
  return sendJson('POST', url, body || {});
}

function detail(text){
  return text ? ' (' + String(text).slice(0, 160) + ')' : '';
}

// What a failed passkey prompt means, in words. NotAllowedError is the
// browser's answer for cancelled, timed out and "no passkey here" alike --
// nearly always someone tapping Cancel, so it says nothing (empty string)
// and leaves them where they were. Anything else carries the browser's own
// error, so a report from a phone says what actually went wrong.
function passkeyErrorText(err){
  if (err && err.name === 'NotAllowedError') return '';
  if (err && err.name === 'InvalidStateError') return t('welcome.passkeyExists');
  return t('welcome.failed') + detail(err && (err.name + ': ' + err.message));
}

// Makes the passkey from the server's options and sends it back. Returns
// the server's answer once it's saved; otherwise null, with the reason in
// errorEl.
async function finishRegistration(options, errorEl){
  let response;
  try{
    response = await startRegistration({ optionsJSON: options });
  }catch(err){
    errorEl.textContent = passkeyErrorText(err);
    return null;
  }
  const { res, data } = await postJson('/api/auth/register/verify', { response });
  if (res.ok) return data;
  errorEl.textContent = data.reason === 'conflict' || data.reason === 'email_has_account' ? t('welcome.emailTaken')
    : data.reason === 'expired' ? t('welcome.expired')
    : data.reason === 'bad_link' ? t('setup.badLink')
    : t('welcome.failed') + detail(data.error || res.status);
  return null;
}

// "Sign in with passkey". True once signed in.
async function signInWithPasskey(errorEl){
  const start = await postJson('/api/auth/login/options');
  if (!start.res.ok){ errorEl.textContent = t('welcome.failed') + detail(start.data.error || start.res.status); return false; }
  let response;
  try{
    response = await startAuthentication({ optionsJSON: start.data.options });
  }catch(err){
    errorEl.textContent = passkeyErrorText(err);
    return false;
  }
  const { res, data } = await postJson('/api/auth/login/verify', { response });
  if (res.ok) return true;
  errorEl.textContent = data.reason === 'unknown_passkey' ? t('welcome.unknownPasskey') : t('welcome.failed') + detail(data.error || res.status);
  return false;
}

// Disables a button while `work` runs, and turns a network failure into
// words in errorEl.
async function busy(btn, errorEl, work){
  if (errorEl) errorEl.textContent = '';
  btn.disabled = true;
  try{
    return await work();
  }catch(err){
    if (errorEl) errorEl.textContent = t('welcome.unreachable');
  }finally{
    btn.disabled = false;
  }
}

// ---------------- The photo picker ----------------
// Wires a .photo-pick label (with an <input type=file>, an <img> and the
// placeholder <svg>) to the framing screen (public/photo-crop.js). Calls
// onPicked(blob) with the framed 512px square; nothing leaves the phone
// until the page sends it.
function wirePhotoPicker(pick, errorEl, onPicked){
  const input = pick.querySelector('input[type=file]');
  const preview = pick.querySelector('img');
  const prompt = pick.querySelector('svg.placeholder');
  input.addEventListener('change', async () => {
    const file = input.files && input.files[0];
    if (!file) return;
    errorEl.textContent = '';
    let result;
    try{
      result = await cropProfilePhoto(file, t('welcome.cropHint'), t('welcome.photoLoading'));
    }catch(err){
      errorEl.textContent = t('welcome.photoUnreadable');
      return;
    }finally{
      // Cleared only once the photo's been read (picking the same one again
      // should still work) -- not while the phone may still be fetching it.
      input.value = '';
    }
    if (!result) return;
    showPhoto(pick, result.dataUrl);
    if (prompt) prompt.classList.add('hidden');
    onPicked(result.blob);
  });
  return {
    show(url){ showPhoto(pick, url); if (prompt) prompt.classList.add('hidden'); }
  };
}

function showPhoto(pick, url){
  const preview = pick.querySelector('img');
  preview.src = url;
  preview.classList.remove('hidden');
  pick.classList.add('has-photo');
}

// ---------------- Backdrop ----------------
// The uploaded backdrop behind the card, when there is one.
function setUpBackdrop(){
  const url = document.body.getAttribute('data-backdrop');
  if (!url || url.charAt(0) !== '/') return;
  document.body.style.setProperty('--backdrop', 'url("' + url + '")');
  document.body.classList.add('has-backdrop');
  document.documentElement.classList.add('has-backdrop');
  tintEdgesFrom(url);
}

// Works out the colour along the top and bottom edges of the backdrop as
// it's actually cropped on this screen (cover, centered), and hands each
// to its .edge-tint bar -- and the bottom one to the page background, for
// a Safari that ignores the bars. Scaled down to a few dozen pixels first.
function tintEdgesFrom(url){
  const top = document.getElementById('edgeTop');
  const bottom = document.getElementById('edgeBottom');
  if (!top || !bottom) return;
  const img = new Image();
  img.onload = () => {
    try{
      const vw = window.innerWidth, vh = window.innerHeight;
      const cw = 48, ch = Math.max(2, Math.round(cw * vh / vw));
      const scale = Math.max(cw / img.naturalWidth, ch / img.naturalHeight);
      const dw = img.naturalWidth * scale, dh = img.naturalHeight * scale;
      const canvas = document.createElement('canvas');
      canvas.width = cw;
      canvas.height = ch;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, (cw - dw) / 2, (ch - dh) / 2, dw, dh);
      // 0.75: the backdrop sits under a 25% black dim (body::after).
      const edge = (y) => {
        const d = ctx.getImageData(0, y, cw, 1).data;
        const sum = [0, 0, 0];
        for (let i = 0; i < d.length; i += 4){ sum[0] += d[i]; sum[1] += d[i + 1]; sum[2] += d[i + 2]; }
        return 'rgb(' + sum.map(v => Math.round(v / cw * 0.75)).join(',') + ')';
      };
      top.style.backgroundColor = edge(0);
      bottom.style.backgroundColor = edge(ch - 1);
      document.documentElement.style.backgroundColor = edge(ch - 1);
    }catch(e){
      // Leave the default dark strips.
    }
  };
  img.src = url;
}

function formatDate(ms){
  return new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}
