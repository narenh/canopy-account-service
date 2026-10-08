// Runs the real server in a child process on a scratch DATA_DIR, and
// browser-ish clients that keep their own cookie and send an Origin.

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { createAuthenticator } = require('./softAuthenticator');

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
    srv.on('error', reject);
  });
}

async function startServer(extraEnv = {}) {
  const port = extraEnv.PORT ? Number(extraEnv.PORT) : await freePort();
  // A scratch folder unless one is given (and then it's left alone).
  const ownDir = !extraEnv.DATA_DIR;
  const dataDir = extraEnv.DATA_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-account-test-'));
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, ADMIN_PASSWORD: 'setup-pw', NODE_ENV: 'test', SMTP_HOST: '', ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let output = '';
  const codes = []; // { email, code }
  const onData = (chunk) => {
    output += chunk;
    for (const m of String(chunk).matchAll(/code for (\S+): (\d{6})/g)) codes.push({ email: m[1], code: m[2] });
  };
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('server did not start:\n' + output)), 10000);
    child.stdout.on('data', () => { if (output.includes('listening on port')) { clearTimeout(timer); resolve(); } });
    child.on('exit', (code) => reject(new Error(`server exited ${code}:\n${output}`)));
  });
  const base = `http://localhost:${port}`;
  return {
    base,
    port,
    dataDir,
    output: () => output,
    lastCode(email) {
      const found = codes.filter((c) => c.email === email).pop();
      return found && found.code;
    },
    stop() {
      child.kill();
      if (ownDir) fs.rmSync(dataDir, { recursive: true, force: true });
    }
  };
}

// A browser: a cookie, an Origin, and a device's passkeys.
function browser(server, { origin } = {}) {
  let cookie = null;
  const authenticator = createAuthenticator();
  const pageOrigin = origin || server.base;

  async function request(method, url, { body, headers = {}, form } = {}) {
    const h = { ...headers };
    if (cookie) h.Cookie = `canopy_session=${cookie}`;
    if (method !== 'GET' && h.Origin === undefined) h.Origin = pageOrigin;
    let payload;
    if (form) payload = form;
    else if (body !== undefined) { h['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
    const res = await fetch(server.base + url, { method, headers: h, body: payload, redirect: 'manual' });
    (res.headers.getSetCookie ? res.headers.getSetCookie() : []).forEach((c) => {
      const m = /^canopy_session=([^;]*)/.exec(c);
      if (m) cookie = /Max-Age=0/.test(c) ? null : m[1];
    });
    const text = await res.text();
    let data = null;
    try { data = JSON.parse(text); } catch (e) {}
    return { status: res.status, data, text, headers: res.headers };
  }

  return {
    authenticator,
    get cookie() { return cookie; },
    set cookie(v) { cookie = v; },
    get: (url, opts) => request('GET', url, opts),
    post: (url, body, opts) => request('POST', url, { ...opts, body: body === undefined ? {} : body }),
    patch: (url, body, opts) => request('PATCH', url, { ...opts, body }),
    del: (url, opts) => request('DELETE', url, opts),
    upload: (url, form, opts) => request('POST', url, { ...opts, form }),

    // The passkey half of a sign-up / new-passkey step, from its options.
    async makePasskey(optionsRes, opts) {
      const response = authenticator.register(optionsRes.data.options, pageOrigin);
      return this.post('/api/auth/register/verify', { response }, opts);
    },

    async signInWithPasskey(credId, opts) {
      const start = await this.post('/api/auth/login/options', {}, opts);
      const response = authenticator.authenticate(start.data.options, pageOrigin, credId);
      return this.post('/api/auth/login/verify', { response }, opts);
    },

    // Email -> code (from the server's console) -> proven. Returns the
    // verify answer.
    async proveEmail(email, opts) {
      const start = await this.post('/api/auth/email/start', { email }, opts);
      if (start.data && start.data.verified) return start;
      if (start.status !== 200) return start;
      return this.post('/api/auth/email/verify', { code: server.lastCode(email) }, opts);
    },

    // `opts` (headers) go with every step.
    async signUp(email, firstName, lastName, opts) {
      const proven = await this.proveEmail(email, opts);
      if (proven.status !== 200 || proven.data.state !== 'new') throw new Error('expected a new email: ' + proven.text);
      const made = await this.post('/api/auth/register/new', { firstName, lastName }, opts);
      if (made.status !== 200) throw new Error('register/new failed: ' + made.text);
      return this.makePasskey(made, opts);
    },

    // A quick sign-up: name, email, passkey, no code. Returns the
    // register/verify answer (or the start's, if that was refused).
    async quickSignUp(email, firstName, lastName, opts) {
      const start = await this.post('/api/auth/quick/start', { email, firstName, lastName }, opts);
      if (start.status !== 200) return start;
      const response = authenticator.register(start.data.options, pageOrigin);
      return this.post('/api/auth/register/verify', { response }, opts);
    }
  };
}

module.exports = { startServer, browser };
