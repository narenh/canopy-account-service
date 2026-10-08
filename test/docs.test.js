// The apps' contract: every /api/native/v1 route is in openapi.yaml and
// everything there is a route, the spec holds together and is served,
// the guide mentions every path, and the association files are what the
// phones expect.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const YAML = require('yaml');
const { startServer, browser, nativeApp } = require('./harness');

const ROOT = path.join(__dirname, '..');
const spec = YAML.parse(fs.readFileSync(path.join(ROOT, 'openapi.yaml'), 'utf8'));

// The routes on the native router, as "METHOD /path/{param}". server.js
// is required here for its routes only: it doesn't listen when required.
function nativeRoutes() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'canopy-docs-test-'));
  Object.assign(process.env, { DATA_DIR: dir, ADMIN_PASSWORD: 'x', NODE_ENV: 'test' });
  // Quietly: the startup lines are for a real start.
  const log = console.log;
  console.log = () => {};
  let native;
  try { ({ native } = require('../server')); } finally { console.log = log; }
  return native.stack.filter((l) => l.route).flatMap((l) => Object.keys(l.route.methods)
    .map((m) => `${m.toUpperCase()} ${l.route.path.replace(/:(\w+)/g, '{$1}')}`));
}

function specRoutes() {
  const methods = ['get', 'post', 'patch', 'put', 'delete'];
  return Object.entries(spec.paths).flatMap(([p, ops]) => Object.keys(ops).filter((m) => methods.includes(m)).map((m) => `${m.toUpperCase()} ${p}`));
}

test('every native route is in the spec, and every path in the spec is a route', () => {
  const routes = nativeRoutes().sort();
  const documented = specRoutes().sort();
  assert.ok(routes.length > 20);
  assert.deepEqual(routes.filter((r) => !documented.includes(r)), [], 'routes missing from openapi.yaml');
  assert.deepEqual(documented.filter((r) => !routes.includes(r)), [], 'openapi.yaml paths that are not routes');
});

test('the spec holds together', () => {
  assert.equal(spec.openapi, '3.1.0');
  assert.equal(spec.servers[0].url, 'https://account.canopysf.com/api/native/v1');
  const ids = new Set();
  for (const [p, ops] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(ops)) {
      assert.ok(op.operationId, `${method} ${p} has an operationId`);
      assert.ok(!ids.has(op.operationId), `${op.operationId} is used once`);
      ids.add(op.operationId);
      assert.ok(op.responses && Object.keys(op.responses).length, `${method} ${p} has responses`);
      for (const param of (p.match(/\{(\w+)\}/g) || [])) {
        assert.ok((op.parameters || []).some((x) => `{${x.name}}` === param && x.in === 'path'), `${method} ${p} declares ${param}`);
      }
    }
  }
  // Every $ref points at something.
  const refs = [];
  (function walk(v) {
    if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.entries(v).forEach(([k, x]) => (k === '$ref' ? refs.push(x) : walk(x)));
  })(spec);
  assert.ok(refs.length > 50);
  for (const ref of refs) {
    const target = ref.replace(/^#\//, '').split('/').reduce((o, k) => o && o[k], spec);
    assert.ok(target, `${ref} resolves`);
  }
  // And every security scheme used is declared.
  for (const ops of Object.values(spec.paths)) {
    for (const op of Object.values(ops)) {
      for (const req of op.security || []) Object.keys(req).forEach((k) => assert.ok(spec.components.securitySchemes[k], k));
    }
  }
});

test('the guide mentions every path', () => {
  const guide = fs.readFileSync(path.join(ROOT, 'docs', 'native-api.md'), 'utf8');
  for (const p of Object.keys(spec.paths)) {
    const shown = p.replace(/\{\w+\}/g, '');
    assert.ok(guide.includes(shown), `docs/native-api.md mentions ${p}`);
  }
});

test('the spec is served', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const r = await fetch(server.base + '/api/native/v1/openapi.yaml');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /^application\/yaml/);
  assert.equal(await r.text(), fs.readFileSync(path.join(ROOT, 'openapi.yaml'), 'utf8'));
});

test("the answers have the spec's fields", async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const app = nativeApp(server);
  const made = await app.signUp('ana@example.com', 'Ana', 'Lima');
  const schemas = spec.components.schemas;
  const keys = (o) => Object.keys(o).sort();
  const signedIn = spec.components.responses.SignedInNow.content['application/json'].schema;
  assert.deepEqual(keys(made.data), [...signedIn.required].sort());
  for (const k of Object.keys(made.data)) assert.ok(signedIn.properties[k], `SignedInNow has ${k}`);
  assert.deepEqual(keys(made.data.person), [...schemas.Person.required].sort());
  assert.deepEqual(keys((await app.get('/me/passkeys')).data.passkeys[0]), [...schemas.Passkey.required].sort());
  assert.deepEqual(keys((await app.get('/me/sessions')).data.sessions[0]), [...schemas.Session.required].sort());
  const proven = await nativeApp(server).proveEmail('ana@example.com');
  for (const k of Object.keys(proven.data)) assert.ok(schemas.EmailState.properties[k], `EmailState has ${k}`);
  const options = (await app.post('/me/passkeys/options')).data.options;
  for (const k of schemas.CreationOptions.required) assert.ok(k in options, `creation options have ${k}`);
});

test('the association files', () => {
  const { androidOrigin } = require('../lib/domain');
  const aasa = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs', 'well-known', 'apple-app-site-association'), 'utf8'));
  assert.deepEqual(aasa.webcredentials.apps, ['UC3Y84QJ83.com.canopysf.CanopyEvents']);
  const links = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs', 'well-known', 'assetlinks.json'), 'utf8'));
  assert.equal(links.length, 1);
  assert.deepEqual(links[0].relation, ['delegate_permission/common.get_login_creds']);
  assert.equal(links[0].target.namespace, 'android_app');
  for (const fp of links[0].target.sha256_cert_fingerprints) {
    assert.match(fp, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    // The same fingerprint, as ANDROID_APK_KEY_HASHES takes it.
    assert.match(androidOrigin(fp), /^android:apk-key-hash:[A-Za-z0-9_-]{43}$/);
  }
});
