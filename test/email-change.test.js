// Changing your own email: a passkey check, a code to the new address,
// and a notice to the old one.

const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, browser } = require('./harness');

test('changing your own email', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  const ana = browser(server);
  const anaId = (await ana.signUp('ana@example.com', 'Ana', 'Lima')).data.person.id;

  const reauth = async (b, credId) => {
    const start = await b.post('/api/auth/reauth/options');
    assert.equal(start.status, 200, start.text);
    assert.equal(start.data.options.userVerification, 'required');
    const response = b.authenticator.authenticate(start.data.options, server.base, credId);
    return b.post('/api/auth/reauth/verify', { response });
  };

  await t.test('no passkey check, no change', async () => {
    const r = await ana.post('/api/profile/email/start', { email: 'ana.new@example.com' });
    assert.equal(r.status, 403);
    assert.equal(r.data.reason, 'reauth_required');
  });

  await t.test("someone else's passkey doesn't count", async () => {
    const start = await ana.post('/api/auth/reauth/options');
    const response = admin.authenticator.authenticate(start.data.options, server.base);
    const r = await ana.post('/api/auth/reauth/verify', { response });
    assert.equal(r.status, 400);
    assert.equal((await ana.post('/api/profile/email/start', { email: 'ana.new@example.com' })).data.reason, 'reauth_required');
  });

  await t.test('passkey, then a code to the new address, then the old one hears about it', async () => {
    assert.equal((await reauth(ana)).status, 200);
    assert.equal((await ana.post('/api/profile/email/start', { email: 'ana@example.com' })).data.reason, 'same_email');
    const start = await ana.post('/api/profile/email/start', { email: 'Ana.New@Example.com' });
    assert.equal(start.status, 200, start.text);
    const code = server.lastCode('ana.new@example.com');
    assert.match(code, /^\d{6}$/);
    assert.equal((await ana.post('/api/profile/email/verify', { code: code === '000000' ? '111111' : '000000' })).data.reason, 'wrong_code');
    const done = await ana.post('/api/profile/email/verify', { code });
    assert.equal(done.status, 200, done.text);
    assert.equal(done.data.person.email, 'ana.new@example.com');
    assert.match(server.output(), /email-changed notice for ana@example\.com: now a•••@example\.com/);
    // Proven, so it counts as verified.
    const listed = (await admin.get('/api/admin/people')).data.people.find((p) => p.id === anaId);
    assert.ok(listed.emailVerifiedAt);
  });

  await t.test('one change per passkey check', async () => {
    const r = await ana.post('/api/profile/email/start', { email: 'ana.third@example.com' });
    assert.equal(r.data.reason, 'reauth_required');
  });

  await t.test('signed out, nothing', async () => {
    const nobody = browser(server);
    assert.equal((await nobody.post('/api/auth/reauth/options')).status, 401);
    assert.equal((await nobody.post('/api/profile/email/start', { email: 'x@example.com' })).status, 401);
  });

  await t.test('the new email signs in with a code; the old one is just a new email', async () => {
    const phone = browser(server);
    const proven = await phone.proveEmail('ana.new@example.com');
    assert.equal(proven.data.state, 'existing');
    const other = browser(server);
    assert.equal((await other.proveEmail('ana@example.com')).data.state, 'new');
  });
});

// The reviewer's enum.js: a quick account (nothing proven), one passkey
// check, and then a list of addresses through the email change, to find
// out which have accounts. Every address answers the same, the tries are
// counted before anything is looked up, and only the code step -- which
// needs the code from that inbox -- says an address is taken.
test("changing your email doesn't say which addresses have accounts", async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = browser(server);
  await admin.post('/api/auth/admin-setup', { password: 'setup-pw' });
  await admin.signUp('host@example.com', 'Hana', 'Host');
  for (let i = 0; i < 3; i++) await browser(server).signUp(`real${i}@example.com`, 'R', 'P');

  const reauth = async (b) => {
    const start = await b.post('/api/auth/reauth/options');
    const response = b.authenticator.authenticate(start.data.options, server.base);
    assert.equal((await b.post('/api/auth/reauth/verify', { response })).status, 200);
  };
  // Without the varying email, everything about an answer.
  const shape = (r) => ({ status: r.status, data: { ...r.data, email: r.data && r.data.email ? '<email>' : undefined } });

  await t.test('an address with an account answers exactly like one without', async () => {
    const att = browser(server);
    assert.equal((await att.quickSignUp('throwaway@nowhere.invalid', 'X', 'Y')).data.person.emailVerified, false);
    await reauth(att);
    const codesFor = (email) => server.output().split(`code for ${email}:`).length - 1;
    const realCodes = codesFor('real0@example.com');
    const answers = [];
    for (const email of ['guess0@example.com', 'real0@example.com', 'guess1@example.com', 'host@example.com', 'real1@example.com']) {
      answers.push(shape(await att.post('/api/profile/email/start', { email })));
    }
    for (const a of answers) assert.deepEqual(a, { status: 200, data: { ok: true, email: '<email>' } });
    // A new address gets a code; one with an account gets a notice instead.
    assert.match(server.lastCode('guess0@example.com'), /^\d{6}$/);
    assert.equal(codesFor('real0@example.com'), realCodes, 'no code to an address with an account');
    assert.match(server.output(), /address-in-use notice for real0@example\.com/);
    assert.match(server.output(), /address-in-use notice for host@example\.com/);
    assert.doesNotMatch(server.output(), /address-in-use notice for guess/);
  });

  await t.test('the tries are counted first: 5 per person an hour, account or not', async () => {
    const att = browser(server);
    await att.quickSignUp('throwaway2@nowhere.invalid', 'X', 'Y');
    await reauth(att);
    const tally = {};
    const candidates = [];
    for (let i = 0; i < 20; i++) candidates.push(`many${i}@example.com`);
    candidates.splice(3, 0, 'real2@example.com');
    candidates.splice(8, 0, 'host@example.com');
    for (const email of candidates) {
      const r = await att.post('/api/profile/email/start', { email });
      const k = `${r.status}:${r.data.reason || 'ok'}`;
      tally[k] = (tally[k] || 0) + 1;
    }
    assert.deepEqual(tally, { '200:ok': 5, '429:rate_limited': 17 });
    // Past the limit, an address with an account is refused the same way.
    assert.equal((await att.post('/api/profile/email/start', { email: 'real1@example.com' })).data.reason, 'rate_limited');
  });

  await t.test('the code step: a wrong code is a wrong code, account or not', async () => {
    const att = browser(server);
    await att.quickSignUp('throwaway3@nowhere.invalid', 'X', 'Y');
    await reauth(att);
    assert.equal((await att.post('/api/profile/email/start', { email: 'real1@example.com' })).status, 200);
    const guess = await att.post('/api/profile/email/verify', { code: '123456' });
    assert.equal(guess.status, 403);
    assert.equal(guess.data.reason, 'wrong_code');
  });

  await t.test('taken between the code and typing it: refused at the code step', async () => {
    const zoe = browser(server);
    await zoe.signUp('zoe@example.com', 'Zoe', 'Zee');
    await reauth(zoe);
    assert.equal((await zoe.post('/api/profile/email/start', { email: 'zoe.new@example.com' })).status, 200);
    const code = server.lastCode('zoe.new@example.com');
    await browser(server).signUp('zoe.new@example.com', 'Someone', 'Else');
    const r = await zoe.post('/api/profile/email/verify', { code });
    assert.equal(r.status, 409);
    assert.equal(r.data.reason, 'email_unavailable');
    assert.equal((await zoe.get('/api/me')).data.person.email, 'zoe@example.com');
  });
});
