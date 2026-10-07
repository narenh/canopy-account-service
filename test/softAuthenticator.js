// A software passkey for tests: makes and uses ES256 credentials the way a
// phone does, so the real @simplewebauthn/server checks run end to end.
// "none" attestation, like every real sign-up here.

const crypto = require('crypto');

// ---- Just enough CBOR for an attestation object and a COSE key ----
function head(major, len) {
  if (len < 24) return Buffer.from([(major << 5) | len]);
  if (len < 256) return Buffer.from([(major << 5) | 24, len]);
  return Buffer.from([(major << 5) | 25, len >> 8, len & 0xff]);
}
function cbor(value) {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') { const b = Buffer.from(value, 'utf8'); return Buffer.concat([head(3, b.length), b]); }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (value instanceof Map) {
    const parts = [head(5, value.size)];
    value.forEach((v, k) => parts.push(cbor(k), cbor(v)));
    return Buffer.concat(parts);
  }
  throw new Error('unsupported CBOR value');
}

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

// One device's passkeys.
function createAuthenticator() {
  const creds = []; // { id (Buffer), privateKey, rpId, userHandle, counter }

  function register(options, origin) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const id = crypto.randomBytes(16);
    const coseKey = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
    const counter = Buffer.alloc(4);
    const idLen = Buffer.from([id.length >> 8, id.length & 0xff]);
    // UP | UV | BE | BS | AT: present, verified, synced, with credential data.
    const authData = Buffer.concat([sha256(options.rp.id), Buffer.from([0x01 | 0x04 | 0x08 | 0x10 | 0x40]), counter, Buffer.alloc(16), idLen, id, coseKey]);
    const attestationObject = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false }));
    creds.push({ id, privateKey, rpId: options.rp.id, userHandle: options.user.id, counter: 0 });
    return {
      id: b64u(id),
      rawId: b64u(id),
      type: 'public-key',
      response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject), transports: ['internal'] },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform'
    };
  }

  // Signs in with this device's first passkey for the RP (or the one with
  // `credId`).
  function authenticate(options, origin, credId) {
    const cred = credId ? creds.find((c) => b64u(c.id) === credId) : creds.find((c) => c.rpId === options.rpId);
    if (!cred) throw new Error('no passkey for that site on this device');
    cred.counter++;
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(cred.counter);
    const authData = Buffer.concat([sha256(options.rpId), Buffer.from([0x01 | 0x04 | 0x08 | 0x10]), counter]);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false }));
    const signature = crypto.sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), cred.privateKey);
    return {
      id: b64u(cred.id),
      rawId: b64u(cred.id),
      type: 'public-key',
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authData),
        signature: b64u(signature),
        userHandle: cred.userHandle
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform'
    };
  }

  return { register, authenticate, creds };
}

module.exports = { createAuthenticator };
