// Tests for the signed-announce shape helpers (Phase A, slice 4).
// Run from the repo root with: node test-announce.js
//
// Pure-helper tests only. The receiver-side handler that wraps these
// (handleSignedAnnounce in server.js) is validated end-to-end against
// the cohort, not in unit tests.

const nacl = require('tweetnacl');
const {
  canonicalize,
  signPayload,
  verifyPayload,
  isSignedAnnounce,
  validateSignedAnnounceShape,
  isSignedSelfUpdate,
  validateSignedSelfUpdateShape,
} = require('./server.js');

let passed = 0;
let failed = 0;

function check(label, ok, detail) {
  if (ok) {
    console.log('  PASS  ' + label);
    passed += 1;
  } else {
    console.log('  FAIL  ' + label + (detail ? '  (' + detail + ')' : ''));
    failed += 1;
  }
}

// Build a minimal valid signed-announce payload (unsigned). Tests
// assemble cases by mutating this base.
function basePayload(overrides = {}) {
  return {
    pubkey: 'a'.repeat(64),
    endpoint: { host: '203.0.113.42', port: 3141 },
    version: '2.4.0',
    witnessed_count: 0,
    sequence: 1,
    signed_at: Math.floor(Date.now() / 1000),
    peers: [],
    signature: 'b'.repeat(128),
    ...overrides,
  };
}

console.log('');
console.log('isSignedAnnounce');

check('rejects null',
  isSignedAnnounce(null) === false);
check('rejects undefined',
  isSignedAnnounce(undefined) === false);
check('rejects empty object',
  isSignedAnnounce({}) === false);
check('rejects legacy announce shape',
  isSignedAnnounce({ url: 'https://example.com', pubkey: 'a'.repeat(64) }) === false);
check('rejects missing signature',
  isSignedAnnounce(basePayload({ signature: undefined })) === false);
check('rejects non-string signature',
  isSignedAnnounce(basePayload({ signature: 123 })) === false);
check('rejects missing endpoint',
  isSignedAnnounce(basePayload({ endpoint: undefined })) === false);
check('rejects non-object endpoint',
  isSignedAnnounce(basePayload({ endpoint: 'host:port' })) === false);
check('rejects missing sequence',
  isSignedAnnounce(basePayload({ sequence: undefined })) === false);
check('rejects float sequence',
  isSignedAnnounce(basePayload({ sequence: 1.5 })) === false);
check('rejects missing signed_at',
  isSignedAnnounce(basePayload({ signed_at: undefined })) === false);
check('rejects missing pubkey',
  isSignedAnnounce(basePayload({ pubkey: undefined })) === false);
check('accepts well-formed signed announce',
  isSignedAnnounce(basePayload()) === true);

console.log('');
console.log('validateSignedAnnounceShape');

check('returns null for valid payload',
  validateSignedAnnounceShape(basePayload()) === null);
check('rejects non-signed-shape',
  typeof validateSignedAnnounceShape({}) === 'string');
check('rejects bad pubkey hex (too short)',
  validateSignedAnnounceShape(basePayload({ pubkey: 'abc' })) === 'bad pubkey');
check('rejects bad pubkey hex (non-hex chars)',
  validateSignedAnnounceShape(basePayload({ pubkey: 'g'.repeat(64) })) === 'bad pubkey');
check('accepts pubkey with mixed case hex',
  validateSignedAnnounceShape(basePayload({ pubkey: 'AbCdEf' + 'a'.repeat(58) })) === null);
check('rejects empty endpoint.host',
  validateSignedAnnounceShape(basePayload({ endpoint: { host: '', port: 3141 } })) === 'bad endpoint.host');
check('rejects non-string endpoint.host',
  validateSignedAnnounceShape(basePayload({ endpoint: { host: 42, port: 3141 } })) === 'bad endpoint.host');
check('rejects port 0',
  validateSignedAnnounceShape(basePayload({ endpoint: { host: 'h', port: 0 } })) === 'bad endpoint.port');
check('rejects port 65536',
  validateSignedAnnounceShape(basePayload({ endpoint: { host: 'h', port: 65536 } })) === 'bad endpoint.port');
check('rejects float port',
  validateSignedAnnounceShape(basePayload({ endpoint: { host: 'h', port: 3141.5 } })) === 'bad endpoint.port');
check('accepts witnessed_count omitted',
  validateSignedAnnounceShape(basePayload({ witnessed_count: undefined })) === null);
check('rejects float witnessed_count',
  validateSignedAnnounceShape(basePayload({ witnessed_count: 1.5 })) === 'bad witnessed_count');
check('accepts peers omitted',
  validateSignedAnnounceShape(basePayload({ peers: undefined })) === null);
check('rejects non-array peers',
  validateSignedAnnounceShape(basePayload({ peers: { 0: 'x' } })) === 'bad peers');
check('rejects non-string version',
  validateSignedAnnounceShape(basePayload({ version: 240 })) === 'bad version');

console.log('');
console.log('round-trip: real keypair, signPayload then verify against unsigned pubkey');

// Sanity check that the helpers integrate end-to-end with a real keypair:
// build an unsigned payload, sign it, the result has isSignedAnnounce true
// (because signPayload appends a signature), shape is valid, and verify
// passes. This crosses slice-3 primitives with slice-4 detectors and
// confirms they compose.
const kp = nacl.sign.keyPair();
const pubHex = Buffer.from(kp.publicKey).toString('hex');

const unsigned = {
  pubkey: pubHex,
  endpoint: { host: '198.51.100.7', port: 3141 },
  version: '2.4.0',
  witnessed_count: 0,
  sequence: 1,
  signed_at: Math.floor(Date.now() / 1000),
  peers: [],
};
const signed = signPayload(unsigned, kp.secretKey);

check('signed payload is detected as signed-announce',
  isSignedAnnounce(signed) === true);
check('signed payload passes shape validation',
  validateSignedAnnounceShape(signed) === null);
check('signed payload verifies under pubkey',
  verifyPayload(signed, kp.publicKey) === true);

// Tampering: change the announced port after signing.
const tampered = { ...signed, endpoint: { host: signed.endpoint.host, port: 9999 } };
check('tampered payload (port change) fails verify',
  verifyPayload(tampered, kp.publicKey) === false);
check('tampered payload still passes shape (signature is structurally present)',
  validateSignedAnnounceShape(tampered) === null);

// === Slice 6: signed self-update shape ===

function baseUpdatePayload(overrides = {}) {
  return {
    pubkey: 'a'.repeat(64),
    endpoint: { host: '203.0.113.42', port: 3141 },
    sequence: 1,
    signed_at: Math.floor(Date.now() / 1000),
    signature: 'b'.repeat(128),
    ...overrides,
  };
}

console.log('');
console.log('isSignedSelfUpdate');

check('rejects null',
  isSignedSelfUpdate(null) === false);
check('rejects empty object',
  isSignedSelfUpdate({}) === false);
check('rejects legacy announce shape',
  isSignedSelfUpdate({ url: 'https://example.com', pubkey: 'a'.repeat(64) }) === false);
check('rejects missing signature',
  isSignedSelfUpdate(baseUpdatePayload({ signature: undefined })) === false);
check('rejects missing endpoint',
  isSignedSelfUpdate(baseUpdatePayload({ endpoint: undefined })) === false);
check('rejects missing sequence',
  isSignedSelfUpdate(baseUpdatePayload({ sequence: undefined })) === false);
check('rejects float sequence',
  isSignedSelfUpdate(baseUpdatePayload({ sequence: 1.5 })) === false);
check('rejects missing signed_at',
  isSignedSelfUpdate(baseUpdatePayload({ signed_at: undefined })) === false);
check('rejects missing pubkey',
  isSignedSelfUpdate(baseUpdatePayload({ pubkey: undefined })) === false);
check('accepts well-formed self-update',
  isSignedSelfUpdate(baseUpdatePayload()) === true);

console.log('');
console.log('validateSignedSelfUpdateShape');

check('returns null for valid payload',
  validateSignedSelfUpdateShape(baseUpdatePayload()) === null);
check('rejects non-update-shape',
  typeof validateSignedSelfUpdateShape({}) === 'string');
check('rejects bad pubkey hex',
  validateSignedSelfUpdateShape(baseUpdatePayload({ pubkey: 'abc' })) === 'bad pubkey');
check('rejects empty endpoint.host',
  validateSignedSelfUpdateShape(baseUpdatePayload({ endpoint: { host: '', port: 3141 } })) === 'bad endpoint.host');
check('rejects port 0',
  validateSignedSelfUpdateShape(baseUpdatePayload({ endpoint: { host: 'h', port: 0 } })) === 'bad endpoint.port');
check('rejects port 65536',
  validateSignedSelfUpdateShape(baseUpdatePayload({ endpoint: { host: 'h', port: 65536 } })) === 'bad endpoint.port');

console.log('');
console.log('round-trip: real keypair, sign self-update, verify');

const updateUnsigned = {
  pubkey: pubHex,
  endpoint: { host: '198.51.100.7', port: 3141 },
  sequence: 5,
  signed_at: Math.floor(Date.now() / 1000),
};
const updateSigned = signPayload(updateUnsigned, kp.secretKey);

check('signed update is detected as self-update',
  isSignedSelfUpdate(updateSigned) === true);
check('signed update passes shape validation',
  validateSignedSelfUpdateShape(updateSigned) === null);
check('signed update verifies under pubkey',
  verifyPayload(updateSigned, kp.publicKey) === true);

const updateTampered = { ...updateSigned, endpoint: { host: 'attacker', port: 1 } };
check('tampered update fails verify',
  verifyPayload(updateTampered, kp.publicKey) === false);

// Self-update shape is intentionally a subset of announce; an announce
// payload (which has extra fields) does NOT match isSignedSelfUpdate
// only because of structural distinctness... actually it does match,
// since update fields are all present in announce. The dispatch path
// in server.js therefore checks isSignedAnnounce first via the
// /announce route; the /update route is reached only by clients that
// post to /update, which is itself the disambiguator.
// We test a realistic case: the announce shape (with peers etc) sent
// to the update endpoint matches the update-shape check structurally.
// This is intentional; the route URL is the discriminator, not the
// payload shape. The shape check just confirms required fields exist.
check('a full announce payload structurally satisfies update shape too (URL discriminates)',
  isSignedSelfUpdate(signed) === true);

console.log('');
console.log('summary  ' + passed + ' passed, ' + failed + ' failed');
console.log('');

process.exit(failed > 0 ? 1 : 0);
