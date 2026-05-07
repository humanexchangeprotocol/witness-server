// Tests for the canonical-JSON and signed-payload utilities.
// Run from the repo root with: node test-signing.js
//
// No server boot. Requires server.js for the pure functions only.

const nacl = require('tweetnacl');
const { canonicalize, signPayload, verifyPayload } = require('./server.js');

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

console.log('');
console.log('canonicalize');

check('null',
  canonicalize(null) === 'null');
check('number',
  canonicalize(42) === '42');
check('string',
  canonicalize('hi') === '"hi"');
check('empty object',
  canonicalize({}) === '{}');
check('empty array',
  canonicalize([]) === '[]');
check('keys sorted alphabetically at top level',
  canonicalize({ b: 1, a: 2 }) === '{"a":2,"b":1}');
check('keys sorted at every level',
  canonicalize({ z: { y: 1, x: 2 } }) === '{"z":{"x":2,"y":1}}');
check('array element order preserved',
  canonicalize([3, 1, 2]) === '[3,1,2]');
check('array of objects, each object sorted',
  canonicalize([{ b: 1, a: 2 }, { d: 3, c: 4 }]) === '[{"a":2,"b":1},{"c":4,"d":3}]');
check('mixed types',
  canonicalize({ b: null, a: [1, { y: 'q', x: 'p' }], c: true })
    === '{"a":[1,{"x":"p","y":"q"}],"b":null,"c":true}');
check('input key order does not affect output',
  canonicalize({ a: 1, b: 2, c: 3 }) === canonicalize({ c: 3, a: 1, b: 2 }));

console.log('');
console.log('signPayload + verifyPayload round-trip');

const kp = nacl.sign.keyPair();

const samplePayloads = [
  { kind: 'announce', pubkey: 'a'.repeat(64), sequence: 1, signed_at: 1715000000 },
  { kind: 'peers', server_pubkey: 'b'.repeat(64), peers: [], as_of: 1715000001 },
  { kind: 'update', pubkey: 'c'.repeat(64), endpoint: { host: '1.2.3.4', port: 3141 }, sequence: 42, signed_at: 1715000002 },
  { kind: 'nested', deep: { a: { b: { c: [1, 2, 3] } } }, list: [{ x: 1 }, { y: 2 }] },
];

for (const p of samplePayloads) {
  const signed = signPayload(p, kp.secretKey);
  check(p.kind + ': signature is hex string of length 128',
    typeof signed.signature === 'string' && signed.signature.length === 128 && /^[0-9a-f]+$/.test(signed.signature));
  check(p.kind + ': signed payload verifies under correct pubkey',
    verifyPayload(signed, kp.publicKey));
  check(p.kind + ': original fields preserved on signed payload',
    Object.keys(p).every(k => JSON.stringify(signed[k]) === JSON.stringify(p[k])));
}

console.log('');
console.log('verifyPayload rejection cases');

const signed = signPayload({ a: 1, b: 'two' }, kp.secretKey);

check('rejects tampered payload (a changed after signing)',
  !verifyPayload({ ...signed, a: 99 }, kp.publicKey));

const otherKp = nacl.sign.keyPair();
check('rejects wrong public key',
  !verifyPayload(signed, otherKp.publicKey));

check('rejects missing signature field',
  !verifyPayload({ a: 1, b: 'two' }, kp.publicKey));

check('rejects non-hex signature',
  !verifyPayload({ ...signed, signature: 'not-hex' }, kp.publicKey));

check('rejects truncated signature',
  !verifyPayload({ ...signed, signature: signed.signature.slice(0, 10) }, kp.publicKey));

check('rejects null payload',
  !verifyPayload(null, kp.publicKey));

check('rejects pubkey of wrong length',
  !verifyPayload(signed, new Uint8Array(16)));

console.log('');
console.log('re-sign use case');

const resigned = signPayload(signed, kp.secretKey);
check('re-signing a payload that already has a signature drops it cleanly',
  verifyPayload(resigned, kp.publicKey)
  && resigned.signature === signed.signature);

console.log('');
console.log('determinism');

const first = signPayload({ a: 1, b: 2, c: 3 }, kp.secretKey);
const second = signPayload({ c: 3, a: 1, b: 2 }, kp.secretKey);
check('signature is identical regardless of input key order',
  first.signature === second.signature);

console.log('');
console.log('summary  ' + passed + ' passed, ' + failed + ' failed');
console.log('');

process.exit(failed === 0 ? 0 : 1);
