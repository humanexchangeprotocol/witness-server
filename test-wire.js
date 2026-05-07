// Wire-level integration tests for Phase A (witness-identity-protocol).
// Boots server.js as a subprocess on a fresh isolated database and
// exercises the dual-mode endpoints end-to-end. Slice 4 covers the
// signed /announce path; slice 5 covers signed /peers.
//
// Run from the repo root with: node test-wire.js
//
// The unit-level pure-helper tests live in test-signing.js and
// test-announce.js. This file is the integration tier: it confirms
// that the express routes, JSON parsing, signature flow, replay
// rejection, and dual-mode dispatch all work together over the wire.

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const nacl = require('tweetnacl');
const { verifyPayload, signPayload } = require('./server.js');

const PORT = 4445;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'hep-wire-'));
const env = {
  ...process.env,
  HCP_PORT: String(PORT),
  HCP_DB: path.join(TMP, 'witness.db'),
  HCP_KEY: path.join(TMP, 'server_key.json'),
  HCP_STATE: path.join(TMP, 'server_state.json'),
};

let serverPubkey = null;
let booted = false;
const proc = spawn('node', ['server.js'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
proc.stdout.on('data', d => {
  const s = d.toString();
  const m = s.match(/Public key:\s+([0-9a-f]{64})/);
  if (m) serverPubkey = m[1];
  if (s.includes('Listening on port')) booted = true;
});
proc.stderr.on('data', d => {
  // Surface server-side errors during a failing test.
  if (process.env.WIRE_VERBOSE) process.stderr.write('[srv-err] ' + d);
});

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

async function waitFor(pred, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (pred()) return true;
    await new Promise(r => setTimeout(r, 50));
  }
  return false;
}

async function main() {
  await waitFor(() => booted && serverPubkey, 5000);
  if (!booted || !serverPubkey) {
    console.log('FAIL: server did not boot within 5s');
    process.exit(1);
  }
  const serverPubkeyBytes = new Uint8Array(Buffer.from(serverPubkey, 'hex'));

  // === Slice 4: signed /announce ===
  console.log('');
  console.log('Slice 4: signed /announce round-trip');

  const kp = nacl.sign.keyPair();
  const pubHex = Buffer.from(kp.publicKey).toString('hex');
  const now = Math.floor(Date.now() / 1000);

  const a1 = signPayload({
    pubkey: pubHex,
    endpoint: { host: '203.0.113.99', port: 3141 },
    version: '2.4.0-test',
    witnessed_count: 0,
    sequence: 1,
    signed_at: now,
    peers: [],
  }, kp.secretKey);

  const r1 = await fetch(`http://localhost:${PORT}/announce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(a1),
  });
  check('signed announce returns 200', r1.status === 200, 'got ' + r1.status);
  const d1 = await r1.json();
  check('response.accepted is true', d1.accepted === true);
  check('response.observed_ip is a string', typeof d1.observed_ip === 'string');
  check('response.server_pubkey matches running server', d1.server_pubkey === serverPubkey);
  check('response signature verifies under server_pubkey', verifyPayload(d1, serverPubkeyBytes) === true);

  console.log('');
  console.log('Slice 4: replay and tamper rejection');

  const r2 = await fetch(`http://localhost:${PORT}/announce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(a1),
  });
  check('replay (same sequence) returns 409', r2.status === 409, 'got ' + r2.status);

  const a3 = signPayload({
    pubkey: pubHex,
    endpoint: { host: '203.0.113.99', port: 3141 },
    version: '2.4.0-test',
    witnessed_count: 0,
    sequence: 2,
    signed_at: now + 1,
    peers: [],
  }, kp.secretKey);
  const r3 = await fetch(`http://localhost:${PORT}/announce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(a3),
  });
  check('higher sequence accepted', r3.status === 200, 'got ' + r3.status);

  // Tamper: mutate endpoint after signing so signature will not verify.
  const tampered = { ...a3, endpoint: { host: 'attacker.example', port: 3141 }, sequence: 3 };
  const r4 = await fetch(`http://localhost:${PORT}/announce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(tampered),
  });
  check('tampered payload returns 401', r4.status === 401, 'got ' + r4.status);

  console.log('');
  console.log('Slice 4: legacy /announce path unchanged');

  const r5 = await fetch(`http://localhost:${PORT}/announce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: 'http://198.51.100.1:3141',
      pubkey: 'c'.repeat(64),
      version: '2.3.0',
      witnessed_count: 0,
    }),
  });
  check('legacy announce returns 200', r5.status === 200, 'got ' + r5.status);
  const d5 = await r5.json();
  check('legacy response.accepted is true', d5.accepted === true);
  check('legacy response carries plain peers array', Array.isArray(d5.peers));
  check('legacy response has no signature field', d5.signature === undefined);

  // === Slice 5: signed /peers ===
  console.log('');
  console.log('Slice 5: legacy GET /peers unchanged');

  const r6 = await fetch(`http://localhost:${PORT}/peers`);
  check('legacy /peers returns 200', r6.status === 200);
  const d6 = await r6.json();
  check('legacy /peers has count field', typeof d6.count === 'number');
  check('legacy /peers has peers array', Array.isArray(d6.peers));
  check('legacy /peers has no server_pubkey field', d6.server_pubkey === undefined);
  check('legacy /peers has no signature field', d6.signature === undefined);

  console.log('');
  console.log('Slice 5: signed GET /peers?signed=1');

  const r7 = await fetch(`http://localhost:${PORT}/peers?signed=1`);
  check('signed /peers returns 200', r7.status === 200);
  const d7 = await r7.json();
  check('signed /peers has server_pubkey matching server', d7.server_pubkey === serverPubkey);
  check('signed /peers has peers array', Array.isArray(d7.peers));
  check('signed /peers has as_of timestamp', Number.isInteger(d7.as_of));
  check('signed /peers has signature', typeof d7.signature === 'string');
  check('signed /peers signature verifies', verifyPayload(d7, serverPubkeyBytes) === true);

  // The known signed-mode peer (pubHex) we just announced should appear here.
  const found = d7.peers.find(p => p.pubkey === pubHex);
  check('signed /peers includes the previously announced peer', !!found);
  if (found) {
    check('peer entry has endpoint.host', typeof found.endpoint?.host === 'string');
    check('peer entry has endpoint.port', Number.isInteger(found.endpoint?.port));
    check('peer entry endpoint matches announce', found.endpoint.host === '203.0.113.99' && found.endpoint.port === 3141);
    check('peer entry has version', typeof found.version === 'string');
    check('peer entry has last_seen', Number.isInteger(found.last_seen));
  }

  // Legacy peer (no host/port) should NOT appear in signed peer list.
  const legacyInSigned = d7.peers.find(p => p.pubkey === 'c'.repeat(64));
  check('signed /peers excludes legacy peers without endpoint', !legacyInSigned);

  // === Done ===
  console.log('');
  console.log('summary  ' + passed + ' passed, ' + failed + ' failed');
  console.log('');

  proc.kill();
  await new Promise(r => setTimeout(r, 200));
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => {
  console.error('test threw:', e);
  proc.kill();
  process.exit(1);
});
