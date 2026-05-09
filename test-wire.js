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
    if (await pred()) return true;
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

  // Slice 7 reachability filter: the previously-announced peer used
  // a synthetic IP (203.0.113.99). The server's probe to that IP fails,
  // so the peer stays at reachable=0 and is excluded from /peers?signed=1.
  // Inclusion semantics are tested in the Slice 7 two-server section
  // below where the announced endpoint is actually reachable.
  const found = d7.peers.find(p => p.pubkey === pubHex);
  check('signed /peers excludes the announced peer (synthetic IP unreachable, slice 7)', !found);

  // Legacy peer (no host/port) should NOT appear in signed peer list.
  const legacyInSigned = d7.peers.find(p => p.pubkey === 'c'.repeat(64));
  check('signed /peers excludes legacy peers without endpoint', !legacyInSigned);

  // === Slice 6: POST /update ===
  console.log('');
  console.log('Slice 6: /update on known peer');

  // Use the peer we already announced (pubHex is in the table from earlier).
  // The peer's last_sequence is 2 from the signed announce above.
  const u1 = signPayload({
    pubkey: pubHex,
    endpoint: { host: '203.0.113.250', port: 3141 },
    sequence: 10,
    signed_at: Math.floor(Date.now() / 1000),
  }, kp.secretKey);
  const ru1 = await fetch(`http://localhost:${PORT}/update`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(u1),
  });
  check('/update on known peer returns 200', ru1.status === 200, 'got ' + ru1.status);
  const du1 = await ru1.json();
  check('/update response.accepted is true', du1.accepted === true);

  // The /update changes the endpoint to another synthetic IP (probe
  // also fails), so we cannot verify the row update via /peers?signed=1
  // here. The row update is proved instead by the replay-rejection
  // tests immediately below, which depend on last_sequence having been
  // advanced to 10. Endpoint preservation across /update is exercised
  // in the Slice 7 two-server section.

  console.log('');
  console.log('Slice 6: /update replay rejection');

  const ru2 = await fetch(`http://localhost:${PORT}/update`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(u1),
  });
  check('/update replay (same sequence) returns 409', ru2.status === 409, 'got ' + ru2.status);

  // A sequence below the last_sequence (10) but above the announce's
  // sequence (2) is still stale: /update and /announce share the
  // per-peer sequence space.
  const u3 = signPayload({
    pubkey: pubHex,
    endpoint: { host: '203.0.113.250', port: 3141 },
    sequence: 5,
    signed_at: Math.floor(Date.now() / 1000),
  }, kp.secretKey);
  const ru3 = await fetch(`http://localhost:${PORT}/update`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(u3),
  });
  check('/update with sequence below stored returns 409', ru3.status === 409, 'got ' + ru3.status);

  console.log('');
  console.log('Slice 6: /update unknown pubkey');

  // Brand-new pubkey, never announced. /update must reject with 404
  // (design: /update is for known peers only).
  const newKp = nacl.sign.keyPair();
  const newPubHex = Buffer.from(newKp.publicKey).toString('hex');
  const u4 = signPayload({
    pubkey: newPubHex,
    endpoint: { host: '203.0.113.99', port: 3141 },
    sequence: 1,
    signed_at: Math.floor(Date.now() / 1000),
  }, newKp.secretKey);
  const ru4 = await fetch(`http://localhost:${PORT}/update`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(u4),
  });
  check('/update with unknown pubkey returns 404', ru4.status === 404, 'got ' + ru4.status);

  console.log('');
  console.log('Slice 6: /update tampered payload');

  const u5 = signPayload({
    pubkey: pubHex,
    endpoint: { host: '203.0.113.250', port: 3141 },
    sequence: 11,
    signed_at: Math.floor(Date.now() / 1000),
  }, kp.secretKey);
  const tamperedU = { ...u5, endpoint: { host: 'attacker.example', port: 3141 } };
  const ru5 = await fetch(`http://localhost:${PORT}/update`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(tamperedU),
  });
  check('/update with tampered payload returns 401', ru5.status === 401, 'got ' + ru5.status);

  console.log('');
  console.log('Slice 6: /update bad shape');

  const ru6 = await fetch(`http://localhost:${PORT}/update`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pubkey: pubHex }),
  });
  check('/update with missing fields returns 400', ru6.status === 400, 'got ' + ru6.status);

  const ru7 = await fetch(`http://localhost:${PORT}/update`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(signPayload({
      pubkey: pubHex,
      endpoint: { host: '', port: 3141 },
      sequence: 11,
      signed_at: Math.floor(Date.now() / 1000),
    }, kp.secretKey)),
  });
  check('/update with empty endpoint.host returns 400', ru7.status === 400, 'got ' + ru7.status);

  console.log('');
  console.log('Slice 6: /update with own pubkey (self short-circuit)');

  // The server's own pubkey signing isn't possible from here (we don't
  // have its secret key) so we just send a structurally valid payload
  // claiming to be from the server itself. Signature won't verify, but
  // self-pubkey check happens BEFORE signature verification, so the
  // self short-circuit returns 200 with self: true.
  const u8 = signPayload({
    pubkey: serverPubkey,
    endpoint: { host: '203.0.113.1', port: 3141 },
    sequence: 1,
    signed_at: Math.floor(Date.now() / 1000),
  }, kp.secretKey); // signed with wrong key, but server short-circuits before checking
  const ru8 = await fetch(`http://localhost:${PORT}/update`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(u8),
  });
  check('/update from own pubkey returns 200 with self:true', ru8.status === 200, 'got ' + ru8.status);
  const du8 = await ru8.json();
  check('/update self short-circuit response has self: true', du8.self === true);

  // === Slice 7: reachability check (witness-identity-protocol §9) ===
  // The receiver verifies a signed announce by also fetching /status
  // on the announced endpoint and confirming the returned server_pubkey
  // matches. To exercise the success path we need a real reachable
  // endpoint whose pubkey matches the announced pubkey, which means
  // spawning a second server B with a known keypair and announcing
  // FROM B (signed with B's secret key) TO A.
  console.log('');
  console.log('Slice 7: reachability check, two-server harness');

  const PORT_B = 4446;
  const TMP_B = fs.mkdtempSync(path.join(os.tmpdir(), 'hep-wire-b-'));
  const KEY_B = path.join(TMP_B, 'server_key.json');

  // Generate B's keypair, write to disk in the format server.js expects
  // (loadOrCreateKeys uses naclUtil.decodeBase64 on publicKey/secretKey
  // and reads publicKeyHex as a separate field).
  const kpB = nacl.sign.keyPair();
  const pubB = Buffer.from(kpB.publicKey).toString('hex');
  fs.writeFileSync(KEY_B, JSON.stringify({
    publicKey: Buffer.from(kpB.publicKey).toString('base64'),
    secretKey: Buffer.from(kpB.secretKey).toString('base64'),
    publicKeyHex: pubB,
    created: new Date().toISOString(),
  }, null, 2));

  let bBooted = false;
  const procB = spawn('node', ['server.js'], {
    env: {
      ...process.env,
      HCP_PORT: String(PORT_B),
      HCP_DB: path.join(TMP_B, 'witness.db'),
      HCP_KEY: KEY_B,
      HCP_STATE: path.join(TMP_B, 'server_state.json'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  procB.stdout.on('data', d => {
    if (d.toString().includes('Listening on port')) bBooted = true;
  });

  await waitFor(() => bBooted, 5000);
  if (!bBooted) {
    console.log('FAIL: server B did not boot within 5s');
    proc.kill();
    procB.kill();
    process.exit(1);
  }

  // Sanity: B's /status returns B's pubkey. This is the value A's
  // probe will compare against.
  const bStatus = await fetch(`http://localhost:${PORT_B}/status`).then(r => r.json());
  check('server B /status returns B\'s pubkey', bStatus.server_pubkey === pubB);

  // Announce TO server A claiming endpoint = localhost:PORT_B and
  // pubkey = B's pubkey. A receives, signature verifies (we signed
  // with B's secretKey), A fires probe to localhost:PORT_B/status,
  // gets pubB back, sets reachable=1.
  const announceB = signPayload({
    pubkey: pubB,
    endpoint: { host: 'localhost', port: PORT_B },
    version: '2.4.0-test-B',
    witnessed_count: 0,
    sequence: 1,
    signed_at: Math.floor(Date.now() / 1000),
    peers: [],
  }, kpB.secretKey);

  const rB = await fetch(`http://localhost:${PORT}/announce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(announceB),
  });
  check('signed announce from B accepted by A', rB.status === 200, 'got ' + rB.status);

  // Probe is async fire-and-forget; poll A's signed peer list until
  // peer B appears. Probe should resolve within a second on loopback.
  const sawB = await waitFor(async () => {
    const r = await fetch(`http://localhost:${PORT}/peers?signed=1`);
    const d = await r.json();
    return d.peers.some(p => p.pubkey === pubB);
  }, 8000);
  check('A\'s probe to B succeeds and B is included in A\'s signed peers', sawB);

  // Verify the peer entry shape now that we have a reachable peer to
  // inspect (these were the assertions removed from slice 5).
  const peersA = await fetch(`http://localhost:${PORT}/peers?signed=1`).then(r => r.json());
  const entryB = peersA.peers.find(p => p.pubkey === pubB);
  check('peer entry has endpoint.host', entryB && typeof entryB.endpoint?.host === 'string');
  check('peer entry has endpoint.port', entryB && Number.isInteger(entryB.endpoint?.port));
  check('peer entry endpoint matches announce', entryB && entryB.endpoint.host === 'localhost' && entryB.endpoint.port === PORT_B);
  check('peer entry has version', entryB && typeof entryB.version === 'string');
  check('peer entry has last_seen', entryB && Number.isInteger(entryB.last_seen));

  console.log('');
  console.log('Slice 7: pubkey-mismatch is rejected at the probe');

  // Announce claiming endpoint = localhost:PORT_B but with a fresh
  // pubkey C. A's probe to localhost:PORT_B/status returns pubB, which
  // does not match the announced pubC, so reachable stays 0 and
  // peer C does not appear in /peers?signed=1.
  const kpC = nacl.sign.keyPair();
  const pubC = Buffer.from(kpC.publicKey).toString('hex');
  const announceC = signPayload({
    pubkey: pubC,
    endpoint: { host: 'localhost', port: PORT_B },
    version: '2.4.0-test-C',
    witnessed_count: 0,
    sequence: 1,
    signed_at: Math.floor(Date.now() / 1000),
    peers: [],
  }, kpC.secretKey);
  const rC = await fetch(`http://localhost:${PORT}/announce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(announceC),
  });
  check('signed announce from C accepted by A (signature OK, probe pending)', rC.status === 200, 'got ' + rC.status);

  // Wait long enough for A's probe to complete (probe timeout is 5s,
  // but loopback /status responds in ms; pubkey comparison fails
  // immediately, reachable=0).
  await new Promise(r => setTimeout(r, 1500));

  const peersAAfterC = await fetch(`http://localhost:${PORT}/peers?signed=1`).then(r => r.json());
  const entryC = peersAAfterC.peers.find(p => p.pubkey === pubC);
  check('A excludes C from signed peers (probe pubkey mismatch)', !entryC);
  // B should still be there.
  const stillB = peersAAfterC.peers.find(p => p.pubkey === pubB);
  check('A still includes B (mismatch on C did not affect B)', !!stillB);

  // Cleanup server B before exiting.
  procB.kill();
  await new Promise(r => setTimeout(r, 200));

  // === Slice 8: heartbeat mode dispatch (witness-identity-protocol §6.1) ===
  // Spawn a third server A2 with HCP_PUBLIC_IP set so it can originate
  // signed announces, and a fourth server B2 with a known keypair.
  // Bootstrap A2's peer table with B2 by manually announcing as B2.
  // Then trigger A2's heartbeat (via the HCP_DEBUG endpoint) and
  // verify B2 received a signed announce for A2.
  console.log('');
  console.log('Slice 8: heartbeat dispatches signed when peer has signed-mode columns');

  const PORT_A2 = 4448;
  const PORT_B2 = 4449;
  const TMP_A2 = fs.mkdtempSync(path.join(os.tmpdir(), 'hep-wire-a2-'));
  const TMP_B2 = fs.mkdtempSync(path.join(os.tmpdir(), 'hep-wire-b2-'));

  // Pre-place B2's keypair so the test client can sign as B2.
  const kpB2 = nacl.sign.keyPair();
  const pubB2 = Buffer.from(kpB2.publicKey).toString('hex');
  fs.writeFileSync(path.join(TMP_B2, 'server_key.json'), JSON.stringify({
    publicKey: Buffer.from(kpB2.publicKey).toString('base64'),
    secretKey: Buffer.from(kpB2.secretKey).toString('base64'),
    publicKeyHex: pubB2,
    created: new Date().toISOString(),
  }, null, 2));

  // A2: configured for signed outbound (HCP_PUBLIC_IP), HCP_DEBUG so
  // we can trigger heartbeat on demand. We don't set HCP_URL here
  // because A2 only needs signed-mode capability for this test.
  let a2Booted = false;
  let a2Pubkey = null;
  const procA2 = spawn('node', ['server.js'], {
    env: {
      ...process.env,
      HCP_PORT: String(PORT_A2),
      HCP_DB: path.join(TMP_A2, 'witness.db'),
      HCP_KEY: path.join(TMP_A2, 'server_key.json'),
      HCP_STATE: path.join(TMP_A2, 'server_state.json'),
      HCP_PUBLIC_IP: '127.0.0.1',
      HCP_PUBLIC_PORT: String(PORT_A2),
      HCP_DEBUG: '1',
      HCP_HEARTBEAT_INTERVAL_MS: '3600000', // 1 hour, effectively disabled; we trigger manually
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  procA2.stdout.on('data', d => {
    const s = d.toString();
    const m = s.match(/Public key:\s+([0-9a-f]{64})/);
    if (m) a2Pubkey = m[1];
    if (s.includes('Listening on port')) a2Booted = true;
  });

  let b2Booted = false;
  const procB2 = spawn('node', ['server.js'], {
    env: {
      ...process.env,
      HCP_PORT: String(PORT_B2),
      HCP_DB: path.join(TMP_B2, 'witness.db'),
      HCP_KEY: path.join(TMP_B2, 'server_key.json'),
      HCP_STATE: path.join(TMP_B2, 'server_state.json'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  procB2.stdout.on('data', d => {
    if (d.toString().includes('Listening on port')) b2Booted = true;
  });

  await waitFor(() => a2Booted && b2Booted && a2Pubkey, 5000);
  if (!a2Booted || !b2Booted || !a2Pubkey) {
    console.log('FAIL: A2/B2 did not boot within 5s');
    proc.kill(); procA2.kill(); procB2.kill();
    process.exit(1);
  }

  // Bootstrap: announce as B2 to A2 so A2 has B2 in its peer table
  // with signed-mode columns populated. Reachability probe will
  // succeed (B2 actually serves /status with pubB2).
  const bootstrapAnnounce = signPayload({
    pubkey: pubB2,
    endpoint: { host: 'localhost', port: PORT_B2 },
    version: '2.4.0-test-B2',
    witnessed_count: 0,
    sequence: 1,
    signed_at: Math.floor(Date.now() / 1000),
    peers: [],
  }, kpB2.secretKey);
  const rBoot = await fetch(`http://localhost:${PORT_A2}/announce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(bootstrapAnnounce),
  });
  check('A2 accepts bootstrap announce from B2', rBoot.status === 200, 'got ' + rBoot.status);

  // Wait for A2's reachability probe to B2 to complete (B2 is on
  // loopback so it should be quick).
  const a2KnowsB2 = await waitFor(async () => {
    const r = await fetch(`http://localhost:${PORT_A2}/peers?signed=1`);
    const d = await r.json();
    return d.peers.some(p => p.pubkey === pubB2);
  }, 5000);
  check('A2 has B2 as a reachable signed peer (bootstrap done)', a2KnowsB2);

  // Sanity check: B2 does NOT yet know A2 (A2 has not announced to
  // anyone yet; heartbeat hasn't fired).
  const b2PeersBefore = await fetch(`http://localhost:${PORT_B2}/peers?signed=1`).then(r => r.json());
  const b2HasA2Before = b2PeersBefore.peers.some(p => p.pubkey === a2Pubkey);
  check('B2 does not yet know A2 (pre-heartbeat)', !b2HasA2Before);

  // Trigger A2's heartbeat. selectAnnounceMode will return 'signed'
  // for B2 (host/port/pubkey populated), SELF_HOST is set on A2, so
  // A2 sends a signed announce to B2.
  const rHb = await fetch(`http://localhost:${PORT_A2}/debug/heartbeat`, {
    method: 'POST',
  });
  check('A2 /debug/heartbeat returns 200', rHb.status === 200, 'got ' + rHb.status);
  const dHb = await rHb.json();
  check('A2 /debug/heartbeat reports ok', dHb.ok === true);

  // After the heartbeat, B2 should have received A2's signed announce.
  // B2's reachability probe back to A2 (at 127.0.0.1:PORT_A2) should
  // also succeed since A2's /status returns A2's pubkey. Poll B2's
  // signed peers until A2 appears.
  const b2KnowsA2 = await waitFor(async () => {
    const r = await fetch(`http://localhost:${PORT_B2}/peers?signed=1`);
    const d = await r.json();
    return d.peers.some(p => p.pubkey === a2Pubkey);
  }, 8000);
  check('B2 received A2 as a reachable signed peer (heartbeat dispatched correctly)', b2KnowsA2);

  // Verify the entry shape on B2's view of A2.
  const peersB2 = await fetch(`http://localhost:${PORT_B2}/peers?signed=1`).then(r => r.json());
  const a2OnB2 = peersB2.peers.find(p => p.pubkey === a2Pubkey);
  check('B2\'s view of A2 has correct host', a2OnB2 && a2OnB2.endpoint.host === '127.0.0.1');
  check('B2\'s view of A2 has correct port', a2OnB2 && a2OnB2.endpoint.port === PORT_A2);

  // Cleanup A2/B2.
  procA2.kill();
  procB2.kill();
  await new Promise(r => setTimeout(r, 200));

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
