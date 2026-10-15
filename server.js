/**
 * Human Exchange Protocol Witness Server
 *
 * Three jobs. Witness attestation, settlement relay, network presence.
 * Two tables. One signing key. Nothing more.
 */

const express = require('express');
const cors = require('cors');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// === CONFIGURATION ===
const PORT = process.env.HCP_PORT || 3141;
const DB_PATH = process.env.HCP_DB || path.join(__dirname, 'witness.db');
const KEY_PATH = process.env.HCP_KEY || path.join(__dirname, 'server_key.json');
const STATE_PATH = process.env.HCP_STATE || path.join(__dirname, 'server_state.json');
// v2.10.0 minimization: a witness keeps what it holds for hours, not days.
const MINT_RETENTION_HOURS = 6; // idempotent re-witness window only
const RELAY_RETENTION_HOURS = 72;
const SESSION_RETENTION_HOURS = 2; // v2.10.0: sessions are ephemeral, two hours max
const SESSION_OPEN_MINUTES = 10; // v2.11.0: a session with no partner is dropped after this
const PIPE_RETENTION_HOURS = 24; // Invite pipes are ephemeral, 24 hour max (matches sessions)
const CLEANUP_INTERVAL_MS = 15 * 60 * 1000; // 15 minutes
const DB_SAVE_INTERVAL_MS = 60 * 1000; // 1 minute
const HEARTBEAT_INTERVAL_MS = parseInt(process.env.HCP_HEARTBEAT_INTERVAL_MS, 10) || (15 * 60 * 1000); // default 15 minutes; env override in seconds*1000 for test/operator tuning
const PEER_STALE_HOURS = 24;
// v2.14.0 (Oct 15, 2026): peer flood limits. A witness admits a NEW peer only while it
// holds fewer than PEER_MAX peers and fewer than PEER_PER_OWNER from the same owner
// (registrable domain; a free name service such as DuckDNS is one owner with PEER_PER_FREE;
// a bare IP is its own owner). Known peers always refresh; seed hosts are always admitted.
// Fixed numbers, so the count of instances an attacker runs stops mattering. Matches the
// phone's carrier limits (app 2.143.0). Configurable by env for test rigs and operators.
const PEER_MAX = parseInt(process.env.HCP_PEER_MAX, 10) || 256;
const PEER_PER_OWNER = parseInt(process.env.HCP_PEER_PER_OWNER, 10) || 3;
const PEER_PER_FREE = parseInt(process.env.HCP_PEER_PER_FREE, 10) || 16;
const PEER_FREE_NAMES = ['duckdns.org', 'ddns.net', 'no-ip.org', 'no-ip.com', 'noip.me', 'hopto.org', 'zapto.org', 'sytes.net', 'servebeer.com', 'afraid.org', 'mooo.com', 'dynu.net', 'dynv6.net', 'freeddns.org', 'nip.io', 'sslip.io', 'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'trycloudflare.com', 'loca.lt', 'serveo.net', 'github.io', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'herokuapp.com', 'onrender.com', 'fly.dev', 'glitch.me', 'repl.co', 'replit.dev', 'deno.dev', 'tailscale.net', 'ts.net'];
const PEER_TWO_LEVEL = ['co.uk', 'org.uk', 'ac.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.in', 'net.in', 'org.in', 'firm.in', 'co.jp', 'ne.jp', 'or.jp', 'com.br', 'co.nz', 'co.za', 'com.mx', 'com.ar', 'com.cn', 'com.tw', 'co.kr', 'com.sg', 'com.tr', 'com.hk', 'co.id', 'com.my', 'com.ph', 'com.ng', 'co.ke', 'com.pk', 'com.bd', 'com.np', 'com.co', 'com.pe', 'com.ve', 'com.ua', 'com.eg', 'co.il', 'co.th', 'com.vn'];
function peerHostOf(hostOrUrl) {
  if (typeof hostOrUrl !== 'string' || !hostOrUrl) return '';
  if (hostOrUrl.indexOf('://') < 0) return hostOrUrl.trim().toLowerCase().replace(/:\d+$/, '');
  try { return new URL(hostOrUrl).hostname.toLowerCase(); } catch { return ''; }
}
function peerOwner(hostOrUrl) {
  const h = peerHostOf(hostOrUrl);
  if (!h) return { owner: '', cap: PEER_PER_OWNER };
  if (/^[0-9.]+$/.test(h) || h.indexOf(':') >= 0) return { owner: h, cap: PEER_PER_OWNER };
  for (const f of PEER_FREE_NAMES) if (h === f || h.endsWith('.' + f)) return { owner: 'free:' + f, cap: PEER_PER_FREE };
  const lab = h.split('.'), two = lab.slice(-2).join('.');
  return { owner: (lab.length >= 3 && PEER_TWO_LEVEL.includes(two)) ? lab.slice(-3).join('.') : two, cap: PEER_PER_OWNER };
}
let _seedHosts = null;
function peerIsSeedHost(h) {
  if (!_seedHosts) _seedHosts = (process.env.HCP_SEEDS || '').split(',').map(x => peerHostOf(x.trim())).filter(Boolean);
  return _seedHosts.includes(h);
}
// peerAdmit: true if a peer with this pubkey (or legacy url) at this host/url may be added.
function peerAdmit(pubkey, hostOrUrl, legacyUrl) {
  try {
    const known = legacyUrl
      ? db.exec('SELECT 1 FROM peers WHERE url = ?', [legacyUrl])
      : db.exec('SELECT 1 FROM peers WHERE pubkey = ?', [pubkey]);
    if (known.length && known[0].values.length) return true;
    const h = peerHostOf(hostOrUrl);
    if (h && peerIsSeedHost(h)) return true;
    const self = SELF_URL ? SELF_URL.replace(/\/+$/, '') : '';
    const rows = db.exec('SELECT url, host FROM peers');
    const all = rows.length ? rows[0].values.filter(r => r[0] !== self) : [];
    if (all.length >= PEER_MAX) { console.log(`[peers] refused ${h || hostOrUrl}: table full (${PEER_MAX})`); return false; }
    const o = peerOwner(hostOrUrl);
    const same = all.filter(r => peerOwner(r[1] || r[0]).owner === o.owner).length;
    if (same >= o.cap) { console.log(`[peers] refused ${h}: owner ${o.owner} at its limit (${o.cap})`); return false; }
    return true;
  } catch (e) { console.error('[peers] admit check failed:', e.message); return false; }
}
const SELF_URL = process.env.HCP_URL || null; // This server's public URL (legacy)
// Phase A signed-mode self-identification (witness-identity-protocol §6.1).
// If unset, the witness still accepts signed announces but cannot originate
// outbound signed announces until self-discovery (§5) lands in a later phase.
const SELF_HOST = process.env.HCP_PUBLIC_IP || null;
const SELF_PORT_PUBLIC = parseInt(process.env.HCP_PUBLIC_PORT, 10) || (parseInt(process.env.HCP_PORT, 10) || 3141);
const SEED_PEERS = (process.env.HCP_SEEDS || '').split(',').map(s => s.trim()).filter(Boolean);
const VERSION = '2.14.0';

let db = null;
let serverKeys = null;
let serverState = null;
let startTime = Date.now();

// === ED25519 KEY MANAGEMENT ===

function loadOrCreateKeys() {
  if (fs.existsSync(KEY_PATH)) {
    const data = JSON.parse(fs.readFileSync(KEY_PATH, 'utf8'));
    const secretKey = naclUtil.decodeBase64(data.secretKey);
    const publicKey = naclUtil.decodeBase64(data.publicKey);
    console.log('[keys] Loaded existing server keypair');
    console.log('[keys] Public key:', data.publicKeyHex);
    return { publicKey, secretKey, publicKeyHex: data.publicKeyHex };
  }

  // Generate new keypair on first run
  const keyPair = nacl.sign.keyPair();
  const publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex');
  const data = {
    publicKey: naclUtil.encodeBase64(keyPair.publicKey),
    secretKey: naclUtil.encodeBase64(keyPair.secretKey),
    publicKeyHex,
    created: new Date().toISOString(),
  };
  fs.writeFileSync(KEY_PATH, JSON.stringify(data, null, 2));
  console.log('[keys] Generated new server keypair');
  console.log('[keys] Public key:', publicKeyHex);
  return { publicKey: keyPair.publicKey, secretKey: keyPair.secretKey, publicKeyHex };
}

function sign(message) {
  const msgBytes = naclUtil.decodeUTF8(message);
  const signature = nacl.sign.detached(msgBytes, serverKeys.secretKey);
  return Buffer.from(signature).toString('hex');
}

// === SEQUENCE COUNTER ===
// Monotonic 64-bit (JS-safe via Number, max 2^53-1) counter for replay
// protection on signed wire payloads. Persisted to disk on every increment
// so a sudden process exit cannot retroactively reissue a sequence number.
//
// State loss recovery (server_state.json deleted but server_key.json kept).
// Counter restarts at 0. The protocol's 24-hour signed_at relaxation in
// receivers (see witness-identity-protocol Section 7) is what lets the
// witness rejoin the network after a one-day quiet window. No special
// recovery logic on the sender side.

function loadOrCreateState() {
  if (fs.existsSync(STATE_PATH)) {
    const data = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
    const sequence = Number.isInteger(data.sequence) ? data.sequence : 0;
    console.log('[state] Loaded sequence counter at', sequence);
    return { sequence, updated: data.updated || null };
  }
  const fresh = { sequence: 0, updated: new Date().toISOString() };
  fs.writeFileSync(STATE_PATH, JSON.stringify(fresh, null, 2));
  console.log('[state] Initialized sequence counter at 0');
  return fresh;
}

function persistState() {
  serverState.updated = new Date().toISOString();
  writeFileAtomic(STATE_PATH, JSON.stringify(serverState, null, 2)); // v2.13.0: never half-written
}

function nextSequence() {
  serverState.sequence += 1;
  persistState();
  return serverState.sequence;
}

// === CANONICAL JSON AND SIGNED PAYLOADS ===
// Wire-level signing pre-image. JSON with object keys at every level
// sorted lexicographically, no insignificant whitespace, primitives
// rendered by JSON.stringify. Array element order is preserved (only
// object key order is canonicalized). Used as the byte string an
// Ed25519 signature covers in Phase A and later wire formats.
//
// Pure functions. No module state. Callers pass the keys explicitly,
// which makes these directly testable with throwaway keypairs.

function canonicalize(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    const parts = keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k]));
    return '{' + parts.join(',') + '}';
  }
  return JSON.stringify(value);
}

// signPayload returns a new object with the signature appended. The
// signature covers canonicalize(payload-without-signature). If the
// caller's payload already has a signature field it is dropped before
// signing; this lets a caller re-sign an updated payload without first
// stripping it manually.
function signPayload(payload, secretKeyBytes) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('signPayload: payload must be an object');
  }
  const { signature: _drop, ...rest } = payload;
  const canonical = canonicalize(rest);
  const msgBytes = naclUtil.decodeUTF8(canonical);
  const sigBytes = nacl.sign.detached(msgBytes, secretKeyBytes);
  return { ...rest, signature: Buffer.from(sigBytes).toString('hex') };
}

// verifyPayload returns true only if the signature field is present,
// well-formed, and validates the canonical serialization of the
// remaining fields under the supplied public key. Any malformed input
// returns false rather than throwing, since this function processes
// untrusted data from the network.
function verifyPayload(payload, publicKeyBytes) {
  if (!payload || typeof payload !== 'object') return false;
  if (typeof payload.signature !== 'string') return false;
  if (!(publicKeyBytes instanceof Uint8Array) || publicKeyBytes.length !== 32) return false;
  const { signature, ...rest } = payload;
  let sigBytes;
  try {
    sigBytes = new Uint8Array(Buffer.from(signature, 'hex'));
  } catch {
    return false;
  }
  if (sigBytes.length !== 64) return false;
  try {
    const canonical = canonicalize(rest);
    const msgBytes = naclUtil.decodeUTF8(canonical);
    return nacl.sign.detached.verify(msgBytes, sigBytes, publicKeyBytes);
  } catch {
    return false;
  }
}

// === SIGNED ANNOUNCE WIRE FORMAT (Phase A, slice 4) ===
// Witness-identity-protocol §6.1. Dual-mode: this format coexists with
// the legacy URL-keyed announce until Phase D removes legacy.
//
// Pure shape helpers. No DB access, no signature verification, no clock
// or sequence checks. Receiver-side logic in handleSignedAnnounce wraps
// these with verifyPayload, sequence freshness, and §7's 24-hour
// relaxation for state-loss recovery.

// isSignedAnnounce returns true if a request body has the structural
// shape of the new signed-announce format. Distinguishes new format
// from legacy by the fields the new format requires that legacy did
// not carry (signature, endpoint, sequence, signed_at).
function isSignedAnnounce(body) {
  if (!body || typeof body !== 'object') return false;
  if (typeof body.signature !== 'string') return false;
  if (!body.endpoint || typeof body.endpoint !== 'object') return false;
  if (!Number.isInteger(body.sequence)) return false;
  if (!Number.isInteger(body.signed_at)) return false;
  if (typeof body.pubkey !== 'string') return false;
  return true;
}

// validateSignedAnnounceShape returns null on a structurally valid
// payload, or a short error string identifying the first problem.
// Does not check signature, sequence freshness, or clock skew (those
// are receiver-side concerns layered on top of structural shape).
function validateSignedAnnounceShape(body) {
  if (!isSignedAnnounce(body)) return 'not signed-announce shape';
  if (!/^[0-9a-f]{64}$/i.test(body.pubkey)) return 'bad pubkey';
  const ep = body.endpoint;
  if (typeof ep.host !== 'string' || ep.host.length === 0) return 'bad endpoint.host';
  if (!Number.isInteger(ep.port) || ep.port < 1 || ep.port > 65535) return 'bad endpoint.port';
  if (body.witnessed_count != null && !Number.isInteger(body.witnessed_count)) return 'bad witnessed_count';
  if (body.peers != null && !Array.isArray(body.peers)) return 'bad peers';
  if (body.version != null && typeof body.version !== 'string') return 'bad version';
  return null;
}

// === SIGNED SELF-UPDATE WIRE FORMAT (Phase A, slice 6) ===
// Witness-identity-protocol §6.3. New POST /update endpoint. Smaller
// payload than /announce; used when a witness's observed public IP
// changes and it wants to broadcast the new endpoint without waiting
// for the heartbeat cycle.
//
// Pure shape helpers, mirroring the announce pair above.

function isSignedSelfUpdate(body) {
  if (!body || typeof body !== 'object') return false;
  if (typeof body.signature !== 'string') return false;
  if (typeof body.pubkey !== 'string') return false;
  if (!body.endpoint || typeof body.endpoint !== 'object') return false;
  if (!Number.isInteger(body.sequence)) return false;
  if (!Number.isInteger(body.signed_at)) return false;
  return true;
}

function validateSignedSelfUpdateShape(body) {
  if (!isSignedSelfUpdate(body)) return 'not signed-update shape';
  if (!/^[0-9a-f]{64}$/i.test(body.pubkey)) return 'bad pubkey';
  const ep = body.endpoint;
  if (typeof ep.host !== 'string' || ep.host.length === 0) return 'bad endpoint.host';
  if (!Number.isInteger(ep.port) || ep.port < 1 || ep.port > 65535) return 'bad endpoint.port';
  return null;
}

// === HEARTBEAT MODE DISPATCH (Phase A, slice 8) ===
// Pure function that decides whether we should announce TO a given
// peer using the signed wire format (§6.1) or the legacy URL-keyed
// format. Returns 'signed' if the peer's row has populated host AND
// port columns (which means the peer has previously spoken signed
// to us, so we know they understand the format). Returns 'legacy'
// otherwise.
//
// The caller (heartbeat) further gates 'signed' on whether we
// ourselves can originate signed announces (SELF_HOST set; without
// it announceSignedToServer cannot construct the endpoint to claim
// in the payload). Mode-selection here reflects peer-side capability
// only; sender-side capability is the caller's concern.
function selectAnnounceMode(peerRow) {
  if (!peerRow || typeof peerRow !== 'object') return 'legacy';
  if (typeof peerRow.host !== 'string' || peerRow.host.length === 0) return 'legacy';
  if (!Number.isInteger(peerRow.port) || peerRow.port < 1 || peerRow.port > 65535) return 'legacy';
  if (typeof peerRow.pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(peerRow.pubkey)) return 'legacy';
  return 'signed';
}

// === REACHABILITY (witness-identity-protocol §9, slice 7) ===
// When a signed announce or self-update is accepted, the receiver
// fires an HTTP GET to the announced endpoint's /status and confirms
// the returned server_pubkey matches the pubkey the announcer claimed.
// This is the binding-consistency check that catches IP recycling: a
// witness moves IP, the old IP is now answered by a different machine
// running HEP software with a different pubkey; without this check
// the network keeps sending traffic to the wrong machine.
//
// The probe is async fire-and-forget. handleSignedAnnounce returns
// immediately; the peer is initially inserted with reachable=0 and
// updated to reachable=1 by the probe when (and only if) it succeeds.
// Peers with reachable!=1 are excluded from signed /peers responses.
//
// The async pattern also avoids a DoS surface: if the probe were
// synchronous, an attacker could announce themselves at a slow
// endpoint and tie up announce-handler time up to the probe timeout.
// Async means the announce path always returns in milliseconds.
//
// HCP_PROBE_DISABLED env var skips the probe entirely (peer stays at
// reachable=0). Useful in test environments or for operators on
// networks where outbound HTTP is blocked. Default is probe enabled.

const PROBE_TIMEOUT_MS = 5000;
const PROBE_DISABLED = process.env.HCP_PROBE_DISABLED === '1';

// schemeForPort returns the URL scheme to use when contacting a peer
// at a given port. Operators commonly front witnesses with nginx + TLS
// cert on 443 (the testbed pattern); all other ports default to plain
// HTTP. This avoids a wire-format change while covering the realistic
// deployment shapes. If a future operator runs HTTPS on a non-443
// port, the wire format needs a scheme field; pinned as a Component 3
// follow-up if that case appears.
//
// Used by probeReachability (§9 probe) and the heartbeat outbound
// dispatch. Keep both paths going through this helper so the
// inferred scheme cannot drift between probe and dispatch.
function schemeForPort(port) {
  return port === 443 ? 'https' : 'http';
}

async function probeReachability(host, port, expectedPubkey) {
  try {
    const scheme = schemeForPort(port);
    const resp = await fetch(`${scheme}://${host}:${port}/status`, {
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    if (!resp.ok) return false;
    const data = await resp.json();
    return data.server_pubkey === expectedPubkey;
  } catch {
    return false;
  }
}

// triggerReachabilityProbe runs the probe asynchronously and updates
// the peer's reachable flag when it resolves. The UPDATE matches
// pubkey AND host AND port, so a stale probe result does not
// overwrite a newer announce that changed the endpoint while the
// probe was in flight.
function triggerReachabilityProbe(host, port, pubkey) {
  if (PROBE_DISABLED) return;
  probeReachability(host, port, pubkey)
    .then(ok => {
      try {
        db.run(
          'UPDATE peers SET reachable = ? WHERE pubkey = ? AND host = ? AND port = ?',
          [ok ? 1 : 0, pubkey, host, port]
        );
        saveDatabase();
        console.log(`[probe] ${pubkey.slice(0, 12)} at ${host}:${port} reachable=${ok}`);
      } catch (e) {
        console.error('[probe] DB update failed:', e.message);
      }
    })
    .catch(() => {});
}

// === DATABASE ===

async function initDatabase() {
  const SQL = await initSqlJs();

  // Load existing database or create new
  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
    console.log('[db] Loaded existing database');
  } else {
    db = new SQL.Database();
    console.log('[db] Created new database');
  }

  // === v2.10.0 MINIMIZATION (Oct 13 rulings) ===
  // The witness is a notary of two sealed packets. Person-facing tables
  // hold only the allowlist: codes, fingerprints, public keys, act hash
  // and signatures, encrypted blobs, timestamps. Older databases are
  // migrated in place: tables whose shape held anything more are rebuilt
  // with the allowed columns only, and tables that should not exist are
  // dropped. Run once at boot; idempotent.
  migrateToMinimal();

  db.run(`
    CREATE TABLE IF NOT EXISTS witnessed_mints (
      mint_hash TEXT PRIMARY KEY,
      device_ts INTEGER NOT NULL,
      server_ts INTEGER NOT NULL,
      server_sig TEXT NOT NULL,
      act_hash TEXT,
      created_at INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS settlement_relay (
      handshake_id TEXT PRIMARY KEY,
      encrypted_payload TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS peers (
      url TEXT PRIMARY KEY,
      pubkey TEXT NOT NULL,
      version TEXT,
      witnessed_count INTEGER DEFAULT 0,
      last_heartbeat INTEGER NOT NULL,
      added_at INTEGER NOT NULL
    )
  `);

  // Session tables. Ephemeral rendezvous: codes, keys, sealed packets.
  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      my_code TEXT PRIMARY KEY,
      their_code TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      public_key TEXT NOT NULL,
      encrypted_snapshot TEXT,
      created_at INTEGER NOT NULL,
      session_key TEXT,
      session_sig TEXT
    )
  `);
  // v2.11.0: a fresh per-session key and its signature by the phone's signing
  // key (public material, already on the allowlist as keys and signatures).
  try { db.run('ALTER TABLE sessions ADD COLUMN session_key TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE sessions ADD COLUMN session_sig TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE sessions ADD COLUMN session_commit TEXT'); } catch(e) {} // v2.12.0: the mark

  db.run(`
    CREATE TABLE IF NOT EXISTS session_proposals (
      session_key TEXT PRIMARY KEY,
      proposer_code TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      encrypted_exchange TEXT NOT NULL,
      act_hash TEXT,
      proposer_act_sig TEXT,
      confirmer_act_sig TEXT,
      device_ts INTEGER,
      confirmer_device_ts INTEGER,
      created_at INTEGER NOT NULL,
      resolved_at INTEGER
    )
  `);

  // Invite pipes (code-introduction layer on top of sessions).
  // A pipe is a temporary rendezvous reference carried in a QR code.
  // Redemption introduces session codes to both sides; the existing
  // session machinery then runs unchanged. The pipe never carries an
  // exchange or a name. max_redemptions: 1 = single invite, 0 = room.
  db.run(`
    CREATE TABLE IF NOT EXISTS pipes (
      pipe_code TEXT PRIMARY KEY,
      owner_fingerprint TEXT NOT NULL,
      owner_public_key TEXT NOT NULL,
      max_redemptions INTEGER NOT NULL DEFAULT 1,
      redemption_count INTEGER NOT NULL DEFAULT 0,
      closed INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS pipe_redemptions (
      pipe_code TEXT NOT NULL,
      redeemer_code TEXT NOT NULL,
      owner_code TEXT NOT NULL,
      redeemer_fingerprint TEXT NOT NULL,
      redeemer_public_key TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (pipe_code, redeemer_code)
    )
  `);

  // Ping challenges: the only thing a ping leaves behind, for 60 seconds.
  db.run(`
    CREATE TABLE IF NOT EXISTS ping_challenges (
      nonce TEXT PRIMARY KEY,
      chain_fingerprint TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )
  `);

  db.run('CREATE INDEX IF NOT EXISTS idx_mints_created ON witnessed_mints(created_at)');
  db.run('CREATE INDEX IF NOT EXISTS idx_relay_created ON settlement_relay(created_at)');
  db.run('CREATE INDEX IF NOT EXISTS idx_peers_heartbeat ON peers(last_heartbeat)');
  db.run('CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at)');
  db.run('CREATE INDEX IF NOT EXISTS idx_sessions_their ON sessions(their_code)');
  db.run('CREATE INDEX IF NOT EXISTS idx_session_proposals_created ON session_proposals(created_at)');
  finishMigration();

  // Witness identity protocol Phase A, slice 4: signed-format peer columns.
  // Additive nullable migration. Existing url-keyed rows continue functioning
  // through the dual-mode period. Signed-mode peers are deduplicated by
  // pubkey at the application layer (see handleSignedAnnounce); url is
  // synthesized from host:port to satisfy the existing PRIMARY KEY.
  // last_signed_at is required by §7's 24-hour relaxation rule for
  // recovery from server_state.json loss; receivers compare both sequence
  // and signed_at to decide whether to accept a payload.
  try { db.run('ALTER TABLE peers ADD COLUMN host TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE peers ADD COLUMN port INTEGER'); } catch(e) {}
  try { db.run('ALTER TABLE peers ADD COLUMN last_sequence INTEGER'); } catch(e) {}
  try { db.run('ALTER TABLE peers ADD COLUMN last_signed_at INTEGER'); } catch(e) {}

  // Slice 7: reachability flag per witness-identity-protocol §9.
  // 0 = not yet probed or probe failed; 1 = probe succeeded (HTTP GET
  // /status returned matching server_pubkey within 5 seconds).
  // Signed-mode peers are inserted with reachable=0 and updated by
  // the async probe. Filtered to reachable=1 in getActivePeersSigned.
  try { db.run('ALTER TABLE peers ADD COLUMN reachable INTEGER'); } catch(e) {}

  saveDatabaseNow(); // v2.13.0: the startup migration lands at once
  console.log('[db] Tables ready (minimal shapes, v2.10.0)');
}

// v2.13.0: the write path. Writes go to a temp file that is then renamed over the old
// one, so a crash mid-write can never leave a half-written database (rename is atomic on
// the same filesystem). Saves are grouped: a burst of changes inside SAVE_COALESCE_MS
// becomes one write instead of one per change. Honest limit: a crash loses at most that
// window; open sessions are retried by the phones and attestations are re-requested, so
// nothing on a person's chain depends on it. A shutdown signal (pm2 restart) flushes first.
// The full fix for a busy witness (a file-backed engine writing row by row) stays pinned.
const SAVE_COALESCE_MS = 1000;
let _saveTimer = null;
function writeFileAtomic(path, data) {
  const tmp = path + '.tmp';
  const fd = fs.openSync(tmp, 'w');
  try { fs.writeSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, path);
}
function saveDatabaseNow() {
  if (_saveTimer) { clearTimeout(_saveTimer); _saveTimer = null; }
  try {
    writeFileAtomic(DB_PATH, Buffer.from(db.export()));
  } catch (e) {
    console.error('[db] Save error:', e.message);
  }
}
function saveDatabase() {
  if (_saveTimer) return;
  _saveTimer = setTimeout(saveDatabaseNow, SAVE_COALESCE_MS);
}
function flushAndExit(sig) {
  console.log('[db] ' + sig + ': saving before exit');
  try { if (db) saveDatabaseNow(); } catch (e) { console.error('[db] Final save failed:', e.message); }
  process.exit(0);
}
process.on('SIGINT', () => flushAndExit('SIGINT'));
process.on('SIGTERM', () => flushAndExit('SIGTERM'));

// === MIGRATION TO MINIMAL SHAPES (v2.10.0) ===
// Keeps only allowlisted columns. A table is rebuilt when it carries any
// column outside its allowed set; rows keep their allowed values. Tables
// that should not exist (pair halves, ping log, presence registry,
// aggregate counters) are dropped outright. VACUUM afterwards so the
// removed values do not linger in free pages of the database file.
const MINIMAL_COLUMNS = {
  witnessed_mints: ['mint_hash', 'device_ts', 'server_ts', 'server_sig', 'act_hash', 'created_at'],
  sessions: ['my_code', 'their_code', 'fingerprint', 'public_key', 'encrypted_snapshot', 'created_at', 'session_key', 'session_sig', 'session_commit'],
  session_proposals: ['session_key', 'proposer_code', 'status', 'encrypted_exchange', 'act_hash', 'proposer_act_sig', 'confirmer_act_sig', 'device_ts', 'confirmer_device_ts', 'created_at', 'resolved_at'],
  pipes: ['pipe_code', 'owner_fingerprint', 'owner_public_key', 'max_redemptions', 'redemption_count', 'closed', 'created_at'],
  pipe_redemptions: ['pipe_code', 'redeemer_code', 'owner_code', 'redeemer_fingerprint', 'redeemer_public_key', 'created_at'],
};
const DROPPED_TABLES = ['pair_halves', 'poh_pings', 'presence_registry', 'counters'];

function tableColumns(name) {
  const r = db.exec(`PRAGMA table_info(${name})`);
  return r.length > 0 ? r[0].values.map(v => v[1]) : [];
}

function migrateToMinimal() {
  let changed = false;
  for (const t of DROPPED_TABLES) {
    if (tableColumns(t).length > 0) {
      db.run(`DROP TABLE ${t}`);
      console.log(`[migrate] Dropped table ${t}`);
      changed = true;
    }
  }
  for (const [t, allowed] of Object.entries(MINIMAL_COLUMNS)) {
    const cols = tableColumns(t);
    if (cols.length === 0) continue; // fresh database: created below
    const extra = cols.filter(c => !allowed.includes(c));
    if (extra.length === 0) continue;
    const keep = allowed.filter(c => cols.includes(c));
    db.run(`ALTER TABLE ${t} RENAME TO ${t}_old`);
    changed = true;
    console.log(`[migrate] Rebuilding ${t}: removing ${extra.join(', ')}`);
    // initDatabase creates the minimal shape next; finishMigration then
    // copies the allowed columns across and drops the old table.
    pendingCopies.push({ t, keep });
  }
  migrationChanged = changed;
}
let pendingCopies = [];
let migrationChanged = false;

function finishMigration() {
  for (const { t, keep } of pendingCopies) {
    const list = keep.join(', ');
    let where = '';
    // A proposal without a sealed packet cannot be carried forward.
    if (t === 'session_proposals') where = " WHERE encrypted_exchange IS NOT NULL AND encrypted_exchange != ''";
    db.run(`INSERT OR IGNORE INTO ${t} (${list}) SELECT ${list} FROM ${t}_old${where}`);
    db.run(`DROP TABLE ${t}_old`);
  }
  pendingCopies = [];
  if (migrationChanged) {
    try { db.run('VACUUM'); } catch (e) { console.error('[migrate] VACUUM failed:', e.message); }
    console.log('[migrate] Minimal shapes in place');
  }
  // The lifetime count file (aggregate) is no longer kept.
  for (const dir of new Set([__dirname, path.dirname(DB_PATH)])) {
    const countFile = path.join(dir, 'witness_count.txt');
    if (fs.existsSync(countFile)) { try { fs.unlinkSync(countFile); console.log('[migrate] Removed witness_count.txt'); } catch (e) {} }
  }
}

// === CLEANUP ===

function runCleanup() {
  const now = Math.floor(Date.now() / 1000);
  const mintCutoff = now - (MINT_RETENTION_HOURS * 60 * 60);
  const relayCutoff = now - (RELAY_RETENTION_HOURS * 60 * 60);
  const peerCutoff = now - (PEER_STALE_HOURS * 60 * 60);

  db.run('DELETE FROM witnessed_mints WHERE created_at < ?', [mintCutoff]);
  db.run('DELETE FROM settlement_relay WHERE created_at < ?', [relayCutoff]);

  // Expired sessions (ephemeral, SESSION_RETENTION_HOURS max)
  const sessionCutoff = now - (SESSION_RETENTION_HOURS * 60 * 60);
  db.run('DELETE FROM sessions WHERE created_at < ?', [sessionCutoff]);
  // v2.11.0: a session nobody joined expires in SESSION_OPEN_MINUTES, which
  // shortens the window in which its code could be guessed.
  db.run('DELETE FROM sessions WHERE created_at < ? AND NOT EXISTS (SELECT 1 FROM sessions p WHERE p.my_code = sessions.their_code AND p.their_code = sessions.my_code)', [now - SESSION_OPEN_MINUTES * 60]);
  db.run('DELETE FROM session_proposals WHERE created_at < ?', [sessionCutoff]);
  pruneSessionMemory(sessionCutoff * 1000);
  // Expired invite pipes and their redemption rows (24 hours max)
  const pipeCutoff = now - (PIPE_RETENTION_HOURS * 60 * 60);
  db.run('DELETE FROM pipe_redemptions WHERE created_at < ?', [pipeCutoff]);
  db.run('DELETE FROM pipes WHERE created_at < ?', [pipeCutoff]);
  // Expired ping challenges (60 seconds max)
  db.run('DELETE FROM ping_challenges WHERE created_at < ?', [now - 60]);

  // Remove stale peers (but never remove self)
  db.run('DELETE FROM peers WHERE last_heartbeat < ? AND url != ?', [peerCutoff, SELF_URL || '']);

  saveDatabase();
}

// === REQUEST ALLOWLIST (v2.10.0, security tenet gate) ===
// Every person-facing endpoint names the body fields it may accept.
// Anything else is dropped before a handler sees it, so no readable field
// can reach a row, a response or a log by accident. The allowed fields are
// codes, fingerprints, public keys, act hash and signatures, encrypted
// blobs, timestamps, and a few control values (confirmed, reason,
// max_redemptions). The dropped field names are logged once each per
// process, never their values.
const _droppedLogged = new Set();
function allow(fields) {
  const set = new Set(fields);
  return (req, res, next) => {
    const b = req.body;
    if (b && typeof b === 'object' && !Array.isArray(b)) {
      const kept = {};
      for (const k of Object.keys(b)) {
        if (set.has(k)) kept[k] = b[k];
        else if (!_droppedLogged.has(req.route.path + ':' + k)) {
          _droppedLogged.add(req.route.path + ':' + k);
          console.log(`[allowlist] ${req.method} ${req.route.path}: dropped field '${k}'`);
        }
      }
      req.body = kept;
    } else {
      req.body = {};
    }
    next();
  };
}

// === EXPRESS APP ===

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// Request logging
app.use((req, res, next) => {
  if (req.path !== '/status' && req.path !== '/peers') {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  }
  next();
});

// --- POST /witness ---
// Phone submits a mint event for witnessing
// v2.10.0: the public keys and chain signature older apps send are dropped
// (not needed to attest a hash, and not kept). The attestation signs
// mint_hash:server_ts exactly as before.
app.post('/witness', allow(['mint_hash', 'device_timestamp', 'act_hash']), (req, res) => {
  try {
    const { mint_hash, device_timestamp, act_hash } = req.body;

    // Validate required fields
    if (!mint_hash || !device_timestamp) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Validate mint_hash format (should be hex SHA-256)
    if (!/^[a-f0-9]{64}$/i.test(mint_hash)) {
      return res.status(400).json({ error: 'Invalid mint_hash format' });
    }

    // Check if already witnessed
    const existing = db.exec('SELECT server_ts, server_sig FROM witnessed_mints WHERE mint_hash = ?', [mint_hash]);
    if (existing.length > 0 && existing[0].values.length > 0) {
      // Idempotent. Return existing attestation
      const row = existing[0].values[0];
      return res.json({
        mint_hash,
        server_timestamp: row[0],
        server_signature: row[1],
        server_pubkey: serverKeys.publicKeyHex,
        witnessed: true,
        existing: true,
      });
    }

    // Create attestation
    const serverTimestamp = Math.floor(Date.now() / 1000);
    const attestationMessage = mint_hash + ':' + serverTimestamp;
    const serverSignature = sign(attestationMessage);

    // Store
    // Kept for MINT_RETENTION_HOURS so a retry gets the same attestation.
    const ah = (act_hash && /^[a-f0-9]{64}$/i.test(act_hash)) ? act_hash : null;
    db.run(
      'INSERT INTO witnessed_mints (mint_hash, device_ts, server_ts, server_sig, act_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [mint_hash, device_timestamp, serverTimestamp, serverSignature, ah, serverTimestamp]
    );
    saveDatabase();

    console.log(`[witness] New attestation: ${mint_hash.substring(0, 16)}...`);

    res.json({
      mint_hash,
      server_timestamp: serverTimestamp,
      server_signature: serverSignature,
      server_pubkey: serverKeys.publicKeyHex,
      witnessed: true,
      existing: false,
    });
  } catch (e) {
    console.error('[witness] Error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /ping/challenge ---
// Issue a time-limited nonce for challenge-response ping verification
app.post('/ping/challenge', allow(['chain_fingerprint']), (req, res) => {
  try {
    const { chain_fingerprint } = req.body;
    if (!chain_fingerprint || !/^[a-f0-9]+$/i.test(chain_fingerprint)) {
      return res.status(400).json({ error: 'Invalid chain_fingerprint' });
    }

    const nonce = crypto.randomBytes(16).toString('hex');
    const now = Math.floor(Date.now() / 1000);

    // Clean old challenges for this fingerprint
    db.run('DELETE FROM ping_challenges WHERE chain_fingerprint = ?', [chain_fingerprint]);

    db.run(
      'INSERT INTO ping_challenges (nonce, chain_fingerprint, created_at) VALUES (?, ?, ?)',
      [nonce, chain_fingerprint, now]
    );

    saveDatabase();
    res.json({ nonce, issued_at: now });
  } catch (e) {
    console.error('[ping/challenge] Error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /ping ---
// Proof-of-Human heartbeat attestation. Sign and return; store nothing
// but the 60-second challenge (Oct 8 ruling). v2.10.0: the ping may carry
// head_hash, the hash of the chain's latest record (the ping record
// itself), and the witness signs it in:
//   ping2:<fingerprint>:<head_hash>:<server_ts>
// Rewriting anything before that record then breaks the signature, and a
// witness cannot sign a past time (registry, Component 1, "PING ANCHORS
// THE CHAIN'S HISTORY", Oct 13). Without head_hash (older apps) the old
// message is signed: ping:<fingerprint>::<server_ts>. The sensor hash
// older apps send is dropped by the allowlist and no longer signed.
app.post('/ping', allow(['chain_fingerprint', 'device_ts', 'challenge_nonce', 'head_hash']), (req, res) => {
  try {
    const { chain_fingerprint, device_ts, challenge_nonce, head_hash } = req.body;

    if (!chain_fingerprint || !device_ts) {
      return res.status(400).json({ error: 'Missing required fields (chain_fingerprint, device_ts)' });
    }
    if (!/^[a-f0-9]+$/i.test(chain_fingerprint)) {
      return res.status(400).json({ error: 'Invalid chain_fingerprint format' });
    }
    if (head_hash !== undefined && head_hash !== null && !/^[a-f0-9]{64}$/i.test(head_hash)) {
      return res.status(400).json({ error: 'Invalid head_hash format' });
    }

    // Verify challenge-response if nonce provided
    let challenged = false;
    if (challenge_nonce) {
      const challenge = db.exec(
        'SELECT created_at FROM ping_challenges WHERE nonce = ? AND chain_fingerprint = ?',
        [challenge_nonce, chain_fingerprint]
      );
      if (challenge.length > 0 && challenge[0].values.length > 0) {
        const issuedAt = challenge[0].values[0][0];
        const now = Math.floor(Date.now() / 1000);
        if (now - issuedAt <= 10) {
          challenged = true;
        }
      }
      // Delete used challenge regardless
      db.run('DELETE FROM ping_challenges WHERE nonce = ?', [challenge_nonce]);
    }

    const serverTimestamp = Math.floor(Date.now() / 1000);
    const head = head_hash ? head_hash.toLowerCase() : null;
    const pingMessage = head
      ? 'ping2:' + chain_fingerprint + ':' + head + ':' + serverTimestamp
      : 'ping:' + chain_fingerprint + '::' + serverTimestamp;
    const serverSignature = sign(pingMessage);

    res.json({
      chain_fingerprint,
      head_hash: head,
      server_timestamp: serverTimestamp,
      server_signature: serverSignature,
      server_pubkey: serverKeys.publicKeyHex,
      attested: true,
      challenged,
    });
  } catch (e) {
    console.error('[ping] Error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /presence/:fingerprint was removed in v2.10.0 (Oct 13 ruling): a
// public lookup of when a chain was seen is surveillance. Falls to 404.

// --- PUT /relay/:handshake_id ---
// Phone A deposits encrypted settlement for Phone B
app.put('/relay/:handshake_id', allow(['encrypted_payload']), (req, res) => {
  try {
    const { handshake_id } = req.params;
    const { encrypted_payload } = req.body;

    if (!handshake_id || !encrypted_payload) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Validate handshake_id format
    if (!/^[a-f0-9]{64}$/i.test(handshake_id)) {
      return res.status(400).json({ error: 'Invalid handshake_id format' });
    }

    const now = Math.floor(Date.now() / 1000);

    // Upsert. Overwrite if exists (handles retries)
    db.run('DELETE FROM settlement_relay WHERE handshake_id = ?', [handshake_id]);
    db.run(
      'INSERT INTO settlement_relay (handshake_id, encrypted_payload, created_at) VALUES (?, ?, ?)',
      [handshake_id, encrypted_payload, now]
    );

    saveDatabase();
    console.log(`[relay] Stored settlement: ${handshake_id.substring(0, 16)}...`);

    res.json({ stored: true });
  } catch (e) {
    console.error('[relay] PUT error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- GET /relay/:handshake_id ---
// Phone B retrieves settlement, server deletes it
app.get('/relay/:handshake_id', (req, res) => {
  try {
    const { handshake_id } = req.params;

    if (!/^[a-f0-9]{64}$/i.test(handshake_id)) {
      return res.status(400).json({ error: 'Invalid handshake_id format' });
    }

    const result = db.exec('SELECT encrypted_payload FROM settlement_relay WHERE handshake_id = ?', [handshake_id]);

    if (result.length === 0 || result[0].values.length === 0) {
      return res.status(404).json({ found: false });
    }

    const payload = result[0].values[0][0];

    // Fire and forget. Delete after retrieval
    db.run('DELETE FROM settlement_relay WHERE handshake_id = ?', [handshake_id]);
    saveDatabase();

    console.log(`[relay] Delivered and deleted: ${handshake_id.substring(0, 16)}...`);

    res.json({ found: true, encrypted_payload: payload });
  } catch (e) {
    console.error('[relay] GET error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /announce ---
// Dual-mode dispatch (witness-identity-protocol Phase A, slice 4).
// Signed format (§6.1) is detected by isSignedAnnounce; legacy format
// is the existing url-keyed payload. Both paths coexist until Phase D.
app.post('/announce', (req, res) => {
  try {
    if (isSignedAnnounce(req.body)) {
      return handleSignedAnnounce(req, res);
    }
    return handleLegacyAnnounce(req, res);
  } catch (e) {
    console.error('[announce] Error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

function handleLegacyAnnounce(req, res) {
  const { url, pubkey, version: peerVersion, witnessed_count, peers: peerList } = req.body;

  if (!url || !pubkey) {
    return res.status(400).json({ error: 'Missing url or pubkey' });
  }

  // Validate URL format
  try { new URL(url); } catch { return res.status(400).json({ error: 'Invalid URL' }); }

  // Don't accept announcements about ourselves
  if (SELF_URL && url.replace(/\/+$/, '') === SELF_URL.replace(/\/+$/, '')) {
    return res.json({ accepted: true, self: true });
  }

  const now = Math.floor(Date.now() / 1000);
  const cleanUrl = url.replace(/\/+$/, '');

  // Check if we already know this peer
  const existing = db.exec('SELECT pubkey FROM peers WHERE url = ?', [cleanUrl]);
  const isNew = existing.length === 0 || existing[0].values.length === 0;

  if (isNew && !peerAdmit(pubkey, cleanUrl, cleanUrl)) {
    return res.status(429).json({ error: 'peer limit reached' });
  }
  // Upsert the peer
  db.run('DELETE FROM peers WHERE url = ?', [cleanUrl]);
  db.run(
    'INSERT INTO peers (url, pubkey, version, witnessed_count, last_heartbeat, added_at) VALUES (?, ?, ?, ?, ?, ?)',
    [cleanUrl, pubkey, peerVersion || '?', witnessed_count || 0, now, isNew ? now : now]
  );

  // Process any peers they told us about
  if (Array.isArray(peerList)) {
    for (const p of peerList.slice(0, 50)) { // Cap at 50 to prevent abuse
      if (!p.url || !p.pubkey) continue;
      const pUrl = p.url.replace(/\/+$/, '');
      if (SELF_URL && pUrl === SELF_URL.replace(/\/+$/, '')) continue;
      const pExists = db.exec('SELECT url FROM peers WHERE url = ?', [pUrl]);
      if ((pExists.length === 0 || pExists[0].values.length === 0) && peerAdmit(p.pubkey, pUrl, pUrl)) {
        // New peer we didn't know about. Add with their reported heartbeat or now
        db.run(
          'INSERT INTO peers (url, pubkey, version, witnessed_count, last_heartbeat, added_at) VALUES (?, ?, ?, ?, ?, ?)',
          [pUrl, p.pubkey, p.version || '?', p.witnessed_count || 0, p.last_seen || now, now]
        );
        console.log(`[gossip] Learned about new peer: ${pUrl}`);
      }
    }
  }

  saveDatabase();

  if (isNew) {
    console.log(`[gossip] New peer registered: ${cleanUrl}`);
    // Announce ourselves back to the new peer (async, non-blocking)
    if (SELF_URL) {
      announceToServer(cleanUrl).catch(() => {});
    }
  } else {
    console.log(`[gossip] Heartbeat from: ${cleanUrl}`);
  }

  // Return our peer list so the announcer learns about others
  const ourPeers = getActivePeers();
  res.json({ accepted: true, peers: ourPeers });
}

// handleSignedAnnounce implements witness-identity-protocol §6.1 plus
// the §7 sequence and clock checks. The body has already been
// structurally identified as signed by isSignedAnnounce in the route.
function handleSignedAnnounce(req, res) {
  const body = req.body;
  const shapeError = validateSignedAnnounceShape(body);
  if (shapeError) {
    return res.status(400).json({ error: shapeError });
  }

  // Don't accept announcements claiming our own pubkey.
  if (body.pubkey === serverKeys.publicKeyHex) {
    return res.json({ accepted: true, self: true });
  }

  // Verify signature against the announcer's claimed pubkey.
  let pubkeyBytes;
  try {
    pubkeyBytes = new Uint8Array(Buffer.from(body.pubkey, 'hex'));
    if (pubkeyBytes.length !== 32) throw new Error('len');
  } catch {
    return res.status(400).json({ error: 'bad pubkey bytes' });
  }
  if (!verifyPayload(body, pubkeyBytes)) {
    return res.status(401).json({ error: 'signature verification failed' });
  }

  // Clock skew guard (§7). Reject payloads more than 24 hours from our clock.
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - body.signed_at) > 24 * 60 * 60) {
    return res.status(400).json({ error: 'signed_at out of range' });
  }

  // Sequence freshness check (§7) with 24-hour relaxation for state-loss
  // recovery: a payload with sequence <= stored is accepted only if its
  // signed_at is at least 24 hours newer than the last accepted signed_at
  // for that pubkey.
  const existing = db.exec(
    'SELECT last_sequence, last_signed_at FROM peers WHERE pubkey = ?',
    [body.pubkey]
  );
  if (existing.length > 0 && existing[0].values.length > 0) {
    const prevSeq = existing[0].values[0][0];
    const prevSignedAt = existing[0].values[0][1];
    if (Number.isInteger(prevSeq) && body.sequence <= prevSeq) {
      const relaxed =
        Number.isInteger(prevSignedAt) &&
        body.signed_at - prevSignedAt >= 24 * 60 * 60;
      if (!relaxed) {
        return res.status(409).json({ error: 'stale sequence' });
      }
    }
  }

  // Synthesize url for primary-key purposes; signed-mode rows are
  // logically keyed by pubkey (DELETE WHERE pubkey = ? then INSERT).
  // The synthesis includes the pubkey so two different pubkeys
  // claiming the same endpoint do not collide on the primary key
  // (the reachability check disambiguates which one is the real
  // binding). reachable starts at 0 and is updated to 1 by the async
  // probe (triggerReachabilityProbe below) if /status confirms the
  // pubkey-to-endpoint binding.
  if (!peerAdmit(body.pubkey, body.endpoint.host)) {
    return res.status(429).json({ error: 'peer limit reached' });
  }
  const synthesized = `signed://${body.pubkey}@${body.endpoint.host}:${body.endpoint.port}`;
  db.run('DELETE FROM peers WHERE pubkey = ?', [body.pubkey]);
  db.run(
    'INSERT INTO peers (url, pubkey, version, witnessed_count, last_heartbeat, added_at, host, port, last_sequence, last_signed_at, reachable) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [
      synthesized,
      body.pubkey,
      body.version || '?',
      body.witnessed_count || 0,
      now,
      now,
      body.endpoint.host,
      body.endpoint.port,
      body.sequence,
      body.signed_at,
      0,
    ]
  );

  // Fire async reachability probe (§9). Non-blocking; updates the
  // row's reachable flag when the probe resolves.
  triggerReachabilityProbe(body.endpoint.host, body.endpoint.port, body.pubkey);

  // Process gossip-list entries. We accept new pubkeys for storage but
  // never overwrite an existing pubkey's row from gossip; trust comes
  // from a peer's own signed announce, never from a third party's claim.
  if (Array.isArray(body.peers)) {
    for (const p of body.peers.slice(0, 50)) {
      if (!p || typeof p !== 'object') continue;
      if (typeof p.pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(p.pubkey)) continue;
      if (p.pubkey === serverKeys.publicKeyHex) continue;
      if (p.pubkey === body.pubkey) continue;
      if (!p.endpoint || typeof p.endpoint !== 'object') continue;
      const pHost = p.endpoint.host;
      const pPort = p.endpoint.port;
      if (typeof pHost !== 'string' || pHost.length === 0) continue;
      if (!Number.isInteger(pPort) || pPort < 1 || pPort > 65535) continue;
      const known = db.exec('SELECT pubkey FROM peers WHERE pubkey = ?', [p.pubkey]);
      if ((known.length === 0 || known[0].values.length === 0) && peerAdmit(p.pubkey, pHost)) {
        const pUrl = `signed://${p.pubkey}@${pHost}:${pPort}`;
        db.run(
          'INSERT INTO peers (url, pubkey, version, witnessed_count, last_heartbeat, added_at, host, port) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          [pUrl, p.pubkey, '?', 0, p.last_seen || now, now, pHost, pPort]
        );
        console.log(`[gossip] Learned about new peer (signed): ${p.pubkey.slice(0, 12)} at ${pHost}:${pPort}`);
      }
    }
  }

  saveDatabase();
  console.log(`[gossip] Signed announce from ${body.pubkey.slice(0, 12)} seq=${body.sequence}`);

  // Build signed response with observed_ip echo (§5).
  const observedIpRaw = req.ip || (req.socket && req.socket.remoteAddress) || '';
  const observedIp = observedIpRaw.replace(/^::ffff:/, '');
  const response = {
    accepted: true,
    observed_ip: observedIp,
    peers: getActivePeersSigned(),
    server_pubkey: serverKeys.publicKeyHex,
    signed_at: now,
  };
  const signed = signPayload(response, serverKeys.secretKey);
  res.json(signed);
}

// --- GET /peers ---
// Dual-mode (witness-identity-protocol Phase A, slice 5).
// Plain /peers returns the legacy { peers, count } shape unchanged.
// /peers?signed=1 returns the signed envelope per Section 6.2:
// { server_pubkey, peers, as_of, signature } where each peer carries
// pubkey + endpoint + version + last_seen.
//
// Mode is detected by an explicit query parameter. This is curl-
// testable and gives Phase D a clean cutover when the legacy path
// is removed.
app.get('/peers', (req, res) => {
  if (req.query.signed === '1') {
    const now = Math.floor(Date.now() / 1000);
    const envelope = {
      server_pubkey: serverKeys.publicKeyHex,
      peers: getActivePeersSigned(),
      as_of: now,
    };
    const signed = signPayload(envelope, serverKeys.secretKey);
    return res.json(signed);
  }
  const peers = getActivePeers();
  res.json({ peers, count: peers.length });
});

// --- POST /debug/heartbeat ---
// Test affordance only, gated on HCP_DEBUG=1. Triggers heartbeat()
// synchronously and returns when it completes. Lets the wire test
// exercise the per-peer mode dispatch without waiting on the
// interval timer. The endpoint is not registered at all unless
// HCP_DEBUG is set, so production deploys cannot reach it.
if (process.env.HCP_DEBUG === '1') {
  app.post('/debug/heartbeat', async (req, res) => {
    try {
      await heartbeat();
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
}

// --- POST /update ---
// Self-update broadcast (witness-identity-protocol §6.3). A known
// peer announcing a changed endpoint without a full /announce cycle.
//
// Receiver checks (same as signed /announce):
// - Structural shape.
// - Signature verification against the announcer's claimed pubkey.
// - Clock skew guard (24h window).
// - Sequence freshness with 24h signed_at relaxation for state-loss
//   recovery.
//
// Distinct from /announce in three ways: smaller payload (no peers
// gossip, no witnessed_count, no version), updates only the endpoint
// fields, and rejects unknown pubkeys with 404 (a brand-new peer
// must do a full /announce first; /update is for IP changes on
// peers we already know).
app.post('/update', (req, res) => {
  try {
    const body = req.body;
    if (!isSignedSelfUpdate(body)) {
      return res.status(400).json({ error: 'not signed-update shape' });
    }
    const shapeError = validateSignedSelfUpdateShape(body);
    if (shapeError) {
      return res.status(400).json({ error: shapeError });
    }

    if (body.pubkey === serverKeys.publicKeyHex) {
      return res.json({ accepted: true, self: true });
    }

    let pubkeyBytes;
    try {
      pubkeyBytes = new Uint8Array(Buffer.from(body.pubkey, 'hex'));
      if (pubkeyBytes.length !== 32) throw new Error('len');
    } catch {
      return res.status(400).json({ error: 'bad pubkey bytes' });
    }
    if (!verifyPayload(body, pubkeyBytes)) {
      return res.status(401).json({ error: 'signature verification failed' });
    }

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - body.signed_at) > 24 * 60 * 60) {
      return res.status(400).json({ error: 'signed_at out of range' });
    }

    // Pubkey must already be in the peer table; /update is for IP
    // changes on known peers, not for first introductions.
    const existing = db.exec(
      'SELECT last_sequence, last_signed_at, version, witnessed_count FROM peers WHERE pubkey = ?',
      [body.pubkey]
    );
    if (existing.length === 0 || existing[0].values.length === 0) {
      return res.status(404).json({ error: 'unknown pubkey, send /announce first' });
    }

    const prevSeq = existing[0].values[0][0];
    const prevSignedAt = existing[0].values[0][1];
    const prevVersion = existing[0].values[0][2] || '?';
    const prevWitnessed = existing[0].values[0][3] || 0;

    if (Number.isInteger(prevSeq) && body.sequence <= prevSeq) {
      const relaxed =
        Number.isInteger(prevSignedAt) &&
        body.signed_at - prevSignedAt >= 24 * 60 * 60;
      if (!relaxed) {
        return res.status(409).json({ error: 'stale sequence' });
      }
    }

    const synthesized = `signed://${body.pubkey}@${body.endpoint.host}:${body.endpoint.port}`;
    db.run('DELETE FROM peers WHERE pubkey = ?', [body.pubkey]);
    db.run(
      'INSERT INTO peers (url, pubkey, version, witnessed_count, last_heartbeat, added_at, host, port, last_sequence, last_signed_at, reachable) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        synthesized,
        body.pubkey,
        prevVersion,
        prevWitnessed,
        now,
        now,
        body.endpoint.host,
        body.endpoint.port,
        body.sequence,
        body.signed_at,
        0,
      ]
    );
    saveDatabase();
    console.log(`[gossip] Self-update from ${body.pubkey.slice(0, 12)} -> ${body.endpoint.host}:${body.endpoint.port} seq=${body.sequence}`);

    // The endpoint changed; re-probe to confirm the new binding (§9).
    triggerReachabilityProbe(body.endpoint.host, body.endpoint.port, body.pubkey);

    res.json({ accepted: true });
  } catch (e) {
    console.error('[update] Error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// === GOSSIP FUNCTIONS ===

function getActivePeers() {
  const cutoff = Math.floor(Date.now() / 1000) - (PEER_STALE_HOURS * 60 * 60);
  const result = db.exec(
    'SELECT url, pubkey, version, witnessed_count, last_heartbeat FROM peers WHERE last_heartbeat >= ?',
    [cutoff]
  );
  if (result.length === 0) return [];
  return result[0].values.map(row => ({
    url: row[0],
    pubkey: row[1],
    version: row[2],
    witnessed_count: row[3],
    last_seen: row[4],
  }));
}

// getActivePeersSigned returns the peer list in the signed-format shape
// (witness-identity-protocol §6.1 and §6.2). Only peers we have host/port
// data for AND that have passed the §9 reachability probe (reachable=1)
// are returned. Legacy url-only peers and signed-mode peers whose probe
// has not yet succeeded are excluded; both surface here once they
// announce successfully and the probe to their endpoint confirms the
// pubkey binding.
function getActivePeersSigned() {
  const cutoff = Math.floor(Date.now() / 1000) - (PEER_STALE_HOURS * 60 * 60);
  const result = db.exec(
    'SELECT pubkey, host, port, version, last_heartbeat FROM peers WHERE last_heartbeat >= ? AND host IS NOT NULL AND port IS NOT NULL AND reachable = 1',
    [cutoff]
  );
  if (result.length === 0) return [];
  return result[0].values.map(row => ({
    pubkey: row[0],
    endpoint: { host: row[1], port: row[2] },
    version: row[3] || '?',
    last_seen: row[4],
  }));
}

async function announceToServer(targetUrl) {
  const cleanTarget = targetUrl.replace(/\/+$/, '');
  const payload = {
    url: SELF_URL,
    pubkey: serverKeys.publicKeyHex,
    version: VERSION,
    witnessed_count: 0, // v2.10.0: no aggregate counts (No dashboard ruling); field kept for older peers
    peers: getActivePeers(),
  };
  try {
    const resp = await fetch(cleanTarget + '/announce', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000),
    });
    if (resp.ok) {
      const data = await resp.json();
      // Process any peers they returned
      if (Array.isArray(data.peers)) {
        const now = Math.floor(Date.now() / 1000);
        for (const p of data.peers) {
          if (!p.url || !p.pubkey) continue;
          const pUrl = p.url.replace(/\/+$/, '');
          if (SELF_URL && pUrl === SELF_URL.replace(/\/+$/, '')) continue;
          const exists = db.exec('SELECT url FROM peers WHERE url = ?', [pUrl]);
          if ((exists.length === 0 || exists[0].values.length === 0) && peerAdmit(p.pubkey, pUrl, pUrl)) {
            db.run(
              'INSERT INTO peers (url, pubkey, version, witnessed_count, last_heartbeat, added_at) VALUES (?, ?, ?, ?, ?, ?)',
              [pUrl, p.pubkey, p.version || '?', p.witnessed_count || 0, p.last_seen || now, now]
            );
            console.log(`[gossip] Learned about peer from ${cleanTarget}: ${pUrl}`);
          }
        }
        saveDatabase();
      }
      return true;
    }
  } catch (e) {
    console.log(`[gossip] Could not reach ${cleanTarget}: ${e.message}`);
  }
  return false;
}

// announceSignedToServer originates a signed-format announce per
// witness-identity-protocol §6.1, verifies the response signature, and
// ingests the signed peer list. Requires SELF_HOST to be set (the
// witness has a known public IP) and targetPubkey (the recipient's
// known pubkey for response verification).
//
// Not yet wired into heartbeat. Available for cohort interop testing
// and for future slices that drive outbound signed gossip. Wiring
// signed-vs-legacy outbound mode selection into heartbeat is a
// downstream concern; slice 4 is the inbound path and the staged
// outbound helper, no automatic outbound behavior change.
async function announceSignedToServer(targetUrl, targetPubkey) {
  if (!SELF_HOST) {
    console.log('[gossip] Cannot send signed announce: HCP_PUBLIC_IP unset');
    return false;
  }
  if (typeof targetPubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(targetPubkey)) {
    console.log('[gossip] Cannot send signed announce: bad targetPubkey');
    return false;
  }
  const cleanTarget = targetUrl.replace(/\/+$/, '');
  const now = Math.floor(Date.now() / 1000);
  const sequence = nextSequence();
  const peers = getActivePeersSigned().filter(p => p.pubkey !== targetPubkey);
  const payload = {
    pubkey: serverKeys.publicKeyHex,
    endpoint: { host: SELF_HOST, port: SELF_PORT_PUBLIC },
    version: VERSION,
    witnessed_count: 0, // v2.10.0: no aggregate counts (No dashboard ruling); field kept for older peers
    sequence,
    signed_at: now,
    peers,
  };
  const signed = signPayload(payload, serverKeys.secretKey);

  try {
    const resp = await fetch(cleanTarget + '/announce', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signed),
      signal: AbortSignal.timeout(10000),
    });
    if (!resp.ok) {
      console.log(`[gossip] Signed announce to ${cleanTarget}: HTTP ${resp.status}`);
      return false;
    }
    const data = await resp.json();
    if (data.self) return true; // peer recognized us as themselves; no-op

    // Verify the response is signed by the pubkey we expect.
    if (data.server_pubkey !== targetPubkey) {
      console.log(`[gossip] Signed announce to ${cleanTarget}: server_pubkey mismatch`);
      return false;
    }
    let targetPubkeyBytes;
    try {
      targetPubkeyBytes = new Uint8Array(Buffer.from(targetPubkey, 'hex'));
      if (targetPubkeyBytes.length !== 32) throw new Error('len');
    } catch {
      return false;
    }
    if (!verifyPayload(data, targetPubkeyBytes)) {
      console.log(`[gossip] Signed announce response from ${cleanTarget}: bad signature`);
      return false;
    }

    // Ingest gossipped peers from the signed response.
    if (Array.isArray(data.peers)) {
      const tNow = Math.floor(Date.now() / 1000);
      let inserted = false;
      for (const p of data.peers) {
        if (!p || typeof p !== 'object') continue;
        if (typeof p.pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(p.pubkey)) continue;
        if (p.pubkey === serverKeys.publicKeyHex) continue;
        if (!p.endpoint || typeof p.endpoint !== 'object') continue;
        const pHost = p.endpoint.host;
        const pPort = p.endpoint.port;
        if (typeof pHost !== 'string' || pHost.length === 0) continue;
        if (!Number.isInteger(pPort) || pPort < 1 || pPort > 65535) continue;
        const known = db.exec('SELECT pubkey FROM peers WHERE pubkey = ?', [p.pubkey]);
        if ((known.length === 0 || known[0].values.length === 0) && peerAdmit(p.pubkey, pHost)) {
          const pUrl = `signed://${p.pubkey}@${pHost}:${pPort}`;
          db.run(
            'INSERT INTO peers (url, pubkey, version, witnessed_count, last_heartbeat, added_at, host, port) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [pUrl, p.pubkey, p.version || '?', 0, p.last_seen || tNow, tNow, pHost, pPort]
          );
          console.log(`[gossip] Learned about peer from signed response ${cleanTarget}: ${p.pubkey.slice(0, 12)} at ${pHost}:${pPort}`);
          inserted = true;
        }
      }
      if (inserted) saveDatabase();
    }
    return true;
  } catch (e) {
    console.log(`[gossip] Could not reach ${cleanTarget} (signed): ${e.message}`);
    return false;
  }
}

async function heartbeat() {
  // Run heartbeat if either legacy (SELF_URL) or signed (SELF_HOST)
  // self-identification is configured. Without either we have nothing
  // to announce ourselves AS.
  if (!SELF_URL && !SELF_HOST) return;
  const now = Math.floor(Date.now() / 1000);

  // Self-row update (legacy schema). Only meaningful when SELF_URL is
  // set, since the row is keyed by url. The signed-mode equivalent is
  // implicit: we don't probe ourselves and our own /peers list does
  // not need to contain us.
  let selfClean = null;
  if (SELF_URL) {
    selfClean = SELF_URL.replace(/\/+$/, '');
    db.run('DELETE FROM peers WHERE url = ?', [selfClean]);
    db.run(
      'INSERT INTO peers (url, pubkey, version, witnessed_count, last_heartbeat, added_at) VALUES (?, ?, ?, ?, ?, ?)',
      [selfClean, serverKeys.publicKeyHex, VERSION, 0, now, now]
    );
    saveDatabase();
  }

  // Read peers with all fields needed for mode dispatch. Filter self
  // by pubkey (covers both legacy and signed-mode self rows).
  const peerCutoff = now - (PEER_STALE_HOURS * 60 * 60);
  const result = db.exec(
    'SELECT url, pubkey, host, port FROM peers WHERE last_heartbeat >= ? AND pubkey != ?',
    [peerCutoff, serverKeys.publicKeyHex]
  );
  const peers = result.length === 0 ? [] : result[0].values.map(row => ({
    url: row[0],
    pubkey: row[1],
    host: row[2],
    port: row[3],
  }));

  // Seed peers (legacy URLs from HCP_SEEDS env). We have no pubkey
  // for these until they reply, so dispatch is always legacy.
  // Dedupe: skip a seed if any peer row already covers it. A signed-
  // mode peer's url is synthesized (signed://pubkey@host:port) and
  // does not literally equal the seed string, so we also compare
  // hostnames against the host column. Without this, the same logical
  // peer is announced twice per heartbeat (once signed, once legacy).
  const seedTargets = SEED_PEERS.filter(s => {
    if (s === selfClean) return false;
    if (peers.some(p => p.url === s)) return false;
    try {
      const sHost = new URL(s).hostname;
      return !peers.some(p => p.host === sHost);
    } catch {
      return true;
    }
  });

  if (peers.length === 0 && seedTargets.length === 0) return { signed: 0, legacy: 0 };

  let signedCount = 0;
  let legacyCount = 0;
  for (const peer of peers) {
    // v2.4.0: send signed whenever WE can (SELF_HOST set) and we have
    // the peer's pubkey, regardless of whether the peer row carries
    // host/port. Peers learned via legacy bootstrap have url+pubkey
    // only; before this change those would stay in legacy gossip
    // forever because selectAnnounceMode requires host+port. Target URL
    // is host:port if known (still the protocol's preferred shape),
    // else the legacy url we have on file. announceSignedToServer
    // already accepts a URL as destination; receiver-side handling
    // is shape-driven, not URL-driven.
    const canSendSigned =
      SELF_HOST &&
      typeof peer.pubkey === 'string' &&
      /^[0-9a-f]{64}$/i.test(peer.pubkey);
    if (canSendSigned) {
      // Target URL is host:port if known (the protocol's preferred
      // shape), else the legacy url we have on file. Scheme inferred
      // from port via schemeForPort, the same way the §9 probe does.
      // Pre-v2.4.1 this line hardcoded http://, which produced HTTP
      // 400 from any TLS-fronted peer on port 443; fix locked in by
      // routing both probe and dispatch through the same helper.
      const targetUrl = (peer.host && peer.port)
        ? `${schemeForPort(peer.port)}://${peer.host}:${peer.port}`
        : peer.url;
      if (targetUrl) {
        signedCount += 1;
        await announceSignedToServer(targetUrl, peer.pubkey);
        continue;
      }
    }
    if (peer.url) {
      legacyCount += 1;
      await announceToServer(peer.url);
    }
  }
  for (const target of seedTargets) {
    legacyCount += 1;
    await announceToServer(target);
  }
  console.log(`[gossip] Heartbeat: ${signedCount} signed + ${legacyCount} legacy`);
  return { signed: signedCount, legacy: legacyCount };
}

// --- GET /status ---
// Health check and identity. v2.10.0: no activity counts of any kind
// (No dashboard ruling, Oct 6): what a witness has attested, how many
// sessions are open, how many pings it signed are nobody's business.
app.get('/status', (req, res) => {
  res.json({
    server_pubkey: serverKeys.publicKeyHex,
    version: VERSION,
    url: SELF_URL || null,
    uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
    peer_count: getActivePeers().length,
    timestamp: Math.floor(Date.now() / 1000),
    retention: {
      mints_hours: MINT_RETENTION_HOURS,
      sessions_hours: SESSION_RETENTION_HOURS,
      relay_hours: RELAY_RETENTION_HOURS,
    },
  });
});

// --- GET /stats ---
// v2.10.0: version, uptime and peer count only (No dashboard ruling).
// GET /stats/daily was removed.
app.get('/stats', (req, res) => {
  res.json({
    server_pubkey: serverKeys.publicKeyHex,
    version: VERSION,
    uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
    peer_count: getActivePeers().length,
    as_of: Math.floor(Date.now() / 1000),
  });
});

// --- POST /pair, GET /pair/check/:code ---
// Retired in v2.10.0. A pair half carried the terms of an exchange in
// clear (value, direction, description), which no witness may hold. The
// app withdrew pair-with-codes in v2.134.0 until it has a sealed design.
app.post('/pair', (req, res) => res.status(410).json({ error: 'gone', reason: 'Pair-with-codes is retired: it sent exchange terms in clear' }));
app.get('/pair/check/:code', (req, res) => res.status(410).json({ error: 'gone' }));

// === SESSION ENDPOINTS ===
// Ephemeral pipe: exchange codes → share threads → propose → confirm → chains write → pipe closes.
// The server is just a relay. It never interprets the data.

// Helper: derive a deterministic session key from two codes (sorted)
function sessionKey(codeA, codeB) {
  return [codeA, codeB].sort().join(':');
}

// Code format validation (same alphabet as pairing codes)
function validSessionCode(code) {
  return /^[A-Z]{4}$/.test(code);
}

// --- Session presence and cancel (v2.7.0, Oct 2 rulings) ---
// Presence is in memory only: the time each code last talked to us.
// Every session call counts (join, poll, thread, propose, confirm,
// cancel). A partner silent for SESSION_GONE_S is reported as not
// present. Automatic cancel on silence is OFF unless the operator sets
// HEP_SESSION_AUTOCANCEL=1 (observe before enforce): until then the
// server only logs when it would have cancelled. An explicit cancel
// (POST /session/:code/cancel) always works and ends the session for
// both phones; a pending proposal becomes 'cancelled' so it can no
// longer be confirmed.
const SESSION_GONE_S = 60;
const SESSION_AUTOCANCEL = process.env.HEP_SESSION_AUTOCANCEL === '1';
const SESSION_START_MS = Date.now();
const sessionSeen = new Map();       // code -> ms last seen
const sessionCancelled = new Map();  // session key -> { by, reason, at }
const sessionWouldCancel = new Set(); // session keys already logged

function touchSession(code) { sessionSeen.set(code, Date.now()); }

// seen_s is null when the partner has not talked to this server since
// it started; they count as seen at startup so a restart cancels nobody.
function sessionPresence(theirCode, nowMs) {
  const t = sessionSeen.get(theirCode);
  const age = Math.floor(((nowMs || Date.now()) - (t || SESSION_START_MS)) / 1000);
  return { seen_s: t ? age : null, present: age < SESSION_GONE_S };
}

function validCancelReason(r) { return r === undefined || r === 'cancelled' || r === 'disconnected'; }

function markSessionCancelled(sKey, byCode, reason) {
  if (sessionCancelled.has(sKey)) return sessionCancelled.get(sKey);
  const c = { by: byCode, reason: reason || 'cancelled', at: Date.now() };
  sessionCancelled.set(sKey, c);
  const now = Math.floor(Date.now() / 1000);
  db.run("UPDATE session_proposals SET status = 'cancelled', resolved_at = ? WHERE session_key = ? AND status = 'pending'", [now, sKey]);
  saveDatabase();
  console.log(`[session] Cancelled: ${sKey} by ${byCode} (${c.reason})`);
  return c;
}

function pruneSessionMemory(cutoffMs) {
  for (const [k, t] of sessionSeen) if (t < cutoffMs) sessionSeen.delete(k);
  for (const [k, c] of sessionCancelled) if (c.at < cutoffMs) { sessionCancelled.delete(k); sessionWouldCancel.delete(k); }
}

// Older apps read these keys; they are constant placeholders and carry
// nothing. The terms travel only inside encrypted_exchange.
const PROPOSAL_PLACEHOLDERS = { value: 0, direction: '', description: '', category: '', duration: 0 };

function partnerView(row) {
  return {
    fingerprint: row[0],
    public_key: row[1] ? JSON.parse(row[1]) : null,
    encrypted_snapshot: row[2] || null,
    session_key: row[3] ? JSON.parse(row[3]) : null,
    session_sig: row[4] || null,
    session_commit: row[5] || null,
  };
}
const PARTNER_COLS = 'fingerprint, public_key, encrypted_snapshot, session_key, session_sig, session_commit';
// v2.12.0: the mark (outside scrutiny finding 1, batch three). A phone may join with a
// commitment (a hash of its session key) instead of the key, and reveal the key only once
// the other side has joined too. Both are public key material on the allowlist; the
// witness checks shape only and keeps nothing else.
function validCommit(c) { return typeof c === 'string' && /^[0-9a-f]{64}$/.test(c); }
function validSessionKeyShape(k) { return k && typeof k === 'object' && typeof k.x === 'string' && typeof k.y === 'string' && k.x.length <= 64 && k.y.length <= 64; }

// v2.11.0: joins are rate limited per address, in memory only, nothing written
// or logged. A 4-letter code has 456,976 values; this makes guessing one an
// open session's code impractical from one address. Honest phones join once
// per session.
const JOIN_WINDOW_MS = 10 * 60 * 1000, JOIN_MAX = 60;
const joinHits = new Map();
function clientAddr(req) {
  const xf = req.headers['x-forwarded-for'];
  const a = (xf ? String(xf).split(',')[0].trim() : (req.ip || (req.socket && req.socket.remoteAddress) || '')).replace(/^::ffff:/, '');
  return a || 'unknown';
}
function joinAllowed(req) {
  const now = Date.now(), a = clientAddr(req);
  const hits = (joinHits.get(a) || []).filter(t => now - t < JOIN_WINDOW_MS);
  if (hits.length >= JOIN_MAX) { joinHits.set(a, hits); return false; }
  hits.push(now); joinHits.set(a, hits);
  if (joinHits.size > 10000) for (const [k, v] of joinHits) if (!v.length || now - v[v.length - 1] > JOIN_WINDOW_MS) joinHits.delete(k);
  return true;
}

// --- POST /session/join ---
// Phone joins a session with its code, its partner's code and its key.
// v2.10.0: no plaintext snapshot and no role on the join; anything the
// other phone needs travels in the encrypted snapshot.
app.post('/session/join', allow(['my_code', 'their_code', 'fingerprint', 'public_key', 'session_key', 'session_sig', 'session_commit']), (req, res) => {
  try {
    const { my_code, their_code, fingerprint, public_key, session_key, session_sig, session_commit } = req.body;

    if (!my_code || !their_code || !fingerprint || !public_key) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!joinAllowed(req)) return res.status(429).json({ error: 'Too many joins. Wait a few minutes.' });
    if (session_key && (typeof session_key !== 'object' || typeof session_key.x !== 'string' || typeof session_key.y !== 'string' || session_key.x.length > 64 || session_key.y.length > 64)) {
      return res.status(400).json({ error: 'Invalid session key' });
    }
    if (session_sig && (typeof session_sig !== 'string' || session_sig.length > 256)) {
      return res.status(400).json({ error: 'Invalid session signature' });
    }
    if (session_commit && !validCommit(session_commit)) {
      return res.status(400).json({ error: 'Invalid session commitment' });
    }
    if (!validSessionCode(my_code) || !validSessionCode(their_code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }
    if (my_code === their_code) {
      return res.status(400).json({ error: 'Codes must be different' });
    }

    const now = Math.floor(Date.now() / 1000);
    touchSession(my_code);

    const existing = db.exec('SELECT my_code FROM sessions WHERE my_code = ?', [my_code]);
    if (existing.length === 0 || existing[0].values.length === 0) {
      db.run(
        'INSERT INTO sessions (my_code, their_code, fingerprint, public_key, created_at, session_key, session_sig, session_commit) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [my_code, their_code, fingerprint, JSON.stringify(public_key), now, session_key ? JSON.stringify({ kty: session_key.kty || 'EC', crv: session_key.crv || 'P-256', x: session_key.x, y: session_key.y }) : null, session_sig || null, session_commit || null]
      );
      console.log(`[session] Joined: ${my_code} -> ${their_code}`);
      saveDatabase();
    }

    const partner = db.exec(
      'SELECT ' + PARTNER_COLS + ' FROM sessions WHERE my_code = ? AND their_code = ?',
      [their_code, my_code]
    );
    if (partner.length > 0 && partner[0].values.length > 0) {
      console.log(`[session] Connected: ${my_code} <-> ${their_code}`);
      return res.json({ joined: true, connected: true, partner: partnerView(partner[0].values[0]) });
    }
    res.json({ joined: true, connected: false });
  } catch (e) {
    console.error('[session] JOIN error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /session/reveal ---
// v2.12.0: the key behind a commitment, once both sides have joined. Refused before the
// partner's row exists (so neither phone can be made to reveal first) and after a key is
// already on the row (a commitment is kept once). The phones check hash(key) against
// the commitment themselves; the witness only carries it.
app.post('/session/reveal', allow(['my_code', 'session_key', 'session_sig']), (req, res) => {
  try {
    const { my_code, session_key, session_sig } = req.body;
    if (!validSessionCode(my_code) || !validSessionKeyShape(session_key) || typeof session_sig !== 'string' || session_sig.length > 256) {
      return res.status(400).json({ error: 'Invalid reveal' });
    }
    const me = db.exec('SELECT their_code, session_commit, session_key FROM sessions WHERE my_code = ?', [my_code]);
    if (me.length === 0 || me[0].values.length === 0) return res.json({ revealed: false, waiting: true });
    const [theirCode, commit, existingKey] = me[0].values[0];
    if (!commit) return res.status(400).json({ error: 'No commitment on this session' });
    if (existingKey) return res.json({ revealed: true });
    const partner = db.exec('SELECT my_code FROM sessions WHERE my_code = ? AND their_code = ?', [theirCode, my_code]);
    if (partner.length === 0 || partner[0].values.length === 0) return res.json({ revealed: false, waiting: true });
    db.run('UPDATE sessions SET session_key = ?, session_sig = ? WHERE my_code = ?',
      [JSON.stringify({ kty: session_key.kty || 'EC', crv: session_key.crv || 'P-256', x: session_key.x, y: session_key.y }), session_sig, my_code]);
    touchSession(my_code);
    saveDatabase();
    console.log(`[session] Revealed: ${my_code}`);
    res.json({ revealed: true });
  } catch (e) {
    console.error('[session] REVEAL error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- GET /session/:code ---
// Phone polls for session state: connected? sealed snapshot? proposal?
app.get('/session/:code', (req, res) => {
  try {
    const { code } = req.params;
    if (!validSessionCode(code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }

    const me = db.exec('SELECT their_code FROM sessions WHERE my_code = ?', [code]);
    if (me.length === 0 || me[0].values.length === 0) {
      // v2.11.0: an unknown code answers like an open one still waiting, so this
      // endpoint cannot be used to find open sessions by trying codes.
      return res.json({ found: true, connected: false });
    }
    const theirCode = me[0].values[0][0];
    touchSession(code);

    const partner = db.exec(
      'SELECT ' + PARTNER_COLS + ' FROM sessions WHERE my_code = ? AND their_code = ?',
      [theirCode, code]
    );
    const connected = partner.length > 0 && partner[0].values.length > 0;
    const result = { found: true, connected };
    if (connected) result.partner = partnerView(partner[0].values[0]);

    const sKey = sessionKey(code, theirCode);
    const proposal = db.exec(
      'SELECT proposer_code, status, encrypted_exchange, device_ts, confirmer_device_ts, act_hash, proposer_act_sig, confirmer_act_sig FROM session_proposals WHERE session_key = ?',
      [sKey]
    );
    if (proposal.length > 0 && proposal[0].values.length > 0) {
      const pr = proposal[0].values[0];
      result.proposal = Object.assign({}, PROPOSAL_PLACEHOLDERS, {
        proposer_code: pr[0],
        status: pr[1],
        encrypted_exchange: pr[2] || '',
        device_ts: pr[3] || null,
        confirmer_device_ts: pr[4] || null,
        act_hash: pr[5] || '',
        proposer_act_sig: pr[6] || '',
        confirmer_act_sig: pr[7] || '',
      });
    }

    // Presence and cancel (v2.7.0). In memory only; older apps ignore them.
    if (connected) {
      const pres = sessionPresence(theirCode);
      result.partner_present = pres.present;
      result.partner_seen_s = pres.seen_s;
      const settled = result.proposal && result.proposal.status === 'confirmed';
      if (!pres.present && pres.seen_s !== null && !settled && !sessionCancelled.has(sKey)) {
        if (SESSION_AUTOCANCEL) {
          markSessionCancelled(sKey, theirCode, 'disconnected');
          if (result.proposal && result.proposal.status === 'pending') result.proposal.status = 'cancelled';
        } else if (!sessionWouldCancel.has(sKey)) {
          sessionWouldCancel.add(sKey);
          console.log(`[session] Would cancel (observe only): ${sKey}, ${theirCode} silent ${pres.seen_s}s`);
        }
      }
    }
    const cx = sessionCancelled.get(sKey);
    if (cx) result.cancelled = { by_me: cx.by === code, reason: cx.reason };

    res.json(result);
  } catch (e) {
    console.error('[session] GET error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /session/:code/thread ---
// Push or update this phone's sealed snapshot. v2.10.0: encrypted only.
app.post('/session/:code/thread', allow(['encrypted_snapshot']), (req, res) => {
  try {
    const { code } = req.params;
    const { encrypted_snapshot } = req.body;
    if (!validSessionCode(code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }
    if (!encrypted_snapshot || typeof encrypted_snapshot !== 'string') {
      return res.status(400).json({ error: 'Missing encrypted_snapshot (plaintext snapshots are refused)' });
    }
    const existing = db.exec('SELECT my_code FROM sessions WHERE my_code = ?', [code]);
    if (existing.length === 0 || existing[0].values.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }
    touchSession(code);
    db.run('UPDATE sessions SET encrypted_snapshot = ? WHERE my_code = ?', [encrypted_snapshot, code]);
    saveDatabase();
    console.log(`[session] Sealed snapshot updated: ${code}`);
    res.json({ updated: true });
  } catch (e) {
    console.error('[session] THREAD error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /session/:code/propose ---
// One phone submits the sealed proposal. v2.10.0: encrypted_exchange is
// required; an unsealed proposal is refused. The act hash and the
// proposer's signature over it ride beside the sealed packet.
app.post('/session/:code/propose', allow(['encrypted_exchange', 'act_hash', 'act_sig', 'device_ts']), (req, res) => {
  try {
    const { code } = req.params;
    const { encrypted_exchange, act_hash, act_sig, device_ts } = req.body;

    if (!validSessionCode(code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }
    if (!encrypted_exchange || typeof encrypted_exchange !== 'string') {
      return res.status(400).json({ error: 'unsealed', reason: 'A proposal must be sealed (encrypted_exchange)' });
    }
    if (act_hash && !/^[a-f0-9]{64}$/i.test(act_hash)) {
      return res.status(400).json({ error: 'Invalid act_hash format' });
    }

    const me = db.exec('SELECT their_code, fingerprint FROM sessions WHERE my_code = ?', [code]);
    if (me.length === 0 || me[0].values.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }
    const theirCode = me[0].values[0][0];
    const myFp = me[0].values[0][1];

    const partner = db.exec('SELECT my_code, fingerprint FROM sessions WHERE my_code = ? AND their_code = ?', [theirCode, code]);
    if (partner.length === 0 || partner[0].values.length === 0) {
      return res.status(409).json({ error: 'Session not yet connected. Partner has not joined' });
    }
    // Same-owner rule (v2.9.0, protocol): a chain cannot exchange with itself.
    if (myFp && partner[0].values[0][1] && myFp === partner[0].values[0][1]) {
      console.log(`[session] Refused proposal ${code}: both sides are the same chain`);
      return res.status(409).json({ error: 'same_chain', reason: 'A chain cannot exchange with itself' });
    }

    const sKey = sessionKey(code, theirCode);
    const now = Math.floor(Date.now() / 1000);
    touchSession(code);
    if (sessionCancelled.has(sKey)) {
      return res.status(409).json({ error: 'Session cancelled' });
    }

    const existing = db.exec('SELECT status FROM session_proposals WHERE session_key = ?', [sKey]);
    if (existing.length > 0 && existing[0].values.length > 0) {
      if (existing[0].values[0][0] === 'confirmed') {
        return res.status(409).json({ error: 'Proposal already confirmed' });
      }
      db.run('DELETE FROM session_proposals WHERE session_key = ?', [sKey]); // re-proposal overwrites
    }

    db.run(
      `INSERT INTO session_proposals (session_key, proposer_code, status, encrypted_exchange, act_hash, proposer_act_sig, device_ts, created_at)
       VALUES (?, ?, 'pending', ?, ?, ?, ?, ?)`,
      [sKey, code, encrypted_exchange, act_hash || '', act_sig || '', Number.isFinite(device_ts) ? device_ts : null, now]
    );
    saveDatabase();
    console.log(`[session] Sealed proposal: ${code} in session ${sKey}`);
    res.json({ proposed: true, session_key: sKey });
  } catch (e) {
    console.error('[session] PROPOSE error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /session/:code/cancel ---
// Either person ends the exchange for both (DESIGN 2b). Nothing is
// recorded. reason is 'cancelled' (default) or 'disconnected'.
app.post('/session/:code/cancel', allow(['reason']), (req, res) => {
  try {
    const { code } = req.params;
    const reason = (req.body || {}).reason;
    if (!validSessionCode(code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }
    if (!validCancelReason(reason)) {
      return res.status(400).json({ error: 'Invalid reason' });
    }
    const me = db.exec('SELECT their_code FROM sessions WHERE my_code = ?', [code]);
    if (me.length === 0 || me[0].values.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }
    const theirCode = me[0].values[0][0];
    const sKey = sessionKey(code, theirCode);
    touchSession(code);
    const st = db.exec('SELECT status FROM session_proposals WHERE session_key = ?', [sKey]);
    if (st.length > 0 && st[0].values.length > 0 && st[0].values[0][0] === 'confirmed') {
      return res.status(409).json({ error: 'Proposal already confirmed' });
    }
    const c = markSessionCancelled(sKey, code, reason);
    res.json({ cancelled: true, by_me: c.by === code, reason: c.reason });
  } catch (e) {
    console.error('[session] CANCEL error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /session/:code/confirm ---
// The other phone confirms (or rejects) the sealed proposal.
app.post('/session/:code/confirm', allow(['confirmed', 'act_sig', 'device_ts']), (req, res) => {
  try {
    const { code } = req.params;
    const { act_sig: confirmerActSig, confirmed, device_ts: confirmerDeviceTs } = req.body;

    if (!validSessionCode(code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }
    if (confirmed === undefined) {
      return res.status(400).json({ error: 'Missing confirmed field' });
    }

    const me = db.exec('SELECT their_code FROM sessions WHERE my_code = ?', [code]);
    if (me.length === 0 || me[0].values.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }
    const theirCode = me[0].values[0][0];
    const sKey = sessionKey(code, theirCode);
    touchSession(code);

    const proposal = db.exec(
      'SELECT proposer_code, status, encrypted_exchange, device_ts, act_hash, proposer_act_sig FROM session_proposals WHERE session_key = ?',
      [sKey]
    );
    if (proposal.length === 0 || proposal[0].values.length === 0) {
      return res.status(404).json({ error: 'No proposal found' });
    }
    const pr = proposal[0].values[0];
    if (pr[0] === code) {
      return res.status(400).json({ error: 'Cannot confirm your own proposal' });
    }
    if (pr[1] !== 'pending') {
      return res.status(409).json({ error: 'Proposal already ' + pr[1] });
    }

    const now = Math.floor(Date.now() / 1000);
    const newStatus = confirmed ? 'confirmed' : 'rejected';
    db.run(
      'UPDATE session_proposals SET status = ?, confirmer_device_ts = ?, confirmer_act_sig = ?, resolved_at = ? WHERE session_key = ?',
      [newStatus, Number.isFinite(confirmerDeviceTs) ? confirmerDeviceTs : null, (confirmed && confirmerActSig) ? confirmerActSig : '', now, sKey]
    );
    saveDatabase();
    console.log(`[session] Proposal ${newStatus}: ${sKey}`);

    if (!confirmed) {
      return res.json({ confirmed: false, status: 'rejected' });
    }

    // Confirmed: return what both phones need to write their chains.
    const proposerData = db.exec('SELECT fingerprint, public_key FROM sessions WHERE my_code = ?', [theirCode])[0].values[0];
    const confirmerData = db.exec('SELECT fingerprint, public_key FROM sessions WHERE my_code = ?', [code])[0].values[0];

    res.json({
      confirmed: true,
      status: 'confirmed',
      proposal: Object.assign({}, PROPOSAL_PLACEHOLDERS, {
        device_ts: pr[3] || null,
        encrypted_exchange: pr[2] || '',
        act_hash: pr[4] || '',
        proposer_act_sig: pr[5] || '',
        confirmer_act_sig: confirmerActSig || '',
      }),
      proposer: {
        code: theirCode,
        fingerprint: proposerData[0],
        public_key: JSON.parse(proposerData[1]),
        act_sig: pr[5] || '',
      },
      confirmer: {
        code: code,
        fingerprint: confirmerData[0],
        public_key: JSON.parse(confirmerData[1]),
      },
    });
  } catch (e) {
    console.error('[session] CONFIRM error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// === INVITE PIPES ===
// Code-introduction layer on top of sessions (writing/invite-pipeline.md
// in hep-project-state). The QR carries the pipe, never the exchange.
// Lifecycle: open -> (claimed when cap reached) -> closed/expired.
// Security model: pipe closure and claim-binding are hygiene against
// forwarded/photographed QRs; the inviter's per-record signature in the
// normal session flow is the security. Redemption mints nothing.

// Pipe codes are client-generated, 10 chars from the language-proof
// charset (no O/I/L/S/B). Longer than session codes because a pipe is
// semi-public (displayed in a room) and lives up to 24 hours.
function validPipeCode(code) {
  return typeof code === 'string' && /^[ACDEFGHJKMNPQRTUVWXYZ]{10}$/.test(code);
}

// Display names ride in the pipe so the redeemer's accept flow can show
// who opened it. Bounded to keep rows small; empty/absent is fine.
function validPipeName(name) {
  return name === undefined || name === null ||
    (typeof name === 'string' && name.length <= 80);
}

// Shape validators (pure, exported for tests).
function validatePipeCreateShape(body) {
  if (!body || typeof body !== 'object') return 'not an object';
  if (!validPipeCode(body.pipe_code)) return 'invalid pipe_code';
  if (typeof body.fingerprint !== 'string' || !body.fingerprint) return 'missing fingerprint';
  if (body.public_key === undefined || body.public_key === null) return 'missing public_key';
  if (!validPipeName(body.name)) return 'invalid name';
  const cap = body.max_redemptions;
  if (cap !== undefined && (!Number.isInteger(cap) || cap < 0 || cap > 500)) return 'invalid max_redemptions';
  return null;
}

function validatePipeRedeemShape(body) {
  if (!body || typeof body !== 'object') return 'not an object';
  if (typeof body.redeemer_code !== 'string' || !/^[A-Z]{4}$/.test(body.redeemer_code)) return 'invalid redeemer_code';
  if (typeof body.fingerprint !== 'string' || !body.fingerprint) return 'missing fingerprint';
  if (body.public_key === undefined || body.public_key === null) return 'missing public_key';
  if (!validPipeName(body.name)) return 'invalid name';
  return null;
}

// Server-generated owner-side session code for one pairing. Same
// 4-char language-proof charset the app uses. Uniqueness is checked
// against live sessions and pending redemptions by the caller.
const PIPE_PAIR_CHARS = 'ACDEFGHJKMNPQRTUVWXYZ';
function generateOwnerCode() {
  const bytes = crypto.randomBytes(4);
  let out = '';
  for (let i = 0; i < 4; i++) out += PIPE_PAIR_CHARS[bytes[i] % PIPE_PAIR_CHARS.length];
  return out;
}

function uniqueOwnerCode() {
  for (let attempt = 0; attempt < 20; attempt++) {
    const code = generateOwnerCode();
    const inSessions = db.exec('SELECT my_code FROM sessions WHERE my_code = ? OR their_code = ?', [code, code]);
    const inRedemptions = db.exec('SELECT owner_code FROM pipe_redemptions WHERE owner_code = ? OR redeemer_code = ?', [code, code]);
    const taken = (inSessions.length > 0 && inSessions[0].values.length > 0) ||
      (inRedemptions.length > 0 && inRedemptions[0].values.length > 0);
    if (!taken) return code;
  }
  return null; // astronomically unlikely with a healthy table
}

// --- POST /pipe ---
// Inviter opens a pipe. Body: { pipe_code, fingerprint, public_key,
// name?, max_redemptions? } (1 = single invite, 0 = uncapped room).
app.post('/pipe', allow(['pipe_code', 'fingerprint', 'public_key', 'max_redemptions']), (req, res) => {
  try {
    const shapeError = validatePipeCreateShape(req.body);
    if (shapeError) return res.status(400).json({ error: shapeError });

    const { pipe_code, fingerprint, public_key } = req.body;
    const cap = req.body.max_redemptions === undefined ? 1 : req.body.max_redemptions;
    const now = Math.floor(Date.now() / 1000);

    const existing = db.exec('SELECT owner_fingerprint FROM pipes WHERE pipe_code = ?', [pipe_code]);
    if (existing.length > 0 && existing[0].values.length > 0) {
      // Idempotent re-create by the same owner; collision by anyone else.
      if (existing[0].values[0][0] === fingerprint) return res.json({ created: true, pipe_code });
      return res.status(409).json({ error: 'Pipe code in use' });
    }

    db.run(
      'INSERT INTO pipes (pipe_code, owner_fingerprint, owner_public_key, max_redemptions, redemption_count, closed, created_at) VALUES (?, ?, ?, ?, 0, 0, ?)',
      [pipe_code, fingerprint, JSON.stringify(public_key), cap, now]
    );
    saveDatabase();
    console.log(`[pipe] Opened: ${pipe_code} (cap ${cap === 0 ? 'uncapped' : cap})`);
    res.json({ created: true, pipe_code });
  } catch (e) {
    console.error('[pipe] CREATE error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /pipe/:code/redeem ---
// Scanner redeems the pipe with a freshly generated session code.
// Response introduces the owner and a server-generated owner-side
// session code for this pairing, so the redeemer can immediately
// join the normal session machinery. Idempotent per redeemer.
app.post('/pipe/:code/redeem', allow(['redeemer_code', 'fingerprint', 'public_key']), (req, res) => {
  try {
    const pipeCode = req.params.code;
    if (!validPipeCode(pipeCode)) return res.status(400).json({ error: 'Invalid pipe code' });
    const shapeError = validatePipeRedeemShape(req.body);
    if (shapeError) return res.status(400).json({ error: shapeError });

    const { redeemer_code, fingerprint, public_key } = req.body;

    const pipeRows = db.exec(
      'SELECT owner_fingerprint, owner_public_key, max_redemptions, redemption_count, closed, created_at FROM pipes WHERE pipe_code = ?',
      [pipeCode]
    );
    if (pipeRows.length === 0 || pipeRows[0].values.length === 0) {
      return res.status(404).json({ accepted: false, reason: 'not_found' });
    }
    const [ownerFp, ownerKey, cap, count, closed, createdAt] = pipeRows[0].values[0];
    // Same-owner rule (v2.9.0): redeeming a pipe your own chain opened.
    if (ownerFp && fingerprint === ownerFp) {
      return res.json({ accepted: false, reason: 'same_chain' });
    }

    const now = Math.floor(Date.now() / 1000);
    if (now - createdAt > PIPE_RETENTION_HOURS * 60 * 60) {
      return res.json({ accepted: false, reason: 'expired' });
    }
    if (closed) return res.json({ accepted: false, reason: 'closed' });

    // Idempotent retry: same redeemer, same answer.
    const prior = db.exec(
      'SELECT owner_code FROM pipe_redemptions WHERE pipe_code = ? AND redeemer_fingerprint = ?',
      [pipeCode, fingerprint]
    );
    if (prior.length > 0 && prior[0].values.length > 0) {
      return res.json({
        accepted: true,
        owner_code: prior[0].values[0][0],
        owner: { public_key: ownerKey ? JSON.parse(ownerKey) : null, fingerprint: ownerFp },
      });
    }

    if (cap !== 0 && count >= cap) {
      return res.json({ accepted: false, reason: 'claimed' });
    }

    const ownerCode = uniqueOwnerCode();
    if (!ownerCode) return res.status(500).json({ error: 'Could not allocate code' });

    db.run(
      'INSERT INTO pipe_redemptions (pipe_code, redeemer_code, owner_code, redeemer_fingerprint, redeemer_public_key, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [pipeCode, redeemer_code, ownerCode, fingerprint, JSON.stringify(public_key), now]
    );
    db.run('UPDATE pipes SET redemption_count = redemption_count + 1 WHERE pipe_code = ?', [pipeCode]);
    saveDatabase();
    console.log(`[pipe] Redeemed: ${pipeCode} (${count + 1}${cap === 0 ? '' : '/' + cap})`);

    res.json({
      accepted: true,
      owner_code: ownerCode,
      owner: { public_key: ownerKey ? JSON.parse(ownerKey) : null, fingerprint: ownerFp },
    });
  } catch (e) {
    console.error('[pipe] REDEEM error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /pipe/:code/owner (v2.10.0), GET /pipe/:code/owner (older apps) ---
// Inviter polls for redemptions. Requires the owner fingerprint so a
// bystander who can see the QR cannot enumerate who redeemed. v2.10.0
// moves the fingerprint into a POST body so it stays out of URLs and
// access logs; the GET form stays for production v2.99.3 until it is
// promoted past, then goes.
function pipeOwnerPoll(req, res, fingerprint) {
  try {
    const pipeCode = req.params.code;
    if (!validPipeCode(pipeCode)) return res.status(400).json({ error: 'Invalid pipe code' });
    if (!fingerprint || typeof fingerprint !== 'string') return res.status(400).json({ error: 'Missing fingerprint' });

    const pipeRows = db.exec(
      'SELECT owner_fingerprint, max_redemptions, redemption_count, closed FROM pipes WHERE pipe_code = ?',
      [pipeCode]
    );
    if (pipeRows.length === 0 || pipeRows[0].values.length === 0) {
      return res.status(404).json({ found: false });
    }
    const [ownerFp, cap, count, closed] = pipeRows[0].values[0];
    if (ownerFp !== fingerprint) return res.status(403).json({ error: 'Not the pipe owner' });

    const rows = db.exec(
      'SELECT redeemer_code, owner_code, redeemer_fingerprint, redeemer_public_key, created_at FROM pipe_redemptions WHERE pipe_code = ? ORDER BY created_at ASC',
      [pipeCode]
    );
    const redemptions = (rows.length > 0 ? rows[0].values : []).map(r => ({
      redeemer_code: r[0],
      owner_code: r[1],
      fingerprint: r[2],
      public_key: r[3] ? JSON.parse(r[3]) : null,
      created_at: r[4],
    }));
    res.json({ found: true, closed: !!closed, max_redemptions: cap, redemption_count: count, redemptions });
  } catch (e) {
    console.error('[pipe] OWNER POLL error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
}
app.post('/pipe/:code/owner', allow(['fingerprint']), (req, res) => pipeOwnerPoll(req, res, req.body.fingerprint));
app.get('/pipe/:code/owner', (req, res) => pipeOwnerPoll(req, res, req.query.fingerprint));

// --- POST /pipe/:code/close ---
// Inviter closes the pipe. Redemptions already made stay valid; their
// sessions proceed normally.
app.post('/pipe/:code/close', allow(['fingerprint']), (req, res) => {
  try {
    const pipeCode = req.params.code;
    if (!validPipeCode(pipeCode)) return res.status(400).json({ error: 'Invalid pipe code' });
    const { fingerprint } = req.body || {};
    if (!fingerprint) return res.status(400).json({ error: 'Missing fingerprint' });

    const pipeRows = db.exec('SELECT owner_fingerprint FROM pipes WHERE pipe_code = ?', [pipeCode]);
    if (pipeRows.length === 0 || pipeRows[0].values.length === 0) {
      return res.status(404).json({ found: false });
    }
    if (pipeRows[0].values[0][0] !== fingerprint) return res.status(403).json({ error: 'Not the pipe owner' });

    db.run('UPDATE pipes SET closed = 1 WHERE pipe_code = ?', [pipeCode]);
    saveDatabase();
    console.log(`[pipe] Closed: ${pipeCode}`);
    res.json({ closed: true });
  } catch (e) {
    console.error('[pipe] CLOSE error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- 404 handler ---
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// === START SERVER ===

async function start() {
  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log('  ║   Human Exchange Protocol            ║');
  console.log('  ║   Witness Server v' + VERSION + '              ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');

  serverKeys = loadOrCreateKeys();
  serverState = loadOrCreateState();
  await initDatabase();

  // Register self in peers table
  if (SELF_URL) {
    const now = Math.floor(Date.now() / 1000);
    const selfClean = SELF_URL.replace(/\/+$/, '');
    db.run('DELETE FROM peers WHERE url = ?', [selfClean]);
    db.run(
      'INSERT INTO peers (url, pubkey, version, witnessed_count, last_heartbeat, added_at) VALUES (?, ?, ?, ?, ?, ?)',
      [selfClean, serverKeys.publicKeyHex, VERSION, 0, now, now]
    );
    saveDatabase();
    console.log(`[gossip] Self-registered as: ${selfClean}`);
  } else {
    console.log('[gossip] No HCP_URL set, server will accept announces but cannot gossip');
  }

  // Add seed peers
  if (SEED_PEERS.length > 0) {
    console.log(`[gossip] Seed peers: ${SEED_PEERS.join(', ')}`);
  }

  // Scheduled cleanup
  setInterval(runCleanup, CLEANUP_INTERVAL_MS);
  console.log(`[cleanup] Scheduled every ${CLEANUP_INTERVAL_MS / 60000} minutes`);

  // Periodic database save
  setInterval(saveDatabase, DB_SAVE_INTERVAL_MS);

  // Periodic heartbeat to all peers. Runs if either legacy
  // self-identification (SELF_URL) or signed self-identification
  // (SELF_HOST) is configured. Per-peer mode dispatch happens inside
  // heartbeat() via selectAnnounceMode.
  if (SELF_URL || SELF_HOST) {
    setInterval(heartbeat, HEARTBEAT_INTERVAL_MS);
    const intervalDisplay = HEARTBEAT_INTERVAL_MS >= 60000
      ? `${HEARTBEAT_INTERVAL_MS / 60000} minutes`
      : `${HEARTBEAT_INTERVAL_MS} ms`;
    console.log(`[gossip] Heartbeat every ${intervalDisplay}`);
  }

  app.listen(PORT, () => {
    console.log(`[server] Listening on port ${PORT}`);
    console.log(`[server] Endpoints:`);
    console.log(`         POST /witness     submit mint for attestation`);
    console.log(`         POST /ping        heartbeat attestation (signs head_hash; stores nothing)`);
    console.log(`         PUT  /relay/:id   deposit settlement`);
    console.log(`         GET  /relay/:id   retrieve settlement`);
    console.log(`         POST /session/join     join a session`);
    console.log(`         GET  /session/:code    poll session state`);
    console.log(`         POST /session/:code/thread  push thread snapshot`);
    console.log(`         POST /session/:code/propose submit proposal`);
    console.log(`         POST /session/:code/confirm confirm proposal`);
    console.log(`         POST /session/:code/cancel  end the exchange for both`);
    console.log(`         session auto-cancel on silence: ${SESSION_AUTOCANCEL ? 'ON' : 'off (observe only)'}`);
    console.log(`         POST /announce    register a server`);
    console.log(`         GET  /peers       list active servers`);
    console.log(`         POST /update      signed self-update broadcast`);
    console.log(`         GET  /status      health check`);
    console.log(`         GET  /stats       version, uptime, peer count`);
    console.log(`         request allowlist: on (unlisted fields dropped before writing)`);
    console.log('');

    // Initial heartbeat after startup (give server 2 seconds to settle).
    // v2.13.2: a new witness knows no peer pubkeys yet, so its first
    // heartbeat goes out legacy; the replies teach it the keys, but only
    // a signed announce gets it into a peer's signed /peers list, and the
    // next regular heartbeat is HEARTBEAT_INTERVAL_MS away (15 min). So
    // when the first heartbeat sent anything legacy, send one follow-up
    // 30 s later, which is signed for every peer whose key arrived.
    // Timing only: nothing new is sent or stored.
    if (SELF_URL) {
      setTimeout(async () => {
        const first = await heartbeat().catch(() => null);
        if (first && first.legacy > 0) {
          console.log('[gossip] First heartbeat was partly legacy; a signed follow-up goes out in 30 s');
          setTimeout(() => heartbeat().catch(() => {}), 30 * 1000);
        }
      }, 2000);
    }
  });
}

if (require.main === module) {
  start().catch(e => {
    console.error('Fatal:', e);
    process.exit(1);
  });
}

// Pure helpers exported for test scripts. Module state (serverKeys,
// serverState, db) is not exported and is undefined unless start() ran.
module.exports = {
  canonicalize,
  signPayload,
  verifyPayload,
  isSignedAnnounce,
  validateSignedAnnounceShape,
  isSignedSelfUpdate,
  validateSignedSelfUpdateShape,
  selectAnnounceMode,
  validPipeCode,
  validPipeName,
  validatePipeCreateShape,
  validatePipeRedeemShape,
  generateOwnerCode,
};
