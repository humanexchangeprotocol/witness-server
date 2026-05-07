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
const MINT_RETENTION_DAYS = 30;
const RELAY_RETENTION_HOURS = 72;
const PAIR_RETENTION_DAYS = 7;
const SESSION_RETENTION_HOURS = 24; // Sessions are ephemeral, 24 hour max
const CLEANUP_INTERVAL_MS = 15 * 60 * 1000; // 15 minutes
const DB_SAVE_INTERVAL_MS = 60 * 1000; // 1 minute
const HEARTBEAT_INTERVAL_MS = 15 * 60 * 1000; // 15 minutes
const PEER_STALE_HOURS = 24;
const SELF_URL = process.env.HCP_URL || null; // This server's public URL
const SEED_PEERS = (process.env.HCP_SEEDS || '').split(',').map(s => s.trim()).filter(Boolean);
const VERSION = '2.3.1';

let db = null;
let serverKeys = null;
let serverState = null;
let startTime = Date.now();
let witnessedCount = 0;
let pohPingCount = 0;

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
  fs.writeFileSync(STATE_PATH, JSON.stringify(serverState, null, 2));
}

function nextSequence() {
  serverState.sequence += 1;
  persistState();
  return serverState.sequence;
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

  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS witnessed_mints (
      mint_hash TEXT PRIMARY KEY,
      pubkey_a TEXT NOT NULL,
      pubkey_b TEXT NOT NULL,
      device_ts INTEGER NOT NULL,
      server_ts INTEGER NOT NULL,
      server_sig TEXT NOT NULL,
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

  db.run(`
    CREATE TABLE IF NOT EXISTS pair_halves (
      my_code TEXT PRIMARY KEY,
      their_code TEXT NOT NULL,
      value REAL NOT NULL,
      direction TEXT NOT NULL,
      description TEXT,
      category TEXT,
      duration INTEGER DEFAULT 0,
      fingerprint TEXT NOT NULL,
      public_key TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      resolved INTEGER DEFAULT 0,
      resolve_status TEXT,
      counterparty_fp TEXT,
      counterparty_key TEXT,
      counterparty_desc TEXT
    )
  `);

  // Session tables. Ephemeral pipe for thread sharing + single-sided proposals
  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      my_code TEXT PRIMARY KEY,
      their_code TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      public_key TEXT NOT NULL,
      thread_snapshot TEXT,
      created_at INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS session_proposals (
      session_key TEXT PRIMARY KEY,
      proposer_code TEXT NOT NULL,
      value REAL NOT NULL,
      direction TEXT NOT NULL,
      description TEXT,
      category TEXT,
      duration INTEGER DEFAULT 0,
      status TEXT DEFAULT 'pending',
      confirmer_desc TEXT,
      created_at INTEGER NOT NULL,
      resolved_at INTEGER
    )
  `);

  // Create indexes for cleanup queries
  db.run('CREATE INDEX IF NOT EXISTS idx_mints_created ON witnessed_mints(created_at)');
  db.run('CREATE INDEX IF NOT EXISTS idx_relay_created ON settlement_relay(created_at)');
  db.run('CREATE INDEX IF NOT EXISTS idx_peers_heartbeat ON peers(last_heartbeat)');
  db.run('CREATE INDEX IF NOT EXISTS idx_pairs_created ON pair_halves(created_at)');
  db.run('CREATE INDEX IF NOT EXISTS idx_pairs_their_code ON pair_halves(their_code)');
  db.run('CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at)');
  db.run('CREATE INDEX IF NOT EXISTS idx_sessions_their ON sessions(their_code)');
  db.run('CREATE INDEX IF NOT EXISTS idx_session_proposals_created ON session_proposals(created_at)');

  // Add device_ts columns for clock skew measurement (v2.2.1+)
  try { db.run('ALTER TABLE session_proposals ADD COLUMN device_ts INTEGER'); } catch(e) {}
  try { db.run('ALTER TABLE session_proposals ADD COLUMN confirmer_device_ts INTEGER'); } catch(e) {}
  // Add device_ts to pair_halves for future clock skew on QR exchanges
  try { db.run('ALTER TABLE pair_halves ADD COLUMN device_ts INTEGER'); } catch(e) {}

  // Cross-device sensor hash for proof-of-human (v2.2.2+)
  try { db.run('ALTER TABLE session_proposals ADD COLUMN sensor_hash TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE session_proposals ADD COLUMN platform TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE session_proposals ADD COLUMN confirmer_sensor_hash TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE session_proposals ADD COLUMN confirmer_platform TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE session_proposals ADD COLUMN geo TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE session_proposals ADD COLUMN confirmer_geo TEXT'); } catch(e) {}

  // Proof-of-Human ping table (v2.2.2+)
  db.run(`
    CREATE TABLE IF NOT EXISTS poh_pings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      chain_fingerprint TEXT NOT NULL,
      sensor_hash TEXT,
      device_ts INTEGER NOT NULL,
      server_ts INTEGER NOT NULL,
      server_sig TEXT NOT NULL,
      seq INTEGER,
      created_at INTEGER NOT NULL
    )
  `);
  db.run('CREATE INDEX IF NOT EXISTS idx_poh_pings_chain ON poh_pings(chain_fingerprint)');
  db.run('CREATE INDEX IF NOT EXISTS idx_poh_pings_created ON poh_pings(created_at)');

  // Ping challenge-response table (v2.3.0+)
  db.run(`
    CREATE TABLE IF NOT EXISTS ping_challenges (
      nonce TEXT PRIMARY KEY,
      chain_fingerprint TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )
  `);

  // Presence registry (v2.3.0+)
  db.run(`
    CREATE TABLE IF NOT EXISTS presence_registry (
      chain_fingerprint TEXT PRIMARY KEY,
      first_seen INTEGER NOT NULL,
      last_seen INTEGER NOT NULL,
      attested_ping_count INTEGER DEFAULT 0,
      witnessed_exchange_count INTEGER DEFAULT 0,
      last_device_hash TEXT
    )
  `);

  // Device hash relay for session and pair exchanges (v2.3.0+)
  try { db.run('ALTER TABLE session_proposals ADD COLUMN device_hash TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE session_proposals ADD COLUMN confirmer_device_hash TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE pair_halves ADD COLUMN device_hash TEXT'); } catch(e) {}

  // Photo relay for session exchanges (v2.3.0+)
  try { db.run('ALTER TABLE session_proposals ADD COLUMN proposer_photo TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE session_proposals ADD COLUMN confirmer_photo TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE session_proposals ADD COLUMN proposer_photo_hash TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE session_proposals ADD COLUMN confirmer_photo_hash TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE session_proposals ADD COLUMN encrypted_exchange TEXT'); } catch(e) {}

  // Option B: encrypted snapshot + role for session privacy
  try { db.run('ALTER TABLE sessions ADD COLUMN encrypted_snapshot TEXT'); } catch(e) {}
  try { db.run('ALTER TABLE sessions ADD COLUMN role TEXT'); } catch(e) {}

  // Load lifetime witness count
  const row = db.exec('SELECT COUNT(*) as c FROM witnessed_mints');
  witnessedCount = row.length > 0 ? row[0].values[0][0] : 0;
  // Also count any previously deleted (track via a counter file)
  if (fs.existsSync(path.join(__dirname, 'witness_count.txt'))) {
    witnessedCount += parseInt(fs.readFileSync(path.join(__dirname, 'witness_count.txt'), 'utf8')) || 0;
  }

  // Load ping count
  const pingRow = db.exec('SELECT COUNT(*) as c FROM poh_pings');
  pohPingCount = pingRow.length > 0 ? pingRow[0].values[0][0] : 0;

  saveDatabase();
  console.log('[db] Tables ready. Witnessed mints in DB:', row.length > 0 ? row[0].values[0][0] : 0);
}

function saveDatabase() {
  try {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
  } catch (e) {
    console.error('[db] Save error:', e.message);
  }
}

// === CLEANUP ===

function runCleanup() {
  const now = Math.floor(Date.now() / 1000);
  const mintCutoff = now - (MINT_RETENTION_DAYS * 24 * 60 * 60);
  const relayCutoff = now - (RELAY_RETENTION_HOURS * 60 * 60);
  const peerCutoff = now - (PEER_STALE_HOURS * 60 * 60);

  // Count before delete for lifetime counter
  const mintsBefore = db.exec('SELECT COUNT(*) FROM witnessed_mints WHERE created_at < ?', [mintCutoff]);
  const mintsDeleted = mintsBefore.length > 0 ? mintsBefore[0].values[0][0] : 0;

  db.run('DELETE FROM witnessed_mints WHERE created_at < ?', [mintCutoff]);
  db.run('DELETE FROM settlement_relay WHERE created_at < ?', [relayCutoff]);
  db.run('DELETE FROM poh_pings WHERE created_at < ?', [mintCutoff]);

  // Clean up old pair halves (resolved or expired)
  const pairCutoff = now - (PAIR_RETENTION_DAYS * 24 * 60 * 60);
  db.run('DELETE FROM pair_halves WHERE created_at < ?', [pairCutoff]);

  // Clean up expired sessions (ephemeral, 24 hours max)
  const sessionCutoff = now - (SESSION_RETENTION_HOURS * 60 * 60);
  const expiredSessions = db.exec('SELECT my_code FROM sessions WHERE created_at < ?', [sessionCutoff]);
  const sessionCount = expiredSessions.length > 0 ? expiredSessions[0].values.length : 0;
  db.run('DELETE FROM sessions WHERE created_at < ?', [sessionCutoff]);
  db.run('DELETE FROM session_proposals WHERE created_at < ?', [sessionCutoff]);
  // Clean up expired ping challenges (60 seconds max)
  db.run('DELETE FROM ping_challenges WHERE created_at < ?', [now - 60]);
  if (sessionCount > 0) {
    console.log(`[cleanup] Expired ${sessionCount} session halves`);
  }

  // Remove stale peers (but never remove self)
  const stalePeers = db.exec('SELECT url FROM peers WHERE last_heartbeat < ? AND url != ?', [peerCutoff, SELF_URL || '']);
  const staleCount = stalePeers.length > 0 ? stalePeers[0].values.length : 0;
  db.run('DELETE FROM peers WHERE last_heartbeat < ? AND url != ?', [peerCutoff, SELF_URL || '']);

  // Track lifetime count (deleted mints still count)
  if (mintsDeleted > 0) {
    const countFile = path.join(__dirname, 'witness_count.txt');
    const existing = fs.existsSync(countFile) ? parseInt(fs.readFileSync(countFile, 'utf8')) || 0 : 0;
    fs.writeFileSync(countFile, String(existing + mintsDeleted));
    console.log(`[cleanup] Deleted ${mintsDeleted} expired mints`);
  }
  if (staleCount > 0) {
    console.log(`[cleanup] Removed ${staleCount} stale peers`);
  }

  saveDatabase();
}

// === PRESENCE REGISTRY ===

function updatePresence(chainFingerprint, deviceHash, eventType) {
  const now = Math.floor(Date.now() / 1000);
  const existing = db.exec('SELECT first_seen, attested_ping_count, witnessed_exchange_count FROM presence_registry WHERE chain_fingerprint = ?', [chainFingerprint]);

  if (existing.length > 0 && existing[0].values.length > 0) {
    const pingInc = eventType === 'ping' ? 1 : 0;
    const witnessInc = eventType === 'witness' ? 1 : 0;
    db.run(
      'UPDATE presence_registry SET last_seen = ?, attested_ping_count = attested_ping_count + ?, witnessed_exchange_count = witnessed_exchange_count + ?, last_device_hash = ? WHERE chain_fingerprint = ?',
      [now, pingInc, witnessInc, deviceHash || '', chainFingerprint]
    );
  } else {
    db.run(
      'INSERT INTO presence_registry (chain_fingerprint, first_seen, last_seen, attested_ping_count, witnessed_exchange_count, last_device_hash) VALUES (?, ?, ?, ?, ?, ?)',
      [chainFingerprint, now, now, eventType === 'ping' ? 1 : 0, eventType === 'witness' ? 1 : 0, deviceHash || '']
    );
  }
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
app.post('/witness', (req, res) => {
  try {
    const { mint_hash, pubkey_a, pubkey_b, device_timestamp, chain_sig } = req.body;

    // Validate required fields
    if (!mint_hash || !pubkey_a || !pubkey_b || !device_timestamp || !chain_sig) {
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
    db.run(
      'INSERT INTO witnessed_mints (mint_hash, pubkey_a, pubkey_b, device_ts, server_ts, server_sig, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [mint_hash, pubkey_a, pubkey_b, device_timestamp, serverTimestamp, serverSignature, serverTimestamp]
    );

    witnessedCount++;
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
app.post('/ping/challenge', (req, res) => {
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
// Proof-of-Human genesis ping attestation
// No counterparty -- just "this chain's device pinged at this time"
app.post('/ping', (req, res) => {
  try {
    const { chain_fingerprint, sensor_hash, device_ts, seq, challenge_nonce } = req.body;

    if (!chain_fingerprint || !device_ts) {
      return res.status(400).json({ error: 'Missing required fields (chain_fingerprint, device_ts)' });
    }

    // Validate chain_fingerprint format (should be hex, 16 chars)
    if (!/^[a-f0-9]+$/i.test(chain_fingerprint)) {
      return res.status(400).json({ error: 'Invalid chain_fingerprint format' });
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
        // Delete used challenge regardless
        db.run('DELETE FROM ping_challenges WHERE nonce = ?', [challenge_nonce]);
      }
    }

    const serverTimestamp = Math.floor(Date.now() / 1000);
    const pingMessage = 'ping:' + chain_fingerprint + ':' + (sensor_hash || '') + ':' + serverTimestamp;
    const serverSignature = sign(pingMessage);

    // Store
    db.run(
      'INSERT INTO poh_pings (chain_fingerprint, sensor_hash, device_ts, server_ts, server_sig, seq, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [chain_fingerprint, sensor_hash || '', device_ts, serverTimestamp, serverSignature, seq || 0, serverTimestamp]
    );

    // Update presence registry
    updatePresence(chain_fingerprint, sensor_hash, 'ping');

    pohPingCount++;
    saveDatabase();

    console.log(`[ping] PoH attestation: chain ${chain_fingerprint.substring(0, 8)}... seq ${seq || 0} challenged=${challenged}`);

    res.json({
      chain_fingerprint,
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

// --- GET /presence/:fingerprint ---
// Return presence summary for a chain fingerprint
app.get('/presence/:fingerprint', (req, res) => {
  try {
    const { fingerprint } = req.params;
    if (!fingerprint || !/^[a-f0-9]+$/i.test(fingerprint)) {
      return res.status(400).json({ error: 'Invalid fingerprint format' });
    }

    const row = db.exec(
      'SELECT first_seen, last_seen, attested_ping_count, witnessed_exchange_count, last_device_hash FROM presence_registry WHERE chain_fingerprint = ?',
      [fingerprint]
    );

    if (row.length === 0 || row[0].values.length === 0) {
      return res.json({ found: false });
    }

    const r = row[0].values[0];
    res.json({
      found: true,
      chain_fingerprint: fingerprint,
      first_seen: r[0],
      last_seen: r[1],
      attested_ping_count: r[2],
      witnessed_exchange_count: r[3],
      last_device_hash: r[4] || '',
    });
  } catch (e) {
    console.error('[presence] Error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- PUT /relay/:handshake_id ---
// Phone A deposits encrypted settlement for Phone B
app.put('/relay/:handshake_id', (req, res) => {
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
// A server or phone tells us about a server
app.post('/announce', (req, res) => {
  try {
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
        if (pExists.length === 0 || pExists[0].values.length === 0) {
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
  } catch (e) {
    console.error('[announce] Error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- GET /peers ---
// Phone or server requests the list of healthy servers
app.get('/peers', (req, res) => {
  const peers = getActivePeers();
  res.json({ peers, count: peers.length });
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

async function announceToServer(targetUrl) {
  const cleanTarget = targetUrl.replace(/\/+$/, '');
  const payload = {
    url: SELF_URL,
    pubkey: serverKeys.publicKeyHex,
    version: VERSION,
    witnessed_count: witnessedCount,
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
          if (exists.length === 0 || exists[0].values.length === 0) {
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

async function heartbeat() {
  if (!SELF_URL) return;
  const now = Math.floor(Date.now() / 1000);

  // Update our own heartbeat
  const selfClean = SELF_URL.replace(/\/+$/, '');
  db.run('DELETE FROM peers WHERE url = ?', [selfClean]);
  db.run(
    'INSERT INTO peers (url, pubkey, version, witnessed_count, last_heartbeat, added_at) VALUES (?, ?, ?, ?, ?, ?)',
    [selfClean, serverKeys.publicKeyHex, VERSION, witnessedCount, now, now]
  );
  saveDatabase();

  // Announce to all known peers
  const peers = getActivePeers().filter(p => p.url !== selfClean);
  if (peers.length === 0 && SEED_PEERS.length === 0) return;

  const targets = [...new Set([...peers.map(p => p.url), ...SEED_PEERS])];
  console.log(`[gossip] Heartbeating to ${targets.length} peer(s)`);

  for (const target of targets) {
    await announceToServer(target);
  }
}

// --- GET /status (updated with peer count) ---
// Health check and network info
app.get('/status', (req, res) => {
  const uptimeSeconds = Math.floor((Date.now() - startTime) / 1000);
  const currentMints = db.exec('SELECT COUNT(*) FROM witnessed_mints');
  const pendingRelays = db.exec('SELECT COUNT(*) FROM settlement_relay');
  const pendingPairs = db.exec('SELECT COUNT(*) FROM pair_halves WHERE resolved = 0');
  const activeSessions = db.exec('SELECT COUNT(*) FROM sessions');
  const pendingProposals = db.exec("SELECT COUNT(*) FROM session_proposals WHERE status = 'pending'");
  const activePeers = getActivePeers();

  res.json({
    server_pubkey: serverKeys.publicKeyHex,
    version: VERSION,
    url: SELF_URL || null,
    uptime_seconds: uptimeSeconds,
    witnessed_total: witnessedCount,
    witnessed_current: currentMints.length > 0 ? currentMints[0].values[0][0] : 0,
    poh_pings_total: pohPingCount,
    pending_relays: pendingRelays.length > 0 ? pendingRelays[0].values[0][0] : 0,
    pending_pairs: pendingPairs.length > 0 ? pendingPairs[0].values[0][0] : 0,
    active_sessions: activeSessions.length > 0 ? activeSessions[0].values[0][0] : 0,
    pending_proposals: pendingProposals.length > 0 ? pendingProposals[0].values[0][0] : 0,
    peer_count: activePeers.length,
    timestamp: Math.floor(Date.now() / 1000),
    retention: {
      mints_days: MINT_RETENTION_DAYS,
      relay_hours: RELAY_RETENTION_HOURS,
    },
  });
});

// --- POST /pair ---
// Phone submits one half of a pairing code exchange
app.post('/pair', (req, res) => {
  try {
    const { my_code, their_code, value, direction, description, category, duration, fingerprint, public_key, timestamp, device_ts, device_hash } = req.body;

    // Validate required fields
    if (!my_code || !their_code || value === undefined || !direction || !fingerprint || !public_key) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Validate codes. 6 alphanumeric characters
    if (!/^[A-Z]{6}$/.test(my_code) || !/^[A-Z]{6}$/.test(their_code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }

    // Validate direction
    if (!encrypted_exchange && direction !== 'provided' && direction !== 'received') {
      return res.status(400).json({ error: 'Invalid direction' });
    }

    const now = Math.floor(Date.now() / 1000);

    // Check if this code already submitted (idempotent)
    const existing = db.exec('SELECT resolved, resolve_status, counterparty_fp, counterparty_key, counterparty_desc, their_code FROM pair_halves WHERE my_code = ?', [my_code]);
    if (existing.length > 0 && existing[0].values.length > 0) {
      const row = existing[0].values[0];
      if (row[0]) {
        // Already resolved -- return result with counterparty device_ts and device_hash
        let cpDeviceTs = null;
        let cpDeviceHash = '';
        const cpCode = row[5];
        if (cpCode) {
          const cpRow = db.exec('SELECT device_ts, device_hash FROM pair_halves WHERE my_code = ?', [cpCode]);
          if (cpRow.length > 0 && cpRow[0].values.length > 0) {
            cpDeviceTs = cpRow[0].values[0][0] || null;
            cpDeviceHash = cpRow[0].values[0][1] || '';
          }
        }
        return res.json({
          stored: true,
          resolved: true,
          status: row[1],
          counterparty_fp: row[2],
          counterparty_key: row[3] ? JSON.parse(row[3]) : null,
          counterparty_desc: row[4] || '',
          counterparty_device_ts: cpDeviceTs,
          counterparty_device_hash: cpDeviceHash,
        });
      }
      // Already stored but not resolved. Update and re-check
      return res.json({ stored: true, resolved: false, status: 'waiting' });
    }

    // Store this half
    db.run(
      `INSERT INTO pair_halves (my_code, their_code, value, direction, description, category, duration, fingerprint, public_key, timestamp, device_ts, device_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [my_code, their_code, value, direction, description || '', category || '', duration || 0,
       fingerprint, JSON.stringify(public_key), timestamp || new Date().toISOString(), device_ts || null, device_hash || '', now]
    );

    console.log(`[pair] Stored half: ${my_code} -> ${their_code}`);

    // Check for matching half: the other person's my_code should be our their_code,
    // and their their_code should be our my_code
    const match = db.exec(
      'SELECT my_code, value, direction, fingerprint, public_key, description, device_ts, device_hash FROM pair_halves WHERE my_code = ? AND their_code = ?',
      [their_code, my_code]
    );

    if (match.length > 0 && match[0].values.length > 0) {
      const other = match[0].values[0];
      const otherValue = other[1];
      const otherDirection = other[2];
      const otherFp = other[3];
      const otherKey = other[4];
      const otherDesc = other[5] || '';
      const otherDeviceTs = other[6] || null;
      const otherDeviceHash = other[7] || '';

      // Check: values must match exactly, directions must be complementary
      const valuesMatch = Math.abs(value - otherValue) < 0.001;
      const directionsComplement =
        (direction === 'provided' && otherDirection === 'received') ||
        (direction === 'received' && otherDirection === 'provided');

      if (valuesMatch && directionsComplement) {
        // Match. Resolve both halves and store each other's descriptions
        db.run('UPDATE pair_halves SET resolved = 1, resolve_status = ?, counterparty_fp = ?, counterparty_key = ?, counterparty_desc = ? WHERE my_code = ?',
          ['matched', otherFp, otherKey, otherDesc, my_code]);
        db.run('UPDATE pair_halves SET resolved = 1, resolve_status = ?, counterparty_fp = ?, counterparty_key = ?, counterparty_desc = ? WHERE my_code = ?',
          ['matched', fingerprint, JSON.stringify(public_key), description || '', their_code]);

        saveDatabase();
        console.log(`[pair] Matched: ${my_code} <-> ${their_code}`);

        return res.json({
          stored: true,
          resolved: true,
          status: 'matched',
          counterparty_fp: otherFp,
          counterparty_key: JSON.parse(otherKey),
          counterparty_desc: otherDesc,
          counterparty_device_ts: otherDeviceTs,
          counterparty_device_hash: otherDeviceHash,
        });
      } else {
        // Codes cross-reference but values or directions don't match
        const reason = !valuesMatch ? 'value_mismatch' : 'direction_mismatch';
        db.run('UPDATE pair_halves SET resolved = 1, resolve_status = ? WHERE my_code = ?', [reason, my_code]);
        db.run('UPDATE pair_halves SET resolved = 1, resolve_status = ? WHERE my_code = ?', [reason, their_code]);

        saveDatabase();
        console.log(`[pair] Mismatch (${reason}): ${my_code} <-> ${their_code}`);

        return res.json({ stored: true, resolved: true, status: reason });
      }
    }

    // No match yet. Other half hasn't arrived
    saveDatabase();
    res.json({ stored: true, resolved: false, status: 'waiting' });
  } catch (e) {
    console.error('[pair] POST error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- GET /pair/check/:code ---
// Phone polls to check if its pair half has been resolved
app.get('/pair/check/:code', (req, res) => {
  try {
    const { code } = req.params;

    if (!/^[A-Z]{6}$/.test(code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }

    const result = db.exec(
      'SELECT resolved, resolve_status, counterparty_fp, counterparty_key, counterparty_desc, their_code FROM pair_halves WHERE my_code = ?',
      [code]
    );

    if (result.length === 0 || result[0].values.length === 0) {
      return res.status(404).json({ found: false });
    }

    const row = result[0].values[0];
    const resolved = row[0] === 1;

    if (!resolved) {
      return res.json({ found: true, resolved: false, status: 'waiting' });
    }

    // Fetch counterparty's device_ts and device_hash from their pair half
    const theirCode = row[5];
    let counterpartyDeviceTs = null;
    let counterpartyDeviceHash = '';
    if (theirCode) {
      const otherHalf = db.exec('SELECT device_ts, device_hash FROM pair_halves WHERE my_code = ?', [theirCode]);
      if (otherHalf.length > 0 && otherHalf[0].values.length > 0) {
        counterpartyDeviceTs = otherHalf[0].values[0][0] || null;
        counterpartyDeviceHash = otherHalf[0].values[0][1] || '';
      }
    }

    res.json({
      found: true,
      resolved: true,
      status: row[1],
      counterparty_fp: row[2],
      counterparty_key: row[3] ? JSON.parse(row[3]) : null,
      counterparty_desc: row[4] || '',
      counterparty_device_ts: counterpartyDeviceTs,
      counterparty_device_hash: counterpartyDeviceHash,
    });
  } catch (e) {
    console.error('[pair] CHECK error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

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

// --- POST /session/join ---
// Phone joins a session with its code, partner's code, identity, and optional thread snapshot
app.post('/session/join', (req, res) => {
  try {
    const { my_code, their_code, fingerprint, public_key, thread_snapshot, role } = req.body;

    if (!my_code || !their_code || !fingerprint || !public_key) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!validSessionCode(my_code) || !validSessionCode(their_code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }
    if (my_code === their_code) {
      return res.status(400).json({ error: 'Codes must be different' });
    }

    const now = Math.floor(Date.now() / 1000);

    // Check if already joined (idempotent)
    const existing = db.exec('SELECT my_code FROM sessions WHERE my_code = ?', [my_code]);
    if (existing.length === 0 || existing[0].values.length === 0) {
      db.run(
        'INSERT INTO sessions (my_code, their_code, fingerprint, public_key, thread_snapshot, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [my_code, their_code, fingerprint, JSON.stringify(public_key), thread_snapshot || null, role || null, now]
      );
      console.log(`[session] Joined: ${my_code} -> ${their_code}` + (thread_snapshot ? ' (with thread snapshot)' : ' (no thread snapshot)'));
    } else {
      // Update thread snapshot if provided
      if (thread_snapshot) {
        db.run('UPDATE sessions SET thread_snapshot = ? WHERE my_code = ?', [thread_snapshot, my_code]);
      }
    }

    saveDatabase();

    // Check if partner has joined (codes cross-reference)
    const partner = db.exec(
      'SELECT fingerprint, public_key, thread_snapshot, encrypted_snapshot, role FROM sessions WHERE my_code = ? AND their_code = ?',
      [their_code, my_code]
    );

    if (partner.length > 0 && partner[0].values.length > 0) {
      const p = partner[0].values[0];
      console.log(`[session] Connected: ${my_code} <-> ${their_code}`);
      return res.json({
        joined: true,
        connected: true,
        partner: {
          fingerprint: p[0],
          public_key: p[1] ? JSON.parse(p[1]) : null,
          thread_snapshot: p[2] ? JSON.parse(p[2]) : null,
          encrypted_snapshot: p[3] || null,
          role: p[4] || null,
        },
      });
    }

    res.json({ joined: true, connected: false });
  } catch (e) {
    console.error('[session] JOIN error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- GET /session/:code ---
// Phone polls for session state: connected? thread? proposal? confirmation?
app.get('/session/:code', (req, res) => {
  try {
    const { code } = req.params;
    if (!validSessionCode(code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }

    // Find my session entry
    const me = db.exec('SELECT their_code FROM sessions WHERE my_code = ?', [code]);
    if (me.length === 0 || me[0].values.length === 0) {
      return res.status(404).json({ found: false });
    }
    const theirCode = me[0].values[0][0];

    // Check if partner has joined
    const partner = db.exec(
      'SELECT fingerprint, public_key, thread_snapshot, encrypted_snapshot, role FROM sessions WHERE my_code = ? AND their_code = ?',
      [theirCode, code]
    );

    const connected = partner.length > 0 && partner[0].values.length > 0;
    const result = { found: true, connected };

    if (connected) {
      const p = partner[0].values[0];
      result.partner = {
        fingerprint: p[0],
        public_key: p[1] ? JSON.parse(p[1]) : null,
        thread_snapshot: p[2] ? JSON.parse(p[2]) : null,
        encrypted_snapshot: p[3] || null,
        role: p[4] || null,
      };
    }

    // Check for proposal
    const sKey = sessionKey(code, theirCode);
    const proposal = db.exec(
      'SELECT proposer_code, value, direction, description, category, duration, status, confirmer_desc, device_ts, confirmer_device_ts, sensor_hash, platform, confirmer_sensor_hash, confirmer_platform, geo, confirmer_geo, device_hash, confirmer_device_hash, proposer_photo, confirmer_photo, proposer_photo_hash, confirmer_photo_hash, encrypted_exchange FROM session_proposals WHERE session_key = ?',
      [sKey]
    );

    if (proposal.length > 0 && proposal[0].values.length > 0) {
      const pr = proposal[0].values[0];
      result.proposal = {
        proposer_code: pr[0],
        value: pr[1],
        direction: pr[2],
        description: pr[3],
        category: pr[4],
        duration: pr[5],
        status: pr[6],
        confirmer_desc: pr[7] || '',
        device_ts: pr[8] || null,
        confirmer_device_ts: pr[9] || null,
        sensor_hash: pr[10] || '',
        platform: pr[11] || '',
        confirmer_sensor_hash: pr[12] || '',
        confirmer_platform: pr[13] || '',
        geo: pr[14] || '',
        confirmer_geo: pr[15] || '',
        device_hash: pr[16] || '',
        confirmer_device_hash: pr[17] || '',
        proposer_photo: pr[18] || '',
        confirmer_photo: pr[19] || '',
        proposer_photo_hash: pr[20] || '',
        confirmer_photo_hash: pr[21] || '',
        encrypted_exchange: pr[22] || '',
      };
    }

    res.json(result);
  } catch (e) {
    console.error('[session] GET error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /session/:code/thread ---
// Push or update thread snapshot for this session
app.post('/session/:code/thread', (req, res) => {
  try {
    const { code } = req.params;
    const { thread_snapshot, encrypted_snapshot } = req.body;
    if (!validSessionCode(code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }
    if (!thread_snapshot && !encrypted_snapshot) {
      return res.status(400).json({ error: 'Missing thread_snapshot or encrypted_snapshot' });
    }

    const existing = db.exec('SELECT my_code FROM sessions WHERE my_code = ?', [code]);
    if (existing.length === 0 || existing[0].values.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }

    if (thread_snapshot) {
      db.run('UPDATE sessions SET thread_snapshot = ? WHERE my_code = ?', [
        typeof thread_snapshot === 'string' ? thread_snapshot : JSON.stringify(thread_snapshot),
        code
      ]);
    }
    if (encrypted_snapshot) {
      db.run('UPDATE sessions SET encrypted_snapshot = ? WHERE my_code = ?', [encrypted_snapshot, code]);
    }
    saveDatabase();

    console.log(`[session] Thread snapshot updated: ${code}` + (encrypted_snapshot ? ' (encrypted)' : ''));
    res.json({ updated: true });
  } catch (e) {
    console.error('[session] THREAD error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /session/:code/propose ---
// One person submits the full proposal through the session
app.post('/session/:code/propose', (req, res) => {
  try {
    const { code } = req.params;
    const { value, direction, description, category, duration, device_ts, sensor_hash, platform, geo, device_hash, photo, photo_hash, encrypted_exchange } = req.body;

    if (!validSessionCode(code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }
    if (value === undefined || (!direction && !encrypted_exchange) || (!description && !encrypted_exchange)) {
      return res.status(400).json({ error: 'Missing required proposal fields' });
    }
    if (!encrypted_exchange && direction !== 'provided' && direction !== 'received') {
      return res.status(400).json({ error: 'Invalid direction' });
    }

    // Verify session exists and is connected
    const me = db.exec('SELECT their_code FROM sessions WHERE my_code = ?', [code]);
    if (me.length === 0 || me[0].values.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }
    const theirCode = me[0].values[0][0];

    const partner = db.exec('SELECT my_code FROM sessions WHERE my_code = ? AND their_code = ?', [theirCode, code]);
    if (partner.length === 0 || partner[0].values.length === 0) {
      return res.status(409).json({ error: 'Session not yet connected. Partner has not joined' });
    }

    const sKey = sessionKey(code, theirCode);
    const now = Math.floor(Date.now() / 1000);

    // Check for existing proposal
    const existing = db.exec('SELECT status FROM session_proposals WHERE session_key = ?', [sKey]);
    if (existing.length > 0 && existing[0].values.length > 0) {
      const status = existing[0].values[0][0];
      if (status === 'confirmed') {
        return res.status(409).json({ error: 'Proposal already confirmed' });
      }
      // Allow re-proposal (overwrite pending proposal)
      db.run('DELETE FROM session_proposals WHERE session_key = ?', [sKey]);
    }

    db.run(
      `INSERT INTO session_proposals (session_key, proposer_code, value, direction, description, category, duration, status, device_ts, sensor_hash, platform, geo, device_hash, proposer_photo, proposer_photo_hash, encrypted_exchange, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [sKey, code, value, direction, description, category || '', duration || 0, device_ts || null, sensor_hash || '', platform || '', geo || '', device_hash || '', photo || '', photo_hash || '', encrypted_exchange || '', now]
    );

    // Update presence
    const fpRow = db.exec('SELECT fingerprint FROM sessions WHERE my_code = ?', [code]);
    if (fpRow.length > 0 && fpRow[0].values.length > 0) {
      updatePresence(fpRow[0].values[0][0], device_hash, 'session');
    }

    saveDatabase();
    console.log(`[session] Proposal submitted: ${code} in session ${sKey}`);

    res.json({ proposed: true, session_key: sKey });
  } catch (e) {
    console.error('[session] PROPOSE error:', e.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- POST /session/:code/confirm ---
// The other person confirms (or rejects) the proposal
app.post('/session/:code/confirm', (req, res) => {
  try {
    const { code } = req.params;
    const { confirmed, description: confirmerDesc, device_ts: confirmerDeviceTs, sensor_hash: confirmerSensorHash, platform: confirmerPlatform, geo: confirmerGeo, device_hash: confirmerDeviceHash, photo: confirmerPhoto, photo_hash: confirmerPhotoHash } = req.body;

    if (!validSessionCode(code)) {
      return res.status(400).json({ error: 'Invalid code format' });
    }
    if (confirmed === undefined) {
      return res.status(400).json({ error: 'Missing confirmed field' });
    }

    // Find session
    const me = db.exec('SELECT their_code FROM sessions WHERE my_code = ?', [code]);
    if (me.length === 0 || me[0].values.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }
    const theirCode = me[0].values[0][0];
    const sKey = sessionKey(code, theirCode);

    // Find proposal
    const proposal = db.exec(
      'SELECT proposer_code, value, direction, description, category, duration, status, device_ts, sensor_hash, platform, geo, device_hash, proposer_photo, proposer_photo_hash, encrypted_exchange FROM session_proposals WHERE session_key = ?',
      [sKey]
    );
    if (proposal.length === 0 || proposal[0].values.length === 0) {
      return res.status(404).json({ error: 'No proposal found' });
    }

    const pr = proposal[0].values[0];
    if (pr[0] === code) {
      return res.status(400).json({ error: 'Cannot confirm your own proposal' });
    }
    if (pr[6] !== 'pending') {
      return res.status(409).json({ error: 'Proposal already ' + pr[6] });
    }

    const now = Math.floor(Date.now() / 1000);
    const newStatus = confirmed ? 'confirmed' : 'rejected';

    db.run(
      'UPDATE session_proposals SET status = ?, confirmer_desc = ?, confirmer_device_ts = ?, confirmer_sensor_hash = ?, confirmer_platform = ?, confirmer_geo = ?, confirmer_device_hash = ?, confirmer_photo = ?, confirmer_photo_hash = ?, resolved_at = ? WHERE session_key = ?',
      [newStatus, confirmerDesc || '', confirmerDeviceTs || null, confirmerSensorHash || '', confirmerPlatform || '', confirmerGeo || '', confirmerDeviceHash || '', confirmerPhoto || '', confirmerPhotoHash || '', now, sKey]
    );

    // Update presence
    const fpRow = db.exec('SELECT fingerprint FROM sessions WHERE my_code = ?', [code]);
    if (fpRow.length > 0 && fpRow[0].values.length > 0) {
      updatePresence(fpRow[0].values[0][0], confirmerDeviceHash, 'session');
    }

    saveDatabase();
    console.log(`[session] Proposal ${newStatus}: ${sKey}`);

    if (!confirmed) {
      return res.json({ confirmed: false, status: 'rejected' });
    }

    // Confirmed -- return all data both phones need to write their chains
    const proposer = db.exec(
      'SELECT fingerprint, public_key FROM sessions WHERE my_code = ?', [theirCode]
    );
    const confirmer = db.exec(
      'SELECT fingerprint, public_key FROM sessions WHERE my_code = ?', [code]
    );

    const proposerData = proposer[0].values[0];
    const confirmerData = confirmer[0].values[0];

    res.json({
      confirmed: true,
      status: 'confirmed',
      proposal: {
        value: pr[1],
        direction: pr[2],
        description: pr[3],
        category: pr[4],
        duration: pr[5],
        device_ts: pr[7] || null,
        sensor_hash: pr[8] || '',
        platform: pr[9] || '',
        geo: pr[10] || '',
        encrypted_exchange: pr[14] || '',
      },
      proposer: {
        code: theirCode,
        fingerprint: proposerData[0],
        public_key: JSON.parse(proposerData[1]),
        device_hash: pr[11] || '',
        photo: pr[12] || '',
        photo_hash: pr[13] || '',
      },
      confirmer: {
        code: code,
        fingerprint: confirmerData[0],
        public_key: JSON.parse(confirmerData[1]),
        description: confirmerDesc || '',
        device_hash: confirmerDeviceHash || '',
      },
    });
  } catch (e) {
    console.error('[session] CONFIRM error:', e.message);
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
      [selfClean, serverKeys.publicKeyHex, VERSION, witnessedCount, now, now]
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

  // Periodic heartbeat to all peers
  if (SELF_URL) {
    setInterval(heartbeat, HEARTBEAT_INTERVAL_MS);
    console.log(`[gossip] Heartbeat every ${HEARTBEAT_INTERVAL_MS / 60000} minutes`);
  }

  app.listen(PORT, () => {
    console.log(`[server] Listening on port ${PORT}`);
    console.log(`[server] Endpoints:`);
    console.log(`         POST /witness     submit mint for attestation`);
    console.log(`         POST /ping        proof-of-human heartbeat attestation`);
    console.log(`         PUT  /relay/:id   deposit settlement`);
    console.log(`         GET  /relay/:id   retrieve settlement`);
    console.log(`         POST /pair        submit pairing code half`);
    console.log(`         GET  /pair/check/:code check pair resolution`);
    console.log(`         POST /session/join     join a session`);
    console.log(`         GET  /session/:code    poll session state`);
    console.log(`         POST /session/:code/thread  push thread snapshot`);
    console.log(`         POST /session/:code/propose submit proposal`);
    console.log(`         POST /session/:code/confirm confirm proposal`);
    console.log(`         POST /announce    register a server`);
    console.log(`         GET  /peers       list active servers`);
    console.log(`         GET  /status      health check`);
    console.log('');

    // Initial heartbeat after startup (give server 2 seconds to settle)
    if (SELF_URL) {
      setTimeout(heartbeat, 2000);
    }
  });
}

start().catch(e => {
  console.error('Fatal:', e);
  process.exit(1);
});
