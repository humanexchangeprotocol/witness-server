// Tests for the v2.10.0 minimization release (Oct 13 rulings).
// Run from the repo root with: node test-minimal.js
//
// 1. Migration: an old-shape database full of readable person fields
//    (geo, platform, photos, names, plaintext snapshot, ping log,
//    presence registry, pair halves) is upgraded in place; afterwards no
//    such column, table or value remains, not even in the file's bytes.
// 2. Allowlist: a request carrying an extra clear field is accepted but
//    the field is not kept anywhere (row, response).
// 3. Sealed only: plaintext snapshots and unsealed proposals are refused.
// 4. A full sealed session (join, thread, propose, confirm) still works.
// 5. Ping: signs head_hash in, stores nothing; presence and pair are gone.

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const nacl = require('tweetnacl');
const initSqlJs = require('sql.js');

const PORT = 4461;
const BASE = `http://localhost:${PORT}`;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'hep-min-'));
const DB = path.join(TMP, 'witness.db');

let passed = 0, failed = 0;
function check(label, ok, detail) {
  if (ok) { console.log('  PASS  ' + label); passed++; }
  else { console.log('  FAIL  ' + label + (detail ? '  (' + detail + ')' : '')); failed++; }
}
const post = (p, body) => fetch(BASE + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

// Canary strings planted in the old database. None may survive.
const CANARY = ['GEOCANARY', 'PLATCANARY', 'PHOTOCANARY', 'NAMECANARY', 'SNAPCANARY', 'DESCCANARY', 'SENSORCANARY', 'PRESENCECANARY', 'PUBKEYACANARY'];

async function buildOldDb(SQL) {
  const db = new SQL.Database();
  db.run(`CREATE TABLE witnessed_mints (mint_hash TEXT PRIMARY KEY, pubkey_a TEXT NOT NULL, pubkey_b TEXT NOT NULL, device_ts INTEGER NOT NULL, server_ts INTEGER NOT NULL, server_sig TEXT NOT NULL, created_at INTEGER NOT NULL, act_hash TEXT)`);
  db.run(`CREATE TABLE sessions (my_code TEXT PRIMARY KEY, their_code TEXT NOT NULL, fingerprint TEXT NOT NULL, public_key TEXT NOT NULL, thread_snapshot TEXT, created_at INTEGER NOT NULL, encrypted_snapshot TEXT, role TEXT)`);
  db.run(`CREATE TABLE session_proposals (session_key TEXT PRIMARY KEY, proposer_code TEXT NOT NULL, value REAL NOT NULL, direction TEXT NOT NULL, description TEXT, category TEXT, duration INTEGER DEFAULT 0, status TEXT DEFAULT 'pending', confirmer_desc TEXT, created_at INTEGER NOT NULL, resolved_at INTEGER, device_ts INTEGER, act_hash TEXT, proposer_act_sig TEXT, confirmer_act_sig TEXT, confirmer_device_ts INTEGER, sensor_hash TEXT, platform TEXT, confirmer_sensor_hash TEXT, confirmer_platform TEXT, geo TEXT, confirmer_geo TEXT, device_hash TEXT, confirmer_device_hash TEXT, proposer_photo TEXT, confirmer_photo TEXT, proposer_photo_hash TEXT, confirmer_photo_hash TEXT, encrypted_exchange TEXT)`);
  db.run(`CREATE TABLE pipes (pipe_code TEXT PRIMARY KEY, owner_fingerprint TEXT NOT NULL, owner_public_key TEXT NOT NULL, owner_name TEXT, max_redemptions INTEGER NOT NULL DEFAULT 1, redemption_count INTEGER NOT NULL DEFAULT 0, closed INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)`);
  db.run(`CREATE TABLE pipe_redemptions (pipe_code TEXT NOT NULL, redeemer_code TEXT NOT NULL, owner_code TEXT NOT NULL, redeemer_fingerprint TEXT NOT NULL, redeemer_public_key TEXT NOT NULL, redeemer_name TEXT, created_at INTEGER NOT NULL, PRIMARY KEY (pipe_code, redeemer_code))`);
  db.run(`CREATE TABLE pair_halves (my_code TEXT PRIMARY KEY, their_code TEXT, value REAL, direction TEXT, description TEXT, fingerprint TEXT, public_key TEXT, timestamp TEXT, created_at INTEGER)`);
  db.run(`CREATE TABLE poh_pings (id INTEGER PRIMARY KEY AUTOINCREMENT, chain_fingerprint TEXT NOT NULL, sensor_hash TEXT, device_ts INTEGER NOT NULL, server_ts INTEGER NOT NULL, server_sig TEXT NOT NULL, seq INTEGER, created_at INTEGER NOT NULL)`);
  db.run(`CREATE TABLE presence_registry (chain_fingerprint TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, attested_ping_count INTEGER DEFAULT 0, witnessed_exchange_count INTEGER DEFAULT 0, last_device_hash TEXT)`);
  db.run(`CREATE TABLE counters (key TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0)`);
  const now = Math.floor(Date.now() / 1000);
  const mh = 'a'.repeat(64);
  db.run('INSERT INTO witnessed_mints VALUES (?,?,?,?,?,?,?,?)', [mh, 'PUBKEYACANARY', 'PUBKEYACANARY', now, now, 'sig', now, 'b'.repeat(64)]);
  db.run('INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)', ['ACDE', 'FGHJ', 'fp1', '{"k":1}', 'SNAPCANARY', now, 'ENC1', 'NAMECANARY']);
  db.run(`INSERT INTO session_proposals (session_key, proposer_code, value, direction, description, created_at, geo, platform, proposer_photo, sensor_hash, encrypted_exchange) VALUES ('ACDE:FGHJ','ACDE',5,'provided','DESCCANARY',?, 'GEOCANARY','PLATCANARY','PHOTOCANARY','SENSORCANARY','SEALED1')`, [now]);
  db.run(`INSERT INTO session_proposals (session_key, proposer_code, value, direction, description, created_at, geo) VALUES ('KMNP:QRTU','KMNP',5,'provided','DESCCANARY',?, 'GEOCANARY')`, [now]); // unsealed: dropped
  db.run('INSERT INTO pipes VALUES (?,?,?,?,?,?,?,?)', ['ACDEFGHJKM', 'fp1', '{"k":1}', 'NAMECANARY', 1, 0, 0, now]);
  db.run('INSERT INTO pipe_redemptions VALUES (?,?,?,?,?,?,?)', ['ACDEFGHJKM', 'VWXY', 'ZACD', 'fp2', '{"k":2}', 'NAMECANARY', now]);
  db.run('INSERT INTO pair_halves VALUES (?,?,?,?,?,?,?,?,?)', ['ABCDEF', 'GHIJKL', 5, 'provided', 'DESCCANARY', 'fp', '{}', 't', now]);
  db.run('INSERT INTO poh_pings (chain_fingerprint, sensor_hash, device_ts, server_ts, server_sig, created_at) VALUES (?,?,?,?,?,?)', ['fp1', 'SENSORCANARY', now, now, 's', now]);
  db.run('INSERT INTO presence_registry VALUES (?,?,?,?,?,?)', ['fp1', now, now, 1, 1, 'PRESENCECANARY']);
  fs.writeFileSync(DB, Buffer.from(db.export()));
  fs.writeFileSync(path.join(TMP, 'witness_count.txt'), '171');
}

function startServer() {
  const env = { ...process.env, HCP_PORT: String(PORT), HCP_DB: DB, HCP_KEY: path.join(TMP, 'k.json'), HCP_STATE: path.join(TMP, 's.json') };
  delete env.HCP_URL; delete env.HCP_PUBLIC_IP;
  const proc = spawn('node', ['server.js'], { env, stdio: ['ignore', 'pipe', 'pipe'], cwd: __dirname });
  let out = '';
  proc.stdout.on('data', d => { out += d; if (process.env.MIN_VERBOSE) process.stdout.write('[srv] ' + d); });
  proc.stderr.on('data', d => { out += d; if (process.env.MIN_VERBOSE) process.stderr.write('[srv-err] ' + d); });
  return { proc, log: () => out };
}

async function waitUp() {
  for (let i = 0; i < 50; i++) {
    try { const r = await fetch(BASE + '/status'); if (r.ok) return; } catch (e) {}
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error('server did not start');
}

async function readDb(SQL) {
  return new SQL.Database(fs.readFileSync(DB));
}
function cols(db, t) { const r = db.exec(`PRAGMA table_info(${t})`); return r.length ? r[0].values.map(v => v[1]) : []; }

async function main() {
  const SQL = await initSqlJs();
  await buildOldDb(SQL);
  const srv = startServer();
  await waitUp();

  console.log('\n1. Migration of an old database');
  let db = await readDb(SQL);
  for (const t of ['pair_halves', 'poh_pings', 'presence_registry', 'counters']) check(`table ${t} dropped`, cols(db, t).length === 0);
  check('session_proposals has only allowed columns',
    JSON.stringify(cols(db, 'session_proposals').sort()) === JSON.stringify(['act_hash', 'confirmer_act_sig', 'confirmer_device_ts', 'created_at', 'device_ts', 'encrypted_exchange', 'proposer_act_sig', 'proposer_code', 'resolved_at', 'session_key', 'status'].sort()), cols(db, 'session_proposals').join(','));
  check('sessions has no thread_snapshot or role', !cols(db, 'sessions').includes('thread_snapshot') && !cols(db, 'sessions').includes('role'));
  check('witnessed_mints has no pubkeys', !cols(db, 'witnessed_mints').includes('pubkey_a'));
  check('pipes has no owner_name', !cols(db, 'pipes').includes('owner_name'));
  check('pipe_redemptions has no redeemer_name', !cols(db, 'pipe_redemptions').includes('redeemer_name'));
  const sp = db.exec('SELECT session_key, encrypted_exchange FROM session_proposals');
  check('sealed proposal carried forward, unsealed one dropped', sp.length && sp[0].values.length === 1 && sp[0].values[0][1] === 'SEALED1');
  const ss = db.exec("SELECT encrypted_snapshot FROM sessions WHERE my_code='ACDE'");
  check('session row kept with its sealed snapshot', ss.length && ss[0].values[0][0] === 'ENC1');
  const bytes = fs.readFileSync(DB).toString('latin1');
  const left = CANARY.filter(c => bytes.includes(c));
  check('no planted person value left in the database file bytes', left.length === 0, left.join(','));
  check('lifetime count file removed', !fs.existsSync(path.join(TMP, 'witness_count.txt')));

  console.log('\n2. Status and stats carry no counts');
  const st = await (await fetch(BASE + '/status')).json();
  check('/status has no witnessed_total', st.witnessed_total === undefined);
  check('/status has no active_sessions', st.active_sessions === undefined);
  check('/status keeps pubkey and version', typeof st.server_pubkey === 'string' && st.version === '2.13.1');
  const pubkey = Buffer.from(st.server_pubkey, 'hex');

  console.log('\n3. Sealed session with extra clear fields');
  const kA = { kty: 'EC', x: 'A' }, kB = { kty: 'EC', x: 'B' };
  let r = await post('/session/join', { my_code: 'MNPQ', their_code: 'RTUV', fingerprint: 'fpA', public_key: kA, role: 'attach-new', thread_snapshot: '{"n":"NAMECANARY"}', geo: 'GEOCANARY' });
  check('join A accepted', r.ok);
  r = await post('/session/join', { my_code: 'RTUV', their_code: 'MNPQ', fingerprint: 'fpB', public_key: kB, name: 'NAMECANARY' });
  let j = await r.json();
  check('join B connected', j.connected === true);
  check('partner view has no role and no thread_snapshot', j.partner && j.partner.role === undefined && j.partner.thread_snapshot === undefined);
  r = await post('/session/MNPQ/thread', { thread_snapshot: { n: 'NAMECANARY' } });
  check('plaintext snapshot refused', r.status === 400);
  r = await post('/session/MNPQ/thread', { encrypted_snapshot: 'ENC-A', thread_snapshot: 'SNAPCANARY' });
  check('sealed snapshot accepted (extra field dropped)', r.ok);
  r = await post('/session/MNPQ/propose', { value: 5, direction: 'provided', description: 'DESCCANARY' });
  j = await r.json();
  check('unsealed proposal refused', r.status === 400 && j.error === 'unsealed');
  r = await post('/session/MNPQ/propose', { encrypted_exchange: 'SEALED-X', act_hash: 'c'.repeat(64), act_sig: 'SIGA', device_ts: 123, value: 0, direction: '', geo: 'GEOCANARY', platform: 'PLATCANARY', photo: 'PHOTOCANARY', sensor_hash: 'SENSORCANARY', device_hash: 'x', photo_hash: 'y' });
  check('sealed proposal accepted', r.ok);
  j = await (await fetch(BASE + '/session/RTUV')).json();
  check('poll returns sealed packet and act data', j.proposal && j.proposal.encrypted_exchange === 'SEALED-X' && j.proposal.act_hash === 'c'.repeat(64) && j.proposal.proposer_act_sig === 'SIGA' && j.proposal.device_ts === 123);
  check('poll carries no geo/platform/photo/sensor/device fields', ['geo', 'platform', 'proposer_photo', 'confirmer_photo', 'sensor_hash', 'device_hash', 'proposer_photo_hash'].every(k => j.proposal[k] === undefined));
  check('partner snapshot is the sealed one', j.partner.encrypted_snapshot === 'ENC-A');
  r = await post('/session/RTUV/confirm', { confirmed: true, act_sig: 'SIGB', device_ts: 456, description: 'DESCCANARY', geo: 'GEOCANARY', photo: 'PHOTOCANARY', platform: 'PLATCANARY' });
  j = await r.json();
  check('confirm returns both keys and both signatures', j.confirmed && j.proposer.fingerprint === 'fpA' && j.confirmer.fingerprint === 'fpB' && j.proposal.confirmer_act_sig === 'SIGB' && j.proposer.act_sig === 'SIGA');
  check('confirm response carries no person fields', JSON.stringify(j).indexOf('CANARY') === -1 && j.confirmer.description === undefined && j.proposer.photo === undefined);

  console.log('\n4. Witness, ping, removed endpoints');
  r = await post('/witness', { mint_hash: 'd'.repeat(64), pubkey_a: 'PUBKEYACANARY', pubkey_b: 'PUBKEYACANARY', chain_sig: 'x', device_timestamp: 1, act_hash: 'e'.repeat(64) });
  j = await r.json();
  check('witness attests', j.witnessed === true);
  check('witness signature verifies over mint_hash:ts', nacl.sign.detached.verify(Buffer.from('d'.repeat(64) + ':' + j.server_timestamp), Buffer.from(j.server_signature, 'hex'), pubkey));
  const head = 'f'.repeat(64);
  const ch = await (await post('/ping/challenge', { chain_fingerprint: 'abc123' })).json();
  r = await post('/ping', { chain_fingerprint: 'abc123', device_ts: 1, challenge_nonce: ch.nonce, head_hash: head, sensor_hash: 'SENSORCANARY', seq: 9 });
  j = await r.json();
  check('ping attested and challenged', j.attested && j.challenged);
  check('ping signs the head hash in (ping2:fp:head:ts)', nacl.sign.detached.verify(Buffer.from('ping2:abc123:' + head + ':' + j.server_timestamp), Buffer.from(j.server_signature, 'hex'), pubkey));
  check('the same signature fails for a different head', !nacl.sign.detached.verify(Buffer.from('ping2:abc123:' + '0'.repeat(64) + ':' + j.server_timestamp), Buffer.from(j.server_signature, 'hex'), pubkey));
  r = await post('/ping', { chain_fingerprint: 'abc123', device_ts: 1 });
  j = await r.json();
  check('legacy ping (no head) still attested', j.attested && nacl.sign.detached.verify(Buffer.from('ping:abc123::' + j.server_timestamp), Buffer.from(j.server_signature, 'hex'), pubkey));
  r = await post('/ping', { chain_fingerprint: 'abc123', device_ts: 1, head_hash: 'nothex' });
  check('malformed head_hash refused', r.status === 400);
  check('GET /presence is gone', (await fetch(BASE + '/presence/abc123')).status === 404);
  check('POST /pair is gone', (await post('/pair', { my_code: 'ABCDEF' })).status === 410);
  check('GET /stats/daily is gone', (await fetch(BASE + '/stats/daily')).status === 404);

  console.log('\n5. Pipes without names; owner poll by POST');
  r = await post('/pipe', { pipe_code: 'QRTUVWXYZA', fingerprint: 'fpO', public_key: kA, name: 'NAMECANARY' });
  check('pipe opened (name dropped)', r.ok);
  r = await post('/pipe/QRTUVWXYZA/redeem', { redeemer_code: 'CDEF', fingerprint: 'fpR', public_key: kB, name: 'NAMECANARY' });
  j = await r.json();
  check('redeem accepted, owner has no name', j.accepted && j.owner && j.owner.name === undefined);
  r = await post('/pipe/QRTUVWXYZA/owner', { fingerprint: 'fpO' });
  j = await r.json();
  check('owner poll by POST works', j.found && j.redemptions.length === 1 && j.redemptions[0].name === undefined);
  r = await post('/pipe/QRTUVWXYZA/owner', { fingerprint: 'someone-else' });
  check('owner poll refuses a non-owner', r.status === 403);
  check('owner poll by GET still works for older apps', (await fetch(BASE + '/pipe/QRTUVWXYZA/owner?fingerprint=fpO')).ok);

  console.log('\n5b. Session keys (v2.11.0): stored, returned, no code oracle, join rate limit');
  const skA = { kty: 'EC', crv: 'P-256', x: 'x'.repeat(43), y: 'y'.repeat(43) }, skB = { kty: 'EC', crv: 'P-256', x: 'a'.repeat(43), y: 'b'.repeat(43) };
  r = await post('/session/join', { my_code: 'KLMN', their_code: 'PQRS', fingerprint: 'fpA', public_key: kA, session_key: skA, session_sig: 'sigA', extra_clear: 'NAMECANARY' });
  check('join with session key accepted', r.ok);
  r = await post('/session/join', { my_code: 'PQRS', their_code: 'KLMN', fingerprint: 'fpB', public_key: kB, session_key: skB, session_sig: 'sigB' });
  j = await r.json();
  check('partner carries session_key and session_sig', j.connected && j.partner.session_key && j.partner.session_key.x === skA.x && j.partner.session_sig === 'sigA');
  r = await fetch(BASE + '/session/KLMN'); j = await r.json();
  check('poll carries the partner session key', j.connected && j.partner.session_key && j.partner.session_key.y === skB.y && j.partner.session_sig === 'sigB');
  r = await fetch(BASE + '/session/ZZZZ'); j = await r.json();
  check('unknown code answers like an open one (no oracle)', r.status === 200 && j.found === true && j.connected === false);
  r = await post('/session/join', { my_code: 'KLMN', their_code: 'PQRS', fingerprint: 'fpA', public_key: kA, session_key: { x: 5 }, session_sig: 'sigA' });
  check('malformed session key refused', r.status === 400);

  console.log('\n5c. v2.12.0: commitment on join, reveal once both are in');
  const cA = 'a'.repeat(64), cB = 'b'.repeat(64);
  r = await post('/session/join', { my_code: 'CDEF', their_code: 'GHJK', fingerprint: 'fpA', public_key: kA, session_commit: 'nothex' });
  check('malformed commitment refused', r.status === 400);
  r = await post('/session/reveal', { my_code: 'CDEF', session_key: skA, session_sig: 'sigA' }); j = await r.json();
  check('reveal on an unknown code answers waiting (no oracle)', r.status === 200 && j.revealed === false && j.waiting === true);
  r = await post('/session/join', { my_code: 'CDEF', their_code: 'GHJK', fingerprint: 'fpA', public_key: kA, session_commit: cA });
  check('join with a commitment and no key accepted', r.status === 200);
  r = await post('/session/reveal', { my_code: 'CDEF', session_key: skA, session_sig: 'sigA' }); j = await r.json();
  check('reveal before the partner joined refused as waiting', j.revealed === false && j.waiting === true);
  r = await post('/session/join', { my_code: 'GHJK', their_code: 'CDEF', fingerprint: 'fpB', public_key: kB, session_commit: cB }); j = await r.json();
  check('second join connects and the partner view carries the commitment, not a key', j.connected === true && j.partner.session_commit === cA && j.partner.session_key === null);
  r = await post('/session/reveal', { my_code: 'CDEF', session_key: skA, session_sig: 'sigA' }); j = await r.json();
  check('reveal after both joined accepted', j.revealed === true);
  r = await post('/session/reveal', { my_code: 'CDEF', session_key: skB, session_sig: 'sigB' });
  r = await fetch(BASE + '/session/GHJK'); j = await r.json();
  check('a second reveal cannot replace the first key', j.partner.session_key.x === skA.x && j.partner.session_sig === 'sigA');
  check('partner view after reveal carries key, signature and commitment', j.partner.session_commit === cA && j.partner.session_key.x === skA.x);
  r = await post('/session/reveal', { my_code: 'KLMN', session_key: skA, session_sig: 'sigA' });
  check('reveal on a session joined without a commitment refused', r.status === 400);
  let limited = false;
  for (let i = 0; i < 70; i++) { const c = 'R' + String.fromCharCode(65 + (i % 26)) + String.fromCharCode(65 + Math.floor(i / 26)) + 'T'; const rr = await post('/session/join', { my_code: c, their_code: 'ZZZA', fingerprint: 'fpX', public_key: kA }); if (rr.status === 429) { limited = true; break; } }
  check('joins rate limited per address', limited);

  console.log('\n6. Nothing planted reached the database');
  await new Promise(r => setTimeout(r, 1300)); // saveDatabase runs on writes; give the last one a moment
  db = await readDb(SQL);
  const dump = JSON.stringify(['sessions', 'session_proposals', 'witnessed_mints', 'pipes', 'pipe_redemptions', 'ping_challenges'].map(t => db.exec('SELECT * FROM ' + t)));
  const leaked = CANARY.filter(c => dump.includes(c));
  check('no clear field from any request was kept', leaked.length === 0, leaked.join(','));
  const mintRow = db.exec("SELECT * FROM witnessed_mints WHERE mint_hash = '" + 'd'.repeat(64) + "'");
  check('witnessed mint row holds hash, times, signature, act hash only', mintRow.length && mintRow[0].columns.join(',') === 'mint_hash,device_ts,server_ts,server_sig,act_hash,created_at', mintRow.length ? mintRow[0].columns.join(',') : 'none');
  check('allowlist logged dropped field names', /\[allowlist\].*dropped field 'geo'/.test(srv.log()));
  check('log never printed a planted value', CANARY.every(c => !srv.log().includes(c)));

  console.log('\nsummary  ' + passed + ' passed, ' + failed + ' failed\n');
  srv.proc.kill();
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error('test threw:', e); process.exit(1); });
