// v2.13.0 write path. (1) A write followed at once by SIGTERM (what pm2 restart sends)
// is on disk after exit. (2) A burst of writes then SIGKILL (no chance to flush) leaves a
// database that still opens. (3) No .tmp file is left behind after a clean save.
const { spawn } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');
const initSqlJs = require('sql.js');
const PORT = 4471, BASE = `http://localhost:${PORT}`;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-'));
const DB = path.join(dir, 'w.db');
let pass = 0, fail = 0;
const check = (n, ok) => { console.log((ok ? '  PASS  ' : '  FAIL  ') + n); ok ? pass++ : fail++; };
const sleep = ms => new Promise(r => setTimeout(r, ms));
function start() {
  const p = spawn('node', ['server.js'], { env: { ...process.env, HCP_PORT: PORT, HCP_DB: DB, HCP_KEY: path.join(dir, 'k.json'), HCP_STATE: path.join(dir, 's.json'), HCP_PROBE_DISABLED: '1' }, stdio: 'ignore' });
  return p;
}
async function up() { for (let i = 0; i < 50; i++) { try { if ((await fetch(BASE + '/status')).ok) return; } catch {} await sleep(100); } throw new Error('no start'); }
const exited = p => new Promise(r => p.on('exit', r));
const announce = n => fetch(BASE + '/announce', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://peer' + n + '.example', pubkey: 'ab'.repeat(32) }) });
(async () => {
  let p = start(); await up(); await sleep(1500);
  await announce('TERMCANARY'); p.kill('SIGTERM'); await exited(p);
  check('write then SIGTERM: on disk after exit', fs.readFileSync(DB).includes('peerTERMCANARY'));
  check('no .tmp left after a clean save', !fs.existsSync(DB + '.tmp'));
  p = start(); await up();
  const burst = []; for (let i = 0; i < 200; i++) burst.push(announce('B' + i));
  await Promise.all(burst); await sleep(1100); for (let i = 0; i < 100; i++) announce('C' + i).catch(() => {});
  await sleep(30); p.kill('SIGKILL'); await exited(p);
  const SQL = await initSqlJs(); let opened = false;
  try { const d = new SQL.Database(fs.readFileSync(DB)); d.exec('SELECT count(*) FROM peers'); opened = true; } catch (e) { console.log('    ' + e.message); }
  check('burst then SIGKILL: database still opens', opened);
  p = start(); let restarted = true; try { await up(); } catch { restarted = false; }
  check('witness restarts on that file', restarted); p.kill('SIGTERM'); await exited(p);
  console.log(`\nsummary  ${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
