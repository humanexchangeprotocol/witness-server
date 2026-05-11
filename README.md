# HEP Witness Server

A small Node.js service that records cooperative-act attestations and relays encrypted messages between exchanging parties for the Human Exchange Protocol. Attestation only. Does not host the app, does not see message contents, does not store identity.

For details on what HEP is, see [humanexchangeprotocol.org](https://humanexchangeprotocol.org).

This README covers running a witness in three settings: on a local network only, on the public internet via an opened router port, and on the public internet behind a reverse proxy. All three settings use the same software and the same operator path; only the network shape differs.

A witness is identified by its Ed25519 public key, generated on first run and persisted in `server_key.json`. Domain names are not required and not part of the trust model. The key file is the witness's permanent identity.

---

## Hardware and software

- Raspberry Pi 3B+ or newer with 1 GB RAM, or any Linux / macOS / Windows machine
- Node.js 20.x or later
- Persistent network connection
- Roughly 200 MB RAM in normal operation, modest disk

The witness is pure JavaScript with no native dependencies, so it runs on ARM (Pi) and x86 alike without recompilation.

---

## Quick start

```bash
git clone https://github.com/humanexchangeprotocol/witness-server.git
cd witness-server
npm install
node server.js
```

The witness listens on port 3141. Configurable via the `HCP_PORT` environment variable.

On first run, the witness generates an Ed25519 signing key (`server_key.json`) and a SQLite database (`witness.db`) in the working directory. The signing key is the witness's permanent identity; back it up. The next section covers why and how.

Confirm the server is responding:

```bash
curl http://localhost:3141/status
```

You should see a JSON response with `version`, `witnessed_total`, uptime, and a `server_pubkey` field. The `server_pubkey` is the 64-character hex form of the witness's public key. This identifier never changes for the life of this `server_key.json` file.

---

## Back up `server_key.json`

The signing key file is the witness's identity. Treat it the way you would treat the private key for an SSH server you operate.

- **If `server_key.json` leaks**, anyone who holds it can sign arbitrary statements as your witness. Treat that as a compromise: stop the witness, generate a new key, retire the old pubkey from any seed lists. There is no in-band revocation; loss of secrecy means loss of the identity.
- **If `server_key.json` is deleted or lost**, the next start generates a new keypair. Your previous pubkey is permanently gone. Any users who knew your old pubkey now have no way to reach you under that identity; your witness becomes a brand-new witness from their perspective. There is no recovery procedure, by design.

Back the file up at install time and after any operational change that could touch it. A copy on encrypted external media or a password manager attachment is sufficient. Do not commit it to git; the `.gitignore` already excludes it.

The same applies to `witness.db` (the attestation database) and `server_state.json` (the sequence counter for signed broadcasts). These three files together represent the witness's accumulated state. The repo's `.gitignore` excludes all three.

---

## Step-by-step install on Raspberry Pi OS

This walks through a clean install on Raspberry Pi OS Bookworm. The same commands work on Ubuntu, Debian, and other Debian-derived systems. On non-Debian Linux, substitute your package manager for `apt`.

If your Pi has both wired and wireless options available, ethernet is the more reliable first-boot path. Pi Imager's wifi customization has been observed to silently fail to apply on some installs; ethernet has been reliable on the same hardware. Once the Pi is running and reachable, wifi can be configured directly on the device.

### 1. Update the system

```bash
sudo apt update
sudo apt upgrade -y
```

### 2. Install Node.js 20

The Node version in Raspberry Pi OS's default repositories is too old. Use the official NodeSource installer:

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

Verify:

```bash
node --version
```

You should see `v20.x.x`.

### 3. Install git (if not already present)

```bash
sudo apt install -y git
```

### 4. Clone, install dependencies, run

```bash
cd ~
git clone https://github.com/humanexchangeprotocol/witness-server.git
cd witness-server
npm install
node server.js
```

You should see output similar to:

```
[keys] Generated new server keypair
[keys] Public key: a1b2c3...
[db] Created new database
[db] Tables ready. Witnessed mints in DB: 0
[server] Listening on port 3141
[server] Endpoints:
         POST /witness     submit mint for attestation
         POST /ping        proof-of-human heartbeat attestation
         ...
```

Note your public key. From another device on the same network, you can reach the witness at `http://<pi-local-ip>:3141/status`.

In this basic mode, the witness runs only while the terminal is open. Closing the terminal kills it. The next section sets it up to run continuously.

---

## Run as a service (so it survives reboots)

This step uses systemd, the standard service manager on Raspberry Pi OS and most modern Linux. After this, the witness starts at boot, restarts if it crashes, and keeps running when you log out.

Create the service file:

```bash
sudo nano /etc/systemd/system/hep-witness.service
```

Paste this in. Adjust `User=` and `WorkingDirectory=` to match your username and the path you cloned to. On a default Raspberry Pi OS install where the user is `pi`, no changes needed:

```ini
[Unit]
Description=HEP Witness Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/witness-server
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Save (`Ctrl+O`, Enter) and exit (`Ctrl+X`).

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable hep-witness
sudo systemctl start hep-witness
```

Verify:

```bash
sudo systemctl status hep-witness
curl http://localhost:3141/status
```

Tail the live log:

```bash
sudo journalctl -u hep-witness -f
```

Press `Ctrl+C` to stop tailing (this does not stop the server). To stop or restart the service:

```bash
sudo systemctl stop hep-witness
sudo systemctl restart hep-witness
```

To remove the service entirely (leaving the witness files in place so you can run it manually again later):

```bash
sudo systemctl stop hep-witness
sudo systemctl disable hep-witness
sudo rm /etc/systemd/system/hep-witness.service
sudo systemctl daemon-reload
```

To remove the witness fully, also delete `~/witness-server`. Back up `server_key.json` first if you might run a witness again later under the same identity.

---

## Upgrade path

The witness upgrades by replacing the source code while preserving the three state files (`server_key.json`, `witness.db`, `server_state.json`). The pubkey-as-identity property is the property that lets upgrades happen without re-bootstrapping anything else on the network.

### Standard upgrade (your install is a git checkout)

```bash
sudo systemctl stop hep-witness
cd ~/witness-server
git pull
npm install
sudo systemctl start hep-witness
sudo journalctl -u hep-witness -n 20 --no-pager
```

The state files live outside the git working tree (protected by `.gitignore`), so `git pull` cannot disturb them. The boot log should show the same `[keys] Loaded existing server keypair` and `[keys] Public key:` lines as before, with the same pubkey.

### Clone-and-swap upgrade (your install is not a git checkout)

If an older install was put in place by hand-copying files rather than cloning the repo, use this pattern. It is also the safer pattern for any upgrade that worries you.

```bash
sudo systemctl stop hep-witness
cd /path/to/parent
git clone https://github.com/humanexchangeprotocol/witness-server.git witness-server-new
cp witness-server/server_key.json witness-server-new/
cp witness-server/witness.db witness-server-new/
cp witness-server/server_state.json witness-server-new/ 2>/dev/null || true
cd witness-server-new
npm install
cd ..
mv witness-server witness-server.backup-$(date +%F)
mv witness-server-new witness-server
sudo systemctl start hep-witness
sudo journalctl -u hep-witness -n 20 --no-pager
```

Adjust paths to match your install. The backup directory can be deleted after a few days of healthy operation on the new install.

---

## Public-internet operation

Local-network operation is fully supported and is the default. This section covers what changes when you want users outside your local network to reach the witness.

The witness is identified by its public key, not by a domain name. A domain name is one way to give clients a stable hostname, but it is not part of the trust model and not required to operate a public witness.

### Option A: opened router port (no domain required)

The simplest public-internet path. Open one TCP port on your home router and forward it to the machine running the witness. Users reach the witness at your public IP and that port.

Steps:

1. Pick a port on your router. Port 3141 is fine if you have only one witness behind that router; otherwise pick any unused port.
2. In your router's admin UI, add a port-forward rule: external port (your pick) -> internal IP (the witness machine) -> internal port (3141 unless changed via `HCP_PORT`).
3. If your home IP is dynamic (most residential connections are), set up a dynamic DNS hostname so users have a stable address. Free DDNS providers like duckdns.org are sufficient. The hostname is for client convenience; the trust anchor is still your pubkey.
4. If a firewall on the witness machine is active, allow inbound on the witness's listening port (default 3141).

The witness does not need to know its own public IP for this option. Clients reaching it from outside arrive on the same listening port the witness already has open. Test by visiting `http://<your-ddns-hostname>:<external-port>/status` from a phone on cellular data (not on your home wifi).

### Option B: reverse proxy with TLS (for operators who already run a web server)

If you already operate a domain and a web server, you can put the witness behind nginx (or any reverse proxy) and serve it over HTTPS. The IONOS production witness at `witness.thesitefit.com` follows this pattern.

Sketch:

- The witness listens on `localhost:3141` (no public binding).
- nginx terminates TLS on 443 and proxies to `http://127.0.0.1:3141`.
- The TLS certificate comes from Let's Encrypt or equivalent.

Configuration of nginx and TLS is outside the scope of this README; both are standard topics with extensive documentation elsewhere. The witness side requires no additional configuration for this option.

Note that the domain in this case is a convenience for clients, not part of the trust model. The witness's pubkey is what clients verify against. Two witnesses behind the same domain at different times would be two different witnesses.

### Becoming reachable to users in the wild

A new public witness is not automatically known to client apps. Today the app holds a hard-coded seed list of trusted witness pubkeys (`HEP_SEEDS` in the app source). To be reached by users, your witness's pubkey needs to be added to that list.

The path to seed-list inclusion is not self-service yet. Architectural decisions about the bootstrap signing key are still open. If you have stood up a witness and want to be added to the network, open an issue on this repo with your pubkey and a brief description of your hosting setup.

---

## Witness as good guest on a shared machine

Most witness operators will run the witness on a machine they also use for other things, not on a dedicated witness box. The witness is built to be a good guest on a shared host.

- **Resource footprint.** Roughly 200 MB RAM steady-state, modest disk (the database grows slowly), one TCP port. No background CPU when idle.
- **No conflict with other services on the same machine** unless something else is bound to port 3141. Configurable via `HCP_PORT` if there is a collision.
- **Stop and start without uninstalling.** `sudo systemctl stop hep-witness` halts the witness without removing it. Restart with `sudo systemctl start hep-witness`. State files persist across stops and starts.
- **Survives reboots** once the systemd unit is enabled. Survives crashes (the unit restarts the witness automatically).
- **Removable without residue.** See the systemd section above for full uninstall steps.

If you take the machine down for maintenance, you can leave the witness's port forwarding rule in place; clients will fail to connect during the outage and rotate to other witnesses if they have any seeded.

You do not need to run a 24/7 server to be useful. HEP is designed to be offline-first; witnesses are an enhancement, not a requirement. A network of imperfect hosts whose collective availability is high serves the protocol better than a few perfect ones. If your machine reboots once a week, sleeps overnight, or goes offline when you travel, that is fine. Honest participation matters more than uptime.

---

## Environment variables

All env vars are optional. The witness runs with reasonable defaults.

| Variable | Default | Purpose |
| --- | --- | --- |
| `HCP_PORT` | `3141` | TCP port the witness listens on. |
| `HCP_DB` | `./witness.db` | Path to the SQLite database file. |
| `HCP_KEY` | `./server_key.json` | Path to the signing key file. |
| `HCP_STATE` | `./server_state.json` | Path to the sequence counter file. |
| `HCP_PUBLIC_IP` | (unset) | Public IP this witness announces itself at in signed gossip. Set when running on the public internet via an opened router port. |
| `HCP_PUBLIC_PORT` | falls back to `HCP_PORT` | Public port this witness announces. Set if external port and internal port differ. |
| `HCP_URL` | (unset) | Legacy public URL announcement field. Used by older clients. Optional. |
| `HCP_SEEDS` | (empty) | Comma-separated list of seed peer URLs to attempt at startup. Used by witnesses that want to join an existing peer network. |
| `HCP_PROBE_DISABLED` | (unset) | When set to `1`, skips the inbound-reachability self-check on startup. Useful when running behind a reverse proxy where the self-check cannot reach the public endpoint. |
| `HCP_HEARTBEAT_INTERVAL_MS` | `900000` (15 min) | Override the heartbeat interval. Mainly for tests. |
| `HCP_DEBUG` | (unset) | When set to `1`, registers a `POST /debug/heartbeat` endpoint for testing. Off in production. |

The `HCP_` prefix is historical (the project was previously named Human Credit Protocol). The variable names are retained to avoid breaking existing operator scripts.

---

## Endpoints

The witness exposes the following HTTP endpoints. Full payload shapes are in the protocol spec at humanexchangeprotocol.org.

| Endpoint | Purpose |
| --- | --- |
| `GET /status` | Health check. Returns version, pubkey, uptime, witnessed-mint count. |
| `GET /stats` | Public aggregate counters. Daily-grain only, no identifiers. |
| `POST /witness` | Submit a cooperative-act mint for attestation. |
| `POST /ping` | Proof-of-human heartbeat attestation. |
| `PUT /relay/:id` | Deposit a settlement payload for a counterparty to retrieve. |
| `GET /relay/:id` | Retrieve a deposited settlement. |
| `POST /pair` | Submit a pairing-code half. |
| `GET /pair/check/:code` | Poll pairing-code resolution. |
| `POST /session/join` | Join an exchange session by code. |
| `GET /session/:code` | Poll session state. |
| `POST /session/:code/thread` | Push a thread snapshot to the session. |
| `POST /session/:code/propose` | Submit a proposal in a session. |
| `POST /session/:code/confirm` | Confirm a proposal in a session. |
| `POST /announce` | Register this witness or a peer in the gossip network. Signed-mode variant carries an Ed25519 signature. |
| `GET /peers` | List active peer witnesses. `?signed=1` returns the list inside a signed envelope. |
| `POST /update` | Signed self-update broadcast. Used by peers to push current endpoint info. |

The signed-mode endpoints (`POST /announce` signed variant, `GET /peers?signed=1`, `POST /update`) are part of the cryptographic-identity protocol. Clients verify the returned signatures against pubkeys they already trust.

The witness never exposes raw chain content, message contents, or counterparty identities. Everything the witness sees is hashed before reaching the wire.

---

## Troubleshooting

**`npm install` fails with permission errors.** You may have run an earlier command with `sudo` and ended up with files owned by root. Fix ownership: `sudo chown -R $(whoami):$(whoami) ~/witness-server`.

**`Error: EADDRINUSE :::3141`.** Something else is on port 3141. Find and stop it, or use a different port: `HCP_PORT=4242 node server.js`.

**`/status` returns nothing or connection refused.** The server is not running. Check `sudo systemctl status hep-witness` if you set up the service, or look at the terminal where you ran `node server.js`.

**The Pi's local IP keeps changing.** Set a DHCP reservation in your router admin so the Pi gets the same local IP every time.

**Fresh Pi boots but does not appear on the network after a Pi Imager wifi customization.** Observed on at least one install. Workaround: boot via ethernet, then configure wifi directly on the device (`sudo raspi-config` or `nmcli`). Investigation is ongoing; if you have hit this, an issue with your Pi model, OS image, and gateway brand is welcome.

**Witness boots with a new pubkey when I expected the old one.** Something happened to `server_key.json`. Stop the witness immediately. Check whether you have a backup of the original key file. If not, the previous identity is gone; you are now running a new witness. Restore the backup over the new file (with the witness stopped), then start the witness and confirm via `/status` that the original pubkey is back.

**After an upgrade, `/status` returns 502 or the witness will not start.** Check `sudo journalctl -u hep-witness -n 50 --no-pager`. The most common cause is a missed `npm install` after a `git pull` introduced a new dependency.

---

## Where to get help

- Issues: [github.com/humanexchangeprotocol/witness-server/issues](https://github.com/humanexchangeprotocol/witness-server/issues)
- Project home: [humanexchangeprotocol.org](https://humanexchangeprotocol.org)

---

## License

MIT. See LICENSE.
