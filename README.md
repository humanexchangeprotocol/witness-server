# HEP Witness Server

A small Node.js service that records cooperative-act attestations and relays encrypted messages between exchanging parties for the Human Exchange Protocol. Attestation only. Does not host the app, does not see message contents, does not store identity.

For details on what HEP is, see [humanexchangeprotocol.org](https://humanexchangeprotocol.org).

This README covers running a witness on a local machine or local network. **It deliberately does not cover public internet exposure.** How witnesses present themselves to the wider network is an active architectural decision. Current direction: cryptographic identity (Ed25519 public key), not domain-based. This README will grow as that decision lands.

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

Witness listens on port 3141. Configurable via the `HCP_PORT` environment variable.

On first run, the witness generates an Ed25519 signing key (`server_key.json`) and a SQLite database (`witness.db`) in the working directory. **Both files are private.** Back them up. Do not commit them. Do not share them. The signing key is the witness's identity; if it leaks, the witness is compromised.

Confirm the server is responding:

```bash
curl http://localhost:3141/status
```

You should see a JSON response with `version`, `witnessed_total`, and uptime info. The `server_pubkey` field is the witness's permanent identity.

---

## Step-by-step install on Raspberry Pi OS

This walks through a clean install on Raspberry Pi OS Bookworm. The same commands work on Ubuntu, Debian, and other Debian-derived systems. On non-Debian Linux, substitute your package manager for `apt`.

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

You should see:

```
[keys] Generated new server keypair
[keys] Public key: a1b2c3...
[db] Created new database
[server] Listening on port 3141
```

The witness is now running on your local network. Note your public key. From another device on the same network, you can reach the witness at `http://<pi-local-ip>:3141/status`.

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

---

## A note on hosting expectations

You do not need to run a 24/7 server to be useful. HEP is designed to be offline-first; witnesses are an enhancement, not a requirement. A network of imperfect hosts whose collective availability is high serves the protocol better than a few perfect ones. If your machine reboots once a week, sleeps overnight, or goes offline when you travel, that's fine. Honest participation matters more than uptime.

---

## What this README does not cover (yet)

- **Public internet exposure.** Reaching the witness from outside your local network. Pending the architectural decision on cryptographic versus domain-based witness identity.
- **Bandwidth limits inside the witness.** Currently handled at the network level (your router) rather than inside the server. Configurable per-witness rate limits are not yet built.
- **Multiple witnesses on one machine.** Possible by running each on a different port. Not yet documented.

---

## Troubleshooting

**`npm install` fails with permission errors.** You may have run an earlier command with `sudo` and ended up with files owned by root. Fix ownership: `sudo chown -R $(whoami):$(whoami) ~/witness-server`.

**`Error: EADDRINUSE :::3141`.** Something else is on port 3141. Find and stop it, or use a different port: `HCP_PORT=4242 node server.js`.

**`/status` returns nothing or connection refused.** The server isn't running. Check `sudo systemctl status hep-witness` if you set up the service, or look at the terminal where you ran `node server.js`.

**The Pi's local IP keeps changing.** Set a DHCP reservation in your router admin so the Pi gets the same local IP every time.

---

## Where to get help

- Issues: [github.com/humanexchangeprotocol/witness-server/issues](https://github.com/humanexchangeprotocol/witness-server/issues)
- Project home: [humanexchangeprotocol.org](https://humanexchangeprotocol.org)

---

## License

MIT. See LICENSE.
