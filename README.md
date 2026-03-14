<p align="center">
  <img src="diz.svg" alt="diz" />
</p>

# diz

**diz is like [Magic Wormhole](https://magic-wormhole.readthedocs.io/en/latest/) but for SSH key exchange.**

Run one command on each machine, share a short code, and you have authenticated SSH access. No manual key copying, no password auth, no editing `authorized_keys` by hand.

The code encodes everything needed for a secure first contact — IP, port, a one-time token, and a TLS certificate fingerprint. The connection is encrypted and pinned against MITM from the start.

---

## How it works

**Machine A — the machine you want to connect to:**

![server](demo-server.gif)

```bash
diz --listen
```

**Machine B — your machine:**

![client](demo-client.gif)

```bash
diz --connect <code>
```

diz opens a temporary authenticated channel, swaps your public key, adds it to `authorized_keys`, and drops you straight into a shell. No file copying, no manual editing, no crying.

---

## Install

**macOS**

```bash
brew tap noahra/diz
brew install diz
```

**Arch Linux**

```bash
yay -S diz-bin
```

---

## All commands

| Command                          | What it does                                              |
| -------------------------------- | --------------------------------------------------------- |
| `diz --listen`                   | Advertise this machine and wait for a key                 |
| `diz --listen -p`                | Same, but copy the share code to clipboard                |
| `diz --connect <code>`           | Send your key and SSH in                                  |
| `diz --connect <code> --temp`    | Same, but delete the generated SSH keys after the session ends (useful on shared or borrowed machines) |

---

## Using diz across the internet

diz uses your local network IP, so it works out of the box on the same network. For connecting between machines in different locations, pair it with a VPN such as [Tailscale](https://tailscale.com), [ZeroTier](https://www.zerotier.com), or [WireGuard](https://www.wireguard.com). Once both machines are on the same virtual network, `diz` works exactly the same way across any distance.

---

## Security

diz uses TLS with certificate pinning for the key exchange. The connection is encrypted end-to-end and protected against man-in-the-middle attacks. Each session generates a one-time certificate, and the fingerprint is embedded in the share code, so any tampering is detected and the connection is aborted immediately.

## Threat model & honest limitations

diz is **not** trying to replace ssh-copy-id when you already have access.
It is for the narrow case where:
- You can run a command on both machines
- You can share a short code out-of-band (chat, voice, in-person, Signal, etc.)
- You do NOT want to manually copy-paste/type a 70+ character base64 pubkey

It is intentionally **short-lived and single-use**.
It is **not** appropriate for:
- High-security production servers
- Environments where you cannot verify the share-code out-of-band
- Situations where both machines are behind aggressive NAT without VPN

Security properties:
- TLS + cert fingerprint pinning via out-of-band code
- One-time 128-bit token
- No persistent listener
- No central server / relay