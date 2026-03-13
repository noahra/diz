<p align="center">
  <img src="diz.svg" alt="diz" />
</p>

# diz

> Ever tried to SSH into another machine and somehow ended up spending 20 minutes copying keys around like it's 2003?
>
> Yeah. Same.
>
> **diz** fixes that.

Run one command on each machine, share a short code, and you're in. No key juggling required.

---

## How it works

**On the machine you want to connect to:**

![server](demo-server.gif)

**On your machine:**

![client](demo-client.gif)

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

| Command                    | What it does                                        |
| -------------------------- | --------------------------------------------------- |
| `diz --listen`             | Advertise this machine and wait for a key           |
| `diz --listen --pb`        | Same, but copy the share code to clipboard          |
| `diz --connect <code>`     | Send your key and SSH in                            |

---

## Using diz across the internet

diz uses your local network IP, so it works out of the box on the same network. For connecting between machines in different locations, pair it with [Tailscale](https://tailscale.com), a free VPN that gives every machine a stable private IP that works globally. Once Tailscale is running, `diz` works exactly the same way across any distance.

---

## Security

diz uses TLS with certificate pinning for the key exchange. The connection is encrypted end-to-end and protected against man-in-the-middle attacks. Each session generates a one-time certificate, and the fingerprint is embedded in the share code, so any tampering is detected and the connection is aborted immediately.
