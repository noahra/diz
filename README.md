# diz

> Have you ever tried to SSH into another machine, only to spend 20 minutes copying keys around like it's 2003 and you're configuring a router? Yeah. Same.

**diz** fixes that. One command on each machine, share a short code, done. You're in.

---

## How it works

**On the machine you want to connect to:**

```bash
diz --listen
# → Share this code: 3vQB7B6MiUc9fNe2...
```

**On your machine:**

```bash
diz --connect 3vQB7B6MiUc9fNe2...
# → key exchanged, SSH session starts automatically
```

That's it. diz opens a temporary authenticated channel, swaps your public key, adds it to `authorized_keys`, and drops you straight into a shell. No file copying, no manual editing, no crying.

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

| Command                | What it does                              |
| ---------------------- | ----------------------------------------- |
| `diz --listen`         | Advertise this machine and wait for a key |
| `diz --connect <code>` | Send your key and SSH in                  |
| `diz -gk`              | Generate a new ed25519 key pair           |
