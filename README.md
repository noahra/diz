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
