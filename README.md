# Learn2Pwn Bank

A deliberately vulnerable online-banking web app for practicing web exploitation.
Which vulnerabilities are live depends on the **mode** you pick at startup.

> **Warning:** this app is insecure on purpose. Run it only on your own machine or an
> isolated lab network. It binds to `127.0.0.1` by default.

## Quick start (Ubuntu)

```bash
sudo apt install python3 python3-venv
chmod +x run.sh
./run.sh --mode hidden_admin
```

Then open http://127.0.0.1:5000/, create an account, and go for the goal.

Without the helper script:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python3 app.py --mode hidden_admin
```

## Options

| Flag | Meaning |
|---|---|
| `--mode NAME` | vulnerability mode (default `hidden_admin`) |
| `--list-modes` | show all modes and their goals |
| `--reset` | wipe and re-seed the database (`instance/bank.db`) |
| `--host ADDR` | bind address, default `127.0.0.1` (use `0.0.0.0` for a lab VM) |
| `--port N` | port, default `5000` |
| `--debug` | Flask debug mode |

## Modes

| Mode | Goal |
|---|---|
| `hidden_admin` | Level 1: find the admin panel and get $2,000.00 into your own account. |
| `idor` | Level 2: read the private statement of the bank's VIP customer. |
| `sqli` | Level 3: extract the vault master code from the bank's database. |
| `xss` | Level 4: execute JavaScript on the transactions page to read the hidden flag. |
| `race` | Level 5: double-spend your $100 starting balance into $500+ via concurrent transfers. |
| `csrf` | Level 6: get the victim's browser to send you money, without her password. |
| `secure` | Every vulnerability fixed, as a reference. |

Flags look like `L2P{...}`. Depending on the mode, a flag appears on your dashboard
when you reach the goal, or it is hidden in data you shouldn't be able to see.
A flag is only written to the database while its own mode is running, so you can't
grab one mode's flag through another mode's bug.
Spoilers are in [SOLUTIONS.md](SOLUTIONS.md).

## Monitoring board

`/monitoring` is a public, live-updating scoreboard - anyone can open it, no login needed.
`/verify` lets anyone submit the flag for whichever mode is currently running; once it
checks out, they pick a display name and it shows up on the board within about half a
second (via Server-Sent Events, no extra dependency needed). It's a classroom convenience
for tracking who's solved the current level, not part of any level itself: the board lives
only in memory and is wiped whenever the server restarts, and it never touches the database.

## Running it as a network target (attack box on another VM)

By default the app only listens on `127.0.0.1` - nothing outside the machine can reach it.
To let a separate attack-box VM connect to it (the usual pentesting-lab setup: a "target"
VM running this app and a separate "attacker" VM running Burp/sqlmap/gobuster/etc.):

1. **Put both VMs on the same isolated virtual subnet.** In VirtualBox, use a *Host-only
   Adapter* or an *Internal Network* (give both VMs the same internal network name, e.g.
   `lab-net`); in VMware, a custom host-only `vmnet`. Don't bridge either VM to your real
   network or the internet - this app is deliberately vulnerable.
2. **Bind to all interfaces** on the target VM:
   ```bash
   ./run.sh --host 0.0.0.0 --mode hidden_admin
   ```
   The startup banner prints every address other machines on your lab network can reach it
   at, so you don't need to go run `ip a` yourself.
3. **If Ubuntu's firewall is on,** allow the port (swap `5000` for `--port` if you changed it):
   ```bash
   sudo ufw allow 5000/tcp
   ```
4. **From the attack box,** confirm connectivity, then point your tools at it:
   ```bash
   curl http://<target-ip>:5000/
   ```

The CSRF lab's "victim bot" (Level 6) will fetch an exploit page from any private-network
address (localhost or a `10.x`/`172.16.x`/`192.168.x` IP) - so you can host `exploit.html` on
the attack box itself, like a real attacker would, not just on the target VM. It refuses the
public internet either way, so this stays a closed lab exercise regardless of how you host it.

## Seed accounts

`alice / alice123` and `bob / bob123` are ordinary customers. The `admin` and VIP
accounts get random passwords on every database reset. `nora` is the CSRF lab's victim
account - her password is never shown anywhere; you're not meant to log in as her, only
to trick her browser (see `csrf` mode). If you start the app with a database from an
older version, it is re-seeded automatically.
