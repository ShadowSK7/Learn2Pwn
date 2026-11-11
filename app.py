#!/usr/bin/env python3
"""
Learn2Pwn Bank - a deliberately vulnerable banking web app for practice.

    python3 app.py --mode hidden_admin
    python3 app.py --list-modes

DO NOT expose this to the internet. It is insecure on purpose.
"""
import argparse
import http.cookiejar
import ipaddress
import json
import os
import secrets
import socket
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from functools import wraps
from html.parser import HTMLParser

from flask import (Flask, Response, abort, flash, g, redirect,
                   render_template, request, session, stream_with_context, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from modes import DEFAULT_MODE, MODES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "bank.db")
NEW_ACCOUNT_BALANCE_CENTS = 100_00

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)
app.config["MODE"] = DEFAULT_MODE


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def mode():
    return MODES[app.config["MODE"]]


def vuln(name):
    """True if the given vulnerability is switched on in the current mode."""
    return name in mode()["vulns"]


def get_db():
    if "db" not in g:
        # timeout: wait for a writer lock instead of failing immediately -
        # concurrent requests (see the race mode) can otherwise collide.
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def current_user():
    uid = session.get("user_id")
    if uid is None:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def get_csrf_token():
    """A per-session token for the synchronizer-token CSRF defense.

    It is not rotated on use (like most real frameworks' defaults): an
    attacker-forged request never has a copy of it, which is all that
    matters, and a page that's been open in a browser for a while can
    still submit forms without a stale-token error.
    """
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def parse_amount_cents(raw, allow_negative=False):
    """Parse a dollar string like '12.50' into integer cents, or None."""
    try:
        value = round(float(raw) * 100)
    except (TypeError, ValueError):
        return None
    if value == 0 or (value < 0 and not allow_negative):
        return None
    if abs(value) > 1_000_000_00:
        return None
    return value


@app.template_filter("money")
def money(cents):
    sign = "-" if cents < 0 else ""
    return f"{sign}${abs(cents) / 100:,.2f}"


@app.context_processor
def inject_globals():
    return {"user": current_user(), "mode_name": app.config["MODE"], "mode": mode(),
            "csrf_token": get_csrf_token}


# --------------------------------------------------------------------------
# Database setup
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    balance_cents INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE transactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user    INTEGER REFERENCES users(id),
    to_user      INTEGER REFERENCES users(id),
    amount_cents INTEGER NOT NULL,
    memo         TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE bank_vault (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    label  TEXT UNIQUE NOT NULL,
    secret TEXT NOT NULL
);
"""

# The csrf-lab "victim bot" (see run_victim_bot below) logs this account in for
# real over HTTP, exactly like a browser would, using a password only the
# server itself knows - the player never sees it and never needs to.
VICTIM_USERNAME = "nora"
_VICTIM_PASSWORD = secrets.token_urlsafe(24)

SEED_USERS = [
    # id order matters: transactions below refer to these ids, and so do
    # some hardcoded account numbers in SOLUTIONS.md - append, don't insert.
    # username, full name, is_admin, balance (cents), password (None = random)
    ("admin", "Bank Administrator", 1, 0, None),                       # 1
    ("alice", "Alice Novak", 0, 5_420_17, "alice123"),                 # 2
    ("bob", "Bob Horvath", 0, 312_50, "bob123"),                       # 3
    ("rvance", "Richard Vance (VIP)", 0, 1_250_000_00, None),          # 4
    (VICTIM_USERNAME, "Nora Kessler", 0, 3_000_00, _VICTIM_PASSWORD),  # 5
]

SEED_TRANSACTIONS = [
    # from_user, to_user, amount (cents), memo
    (3, 2, 45_00, "Pizza night"),
    (None, 4, 1_000_000_00, "Wire in - Vance Holdings Ltd."),
    (4, 2, 2_500_00, "Consulting retainer"),
    (None, 4, 250_000_00, "Dividend payout Q3"),
    # to_user NULL = paid to the bank itself. sync_mode_data() fills in the code.
    (4, None, 25_00, "Safe deposit box #7 rental"),
    (4, 3, 120_00, "Car detailing"),
]

SEED_VAULT = ["hsm_backup_pin", "core_banking_api_key", "vault_master_code", "swift_operator_token"]


def sync_mode_data(mode_name):
    """Write each mode's flag into the database only while that mode is active.

    The database persists across modes, so without this, one mode's bug (e.g.
    SQL injection dumping every table) could leak another mode's flag.
    """
    def flag_if(m):
        return MODES[m]["flag"] if mode_name == m else None

    db = sqlite3.connect(DB_PATH)
    idor = flag_if("idor")
    db.execute(
        "UPDATE transactions SET memo = ?"
        " WHERE from_user = 4 AND to_user IS NULL AND memo LIKE 'Safe deposit box #7%'",
        (f"Safe deposit box #7 rental, code: {idor}" if idor else "Safe deposit box #7 rental",),
    )
    for label in SEED_VAULT:
        value = secrets.token_hex(16)
        if label == "vault_master_code" and flag_if("sqli"):
            value = flag_if("sqli")
        db.execute("UPDATE bank_vault SET secret = ? WHERE label = ?", (value, label))
    db.commit()
    db.close()


def prepare_db(mode_name):
    init_db()
    sync_mode_data(mode_name)


def init_db():
    """Always starts from a clean, freshly-seeded database. Simpler and more
    predictable for a classroom session than a --reset flag you have to
    remember - every run starts the same way, with everyone's balances and
    the monitoring board both back to a known state."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    for username, full_name, is_admin, balance, password in SEED_USERS:
        password = password or secrets.token_urlsafe(24)
        db.execute(
            "INSERT INTO users (username, password_hash, full_name, is_admin, balance_cents)"
            " VALUES (?, ?, ?, ?, ?)",
            (username, generate_password_hash(password), full_name, is_admin, balance),
        )
    db.executemany("INSERT INTO transactions (from_user, to_user, amount_cents, memo)"
                   " VALUES (?, ?, ?, ?)", SEED_TRANSACTIONS)
    db.executemany("INSERT INTO bank_vault (label, secret) VALUES (?, '')",
                   [(label,) for label in SEED_VAULT])
    db.commit()
    db.close()


# --------------------------------------------------------------------------
# Public pages
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if current_user() else "login"))


@app.route("/robots.txt")
def robots():
    body = "User-agent: *\nDisallow: /admin_manage\n"
    return Response(body, mimetype="text/plain")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        if not (3 <= len(username) <= 32 and username.isalnum()):
            flash("Username must be 3-32 letters or digits.", "error")
        elif not full_name or len(full_name) > 64:
            flash("Please enter your full name (max 64 chars).", "error")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
        else:
            db = get_db()
            try:
                cur = db.execute(
                    "INSERT INTO users (username, password_hash, full_name, balance_cents)"
                    " VALUES (?, ?, ?, ?)",
                    (username, generate_password_hash(password), full_name,
                     NEW_ACCOUNT_BALANCE_CENTS),
                )
                db.execute(
                    "INSERT INTO transactions (from_user, to_user, amount_cents, memo)"
                    " VALUES (NULL, ?, ?, 'Welcome bonus')",
                    (cur.lastrowid, NEW_ACCOUNT_BALANCE_CENTS),
                )
                db.commit()
            except sqlite3.IntegrityError:
                flash("That username is taken.", "error")
            else:
                session.clear()
                session["user_id"] = cur.lastrowid
                flash("Account created. Welcome to Learn2Pwn Bank!", "ok")
                return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        row = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user_id"] = row["id"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Banking
# --------------------------------------------------------------------------
def flag_for(user):
    """Return the mode's flag if this user has reached the goal."""
    m = mode()
    if not m.get("flag") or user["is_admin"]:
        return None
    if user["balance_cents"] >= m.get("flag_min_balance_cents", float("inf")):
        return m["flag"]
    return None


def transactions_for(account_id, limit=-1):
    """All transactions touching an account, newest first (limit -1 = no limit)."""
    return get_db().execute(
        """SELECT t.*, fu.username AS from_name, tu.username AS to_name
           FROM transactions t
           LEFT JOIN users fu ON fu.id = t.from_user
           LEFT JOIN users tu ON tu.id = t.to_user
           WHERE t.from_user = ? OR t.to_user = ?
           ORDER BY t.id DESC LIMIT ?""",
        (account_id, account_id, limit),
    ).fetchall()


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    return render_template("dashboard.html", txs=transactions_for(user["id"], 5),
                           flag=flag_for(user))


SEARCH_SQL = """
    SELECT t.id, t.created_at, fu.username AS from_name, tu.username AS to_name,
           t.from_user, t.to_user, t.memo, t.amount_cents
    FROM transactions t
    LEFT JOIN users fu ON fu.id = t.from_user
    LEFT JOIN users tu ON tu.id = t.to_user
    WHERE (t.from_user = {uid} OR t.to_user = {uid}) AND t.memo LIKE {pattern} ORDER BY t.id DESC
"""


@app.route("/transactions")
@login_required
def search_transactions():
    user = current_user()
    q = request.args.get("q", "")
    db = get_db()
    txs, error = [], None
    if vuln("sqli_search"):
        # VULN sqli_search: the search term is pasted straight into the SQL
        # string, and database errors are shown to the user.
        sql = SEARCH_SQL.format(uid=user["id"], pattern=f"'%{q}%'")
        try:
            txs = db.execute(sql).fetchall()
        except sqlite3.Error as e:
            error = f"Database error: {e}"
    else:
        sql = SEARCH_SQL.format(uid=":uid", pattern=":pattern")
        txs = db.execute(sql, {"uid": user["id"], "pattern": f"%{q}%"}).fetchall()
    xss_flag = mode()["flag"] if vuln("xss_search") else None
    return render_template("transactions.html", q=q, txs=txs, error=error, xss_flag=xss_flag)


@app.route("/account/<int:account_id>/statement")
@login_required
def statement(account_id):
    user = current_user()
    # VULN idor_statement: the account id comes straight from the URL and is
    # never checked against the logged-in user, so any account can be viewed.
    if not vuln("idor_statement"):
        if account_id != user["id"] and not user["is_admin"]:
            abort(404)
    owner = get_db().execute("SELECT * FROM users WHERE id = ?", (account_id,)).fetchone()
    if owner is None:
        abort(404)
    return render_template("statement.html", owner=owner, txs=transactions_for(owner["id"]))


@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    user = current_user()
    # VULN csrf_transfer: every other mode requires a token that only a page
    # served by this site could have read out of the user's own session, so
    # a form hosted on another origin can't forge a valid transfer. This
    # mode skips that check entirely - see the CSRF lab for what that costs.
    if not vuln("csrf_transfer") and request.form.get("csrf_token") != session.get("csrf_token"):
        flash("Your request couldn't be verified (missing or invalid CSRF token). Please try again.",
              "error")
        return redirect(url_for("dashboard"))
    to_username = request.form.get("to", "").strip().lower()
    memo = request.form.get("memo", "").strip()[:140]
    amount = parse_amount_cents(request.form.get("amount"))
    db = get_db()
    recipient = db.execute("SELECT * FROM users WHERE username = ?", (to_username,)).fetchone()

    if amount is None:
        flash("Enter a valid positive amount.", "error")
    elif recipient is None:
        flash("Recipient not found.", "error")
    elif recipient["id"] == user["id"]:
        flash("You can't send money to yourself.", "error")
    elif amount > user["balance_cents"]:
        flash("Insufficient funds.", "error")
    elif vuln("race_transfer"):
        # VULN race_transfer: checks the sender's balance, then (after a
        # deliberate delay that widens the window) writes back a balance
        # computed from that stale read instead of a fresh, atomic
        # decrement. Two concurrent transfers can both pass the check
        # above against the same starting balance, and both later
        # overwrite it from the same stale snapshot - a classic TOCTOU /
        # lost-update bug. The recipient is still credited for every
        # request that gets this far, so money is created out of nowhere.
        stale_balance = user["balance_cents"]
        time.sleep(0.2)
        db.execute("UPDATE users SET balance_cents = ? WHERE id = ?",
                   (stale_balance - amount, user["id"]))
        db.execute("UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
                   (amount, recipient["id"]))
        db.execute("INSERT INTO transactions (from_user, to_user, amount_cents, memo)"
                   " VALUES (?, ?, ?, ?)", (user["id"], recipient["id"], amount, memo))
        db.commit()
        flash(f"Sent {money(amount)} to {recipient['username']}.", "ok")
    else:
        # Atomic, single-statement check-and-decrement: the WHERE clause
        # re-verifies the balance at write time, so a concurrent request
        # that already spent the money can't also succeed.
        cur = db.execute(
            "UPDATE users SET balance_cents = balance_cents - ?"
            " WHERE id = ? AND balance_cents >= ?", (amount, user["id"], amount))
        if cur.rowcount == 0:
            db.rollback()
            flash("Insufficient funds.", "error")
        else:
            db.execute("UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
                       (amount, recipient["id"]))
            db.execute("INSERT INTO transactions (from_user, to_user, amount_cents, memo)"
                       " VALUES (?, ?, ?, ?)", (user["id"], recipient["id"], amount, memo))
            db.commit()
            flash(f"Sent {money(amount)} to {recipient['username']}.", "ok")
    return redirect(url_for("dashboard"))


# --------------------------------------------------------------------------
# Admin panel
# --------------------------------------------------------------------------
def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # VULN unauth_admin_panel: the panel is only "protected" by not being
        # linked anywhere. No authentication or authorization check at all.
        if not vuln("unauth_admin_panel"):
            user = current_user()
            if user is None or not user["is_admin"]:
                abort(404)  # don't even reveal that the panel exists
        return view(*args, **kwargs)
    return wrapped


@app.route("/admin_manage")
@admin_required
def admin_panel():
    users = get_db().execute("SELECT * FROM users ORDER BY id").fetchall()
    total = sum(u["balance_cents"] for u in users)
    return render_template("admin.html", users=users, total=total)


@app.route("/admin_manage/adjust", methods=["POST"])
@admin_required
def admin_adjust():
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id = ?",
                        (request.form.get("user_id"),)).fetchone()
    amount = parse_amount_cents(request.form.get("amount"), allow_negative=True)
    memo = request.form.get("memo", "").strip()[:140] or "Manual adjustment"
    if target is None or amount is None:
        flash("Pick a user and a non-zero amount.", "error")
    else:
        db.execute("UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
                   (amount, target["id"]))
        db.execute("INSERT INTO transactions (from_user, to_user, amount_cents, memo)"
                   " VALUES (NULL, ?, ?, ?)", (target["id"], amount, memo))
        db.commit()
        flash(f"Adjusted {target['username']} by {money(amount)}.", "ok")
    return redirect(url_for("admin_panel"))


# --------------------------------------------------------------------------
# CSRF lab: a "victim bot" that simulates a logged-in browser visiting
# whatever page you give it, so you can test a real forged-request attack
# end to end without needing an actual second person or browser.
# --------------------------------------------------------------------------
class _FirstFormExtractor(HTMLParser):
    """Pulls the action/method/fields out of the first <form> on a page."""

    def __init__(self):
        super().__init__()
        self._in_form = False
        self.form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and self.form is None:
            self._in_form = True
            self.form = {"action": attrs.get("action", ""),
                        "method": attrs.get("method", "get").upper(), "inputs": {}}
        elif tag == "input" and self._in_form and attrs.get("name"):
            self.form["inputs"][attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self._in_form = False


def _is_lab_network_url(url):
    """Restrict the bot to private/loopback addresses (localhost, plus the
    RFC 1918 ranges a VM lab subnet uses), so it can follow a two-VM setup
    (attack box hosting the exploit page) without turning into an SSRF
    tool against the public internet. The hostname is actually resolved,
    not just string-matched, so "localhost.example.com"-style tricks can't
    sneak a public address past this check."""
    try:
        host = urllib.parse.urlparse(url).hostname
        if not host:
            return False
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except (ValueError, OSError):
        return False
    return ip.is_private  # covers loopback, 10/8, 172.16/12, 192.168/16, link-local, etc.


def _nora_balance():
    row = get_db().execute("SELECT balance_cents FROM users WHERE username = ?",
                          (VICTIM_USERNAME,)).fetchone()
    return row["balance_cents"] if row else 0


def run_victim_bot(attacker_url, bank_base):
    """Simulate the victim's already-logged-in browser visiting attacker_url.

    This is a real HTTP client with its own cookie jar - it logs in as the
    victim over actual HTTP, fetches whatever page you host, and submits
    whatever <form> it finds there, carrying the victim's session cookie.
    Nothing here is mocked; it exercises the exact same /login and /transfer
    code paths a real browser would.
    """
    log = []
    if not _is_lab_network_url(attacker_url):
        return {"ok": False, "log": ["Refused: the bot only visits private-network addresses"
                                    " (localhost, or a 10.x/172.16.x/192.168.x lab IP), never the"
                                    " public internet. Host your page with e.g."
                                    " `python3 -m http.server 8000` - on this machine, or on"
                                    " another VM on the same lab subnet - and give the bot that URL."]}

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        opener.open(f"{bank_base}/login", urllib.parse.urlencode(
            {"username": VICTIM_USERNAME, "password": _VICTIM_PASSWORD}).encode(), timeout=5)
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "log": [f"Bot couldn't reach the bank to log in: {e}"]}
    log.append("Bot logged in as the victim over HTTP (simulating her already-open session).")

    try:
        with opener.open(attacker_url, timeout=5) as resp:
            page_html = resp.read(200_000).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "log": log + [f"Could not fetch {attacker_url}: {e}"]}
    log.append(f"Bot fetched {attacker_url}")

    parser = _FirstFormExtractor()
    parser.feed(page_html)
    form = parser.form
    if not form or not form["action"]:
        return {"ok": False, "log": log + ["No <form action=\"...\"> was found on that page."]}

    action_url = urllib.parse.urljoin(attacker_url, form["action"])
    if not _is_lab_network_url(action_url):
        return {"ok": False, "log": log + [f"Refused: the form's action ({action_url}) isn't a"
                                           " private-network bank URL."]}
    log.append(f"Found a form: method={form['method']} action={action_url} fields={form['inputs']}")

    query = urllib.parse.urlencode(form["inputs"])
    if form["method"] == "POST":
        req = urllib.request.Request(action_url, data=query.encode(), method="POST")
    else:
        req = urllib.request.Request(f"{action_url}?{query}", method="GET")
    try:
        with opener.open(req, timeout=5) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "log": log + [f"The forged request failed: {e}"]}
    log.append(f"Bot submitted the form as the victim -> HTTP {status}")
    log.append(f"The victim's balance is now {money(_nora_balance())}.")
    return {"ok": True, "log": log}


@app.route("/csrf-lab")
@login_required
def csrf_lab():
    return render_template("csrf_lab.html", report=None, last_url="", nora_balance=_nora_balance())


@app.route("/csrf-lab/run-bot", methods=["POST"])
@login_required
def csrf_lab_run_bot():
    url = request.form.get("url", "").strip()
    report = run_victim_bot(url, request.host_url.rstrip("/")) if url else \
        {"ok": False, "log": ["Give the bot a URL to visit first."]}
    return render_template("csrf_lab.html", report=report, last_url=url, nora_balance=_nora_balance())


# --------------------------------------------------------------------------
# Monitoring board: a public, in-memory "who found it" scoreboard. Anyone
# can submit the flag for whichever mode is currently running and have
# their name show up live on /monitoring. Deliberately not persisted to
# the database - it's a classroom convenience, not part of any level, and
# resets whenever the server restarts.
# --------------------------------------------------------------------------
_BOARD_MAX = 10
_board_lock = threading.Lock()
_board = deque(maxlen=_BOARD_MAX)  # newest first
_board_version = 0


def _board_add(username, flag, mode_title):
    global _board_version
    with _board_lock:
        _board.appendleft({"username": username, "flag": flag, "mode": mode_title,
                          "time": time.strftime("%Y-%m-%d %H:%M:%S")})
        _board_version += 1


def _board_snapshot():
    with _board_lock:
        return list(_board), _board_version


@app.route("/monitoring")
def monitoring():
    board, _ = _board_snapshot()
    return render_template("monitoring.html", board=board)


@app.route("/monitoring/stream")
def monitoring_stream():
    # Server-Sent Events: a plain long-lived HTTP response, one line of
    # "data: ..." per update. No extra dependency (unlike real WebSockets),
    # at the cost of being push-only - which is all this needs. Each
    # connection is its own thread polling a shared in-memory version
    # counter twice a second; fine for a classroom, not meant to scale
    # past that.
    def gen():
        last_version = -1
        while True:
            board, version = _board_snapshot()
            if version != last_version:
                last_version = version
                yield f"data: {json.dumps(board)}\n\n"
            time.sleep(0.5)

    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/verify", methods=["GET", "POST"])
def verify():
    """Two-step, stateless flag verification: submit the flag; if it
    matches the mode currently running, a second form asks for a display
    name, then adds {name, flag, mode, time} to the monitoring board."""
    stage, validated_flag, error, success = "flag", None, None, None
    if request.method == "POST":
        submitted_flag = request.form.get("flag", "").strip()
        current_flag = mode()["flag"]
        if request.form.get("stage") == "username":
            # The flag was already checked once to get here; check again
            # rather than trusting the hidden field blindly.
            if not current_flag or submitted_flag != current_flag:
                error = "That flag isn't valid for the level currently running. Start over."
            else:
                username = request.form.get("username", "").strip()[:32]
                if not username:
                    error = "Enter a name to show on the board."
                    stage, validated_flag = "username", submitted_flag
                else:
                    _board_add(username, submitted_flag, mode()["title"])
                    success = f'Added "{username}" to the monitoring board.'
        elif not current_flag:
            error = "This mode has no flag to verify (e.g. secure mode)."
        elif submitted_flag != current_flag:
            error = "Incorrect flag."
        else:
            stage, validated_flag = "username", submitted_flag
    return render_template("verify.html", stage=stage, validated_flag=validated_flag,
                           error=error, success=success)


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


def _lan_ip_guesses():
    """Best-effort list of this machine's non-loopback IPs, for the startup
    banner when binding to 0.0.0.0 - so you don't have to go run `ip a`
    yourself to find the address another VM on the lab network should use."""
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # UDP connect: just makes the kernel pick a local route/interface
            # for that destination, no packet is actually sent anywhere.
            s.connect(("10.255.255.255", 1))
            ips.add(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    ips.discard("127.0.0.1")
    return sorted(ips)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Learn2Pwn Bank - deliberately vulnerable app")
    parser.add_argument("--mode", default=DEFAULT_MODE, choices=sorted(MODES),
                        help=f"vulnerability mode (default: {DEFAULT_MODE})")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default: 127.0.0.1; use 0.0.0.0 with care)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--list-modes", action="store_true", help="list modes and exit")
    parser.add_argument("--debug", action="store_true", help="enable Flask debug mode")
    args = parser.parse_args()

    if args.list_modes:
        for name, m in MODES.items():
            print(f"  {name:<16} {m['title']}\n  {'':<16} goal: {m['goal']}\n")
        return 0

    app.config["MODE"] = args.mode
    prepare_db(args.mode)

    m = MODES[args.mode]
    print("=" * 64)
    print(" Learn2Pwn Bank - DELIBERATELY VULNERABLE, do not expose publicly")
    print(f" Mode : {args.mode} ({m['title']})")
    print(f" Goal : {m['goal']}")
    print(f" URL  : http://{args.host}:{args.port}/")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        lan_ips = _lan_ip_guesses()
        if lan_ips:
            print(" Reachable from other machines on your lab network at:")
            for ip in lan_ips:
                print(f"        http://{ip}:{args.port}/")
        else:
            print(" Could not auto-detect a LAN IP; run `ip a` or `hostname -I` to find one.")
    print("=" * 64)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(" WARNING: listening on a non-loopback address - only do this on an isolated"
              " lab/VM network, never on the open internet or a shared/corporate network.",
              file=sys.stderr)

    # threaded: lets the dev server handle more than one request at a time,
    # which several modes (e.g. race) rely on to be exploitable at all.
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
