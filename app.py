#!/usr/bin/env python3
"""
Learn2Pwn Bank - a deliberately vulnerable banking web app for practice.

    python3 app.py --mode hidden_admin
    python3 app.py --list-modes

DO NOT expose this to the internet. It is insecure on purpose.
"""
import argparse
import os
import secrets
import sqlite3
import sys
import time
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect,
                   render_template, request, session, url_for)
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
    return {"user": current_user(), "mode_name": app.config["MODE"], "mode": mode()}


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

# Bump this whenever seed data or schema changes; older databases get re-seeded.
SEED_VERSION = 3

SEED_USERS = [
    # id order matters: transactions below refer to these ids.
    # username, full name, is_admin, balance (cents), password (None = random)
    ("admin", "Bank Administrator", 1, 0, None),                 # 1
    ("alice", "Alice Novak", 0, 5_420_17, "alice123"),           # 2
    ("bob", "Bob Horvath", 0, 312_50, "bob123"),                 # 3
    ("rvance", "Richard Vance (VIP)", 0, 1_250_000_00, None),    # 4
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


def prepare_db(mode_name, reset=False):
    init_db(reset=reset)
    sync_mode_data(mode_name)


def init_db(reset=False):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    if os.path.exists(DB_PATH) and not reset:
        db = sqlite3.connect(DB_PATH)
        version = db.execute("PRAGMA user_version").fetchone()[0]
        db.close()
        if version == SEED_VERSION:
            return
        print("[*] Database is from an older version of the app, re-seeding it.")
        reset = True
    if reset and os.path.exists(DB_PATH):
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
    db.execute(f"PRAGMA user_version = {SEED_VERSION}")
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
    body = "User-agent: *\nDisallow: /admin-panel\n"
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


@app.route("/admin-panel")
@admin_required
def admin_panel():
    users = get_db().execute("SELECT * FROM users ORDER BY id").fetchall()
    total = sum(u["balance_cents"] for u in users)
    return render_template("admin.html", users=users, total=total)


@app.route("/admin-panel/adjust", methods=["POST"])
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


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


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
    parser.add_argument("--reset", action="store_true", help="wipe and re-seed the database")
    parser.add_argument("--list-modes", action="store_true", help="list modes and exit")
    parser.add_argument("--debug", action="store_true", help="enable Flask debug mode")
    args = parser.parse_args()

    if args.list_modes:
        for name, m in MODES.items():
            print(f"  {name:<16} {m['title']}\n  {'':<16} goal: {m['goal']}\n")
        return 0

    app.config["MODE"] = args.mode
    prepare_db(args.mode, reset=args.reset)

    m = MODES[args.mode]
    print("=" * 64)
    print(" Learn2Pwn Bank - DELIBERATELY VULNERABLE, do not expose publicly")
    print(f" Mode : {args.mode} ({m['title']})")
    print(f" Goal : {m['goal']}")
    print(f" URL  : http://{args.host}:{args.port}/")
    print("=" * 64)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(" WARNING: listening on a non-loopback address!", file=sys.stderr)

    # threaded: lets the dev server handle more than one request at a time,
    # which several modes (e.g. race) rely on to be exploitable at all.
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
