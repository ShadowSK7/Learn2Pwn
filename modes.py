"""
Vulnerability modes for the Learn2Pwn bank app.

Each mode turns on a set of vulnerability switches ("vulns"). Code in app.py
checks them with `vuln("name")`, so one codebase serves every mode, plus a
`secure` mode that has all of them fixed.
"""

MODES = {
    "secure": {
        "title": "Secure reference",
        "goal": "Nothing to exploit (hopefully). Compare against the vulnerable modes.",
        "vulns": set(),
        "flag": None,
    },
    "hidden_admin": {
        "title": "Level 1 - Hidden admin panel",
        "goal": "Find the admin panel and get $2,000.00 into your own account.",
        "vulns": {"unauth_admin_panel"},
        "flag": "L2P{h1dd3n_d03s_n0t_m34n_pr0t3ct3d}",
        "flag_min_balance_cents": 2000_00,
    },
    "idor": {
        "title": "Level 2 - IDOR on account statements",
        "goal": "Read the private statement of the bank's VIP customer.",
        "vulns": {"idor_statement"},
        # Planted in a transaction memo on the VIP's account (see SEED_* in app.py).
        "flag": "L2P{1d0r_m34ns_ch4ng1ng_0n3_numb3r}",
    },
    "sqli": {
        "title": "Level 3 - SQL injection in transaction search",
        "goal": "Extract the vault master code from the bank's database.",
        "vulns": {"sqli_search"},
        # Written into the bank_vault table at startup (see sync_mode_data in app.py).
        "flag": "L2P{un10n_s3l3ct_th3_v4ult}",
    },
    "xss": {
        "title": "Level 4 - Reflected XSS in transaction search",
        "goal": "Execute JavaScript on the transactions page to read the hidden flag.",
        "vulns": {"xss_search"},
        # Embedded as a JS variable on the transactions page; never stored in the DB.
        "flag": "L2P{x55_g03s_wh3r3_y0u_d0nt_3xp3ct}",
    },
    "race": {
        "title": "Level 5 - Race condition in money transfers",
        "goal": "Fire concurrent transfers to double-spend your $100 starting balance"
                " into $500+ on a second account.",
        "vulns": {"race_transfer"},
        "flag": "L2P{t0ct0u_tw0_wr1t3rs_0n3_b4l4nc3}",
        "flag_min_balance_cents": 500_00,
    },
    "csrf": {
        "title": "Level 6 - CSRF on the transfer form",
        "goal": "Get the victim's browser to send you money without ever knowing her password.",
        "vulns": {"csrf_transfer"},
        "flag": "L2P{n0_t0k3n_n0_pr0bl3m_f0r_th3_4tt4ck3r}",
        "flag_min_balance_cents": 1000_00,
    },
}

DEFAULT_MODE = "hidden_admin"
