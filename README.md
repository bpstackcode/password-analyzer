# 🔐 Password Strength Analyzer & Breach Detection Engine

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python)](https://python.org)
[![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?style=for-the-badge&logo=sqlite)](https://sqlite.org)
[![Security](https://img.shields.io/badge/Domain-Credential_Security-red?style=for-the-badge)]()

-----

## Why This Project Exists

Weak and reused passwords are behind the majority of account takeover incidents. Security teams need tooling that can evaluate credential strength programmatically — not just flag “too short,” but quantify *how* attackable a password actually is and surface that risk in a way that drives action.

This tool does exactly that: it scores passwords using entropy-based mathematics, checks them against a breach database, and returns specific, actionable remediation feedback — the same logic that underlies enterprise credential hygiene policies aligned to NIST SP 800-63B.

-----

## Business Impact

|Risk                                                          |How This Addresses It                                                                   |
|--------------------------------------------------------------|----------------------------------------------------------------------------------------|
|Weak credentials are the #1 attack vector for account takeover|Entropy scoring quantifies actual brute-force resistance, not just rule compliance      |
|Users don’t know *why* their password is weak                 |Criteria breakdown gives specific, actionable feedback per check                        |
|Known-breached passwords bypass basic strength checks         |Breach database lookup catches compromised credentials that pass length/complexity rules|
|No audit trail for credential policy enforcement              |Every check is logged to SQLite with timestamp, score, and breach status                |

-----

## How It Works

```
User Input → Entropy Calculation → Strength Scoring → Breach Check → Logged Result
```

**Entropy calculation** measures the actual keyspace an attacker must search — a 14-character password mixing uppercase, lowercase, numbers, and symbols produces ~91 bits of entropy, meaning brute-force is computationally infeasible with current hardware.

**Breach check** compares the password against a local SQLite table of known-compromised credentials. A password can pass every complexity rule and still be in a breach dump — this step catches that gap.

**Audit logging** stores every check with a timestamp, score, rating, and breach flag — enabling historical analysis of credential hygiene trends across a user population.

-----

## Example Output

```
Enter password (or command): MyP@ssw0rd!22

Analysis for: **************  (hidden for privacy)
Score:    85/100
Rating:   STRONG 🔒
Length:   14 characters
Entropy:  91.28 bits

Criteria Breakdown:
  • Length               Excellent (14+ chars)
  • Uppercase            ✓ Present
  • Lowercase            ✓ Present
  • Numbers              ✓ Present
  • Special Chars        ✓ Present
  • No Repeats           ✓ No repeated characters

✅ Not found in breach database.
🎉 No suggestions — this is a strong password!
```

-----

## Database Schema

```sql
-- Full audit log of every credential check
CREATE TABLE check_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at  TEXT NOT NULL,
    length      INTEGER NOT NULL,
    score       INTEGER NOT NULL,
    rating      TEXT NOT NULL,
    breached    INTEGER NOT NULL   -- 1 = found in breach DB, 0 = clean
);

-- Simulated breach credential database
CREATE TABLE breached_passwords (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    password TEXT NOT NULL UNIQUE
);
```

-----

## Tech Stack

|Layer           |Technology                                          |
|----------------|----------------------------------------------------|
|Language        |Python 3 (standard library only — zero dependencies)|
|Database        |SQLite via Python `sqlite3` module                  |
|Security Logic  |Entropy math, regex pattern analysis, breach lookup |
|Data Persistence|Parameterized SQL queries (injection-safe)          |

-----

## Project Structure

```
password-analyzer/
├── password_analyzer.py   # Core engine — scoring, entropy, breach check, logging
├── password_checks.db     # SQLite audit log (auto-created on first run)
└── README.md
```

-----

## Run It

```bash
# No install required — Python standard library only
python password_analyzer.py
```

-----

## What’s Next

This project is actively being extended. Planned additions:

- **REST API wrapper** — expose scoring as an endpoint consumable by other services
- **Bulk analysis mode** — evaluate credential lists from CSV input for population-level reporting
- **NIST 800-63B alignment report** — generate a compliance summary against NIST password guidelines
- **GitHub Actions CI** — automated test suite on every push

-----

## Engineering Concepts Demonstrated

- Entropy-based security scoring (not just rule matching)
- SQLite schema design with audit logging and parameterized queries
- Modular Python architecture — separation of concerns across scoring, storage, and I/O
- Security-first design — passwords masked in output, never stored in plain text in history
- Credential hygiene aligned to NIST SP 800-63B principles

-----

## Author

**Bryan Peterson** | [@bpstackcode](https://github.com/bpstackcode)

*Part of an ongoing cloud engineering & cybersecurity portfolio.*
