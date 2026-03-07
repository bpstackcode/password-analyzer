# 🔐 Password Strength Analyzer & Breach Checker

A Python command-line tool that analyzes password security and checks against a simulated breach database — built to demonstrate Python programming, SQLite database integration, and cybersecurity concepts.

-----

## Features

- **Strength scoring** (0–100) based on length, character variety, and patterns
- **Entropy calculation** — measures how hard the password is to brute-force
- **Breach database check** — compares against a SQLite table of compromised passwords
- **History tracking** — every check is logged to a local database
- **Actionable feedback** — tells you exactly how to improve a weak password

## Skills Demonstrated

|Skill                |How It’s Used                                      |
|---------------------|---------------------------------------------------|
|Python               |Core logic, functions, regex, math module          |
|SQLite / SQL         |CREATE TABLE, INSERT, SELECT, parameterized queries|
|Security concepts    |Entropy, character pools, breach detection         |
|Code organization    |Modular functions, separation of concerns          |
|Git / Version Control|Project structured for clean commits               |

# 🔐 Password Strength Analyzer & Breach Checker

A Python command-line tool that analyzes password security and checks against a simulated breach database — built to demonstrate Python programming, SQLite database integration, and cybersecurity concepts.

-----

## Features

- **Strength scoring** (0–100) based on length, character variety, and patterns
- **Entropy calculation** — measures how hard the password is to brute-force
- **Breach database check** — compares against a SQLite table of compromised passwords
- **History tracking** — every check is logged to a local database
- **Actionable feedback** — tells you exactly how to improve a weak password

## Skills Demonstrated

|Skill                |How It’s Used                                      |
|---------------------|---------------------------------------------------|
|Python               |Core logic, functions, regex, math module          |
|SQLite / SQL         |CREATE TABLE, INSERT, SELECT, parameterized queries|
|Security concepts    |Entropy, character pools, breach detection         |
|Code organization    |Modular functions, separation of concerns          |
|Git / Version Control|Project structured for clean commits               |

## How to Run

```bash
# No dependencies needed — uses Python standard library only
python password_analyzer.py
```

## Example Output

```
  Enter password (or command): MyP@ssw0rd!22

  Analysis for: **************  (hidden for privacy)
  Score:    85/100
  Rating:   STRONG 🔒
  Length:   14 characters
  Entropy:  91.28 bits

  Criteria Breakdown:
    • Length               Excellent (16+ chars)
    • Uppercase            ✓ Present
    • Lowercase            ✓ Present
    • Numbers              ✓ Present
    • Special Chars        ✓ Present
    • No Repeats           ✓ No repeated characters

  ✅  Not found in breach database.
  🎉 No suggestions — this is a strong password!
```

## Database Schema

```sql
-- Logs every password check
CREATE TABLE check_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at  TEXT NOT NULL,
    length      INTEGER NOT NULL,
    score       INTEGER NOT NULL,
    rating      TEXT NOT NULL,
    breached    INTEGER NOT NULL
);

-- Simulated breach database
CREATE TABLE breached_passwords (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    password TEXT NOT NULL UNIQUE
);
```

## Project Structure

```
project1_password_analyzer/
├── password_analyzer.py   # Main application
├── password_checks.db     # SQLite database (auto-created on first run)
└── README.md
```

## Resume Bullet Points (copy these!)

- Built a Python CLI tool that scores password strength using entropy calculations and regex pattern analysis
- Designed and queried a SQLite database to store check history and detect breached passwords using parameterized SQL queries
- Implemented modular, well-documented code following separation-of-concerns principles
