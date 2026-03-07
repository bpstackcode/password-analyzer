"""
Password Strength Analyzer & Breach Checker
============================================
A cybersecurity-focused tool that:
  - Analyzes password strength using multiple criteria
  - Assigns a security score and rating
  - Checks against a simulated breach database
  - Logs all checks to a SQLite database for history tracking

Skills demonstrated: Python, SQLite/SQL, functions, loops, conditionals, string manipulation
"""

import sqlite3
import re
import math
import datetime

# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────

def init_database():
    """Create the SQLite database and tables if they don't exist."""
    conn = sqlite3.connect("password_checks.db")
    cursor = conn.cursor()

    # Table to log every password check (we store a HASH hint, never plain text)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS check_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            checked_at  TEXT NOT NULL,
            length      INTEGER NOT NULL,
            score       INTEGER NOT NULL,
            rating      TEXT NOT NULL,
            breached    INTEGER NOT NULL  -- 0 = safe, 1 = breached
        )
    """)

    # Simulated table of commonly breached password patterns
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS breached_passwords (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            password TEXT NOT NULL UNIQUE
        )
    """)

    # Seed some common breached passwords
    common_breached = [
        "password", "123456", "qwerty", "abc123", "letmein",
        "monkey", "iloveyou", "admin", "welcome", "password1",
        "1234567890", "sunshine", "princess", "dragon", "master"
    ]
    for pw in common_breached:
        cursor.execute(
            "INSERT OR IGNORE INTO breached_passwords (password) VALUES (?)", (pw,)
        )

    conn.commit()
    return conn


# ─────────────────────────────────────────────
# PASSWORD ANALYSIS FUNCTIONS
# ─────────────────────────────────────────────

def calculate_entropy(password):
    """
    Estimate password entropy in bits.
    Entropy = length * log2(character_pool_size)
    Higher entropy = harder to brute-force.
    """
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26   # lowercase letters
    if re.search(r'[A-Z]', password):
        pool += 26   # uppercase letters
    if re.search(r'[0-9]', password):
        pool += 10   # digits
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        pool += 32   # special characters

    if pool == 0:
        return 0
    return round(len(password) * math.log2(pool), 2)


def analyze_password(password):
    """
    Score a password from 0–100 based on multiple security criteria.
    Returns a dict with the full analysis breakdown.
    """
    score = 0
    feedback = []
    criteria = {}

    # ── Criterion 1: Length ──────────────────────────────────────────
    length = len(password)
    if length >= 16:
        score += 30
        criteria["length"] = "Excellent (16+ chars)"
    elif length >= 12:
        score += 22
        criteria["length"] = "Good (12–15 chars)"
    elif length >= 8:
        score += 12
        criteria["length"] = "Weak (8–11 chars)"
        feedback.append("Use at least 12 characters.")
    else:
        score += 0
        criteria["length"] = "Very weak (under 8 chars)"
        feedback.append("Password is too short — use at least 12 characters.")

    # ── Criterion 2: Uppercase letters ───────────────────────────────
    if re.search(r'[A-Z]', password):
        score += 15
        criteria["uppercase"] = "✓ Present"
    else:
        criteria["uppercase"] = "✗ Missing"
        feedback.append("Add uppercase letters (A–Z).")

    # ── Criterion 3: Lowercase letters ───────────────────────────────
    if re.search(r'[a-z]', password):
        score += 15
        criteria["lowercase"] = "✓ Present"
    else:
        criteria["lowercase"] = "✗ Missing"
        feedback.append("Add lowercase letters (a–z).")

    # ── Criterion 4: Numbers ─────────────────────────────────────────
    if re.search(r'[0-9]', password):
        score += 15
        criteria["numbers"] = "✓ Present"
    else:
        criteria["numbers"] = "✗ Missing"
        feedback.append("Add at least one number (0–9).")

    # ── Criterion 5: Special characters ──────────────────────────────
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 20
        criteria["special_chars"] = "✓ Present"
    else:
        criteria["special_chars"] = "✗ Missing"
        feedback.append("Add special characters (e.g. !, @, #, $).")

    # ── Criterion 6: No repeated sequences ───────────────────────────
    if not re.search(r'(.)\1{2,}', password):
        score += 5
        criteria["no_repeats"] = "✓ No repeated characters"
    else:
        criteria["no_repeats"] = "✗ Contains repeating characters"
        feedback.append("Avoid repeating characters like 'aaa' or '111'.")

    # ── Rating label ─────────────────────────────────────────────────
    if score >= 85:
        rating = "STRONG 🔒"
    elif score >= 60:
        rating = "MODERATE ⚠️"
    elif score >= 35:
        rating = "WEAK 🔓"
    else:
        rating = "VERY WEAK ❌"

    entropy = calculate_entropy(password)

    return {
        "score":    score,
        "rating":   rating,
        "length":   length,
        "entropy":  entropy,
        "criteria": criteria,
        "feedback": feedback
    }


def check_breach(password, conn):
    """Check if the password exists in the breached passwords table."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM breached_passwords WHERE LOWER(password) = LOWER(?)",
        (password,)
    )
    return cursor.fetchone() is not None


def log_result(result, breached, conn):
    """Save the analysis result to the database for history tracking."""
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO check_history (checked_at, length, score, rating, breached)
        VALUES (?, ?, ?, ?, ?)
    """, (
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        result["length"],
        result["score"],
        result["rating"],
        1 if breached else 0
    ))
    conn.commit()


def show_history(conn):
    """Print the last 10 password checks from the database."""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT checked_at, length, score, rating, breached
        FROM check_history
        ORDER BY id DESC
        LIMIT 10
    """)
    rows = cursor.fetchall()

    if not rows:
        print("\nNo check history yet.\n")
        return

    print("\n" + "─" * 55)
    print(f"  {'Date/Time':<20} {'Len':>4} {'Score':>6}  {'Rating':<15} {'Breach?'}")
    print("─" * 55)
    for row in rows:
        breach_label = "⚠️ YES" if row[4] else "Safe"
        print(f"  {row[0]:<20} {row[1]:>4} {row[2]:>6}   {row[3]:<15} {breach_label}")
    print("─" * 55 + "\n")


# ─────────────────────────────────────────────
# DISPLAY FUNCTIONS
# ─────────────────────────────────────────────

def print_banner():
    print("\n" + "═" * 50)
    print("   🔐  PASSWORD STRENGTH ANALYZER")
    print("       + Breach Database Checker")
    print("═" * 50)

def print_result(password, result, breached):
    print("\n" + "─" * 50)
    print(f"  Analysis for: {'*' * len(password)}  (hidden for privacy)")
    print("─" * 50)
    print(f"  Score:    {result['score']}/100")
    print(f"  Rating:   {result['rating']}")
    print(f"  Length:   {result['length']} characters")
    print(f"  Entropy:  {result['entropy']} bits")
    print("\n  Criteria Breakdown:")
    for key, value in result["criteria"].items():
        label = key.replace("_", " ").title()
        print(f"    • {label:<20} {value}")

    if breached:
        print("\n  ⚠️  BREACH WARNING: This password was found in the")
        print("     breach database! Do NOT use this password.")
    else:
        print("\n  ✅  Not found in breach database.")

    if result["feedback"]:
        print("\n  💡 Suggestions to improve:")
        for tip in result["feedback"]:
            print(f"     → {tip}")
    else:
        print("\n  🎉 No suggestions — this is a strong password!")

    print("─" * 50 + "\n")


# ─────────────────────────────────────────────
# MAIN PROGRAM LOOP
# ─────────────────────────────────────────────

def main():
    print_banner()
    conn = init_database()

    print("\n  Commands:")
    print("  • Type a password to analyze it")
    print("  • Type 'history' to view past checks")
    print("  • Type 'quit' to exit\n")

    while True:
        user_input = input("  Enter password (or command): ").strip()

        if user_input.lower() == "quit":
            print("\n  Goodbye! Stay secure. 🔒\n")
            break
        elif user_input.lower() == "history":
            show_history(conn)
        elif user_input == "":
            print("  Please enter a password.\n")
        else:
            result  = analyze_password(user_input)
            breached = check_breach(user_input, conn)
            log_result(result, breached, conn)
            print_result(user_input, result, breached)

    conn.close()


if __name__ == "__main__":
    main()
