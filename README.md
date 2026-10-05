#!/usr/bin/env python3
"""
Password Strength Analyzer
--------------------------
- Checks length, complexity (character variety) and uniqueness
- Detects common passwords, leetspeak, sequences, repeats, years
- Estimates entropy (bits) and gives a score out of 100
- Suggests stronger passwords / passphrases (using the `secrets` module)
- Optional: SQLite history that stores only salted PBKDF2 hashes,
  so old passwords cannot be reused (never stores plain text).

Usage:
    python password_analyzer.py                 # interactive check
    python password_analyzer.py --user alice    # also check/save reuse history
    python password_analyzer.py --generate      # just generate suggestions
"""
import argparse
import getpass
import hashlib
import hmac
import math
import os
import re
import secrets
import sqlite3
import string
import sys

# ---------------------------------------------------------------- data ----
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "password1", "111111", "123123", "admin", "letmein", "welcome",
    "iloveyou", "monkey", "dragon", "football", "baseball", "login",
    "master", "sunshine", "princess", "qwerty123", "1q2w3e4r", "zaq12wsx",
    "passw0rd", "admin123", "root", "test", "guest", "india123",
    "000000", "654321", "superman", "batman", "shadow", "trustno1",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

LEET = {"@": "a", "4": "a", "$": "s", "5": "s", "0": "o",
        "1": "l", "3": "e", "7": "t", "!": "i"}

WORDS = """apple river tiger cloud mango rocket forest pepper silver coffee
planet garden thunder pencil monkey orange bridge candle window falcon
jungle lemon marble ocean puzzle quartz ribbon spider turtle velvet wizard
yellow zebra anchor basket cactus dolphin eagle flame glacier harbor island
jacket kettle lantern meadow nectar olive panda quiver rabbit sunset temple
umbrella violin walnut yogurt breeze comet desert ember feather galaxy""".split()

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
DB_FILE = "password_history.db"
PBKDF2_ROUNDS = 200_000


# ------------------------------------------------------------ analysis ----
def pool_size(pw):
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        pool += 32
    return pool


def entropy_bits(pw):
    pool = pool_size(pw)
    return len(pw) * math.log2(pool) if pool else 0.0


def has_sequence(pw, n=4):
    """abcd, 4321, qwer, 1234 ... (forward or backward)"""
    s = pw.lower()
    for i in range(len(s) - n + 1):
        chunk = s[i:i + n]
        codes = [ord(c) for c in chunk]
        diffs = {codes[j + 1] - codes[j] for j in range(n - 1)}
        if diffs in ({1}, {-1}):
            return True
        for row in KEYBOARD_ROWS:
            if chunk in row or chunk in row[::-1]:
                return True
    return False


def deleet(pw):
    return "".join(LEET.get(c, c) for c in pw.lower())


def analyze(pw):
    """Return dict: score (0-100), label, entropy, issues, good."""
    issues, good = [], []
    bits = entropy_bits(pw)
    score = min(100.0, bits / 80 * 100)  # 80 bits ~ very strong

    # --- length
    if len(pw) < 8:
        issues.append("Too short (use at least 12 characters).")
        score -= 25
    elif len(pw) < 12:
        issues.append("Okay length, but 12+ characters is much safer.")
        score -= 8
    else:
        good.append(f"Good length ({len(pw)} characters).")

    # --- complexity
    kinds = {
        "lowercase": bool(re.search(r"[a-z]", pw)),
        "uppercase": bool(re.search(r"[A-Z]", pw)),
        "digits": bool(re.search(r"\d", pw)),
        "symbols": bool(re.search(r"[^A-Za-z0-9]", pw)),
    }
    missing = [k for k, v in kinds.items() if not v]
    if missing:
        issues.append("Missing: " + ", ".join(missing) + ".")
        score -= 6 * len(missing)
    else:
        good.append("Uses lowercase, uppercase, digits and symbols.")

    # --- uniqueness / predictable patterns
    low = pw.lower()
    capped = None
    if low in COMMON_PASSWORDS:
        issues.append("This is one of the most commonly used passwords!")
        capped = 5
    elif deleet(pw) in COMMON_PASSWORDS:
        issues.append("Common password with simple substitutions (p@ssw0rd style).")
        capped = 10
    elif any(c in low for c in COMMON_PASSWORDS if len(c) >= 5):
        issues.append("Contains a very common password/word.")
        score -= 20
    if has_sequence(pw):
        issues.append("Contains a sequence (abcd, 1234, qwer...).")
        score -= 15
    if re.search(r"(.)\1{2,}", pw):
        issues.append("Contains repeated characters (aaa, 111).")
        score -= 10
    if re.search(r"(19|20)\d{2}", pw):
        issues.append("Contains a year, which is easy to guess.")
        score -= 20
    if re.fullmatch(r"[A-Za-z]+[!@#$%^&*]?\d+[!@#$%^&*]?", pw):
        issues.append("Pattern 'Word + numbers' is very predictable.")
        score -= 15
    if len(set(pw)) < len(pw) * 0.5 and len(pw) >= 8:
        issues.append("Too many repeated characters overall.")
        score -= 10
    if not issues:
        good.append("No common patterns found.")

    score = max(0, min(100, score))
    if capped is not None:
        score = min(score, capped)
    score = int(round(score))

    if score < 25:
        label = "VERY WEAK"
    elif score < 45:
        label = "WEAK"
    elif score < 65:
        label = "FAIR"
    elif score < 85:
        label = "STRONG"
    else:
        label = "VERY STRONG"

    return {"score": score, "label": label, "entropy": round(bits, 1),
            "issues": issues, "good": good}


# --------------------------------------------------------- suggestions ----
def generate_password(length=16):
    """Random password with at least one char of each type."""
    length = max(length, 12)
    chars = [secrets.choice(string.ascii_lowercase),
             secrets.choice(string.ascii_uppercase),
             secrets.choice(string.digits),
             secrets.choice(SYMBOLS)]
    alphabet = string.ascii_letters + string.digits + SYMBOLS
    chars += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words=4):
    """Easy to remember: Tiger-River-Mango-Cloud-47!"""
    picked = [secrets.choice(WORDS).capitalize() for _ in range(words)]
    return "-".join(picked) + f"-{secrets.randbelow(90) + 10}" + secrets.choice("!@#$%")


def suggest(n=3):
    out = [generate_passphrase(), generate_password(16)]
    out += [generate_password(20) for _ in range(max(0, n - 2))]
    return out


# ------------------------------------------------------ history (DB) ------
def _hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ROUNDS)


def db_connect(path=DB_FILE):
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        salt BLOB NOT NULL,
        hash BLOB NOT NULL,
        created TEXT DEFAULT CURRENT_TIMESTAMP)""")
    return con


def is_reused(con, username, pw):
    rows = con.execute("SELECT salt, hash FROM history WHERE username=?",
                       (username,)).fetchall()
    return any(hmac.compare_digest(_hash(pw, s), h) for s, h in rows)


def save_password(con, username, pw):
    salt = os.urandom(16)
    con.execute("INSERT INTO history (username, salt, hash) VALUES (?,?,?)",
                (username, salt, _hash(pw, salt)))
    con.commit()


# ---------------------------------------------------------------- CLI -----
def read_password(prompt):
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return input(prompt)


def show_report(r):
    bar = "#" * (r["score"] // 5) + "-" * (20 - r["score"] // 5)
    print(f"\n  Strength : {r['label']}  [{bar}] {r['score']}/100")
    print(f"  Entropy  : ~{r['entropy']} bits")
    for g in r["good"]:
        print(f"  [+] {g}")
    for i in r["issues"]:
        print(f"  [-] {i}")


def main():
    ap = argparse.ArgumentParser(description="Password Strength Analyzer")
    ap.add_argument("--user", help="username, enables reuse check with history DB")
    ap.add_argument("--db", default=DB_FILE, help="SQLite file (default: %(default)s)")
    ap.add_argument("--generate", action="store_true", help="only print suggestions")
    args = ap.parse_args()

    if args.generate:
        for s in suggest(5):
            print(s)
        return

    print("=== Password Strength Analyzer === (Ctrl+C to quit)")
    con = db_connect(args.db) if args.user else None
    try:
        while True:
            pw = read_password("\nEnter password to test: ")
            if not pw:
                print("Please type something.")
                continue
            report = analyze(pw)

            if con and is_reused(con, args.user, pw):
                report["issues"].append("You have used this password before. Choose a new one!")
                report["score"], report["label"] = 0, "REUSED"

            show_report(report)

            if report["score"] < 65:
                print("\n  Try one of these stronger options:")
                for s in suggest(3):
                    print("   ->", s)
            elif con and report["label"] != "REUSED":
                if input("\n  Save to history so it can't be reused? (y/n): ").lower() == "y":
                    save_password(con, args.user, pw)
                    print("  Saved (as a salted hash only).")
    except (KeyboardInterrupt, EOFError):
        print("\nBye!")


if __name__ == "__main__":
    main()
