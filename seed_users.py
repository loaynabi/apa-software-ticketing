#!/usr/bin/env python3
"""Create private, one-time user credentials for the ticketing Worker."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import string
import sys

ROOT = Path(__file__).resolve().parent
PRIVATE_DIR = ROOT / "private-data"
DOMAIN = "advancedpsychiatryassociates.com"
ROLES = {"admin", "executive", "user"}
EMAIL_RE = re.compile(rf"^[^\s@]+@{re.escape(DOMAIN)}$", re.IGNORECASE)
PASSWORD_ALPHABET = string.ascii_letters + string.digits
PASSWORD_ITERATIONS = 100_000


def generate_password():
    chars = [
        secrets.choice(string.ascii_letters),
        secrets.choice(string.digits),
        *(secrets.choice(PASSWORD_ALPHABET) for _ in range(22)),
    ]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def read_team(path):
    try:
        stream = path.open(encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise ValueError(f"Cannot read team CSV: {exc}") from exc
    with stream:
        reader = csv.DictReader(stream)
        expected = ["name", "email", "role"]
        if reader.fieldnames != expected:
            raise ValueError("CSV must have exactly these headers in order: name,email,role.")
        users, seen = [], set()
        for line, row in enumerate(reader, start=2):
            name = (row["name"] or "").strip()
            email = (row["email"] or "").strip().lower()
            role = (row["role"] or "").strip().lower()
            if not name or len(name) > 80 or any(ord(char) < 32 for char in name):
                raise ValueError(f"Line {line}: name must be 1-80 characters without control characters.")
            if len(email) > 200 or not EMAIL_RE.fullmatch(email):
                raise ValueError(f"Line {line}: email must use the @{DOMAIN} domain.")
            if email in seen:
                raise ValueError(f"Line {line}: duplicate email address.")
            if role not in ROLES:
                raise ValueError(f"Line {line}: role must be admin, executive, or user.")
            seen.add(email)
            users.append({"name": name, "email": email, "role": role})
    if not users:
        raise ValueError("The team CSV contains no users.")
    if not any(user["role"] == "admin" for user in users):
        raise ValueError("At least one admin account is required.")
    return users


def make_records(team):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    records, credentials, ids = [], [], set()
    for user in team:
        password = generate_password()
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
        ).hex()
        user_id = "u_" + secrets.token_hex(5)
        while user_id in ids:
            user_id = "u_" + secrets.token_hex(5)
        ids.add(user_id)
        records.append({
            "id": user_id,
            **user,
            "passwordHash": password_hash,
            "salt": salt.hex(),
            "active": True,
            "initialPassword": True,
            "createdAt": now,
        })
        credentials.append(f"{user['name']} ({user['email']}): {password}")
    return records, credentials


def write_private_files(users, credentials):
    PRIVATE_DIR.mkdir(mode=0o700, exist_ok=True)
    outputs = [
        (PRIVATE_DIR / "users.json", json.dumps(users, indent=2) + "\n"),
        (PRIVATE_DIR / "initial-credentials.txt",
         "Private one-time passwords. Deliver securely and delete this file afterward.\n\n"
         + "\n".join(credentials) + "\n"),
    ]
    created = []
    try:
        for path, content in outputs:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
    except OSError as exc:
        for path in created:
            path.unlink(missing_ok=True)
        raise ValueError(f"Could not safely create private output files: {exc}") from exc


def main():
    parser = argparse.ArgumentParser(description="Generate private initial user records and random passwords.")
    parser.add_argument("--team-csv", type=Path, default=PRIVATE_DIR / "team.csv",
                        help="private CSV with exactly the columns name,email,role")
    args = parser.parse_args()
    try:
        team = read_team(args.team_csv)
        users, credentials = make_records(team)
        write_private_files(users, credentials)
    except ValueError as exc:
        parser.error(str(exc))
    print(f"Created private user data for {len(users)} accounts in {PRIVATE_DIR}.")
    print("Distribute initial-credentials.txt securely; users must change these passwords at first sign-in.")


if __name__ == "__main__":
    main()
