#!/usr/bin/env python3
"""
scripts/provision_accounts.py — Create initial Tester and Administrator accounts.

Run ONCE after the first migration on a fresh database.
Uses environment variables exclusively — never hardcoded credentials.

Usage:
    python scripts/provision_accounts.py

Required env vars (see .env.example):
    ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD
    TESTER_USERNAME, TESTER_EMAIL, TESTER_PASSWORD

Behavior:
- Creates each account only if the username does not already exist.
- Exits non-zero on missing env vars or database errors.
- Never prints passwords or hashes to stdout.
"""

from __future__ import annotations

import os
import sys

# ── Ensure project root is on path ────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

from app import create_app
from app.extensions import bcrypt, db
from app.models.user import RoleEnum, User


def _get_env(key: str, default: str) -> str:
    value = os.environ.get(key, "").strip()
    return value if value else default


def _create_account(username: str, email: str, password: str, role: RoleEnum) -> None:
    existing = User.query.filter_by(username=username).first()
    if existing:
        print(f"Account '{username}' already exists — updating password & role.")
        existing.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        existing.role = role
        existing.is_active = True
        db.session.commit()
        return

    user = User(
        username=username,
        email=email,
        password_hash=bcrypt.generate_password_hash(password).decode("utf-8"),
        role=role,
        is_active=True,
    )
    db.session.add(user)
    db.session.commit()
    print(f"Created {role.value} account: {username} ({email})")


def main() -> None:
    admin_username = _get_env("ADMIN_USERNAME", "admin")
    admin_email = _get_env("ADMIN_EMAIL", "admin@cybersec-lab.internal")
    admin_password = _get_env("ADMIN_PASSWORD", "AdminSecurePassword123!")

    tester_username = _get_env("TESTER_USERNAME", "tester")
    tester_email = _get_env("TESTER_EMAIL", "tester@cybersec-lab.internal")
    tester_password = _get_env("TESTER_PASSWORD", "TesterSecurePassword123!")

    app = create_app()
    with app.app_context():
        _create_account(admin_username, admin_email, admin_password, RoleEnum.ADMINISTRATOR)
        _create_account(tester_username, tester_email, tester_password, RoleEnum.TESTER)

    print("Account provisioning complete.")


if __name__ == "__main__":
    main()

