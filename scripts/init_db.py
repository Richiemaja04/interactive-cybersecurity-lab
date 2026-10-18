"""
scripts/init_db.py — Wait for database availability and initialize tables.
"""

from __future__ import annotations

import os
import sys
import time

# Ensure project root is on Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db


def main() -> None:
    print("==> Checking database connection and initializing tables...")
    max_attempts = 30
    delay = 2

    for attempt in range(1, max_attempts + 1):
        try:
            app = create_app()
            with app.app_context():
                db.create_all()
            print(f"==> Database connected and verified successfully on attempt {attempt}.")
            return
        except Exception as exc:
            print(f"==> Waiting for database (attempt {attempt}/{max_attempts}): {exc}", flush=True)
            time.sleep(delay)

    print("==> Database connection failed after 60 seconds timeout.", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
